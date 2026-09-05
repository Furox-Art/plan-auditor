"""Background supervisor daemon for Plan Auditor.

The daemon continuously observes the workspace and persists an integrated
L0-L14 assessment. Deterministic implementation checks still run only through
``scripts.audit_check``; the daemon consumes their evidence rather than
silently executing project commands.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path
from typing import Any, Callable

from .config import load_config
from .orchestrator import evaluate_workspace
from .watchdog import Watchdog

STATE_FILENAME = "supervisor-runtime.json"
ASSESSMENT_FILENAME = "supervisor-assessment.json"
STOP_FILENAME = "supervisor.stop"
EVENTS_FILENAME = "watchdog.jsonl"


def runtime_dir(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / ".plan-auditor"


def state_path(workspace: str | Path) -> Path:
    return runtime_dir(workspace) / STATE_FILENAME


def assessment_path(workspace: str | Path) -> Path:
    return runtime_dir(workspace) / ASSESSMENT_FILENAME


def stop_path(workspace: str | Path) -> Path:
    return runtime_dir(workspace) / STOP_FILENAME


def read_state(workspace: str | Path) -> dict[str, Any] | None:
    path = state_path(workspace)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def read_assessment(workspace: str | Path) -> dict[str, Any] | None:
    try:
        value = json.loads(assessment_path(workspace).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _windows_pid_alive(pid: int) -> bool:
    """Probe a Windows process without sending a signal or mutating it."""
    try:
        import ctypes
        from ctypes import wintypes

        process_query_limited_information = 0x1000
        still_active = 259
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        open_process = kernel32.OpenProcess
        open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        open_process.restype = wintypes.HANDLE
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit_code.restype = wintypes.BOOL
        close_handle = kernel32.CloseHandle
        close_handle.argtypes = [wintypes.HANDLE]
        close_handle.restype = wintypes.BOOL

        handle = open_process(process_query_limited_information, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not get_exit_code(handle, ctypes.byref(code)):
                return False
            return code.value == still_active
        finally:
            close_handle(handle)
    except (AttributeError, OSError, ValueError):
        return False


def pid_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        # A permission error still proves that the process exists.
        return True
    except OSError:
        return False


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Use a unique sibling temp file so independent writers cannot collide.
    # Windows can transiently reject replacement while a reader has the old
    # destination open; retry that sharing violation without falling back to
    # a non-atomic in-place write.
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{time.monotonic_ns()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str), encoding="utf-8")
    deadline = time.monotonic() + 3.0
    try:
        while True:
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


def _append_events(workspace: str | Path, events: list[Any]) -> None:
    if not events:
        return
    target = runtime_dir(workspace) / EVENTS_FILENAME
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps({
                "ts": event.ts,
                "kind": event.kind,
                "path": event.path,
                "detail": event.detail,
            }, ensure_ascii=False, sort_keys=True) + "\n")


def _interruptible_wait(workspace: str | Path, seconds: float,
                        should_stop: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + max(0.0, seconds)
    marker = stop_path(workspace)
    while True:
        if should_stop() or marker.exists():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.1, remaining))


def _safe_assessment(root: str, profile: str, mode: str) -> dict[str, Any]:
    try:
        return evaluate_workspace(root, profile=profile, mode=mode)
    except Exception as exc:
        # Fail closed but keep the daemon alive so the error remains observable.
        return {
            "outcome": "UNKNOWN",
            "workspace": root,
            "profile": profile,
            "mode": mode,
            "error": f"assessment failed: {type(exc).__name__}: {exc}",
        }


def run_daemon(workspace: str, profile: str, mode: str) -> int:
    root = str(Path(workspace).resolve())
    pg = runtime_dir(root)
    pg.mkdir(parents=True, exist_ok=True)

    existing = read_state(root)
    if existing and existing.get("state") == "running" and pid_alive(existing.get("pid")):
        return 2

    try:
        stop_path(root).unlink()
    except FileNotFoundError:
        pass

    cfg = load_config(root)
    watchdog = Watchdog(root, poll_interval=2.0)
    should_stop = False
    started_at = time.time()
    events_seen = 0
    gate_outcome = "UNKNOWN"

    def _signal_handler(_signum: int, _frame: object) -> None:
        nonlocal should_stop
        should_stop = True

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _signal_handler)
        except (ValueError, OSError):
            pass

    def write_state(state: str) -> None:
        _atomic_write_json(state_path(root), {
            "state": state,
            "pid": os.getpid(),
            "workspace": root,
            "profile": profile,
            "mode": mode,
            "started_at": started_at,
            "heartbeat_at": time.time(),
            "events_seen": events_seen,
            "gate_outcome": gate_outcome,
            "assessment_file": str(assessment_path(root)),
        })

    # Publish process liveness before the potentially expensive initial assessment.
    # Callers can distinguish a live startup from a crashed child without
    # weakening the requirement that only an assessed daemon becomes running.
    write_state("starting")
    assessment = _safe_assessment(root, profile, mode)
    gate_outcome = str(assessment.get("outcome", "UNKNOWN"))
    _atomic_write_json(assessment_path(root), assessment)
    write_state("running")

    interval = max(0.5, min(float(cfg.heartbeat_sec), 5.0))
    try:
        while not should_stop and not stop_path(root).exists():
            result = watchdog.poll()
            _append_events(root, result.events)
            events_seen += len(result.events)

            assessment = _safe_assessment(root, profile, mode)
            gate_outcome = str(assessment.get("outcome", "UNKNOWN"))
            _atomic_write_json(assessment_path(root), assessment)
            write_state("running")
            if _interruptible_wait(root, interval, lambda: should_stop):
                break
    finally:
        try:
            stop_path(root).unlink()
        except FileNotFoundError:
            pass
        # Final assessment captures any changes observed during shutdown.
        assessment = _safe_assessment(root, profile, mode)
        gate_outcome = str(assessment.get("outcome", "UNKNOWN"))
        _atomic_write_json(assessment_path(root), assessment)
        write_state("stopped")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan Auditor supervisor daemon")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--profile", choices=["light", "standard", "strict"], default="standard")
    parser.add_argument("--mode", choices=["serial", "parallel-warn", "parallel-strict"], default="serial")
    args = parser.parse_args(argv)
    return run_daemon(args.workspace, args.profile, args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
