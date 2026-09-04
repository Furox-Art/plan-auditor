"""Background supervisor daemon for Plan Auditor.

The daemon keeps durable runtime state, polls the workspace watchdog, and
persists observed events. Deterministic verification still happens in
``scripts.audit_check`` and remains the source of truth.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path
from typing import Any

from .config import load_config
from .watchdog import Watchdog

STATE_FILENAME = "supervisor-runtime.json"
STOP_FILENAME = "supervisor.stop"
EVENTS_FILENAME = "watchdog.jsonl"


def runtime_dir(workspace: str | Path) -> Path:
    return Path(workspace).resolve() / ".plan-auditor"


def state_path(workspace: str | Path) -> Path:
    return runtime_dir(workspace) / STATE_FILENAME


def stop_path(workspace: str | Path) -> Path:
    return runtime_dir(workspace) / STOP_FILENAME


def read_state(workspace: str | Path) -> dict[str, Any] | None:
    path = state_path(workspace)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def pid_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except (OSError, PermissionError):
        return False


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


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
                        should_stop: "callable[[], bool]") -> bool:
    """Wait until the next poll while reacting quickly to stop requests.

    Returns ``True`` when execution should stop. The watchdog/heartbeat cadence
    can remain several seconds without making ``supervisor stop`` wait for the
    full polling interval.
    """
    deadline = time.monotonic() + max(0.0, seconds)
    marker = stop_path(workspace)
    while True:
        if should_stop() or marker.exists():
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.1, remaining))


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
        })

    write_state("running")
    interval = max(0.5, min(float(cfg.heartbeat_sec), 5.0))
    try:
        while not should_stop and not stop_path(root).exists():
            result = watchdog.poll()
            _append_events(root, result.events)
            events_seen += len(result.events)
            write_state("running")
            if _interruptible_wait(root, interval, lambda: should_stop):
                break
    finally:
        try:
            stop_path(root).unlink()
        except FileNotFoundError:
            pass
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
