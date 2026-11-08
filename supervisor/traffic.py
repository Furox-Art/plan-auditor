"""Supervisor-side traffic capture lifecycle, report and gate evidence.

The deterministic core owns classification and the proxy; this module owns the
operator-facing lifecycle (start/stop/status, CA install/remove), reads traffic
records from the existing chained evidence, and reduces them to the third
completion-gate evidence. No decision here is semantic: a report is OK only if
the chain verifies, the evidence is authenticated, every session declares the
exact number of requests actually chained, and no request violated the sealed
plan scope.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, cast

from scripts import audit_check as core
from scripts.traffic import (
    CertificateAuthority,
    CertificateError,
    audit_records,
    build_session_id,
    install_trust,
    load_state,
    load_trust_marker,
    log_path,
    pid_is_alive,
    pki_dir,
    plan_dir,
    stop_path,
    traffic_contract,
    trust_path,
    uninstall_trust,
    write_state,
    write_trust_marker,
)

from .evidence import verify_anchor_chain
from .gate import TrafficCheck
from .plans import PlanRef, load_plan_ref, plan_path

START_TIMEOUT_SEC = 60.0
STOP_TIMEOUT_SEC = 20.0

_GATE_OUTCOMES = frozenset({"TAMPERED", "UNVERIFIED", "NOT_CONFIGURED", "INCOMPLETE"})


def selected_plan(root: str | Path, plan_name: str | None) -> tuple[str, dict[str, Any]]:
    from scripts.contract import validate_plan_name

    root_path = Path(root).expanduser().resolve()
    safe = validate_plan_name(plan_name)
    path = plan_path(root_path, safe)
    if not path.is_file():
        raise FileNotFoundError(f"plan not found: {path}")
    ref = PlanRef(safe or "default", path)
    try:
        return ref.key, load_plan_ref(ref)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot load plan {ref.key}: {exc}") from exc


def _evidence_files(root: Path) -> list[Path]:
    archive = root / ".plan-auditor" / "archive"
    files: list[Path] = []
    if archive.is_dir():
        files.extend(sorted(archive.glob("evidence-*.jsonl")))
    active = root / ".plan-auditor" / "evidence.jsonl"
    if active.exists():
        files.append(active)
    return files


def _iter_records(root: Path) -> Iterator[dict[str, Any]]:
    for path in _evidence_files(root):
        try:
            handle = path.open(encoding="utf-8", errors="replace")
        except OSError:
            continue
        with handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    yield record


def traffic_records(root: str | Path, plan_name: str) -> list[dict[str, Any]]:
    root_path = Path(root).resolve()
    return [
        record
        for record in _iter_records(root_path)
        if record.get("plan", "default") == plan_name
        and record.get("mode") in {"traffic_request", "traffic_session"}
    ]


def _chain_state(root: Path) -> dict[str, Any]:
    verify_chain = cast(Callable[[str], tuple[bool, int, str]], core.verify_chain)
    evidence_is_authenticated = cast(
        Callable[[str], tuple[bool, str]], core.evidence_is_authenticated
    )
    active_ok, count, problem = verify_chain(str(root))
    archive = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    authenticated, auth_problem = evidence_is_authenticated(str(root))
    return {
        "active_valid": active_ok,
        "active_records": count,
        "active_problem": problem,
        "archive_anchored": archive.get("anchored") is True,
        "archive": archive.get("broken_at"),
        "authenticated": authenticated,
        "authentication_problem": auth_problem,
    }


def build_traffic_report(
    root: str | Path,
    plan_name: str | None = None,
    *,
    plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Aggregate traffic evidence for one plan and fail closed on any gap."""
    root_path = Path(root).expanduser().resolve()
    key, loaded = (plan_name, plan) if plan is not None else (None, None)
    if loaded is None:
        key, loaded = selected_plan(root_path, plan_name)
    key = key or "default"
    try:
        contract = traffic_contract(loaded)
    except ValueError as exc:
        return {
            "schema": "plan-auditor-traffic-report/v1",
            "plan": key,
            "outcome": "INVALID",
            "ok": False,
            "reason": str(exc),
            "violations": [],
            "chain": {},
        }
    report: dict[str, Any] = {
        "schema": "plan-auditor-traffic-report/v1",
        "plan": key,
        "allowed_hosts": contract["allowed_hosts"] if contract else [],
        "requests": 0,
        "classes": {},
        "hosts": {},
        "by_day": {},
        "secret_hits": [],
        "sessions": [],
        "session_problems": [],
        "violations": [],
        "unrecognized_classes": [],
        "chain": _chain_state(root_path),
    }
    if contract is None:
        report.update({
            "outcome": "NOT_CONFIGURED",
            "ok": False,
            "reason": "plan does not declare a traffic contract",
        })
        return report

    summary = audit_records(traffic_records(root_path, key), allowed_hosts=contract["allowed_hosts"])
    report.update(summary)
    chain = report["chain"]
    if not chain.get("active_valid") or not chain.get("archive_anchored"):
        report["outcome"] = "TAMPERED"
        report["reason"] = (
            "traffic evidence chain is not verifiable: "
            f"{chain.get('active_problem') or 'archive is not anchored'}"
        )
    elif not chain.get("authenticated"):
        report["outcome"] = "UNVERIFIED"
        report["reason"] = (
            "traffic evidence is not authenticated: "
            f"{chain.get('authentication_problem') or 'no HMAC key is configured'}"
        )
    else:
        report["reason"] = _reason(summary)
    report["ok"] = report["outcome"] == "OK"
    return report


def _reason(summary: dict[str, Any]) -> str:
    outcome = summary.get("outcome")
    if outcome == "OK":
        return (
            f"{summary.get('requests', 0)} outbound request(s) observed, "
            "all in plan scope, every session closed exactly"
        )
    if outcome == "SILENT":
        return "proxy observed zero requests; silence is not proof of clean traffic"
    if outcome == "VIOLATION":
        kinds = sorted({str(item.get("kind")) for item in summary.get("violations", [])})
        return f"outbound traffic violations: {', '.join(kinds)}"
    if outcome == "INCOMPLETE":
        problems = sorted({
            str(item.get("kind")) for item in summary.get("session_problems", [])
        })
        return (
            "traffic capture is incomplete: "
            + (", ".join(problems) if problems else "no closing session record")
        )
    return f"traffic audit outcome is {outcome}"


def evaluate_traffic(
    root: str | Path, plan: dict[str, Any], plan_name: str
) -> TrafficCheck:
    """The third chain-verifiable evidence used by the completion gate."""
    try:
        contract = traffic_contract(plan)
    except ValueError as exc:
        return TrafficCheck(
            required=True,
            ok=False,
            outcome="INVALID",
            reason=str(exc),
        )
    if contract is None:
        return TrafficCheck(
            required=False,
            ok=True,
            outcome="NOT_REQUIRED",
            reason="plan does not declare a traffic contract",
        )
    report = build_traffic_report(root, plan_name, plan=plan)
    return TrafficCheck(
        required=True,
        ok=bool(report.get("ok")),
        outcome=str(report.get("outcome", "UNVERIFIED")),
        reason=str(report.get("reason", "")),
        requests=int(report.get("requests", 0) or 0),
        classes=dict(report.get("classes", {}) or {}),
        violations=list(report.get("violations", []) or []),
        authenticated=bool(report.get("chain", {}).get("authenticated")),
        sessions=list(report.get("sessions", []) or []),
    )


# ---------------------------------------------------------------- lifecycle


def _tail(path: Path, limit: int = 4000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[-limit:].strip()
    except OSError:
        return ""


def _spawn_daemon(
    root: Path,
    plan: str,
    *,
    port: int,
    session_id: str,
    started_at: str,
) -> subprocess.Popen[bytes]:
    directory = plan_dir(root, plan)
    directory.mkdir(parents=True, exist_ok=True)
    log = log_path(root, plan).open("ab", buffering=0)
    kwargs: dict[str, Any] = {
        # Never use the audited workspace as cwd: a workspace-local ``scripts``
        # package must not shadow the installed one the daemon imports.
        "cwd": tempfile.gettempdir(),
        "stdin": subprocess.DEVNULL,
        "stdout": log,
        "stderr": subprocess.STDOUT,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    else:
        kwargs["start_new_session"] = True
    argv = [
        sys.executable, "-m", "scripts.traffic",
        "--workspace", str(root),
        "--plan", plan,
        "--port", str(port),
        "--session-id", session_id,
        "--started-at", started_at,
    ]
    try:
        return subprocess.Popen(argv, **kwargs)
    finally:
        log.close()


def _state_running(state: dict[str, Any] | None) -> bool:
    return bool(
        isinstance(state, dict)
        and state.get("running") is True
        and pid_is_alive(state.get("pid"))
    )


def start_traffic(
    root: str | Path,
    plan_name: str | None,
    plan: dict[str, Any],
    *,
    install_ca: bool = False,
    port: int = 0,
    timeout: float = START_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Start the loopback proxy for one plan; idempotent while it is alive."""
    root_path = Path(root).expanduser().resolve()
    contract = traffic_contract(plan)
    if contract is None:
        raise ValueError("plan does not declare a traffic contract")
    key, _loaded = selected_plan(root_path, plan_name)
    if not 0 <= port < 65536:
        raise ValueError(f"port out of range: {port}")

    existing = load_state(root_path, key)
    if existing is not None and _state_running(existing):
        return {**existing, "already_running": True}

    ca = CertificateAuthority(pki_dir(root_path))
    try:
        ca.ensure()
    except CertificateError as exc:
        raise RuntimeError(f"certificate authority setup failed: {exc}") from exc

    trust_installed = False
    trust_detail = "not installed; trust the CA manually or pass --install-ca"
    if install_ca:
        installed, trust_detail = install_trust(ca.cert_path, ca=ca)
        if not installed:
            raise RuntimeError(f"CA trust installation failed: {trust_detail}")
        write_trust_marker(
            root_path,
            {
                "fingerprint": ca.fingerprint(),
                "detail": trust_detail,
                "installed_at": _now(),
            },
        )
        trust_installed = True
    else:
        marker = load_trust_marker(root_path)
        trust_installed = bool(marker and marker.get("fingerprint") == ca.fingerprint())

    started_at = _now()
    session_id = build_session_id()
    try:
        stop_path(root_path, key).unlink()
    except OSError:
        # A missing stop marker is the normal start state.
        pass
    write_state(
        root_path,
        key,
        {
            "version": 1,
            "workspace": str(root_path),
            "plan": key,
            "running": False,
            "starting": True,
            "pid": None,
            "port": None,
            "allowed_hosts": contract["allowed_hosts"],
            "session_id": session_id,
            "started_at": started_at,
            "ca_cert": str(ca.cert_path),
            "ca_fingerprint": ca.fingerprint(),
            "trust_installed": trust_installed,
            "trust_detail": trust_detail,
        },
    )
    try:
        child = _spawn_daemon(
            root_path, key, port=port, session_id=session_id, started_at=started_at
        )
    except OSError as exc:
        raise RuntimeError(f"could not start the traffic daemon: {exc}") from exc

    deadline = time.monotonic() + timeout
    state: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        if child.poll() is not None:
            break
        candidate = load_state(root_path, key)
        if (
            candidate
            and candidate.get("running") is True
            and candidate.get("pid") == child.pid
        ):
            state = candidate
            break
        time.sleep(0.05)
    if state is None:
        if child.poll() is None:
            child.terminate()
        detail = _tail(log_path(root_path, key))
        raise RuntimeError(
            "traffic daemon did not become ready" + (f": {detail}" if detail else "")
        )
    return state


def _wait_stopped(
    root: Path, plan: str, pid: int, timeout: float
) -> dict[str, Any] | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = load_state(root, plan)
        if state and state.get("running") is False and state.get("pid") == pid:
            return state
        if not pid_is_alive(pid):
            state = load_state(root, plan)
            if state and state.get("running") is False:
                return state
            return None
        time.sleep(0.05)
    return None


def _mark_stale(root: Path, plan: str, state: dict[str, Any]) -> dict[str, Any]:
    stale = {
        **state,
        "running": False,
        "stale": True,
        "error": "traffic daemon disappeared without closing its session",
    }
    write_state(root, plan, stale)
    return stale


def stop_traffic(
    root: str | Path,
    plan_name: str | None,
    *,
    timeout: float = STOP_TIMEOUT_SEC,
    remove_ca: bool = False,
) -> dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    key, _loaded = selected_plan(root_path, plan_name)
    state = load_state(root_path, key)
    if state is None:
        raise FileNotFoundError(f"no traffic state under {plan_dir(root_path, key)}")
    pid = state.get("pid")
    running = (
        state.get("running") is True
        and isinstance(pid, int)
        and pid_is_alive(pid)
    )
    if state.get("running") is True and not running:
        state = _mark_stale(root_path, key, state)
    if running and isinstance(pid, int):
        try:
            stop_path(root_path, key).write_text("stop\n", encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"could not write the stop file: {exc}") from exc
        state = _wait_stopped(root_path, key, pid, timeout)
        if state is None:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                # The daemon already exited between the wait and the signal.
                pass
            state = _wait_stopped(root_path, key, pid, 2.0)
            if state is None:
                raise RuntimeError(
                    "traffic daemon did not close its session within "
                    f"{timeout:.0f}s; the report will refuse to call this run complete"
                )
    if not remove_ca:
        return state or {}

    ca = CertificateAuthority(pki_dir(root_path))
    marker = load_trust_marker(root_path)
    trust_removed = False
    trust_detail = "no traffic trust-install marker; nothing removed from a store"
    if marker is not None:
        if not ca.cert_path.is_file():
            raise RuntimeError(
                "cannot remove trust: the CA certificate is missing but an install "
                "marker exists; restore the certificate and retry"
            )
        removed, trust_detail = uninstall_trust(ca.cert_path, ca=ca)
        if not removed:
            raise RuntimeError(
                f"CA trust removal failed: {trust_detail}; the CA files were kept "
                "so the removal can be retried"
            )
        trust_removed = True
        try:
            trust_path(root_path).unlink()
        except OSError:
            # The marker is already gone; the store removal above is what
            # matters and it has succeeded.
            pass
    ca.remove()
    if ca.cert_path.exists() or ca.key_path.exists():
        raise RuntimeError("CA files could not be removed completely")
    updated = load_state(root_path, key) or state or {}
    updated.update(
        {
            "ca_removed": True,
            "trust_installed": False,
            "trust_removed": trust_removed,
            "trust_detail": trust_detail,
        }
    )
    write_state(root_path, key, updated)
    return updated


def traffic_status(root: str | Path, plan_name: str | None) -> dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    key, _loaded = selected_plan(root_path, plan_name)
    state = load_state(root_path, key)
    if state is None:
        raise FileNotFoundError(f"no traffic state under {plan_dir(root_path, key)}")
    alive = state.get("running") is True and pid_is_alive(state.get("pid"))
    port_open = False
    port = state.get("port")
    if alive and isinstance(port, int):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                port_open = True
        except OSError:
            port_open = False
    marker = load_trust_marker(root_path)
    return {
        **state,
        "alive": alive,
        "port_open": port_open,
        "trust_installed": bool(
            marker and marker.get("fingerprint") == state.get("ca_fingerprint")
        ),
    }


def install_ca(root: str | Path) -> dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    ca = CertificateAuthority(pki_dir(root_path))
    try:
        ca.ensure()
    except CertificateError as exc:
        raise RuntimeError(f"certificate authority setup failed: {exc}") from exc
    installed, detail = install_trust(ca.cert_path, ca=ca)
    if not installed:
        raise RuntimeError(f"CA trust installation failed: {detail}")
    write_trust_marker(
        root_path,
        {
            "fingerprint": ca.fingerprint(),
            "detail": detail,
            "installed_at": _now(),
        },
    )
    return {
        "installed": True,
        "detail": detail,
        "ca_cert": str(ca.cert_path),
        "fingerprint": ca.fingerprint(),
    }


def remove_ca(root: str | Path) -> dict[str, Any]:
    root_path = Path(root).expanduser().resolve()
    ca = CertificateAuthority(pki_dir(root_path))
    marker = load_trust_marker(root_path)
    removed = False
    detail = "no traffic trust-install marker; nothing removed from a store"
    if marker is not None:
        if not ca.cert_path.is_file():
            raise RuntimeError(
                "cannot remove trust: the CA certificate is missing but an install "
                "marker exists; restore the certificate and retry"
            )
        removed, detail = uninstall_trust(ca.cert_path, ca=ca)
        if not removed:
            raise RuntimeError(
                f"CA trust removal failed: {detail}; the CA files were kept "
                "so the removal can be retried"
            )
        try:
            trust_path(root_path).unlink()
        except OSError:
            # The marker is already gone; see the removal path above.
            pass
    if ca.root.exists():
        ca.remove()
    if ca.cert_path.exists() or ca.key_path.exists():
        raise RuntimeError("CA files could not be removed completely")
    return {"removed": True, "trust_removed": removed, "detail": detail}


def _now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).isoformat()


def report_exit_code(outcome: str) -> int:
    if outcome == "OK":
        return 0
    return 2 if outcome in _GATE_OUTCOMES else 1


__all__ = [
    "build_traffic_report",
    "evaluate_traffic",
    "install_ca",
    "remove_ca",
    "report_exit_code",
    "selected_plan",
    "start_traffic",
    "stop_traffic",
    "traffic_records",
    "traffic_status",
]
