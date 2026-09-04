"""Command-line interface for the independent Plan Auditor supervisor."""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="plan-auditor",
        description="Plan Auditor — independent AI agent verification supervisor.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    supervisor = sub.add_parser("supervisor", help="supervisor daemon controls")
    supervisor_sub = supervisor.add_subparsers(dest="action", required=True)
    for action in ("start", "stop", "status"):
        item = supervisor_sub.add_parser(action)
        item.add_argument("dir", nargs="?", default=".")
        if action == "start":
            item.add_argument("--profile", choices=["light", "standard", "strict"], default="standard")
            item.add_argument("--mode", choices=["serial", "parallel-warn", "parallel-strict"], default="serial")

    task = sub.add_parser("task", help="inspect plans as supervisor tasks")
    task_sub = task.add_subparsers(dest="action", required=True)
    task_list = task_sub.add_parser("list")
    task_list.add_argument("dir", nargs="?", default=".")
    task_inspect = task_sub.add_parser("inspect")
    task_inspect.add_argument("task_id")
    task_inspect.add_argument("--dir", default=".")

    plan = sub.add_parser("plan", help="verify, seal, or inspect a plan")
    plan_sub = plan.add_subparsers(dest="action", required=True)
    plan_verify = plan_sub.add_parser("verify")
    plan_verify.add_argument("dir", nargs="?", default=".")
    plan_verify.add_argument("--reseal", action="store_true", help="explicitly replace a reviewed legacy seal")
    plan_inspect = plan_sub.add_parser("inspect")
    plan_inspect.add_argument("dir", nargs="?", default=".")

    evidence = sub.add_parser("evidence", help="verify cross-archive evidence anchors")
    evidence_sub = evidence.add_subparsers(dest="action", required=True)
    evidence_verify = evidence_sub.add_parser("verify")
    evidence_verify.add_argument("dir", nargs="?", default=".")

    agents = sub.add_parser("agents", help="inspect the persisted multi-agent registry")
    agents_sub = agents.add_subparsers(dest="action", required=True)
    agents_list = agents_sub.add_parser("list")
    agents_list.add_argument("dir", nargs="?", default=".")

    audit = sub.add_parser("audit", help="run the fresh deterministic final gate")
    audit.add_argument("dir", nargs="?", default=".")
    doctor = sub.add_parser("doctor", help="environment and supervisor capability report")
    doctor.add_argument("dir", nargs="?", default=".")

    for name in ("run", "validate"):
        item = sub.add_parser(name, help=f"forward to deterministic core: {name}")
        item.add_argument("dir", nargs="?", default=".")
    return parser


def _root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def _plan_path(root: Path) -> Path:
    return root / ".plan-auditor" / "plan.json"


def _load_plan(root: Path) -> dict[str, Any]:
    path = _plan_path(root)
    if not path.exists():
        raise FileNotFoundError(f"plan.json not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("plan.json root must be an object")
    return value


def _persist_supervisor_config(root: Path, profile: str, mode: str) -> None:
    from .config import CONFIG_FILENAME
    pg = root / ".plan-auditor"
    pg.mkdir(parents=True, exist_ok=True)
    path = pg / CONFIG_FILENAME
    existing: dict[str, Any] = {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            existing = raw
    except (OSError, json.JSONDecodeError):
        pass
    existing["profile"] = profile
    existing["mode"] = mode
    existing.setdefault("tier", 1)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


def _spawn_daemon(root: Path, profile: str, mode: str) -> subprocess.Popen[bytes]:
    from .daemon import read_state, pid_alive, state_path, stop_path
    current = read_state(root)
    if current and current.get("state") == "running" and pid_alive(current.get("pid")):
        raise RuntimeError(f"supervisor already running with pid {current.get('pid')}")
    for stale in (state_path(root), stop_path(root)):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass
    log_path = root / ".plan-auditor" / "supervisor.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_path.open("ab", buffering=0)
    kwargs: dict[str, Any] = {
        "cwd": str(root), "stdin": subprocess.DEVNULL, "stdout": log_handle,
        "stderr": subprocess.STDOUT, "close_fds": os.name != "nt",
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(subprocess, "DETACHED_PROCESS", 0)
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen([
            sys.executable, "-m", "supervisor.daemon", "--workspace", str(root),
            "--profile", profile, "--mode", mode,
        ], **kwargs)
    finally:
        log_handle.close()
    return process


def cmd_supervisor_start(args: argparse.Namespace) -> int:
    from .daemon import read_state, pid_alive
    root = _root(args.dir)
    if not root.is_dir():
        print(f"ERROR: directory not found: {root}", file=sys.stderr)
        return 1
    _persist_supervisor_config(root, args.profile, args.mode)
    try:
        process = _spawn_daemon(root, args.profile, args.mode)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    deadline = time.time() + 5.0
    while time.time() < deadline:
        state = read_state(root)
        if state and state.get("state") == "running" and state.get("pid") == process.pid and pid_alive(process.pid):
            _json(state)
            return 0
        if process.poll() is not None:
            break
        time.sleep(0.1)
    print(f"ERROR: supervisor failed to start; see {root / '.plan-auditor' / 'supervisor.log'}", file=sys.stderr)
    return 1


def cmd_supervisor_stop(args: argparse.Namespace) -> int:
    from .daemon import pid_alive, read_state, stop_path
    root = _root(args.dir)
    state = read_state(root)
    if not state or not pid_alive(state.get("pid")):
        _json({"state": "stopped", "workspace": str(root)})
        return 0
    pid = int(state["pid"])
    marker = stop_path(root)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("stop\n", encoding="utf-8")
    deadline = time.time() + 8.0
    while time.time() < deadline:
        if not pid_alive(pid):
            _json({"state": "stopped", "pid": pid, "workspace": str(root)})
            return 0
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        pass
    time.sleep(0.2)
    if pid_alive(pid):
        print(f"ERROR: supervisor pid {pid} did not stop", file=sys.stderr)
        return 1
    _json({"state": "stopped", "pid": pid, "workspace": str(root)})
    return 0


def cmd_supervisor_status(args: argparse.Namespace) -> int:
    from .daemon import pid_alive, read_state
    root = _root(args.dir)
    state = read_state(root)
    if not state:
        _json({"state": "stopped", "workspace": str(root), "running": False})
        return 1
    running = state.get("state") == "running" and pid_alive(state.get("pid"))
    state = dict(state)
    state["running"] = running
    if not running and state.get("state") == "running":
        state["state"] = "stale"
    _json(state)
    return 0 if running else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    from .daemon import pid_alive, read_state
    from .workspace import capture_workspace
    root = _root(args.dir)
    ws = capture_workspace(str(root))
    state = read_state(root)
    _json({
        "workspace": ws.to_dict(),
        "supervisor": {"running": bool(state and state.get("state") == "running" and pid_alive(state.get("pid"))), "state": state},
        "deterministic_core": str(_core_script()) if _core_script() else "module:scripts.audit_check",
    })
    return 0


def _existing_seal_plan(root: Path) -> tuple[Any, dict[str, Any] | None]:
    from .sealing import load_seal
    seal = load_seal(str(root / ".plan-auditor" / "seal.json"))
    return seal, seal.as_plan() if seal else None


def cmd_plan_verify(args: argparse.Namespace) -> int:
    from .plan_verifier import verify_plan
    from .sealing import check_monotonic, save_seal, seal_plan
    root = _root(args.dir)
    try:
        plan = _load_plan(root)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    analysis = verify_plan(plan)
    output = {
        "verdict": analysis.verdict, "rationale": analysis.rationale,
        "weakest_verification": analysis.weakest_verification,
        "steps": [{"id": item.step_id, "behavioral": item.has_behavioral_verification, "risks": item.risks} for item in analysis.step_analyses],
    }
    if analysis.verdict != "PASS":
        _json(output)
        return 1
    seal, before = _existing_seal_plan(root)
    if seal and seal.format_version < 2 and not args.reseal:
        output["seal"] = {"status": "legacy", "error": "legacy seal lacks exact verification contents; review and rerun with --reseal"}
        _json(output)
        return 2
    if seal and before and not args.reseal:
        monotonic = check_monotonic(before, plan)
        if not monotonic.ok:
            output["seal"] = {"status": "rejected", "violations": monotonic.violations, "improvements": monotonic.improvements}
            _json(output)
            return 2
    plan_id = str(plan.get("id") or plan.get("task") or "default")
    new_seal = seal_plan(plan, plan_id=plan_id, sealed_at=_dt.datetime.now(_dt.timezone.utc).isoformat())
    save_seal(new_seal, str(root / ".plan-auditor" / "seal.json"))
    output["seal"] = {"status": "sealed", "format_version": new_seal.format_version, "criteria_count": new_seal.criteria_count, "plan_hash": new_seal.plan_hash}
    _json(output)
    return 0


def cmd_plan_inspect(args: argparse.Namespace) -> int:
    try:
        _json(_load_plan(_root(args.dir)))
        return 0
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    from .evidence import verify_anchor_chain
    root = _root(args.dir)
    result = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    _json(result)
    return 0 if result["anchored"] else 2


def cmd_audit(args: argparse.Namespace) -> int:
    from .evidence import verify_anchor_chain
    from .sealing import check_monotonic, load_seal
    root = _root(args.dir)
    try:
        plan = _load_plan(root)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    seal = load_seal(str(root / ".plan-auditor" / "seal.json"))
    if not seal:
        print("ERROR: plan is not sealed; run 'plan-auditor plan verify <dir>' before execution", file=sys.stderr)
        return 2
    if seal.format_version < 2:
        print("ERROR: legacy seal cannot prove exact criteria; review and reseal explicitly", file=sys.stderr)
        return 2
    monotonic = check_monotonic(seal.as_plan(), plan)
    if not monotonic.ok:
        _json({"outcome": "FAIL", "reason": "sealed plan criteria changed", "violations": monotonic.violations})
        return 2
    archive_dir = root / ".plan-auditor" / "archive"
    anchors = verify_anchor_chain(str(archive_dir))
    if not anchors["anchored"]:
        _json({"outcome": "FAIL", "reason": "archive anchor chain broken", **anchors})
        return 2
    rc = _forward_core(["audit", str(root)])
    if rc != 0:
        return rc
    anchors_after = verify_anchor_chain(str(archive_dir))
    if not anchors_after["anchored"]:
        _json({"outcome": "FAIL", "reason": "archive anchor chain broken after audit", **anchors_after})
        return 2
    _json({"outcome": "PASS", "deterministic_core": "fresh audit PASS", "seal": "unchanged", "archive_chain": "anchored"})
    return 0


def _iter_plan_files(root: Path) -> list[Path]:
    pg = root / ".plan-auditor"
    files: list[Path] = []
    default = pg / "plan.json"
    if default.exists():
        files.append(default)
    plans = pg / "plans"
    if plans.is_dir():
        files.extend(sorted(plans.glob("*.json")))
    return files


def _task_summary(path: Path) -> dict[str, Any]:
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"file": str(path), "error": str(exc)}
    steps = plan.get("steps", []) if isinstance(plan, dict) else []
    statuses: dict[str, int] = {}
    for step in steps:
        status = str(step.get("status", "pending")) if isinstance(step, dict) else "invalid"
        statuses[status] = statuses.get(status, 0) + 1
    return {"task_id": str(plan.get("id") or plan.get("task") or path.stem), "file": str(path), "steps": len(steps), "statuses": statuses}


def cmd_task_list(args: argparse.Namespace) -> int:
    _json([_task_summary(path) for path in _iter_plan_files(_root(args.dir))])
    return 0


def cmd_task_inspect(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    for path in _iter_plan_files(root):
        summary = _task_summary(path)
        if summary.get("task_id") == args.task_id or path.stem == args.task_id:
            try:
                _json(json.loads(path.read_text(encoding="utf-8")))
                return 0
            except (OSError, json.JSONDecodeError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 1
    print(f"ERROR: task not found: {args.task_id}", file=sys.stderr)
    return 1


def cmd_agents_list(args: argparse.Namespace) -> int:
    root = _root(args.dir)
    registry = root / ".plan-auditor" / "agents" / "registry.jsonl"
    latest: dict[str, dict[str, Any]] = {}
    if registry.exists():
        for line in registry.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                envelope = json.loads(line)
                rec = envelope.get("rec", {})
                agent = rec.get("agent", {})
                agent_id = agent.get("agent_id")
                if agent_id:
                    latest[str(agent_id)] = {"event": rec.get("event"), "ts": rec.get("ts"), **agent}
            except (json.JSONDecodeError, AttributeError):
                continue
    active = [value for value in latest.values() if value.get("event") != "leave" and value.get("state", "active") != "stale"]
    _json({"agents": active, "count": len(active), "registry": str(registry)})
    return 0


def _core_script() -> Path | None:
    candidate = Path(__file__).resolve().parent.parent / "scripts" / "audit_check.py"
    return candidate if candidate.is_file() else None


def _forward_core(argv: list[str]) -> int:
    core = _core_script()
    command = [sys.executable, str(core), *argv] if core else [sys.executable, "-m", "scripts.audit_check", *argv]
    return subprocess.call(command)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args, rest = parser.parse_known_args(argv)
    if args.cmd in {"run", "validate"}:
        return _forward_core([args.cmd, str(_root(args.dir)), *rest])
    if rest:
        parser.error("unrecognized arguments: " + " ".join(rest))
    if args.cmd == "supervisor":
        return {"start": cmd_supervisor_start, "stop": cmd_supervisor_stop, "status": cmd_supervisor_status}[args.action](args)
    if args.cmd == "task":
        return {"list": cmd_task_list, "inspect": cmd_task_inspect}[args.action](args)
    if args.cmd == "plan":
        return {"verify": cmd_plan_verify, "inspect": cmd_plan_inspect}[args.action](args)
    if args.cmd == "evidence":
        return cmd_evidence_verify(args)
    if args.cmd == "agents":
        return cmd_agents_list(args)
    if args.cmd == "audit":
        return cmd_audit(args)
    if args.cmd == "doctor":
        return cmd_doctor(args)
    return 1


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
