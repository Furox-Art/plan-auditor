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

    plan = sub.add_parser("plan", help="verify, seal, or inspect plans")
    plan_sub = plan.add_subparsers(dest="action", required=True)
    plan_verify = plan_sub.add_parser("verify")
    plan_verify.add_argument("dir", nargs="?", default=".")
    plan_verify.add_argument("--plan", help="named plan; omitted = every active plan")
    plan_verify.add_argument("--reseal", action="store_true")
    plan_inspect = plan_sub.add_parser("inspect")
    plan_inspect.add_argument("dir", nargs="?", default=".")
    plan_inspect.add_argument("--plan", help="named plan; omitted = default or all if no default")

    evidence = sub.add_parser("evidence", help="verify active and archived evidence")
    evidence_sub = evidence.add_subparsers(dest="action", required=True)
    evidence_verify = evidence_sub.add_parser("verify")
    evidence_verify.add_argument("dir", nargs="?", default=".")

    integrity = sub.add_parser("integrity", help="external-key authenticated integrity")
    integrity_sub = integrity.add_subparsers(dest="action", required=True)
    integrity_init = integrity_sub.add_parser("init", help="authenticate current evidence, registry and seals")
    integrity_init.add_argument("dir", nargs="?", default=".")
    integrity_status = integrity_sub.add_parser("status", help="show authenticated integrity status")
    integrity_status.add_argument("dir", nargs="?", default=".")

    agents = sub.add_parser("agents", help="persistent multi-agent registry")
    agents_sub = agents.add_subparsers(dest="action", required=True)
    agents_list = agents_sub.add_parser("list")
    agents_list.add_argument("dir", nargs="?", default=".")
    agents_register = agents_sub.add_parser("register")
    agents_register.add_argument("agent_id")
    agents_register.add_argument("--task-id", default="default")
    agents_register.add_argument("--plan-id", default="default")
    agents_register.add_argument("--pid", type=int)
    agents_register.add_argument("--dir", default=".")
    agents_heartbeat = agents_sub.add_parser("heartbeat")
    agents_heartbeat.add_argument("agent_id")
    agents_heartbeat.add_argument("--action-text", default="")
    agents_heartbeat.add_argument("--dir", default=".")
    agents_claim = agents_sub.add_parser("claim")
    agents_claim.add_argument("agent_id")
    agents_claim.add_argument("files", nargs="+")
    agents_claim.add_argument("--dir", default=".")
    agents_release = agents_sub.add_parser("release")
    agents_release.add_argument("agent_id")
    agents_release.add_argument("--dir", default=".")

    audit = sub.add_parser("audit", help="run integrated final gate across active plans")
    audit.add_argument("dir", nargs="?", default=".")
    audit.add_argument("--plan", help="execute one named plan audit; overall gate still checks all active plans")
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
    from .daemon import pid_alive, read_assessment, read_state
    root = _root(args.dir)
    state = read_state(root)
    if not state:
        _json({"state": "stopped", "workspace": str(root), "running": False,
               "assessment": read_assessment(root)})
        return 1
    running = state.get("state") == "running" and pid_alive(state.get("pid"))
    state = dict(state)
    state["running"] = running
    state["assessment"] = read_assessment(root)
    if not running and state.get("state") == "running":
        state["state"] = "stale"
    _json(state)
    return 0 if running else 1


def cmd_doctor(args: argparse.Namespace) -> int:
    from .daemon import pid_alive, read_assessment, read_state
    from .integrity import integrity_status
    from .orchestrator import evaluate_workspace
    from .workspace import capture_workspace
    root = _root(args.dir)
    ws = capture_workspace(str(root))
    state = read_state(root)
    assessment = evaluate_workspace(str(root))
    payload = {
        "workspace": ws.to_dict(),
        "supervisor": {
            "running": bool(state and state.get("state") == "running" and pid_alive(state.get("pid"))),
            "state": state,
            "persisted_assessment": read_assessment(root),
        },
        "assessment": assessment,
        "integrity": integrity_status(root),
        "deterministic_core": str(_core_script()) if _core_script() else "module:scripts.audit_check",
    }
    _json(payload)
    outcome = assessment.get("outcome")
    if outcome in {"PASS", "NO_PLAN"}:
        return 0
    return 3 if outcome == "UNKNOWN" else 2


def _selected_refs(root: Path, name: str | None = None):
    from .plans import all_plan_refs, plan_path, validate_plan_name, PlanRef
    if name:
        safe = validate_plan_name(name)
        path = plan_path(root, safe)
        if not path.is_file():
            raise FileNotFoundError(f"plan not found: {path}")
        return [PlanRef(safe, path)]
    refs = all_plan_refs(root)
    if not refs:
        raise FileNotFoundError(f"no active plans under {root / '.plan-auditor'}")
    return refs


def _policy_errors(root: Path, cfg) -> list[str]:
    from .policies import load_policy_rules_from_dir
    errors: list[str] = []
    seen: set[Path] = set()
    for directory in (root / cfg.policies_dir, root / ".plan-auditor" / "policies"):
        resolved = directory.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        load_policy_rules_from_dir(str(resolved), errors=errors)
    return errors


def cmd_plan_verify(args: argparse.Namespace) -> int:
    from scripts import audit_check as core
    from .config import load_config
    from .contracts import environment_contract
    from .plans import load_plan_ref, seal_path
    from .plan_verifier import verify_plan
    from .sealing import (
        SealIntegrityError, check_environment, check_monotonic,
        load_seal, save_seal, seal_plan,
    )

    root = _root(args.dir)
    try:
        refs = _selected_refs(root, args.plan)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    cfg = load_config(str(root))
    policy_errors = _policy_errors(root, cfg)
    if cfg.errors or policy_errors:
        _json({"outcome": "FAIL", "configuration_errors": cfg.errors, "policy_errors": policy_errors})
        return 2
    env = environment_contract(root, cfg)
    outputs: dict[str, Any] = {}
    final_rc = 0

    for ref in refs:
        try:
            plan = load_plan_ref(ref)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            outputs[ref.key] = {"verdict": "REJECT", "error": str(exc)}
            final_rc = max(final_rc, 1)
            continue
        schema_errors = core.validate_plan(plan)
        analysis = verify_plan(plan, require_coverage=True)
        output = {
            "verdict": analysis.verdict,
            "schema_errors": schema_errors,
            "rationale": analysis.rationale,
            "weakest_verification": analysis.weakest_verification,
            "graph_errors": analysis.graph_errors,
            "coverage": analysis.coverage.as_dict() if analysis.coverage else None,
            "topological_order": analysis.topological_order,
            "dependencies": analysis.dependencies,
            "steps": [
                {
                    "id": s.step_id,
                    "behavioral": s.has_behavioral_verification,
                    "dependencies": s.dependencies,
                    "required_outputs": s.required_outputs,
                    "declared_outputs": s.declared_outputs,
                    "risks": s.risks,
                }
                for s in analysis.step_analyses
            ],
        }
        if schema_errors or analysis.verdict != "PASS":
            outputs[ref.key] = output
            final_rc = max(final_rc, 1)
            continue

        target = seal_path(root, ref.name)
        try:
            existing = load_seal(str(target))
        except SealIntegrityError as exc:
            output["seal"] = {"status": "invalid", "error": str(exc)}
            outputs[ref.key] = output
            final_rc = max(final_rc, 2)
            continue
        if existing and existing.format_version < 3 and not args.reseal:
            output["seal"] = {"status": "legacy", "error": "legacy seal requires --reseal"}
            outputs[ref.key] = output
            final_rc = max(final_rc, 2)
            continue
        if existing and not args.reseal:
            monotonic = check_monotonic(existing.as_plan(), plan)
            env_check = check_environment(existing, env)
            if not monotonic.ok or not env_check.ok:
                output["seal"] = {
                    "status": "rejected",
                    "violations": monotonic.violations + env_check.violations,
                    "improvements": monotonic.improvements,
                }
                outputs[ref.key] = output
                final_rc = max(final_rc, 2)
                continue

        plan_id = str(plan.get("id") or plan.get("task") or ref.key)
        new_seal = seal_plan(
            plan, plan_id, _dt.datetime.now(_dt.timezone.utc).isoformat(), environment=env
        )
        try:
            save_seal(new_seal, str(target))
        except SealIntegrityError as exc:
            output["seal"] = {"status": "error", "error": str(exc)}
            outputs[ref.key] = output
            final_rc = max(final_rc, 2)
            continue
        output["seal"] = {
            "status": "sealed", "format_version": new_seal.format_version,
            "criteria_count": new_seal.criteria_count, "plan_hash": new_seal.plan_hash,
            "environment": env,
        }
        outputs[ref.key] = output

    _json({"plans": outputs, "outcome": "PASS" if final_rc == 0 else "FAIL"})
    return final_rc


def cmd_plan_inspect(args: argparse.Namespace) -> int:
    from .plans import load_plan_ref
    root = _root(args.dir)
    try:
        refs = _selected_refs(root, args.plan)
        payload = {ref.key: load_plan_ref(ref) for ref in refs}
    except (FileNotFoundError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    if len(payload) == 1:
        _json(next(iter(payload.values())))
    else:
        _json(payload)
    return 0


def cmd_integrity(args: argparse.Namespace) -> int:
    from scripts.integrity import IntegrityKeyError
    from .integrity import initialize_integrity, integrity_status
    from .sealing import SealIntegrityError
    root = _root(args.dir)
    if args.action == "status":
        result = integrity_status(root)
        _json(result)
        if result.get("authenticated") or not result.get("configured"):
            return 0
        return 2
    try:
        result = initialize_integrity(root)
    except (IntegrityKeyError, SealIntegrityError, OSError, ValueError, json.JSONDecodeError) as exc:
        _json({"authenticated": False, "error": str(exc)})
        return 2
    _json(result)
    return 0


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    from scripts import audit_check as core
    from .evidence import verify_anchor_chain
    root = _root(args.dir)
    active_ok, count, active_problem = core.verify_chain(str(root))
    archive = verify_anchor_chain(str(root / ".plan-auditor" / "archive"))
    result = {
        "valid": active_ok and archive.get("anchored") is True,
        "active": {"valid": active_ok, "records": count, "problem": active_problem},
        "archive": archive,
    }
    _json(result)
    return 0 if result["valid"] else 2


def cmd_audit(args: argparse.Namespace) -> int:
    from .config import load_config
    from .contracts import environment_contract
    from .orchestrator import evaluate_workspace
    from .plans import load_plan_ref, seal_path
    from .sealing import SealIntegrityError, check_environment, check_monotonic, load_seal

    root = _root(args.dir)
    try:
        refs = _selected_refs(root, args.plan)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    cfg = load_config(str(root))
    policy_errors = _policy_errors(root, cfg)
    if cfg.errors or policy_errors:
        _json({"outcome": "FAIL", "configuration_errors": cfg.errors, "policy_errors": policy_errors})
        return 2
    env = environment_contract(root, cfg)

    for ref in refs:
        try:
            plan = load_plan_ref(ref)
            seal = load_seal(str(seal_path(root, ref.name)))
        except (OSError, ValueError, json.JSONDecodeError, SealIntegrityError) as exc:
            _json({"outcome": "FAIL", "plan": ref.key, "reason": str(exc)})
            return 2
        if not seal:
            _json({"outcome": "FAIL", "plan": ref.key, "reason": "plan is not sealed; run plan verify first"})
            return 2
        if seal.format_version < 3:
            _json({"outcome": "FAIL", "plan": ref.key, "reason": "legacy seal requires explicit reseal"})
            return 2
        monotonic = check_monotonic(seal.as_plan(), plan)
        env_check = check_environment(seal, env)
        if not monotonic.ok or not env_check.ok:
            _json({
                "outcome": "FAIL", "plan": ref.key,
                "reason": "sealed verification contract changed",
                "violations": monotonic.violations + env_check.violations,
            })
            return 2

    for ref in refs:
        argv = ["audit", str(root)]
        if ref.name != "default":
            argv += ["--plan", ref.name]
        rc = _forward_core(argv)
        if rc != 0:
            return rc

    assessment = evaluate_workspace(str(root), profile=cfg.profile.value, mode=cfg.mode)
    if assessment.get("outcome") != "PASS":
        _json(assessment)
        return 3 if assessment.get("outcome") == "UNKNOWN" else 2
    _json({
        "outcome": "PASS",
        "plans": {name: item.get("outcome") for name, item in assessment.get("plans", {}).items()},
        "deterministic_core": "fresh audit PASS for every active plan",
        "gate": assessment.get("gate"),
    })
    return 0


def _iter_plan_files(root: Path) -> list[Path]:
    from .plans import all_plan_refs
    return [ref.path for ref in all_plan_refs(root)]


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
    return {"task_id": str(plan.get("id") or plan.get("task") or path.stem),
            "file": str(path), "steps": len(steps), "statuses": statuses}


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


def cmd_agents(args: argparse.Namespace) -> int:
    from .agents import Agent, MultiAgentRegistry, RegistryIntegrityError
    from .config import load_config
    root = _root(args.dir)
    cfg = load_config(str(root))
    registry = MultiAgentRegistry(str(root), owner_timeout=cfg.owner_timeout_sec)
    try:
        if args.action == "list":
            active = registry.active_agents()
            valid = registry.verify_registry_chain()
            _json({"agents": [a.to_dict() for a in active], "count": len(active),
                   "registry": str(registry.registry_path), "registry_valid": valid,
                   "problem": registry.registry_problem})
            return 0 if valid else 2
        if args.action == "register":
            registry.register(Agent(args.agent_id, args.task_id, args.plan_id, pid=args.pid))
            _json({"registered": args.agent_id})
            return 0
        if args.action == "heartbeat":
            registry.heartbeat(args.agent_id, action=args.action_text)
            _json({"heartbeat": args.agent_id})
            return 0
        if args.action == "claim":
            ok, conflicts = registry.claim_files(args.agent_id, set(args.files), mode=cfg.mode)
            _json({"claimed": ok, "agent": args.agent_id,
                   "conflicts": [c.__dict__ for c in conflicts], "mode": cfg.mode})
            return 0 if ok else 2
        if args.action == "release":
            registry.unregister(args.agent_id)
            _json({"released": args.agent_id})
            return 0
    except (RegistryIntegrityError, ValueError) as exc:
        _json({"error": str(exc), "registry_valid": False})
        return 2
    return 1


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
        return {"start": cmd_supervisor_start, "stop": cmd_supervisor_stop,
                "status": cmd_supervisor_status}[args.action](args)
    if args.cmd == "task":
        return {"list": cmd_task_list, "inspect": cmd_task_inspect}[args.action](args)
    if args.cmd == "plan":
        return {"verify": cmd_plan_verify, "inspect": cmd_plan_inspect}[args.action](args)
    if args.cmd == "evidence":
        return cmd_evidence_verify(args)
    if args.cmd == "integrity":
        return cmd_integrity(args)
    if args.cmd == "agents":
        return cmd_agents(args)
    if args.cmd == "audit":
        return cmd_audit(args)
    if args.cmd == "doctor":
        return cmd_doctor(args)
    return 1


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
