"""L17 (partial) — CLI for the supervisor.

Ties the layers together behind a small command-line interface. The
deterministic core (audit_check.py) remains the source of truth for
check execution; this CLI orchestrates the surrounding layers around it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plan-auditor",
        description="Plan Auditor — independent AI agent verification supervisor.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("supervisor", help="supervisor daemon controls")
    ss = sp.add_subparsers(dest="action", required=True)
    for a in ("start", "stop", "status"):
        s = ss.add_parser(a)
        if a == "start":
            s.add_argument("--profile", choices=["light", "standard", "strict"],
                           default="standard")
            s.add_argument("--mode", choices=["serial", "parallel-warn", "parallel-strict"],
                           default="serial")
            s.add_argument("dir", nargs="?", default=".")

    for name in ("task", "plan", "evidence", "agents"):
        sp2 = sub.add_parser(name)
        ss2 = sp2.add_subparsers(dest="action", required=True)
        if name == "task":
            ss2.add_parser("list")
            ss2.add_parser("inspect").add_argument("task_id", nargs="?", default=None)
        elif name == "plan":
            ss2.add_parser("verify").add_argument("dir", nargs="?", default=".")
            ss2.add_parser("inspect").add_argument("dir", nargs="?", default=".")
        elif name == "evidence":
            ss2.add_parser("verify").add_argument("dir", nargs="?", default=".")
        elif name == "agents":
            ss2.add_parser("list").add_argument("dir", nargs="?", default=".")

    audit = sub.add_parser("audit", help="run the deterministic core final gate")
    audit.add_argument("dir", nargs="?", default=".")

    doctor = sub.add_parser("doctor", help="environment capability report")
    doctor.add_argument("dir", nargs="?", default=".")

    # Forward everything else to the existing deterministic core.
    sub.add_parser("run").add_argument("dir", nargs="?", default=".")
    sub.add_parser("validate").add_argument("dir", nargs="?", default=".")
    return p


def cmd_status(args) -> int:
    from .config import load_config
    from .evidence import verify_anchor_chain
    from .workspace import capture_workspace

    cfg = load_config(args.dir)
    ws = capture_workspace(args.dir)
    archive_dir = Path(cfg.pg_path) / "archive"
    ev = verify_anchor_chain(str(archive_dir)) if archive_dir.exists() else {"archives": []}
    out = {
        "profile": cfg.profile.value,
        "tier": cfg.tier.value,
        "mode": cfg.mode,
        "language": ws.language,
        "git_branch": ws.git.branch,
        "evidence_anchored": ev.get("anchored"),
    }
    print(json.dumps(out, indent=2))
    return 0


def cmd_doctor(args) -> int:
    from .workspace import capture_workspace

    ws = capture_workspace(args.dir)
    print(json.dumps(ws.to_dict(), indent=2))
    return 0


def cmd_plan_verify(args) -> int:
    from .plan_verifier import verify_plan

    plan_path = Path(args.dir) / ".plan-auditor" / "plan.json"
    if not plan_path.exists():
        print("ERROR: plan.json not found", file=sys.stderr)
        return 1
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    analysis = verify_plan(plan)
    out = {
        "verdict": analysis.verdict,
        "rationale": analysis.rationale,
        "weakest_verification": analysis.weakest_verification,
        "steps": [{"id": s.step_id, "behavioral": s.has_behavioral_verification,
                    "risks": s.risks} for s in analysis.step_analyses],
    }
    print(json.dumps(out, indent=2))
    return 0 if analysis.verdict == "PASS" else 1


def cmd_evidence_verify(args) -> int:
    from .evidence import verify_anchor_chain

    archive_dir = Path(args.dir) / ".plan-auditor" / "archive"
    result = verify_anchor_chain(str(archive_dir))
    print(json.dumps(result, indent=2))
    return 0 if result["anchored"] else 2


def cmd_audit(args) -> int:
    """Final completion gate across layers."""
    from .config import load_config
    from .policies import default_engine
    from .gate import CompletionGate
    from .sealing import check_monotonic, load_seal

    cfg = load_config(args.dir)
    plan_path = Path(cfg.pg_path) / "plan.json"
    if not plan_path.exists():
        print("ERROR: plan.json not found", file=sys.stderr)
        return 1
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    steps = plan.get("steps", [])
    pending = [s["id"] for s in steps if s.get("status") != "verified"]

    workspace_ctx = {
        "plan_steps": steps,
        "evidence_valid": True,
        "missing_required_tools": [],
        "logs": [],
    }
    engine = default_engine()
    gate = CompletionGate(engine)

    seal_path = Path(cfg.pg_path) / "seal.json"
    seal_check = None
    if seal_path.exists():
        seal = load_seal(str(seal_path))
        if seal:
            import hashlib
            cur = hashlib.sha256(
                json.dumps(plan, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            seal_check = check_monotonic({"steps": seal.steps}, {"steps": [
                {"id": s.get("id"), "verify": s.get("verify", [])} for s in steps]})

    report = gate.evaluate(
        deterministic_passed=len(pending) == 0,
        pending_steps=pending,
        workspace_context=workspace_ctx,
        seal_check=seal_check,
    )
    print(json.dumps(report.as_dict(), indent=2))
    return 0 if report.outcome == "PASS" else 1


def scripts_path() -> Path:
    return Path(__file__).resolve().parent.parent / "scripts"


def main(argv: list[str]) -> int:
    parser = _build_parser()
    # If first extra token is a known core command, forward to audit_check.
    args, rest = parser.parse_known_args(argv)

    if args.cmd == "run":
        return _forward_core(["run"] + rest)
    if args.cmd == "validate":
        return _forward_core(["validate"] + rest)

    dispatch = {
        "status": cmd_status,
        "doctor": cmd_doctor,
    }
    if args.cmd == "plan" and args.action == "verify":
        return cmd_plan_verify(args)
    if args.cmd == "evidence" and args.action == "verify":
        return cmd_evidence_verify(args)
    if args.cmd == "audit":
        return cmd_audit(args)
    if args.cmd == "supervisor":
        print(json.dumps({"error": "daemon not implemented in this phase",
                          "hint": "use 'plan-auditor audit <dir>' as the gate"}, indent=2))
        return 0
    if args.cmd == "task" or args.cmd == "agents":
        print(json.dumps({"status": "noop", "cmd": args.cmd, "action": args.action}, indent=2))
        return 0

    fn = dispatch.get(args.cmd)
    if fn:
        return fn(args)
    return 0


def _forward_core(argv: list[str]) -> int:
    import subprocess

    core = Path(__file__).resolve().parent.parent / "scripts" / "audit_check.py"
    return subprocess.call([sys.executable, str(core)] + argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
