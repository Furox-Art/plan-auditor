#!/usr/bin/env python3
"""Platform-agnostic audit gate hook.

Reads the current workspace state and runs the completion gate. Prints a
structured verdict (BLOCKED / PASS / UNKNOWN) plus human-readable detail.

Designed to be called by platform-specific hooks:

  - Claude Code / Cursor / Grok : hook command (output fed to model)
  - Codex CLI                    : notify hook (writes warning file)
  - OpenCode                     : plugin hook (injects context)

Usage:
  python hooks/gate_hook.py <workspace-dir> [--format text|json] [--warn-file <path>]

Exit codes mirror the gate: 0 = PASS, 1 = BLOCKED, 3 = UNKNOWN.
"""
import argparse
import json
import os
import sys
from pathlib import Path


def run_gate(workspace_dir: str):
    """Run the completion gate. Returns (outcome, report_dict)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    from supervisor.config import load_config
    from supervisor.gate import CompletionGate
    from supervisor.policies import default_engine
    from supervisor.sealing import MonotonicCheck

    cfg = load_config(workspace_dir)
    plan_path = Path(cfg.pg_path) / "plan.json"
    if not plan_path.exists():
        return "NO_PLAN", {"outcome": "NO_PLAN", "message": "no active plan.json"}

    try:
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        return "UNKNOWN", {"outcome": "UNKNOWN", "message": "plan.json unreadable: %s" % e}

    steps = plan.get("steps", [])
    pending = [s["id"] for s in steps if s.get("status") != "verified"]

    engine = default_engine()
    gate = CompletionGate(engine)
    workspace_ctx = {
        "plan_steps": steps,
        "evidence_valid": True,
        "logs": [],
        "missing_required_tools": [],
    }
    report = gate.evaluate(
        deterministic_passed=len(pending) == 0,
        pending_steps=pending,
        workspace_context=workspace_ctx,
        seal_check=MonotonicCheck(ok=True, violations=[], improvements=[]),
    )
    return report.outcome, report.as_dict()


def format_text(outcome: str, report: dict, workspace_dir: str) -> str:
    if outcome == "NO_PLAN":
        return "[plan-auditor] No active plan.json — verification skipped."
    if outcome == "PASS":
        return "[plan-auditor] PASS — all plan steps verified."
    pending = report.get("pending_steps", [])
    lines = ["[plan-auditor] %s — completion BLOCKED." % outcome]
    if pending:
        lines.append("  Pending/unverified steps: %s" % pending)
    if report.get("notes"):
        for n in report["notes"]:
            lines.append("  - %s" % n)
    lines.append("  Run: python audit/plan-auditor/scripts/audit_check.py run .")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", default=".", nargs="?", help="workspace directory")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--warn-file", help="also write verdict to this file (Codex notify)")
    args = ap.parse_args()

    outcome, report = run_gate(os.path.abspath(args.dir))

    if args.format == "json":
        out = json.dumps({"outcome": outcome, "report": report}, ensure_ascii=False)
    else:
        out = format_text(outcome, report, args.dir)

    print(out)

    if args.warn_file:
        try:
            Path(args.warn_file).parent.mkdir(parents=True, exist_ok=True)
            Path(args.warn_file).write_text(
                json.dumps({"outcome": outcome, "report": report}, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except OSError:
            pass

    if outcome == "PASS":
        return 0
    if outcome == "UNKNOWN":
        return 3
    return 1


if __name__ == "__main__":
    sys.exit(main())
