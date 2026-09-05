#!/usr/bin/env python3
"""Platform-agnostic Plan Auditor completion hook.

Exit codes: 0 = PASS/NO_PLAN, 1 = FAIL/BLOCKED, 3 = UNKNOWN.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def run_gate(workspace_dir: str):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from supervisor.orchestrator import evaluate_workspace

    root = os.path.abspath(workspace_dir)
    try:
        report = evaluate_workspace(root)
    except Exception as exc:
        return "UNKNOWN", {
            "outcome": "UNKNOWN",
            "message": f"integrated supervisor assessment failed: {type(exc).__name__}: {exc}",
        }
    return str(report.get("outcome", "UNKNOWN")), report


def _plan_failure_lines(name: str, item: dict) -> list[str]:
    lines = [f"  Plan {name}: {item.get('outcome', 'FAIL')}"]
    seal = item.get("seal", {}) if isinstance(item.get("seal"), dict) else {}
    fresh = item.get("fresh_audit", {}) if isinstance(item.get("fresh_audit"), dict) else {}
    coverage = item.get("coverage", {}) if isinstance(item.get("coverage"), dict) else {}
    gate = item.get("gate", {}) if isinstance(item.get("gate"), dict) else {}
    if seal and not seal.get("ok", False):
        lines.append("    Seal: invalid/missing — %s" % seal.get("violations", []))
    if coverage and not coverage.get("valid", False):
        lines.append("    Requirement coverage: %s" % coverage.get("errors", []))
    if fresh and not fresh.get("valid", False):
        lines.append("    Fresh audit: %s" % fresh.get("reason", "missing"))
    for note in gate.get("notes", []) if isinstance(gate, dict) else []:
        lines.append("    - %s" % note)
    return lines


def format_text(outcome: str, report: dict, workspace_dir: str) -> str:
    if outcome == "NO_PLAN":
        return "[plan-auditor] No active plans — verification skipped."
    if outcome == "PASS":
        count = report.get("active_plan_count", 1) if isinstance(report, dict) else 1
        return f"[plan-auditor] PASS — all {count} active plan(s) have sealed fresh deterministic audit evidence."

    lines = [f"[plan-auditor] {outcome} — completion BLOCKED."]
    if isinstance(report, dict):
        for message in report.get("configuration_errors", []) or []:
            lines.append("  Config: %s" % message)
        for message in report.get("policy_errors", []) or []:
            lines.append("  Policy: %s" % message)
        plans = report.get("plans", {})
        if isinstance(plans, dict):
            for name, item in plans.items():
                if isinstance(item, dict) and item.get("outcome") != "PASS":
                    lines.extend(_plan_failure_lines(name, item))
    lines.append("  Run final gate: plan-auditor plan verify . && plan-auditor audit .")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", default=".", nargs="?", help="workspace directory")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--warn-file", help="also write verdict to this file")
    args = ap.parse_args()

    outcome, report = run_gate(os.path.abspath(args.dir))
    payload = {"outcome": outcome, "report": report}
    out = json.dumps(payload, ensure_ascii=False) if args.format == "json" else format_text(outcome, report, args.dir)
    print(out)

    if args.warn_file:
        try:
            Path(args.warn_file).parent.mkdir(parents=True, exist_ok=True)
            Path(args.warn_file).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8"
            )
        except OSError:
            pass

    if outcome in {"PASS", "NO_PLAN"}:
        return 0
    if outcome == "UNKNOWN":
        return 3
    return 1


if __name__ == "__main__":
    sys.exit(main())
