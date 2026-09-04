#!/usr/bin/env python3
"""Platform-agnostic Plan Auditor completion hook.

Unlike the old hook, this does not trust ``status=verified`` by itself and does
not fabricate seal/evidence validity. It runs the integrated supervisor
assessment and only returns PASS when the current plan has matching fresh
full-audit evidence plus valid integrity state.

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


def format_text(outcome: str, report: dict, workspace_dir: str) -> str:
    if outcome == "NO_PLAN":
        return "[plan-auditor] No active plan.json — verification skipped."
    if outcome == "PASS":
        return "[plan-auditor] PASS — sealed current plan has fresh deterministic full-audit evidence."

    gate = report.get("gate", {}) if isinstance(report, dict) else {}
    notes = gate.get("notes", []) if isinstance(gate, dict) else []
    pending = gate.get("pending_steps", []) if isinstance(gate, dict) else []
    fresh = report.get("fresh_audit", {}) if isinstance(report, dict) else {}
    seal = report.get("seal", {}) if isinstance(report, dict) else {}

    lines = [f"[plan-auditor] {outcome} — completion BLOCKED."]
    if pending:
        lines.append("  Pending/unverified steps: %s" % pending)
    if seal and not seal.get("ok", False):
        lines.append("  Seal: invalid/missing — %s" % seal.get("violations", []))
    if fresh and not fresh.get("valid", False):
        lines.append("  Fresh audit: %s" % fresh.get("reason", "missing"))
    for note in notes:
        lines.append("  - %s" % note)
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
                json.dumps(payload, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8",
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
