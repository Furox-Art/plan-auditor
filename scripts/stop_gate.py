#!/usr/bin/env python3
"""Blocking Stop-hook adapter for tools that use exit code 2 to retry a turn.

This compatibility entry point no longer trusts persisted ``status=verified``.
It delegates completion to the same integrated supervisor gate used by
``hooks/gate_hook.py``: every active plan, full-contract seal, fresh audit,
evidence integrity, requirement coverage, policies and registry state.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _workspace() -> str:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError:
        payload = {}
    return os.path.abspath(
        os.environ.get("COMMANDCODE_PROJECT_DIR")
        or (payload.get("cwd") if isinstance(payload, dict) else None)
        or os.getcwd()
    )


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from supervisor.orchestrator import evaluate_workspace

    base = _workspace()
    try:
        report = evaluate_workspace(base)
    except Exception as exc:
        sys.stderr.write(
            "PLAN-AUDITOR UNKNOWN — integrated gate failed closed: %s: %s\n"
            % (type(exc).__name__, exc)
        )
        return 2

    outcome = str(report.get("outcome", "UNKNOWN"))
    if outcome in {"PASS", "NO_PLAN"}:
        return 0

    sys.stderr.write("PLAN-AUDITOR %s — completion blocked.\n" % outcome)
    plans = report.get("plans", {}) if isinstance(report, dict) else {}
    if isinstance(plans, dict):
        for name, item in plans.items():
            if not isinstance(item, dict) or item.get("outcome") == "PASS":
                continue
            gate = item.get("gate", {}) if isinstance(item.get("gate"), dict) else {}
            notes = gate.get("notes", []) if isinstance(gate, dict) else []
            fresh = item.get("fresh_audit", {}) if isinstance(item.get("fresh_audit"), dict) else {}
            sys.stderr.write("  %s: %s\n" % (name, item.get("outcome", "FAIL")))
            if fresh and not fresh.get("valid", False):
                sys.stderr.write("    fresh audit: %s\n" % fresh.get("reason", "missing"))
            for note in notes:
                sys.stderr.write("    - %s\n" % note)
    sys.stderr.write("Run: plan-auditor plan verify . && plan-auditor audit .\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
