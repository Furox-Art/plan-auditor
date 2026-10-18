#!/usr/bin/env python3
"""Blocking Stop-hook adapter for tools that use exit code 2 to retry a turn.

This compatibility entry point no longer trusts persisted ``status=verified``.
It delegates completion to the same integrated supervisor gate used by
``hooks/gate_hook.py``: every active plan, full-contract seal, fresh audit,
evidence integrity, requirement coverage, policies and registry state.
"""
from __future__ import annotations

import json
import math
import os
import sys
from pathlib import Path

MAX_HOOK_JSON_CHARS = 256 * 1024


def _unique_hook_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for field, value in pairs:
        if field in result:
            raise ValueError(f"duplicate Stop-hook field: {field}")
        result[field] = value
    return result


def _finite_hook_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("non-finite Stop-hook number")
    return value


def _invalid_hook_constant(raw: str) -> None:
    raise ValueError(f"non-standard Stop-hook numeric constant: {raw}")


def _workspace() -> str:
    raw = sys.stdin.read(MAX_HOOK_JSON_CHARS + 1)
    if len(raw) > MAX_HOOK_JSON_CHARS:
        raise ValueError("Stop-hook input exceeds bounded JSON size")
    payload = json.loads(
        raw or "{}",
        object_pairs_hook=_unique_hook_keys,
        parse_float=_finite_hook_float,
        parse_constant=_invalid_hook_constant,
    )
    json.dumps(payload, ensure_ascii=False).encode("utf-8")
    if not isinstance(payload, dict):
        raise ValueError("Stop-hook payload must be a JSON object")
    declared_cwd = payload.get("cwd")
    if declared_cwd is not None and (
        not isinstance(declared_cwd, str) or not declared_cwd.strip()
    ):
        raise ValueError("Stop-hook cwd must be a non-empty string")
    return os.path.abspath(
        os.environ.get("COMMANDCODE_PROJECT_DIR")
        or declared_cwd
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

    try:
        base = _workspace()
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
