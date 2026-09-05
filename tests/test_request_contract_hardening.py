from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from supervisor.cli import main as cli_main
from supervisor.orchestrator import evaluate_workspace
from supervisor.request_contract import initialize_request
from supervisor.sealing import check_monotonic, seal_plan


def _request(*requirements):
    return {
        "format_version": 1,
        "task": "authoritative user request",
        "requirements": list(requirements),
    }


def _req(req_id: str, description: str, check=None):
    if check is None:
        check = {"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}
    return {
        "id": req_id,
        "description": description,
        "priority": "must",
        "acceptance_checks": [check],
    }


def _plan(requirements, *, checks=None):
    checks = checks or [{"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}]
    return {
        "task": "implementation",
        "created": "2026-09-05T00:00:00Z",
        "requirements": requirements,
        "steps": [{"id": 1, "title": "behavior", "covers": [item["id"] for item in requirements], "verify": checks}],
    }


def _write(root: Path, plan: dict):
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")


def test_authoritative_request_omission_blocks_plan_verify(tmp_path: Path):
    r1 = _req("REQ-1", "first")
    r2 = _req("REQ-2", "second")
    initialize_request(tmp_path, _request(r1, r2))
    _write(tmp_path, _plan([{"id": "REQ-1", "description": "first", "priority": "must"}]))
    assert cli_main(["plan", "verify", str(tmp_path)]) == 2


def test_covers_label_without_approved_acceptance_check_is_rejected(tmp_path: Path):
    expected = {"type": "run", "argv": [sys.executable, "-c", "print('secure')"]}
    initialize_request(tmp_path, _request(_req("REQ-1", "secure behavior", expected)))
    _write(tmp_path, _plan([
        {"id": "REQ-1", "description": "secure behavior", "priority": "must"}
    ], checks=[{"type": "run", "argv": [sys.executable, "-c", "print('unrelated')"]}]))
    assert cli_main(["plan", "verify", str(tmp_path)]) == 2


def test_activated_workspace_cannot_become_no_plan(tmp_path: Path):
    initialize_request(tmp_path, _request(_req("REQ-1", "behavior")))
    report = evaluate_workspace(str(tmp_path))
    assert report["outcome"] == "FAIL"
    assert report["active_plan_count"] == 0


def test_reseal_is_disabled_after_activation(tmp_path: Path):
    req = _req("REQ-1", "behavior")
    initialize_request(tmp_path, _request(req))
    _write(tmp_path, _plan([{"id": "REQ-1", "description": "behavior", "priority": "must"}]))
    assert cli_main(["plan", "verify", str(tmp_path)]) == 0
    assert cli_main(["plan", "verify", str(tmp_path), "--reseal"]) == 2


def test_multistep_plan_requires_explicit_dependencies(tmp_path: Path):
    plan = {
        "task": "two steps",
        "created": "2026-09-05T00:00:00Z",
        "steps": [
            {"id": 1, "title": "one", "verify": [{"type": "run", "argv": [sys.executable, "-c", "print(1)"]}]},
            {"id": 2, "title": "two", "verify": [{"type": "run", "argv": [sys.executable, "-c", "print(2)"]}]},
        ],
    }
    from scripts import audit_check as core
    errors = core.validate_plan(plan)
    assert any("depends_on" in item for item in errors)


def test_partial_explicit_graph_cannot_switch_dependency_mode():
    from scripts.plan_graph import PlanGraphError, effective_dependencies
    plan = {
        "steps": [
            {"id": 1, "depends_on": []},
            {"id": 2},
        ]
    }
    try:
        effective_dependencies(plan)
    except PlanGraphError as exc:
        assert "every step" in str(exc)
    else:
        raise AssertionError("partial explicit graph was accepted")
