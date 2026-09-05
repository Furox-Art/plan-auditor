"""Regression coverage for dependency DAG and concrete output enforcement."""
from __future__ import annotations

import json
import sys

import pytest

from scripts import audit_check as core
from scripts.plan_graph import (
    PlanGraphError,
    effective_dependencies,
    topological_order,
    validate_output_links,
)
from supervisor.plan_verifier import verify_plan


def _check(code: str = "import sys; sys.exit(0)") -> dict:
    return {"type": "run", "argv": [sys.executable, "-c", code], "expect_exit": 0}


def _step(sid: int, **extra) -> dict:
    step = {"id": sid, "title": f"step {sid}", "verify": [_check()]}
    step.update(extra)
    return step


def _plan(steps: list[dict]) -> dict:
    return {"task": "dependency graph regression", "created": "2026-09-05T00:00:00Z", "steps": steps}


def test_multistep_legacy_dependencies_are_rejected():
    plan = _plan([_step(10), _step(20), _step(30)])
    with pytest.raises(PlanGraphError, match="explicitly declare depends_on"):
        effective_dependencies(plan)


def test_explicit_dag_uses_declared_dependencies_and_stable_topology():
    plan = _plan([
        _step(30, depends_on=[10, 20]),
        _step(10, depends_on=[]),
        _step(20, depends_on=[]),
    ])
    assert effective_dependencies(plan) == {30: [10, 20], 10: [], 20: []}
    assert topological_order(plan) == [10, 20, 30]


def test_dependency_cycle_is_rejected():
    plan = _plan([
        _step(1, depends_on=[2]),
        _step(2, depends_on=[1]),
    ])
    with pytest.raises(PlanGraphError, match="cycle"):
        topological_order(plan)
    analysis = verify_plan(plan)
    assert analysis.verdict == "REJECT"
    assert any("cycle" in err for err in analysis.graph_errors)


def test_required_output_must_exist_on_an_ancestor():
    plan = _plan([
        _step(1, depends_on=[], outputs=[{
            "name": "artifact",
            "verify": [{"type": "file_exists", "path": "artifact.txt"}],
        }]),
        _step(2, depends_on=[1], requires_outputs=[{"step": 1, "name": "missing"}]),
    ])
    errors = validate_output_links(plan)
    assert any("undeclared output" in err for err in errors)
    assert verify_plan(plan).verdict == "REJECT"


def test_explicit_dependency_edge_requires_concrete_output_binding():
    plan = _plan([
        _step(1, depends_on=[]),
        _step(2, depends_on=[1]),
    ])
    analysis = verify_plan(plan)
    assert analysis.verdict == "REJECT"
    assert any("no requires_outputs link" in err for err in analysis.graph_errors)


def test_explicit_dependency_with_bound_output_passes_static_verifier():
    plan = _plan([
        _step(1, depends_on=[], outputs=[{
            "name": "artifact",
            "verify": [{"type": "file_exists", "path": "artifact.txt"}],
        }]),
        _step(2, depends_on=[1], requires_outputs=[{"step": 1, "name": "artifact"}]),
    ])
    analysis = verify_plan(plan)
    assert analysis.verdict == "PASS"
    assert analysis.topological_order == [1, 2]


def test_validate_plan_checks_output_verification_contract():
    plan = _plan([
        _step(1, outputs=[{"name": "artifact", "verify": [{"type": "regex", "path": "a.txt"}]}]),
    ])
    errors = core.validate_plan(plan)
    assert any("output" in err.lower() and "pattern" in err.lower() for err in errors)


def test_run_blocks_step_when_prerequisite_is_not_verified(tmp_path):
    plan = _plan([
        _step(1, depends_on=[], outputs=[{"name": "artifact", "verify": [{"type": "file_exists", "path": "artifact.txt"}]}]),
        _step(2, depends_on=[1], requires_outputs=[{"step": 1, "name": "artifact"}]),
    ])
    assert core.audit_steps(str(tmp_path), plan, ids=[2], mode="run") is False
    assert plan["steps"][1]["status"] == "blocked"


def test_run_rechecks_required_output_before_dependent_step(tmp_path):
    plan = _plan([
        _step(1, depends_on=[], status="verified", outputs=[{
            "name": "artifact",
            "verify": [{"type": "file_exists", "path": "artifact.txt"}],
        }]),
        _step(
            2,
            depends_on=[1],
            requires_outputs=[{"step": 1, "name": "artifact"}],
        ),
    ])
    assert core.audit_steps(str(tmp_path), plan, ids=[2], mode="run") is False
    assert plan["steps"][1]["status"] == "blocked"
    evidence = (tmp_path / ".plan-auditor" / "evidence.jsonl").read_text(encoding="utf-8")
    assert '"status": "blocked"' in evidence or '"status":"blocked"' in evidence


def test_audit_uses_topological_order_and_records_output_contract(tmp_path):
    (tmp_path / "artifact.txt").write_text("ok", encoding="utf-8")
    plan = _plan([
        _step(
            2,
            depends_on=[1],
            requires_outputs=[{"step": 1, "name": "artifact"}],
        ),
        _step(1, depends_on=[], outputs=[{
            "name": "artifact",
            "verify": [{"type": "file_exists", "path": "artifact.txt"}],
        }]),
    ])
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    records = [
        json.loads(line)
        for line in (tmp_path / ".plan-auditor" / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    audit_records = [r for r in records if r.get("mode") == "audit"]
    assert [r["step"] for r in audit_records] == [1, 2]
    assert audit_records[0]["outputs"][0]["name"] == "artifact"
    assert audit_records[1]["required_outputs"][0]["step"] == 1


def test_declared_output_failure_fails_producer_step(tmp_path):
    plan = _plan([_step(1, outputs=[{
        "name": "artifact",
        "verify": [{"type": "file_exists", "path": "missing.txt"}],
    }])])
    assert core.audit_steps(str(tmp_path), plan, ids=[1], mode="run") is False
    assert plan["steps"][0]["status"] == "failed"


def test_plan_fingerprint_changes_when_dependency_contract_changes():
    first = _plan([_step(1), _step(2)])
    second = _plan([_step(1, depends_on=[]), _step(2, depends_on=[])])
    assert core.plan_contract_fingerprint(first) != core.plan_contract_fingerprint(second)
