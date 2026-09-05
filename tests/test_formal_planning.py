"""Regression tests for sealed LLM-free STRIPS/PDDL verification."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from supervisor.formal_planning import (
    analyze_formal_contract,
    contract_sha256,
    export_pddl,
    make_formal_check,
    run_fast_downward,
    verify_workspace,
)
from supervisor.plan_verifier import verify_plan


def _plan(contract: dict) -> dict:
    formal = make_formal_check(contract)
    return {
        "task": "build then verify an artifact",
        "created": "2026-09-05T00:00:00Z",
        "requirements": [
            {"id": "REQ-1", "description": "build artifact", "priority": "must"},
            {"id": "REQ-2", "description": "verify artifact", "priority": "must"},
        ],
        "steps": [
            {
                "id": 1,
                "title": "build",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
                "verify": [formal],
                "outputs": [
                    {
                        "name": "artifact",
                        "verify": [{"type": "file_exists", "path": "artifact.txt"}],
                    }
                ],
            },
            {
                "id": 2,
                "title": "verify",
                "depends_on": [1],
                "requires_outputs": [{"step": 1, "name": "artifact"}],
                "covers": ["REQ-2"],
                "verify": [
                    {"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}
                ],
                "outputs": [],
            },
        ],
    }


def _reachable_contract() -> dict:
    return {
        "version": 1,
        "initial_facts": ["workspace-ready"],
        "goal_facts": [
            "artifact-verified",
            "requirement-satisfied:REQ-1",
            "requirement-satisfied:REQ-2",
        ],
        "actions": [
            {
                "step": 1,
                "preconditions": ["workspace-ready"],
                "add_effects": ["artifact-built", "requirement-satisfied:REQ-1"],
                "del_effects": [],
            },
            {
                "step": 2,
                "preconditions": ["artifact-built"],
                "add_effects": ["artifact-verified", "requirement-satisfied:REQ-2"],
                "del_effects": [],
            },
        ],
    }


def test_reachable_formal_contract_passes_plan_verifier():
    plan = _plan(_reachable_contract())
    formal = analyze_formal_contract(plan)
    assert formal.enabled
    assert formal.verdict == "PASS"
    assert formal.solution_order == [1, 2]
    assert formal.monotonic

    analysis = verify_plan(plan, require_coverage=True)
    assert analysis.verdict == "PASS"
    assert analysis.formal_planning is not None
    assert analysis.formal_semantics is not None
    assert analysis.formal_semantics.valid
    assert analysis.formal_planning.contract_sha256 == contract_sha256(_reachable_contract())


def test_contract_payload_is_bound_to_anchor_hash():
    plan = _plan(_reachable_contract())
    anchor = plan["steps"][0]["verify"][0]
    anchor["formal_planning"]["goal_facts"] = ["different-goal"]

    result = analyze_formal_contract(plan)
    assert result.verdict == "REJECT"
    assert any("canonical argv" in error for error in result.errors)


def test_delete_effect_dead_end_is_rejected():
    contract = {
        "version": 1,
        "initial_facts": ["token"],
        "goal_facts": ["verified"],
        "actions": [
            {
                "step": 1,
                "preconditions": ["token"],
                "add_effects": ["built"],
                "del_effects": ["token"],
            },
            {
                "step": 2,
                "preconditions": ["token", "built"],
                "add_effects": ["verified"],
                "del_effects": [],
            },
        ],
    }
    plan = _plan(contract)
    result = analyze_formal_contract(plan)
    assert result.enabled
    assert not result.monotonic
    assert result.verdict == "REJECT"
    assert "no dependency-respecting" in result.reason
    assert verify_plan(plan, require_coverage=True).verdict == "REJECT"


def test_formal_planner_can_find_non_document_order_when_dag_allows_it():
    contract = {
        "version": 1,
        "initial_facts": ["a"],
        "goal_facts": ["goal"],
        "actions": [
            {
                "step": 1,
                "preconditions": ["b"],
                "add_effects": ["goal"],
                "del_effects": [],
            },
            {
                "step": 2,
                "preconditions": ["a"],
                "add_effects": ["b"],
                "del_effects": [],
            },
        ],
    }
    plan = _plan(contract)
    plan["steps"][1]["depends_on"] = []
    plan["steps"][1]["requires_outputs"] = []
    result = analyze_formal_contract(plan)
    assert result.verdict == "PASS"
    assert result.solution_order == [2, 1]


def test_pddl_export_uses_sanitized_predicates_and_requires_every_step():
    contract = _reachable_contract()
    contract["initial_facts"] = ["workspace-ready", "raw ) (injected"]
    plan = _plan(contract)
    domain, problem, mapping = export_pddl(plan, contract)

    assert "(:requirements :strips)" in domain
    assert "(:action step-1" in domain
    assert "(done-step-1)" in problem
    assert "(done-step-2)" in problem
    assert "raw ) (injected" not in domain
    assert "raw ) (injected" not in problem
    assert mapping["raw ) (injected"].startswith("f")


def test_fast_downward_missing_binary_is_explicitly_unavailable():
    plan = _plan(_reachable_contract())
    result = run_fast_downward(
        plan,
        _reachable_contract(),
        executable="definitely-not-a-real-fast-downward-command-7f6418",
    )
    assert result.status == "UNAVAILABLE"


def test_workspace_verifier_finds_sealed_contract_by_hash(tmp_path: Path):
    plan = _plan(_reachable_contract())
    control = tmp_path / ".plan-auditor"
    control.mkdir()
    (control / "plan.json").write_text(json.dumps(plan), encoding="utf-8")

    digest = contract_sha256(_reachable_contract())
    ok, payload = verify_workspace(tmp_path, digest=digest)
    assert ok
    assert payload["outcome"] == "PASS"
    assert payload["contracts"][0]["analysis"]["solution_order"] == [1, 2]


def test_duplicate_formal_anchors_fail_closed():
    plan = _plan(_reachable_contract())
    plan["steps"][1]["verify"].append(make_formal_check(_reachable_contract()))
    result = analyze_formal_contract(plan)
    assert result.verdict == "REJECT"
    assert "exactly one" in result.reason
