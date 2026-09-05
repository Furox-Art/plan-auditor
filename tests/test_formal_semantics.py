"""Regression tests for deterministic formal requirement semantic alignment."""
from __future__ import annotations

import sys

from supervisor.formal_planning import make_formal_check
from supervisor.formal_semantics import analyze_formal_semantics
from supervisor.plan_verifier import verify_plan


def _plan(contract: dict) -> dict:
    return {
        "task": "build and verify artifact",
        "created": "2026-09-05T00:00:00Z",
        "requirements": [
            {"id": "REQ-1", "description": "build artifact", "priority": "must"},
            {"id": "REQ-2", "description": "verify artifact", "priority": "should"},
        ],
        "steps": [
            {
                "id": 1,
                "title": "build",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
                "verify": [make_formal_check(contract)],
                "outputs": [{"name": "artifact", "verify": [{"type": "file_exists", "path": "artifact.txt"}]}],
            },
            {
                "id": 2,
                "title": "verify",
                "depends_on": [1],
                "requires_outputs": [{"step": 1, "name": "artifact"}],
                "covers": ["REQ-2"],
                "verify": [{"type": "run", "argv": [sys.executable, "-c", "print('ok')"]}],
                "outputs": [],
            },
        ],
    }


def _contract() -> dict:
    return {
        "version": 1,
        "initial_facts": ["workspace-ready"],
        "goal_facts": ["requirement-satisfied:REQ-1", "requirement-satisfied:REQ-2"],
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
                "add_effects": ["requirement-satisfied:REQ-2"],
                "del_effects": [],
            },
        ],
    }


def test_semantic_requirement_binding_passes():
    result = analyze_formal_semantics(_plan(_contract()))
    assert result.enabled
    assert result.valid
    assert result.producer_steps == {"REQ-1": [1], "REQ-2": [2]}


def test_missing_required_goal_binding_rejects_integrated_plan():
    contract = _contract()
    contract["goal_facts"].remove("requirement-satisfied:REQ-2")
    plan = _plan(contract)
    result = analyze_formal_semantics(plan)
    assert not result.valid
    assert any("REQ-2" in error and "not bound" in error for error in result.errors)
    assert verify_plan(plan, require_coverage=True).verdict == "REJECT"


def test_requirement_goal_cannot_be_pre_satisfied_initially():
    contract = _contract()
    contract["initial_facts"].append("requirement-satisfied:REQ-1")
    result = analyze_formal_semantics(_plan(contract))
    assert not result.valid
    assert any("already true initially" in error for error in result.errors)


def test_requirement_goal_must_be_produced_by_covering_step():
    contract = _contract()
    contract["actions"][0]["add_effects"].remove("requirement-satisfied:REQ-1")
    contract["actions"][1]["add_effects"].append("requirement-satisfied:REQ-1")
    result = analyze_formal_semantics(_plan(contract))
    assert not result.valid
    assert any("non-covering step" in error for error in result.errors)


def test_effect_free_formal_action_is_rejected():
    contract = _contract()
    contract["actions"][0]["add_effects"] = []
    result = analyze_formal_semantics(_plan(contract))
    assert not result.valid
    assert any("no symbolic effect" in error for error in result.errors)
