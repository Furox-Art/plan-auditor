"""Regression tests for deterministic automatic formalization."""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

from supervisor.formal_compiler import (
    FORMALIZATION_SOURCE_PREFIX,
    FORMALIZER_EXECUTABLE,
    compile_contract,
    compile_plan,
    compile_workspace,
    output_fact,
    source_fact,
    validate_generated_contract,
    verify_workspace,
)
from supervisor.formal_planning import contract_sha256, make_formal_check
from supervisor.formal_semantics import analyze_formal_semantics
from supervisor.plan_verifier import verify_plan


def _base_plan() -> dict:
    return {
        "task": "build and verify an artifact",
        "created": "2026-09-06T00:00:00Z",
        "requirements": [
            {
                "id": "REQ-1",
                "description": "build the artifact",
                "priority": "must",
            },
            {
                "id": "REQ-2",
                "description": "verify the artifact",
                "priority": "must",
            },
        ],
        "steps": [
            {
                "id": 1,
                "title": "build",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
                "verify": [
                    {
                        "type": "run",
                        "argv": [sys.executable, "-c", "print('build ok')"],
                    }
                ],
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
                    {
                        "type": "run",
                        "argv": [sys.executable, "-c", "print('verify ok')"],
                    }
                ],
                "outputs": [],
            },
        ],
    }


def test_compiler_builds_conservative_structural_contract():
    plan = _base_plan()
    contract = compile_contract(plan)

    marker = source_fact(plan)
    assert contract["initial_facts"] == [marker]
    assert marker.startswith(FORMALIZATION_SOURCE_PREFIX)
    assert "requirement-satisfied:REQ-1" in contract["goal_facts"]
    assert "requirement-satisfied:REQ-2" in contract["goal_facts"]
    assert "step-completed:1" in contract["goal_facts"]
    assert "step-completed:2" in contract["goal_facts"]

    artifact = output_fact(1, "artifact")
    assert artifact in contract["goal_facts"]
    by_step = {action["step"]: action for action in contract["actions"]}
    assert artifact in by_step[1]["add_effects"]
    assert artifact in by_step[2]["preconditions"]
    assert marker in by_step[1]["preconditions"]
    assert marker in by_step[2]["preconditions"]
    assert by_step[1]["del_effects"] == []
    assert by_step[2]["del_effects"] == []


def test_compile_plan_adds_formal_and_independent_semantic_checks():
    plan, contract, anchor = compile_plan(_base_plan())
    assert anchor == 1
    checks = plan["steps"][0]["verify"]
    assert checks[0]["formal_planning"] == contract
    assert checks[1]["argv"][0] == FORMALIZER_EXECUTABLE
    assert checks[1]["argv"][-1] == contract_sha256(contract)

    semantic = analyze_formal_semantics(plan)
    assert semantic.enabled
    assert semantic.generated
    assert semantic.valid
    assert verify_plan(plan, require_coverage=True).verdict == "PASS"


def test_generated_contract_goal_weakening_is_detected_even_with_fresh_anchor_hash():
    plan, _contract, _anchor = compile_plan(_base_plan())
    anchor_check = plan["steps"][0]["verify"][0]
    weakened = copy.deepcopy(anchor_check["formal_planning"])
    weakened["goal_facts"].remove("requirement-satisfied:REQ-2")
    plan["steps"][0]["verify"][0] = make_formal_check(weakened)

    semantic = analyze_formal_semantics(plan)
    assert not semantic.valid
    assert any("REQ-2" in error for error in semantic.errors)
    assert any("deterministic recompilation" in error for error in semantic.errors)
    assert verify_plan(plan, require_coverage=True).verdict == "REJECT"


def test_generated_contract_missing_output_precondition_is_detected():
    plan, _contract, _anchor = compile_plan(_base_plan())
    raw = copy.deepcopy(plan["steps"][0]["verify"][0]["formal_planning"])
    artifact = output_fact(1, "artifact")
    action2 = next(action for action in raw["actions"] if action["step"] == 2)
    action2["preconditions"].remove(artifact)
    plan["steps"][0]["verify"][0] = make_formal_check(raw)

    errors = validate_generated_contract(plan, raw)
    assert any("deterministic recompilation" in error for error in errors)
    assert not analyze_formal_semantics(plan).valid


def test_source_change_makes_generated_contract_stale():
    plan, contract, _anchor = compile_plan(_base_plan())
    assert validate_generated_contract(plan, contract) == []

    plan["steps"][1]["covers"] = ["REQ-1", "REQ-2"]
    errors = validate_generated_contract(plan, contract)
    assert any("source fingerprint" in error for error in errors)


def test_fake_initial_requirement_goal_is_rejected():
    plan, _contract, _anchor = compile_plan(_base_plan())
    raw = copy.deepcopy(plan["steps"][0]["verify"][0]["formal_planning"])
    raw["initial_facts"].append("requirement-satisfied:REQ-1")
    plan["steps"][0]["verify"][0] = make_formal_check(raw)

    semantic = analyze_formal_semantics(plan)
    assert not semantic.valid
    assert any("already true initially" in error for error in semantic.errors)


def test_compile_plan_is_idempotent_for_generated_contract():
    first, contract1, anchor1 = compile_plan(_base_plan())
    second, contract2, anchor2 = compile_plan(first)
    assert contract1 == contract2
    assert anchor1 == anchor2
    assert second == first


def test_compile_workspace_refuses_to_mutate_sealed_plan(tmp_path: Path):
    control = tmp_path / ".plan-auditor"
    control.mkdir()
    path = control / "plan.json"
    path.write_text(json.dumps(_base_plan()), encoding="utf-8")
    (control / "seal.json").write_text("{}", encoding="utf-8")

    results = compile_workspace(tmp_path, write=True)
    assert len(results) == 1
    assert not results[0].valid
    assert any("sealed plan" in error for error in results[0].errors)
    unchanged = json.loads(path.read_text(encoding="utf-8"))
    assert not any(
        isinstance(check, dict) and "formal_planning" in check
        for step in unchanged["steps"]
        for check in step["verify"]
    )


def test_generated_semantic_verifier_recomputes_workspace_contract(tmp_path: Path):
    control = tmp_path / ".plan-auditor"
    control.mkdir()
    plan, contract, _anchor = compile_plan(_base_plan())
    (control / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    digest = contract_sha256(contract)

    ok, payload = verify_workspace(tmp_path, digest=digest)
    assert ok
    assert payload["outcome"] == "PASS"

    mutated = json.loads((control / "plan.json").read_text(encoding="utf-8"))
    mutated["steps"][1]["covers"] = ["REQ-1", "REQ-2"]
    (control / "plan.json").write_text(json.dumps(mutated), encoding="utf-8")
    ok, payload = verify_workspace(tmp_path, digest=digest)
    assert not ok
    assert payload["outcome"] == "FAIL"
    assert any(
        "source fingerprint" in error
        for error in payload["formalizations"][0]["errors"]
    )


def test_manual_contract_is_not_overwritten():
    plan = _base_plan()
    manual = {
        "version": 1,
        "initial_facts": [],
        "goal_facts": [
            "requirement-satisfied:REQ-1",
            "requirement-satisfied:REQ-2",
        ],
        "actions": [
            {
                "step": 1,
                "preconditions": [],
                "add_effects": ["requirement-satisfied:REQ-1"],
                "del_effects": [],
            },
            {
                "step": 2,
                "preconditions": ["requirement-satisfied:REQ-1"],
                "add_effects": ["requirement-satisfied:REQ-2"],
                "del_effects": [],
            },
        ],
    }
    plan["steps"][0]["verify"].insert(0, make_formal_check(manual))
    try:
        compile_plan(plan)
    except ValueError as exc:
        assert "manual formal_planning" in str(exc)
    else:
        raise AssertionError("manual formal contract should not be overwritten")
