"""Deterministic formal compiler cannot manufacture completed requirements."""

from __future__ import annotations

import copy

import pytest

from supervisor import formal_compiler as compiler
from supervisor import formal_planning as formal


def plan():
    return {
        "task": "build a real verified artifact",
        "requirements": [{"id": "REQ-1", "description": "real artifact", "priority": "must"}],
        "steps": [
            {
                "id": 1,
                "title": "produce",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"],
                "outputs": [{"name": "artifact"}],
                "verify": [{"type": "file_exists", "path": "artifact.txt"}],
            }
        ],
    }


def test_generated_contract_is_bound_to_exact_source_and_all_observed_requirements():
    p = plan()
    c = compiler.compile_contract(p)
    assert c["initial_facts"] == [compiler.source_fact(p)]
    assert compiler.requirement_goal_fact("REQ-1") in c["goal_facts"]
    assert compiler.step_fact(1) in c["goal_facts"]
    assert compiler.output_fact(1, "artifact") in c["goal_facts"]
    assert compiler.validate_generated_contract(p, c) == []
    final, contract, anchor = compiler.compile_plan(p)
    assert anchor == 1
    assert final["steps"][0]["verify"][0]["formal_planning"] == contract
    assert formal.analyze_formal_contract(final).verdict == "PASS"
    assert compiler.source_fact(final) == compiler.source_fact(p)


@pytest.mark.parametrize(
    ("requirements", "pattern"),
    [
        ([], "non-empty plan.requirements"),
        ([{"id": "", "description": "task", "priority": "must"}], "non-empty id"),
        ([{"id": "REQ-1", "description": "", "priority": "must"}], "non-empty description"),
        ([{"id": "REQ-1", "description": "test", "priority": "urgent"}], "invalid priority"),
        (
            [
                {"id": "REQ-1", "description": "a", "priority": "must"},
                {"id": "REQ-1", "description": "b", "priority": "must"},
            ],
            "duplicate requirement id",
        ),
        ([5], "must be an object or string"),
        ([{"id": "REQ-1", "description": "valid", "priority": "may"}], "at least one must/should"),
    ],
)
def test_invalid_required_evidence_remains_an_explicit_compiler_error(requirements, pattern):
    p = plan()
    p["requirements"] = requirements
    with pytest.raises(ValueError, match=pattern):
        compiler.compile_contract(p)


@pytest.mark.parametrize(
    ("update", "pattern"),
    [
        ({"id": False}, "positive integer"),
        ({"id": 0}, "positive integer"),
        ({"covers": "REQ-1"}, "covers must be a list"),
        ({"covers": ["REQ-1", "REQ-1"]}, "repeats coverage"),
        ({"covers": ["UNDECLARED"]}, "unknown requirement"),
        ({"outputs": "not-list"}, "outputs must be a list"),
        ({"outputs": ["", ""]}, "non-empty name"),
        ({"outputs": ["same", "same"]}, "repeats output name"),
    ],
)
def test_malformed_step_output_or_coverage_never_compiles_into_fake_goal(update, pattern):
    p = plan()
    p["steps"][0].update(update)
    with pytest.raises(ValueError, match=pattern):
        compiler.compile_contract(p)


def test_missing_requirement_coverage_cannot_be_claimed_by_formal_actions():
    p = plan()
    p["steps"][0]["covers"] = []
    with pytest.raises(ValueError, match="not covered by any formalized step"):
        compiler.compile_contract(p)


def test_missing_steps_cannot_satisfy_required_goals_without_actual_work():
    p = plan()
    p["steps"] = []
    with pytest.raises(ValueError, match="non-empty plan.steps"):
        compiler.compile_contract(p)


def test_source_fingerprint_changes_with_unreviewed_verification_change():
    p = plan()
    marker_before = compiler.source_fact(p)
    p["steps"][0]["verify"][0]["path"] = "other.txt"
    assert compiler.source_fact(p) != marker_before


def test_generated_formal_contract_cannot_be_edited_without_recompilation():
    p = plan()
    original = compiler.compile_contract(p)
    altered = copy.deepcopy(original)
    altered["goal_facts"].remove(compiler.requirement_goal_fact("REQ-1"))
    errors = compiler.validate_generated_contract(p, altered)
    assert any("deterministic recompilation" in error for error in errors)


def test_source_change_cannot_keep_stale_generated_fingerprint_valid():
    p = plan()
    compiled = compiler.compile_contract(p)
    p["task"] = "a different study"
    errors = compiler.validate_generated_contract(p, compiled)
    assert any("source fingerprint" in error for error in errors)


@pytest.mark.parametrize("bad_digest", ["notsha", "A" * 64, "1" * 63])
def test_formal_semantic_check_refuses_invalid_authenticity_hash(bad_digest):
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        compiler.make_semantic_check(bad_digest)


def test_normalize_requirement_strings_into_explicit_must_without_model_inference():
    p = plan()
    p["requirements"] = ["Measure the real output"]
    p["steps"][0]["covers"] = ["REQ-001"]
    contract = compiler.compile_contract(p)
    assert compiler.requirement_goal_fact("REQ-001") in contract["goal_facts"]


def test_compile_plan_rejects_unknown_anchor_step_not_rebind_it():
    with pytest.raises(ValueError, match="does not exist"):
        compiler.compile_plan(plan(), anchor_step=99)


def test_compile_plan_does_not_overwrite_user_manual_formal_model():
    p = plan()
    p["steps"][0]["verify"].insert(
        0,
        formal.make_formal_check(
            {
                "version": 1,
                "initial_facts": ["real"],
                "goal_facts": ["real"],
                "actions": [
                    {"step": 1, "preconditions": ["real"], "add_effects": [], "del_effects": []}
                ],
            }
        ),
    )
    with pytest.raises(ValueError, match="manual formal_planning"):
        compiler.compile_plan(p)


def test_compiler_repeated_execution_does_not_accumulate_duplicate_checks():
    first, raw, _ = compiler.compile_plan(plan())
    second, again, _ = compiler.compile_plan(first)
    assert raw == again
    checks = second["steps"][0]["verify"]
    assert sum("formal_planning" in check for check in checks) == 1
    assert sum(compiler._is_generated_semantic_check(check) for check in checks) == 1
