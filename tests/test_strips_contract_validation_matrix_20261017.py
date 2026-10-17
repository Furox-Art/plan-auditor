"""Scientific planning checks reject malformed STRIPS evidence rather than guessing repairs."""

from __future__ import annotations

import pytest

from supervisor import formal_planning as formal


def raw_contract():
    return {
        "version": 1,
        "initial_facts": ["start"],
        "goal_facts": ["verified"],
        "actions": [
            {"step": 1, "preconditions": ["start"], "add_effects": ["artifact"], "del_effects": []},
            {
                "step": 2,
                "preconditions": ["artifact"],
                "add_effects": ["verified"],
                "del_effects": [],
            },
        ],
    }


def plan(raw):
    return {
        "steps": [
            {
                "id": 1,
                "title": "build",
                "depends_on": [],
                "verify": [formal.make_formal_check(raw)],
            },
            {"id": 2, "title": "verify", "depends_on": [1], "verify": []},
        ]
    }


def test_real_two_step_formal_plan_has_deterministic_order_and_goal_proof():
    p = plan(raw_contract())
    result = formal.analyze_formal_contract(p)
    assert result.verdict == "PASS"
    assert result.solution_order == [1, 2]
    assert result.explored_states >= 2
    assert result.monotonic
    assert result.contract_sha256 == formal.contract_sha256(raw_contract())


@pytest.mark.parametrize(
    ("key", "value", "pattern"),
    [
        ("version", 2, "version must be 1"),
        ("initial_facts", "invalid", "must be a list"),
        ("initial_facts", ["start", "start"], "duplicate facts"),
        ("initial_facts", [0], "must be a non-empty string"),
        ("initial_facts", ["x" * 257], "exceeds 256"),
        ("goal_facts", [], "must not be empty"),
        ("goal_facts", ["unknown"], "no initial/producer source"),
        ("goal_facts", ["verified", "verified"], "duplicate facts"),
        ("actions", "wrong", "actions must be a list"),
        ("unexpected", "invalid", "unknown field"),
    ],
)
def test_rejects_invalid_or_unidentifiable_formal_contract_root(key, value, pattern):
    raw = raw_contract()
    raw[key] = value
    result = formal.analyze_formal_contract(plan(raw))
    assert result.verdict == "REJECT"
    assert any(pattern in err for err in result.errors)


@pytest.mark.parametrize(
    ("action", "pattern"),
    [
        ({}, "step must be a positive integer"),
        ({"step": False}, "step must be a positive integer"),
        ({"step": 3}, "references unknown step"),
        (
            {"step": 1, "preconditions": "wrong", "add_effects": [], "del_effects": []},
            "preconditions must be a list",
        ),
        (
            {"step": 1, "preconditions": [], "add_effects": ["x"], "del_effects": ["x"]},
            "adds and deletes",
        ),
        (
            {"step": 1, "preconditions": ["does-not-exist"], "add_effects": [], "del_effects": []},
            "no initial/producer source",
        ),
        (
            {"step": 1, "preconditions": [], "add_effects": [], "del_effects": ["no-such"]},
            "deletes fact(s)",
        ),
        (
            {"step": 1, "preconditions": [], "add_effects": [], "del_effects": [], "surprise": 1},
            "unknown field",
        ),
    ],
)
def test_each_action_has_exact_contract_and_no_hidden_fact_generation(action, pattern):
    raw = raw_contract()
    raw["actions"][0] = action
    result = formal.analyze_formal_contract(plan(raw))
    assert result.verdict == "REJECT"
    assert any(pattern in err for err in result.errors)


def test_multiple_formal_anchors_are_rejected_as_ambiguous_authority():
    p = plan(raw_contract())
    p["steps"][1]["verify"].append(formal.make_formal_check(raw_contract()))
    result = formal.analyze_formal_contract(p)
    assert result.verdict == "REJECT"
    assert "exactly one" in result.reason


def test_missing_formal_anchor_has_no_fabricated_proof():
    p = {"steps": [{"id": 1, "verify": []}]}
    result = formal.analyze_formal_contract(p)
    assert result.enabled is False
    assert result.solution_order == []


def test_formal_check_with_wrong_argument_digest_is_rejected_even_when_contract_is_valid():
    p = plan(raw_contract())
    p["steps"][0]["verify"][0]["argv"][-1] = "0" * 64
    out = formal.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("canonical argv" in err for err in out.errors)


@pytest.mark.parametrize(
    ("bad_argv", "pattern"),
    [
        (["not-a-program"], "canonical argv"),
        ({"cmd": "shell"}, "structured argv"),
    ],
)
def test_formal_anchor_enforces_structured_command_not_shell_guessing(bad_argv, pattern):
    p = plan(raw_contract())
    p["steps"][0]["verify"][0]["argv"] = bad_argv
    out = formal.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any(pattern in error for error in out.errors)


def test_real_pddl_export_preserves_dependencies_and_goal_predicates():
    p = plan(raw_contract())
    domain, problem, mapping = formal.export_pddl(p, raw_contract())
    assert "(:requirements :strips)" in domain
    assert "(:action step-1" in domain
    assert "(:action step-2" in domain
    assert "(done-step-1)" in domain
    assert "(unused-step-2)" in problem
    assert f"({mapping['verified']})" in problem


def test_formal_pddl_export_refuses_incomplete_malformed_contract():
    raw = raw_contract()
    raw["goal_facts"] = ["imaginary"]
    with pytest.raises(ValueError, match="invalid formal planning contract"):
        formal.export_pddl(plan(raw), raw)


def test_nonmonotonic_planning_distinguishes_deleted_resource_dead_end():
    raw = raw_contract()
    raw["actions"][0]["del_effects"] = ["start"]
    raw["actions"][1]["preconditions"] = ["start", "artifact"]
    out = formal.analyze_formal_contract(plan(raw))
    assert out.monotonic is False
    assert out.verdict == "REJECT"


def test_state_budget_exhaustion_is_reported_unknown_not_as_a_verified_solution():
    raw = raw_contract()
    raw["actions"][0]["del_effects"] = ["start"]
    out = formal.analyze_formal_contract(plan(raw), max_states=0)
    assert out.monotonic is False
    assert out.verdict == "UNKNOWN"
    assert "state-space exceeded" in out.reason


def test_formal_actions_without_effects_are_not_claimed_as_sufficient_proof():
    raw = {
        "version": 1,
        "initial_facts": ["ready"],
        "goal_facts": ["ready"],
        "actions": [{"step": 1, "preconditions": ["ready"], "add_effects": [], "del_effects": []}],
    }
    p = {"steps": [{"id": 1, "verify": [formal.make_formal_check(raw)]}]}
    out = formal.analyze_formal_contract(p)
    assert out.verdict == "PASS"
    assert any("effect-free" in warning for warning in out.warnings)
