"""Formal requirement binding is structural and cannot invent producer evidence."""

from __future__ import annotations

import pytest

from supervisor import formal_semantics as fs


def fixture_plan():
    goal = fs.requirement_goal_fact("REQ-1")
    return {
        "requirements": [
            {"id": "REQ-1", "priority": "must", "description": "verified real outcome"}
        ],
        "steps": [
            {
                "id": 1,
                "covers": ["REQ-1"],
                "verify": [
                    {
                        "formal_planning": {
                            "goal_facts": [goal],
                            "initial_facts": [],
                            "actions": [{"step": 1, "add_effects": [goal], "del_effects": []}],
                        }
                    }
                ],
            }
        ],
    }


def test_valid_structured_goal_has_single_real_producer_and_serialized_evidence():
    out = fs.analyze_formal_semantics(fixture_plan())
    assert out.enabled and out.valid and not out.generated
    assert out.producer_steps == {"REQ-1": [1]}
    record = out.as_dict()
    assert record["requirement_facts"] == {"REQ-1": "requirement-satisfied:REQ-1"}
    assert record["producer_steps"] == {"REQ-1": [1]}
    assert record["errors"] == []


def test_empty_plan_has_explicitly_disabled_alignment():
    out = fs.analyze_formal_semantics({"requirements": ["must audit"]})
    assert out.enabled is False
    assert out.valid is True
    assert out.as_dict()["generated"] is False


def test_canonical_requirement_fact_refuses_unbounded_identifiers():
    with pytest.raises(ValueError, match="too long"):
        fs.requirement_goal_fact("REQ-" + "x" * 280)


@pytest.mark.parametrize(
    ("requirements", "count"),
    [
        ({"not": "an array"}, 0),
        (["ordinary text"], 1),
        ([12, {"id": "", "description": "blank"}, {}, None], 0),
        ([{"id": " R-1 ", "priority": "MUST"}], 1),
    ],
)
def test_untrusted_requirement_grammar_is_not_assumed_to_be_a_signed_goal(requirements, count):
    assert len(fs._requirements({"requirements": requirements})) == count


def test_structural_anchor_enumeration_ignores_nonobject_steps_and_checks():
    plan = fixture_plan()
    plan["steps"].insert(0, 1)
    plan["steps"][1]["verify"].insert(0, "not a check")
    assert len(fs._anchors(plan)) == 1


def test_multiple_formal_anchors_refuse_alignment_not_pick_the_favorable_one():
    plan = fixture_plan()
    plan["steps"].append({"id": 2, "verify": [{"formal_planning": {"goal_facts": []}}]})
    out = fs.analyze_formal_semantics(plan)
    assert out.enabled and not out.valid
    assert "exactly one" in out.errors[0]


def test_nonobject_contract_cannot_be_interpreted_as_verified_goal():
    plan = fixture_plan()
    plan["steps"][0]["verify"][0]["formal_planning"] = []
    out = fs.analyze_formal_semantics(plan)
    assert not out.valid
    assert "must be an object" in out.errors[0]


def test_multiple_generation_markers_are_refused_even_when_validator_returns_no_errors():
    plan = fixture_plan()
    plan["steps"][0]["verify"][0]["formal_planning"]["initial_facts"] = [
        "formalization-source:first",
        "formalization-source:second",
    ]
    out = fs.analyze_formal_semantics(plan, contract_validator=lambda *_args: [])
    assert out.generated and not out.valid
    assert any("exactly one formalization-source marker" in e for e in out.errors)


def test_generated_contract_recompilation_failure_is_explicit_not_silent():
    plan = fixture_plan()
    plan["steps"][0]["verify"][0]["formal_planning"]["initial_facts"] = [
        "formalization-source:original"
    ]

    def verifier(_plan, _contract):
        raise ValueError("recorded source changed")

    out = fs.analyze_formal_semantics(plan, contract_validator=verifier)
    assert out.generated and not out.valid
    assert any("could not be independently recompiled" in e for e in out.errors)


def test_invalid_steps_and_actions_are_not_counted_as_producers():
    plan = fixture_plan()
    plan["steps"].append({"not_an_id": 2, "covers": ["REQ-1"]})
    contract = plan["steps"][0]["verify"][0]["formal_planning"]
    contract["actions"].insert(0, "fake action")
    contract["actions"].insert(0, {"step": "1", "add_effects": ["requirement-satisfied:REQ-1"]})
    out = fs.analyze_formal_semantics(plan)
    assert out.valid
    assert out.producer_steps["REQ-1"] == [1]


def test_nonlist_actions_are_not_assumed_to_have_implicit_effects():
    plan = fixture_plan()
    plan["steps"][0]["verify"][0]["formal_planning"]["actions"] = "unstructured"
    out = fs.analyze_formal_semantics(plan)
    assert not out.valid
    assert any("no producing action" in e for e in out.errors)


def test_empty_action_effects_make_formal_model_invalid():
    plan = fixture_plan()
    plan["steps"][0]["verify"][0]["formal_planning"]["actions"] = [
        {"step": 1, "add_effects": [], "del_effects": []}
    ]
    out = fs.analyze_formal_semantics(plan)
    assert not out.valid
    assert any("no symbolic effect" in e for e in out.errors)


def test_priority_outside_must_should_does_not_gain_required_goal_binding():
    plan = fixture_plan()
    plan["requirements"] = [{"id": "REQ-1", "priority": "optional"}]
    out = fs.analyze_formal_semantics(plan)
    assert out.valid
    assert out.requirement_facts == {}
    assert out.warnings


def test_too_long_requirement_id_produces_an_explicit_error_not_an_exception():
    plan = fixture_plan()
    plan["requirements"] = [{"id": "REQ-" + "a" * 275, "priority": "must"}]
    out = fs.analyze_formal_semantics(plan)
    assert not out.valid
    assert any("too long" in e for e in out.errors)


def test_required_goal_cannot_be_preassumed_true_in_initial_facts():
    plan = fixture_plan()
    goal = fs.requirement_goal_fact("REQ-1")
    plan["steps"][0]["verify"][0]["formal_planning"]["initial_facts"] = [goal]
    out = fs.analyze_formal_semantics(plan)
    assert not out.valid
    assert any("already true initially" in e for e in out.errors)


def test_noncovering_step_cannot_satisfy_a_requirement():
    plan = fixture_plan()
    plan["steps"][0]["covers"] = []
    out = fs.analyze_formal_semantics(plan)
    assert not out.valid
    assert any("non-covering step" in e for e in out.errors)
    assert any("not produced by any step that covers" in e for e in out.errors)


def test_generated_structural_goal_does_not_create_requirement_warning():
    plan = fixture_plan()
    marker = "formalization-source:generated"
    extra = "step-completed:1"
    contract = plan["steps"][0]["verify"][0]["formal_planning"]
    contract["initial_facts"] = [marker]
    contract["goal_facts"].append(extra)
    contract["actions"][0]["add_effects"].append(extra)
    out = fs.analyze_formal_semantics(plan, contract_validator=lambda *_: [])
    assert out.generated and out.valid
    assert not out.warnings


def test_unbound_generated_custom_goal_is_reported_as_a_warning():
    plan = fixture_plan()
    contract = plan["steps"][0]["verify"][0]["formal_planning"]
    contract["initial_facts"] = ["formalization-source:generated"]
    contract["goal_facts"].append("custom-completion")
    contract["actions"][0]["add_effects"].append("custom-completion")
    out = fs.analyze_formal_semantics(plan, contract_validator=lambda *_: [])
    assert out.generated and out.valid
    assert any("custom-completion" in x for x in out.warnings)
