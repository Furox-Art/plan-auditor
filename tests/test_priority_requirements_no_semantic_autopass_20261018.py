"""Untrusted heuristic requirements cannot override higher-authority safety failures."""

from __future__ import annotations

import pytest

from supervisor.policies import RuleResult
from supervisor.priority import (
    LEVEL_AI_SEMANTIC_JUDGMENT,
    LEVEL_DETERMINISTIC_VERIFICATION,
    LEVEL_PROCESS_SAFETY,
    LEVEL_REQUIREMENT_COVERAGE,
    LEVEL_SECURITY_POLICY,
    PriorityVerdict,
    resolve_priority,
)
from supervisor.requirements import _assess_ambiguity, parse_requirements


def finding(name, level, triggered=True, detail=None):
    return RuleResult(
        rule_id=name,
        level=level,
        triggered=triggered,
        detail=detail if detail is not None else name,
    )


def test_empty_priority_report_explicitly_contains_no_contributing_evidence():
    result = PriorityVerdict(outcome="UNKNOWN")
    assert result.contributing == []


def test_no_triggered_rules_have_no_safety_blocker():
    r = resolve_priority([finding("untriggered", 0, False)])
    assert r.outcome == "PASS"
    assert r.blocking_level is None
    assert r.contributing == []


@pytest.mark.parametrize(
    "level",
    [
        LEVEL_PROCESS_SAFETY,
        LEVEL_DETERMINISTIC_VERIFICATION,
        LEVEL_SECURITY_POLICY,
    ],
)
def test_real_safety_failures_override_any_higher_semantic_claim(level):
    results = [
        finding("AI suggests success", LEVEL_AI_SEMANTIC_JUDGMENT, True),
        finding("unsafe evidence", level, True, detail="actual failed security check"),
        finding("irrelevant", 0, False),
    ]
    out = resolve_priority(results)
    assert out.outcome == "FAIL"
    assert out.blocking_level == level
    assert out.blocking_detail == "actual failed security check"
    assert len(out.contributing) == 2


def test_requirement_gap_is_unknown_never_semantically_auto_approved():
    out = resolve_priority([finding("uncovered requirement", LEVEL_REQUIREMENT_COVERAGE)])
    assert out.outcome == "UNKNOWN"
    assert out.blocking_level == LEVEL_REQUIREMENT_COVERAGE


def test_ai_semantic_warning_is_not_a_deterministic_pass():
    out = resolve_priority([finding("model generated narrative", LEVEL_AI_SEMANTIC_JUDGMENT)])
    assert out.outcome == "FAIL"
    assert out.blocking_level == LEVEL_AI_SEMANTIC_JUDGMENT


def test_tie_at_same_priority_is_deterministic_and_preserves_all_triggered_evidence():
    out = resolve_priority([finding("first", 1, True), finding("second", 1, True)])
    assert out.blocking_detail == "first"
    assert [f[0] for f in out.contributing] == ["first", "second"]


@pytest.mark.parametrize(
    ("input_text", "expected"),
    [
        ("Maybe something, etc. and so on", "high"),
        ("Perhaps compare the datasets", "medium"),
        ("Use direct raw measurements", "none"),
    ],
)
def test_ambiguity_has_explicit_mechanical_status_not_a_proof(input_text, expected):
    assert _assess_ambiguity(input_text) == expected


def test_heuristic_requirements_do_not_fabricate_implementation_or_test_success():
    r = parse_requirements("MUST verify direct records\nMaybe check calibration")
    assert len(r) == 2
    assert [x.priority for x in r] == ["must", "should"]
    assert [x.ambiguity for x in r] == ["none", "medium"]
    assert all(x.verification_strategy == "deterministic" for x in r)
    assert all("implementation exists" in x.acceptance_criteria for x in r)


def test_blank_short_fragment_has_explicit_unverified_fallback_requirement():
    r = parse_requirements("-x\n ab ")
    assert len(r) == 1
    assert r[0].id == "REQ-001"
    assert r[0].description == "-x\n ab"
