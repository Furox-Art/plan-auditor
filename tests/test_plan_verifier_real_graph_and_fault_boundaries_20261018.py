"""Plan acceptance requires behavioral checks, bound outputs and valid requirements."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.plan_graph import PlanGraphError
from supervisor import plan_verifier as pv


def checked_step(sid, *, check="pytest", deps=None):
    result = {"id": sid, "verify": [{"type": check, "args": "tests"}]}
    if deps is not None:
        result["depends_on"] = deps
    return result


def test_no_steps_is_rejected_with_explicit_reason():
    for source in ({"steps": []}, {"steps": None}, {"steps": "not-an-array"}):
        result = pv.verify_plan(source)
        assert result.verdict == "REJECT"
        assert "plan has no steps" in result.rationale


def test_simple_verified_step_is_a_real_behavioral_candidate_not_auto_proof():
    result = pv.verify_plan({"steps": [checked_step(1)]})
    assert result.verdict == "PASS"
    assert result.step_analyses[0].has_behavioral_verification
    assert result.weakest_verification is None


@pytest.mark.parametrize("type_", ["file_exists", "regex"])
def test_single_weak_check_cannot_produce_a_verified_plan(type_):
    result = pv.verify_plan({"steps": [checked_step(1, check=type_)]})
    assert result.verdict == "REJECT"
    assert result.weakest_verification == "step 1 lacks behavioral verification"
    assert "no step has behavioral verification" in result.rationale


def test_mixed_strong_and_weak_steps_require_revision_not_fabricated_success():
    result = pv.verify_plan(
        {"steps": [checked_step(1, deps=[]), checked_step(2, check="regex", deps=[])]}
    )
    assert result.verdict == "REVISE"
    assert "1/2 steps lack behavioral verification" in result.rationale
    assert result.weakest_verification == "step 2 lacks behavioral verification"


def test_empty_verification_is_recorded_as_missing_not_only_as_weak():
    result = pv._check_step({"id": 1, "verify": []}, 1, [])
    assert not result.has_behavioral_verification
    assert any("has no verification" in x for x in result.risks)
    assert any("behavioral check" in x for x in result.suggestions)


def test_step_file_output_parse_errors_are_retained_in_check_risks(monkeypatch):
    def fail(_):
        raise PlanGraphError("invalid declared file output")

    monkeypatch.setattr(pv, "output_index", fail)
    out = pv._check_step({"id": 3, "verify": [{"type": "pytest"}]}, 3, [1])
    assert "invalid declared file output" in out.risks
    assert out.declared_outputs == []


def test_step_input_output_dependency_parse_errors_are_retained(monkeypatch):
    def fail(_):
        raise PlanGraphError("unbound upstream data requirement")

    monkeypatch.setattr(pv, "required_outputs", fail)
    out = pv._check_step({"id": 3, "verify": [{"type": "pytest"}]}, 3, [1])
    assert "unbound upstream data requirement" in out.risks
    assert out.required_outputs == []


def test_unbound_explicit_edges_reject_unsupported_upstream_step_mapping(monkeypatch):
    monkeypatch.setattr(pv, "explicit_graph", lambda _: True)
    monkeypatch.setattr(pv, "required_outputs", lambda _: [])
    errors = pv._unbound_explicit_edges(
        {"steps": [checked_step(1, deps=[]), checked_step(2, deps=[])]},
        {2: [1]},
    )
    assert len(errors) == 1
    assert "no requires_outputs link" in errors[0]


def test_unbound_edge_scan_does_not_crash_on_invalid_structural_refs(monkeypatch):
    monkeypatch.setattr(pv, "explicit_graph", lambda _: True)

    def malformed(_):
        raise PlanGraphError("malformed source link")

    monkeypatch.setattr(pv, "required_outputs", malformed)
    assert pv._unbound_explicit_edges({"steps": [checked_step(2)]}, {2: [1]}) == []


def test_explicit_graph_not_declared_means_no_unbound_edge_fabrication(monkeypatch):
    monkeypatch.setattr(pv, "explicit_graph", lambda _: False)
    assert pv._unbound_explicit_edges({"steps": []}, {4: [3]}) == []


def test_verified_step_without_covers_does_not_activate_implicit_coverage_check(monkeypatch):
    calls = []
    monkeypatch.setattr(pv, "analyze_coverage", lambda _: calls.append(True))
    result = pv.verify_plan({"steps": [checked_step(1)]})
    assert result.coverage is None
    assert calls == []


def test_explicit_requirement_coverage_failure_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(
        pv,
        "analyze_coverage",
        lambda _: SimpleNamespace(valid=False, errors=["REQ-1 has no verified step"]),
    )
    plan = {"steps": [checked_step(1)], "requirements": [{"id": "REQ-1"}]}
    assert pv.verify_plan(plan).verdict == "REVISE"
    assert pv.verify_plan(plan, require_coverage=True).verdict == "REJECT"


def test_invalid_graph_dependency_never_becomes_corrected_in_memory(monkeypatch):
    def fail(_):
        raise PlanGraphError("cycle detected in declared dependencies")

    monkeypatch.setattr(pv, "effective_dependencies", fail)
    out = pv.verify_plan({"steps": [checked_step(1), checked_step(2)]})
    assert out.verdict == "REJECT"
    assert "dependency graph is invalid" in out.rationale
    assert out.dependencies == {1: [], 2: []}


def test_output_contract_violation_is_a_fatal_graph_error(monkeypatch):
    monkeypatch.setattr(pv, "validate_output_links", lambda _: ["invalid output checksum"])
    out = pv.verify_plan({"steps": [checked_step(1)]})
    assert out.verdict == "REJECT"
    assert "invalid output checksum" in out.graph_errors


def test_graph_edge_unsupported_by_source_output_is_a_fatal_graph_error(monkeypatch):
    monkeypatch.setattr(
        pv,
        "_unbound_explicit_edges",
        lambda *_: ["dependency edge 1 -> 2 has no source fact"],
    )
    out = pv.verify_plan({"steps": [checked_step(1, deps=[]), checked_step(2, deps=[])]})
    assert out.verdict == "REJECT"
    assert any("lack concrete output bindings" in s for s in out.rationale)


def test_invalid_nonobject_step_is_not_counted_as_a_behavioral_verified_step():
    plan = {"steps": [checked_step(1), 123]}
    out = pv.verify_plan(plan)
    assert len(out.step_analyses) == 1
    assert all(step.step_id == 1 for step in out.step_analyses)


def test_symbolic_formal_rejection_overrides_seemingly_verified_behavior(monkeypatch):
    monkeypatch.setattr(
        pv,
        "analyze_formal_contract",
        lambda _: SimpleNamespace(enabled=True, verdict="REJECT", errors=["goal has no producer"]),
    )
    monkeypatch.setattr(
        pv,
        "analyze_formal_semantics",
        lambda _: SimpleNamespace(valid=True, errors=[]),
    )
    out = pv.verify_plan({"steps": [checked_step(1)]})
    assert out.verdict == "REJECT"
    assert "goal has no producer" in out.contradictions


def test_inconclusive_symbolic_search_is_a_revision_not_a_pass(monkeypatch):
    monkeypatch.setattr(
        pv,
        "analyze_formal_contract",
        lambda _: SimpleNamespace(enabled=True, verdict="UNKNOWN", errors=[]),
    )
    monkeypatch.setattr(
        pv,
        "analyze_formal_semantics",
        lambda _: SimpleNamespace(valid=True, errors=[]),
    )
    out = pv.verify_plan({"steps": [checked_step(1)]})
    assert out.verdict == "REVISE"
    assert any("did not reach a conclusive result" in x for x in out.rationale)


def test_symbolic_contract_semantic_mismatch_is_an_explicit_rejection(monkeypatch):
    monkeypatch.setattr(
        pv,
        "analyze_formal_contract",
        lambda _: SimpleNamespace(enabled=True, verdict="PASS", errors=[]),
    )
    monkeypatch.setattr(
        pv,
        "analyze_formal_semantics",
        lambda _: SimpleNamespace(valid=False, errors=["REQ-1 has no bound producing action"]),
    )
    out = pv.verify_plan({"steps": [checked_step(1)]})
    assert out.verdict == "REJECT"
    assert "REQ-1 has no bound producing action" in out.contradictions
