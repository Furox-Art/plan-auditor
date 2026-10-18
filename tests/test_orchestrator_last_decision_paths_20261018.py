"""The integrated gate preserves all independently observed adverse outcomes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from supervisor import orchestrator as audit
from supervisor.config import Config, Profile


def _context(monkeypatch, tmp_path, names=("default",), outcomes=None):
    """Real top-level aggregation with explicitly controlled external dependencies."""
    cfg = Config(workspace_root=str(tmp_path))
    cfg.profile = Profile.STANDARD
    cfg.policies_dir = ".plan-auditor/policies"
    monkeypatch.setattr(audit, "load_config", lambda _: cfg)
    request = SimpleNamespace(
        valid=True,
        request={"task": "verify authenticated evidence"},
        activated=False,
        reason="",
        as_dict=lambda: {"valid": True},
    )
    monkeypatch.setattr(audit, "verify_request_contract", lambda _: request)
    monkeypatch.setattr(audit, "auditor_state_present", lambda _: False)
    refs = [audit.PlanRef(name, tmp_path / f"{name}.json") for name in names]
    monkeypatch.setattr(audit, "all_plan_refs", lambda _root: refs)
    monkeypatch.setattr(audit, "load_plan_ref", lambda _: {"steps": [{"id": 1}]})
    alignment = SimpleNamespace(errors=[], as_dict=lambda: {"valid": True})
    monkeypatch.setattr(audit, "analyze_request_alignment", lambda *_: alignment)
    state = SimpleNamespace(
        available_tools={},
        to_dict=lambda: {"snapshot": "observed-only"},
    )
    monkeypatch.setattr(audit, "capture_workspace", lambda _: state)
    monkeypatch.setattr(audit, "_tail_logs", lambda _: [])
    monkeypatch.setattr(audit.core, "verify_chain", lambda _: (True, 0, ""))
    monkeypatch.setattr(audit, "verify_anchor_chain", lambda _: {"anchored": True})
    monkeypatch.setattr(audit.core, "evidence_is_authenticated", lambda _: (True, ""))

    class Registry:
        def __init__(self, *args, **kwargs):
            self.owner_timeout = 1

        def release_stale_ownership(self):
            return []

        def active_agents(self):
            return []

        def verify_registry_chain(self):
            return True

    monkeypatch.setattr(audit, "MultiAgentRegistry", Registry)
    monkeypatch.setattr(audit, "_agent_conflicts", lambda _: [])
    monkeypatch.setattr(audit, "load_policy_rules_from_dir", lambda *_args, **_kwargs: [])
    decisions = outcomes or {name: "PASS" for name in names}
    monkeypatch.setattr(
        audit,
        "_evaluate_plan",
        lambda root, ref, *_a: {"outcome": decisions[ref.name], "plan_name": ref.name},
    )
    return cfg, refs


@pytest.mark.parametrize(
    ("decisions", "expected"),
    [
        ({"default": "PASS"}, "PASS"),
        ({"default": "UNKNOWN"}, "UNKNOWN"),
        ({"default": "INVALID"}, "FAIL"),
        ({"default": "FAIL"}, "FAIL"),
    ],
)
def test_no_aggregate_success_can_be_fabricated_from_an_invalid_plan_status(
    monkeypatch, tmp_path, decisions, expected
):
    _context(monkeypatch, tmp_path, outcomes=decisions)
    out = audit.evaluate_workspace(str(tmp_path))
    assert out["outcome"] == expected
    assert out["plans"]["default"]["outcome"] == decisions["default"]
    assert out["active_plan_count"] == 1


def test_multiple_plans_without_default_have_no_fabricated_primary_projection(
    monkeypatch, tmp_path
):
    _context(monkeypatch, tmp_path, names=("a", "b"), outcomes={"a": "PASS", "b": "PASS"})
    out = audit.evaluate_workspace(str(tmp_path))
    assert out["outcome"] == "PASS"
    assert out["active_plan_count"] == 2
    assert "gate" not in out


def test_mixed_plan_outcomes_aggregate_to_unknown_or_fail(monkeypatch, tmp_path):
    _context(
        monkeypatch,
        tmp_path,
        names=("default", "other"),
        outcomes={"default": "PASS", "other": "UNKNOWN"},
    )
    assert audit.evaluate_workspace(str(tmp_path))["outcome"] == "UNKNOWN"


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"profile": "future-nonexistent"}, "invalid requested profile"),
        ({"mode": "illegal-parallel-mode"}, "invalid requested mode"),
    ],
)
def test_explicit_user_mode_and_profile_errors_are_preserved_in_result(
    monkeypatch, tmp_path, kw, message
):
    _context(monkeypatch, tmp_path, names=())
    out = audit.evaluate_workspace(str(tmp_path), **kw)
    assert out["outcome"] == "NO_PLAN"
    assert any(message in e for e in out["configuration_errors"])


def test_plan_parse_failure_is_recorded_as_request_error_not_silent_drop(monkeypatch, tmp_path):
    _context(monkeypatch, tmp_path)

    def failure(_):
        raise ValueError("untrusted plan parse failed")

    monkeypatch.setattr(audit, "load_plan_ref", failure)
    out = audit.evaluate_workspace(str(tmp_path))
    assert out["outcome"] == "PASS"  # stubbed plan evaluator only
    assert any("untrusted plan parse failed" in x for x in out["policy_errors"])


def test_duplicate_policy_directory_is_scanned_once(monkeypatch, tmp_path):
    _context(monkeypatch, tmp_path)
    visited = []
    monkeypatch.setattr(
        audit, "load_policy_rules_from_dir", lambda p, *, errors: visited.append(p) or []
    )
    audit.evaluate_workspace(str(tmp_path))
    assert len(visited) == 1


def test_invalid_plan_ref_fails_locally_and_preserves_plan_name(monkeypatch, tmp_path):
    cfg = Config(workspace_root=str(tmp_path))
    ref = audit.PlanRef("experiment", tmp_path / "missing-plan.json")
    monkeypatch.setattr(
        audit, "load_plan_ref", lambda _: (_ for _ in ()).throw(ValueError("corrupt signed JSON"))
    )
    out = audit._evaluate_plan(
        tmp_path,
        ref,
        cfg,
        SimpleNamespace(available_tools={}, to_dict=lambda: {}),
        [],
        True,
        1,
        "",
        True,
        "",
        {"anchored": True},
        SimpleNamespace(active_agents=lambda: []),
        True,
        [],
        [],
        [],
    )
    assert out == {
        "outcome": "FAIL",
        "plan_name": "experiment",
        "error": "invalid plan: corrupt signed JSON",
    }


def _plan_evaluation(monkeypatch, tmp_path, seal=None, profile=Profile.STANDARD, auth=True):
    cfg = Config(workspace_root=str(tmp_path), profile=profile)
    ref = audit.PlanRef("default", tmp_path / "plan.json")
    model = {"task": "test", "steps": [{"id": 1, "status": "verified", "verify": []}]}
    monkeypatch.setattr(audit, "load_plan_ref", lambda _: model)
    monkeypatch.setattr(audit.core, "validate_plan", lambda _: [])
    monkeypatch.setattr(
        audit,
        "verify_plan",
        lambda *a, **kw: SimpleNamespace(
            verdict="PASS",
            coverage=None,
            rationale=[],
            weakest_verification=None,
            graph_errors=[],
            coverage_gaps=[],
            topological_order=[1],
            dependencies={1: []},
        ),
    )
    monkeypatch.setattr(audit, "environment_contract", lambda *a: {})
    monkeypatch.setattr(
        audit, "fresh_full_audit_proof", lambda *_: audit.FreshAuditProof(True, "observed")
    )
    monkeypatch.setattr(audit, "load_seal", lambda _: seal)
    monkeypatch.setattr(audit, "run_adversarial_review", lambda *a, **k: audit.AdversarialReport())
    monkeypatch.setattr(audit, "_required_tools", lambda *_: [])
    state = SimpleNamespace(available_tools={}, to_dict=lambda: {})
    registry = SimpleNamespace(active_agents=lambda: [])
    return lambda: audit._evaluate_plan(
        tmp_path,
        ref,
        cfg,
        state,
        [],
        True,
        1,
        "",
        auth,
        "missing hmac evidence",
        {"anchored": True},
        registry,
        True,
        [],
        [],
        [],
    )


def test_missing_seal_prevents_completion_even_if_every_other_layer_claims_pass(
    monkeypatch, tmp_path
):
    result = _plan_evaluation(monkeypatch, tmp_path)()
    assert result["seal"]["ok"] is False
    assert result["outcome"] == "FAIL"


def test_strict_profile_runs_independent_adversarial_review(monkeypatch, tmp_path):
    called = []
    runner = _plan_evaluation(monkeypatch, tmp_path, profile=Profile.STRICT)
    monkeypatch.setattr(
        audit,
        "run_adversarial_review",
        lambda *a, **kw: called.append(kw) or audit.AdversarialReport(),
    )
    result = runner()
    assert len(called) == 1
    assert "evidence_path" in called[0]
    assert result["adversarial"]["used_llm"] is False


def test_untrusted_seal_integrity_error_never_becomes_a_valid_seal(monkeypatch, tmp_path):
    runner = _plan_evaluation(monkeypatch, tmp_path)
    monkeypatch.setattr(
        audit,
        "load_seal",
        lambda _: (_ for _ in ()).throw(audit.SealIntegrityError("tampered seal")),
    )
    result = runner()
    assert not result["seal"]["ok"]
    assert "tampered seal" in result["seal"]["violations"][0]


def test_no_hmac_authentication_requires_explicit_failure_note(monkeypatch, tmp_path):
    result = _plan_evaluation(monkeypatch, tmp_path, auth=False)()
    assert result["outcome"] == "FAIL"
    assert result["evidence"]["authenticated"] is False
    assert any("evidence is not authenticated" in x for x in result["gate"]["notes"])


@pytest.mark.parametrize(
    "records",
    [
        [{"name": "unexpected", "passed": True, "results": []}],
        [{"name": "artifact", "passed": False, "results": []}],
        [
            {
                "name": "artifact",
                "passed": True,
                "results": [{"check": {"type": "run"}, "passed": True}],
            }
        ],
    ],
)
def test_declared_output_must_match_verified_contract_checks(monkeypatch, records):
    source = {"id": 1, "verify": []}
    monkeypatch.setattr(
        audit,
        "output_index",
        lambda _: {"artifact": {"verify": [{"type": "pytest", "args": "tests"}]}},
    )
    doc = {"results": [], "dependencies": [], "outputs": records, "required_outputs": []}
    assert not audit._checks_match(source, doc, [], {1: source})


def test_upstream_reference_requires_an_actual_object_and_matching_check(monkeypatch):
    source = {"id": 1, "verify": []}
    target = {"id": 2, "verify": []}
    monkeypatch.setattr(
        audit,
        "output_index",
        lambda s: (
            {"artifact": {"verify": [{"type": "pytest", "args": "tests"}]}} if s["id"] == 1 else {}
        ),
    )
    monkeypatch.setattr(
        audit,
        "required_outputs",
        lambda s: [{"step": 1, "name": "artifact"}] if s["id"] == 2 else [],
    )
    doc = {"results": [], "dependencies": [1], "outputs": [], "required_outputs": [42]}
    assert not audit._checks_match(target, doc, [1], {1: source, 2: target})
    doc["required_outputs"] = [{"step": 1, "name": "artifact", "passed": True, "results": []}]
    assert not audit._checks_match(target, doc, [1], {1: source, 2: target})


def test_no_known_outcome_is_not_interpreted_as_completed_lifecycle():
    state = audit._lifecycle_for(True, True, [], audit.FreshAuditProof(False, ""), "INVESTIGATE")
    assert "final_audit" in str(state.state).lower()


def test_known_explicit_safe_parallel_mode_is_recorded_without_configuration_error(
    monkeypatch, tmp_path
):
    _context(monkeypatch, tmp_path, names=())
    out = audit.evaluate_workspace(str(tmp_path), mode="parallel-strict")
    assert out["mode"] == "parallel-strict"
    assert not any("invalid requested mode" in e for e in out["configuration_errors"])


def test_absent_request_contract_does_not_become_a_successful_request_alignment(
    monkeypatch, tmp_path
):
    _context(monkeypatch, tmp_path)
    invalid = SimpleNamespace(
        valid=False,
        request=None,
        activated=True,
        reason="HMAC request contract unavailable",
        as_dict=lambda: {"valid": False, "reason": "HMAC request contract unavailable"},
    )
    monkeypatch.setattr(audit, "verify_request_contract", lambda _: invalid)
    out = audit.evaluate_workspace(str(tmp_path))
    assert out["request_alignment"]["valid"] is False
    assert any("HMAC request contract unavailable" in e for e in out["policy_errors"])


def test_legacy_seal_refused_even_with_an_earlier_valid_audit_proof(monkeypatch, tmp_path):
    old = SimpleNamespace(format_version=audit.MINIMUM_TRUSTED_SEAL_FORMAT - 1)
    report = _plan_evaluation(monkeypatch, tmp_path, seal=old)()
    assert report["outcome"] == "FAIL"
    assert report["seal"]["present"] is True
    assert report["seal"]["ok"] is False
    assert any("legacy seal requires explicit reseal" in x for x in report["seal"]["violations"])


def test_missing_hmac_evidence_note_is_not_doubled_when_gate_already_reported_it(
    monkeypatch, tmp_path
):
    runner = _plan_evaluation(monkeypatch, tmp_path, auth=False)
    note = "evidence is not authenticated: missing hmac evidence"

    class ExplicitGate:
        def __init__(self, _engine):
            pass

        def evaluate(self, **_kwargs):
            return SimpleNamespace(
                notes=[note],
                outcome="FAIL",
                as_dict=lambda: {"notes": [note]},
            )

    monkeypatch.setattr(audit, "CompletionGate", ExplicitGate)
    out = runner()
    assert out["gate"]["notes"] == [note]


def test_invalid_nonmapping_output_record_is_refused_early(monkeypatch):
    step = {"id": 1, "verify": []}
    monkeypatch.setattr(audit, "output_index", lambda _: {"artifact": {"verify": []}})
    record = {
        "results": [],
        "dependencies": [],
        "outputs": [42],
        "required_outputs": [],
    }
    assert audit._checks_match(step, record, [], {1: step}) is False
