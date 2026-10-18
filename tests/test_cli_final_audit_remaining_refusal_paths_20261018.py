"""Real CLI final-audit selection and fail-closed control-flow regressions."""

from __future__ import annotations

import argparse
import contextlib
from types import SimpleNamespace

import pytest

import supervisor.cli as c
from supervisor.config import load_config
from supervisor.sealing import MonotonicCheck, SealIntegrityError


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    import supervisor.agents as agent_module
    import supervisor.audit_session as session
    import supervisor.config as config_module
    import supervisor.contracts as contracts
    import supervisor.orchestrator as orchestrator
    import supervisor.plans as plans
    import supervisor.sealing as sealing

    ref = SimpleNamespace(key="default", name="default")
    monkeypatch.setattr(c, "_selected_refs", lambda root, name: [ref])
    status = SimpleNamespace(valid=True, as_dict=lambda: {"valid": True})
    monkeypatch.setattr(c, "_request_gate", lambda root: (status, None, []))
    cfg = load_config(str(tmp_path))
    monkeypatch.setattr(config_module, "load_config", lambda root: cfg)
    monkeypatch.setattr(c, "_policy_errors", lambda root, config: [])
    monkeypatch.setattr(contracts, "environment_contract", lambda root, config: {})
    monkeypatch.setattr(plans, "load_plan_ref", lambda ref: {"task": "audit", "steps": []})
    monkeypatch.setattr(plans, "seal_path", lambda root, name: tmp_path / "seal.json")
    seal = SimpleNamespace(format_version=4, as_plan=lambda: {"task": "audit", "steps": []})
    monkeypatch.setattr(sealing, "load_seal", lambda path: seal)
    monkeypatch.setattr(
        sealing, "check_monotonic", lambda before, now: MonotonicCheck(True, [], [])
    )
    monkeypatch.setattr(sealing, "check_environment", lambda s, env: MonotonicCheck(True, [], []))
    monkeypatch.setattr(agent_module, "MultiAgentRegistry", lambda *args, **kwargs: object())
    monkeypatch.setattr(session, "final_audit_session", lambda root, reg: contextlib.nullcontext())
    assessment = {
        "outcome": "PASS",
        "plans": {"default": {"outcome": "PASS"}},
        "gate": {"outcome": "PASS"},
    }
    monkeypatch.setattr(orchestrator, "evaluate_workspace", lambda *args, **kwargs: assessment)
    seen = []
    monkeypatch.setattr(c, "_forward_core", lambda argv: seen.append(argv) or 0)
    monkeypatch.setattr(c, "_json", lambda payload: seen.append(payload))
    args = argparse.Namespace(dir=str(tmp_path), plan=None)
    return SimpleNamespace(
        cfg=cfg,
        ref=ref,
        seal=seal,
        sealing=sealing,
        plans=plans,
        session=session,
        orchestrator=orchestrator,
        args=args,
        seen=seen,
        assessment=assessment,
    )


def test_valid_final_audit_calls_independent_core_and_gate(prepared):
    assert c.cmd_audit(prepared.args) == 0
    assert any(isinstance(x, list) and x[0] == "audit" for x in prepared.seen)
    assert prepared.seen[-1]["outcome"] == "PASS"


def test_invalid_config_must_stop_before_auditing(prepared):
    prepared.cfg.errors.append("invalid config")
    assert c.cmd_audit(prepared.args) == 2
    assert not any(isinstance(x, list) for x in prepared.seen)


def test_unreadable_plan_in_final_audit_refuses(prepared, monkeypatch):
    def bad(_):
        raise ValueError("invalid JSON")

    monkeypatch.setattr(prepared.plans, "load_plan_ref", bad)
    assert c.cmd_audit(prepared.args) == 2
    assert "invalid JSON" in prepared.seen[-1]["reason"]


def test_missing_seal_refuses_deterministic_audit(prepared, monkeypatch):
    monkeypatch.setattr(prepared.sealing, "load_seal", lambda path: None)
    assert c.cmd_audit(prepared.args) == 2
    assert "not sealed" in prepared.seen[-1]["reason"]


def test_legacy_seal_refuses_deterministic_audit(prepared):
    prepared.seal.format_version = 3
    assert c.cmd_audit(prepared.args) == 2
    assert "legacy seal" in prepared.seen[-1]["reason"]


def test_mutated_seal_refuses_deterministic_audit(prepared, monkeypatch):
    monkeypatch.setattr(
        prepared.sealing, "check_monotonic", lambda a, b: MonotonicCheck(False, ["weakened"], [])
    )
    assert c.cmd_audit(prepared.args) == 2
    assert "weakened" in prepared.seen[-1]["violations"]


def test_seal_parse_error_refuses_deterministic_audit(prepared, monkeypatch):
    def corrupt(path):
        raise SealIntegrityError("seal tampered")

    monkeypatch.setattr(prepared.sealing, "load_seal", corrupt)
    assert c.cmd_audit(prepared.args) == 2
    assert "seal tampered" in prepared.seen[-1]["reason"]


def test_nondefault_plan_is_forwarded_by_explicit_name(prepared):
    prepared.ref.name = "named"
    assert c.cmd_audit(prepared.args) == 0
    argv = next(x for x in prepared.seen if isinstance(x, list))
    assert argv[-2:] == ["--plan", "named"]


def test_failed_deterministic_core_retains_failure(prepared, monkeypatch):
    monkeypatch.setattr(c, "_forward_core", lambda argv: 2)
    assert c.cmd_audit(prepared.args) == 2
    assert not prepared.seen


@pytest.mark.parametrize("outcome,expected", [("UNKNOWN", 3), ("FAIL", 2)])
def test_nonpass_independent_gate_never_claims_success(prepared, outcome, expected):
    prepared.assessment["outcome"] = outcome
    assert c.cmd_audit(prepared.args) == expected
    assert prepared.seen[-1]["outcome"] == outcome


def test_final_audit_lock_failure_is_reported(prepared, monkeypatch):
    from supervisor.audit_session import AuditSessionError

    def blocked(root, registry):
        raise AuditSessionError("cannot establish freeze")

    monkeypatch.setattr(prepared.session, "final_audit_session", blocked)
    assert c.cmd_audit(prepared.args) == 2
    assert "quiescence" in prepared.seen[-1]["reason"]


def test_request_error_stops_before_any_audit(prepared, monkeypatch):
    status = SimpleNamespace(valid=False, as_dict=lambda: {"valid": False})
    monkeypatch.setattr(c, "_request_gate", lambda root: (status, None, ["invalid request"]))
    assert c.cmd_audit(prepared.args) == 2
    assert prepared.seen[-1]["request_errors"] == ["invalid request"]
