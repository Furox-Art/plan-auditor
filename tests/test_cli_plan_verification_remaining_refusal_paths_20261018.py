"""CLI plan-verification policy and immutable-seal decision coverage."""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

import supervisor.cli as cli
import supervisor.config as config_module
import supervisor.sealing as sealing


def _args(tmp_path):
    return argparse.Namespace(dir=str(tmp_path), plan=None, reseal=False)


@pytest.fixture
def gate(monkeypatch, tmp_path):
    ref = SimpleNamespace(key="default", name="default")
    status = SimpleNamespace(valid=True, activated=True, as_dict=lambda: {"valid": True})
    monkeypatch.setattr(cli, "_selected_refs", lambda root, name: [ref])
    monkeypatch.setattr(cli, "_request_gate", lambda root: (status, None, []))
    cfg = config_module.load_config(str(tmp_path))

    monkeypatch.setattr(config_module, "load_config", lambda root: cfg)
    monkeypatch.setattr(cli, "_policy_errors", lambda root, config: [])
    monkeypatch.setattr(cli, "_root", lambda value: tmp_path)
    monkeypatch.setattr(cli, "_json", lambda value: None)
    monkeypatch.setattr(cli, "_persist_supervisor_config", lambda *args: None)
    monkeypatch.setattr(cli, "cmd_task_list", lambda args: 0)
    import scripts.audit_check as core
    import scripts.contract as contract
    import supervisor.contracts as contracts
    import supervisor.plan_verifier as pv
    import supervisor.plans as plans

    monkeypatch.setattr(core, "validate_plan", lambda plan: [])
    monkeypatch.setattr(contract, "plan_hash", lambda plan: "current-sha")
    monkeypatch.setattr(contracts, "environment_contract", lambda root, config: {})
    monkeypatch.setattr(plans, "load_plan_ref", lambda ref: {"task": "t", "steps": []})
    monkeypatch.setattr(plans, "seal_path", lambda root, name: tmp_path / "seal.json")
    analysis = SimpleNamespace(
        verdict="PASS",
        rationale="ok",
        weakest_verification="ok",
        graph_errors=[],
        coverage=None,
        topological_order=[],
        dependencies={},
        step_analyses=[],
    )
    monkeypatch.setattr(pv, "verify_plan", lambda plan, require_coverage: analysis)
    monkeypatch.setattr(sealing, "load_seal", lambda path: None)
    monkeypatch.setattr(sealing, "save_seal", lambda s, path: None)
    monkeypatch.setattr(
        sealing,
        "seal_plan",
        lambda *args, **kwargs: SimpleNamespace(
            format_version=4, criteria_count=1, plan_hash="current-sha"
        ),
    )
    monkeypatch.setattr(sealing, "check_monotonic", lambda old, plan: sealing.MonotonicCheck(True, [], []))
    monkeypatch.setattr(
        sealing, "check_environment", lambda seal, env: sealing.MonotonicCheck(True, [], [])
    )
    return SimpleNamespace(
        ref=ref,
        status=status,
        config=cfg,
        core=core,
        contract=contract,
        contracts=contracts,
        plans=plans,
        sealing=sealing,
        pv=pv,
        analysis=analysis,
    )


def test_valid_isolated_plan_can_be_sealed_without_skipping_checks(gate, tmp_path):
    assert cli.cmd_plan_verify(_args(tmp_path)) == 0


def test_invalid_config_refuses_verify_and_does_not_write_seal(gate, tmp_path):
    gate.config.errors.append("invalid setting")
    assert cli.cmd_plan_verify(_args(tmp_path)) == 2


def test_invalid_plan_json_fails_closed(gate, tmp_path, monkeypatch):
    def invalid(_):
        raise ValueError("broken JSON")

    monkeypatch.setattr(gate.plans, "load_plan_ref", invalid)
    assert cli.cmd_plan_verify(_args(tmp_path)) == 1


def test_static_plan_analysis_reject_disables_sealing(gate, tmp_path):
    gate.analysis.verdict = "REJECT"
    assert cli.cmd_plan_verify(_args(tmp_path)) == 1


def test_invalid_existing_seal_refuses_resigning(gate, tmp_path, monkeypatch):
    def forged(_):
        raise sealing.SealIntegrityError("seal signature invalid")

    monkeypatch.setattr(gate.sealing, "load_seal", forged)
    assert cli.cmd_plan_verify(_args(tmp_path)) == 2


def test_legacy_existing_seal_needs_explicit_generation(gate, tmp_path, monkeypatch):
    monkeypatch.setattr(gate.sealing, "load_seal", lambda path: SimpleNamespace(format_version=3))
    assert cli.cmd_plan_verify(_args(tmp_path)) == 2


def test_immutable_request_contract_refuses_plan_hash_change(gate, tmp_path, monkeypatch):
    old = SimpleNamespace(format_version=4, plan_hash="old", as_plan=lambda: {})
    monkeypatch.setattr(gate.sealing, "load_seal", lambda path: old)
    assert cli.cmd_plan_verify(_args(tmp_path)) == 2


def test_matching_plan_hash_with_valid_existing_seal_passes(gate, tmp_path, monkeypatch):
    old = SimpleNamespace(format_version=4, plan_hash="current-sha", as_plan=lambda: {})
    monkeypatch.setattr(gate.sealing, "load_seal", lambda path: old)
    assert cli.cmd_plan_verify(_args(tmp_path)) == 0


def test_existing_seal_with_weakened_contract_is_refused(gate, tmp_path, monkeypatch):
    old = SimpleNamespace(format_version=4, plan_hash="current-sha", as_plan=lambda: {})
    monkeypatch.setattr(gate.sealing, "load_seal", lambda path: old)
    monkeypatch.setattr(
        gate.sealing, "check_monotonic", lambda old, plan: sealing.MonotonicCheck(False, ["weakened"], [])
    )
    assert cli.cmd_plan_verify(_args(tmp_path)) == 2


def test_write_failure_during_sealing_is_explicit_refusal(gate, tmp_path, monkeypatch):
    def failed(*args):
        raise sealing.SealIntegrityError("cannot persist seal")

    monkeypatch.setattr(gate.sealing, "save_seal", failed)
    assert cli.cmd_plan_verify(_args(tmp_path)) == 2


def test_req_generation_reseal_flag_refused(gate, tmp_path):
    args = _args(tmp_path)
    args.reseal = True
    assert cli.cmd_plan_verify(args) == 2


def test_supervisor_settings_do_not_trust_nonmapping_file(tmp_path):

    dest = tmp_path / ".plan-auditor"
    dest.mkdir()
    (dest / config_module.CONFIG_FILENAME).write_text("[1,2,3]", encoding="utf-8")
    cli._persist_supervisor_config(tmp_path, "strict", "serial")
    payload = json.loads((dest / config_module.CONFIG_FILENAME).read_text())
    assert payload["profile"] == "strict"
    assert payload["mode"] == "serial"
    assert payload.get("tier") == 1
