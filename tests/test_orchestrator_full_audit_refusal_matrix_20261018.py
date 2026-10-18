"""Audit fingerprint refusal matrix; each state is explicitly non-PASS."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import supervisor.orchestrator as orch
from scripts.plan_graph import PlanGraphError


@pytest.fixture
def proof_environment(monkeypatch, tmp_path):
    plan = {"steps": [{"id": 1, "verify": []}], "task": "isolated audit"}
    marker = {
        "plan": "default",
        "mode": "audit_complete",
        "status": "verified",
        "topological_order": [1],
        "plan_fingerprint": "contract-1",
        "workspace_fingerprint": "workspace-1",
        "ts": "2026-10-18T12:00:00Z",
    }
    record = {
        "plan": "default",
        "mode": "audit",
        "step": 1,
        "status": "verified",
        "results": [],
        "dependencies": [],
        "outputs": [],
        "required_outputs": [],
    }
    evidence = [record, marker]
    monkeypatch.setattr(orch.core, "verify_chain", lambda root: (True, 2, ""))
    monkeypatch.setattr(orch, "verify_anchor_chain", lambda path: {"anchored": True})
    monkeypatch.setattr(orch, "topological_order", lambda p: [1])
    monkeypatch.setattr(orch, "effective_dependencies", lambda p: {1: []})
    monkeypatch.setattr(orch.core, "plan_contract_fingerprint", lambda p: "contract-1")
    monkeypatch.setattr(orch.core, "workspace_fingerprint", lambda p: "workspace-1")
    monkeypatch.setattr(orch, "_iter_evidence_records", lambda root: iter(evidence))
    return SimpleNamespace(
        plan=plan, marker=marker, record=record, evidence=evidence, root=tmp_path
    )


def test_exact_fresh_full_audit_contract_accepts_only_matching_evidence(proof_environment):
    env = proof_environment
    report = orch.fresh_full_audit_proof(env.root, env.plan)
    assert report.valid is True
    assert report.steps == 1
    assert report.audited_at == env.marker["ts"]


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("status", "failed", "latest full audit did not pass"),
        ("topological_order", [2], "dependency order"),
        ("plan_fingerprint", "old", "plan contract changed"),
        ("workspace_fingerprint", "changed", "workspace content/type/mode"),
    ],
)
def test_marker_mutations_cannot_inherit_old_pass(proof_environment, field, value, reason):
    env = proof_environment
    env.marker[field] = value
    report = orch.fresh_full_audit_proof(env.root, env.plan)
    assert report.valid is False
    assert reason in report.reason


def test_missing_latest_step_evidence_fails_closed(proof_environment):
    env = proof_environment
    env.evidence[:] = [env.marker]
    report = orch.fresh_full_audit_proof(env.root, env.plan)
    assert report.valid is False
    assert "lacks complete step evidence" in report.reason


def test_wrong_step_order_fails_closed(proof_environment):
    env = proof_environment
    env.record["step"] = 2
    report = orch.fresh_full_audit_proof(env.root, env.plan)
    assert report.valid is False
    assert "does not cover dependency order" in report.reason


def test_invalid_step_contract_fails_closed(proof_environment):
    env = proof_environment
    env.record["status"] = "failed"
    report = orch.fresh_full_audit_proof(env.root, env.plan)
    assert report.valid is False
    assert "does not match graph/check/output contract" in report.reason


def test_corrupt_evidence_chain_must_fail(proof_environment, monkeypatch):
    env = proof_environment
    monkeypatch.setattr(orch.core, "verify_chain", lambda root: (False, 0, "bad chain"))
    result = orch.fresh_full_audit_proof(env.root, env.plan)
    assert result.valid is False
    assert "bad chain" in result.reason


def test_unanchored_archive_must_fail(proof_environment, monkeypatch):
    env = proof_environment
    monkeypatch.setattr(orch, "verify_anchor_chain", lambda path: {"anchored": False})
    result = orch.fresh_full_audit_proof(env.root, env.plan)
    assert result.valid is False
    assert "not anchored" in result.reason


def test_invalid_dependency_graph_must_fail(proof_environment, monkeypatch):
    env = proof_environment

    def reject(_):
        raise PlanGraphError("cycle found")

    monkeypatch.setattr(orch, "topological_order", reject)
    result = orch.fresh_full_audit_proof(env.root, env.plan)
    assert result.valid is False
    assert "cycle found" in result.reason


@pytest.mark.parametrize("order", [[], [1, 2]])
def test_empty_or_mismatched_graph_must_fail(proof_environment, monkeypatch, order):
    env = proof_environment
    monkeypatch.setattr(orch, "topological_order", lambda p: order)
    result = orch.fresh_full_audit_proof(env.root, env.plan)
    assert result.valid is False
    assert "no valid dependency-graph steps" in result.reason


def test_overlapping_active_agent_ownership_detects_conflict(monkeypatch):
    def agent(agent_id):
        return SimpleNamespace(agent_id=agent_id, owned_files={"shared", agent_id})

    result = orch._agent_conflicts(SimpleNamespace(active_agents=lambda: [agent("a"), agent("b")]))
    assert result == [{"file": "shared", "owner": "a", "accessor": "b"}]
