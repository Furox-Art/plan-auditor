"""Regression tests for integrated supervisor hardening."""
from __future__ import annotations

import json
import os
from pathlib import Path

from scripts import audit_check as core
from supervisor.agents import Agent, MultiAgentRegistry
from supervisor.config import load_config
from supervisor.contracts import environment_contract
from supervisor.evidence import verify_anchor_chain
from supervisor.orchestrator import evaluate_workspace, fresh_full_audit_proof
from supervisor.policies import PolicyEngine, load_policy_rules_from_dir
from supervisor.sealing import save_seal, seal_plan
from supervisor.workspace import capture_workspace
from tests.request_fixture import activate_for_plan


def _plan(status="pending"):
    return {
        "task": "integration hardening",
        "created": "2026-09-05T00:00:00+00:00",
        "requirements": [
            {"id": "REQ-001", "description": "Real behavior must execute", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [{
            "id": 1,
            "title": "real behavior",
            "covers": ["REQ-001"],
            "status": status,
            "verify": [{"type": "run", "cmd": "python -c \"print('ok')\""}],
        }],
    }


def _write_plan(root: Path, plan=None):
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    value = plan or _plan()
    (pg / "plan.json").write_text(json.dumps(value), encoding="utf-8")
    activate_for_plan(root, value)
    return value


def _seal(root: Path, plan):
    cfg = load_config(str(root))
    seal = seal_plan(
        plan,
        "integration",
        "2026-09-05T00:00:00+00:00",
        environment=environment_contract(root, cfg),
    )
    save_seal(seal, str(root / ".plan-auditor" / "seal.json"))


def test_verified_label_is_not_fresh_audit_proof(tmp_path: Path):
    plan = _write_plan(tmp_path, _plan(status="verified"))
    proof = fresh_full_audit_proof(tmp_path, plan)
    assert proof.valid is False
    assert "audit" in proof.reason.lower()


def test_fresh_audit_proof_matches_current_checks(tmp_path: Path):
    plan = _write_plan(tmp_path)
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    current = json.loads((tmp_path / ".plan-auditor" / "plan.json").read_text())
    proof = fresh_full_audit_proof(tmp_path, current)
    assert proof.valid is True


def test_fresh_audit_invalidated_by_workspace_change(tmp_path: Path):
    plan = _write_plan(tmp_path)
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    (tmp_path / "changed_after_audit.py").write_text("x = 1\n", encoding="utf-8")
    current = json.loads((tmp_path / ".plan-auditor" / "plan.json").read_text())
    proof = fresh_full_audit_proof(tmp_path, current)
    assert proof.valid is False
    assert "workspace" in proof.reason.lower()


def test_workspace_capture_is_read_only(tmp_path: Path):
    before = core.workspace_fingerprint(str(tmp_path))
    capture_workspace(str(tmp_path))
    after = core.workspace_fingerprint(str(tmp_path))
    assert after == before
    if os.name != "nt":
        assert not (tmp_path / "nul").exists()


def test_integrated_gate_requires_seal(tmp_path: Path):
    plan = _write_plan(tmp_path)
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    report = evaluate_workspace(str(tmp_path), profile="standard")
    assert report["outcome"] == "FAIL"
    assert report["seal"]["ok"] is False


def test_integrated_gate_passes_with_seal_and_fresh_audit(tmp_path: Path):
    plan = _write_plan(tmp_path)
    _seal(tmp_path, plan)
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True
    report = evaluate_workspace(str(tmp_path), profile="standard")
    assert report["outcome"] == "PASS"
    assert report["fresh_audit"]["valid"] is True
    assert report["seal"]["ok"] is True
    assert report["coverage"]["valid"] is True


def test_rotation_creates_cross_archive_anchor(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(core, "ROTATE_BYTES", 1)
    base = str(tmp_path)
    for index in range(3):
        core.append_evidence(base, {
            "ts": f"2026-09-05T00:00:0{index}+00:00",
            "mode": "run",
            "plan": "default",
            "step": 1,
            "results": [],
            "status": "verified",
        })
    result = verify_anchor_chain(str(tmp_path / ".plan-auditor" / "archive"))
    assert len(result["archives"]) >= 2
    assert result["anchored"] is True
    assert all(item["chain_valid"] is True for item in result["archives"])


def test_registry_state_is_visible_across_instances(tmp_path: Path):
    first = MultiAgentRegistry(str(tmp_path))
    first.register(Agent("a1", "t1", "p1", owned_files={"src/a.py"}))
    second = MultiAgentRegistry(str(tmp_path))
    active = second.active_agents()
    assert len(active) == 1
    assert active[0].agent_id == "a1"
    assert active[0].owned_files == {"src/a.py"}


def test_parallel_strict_claim_blocks_overlap_across_instances(tmp_path: Path):
    first = MultiAgentRegistry(str(tmp_path))
    first.register(Agent("a1", "t1", "p1"))
    ok, conflicts = first.claim_files("a1", {"src/shared.py"}, mode="parallel-strict")
    assert ok and conflicts == []

    second = MultiAgentRegistry(str(tmp_path))
    second.register(Agent("a2", "t2", "p2"))
    ok, conflicts = second.claim_files("a2", {"src/shared.py"}, mode="parallel-strict")
    assert ok is False
    assert len(conflicts) == 1
    assert conflicts[0].owner_agent == "a1"


def test_custom_toml_policy_is_loaded_and_evaluated(tmp_path: Path):
    policies = tmp_path / "policies"
    policies.mkdir()
    (policies / "security.toml").write_text(
        """
[[rules]]
id = "NO_DANGER_TEXT"
level = 3
kind = "forbid_regex"
field = "logs"
pattern = "danger-token"
detail = "danger marker present"
""".strip(),
        encoding="utf-8",
    )
    errors = []
    rules = load_policy_rules_from_dir(str(policies), errors=errors)
    assert errors == []
    assert len(rules) == 1
    engine = PolicyEngine(rules)
    failures = engine.failures({"logs": ["danger-token"]})
    assert len(failures) == 1
    assert failures[0].rule_id == "NO_DANGER_TEXT"
