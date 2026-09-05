"""Regression tests for external-key HMAC authenticated integrity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from scripts import audit_check as core
from scripts.integrity import IntegrityKeyError, load_key
from supervisor.agents import Agent, MultiAgentRegistry, _registry_hash
from supervisor.integrity import initialize_integrity, integrity_status


def _workspace_and_key(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    key_file = tmp_path / "outside-hmac.key"
    key_file.write_bytes(b"plan-auditor-test-key-material-" * 2)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    return workspace, key_file


def _seed_unsigned_state(workspace: Path):
    core.append_evidence(str(workspace), {
        "ts": "2026-09-05T00:00:00+00:00",
        "mode": "run",
        "plan": "default",
        "step": 1,
        "results": [],
        "status": "verified",
    })
    registry = MultiAgentRegistry(str(workspace))
    registry.register(Agent("a1", "t1", "p1"))


def _enable(workspace: Path, key_file: Path, monkeypatch):
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    result = initialize_integrity(workspace)
    assert result["authenticated"] is True
    return result


def test_key_file_inside_workspace_is_rejected(tmp_path: Path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    key_file = workspace / "key.txt"
    key_file.write_bytes(b"x" * 64)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    with pytest.raises(IntegrityKeyError):
        load_key(workspace, required=True)


def test_integrity_init_authenticates_existing_evidence_and_registry(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_and_key(tmp_path, monkeypatch)
    _seed_unsigned_state(workspace)
    result = _enable(workspace, key_file, monkeypatch)
    assert result["evidence"]["valid"] is True
    assert result["registry"]["valid"] is True
    assert (workspace / ".plan-auditor" / "integrity.json").exists()
    assert (workspace / ".plan-auditor" / "evidence.head.json").exists()

    evidence = json.loads(
        (workspace / ".plan-auditor" / "evidence.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert evidence["auth"]["alg"] == "hmac-sha256"
    registry = json.loads(
        (workspace / ".plan-auditor" / "agents" / "registry.jsonl")
        .read_text(encoding="utf-8").splitlines()[0]
    )
    assert registry["auth"]["alg"] == "hmac-sha256"


def test_evidence_rehash_cannot_forge_hmac(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_and_key(tmp_path, monkeypatch)
    _seed_unsigned_state(workspace)
    _enable(workspace, key_file, monkeypatch)

    path = workspace / ".plan-auditor" / "evidence.jsonl"
    rec = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    rec["status"] = "forged"
    rec["hash"] = hashlib.sha256(
        core.canonical({k: v for k, v in rec.items() if k not in {"hash", "auth"}}).encode("utf-8")
    ).hexdigest()
    path.write_text(core.canonical(rec) + "\n", encoding="utf-8")

    ok, _count, problem = core.verify_chain(str(workspace))
    assert ok is False
    assert "HMAC" in problem or "head" in problem


def test_evidence_signed_head_detects_tail_truncation(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_and_key(tmp_path, monkeypatch)
    _seed_unsigned_state(workspace)
    _enable(workspace, key_file, monkeypatch)
    core.append_evidence(str(workspace), {
        "ts": "2026-09-05T00:00:01+00:00",
        "mode": "run",
        "plan": "default",
        "step": 2,
        "results": [],
        "status": "verified",
    })

    path = workspace / ".plan-auditor" / "evidence.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")
    ok, _count, problem = core.verify_chain(str(workspace))
    assert ok is False
    assert "head" in problem


def test_registry_rehash_and_head_rewrite_cannot_forge_hmac(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_and_key(tmp_path, monkeypatch)
    _seed_unsigned_state(workspace)
    _enable(workspace, key_file, monkeypatch)

    registry = MultiAgentRegistry(str(workspace))
    path = registry.registry_path
    envelope = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    envelope["rec"]["agent"]["task_id"] = "forged-task"
    envelope["hash"] = _registry_hash(envelope["seq"], envelope["prev"], envelope["rec"])
    path.write_text(json.dumps(envelope, sort_keys=True) + "\n", encoding="utf-8")

    head = json.loads(registry.head_path.read_text(encoding="utf-8"))
    head["hash"] = envelope["hash"]
    registry.head_path.write_text(json.dumps(head, sort_keys=True) + "\n", encoding="utf-8")

    fresh = MultiAgentRegistry(str(workspace))
    assert fresh.verify_registry_chain() is False
    assert "HMAC" in fresh.registry_problem


def test_authenticated_state_fails_closed_when_key_disappears(tmp_path: Path, monkeypatch):
    workspace, key_file = _workspace_and_key(tmp_path, monkeypatch)
    _seed_unsigned_state(workspace)
    _enable(workspace, key_file, monkeypatch)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE")

    ok, _count, problem = core.verify_chain(str(workspace))
    assert ok is False
    assert "requires" in problem or "key" in problem.lower()
    status = integrity_status(workspace)
    assert status["authenticated"] is False
