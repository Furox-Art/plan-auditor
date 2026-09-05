"""Regression coverage for the L14 hash-chained multi-agent registry."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from scripts import audit_check as core
from supervisor.agents import (
    Agent,
    MultiAgentRegistry,
    REGISTRY_FORMAT_VERSION,
    REGISTRY_GENESIS,
    RegistryIntegrityError,
)
from supervisor.orchestrator import evaluate_workspace
from supervisor.sealing import save_seal, seal_plan


def _read_lines(registry: MultiAgentRegistry):
    return [
        json.loads(line)
        for line in registry.registry_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_lines(registry: MultiAgentRegistry, values):
    registry.registry_path.write_text(
        "".join(json.dumps(value, ensure_ascii=False) + "\n" for value in values),
        encoding="utf-8",
    )


def _three_event_registry(tmp_path: Path) -> MultiAgentRegistry:
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("a1", "t1", "p1"))
    registry.heartbeat("a1", "working")
    registry.update_ownership("a1", {"src/a.py"})
    assert registry.verify_registry_chain() is True
    return registry


def test_registry_records_are_seq_prev_hash_chained(tmp_path: Path):
    registry = _three_event_registry(tmp_path)
    lines = _read_lines(registry)
    assert [line["seq"] for line in lines] == [1, 2, 3]
    assert all(line["format_version"] == REGISTRY_FORMAT_VERSION for line in lines)
    assert lines[0]["prev"] == REGISTRY_GENESIS
    assert lines[1]["prev"] == lines[0]["hash"]
    assert lines[2]["prev"] == lines[1]["hash"]

    head = json.loads(registry.head_path.read_text(encoding="utf-8"))
    assert head["seq"] == 3
    assert head["hash"] == lines[-1]["hash"]


def test_registry_detects_record_mutation(tmp_path: Path):
    registry = _three_event_registry(tmp_path)
    lines = _read_lines(registry)
    lines[1]["rec"]["agent"]["task_id"] = "tampered"
    _write_lines(registry, lines)
    assert registry.verify_registry_chain() is False
    assert "hash" in registry.registry_problem


def test_registry_detects_middle_record_deletion(tmp_path: Path):
    registry = _three_event_registry(tmp_path)
    lines = _read_lines(registry)
    _write_lines(registry, [lines[0], lines[2]])
    assert registry.verify_registry_chain() is False
    assert (
        "sequence" in registry.registry_problem
        or "prev" in registry.registry_problem
        or "head" in registry.registry_problem
    )


def test_registry_detects_record_reordering(tmp_path: Path):
    registry = _three_event_registry(tmp_path)
    lines = _read_lines(registry)
    _write_lines(registry, [lines[1], lines[0], lines[2]])
    assert registry.verify_registry_chain() is False


def test_registry_head_detects_tail_truncation(tmp_path: Path):
    registry = _three_event_registry(tmp_path)
    lines = _read_lines(registry)
    _write_lines(registry, lines[:-1])
    assert registry.verify_registry_chain() is False
    assert "head" in registry.registry_problem


def test_registry_refuses_mutation_after_integrity_failure(tmp_path: Path):
    registry = _three_event_registry(tmp_path)
    lines = _read_lines(registry)
    _write_lines(registry, lines[:-1])
    with pytest.raises(RegistryIntegrityError):
        registry.register(Agent("a2", "t2", "p2"))


def test_legacy_registry_is_validated_then_migrated(tmp_path: Path):
    agents_dir = tmp_path / ".plan-auditor" / "agents"
    agents_dir.mkdir(parents=True)
    agent = Agent(
        "legacy-a1",
        "legacy-task",
        "legacy-plan",
        workspace_root=str(tmp_path.resolve()),
        last_heartbeat=time.time(),
    )
    rec = {"ts": time.time(), "event": "join", "agent": agent.to_dict()}
    legacy_hash = hashlib.sha256(
        json.dumps(rec, sort_keys=True).encode("utf-8")
    ).hexdigest()
    (agents_dir / "registry.jsonl").write_text(
        json.dumps({"hash": legacy_hash, "rec": rec}, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    registry = MultiAgentRegistry(str(tmp_path))
    assert registry.registry_legacy is True
    assert registry.verify_registry_chain() is True
    assert registry.registry_legacy is False

    lines = _read_lines(registry)
    assert len(lines) == 1
    assert lines[0]["format_version"] == REGISTRY_FORMAT_VERSION
    assert lines[0]["seq"] == 1
    assert lines[0]["prev"] == REGISTRY_GENESIS
    head = json.loads(registry.head_path.read_text(encoding="utf-8"))
    assert head["hash"] == lines[0]["hash"]


def test_integrated_gate_fails_on_registry_tamper(tmp_path: Path):
    plan = {
        "task": "registry gate hardening",
        "created": "2026-09-05T00:00:00+00:00",
        "steps": [
            {
                "id": 1,
                "title": "real behavior",
                "status": "pending",
                "verify": [{"type": "run", "cmd": "python -c \"print('ok')\""}],
            }
        ],
    }
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    seal = seal_plan(plan, "registry-test", "2026-09-05T00:00:00+00:00")
    save_seal(seal, str(pg / "seal.json"))
    assert core.audit_steps(str(tmp_path), plan, mode="audit") is True

    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("a1", "t1", "p1"))
    lines = _read_lines(registry)
    lines[0]["rec"]["agent"]["plan_id"] = "forged-plan"
    _write_lines(registry, lines)

    report = evaluate_workspace(str(tmp_path), profile="standard")
    assert report["outcome"] == "FAIL"
    assert report["agents"]["registry_valid"] is False
    assert any(
        item["rule_id"] == "AGENT_REGISTRY_VALID"
        for item in report["gate"]["policy_findings"]
    )
