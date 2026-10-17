"""Real registry hashes, legacy migration, ownership and fail-closed agent access."""

from __future__ import annotations

import json

import pytest

from supervisor import agents


def agent(name: str = "a") -> agents.Agent:
    return agents.Agent(name, "task", "plan")


def test_agent_json_roundtrip_handles_numeric_retries_and_rejects_invalid_counters():
    before = agent()
    before.retries = {3: 1, 9: 2}
    before.owned_files = {"b.py", "a.py"}
    payload = before.to_dict()
    assert payload["owned_files"] == ["a.py", "b.py"]
    payload["retries"]["bad"] = "invalid"
    after = agents.Agent.from_dict(payload)
    assert after.retries == {3: 1, 9: 2}
    assert after.owned_files == {"a.py", "b.py"}
    assert after.agent_id == "a"


@pytest.mark.parametrize(
    ("record", "expected"),
    [
        ({"event": "join", "agent": "not-object"}, False),
        ({"event": "join", "agent": {}}, False),
        ({"event": "join", "agent": {"agent_id": "a", "task_id": "t", "plan_id": "p"}}, True),
    ],
)
def test_registry_record_ingest_never_invents_missing_agent_identity(record, expected):
    known = {}
    agents.MultiAgentRegistry._apply_record(known, record)
    assert ("a" in known) is expected
    agents.MultiAgentRegistry._apply_record(known, {"event": "leave", "agent": {"agent_id": "a"}})
    assert known == {}


def test_agent_register_heartbeat_ownership_conflict_and_release_roundtrip(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry.register(agent("alice"))
    registry.register(agent("bob"))
    assert registry.verify_registry_chain()
    registry.heartbeat("alice", action="edit")
    alice = registry._agents["alice"]
    assert alice.current_action == "edit"
    registry.update_ownership("alice", {"src/main.py"})
    conflicts = registry.check_conflicts("bob", {"src/main.py"})
    assert len(conflicts) == 1
    assert conflicts[0].owner_agent == "alice"
    assert conflicts[0].accessor_agent == "bob"
    allowed, warnings = registry.claim_files("bob", {"src/main.py"}, mode="parallel-strict")
    assert allowed is False
    assert len(warnings) == 1
    allowed, warnings = registry.claim_files("bob", {"src/main.py"}, mode="parallel-warn")
    assert allowed is True
    assert len(warnings) == 1
    assert registry._agents["bob"].owned_files == {"src/main.py"}
    registry.unregister("alice")
    assert "alice" not in registry._agents
    assert registry.verify_registry_chain()
    reloaded = agents.MultiAgentRegistry(str(tmp_path))
    assert "bob" in reloaded._agents
    assert "alice" not in reloaded._agents


def test_unregistered_agent_cannot_claim_ownership_silently(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    with pytest.raises(agents.RegistryIntegrityError, match="unknown agent: ghost"):
        registry.claim_files("ghost", {"file.py"})
    assert registry._agents == {}


def test_registry_newly_written_hashes_have_matching_head_checkpoint(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry.register(agent())
    assert registry.head_path.exists()
    head = json.loads(registry.head_path.read_text())
    rows = [json.loads(line) for line in registry.registry_path.read_text().splitlines()]
    assert head["seq"] == 1
    assert rows[0]["prev"] == agents.REGISTRY_GENESIS
    assert rows[0]["hash"] == head["hash"]
    assert registry.verify_registry_chain() is True


@pytest.mark.parametrize(
    ("corruption", "reason"),
    [
        ("bad-json", "not JSON"),
        ("not-object", "envelope is not an object"),
        ("missing-rec", "rec is not an object"),
        ("hash-edit", "hash mismatch"),
        ("broken-head", "head checkpoint mismatch"),
    ],
)
def test_registry_refuses_malformed_or_rewritten_evidence(tmp_path, corruption, reason):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry.register(agent())
    records = [json.loads(line) for line in registry.registry_path.read_text().splitlines()]
    if corruption == "bad-json":
        registry.registry_path.write_text("{not valid json\n")
    elif corruption == "not-object":
        registry.registry_path.write_text("[]\n")
    elif corruption == "missing-rec":
        records[0]["rec"] = []
        registry.registry_path.write_text(json.dumps(records[0]) + "\n")
    elif corruption == "hash-edit":
        records[0]["rec"]["event"] = "forged"
        registry.registry_path.write_text(json.dumps(records[0]) + "\n")
    elif corruption == "broken-head":
        head = json.loads(registry.head_path.read_text())
        head["seq"] = 5
        registry.head_path.write_text(json.dumps(head))
    assert registry.verify_registry_chain() is False
    assert reason in registry.registry_problem
    with pytest.raises(agents.RegistryIntegrityError, match="integrity check failed"):
        registry.register(agent("attacker"))


def test_registry_unsigned_mode_rejects_authenticated_checkpoint_without_key(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry.register(agent())
    head = json.loads(registry.head_path.read_text())
    head["auth"] = {"tag": "not verified"}
    registry.head_path.write_text(json.dumps(head))
    assert registry.verify_registry_chain() is False
    assert "requires HMAC key" in registry.registry_problem


def test_registry_legacy_record_is_only_migrated_after_real_hash_validation(tmp_path):
    directory = tmp_path / ".plan-auditor" / "agents"
    directory.mkdir(parents=True)
    payload = {"event": "join", "ts": 1, "agent": agent().to_dict()}
    envelope = {"rec": payload, "hash": agents._legacy_hash(payload)}
    (directory / "registry.jsonl").write_text(json.dumps(envelope) + "\n")
    registry = agents.MultiAgentRegistry(str(tmp_path))
    assert registry.registry_legacy is True
    assert registry.verify_registry_chain() is True
    assert registry.registry_legacy is False
    assert registry.head_path.exists()
    row = json.loads(registry.registry_path.read_text().splitlines()[0])
    assert row["format_version"] == 2
    assert row["seq"] == 1
    assert registry._agents["a"].task_id == "task"


def test_invalid_legacy_hash_is_never_laundered_into_version_two(tmp_path):
    directory = tmp_path / ".plan-auditor" / "agents"
    directory.mkdir(parents=True)
    payload = {"event": "join", "agent": agent().to_dict()}
    (directory / "registry.jsonl").write_text(json.dumps({"rec": payload, "hash": "wrong"}) + "\n")
    registry = agents.MultiAgentRegistry(str(tmp_path))
    assert registry.registry_tampered
    assert not registry.verify_registry_chain()
    assert not (directory / "registry.head.json").exists()


def test_registry_lock_staleness_reports_absence_and_corrupt_json(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    assert registry.is_lock_stale("a") is False
    registry.agents_dir.mkdir(parents=True, exist_ok=True)
    path = registry.agents_dir / "a.lock"
    path.write_text("{truncated")
    assert registry.is_lock_stale("a") is True


def test_unsigned_registry_empty_checkpoint_without_records_rejected(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.head_path.write_text(json.dumps({"format_version": 2, "seq": 10, "hash": "tampered"}))
    assert registry.verify_registry_chain() is False
    assert "registry log missing" in registry.registry_problem
