"""Real legacy-v2 registry migration refuses mixed, reordered and forged records."""

from __future__ import annotations

import json

import pytest

import supervisor.agents as agents
from scripts.integrity import KeyMaterial
from supervisor.agents import MultiAgentRegistry, RegistryIntegrityError, initialize_registry_auth


def key():
    return KeyMaterial(b"a" * 32, "isolated test", "test-key")


def record(agent_id):
    return {"event": "join", "agent": {"agent_id": agent_id, "task_id": "t", "plan_id": "p"}}


def v1(agent_id):
    rec = record(agent_id)
    return {"rec": rec, "hash": agents._legacy_hash(rec)}


def v2(agent_id, seq=1, prev="GENESIS"):
    rec = record(agent_id)
    return {
        "format_version": 2,
        "seq": seq,
        "prev": prev,
        "rec": rec,
        "hash": agents._registry_hash(seq, prev, rec),
    }


def write_registry(tmp_path, records, *, head=None):
    agents_dir = tmp_path / ".plan-auditor" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    path = agents_dir / "registry.jsonl"
    path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    if head is not None:
        (agents_dir / "registry.head.json").write_text(json.dumps(head), encoding="utf-8")
    return path


@pytest.mark.parametrize("records", [[v1("a"), v2("b")], [v2("a"), v1("b")]])
def test_mixed_registry_format_is_refused_even_when_individual_hashes_match(tmp_path, records):
    write_registry(tmp_path, records)
    reg = MultiAgentRegistry(str(tmp_path))
    assert reg.registry_tampered is True
    assert "mixed" in reg.registry_problem
    assert reg.verify_registry_chain() is False


def test_valid_real_legacy_registry_can_be_migrated_and_authenticated(tmp_path, monkeypatch):
    write_registry(tmp_path, [v1("a"), v1("b")])
    reg = MultiAgentRegistry(str(tmp_path))
    assert reg.registry_legacy is True
    assert reg.registry_tampered is False
    initialize_registry_auth(tmp_path, key())
    monkeypatch.setattr(agents, "runtime_key", lambda _: key())
    assert reg.verify_registry_chain() is True
    assert reg.registry_legacy is False
    assert set(reg._agents) == {"a", "b"}
    assert reg.active_agents() == []  # Historical records are stale, not live owners.
    recs = [json.loads(line) for line in reg.registry_path.read_text().splitlines()]
    assert [v["seq"] for v in recs] == [1, 2]
    assert all(v["auth"]["alg"] == "hmac-sha256" for v in recs)
    assert reg.head_path.exists()


def test_legacy_registry_hash_forgery_is_never_signed(tmp_path):
    forged = v1("a")
    forged["hash"] = "0" * 64
    write_registry(tmp_path, [forged])
    with pytest.raises(RegistryIntegrityError, match="legacy registry line 1 hash mismatch"):
        initialize_registry_auth(tmp_path, key())
    assert not (tmp_path / ".plan-auditor" / "agents" / "registry.head.json").exists()


def test_mixed_registry_is_never_signed(tmp_path):
    write_registry(tmp_path, [v1("a"), v2("b")])
    with pytest.raises(RegistryIntegrityError, match="mixed or unknown registry format"):
        initialize_registry_auth(tmp_path, key())


@pytest.mark.parametrize(
    "mutator,reason",
    [
        (lambda row: row.update(seq=2), "sequence/prev mismatch"),
        (lambda row: row.update(prev="not-genesis"), "sequence/prev mismatch"),
        (lambda row: row.update(hash="0" * 64), "hash mismatch"),
    ],
)
def test_unsigned_v2_registry_with_invalid_sequence_or_hash_cannot_be_authenticated(
    tmp_path, mutator, reason
):
    row = v2("a")
    mutator(row)
    write_registry(tmp_path, [row])
    with pytest.raises(RegistryIntegrityError, match=reason):
        initialize_registry_auth(tmp_path, key())


def test_valid_v2_registry_without_head_cannot_be_retroactively_signed(tmp_path):
    write_registry(tmp_path, [v2("a")])
    with pytest.raises(RegistryIntegrityError, match="head missing or invalid"):
        initialize_registry_auth(tmp_path, key())


def test_valid_v2_registry_with_tampered_head_cannot_be_signed(tmp_path):
    write_registry(tmp_path, [v2("a")], head={"format_version": 2, "seq": 2, "hash": "bad"})
    with pytest.raises(RegistryIntegrityError, match="head mismatch"):
        initialize_registry_auth(tmp_path, key())


def test_v2_registry_with_correct_head_is_signed_without_rewriting_sequence(tmp_path, monkeypatch):
    row = v2("a")
    write_registry(tmp_path, [row], head={"format_version": 2, "seq": 1, "hash": row["hash"]})
    initialize_registry_auth(tmp_path, key())
    monkeypatch.setattr(agents, "runtime_key", lambda _: key())
    reg = MultiAgentRegistry(str(tmp_path))
    assert reg.verify_registry_chain() is True
    rows = [json.loads(line) for line in reg.registry_path.read_text().splitlines()]
    assert rows[0]["seq"] == 1
    assert rows[0]["auth"]["alg"] == "hmac-sha256"
