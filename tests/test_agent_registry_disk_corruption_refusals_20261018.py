"""Disk-level registry corruption should not produce a trusted agent inventory."""

from __future__ import annotations

import json

import pytest

from supervisor.agents import MultiAgentRegistry, _legacy_hash, _registry_hash


def _disk(tmp_path, lines, head=None):
    root = tmp_path / ".plan-auditor" / "agents"
    root.mkdir(parents=True)
    path = root / "registry.jsonl"
    path.write_text("".join(line + "\n" for line in lines), encoding="utf-8")
    if head is not None:
        (root / "registry.head.json").write_text(json.dumps(head), encoding="utf-8")
    return MultiAgentRegistry(str(tmp_path))


def _legacy(agent_id="agent"):
    rec = {"event": "join", "agent": {"agent_id": agent_id}}
    return {"rec": rec, "hash": _legacy_hash(rec)}


def _current(agent_id="agent", seq=1, prev="GENESIS"):
    rec = {"event": "join", "agent": {"agent_id": agent_id}}
    return {
        "format_version": 2,
        "seq": seq,
        "prev": prev,
        "rec": rec,
        "hash": _registry_hash(seq, prev, rec),
    }


@pytest.mark.parametrize(
    "raw,reason",
    [
        ("not-json", "not JSON"),
        ("7", "envelope is not an object"),
        (json.dumps({"rec": []}), "rec is not an object"),
    ],
)
def test_invalid_json_envelope_and_record_refuse_trust(tmp_path, raw, reason):
    reg = _disk(tmp_path, [raw])
    assert reg.registry_tampered is True
    assert reason in reg.registry_problem
    assert reg.active_agents() == []


def test_registry_that_is_directory_refuses_unreadable_log(tmp_path):
    agents = tmp_path / ".plan-auditor" / "agents"
    agents.mkdir(parents=True)
    (agents / "registry.jsonl").mkdir()
    reg = MultiAgentRegistry(str(tmp_path))
    assert reg.registry_tampered is True
    assert "registry unreadable" in reg.registry_problem


def test_legacy_registry_with_head_is_refused(tmp_path):
    row = _legacy()
    reg = _disk(tmp_path, [json.dumps(row)], head={"format_version": 2, "seq": 1, "hash": "bad"})
    assert reg.registry_tampered is True
    assert "legacy registry unexpectedly" in reg.registry_problem


def test_v2_registry_without_head_is_refused(tmp_path):
    reg = _disk(tmp_path, [json.dumps(_current())])
    assert reg.registry_tampered is True
    assert "head checkpoint missing or invalid" in reg.registry_problem


def test_v2_registry_head_checkpoint_mismatch_is_refused(tmp_path):
    reg = _disk(
        tmp_path, [json.dumps(_current())], head={"format_version": 2, "seq": 1, "hash": "wrong"}
    )
    assert reg.registry_tampered is True
    assert "head checkpoint mismatch" in reg.registry_problem


def test_blank_log_lines_are_ignored_without_creating_agents(tmp_path):
    reg = _disk(tmp_path, ["", "   "])
    assert reg.registry_tampered is False
    assert reg._agents == {}
    assert reg.verify_registry_chain() is True


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"seq": 3}, "sequence discontinuity"),
        ({"prev": "broken"}, "prev hash mismatch"),
        ({"hash": "0" * 64}, "hash mismatch"),
    ],
)
def test_v2_inconsistent_record_is_rejected_before_agent_claims(tmp_path, change, reason):
    row = _current()
    row.update(change)
    reg = _disk(
        tmp_path, [json.dumps(row)], head={"format_version": 2, "seq": 1, "hash": row["hash"]}
    )
    assert reg.registry_tampered is True
    assert reason in reg.registry_problem
    assert reg.verify_registry_chain() is False


def test_legacy_record_with_wrong_hash_is_rejected(tmp_path):
    row = _legacy()
    row["hash"] = "wrong"
    reg = _disk(tmp_path, [json.dumps(row)])
    assert reg.registry_tampered is True
    assert "legacy line 1 hash mismatch" in reg.registry_problem


def test_legacy_record_with_missing_agent_id_does_not_invent_owner(tmp_path):
    rec = {"event": "join", "agent": {"agent_id": ""}}
    row = {"rec": rec, "hash": _legacy_hash(rec)}
    reg = _disk(tmp_path, [json.dumps(row)])
    assert reg.registry_legacy is True
    assert reg._agents == {}
    assert reg.registry_tampered is False


def test_legacy_leave_record_removes_only_matching_agent(tmp_path):
    first = _legacy("one")
    second = {"rec": {"event": "leave", "agent": {"agent_id": "one"}}}
    second["hash"] = _legacy_hash(second["rec"])
    reg = _disk(tmp_path, [json.dumps(first), json.dumps(second)])
    assert reg.registry_legacy is True
    assert reg._agents == {}
    assert reg.registry_tampered is False
