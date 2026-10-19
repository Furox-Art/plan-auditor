"""Persistent agent registry treats damaged records and HMAC state as untrusted."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.integrity import IntegrityKeyError
from supervisor import agents


def _registered(tmp_path):
    r = agents.MultiAgentRegistry(str(tmp_path))
    r.register(agents.Agent("alice", "task", "plan"))
    return r


def test_agent_retry_decode_discards_unparseable_keys_without_invented_retry_count():
    got = agents.Agent.from_dict(
        {
            "agent_id": "a",
            "task_id": "t",
            "plan_id": "p",
            "retries": {"1": "2", "bad": "missing", "2": None},
        }
    )
    assert got.retries == {1: 2}


def test_registry_record_ingest_discards_nonobject_agent_and_empty_identity():
    records = {}
    agents.MultiAgentRegistry._apply_record(records, {"event": "join", "agent": "not-an-object"})
    agents.MultiAgentRegistry._apply_record(records, {"event": "join", "agent": {}})
    assert not records


def test_registry_record_ingest_leave_event_removes_only_named_identity():
    known = {"a": agents.Agent("a", "task", "plan")}
    agents.MultiAgentRegistry._apply_record(
        known,
        {"event": "leave", "agent": {"agent_id": "a", "task_id": "task", "plan_id": "plan"}},
    )
    assert known == {}


@pytest.mark.parametrize(
    "text",
    [
        "not-json",
        "[]",
        "null",
        '"not a head"',
    ],
)
def test_invalid_signed_head_never_becomes_valid_checksum(tmp_path, text):
    r = agents.MultiAgentRegistry(str(tmp_path))
    r._ensure_dirs()
    r.head_path.write_text(text)
    assert r._read_head() == {"invalid": True}


def test_inaccessible_registry_head_is_not_treated_as_missing(monkeypatch, tmp_path):
    r = agents.MultiAgentRegistry(str(tmp_path))
    r._ensure_dirs()
    r.head_path.write_text('{"format_version":2,"seq":0,"hash":"GENESIS"}')
    original = Path.read_text

    def denied(self, *args, **kwargs):
        if self == r.head_path:
            raise OSError("unavailable HMAC checkpoint")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", denied)
    assert r._read_head() == {"invalid": True}


def test_unsigned_registry_rejects_signed_head_without_an_accessible_external_key(
    monkeypatch, tmp_path
):
    r = _registered(tmp_path)
    envelope = json.loads(r.head_path.read_text())
    envelope["auth"] = {"tag": "unverified"}
    r.head_path.write_text(json.dumps(envelope))
    monkeypatch.setattr(agents, "runtime_key", lambda _: None)
    assert r._verify_registry_auth() == (False, "authenticated registry head requires HMAC key")


def test_unsigned_registry_rejects_signed_record_without_an_accessible_key(monkeypatch, tmp_path):
    r = _registered(tmp_path)
    lines = [json.loads(x) for x in r.registry_path.read_text().splitlines()]
    lines[0]["auth"] = {"tag": "unverified"}
    r.registry_path.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    monkeypatch.setattr(agents, "runtime_key", lambda _: None)
    assert r._verify_registry_auth() == (False, "authenticated registry requires HMAC key")


def test_unsigned_registry_rejects_invalid_json_in_authentication_scan(monkeypatch, tmp_path):
    r = _registered(tmp_path)
    r.registry_path.write_text("{not-json")
    monkeypatch.setattr(agents, "runtime_key", lambda _: None)
    assert r._verify_registry_auth() == (False, "registry authentication scan failed")


def test_registry_missing_record_with_existing_head_is_not_an_empty_valid_registry(
    monkeypatch, tmp_path
):
    r = _registered(tmp_path)
    r.registry_path.unlink()
    monkeypatch.setattr(agents, "runtime_key", lambda _: None)
    assert r._verify_registry_auth() == (False, "registry head exists without records")


def test_corrupt_key_configuration_produces_explicit_untrusted_status(monkeypatch, tmp_path):
    r = agents.MultiAgentRegistry(str(tmp_path))

    def broken(_):
        raise IntegrityKeyError("wrong external key format")

    monkeypatch.setattr(agents, "runtime_key", broken)
    assert r._verify_registry_auth() == (False, "wrong external key format")


def test_signed_registry_without_head_is_never_complete_cryptographic_evidence(
    monkeypatch, tmp_path
):
    r = agents.MultiAgentRegistry(str(tmp_path))
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    assert r._verify_registry_auth() == (False, "authenticated registry head missing")


def test_signed_registry_refuses_unparsable_checkpoint_before_hmac_verification(
    monkeypatch, tmp_path
):
    r = _registered(tmp_path)
    r.head_path.write_text("{invalid")
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    monkeypatch.setattr(agents, "verify_auth", lambda *a, **kw: True)
    assert r._verify_registry_auth() == (False, "authenticated registry head unreadable")


def test_signed_registry_refuses_nonobject_checkpoint(monkeypatch, tmp_path):
    r = _registered(tmp_path)
    r.head_path.write_text("[]")
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    monkeypatch.setattr(agents, "verify_auth", lambda *a, **kw: True)
    assert r._verify_registry_auth() == (False, "authenticated registry head malformed")


def test_signed_registry_refuses_head_hmac_mismatch(monkeypatch, tmp_path):
    r = _registered(tmp_path)
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    monkeypatch.setattr(agents, "verify_auth", lambda *a, **kw: False)
    assert r._verify_registry_auth() == (False, "registry line 1 HMAC authentication failed")


def test_signed_registry_refuses_replayed_head_checksum_after_verified_records(
    monkeypatch, tmp_path
):
    r = _registered(tmp_path)
    value = json.loads(r.head_path.read_text())
    value["seq"] = 999
    r.head_path.write_text(json.dumps(value))
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    monkeypatch.setattr(agents, "verify_auth", lambda *a, **kw: True)
    assert r._verify_registry_auth() == (False, "registry authenticated head checkpoint mismatch")


def test_signed_empty_registry_rejects_non_genesis_head(monkeypatch, tmp_path):
    r = agents.MultiAgentRegistry(str(tmp_path))
    r._ensure_dirs()
    r.head_path.write_text('{"seq":4,"hash":"not-genesis"}')
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    monkeypatch.setattr(agents, "verify_auth", lambda *a, **kw: True)
    assert r._verify_registry_auth() == (False, "empty registry authenticated head mismatch")


def test_invalid_legacy_record_has_no_transparent_unsigned_upgrade(tmp_path):
    directory = tmp_path / ".plan-auditor" / "agents"
    directory.mkdir(parents=True)
    directory.joinpath("registry.jsonl").write_text(
        json.dumps(
            {"rec": {"event": "join", "agent": {"agent_id": "a"}}, "hash": "not-a-valid-hash"}
        )
        + "\n"
    )
    registry = agents.MultiAgentRegistry(str(tmp_path))
    assert registry.registry_tampered is True
    assert "legacy line" in registry.registry_problem


def test_pid_probe_refuses_invalid_or_definitely_missing_process(monkeypatch):
    assert agents._pid_alive(0) is False

    def missing(*_args):
        raise ProcessLookupError("process gone")

    monkeypatch.setattr(agents.os, "kill", missing)
    assert agents._pid_alive(1939942) is False


def test_registry_head_hmac_auth_is_not_guessed_from_plain_hash(monkeypatch, tmp_path):
    r = _registered(tmp_path)
    monkeypatch.setattr(agents, "runtime_key", lambda _: SimpleNamespace(key=b"test"))
    monkeypatch.setattr(agents, "verify_auth", lambda *a, **kw: True)
    assert r._verify_registry_auth() == (True, "")
