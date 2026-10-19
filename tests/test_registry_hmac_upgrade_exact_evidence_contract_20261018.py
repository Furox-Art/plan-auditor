"""Registry HMAC initialisation must independently validate v1/v2 before signing."""

from __future__ import annotations

import json

import pytest

from scripts.integrity import KeyMaterial, verify_auth
from supervisor import agents


@pytest.fixture
def local_key():
    return KeyMaterial(
        key=b"isolated-test-key-material-not-a-real-secret!" * 2,
        source="unit-test-fixture",
        key_id="fixture-key",
    )


def _registry(root, rows):
    folder = root / ".plan-auditor" / "agents"
    folder.mkdir(parents=True)
    log = folder / "registry.jsonl"
    log.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return log, folder / "registry.head.json"


def _rec(agent_id="alice"):
    return {
        "event": "join",
        "ts": 0,
        "agent": {"agent_id": agent_id, "task_id": "study", "plan_id": "plan"},
    }


def _legacy(rec):
    return {"rec": rec, "hash": agents._legacy_hash(rec)}


def _v2(rec, seq=1, prev=agents.REGISTRY_GENESIS):
    return {
        "format_version": agents.REGISTRY_FORMAT_VERSION,
        "seq": seq,
        "prev": prev,
        "rec": rec,
        "hash": agents._registry_hash(seq, prev, rec),
    }


def test_empty_new_registry_is_signed_as_actual_genesis_checkpoint(tmp_path, local_key):
    agents.initialize_registry_auth(tmp_path, local_key)
    head = json.loads((tmp_path / ".plan-auditor" / "agents" / "registry.head.json").read_text())
    assert head["seq"] == 0
    assert head["hash"] == agents.REGISTRY_GENESIS
    assert verify_auth(
        local_key,
        agents.REGISTRY_HEAD_DOMAIN,
        {k: v for k, v in head.items() if k != "auth"},
        head["auth"],
    )


def test_existing_empty_log_is_not_replaced_by_fabricated_agent_event(tmp_path, local_key):
    log, head = _registry(tmp_path, [])
    agents.initialize_registry_auth(tmp_path, local_key)
    assert log.read_text() == ""
    assert json.loads(head.read_text())["seq"] == 0


def test_legacy_registry_is_converted_into_real_numbered_hmac_chain(tmp_path, local_key):
    source = _rec()
    log, head = _registry(tmp_path, [_legacy(source)])
    agents.initialize_registry_auth(tmp_path, local_key)
    value = json.loads(log.read_text())
    checkpoint = json.loads(head.read_text())
    assert value["format_version"] == 2
    assert value["seq"] == 1
    assert value["prev"] == agents.REGISTRY_GENESIS
    assert checkpoint["seq"] == 1 and checkpoint["hash"] == value["hash"]
    assert verify_auth(
        local_key,
        agents.REGISTRY_RECORD_DOMAIN,
        {k: v for k, v in value.items() if k != "auth"},
        value["auth"],
    )


def test_existing_valid_v2_registry_is_signed_without_changing_the_record_hash(tmp_path, local_key):
    row = _v2(_rec())
    log, head = _registry(tmp_path, [row])
    head.write_text(json.dumps({"seq": 1, "hash": row["hash"], "format_version": 2}))
    agents.initialize_registry_auth(tmp_path, local_key)
    authenticated = json.loads(log.read_text())
    assert authenticated["hash"] == row["hash"]
    assert authenticated["auth"]
    assert json.loads(head.read_text())["hash"] == row["hash"]


@pytest.mark.parametrize(
    ("broken", "message"),
    [
        ([{"rec": [], "hash": "invalid"}], "registry line 1 malformed"),
        (
            [{"rec": _rec(), "format_version": 42, "seq": 1, "prev": "GENESIS", "hash": "unknown"}],
            "mixed or unknown",
        ),
        ([_legacy(_rec()), _v2(_rec("bob"))], "mixed or unknown"),
        ([{"rec": _rec(), "hash": "wrong"}], "legacy registry line 1 hash mismatch"),
    ],
)
def test_malformed_or_mixed_registry_is_refused_before_any_hmac_rewrite(
    tmp_path, local_key, broken, message
):
    log, head = _registry(tmp_path, broken)
    original = log.read_bytes()
    with pytest.raises(agents.RegistryIntegrityError, match=message):
        agents.initialize_registry_auth(tmp_path, local_key)
    assert log.read_bytes() == original
    assert not head.exists()


@pytest.mark.parametrize(
    ("modify", "message"),
    [
        ({"seq": 2}, "sequence/prev mismatch"),
        ({"prev": "not-genesis"}, "sequence/prev mismatch"),
        ({"hash": "corrupt"}, "hash mismatch"),
    ],
)
def test_invalid_v2_sequence_hash_or_prev_is_refused_without_resealing(
    tmp_path, local_key, modify, message
):
    value = _v2(_rec())
    value.update(modify)
    log, head = _registry(tmp_path, [value])
    prior = log.read_bytes()
    with pytest.raises(agents.RegistryIntegrityError, match=message):
        agents.initialize_registry_auth(tmp_path, local_key)
    assert log.read_bytes() == prior
    assert not head.exists()


def test_missing_v2_checkpoint_refuses_automatic_recovery(tmp_path, local_key):
    log, head = _registry(tmp_path, [_v2(_rec())])
    with pytest.raises(agents.RegistryIntegrityError, match="head missing or invalid"):
        agents.initialize_registry_auth(tmp_path, local_key)
    assert not head.exists()
    assert '"auth"' not in log.read_text()


def test_v2_checkpoint_hash_mismatch_blocks_authentication(tmp_path, local_key):
    row = _v2(_rec())
    log, head = _registry(tmp_path, [row])
    head.write_text('{"seq":1,"hash":"untrusted"}')
    with pytest.raises(agents.RegistryIntegrityError, match="head mismatch"):
        agents.initialize_registry_auth(tmp_path, local_key)
    assert json.loads(log.read_text()).get("auth") is None


def test_v2_checkpoint_nonobject_fails_closed(tmp_path, local_key):
    log, head = _registry(tmp_path, [_v2(_rec())])
    head.write_text("[]")
    with pytest.raises(agents.RegistryIntegrityError, match="head mismatch"):
        agents.initialize_registry_auth(tmp_path, local_key)
    assert json.loads(log.read_text()).get("auth") is None


def test_signed_migrated_registry_can_be_verified_with_the_same_external_key(
    monkeypatch, tmp_path, local_key
):
    log, head = _registry(tmp_path, [_legacy(_rec())])
    agents.initialize_registry_auth(tmp_path, local_key)
    monkeypatch.setattr(agents, "runtime_key", lambda _: local_key)
    instance = agents.MultiAgentRegistry(str(tmp_path))
    assert instance.verify_registry_chain()
    assert instance.registry_tampered is False
