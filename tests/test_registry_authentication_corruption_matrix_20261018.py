"""Real HMAC verification and registry corruption refusals on isolated directories."""

from __future__ import annotations

import json

import pytest

import supervisor.agents as registry_module
from scripts.integrity import IntegrityKeyError, KeyMaterial, make_auth
from supervisor.agents import (
    Agent,
    MultiAgentRegistry,
    RegistryIntegrityError,
    initialize_registry_auth,
)


def key_material():
    return KeyMaterial(key=b"k" * 32, source="isolated fixture", key_id="isolated-key")


def registry(tmp_path):
    return MultiAgentRegistry(str(tmp_path))


def signed_empty(tmp_path, monkeypatch):
    reg = registry(tmp_path)
    key = key_material()
    initialize_registry_auth(tmp_path, key)
    monkeypatch.setattr(registry_module, "runtime_key", lambda _: key)
    return reg, key


def test_real_empty_signed_registry_head_is_accepted(tmp_path, monkeypatch):
    reg, key = signed_empty(tmp_path, monkeypatch)
    assert reg._verify_registry_auth() == (True, "")
    assert reg.verify_registry_chain() is True


def test_signed_registry_head_missing_refuses_authenticated_mode(tmp_path, monkeypatch):
    reg = registry(tmp_path)
    monkeypatch.setattr(registry_module, "runtime_key", lambda _: key_material())
    assert reg._verify_registry_auth() == (False, "authenticated registry head missing")


def test_unconfigured_key_failure_is_not_silenced(tmp_path, monkeypatch):
    reg = registry(tmp_path)

    def fail(_):
        raise IntegrityKeyError("invalid external key file")

    monkeypatch.setattr(registry_module, "runtime_key", fail)
    assert reg._verify_registry_auth() == (False, "invalid external key file")


def test_unsigned_registry_rejects_signed_record_without_key(tmp_path):
    reg = registry(tmp_path)
    reg.agents_dir.mkdir(parents=True, exist_ok=True)
    reg.registry_path.write_text(json.dumps({"auth": "not trusted"}) + "\n", encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "authenticated registry requires HMAC key")


def test_unsigned_registry_rejects_signed_head_without_key(tmp_path):
    reg = registry(tmp_path)
    reg.agents_dir.mkdir(parents=True, exist_ok=True)
    reg.head_path.write_text(json.dumps({"auth": "unexpected"}), encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "authenticated registry head requires HMAC key")


def test_head_without_registry_is_rejected_in_unsigned_mode(tmp_path):
    reg = registry(tmp_path)
    reg.agents_dir.mkdir(parents=True, exist_ok=True)
    reg.head_path.write_text(json.dumps({"format_version": 2}), encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "registry head exists without records")


def test_authenticated_registry_corrupt_head_json_is_rejected(tmp_path, monkeypatch):
    reg, _ = signed_empty(tmp_path, monkeypatch)
    reg.head_path.write_text("{", encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "authenticated registry head unreadable")


@pytest.mark.parametrize("value", [None, 4, []])
def test_authenticated_registry_nonobject_head_is_rejected(tmp_path, monkeypatch, value):
    reg, _ = signed_empty(tmp_path, monkeypatch)
    reg.head_path.write_text(json.dumps(value), encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "authenticated registry head malformed")


def test_authenticated_head_missing_mac_is_rejected(tmp_path, monkeypatch):
    reg, _ = signed_empty(tmp_path, monkeypatch)
    reg.head_path.write_text(
        json.dumps({"format_version": 2, "seq": 0, "hash": "GENESIS"}), encoding="utf-8"
    )
    assert reg._verify_registry_auth() == (False, "registry head HMAC authentication failed")


def test_valid_signed_but_inconsistent_empty_head_is_rejected(tmp_path, monkeypatch):
    reg, key = signed_empty(tmp_path, monkeypatch)
    payload = {"format_version": 2, "seq": 1, "hash": "nonexistent"}
    signed = {**payload, "auth": make_auth(key, registry_module.REGISTRY_HEAD_DOMAIN, payload)}
    reg.head_path.write_text(json.dumps(signed), encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "empty registry authenticated head mismatch")


def test_legacy_authentication_scan_refuses_invalid_json(tmp_path):
    reg = registry(tmp_path)
    reg.agents_dir.mkdir(parents=True, exist_ok=True)
    reg.registry_path.write_text("NOT JSON\n", encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "registry authentication scan failed")


def test_real_signed_registry_rejects_record_missing_mac(tmp_path, monkeypatch):
    reg = registry(tmp_path)
    reg.register(Agent(agent_id="a", task_id="t", plan_id="p"))
    key = key_material()
    initialize_registry_auth(tmp_path, key)
    monkeypatch.setattr(registry_module, "runtime_key", lambda _: key)
    assert reg._verify_registry_auth() == (True, "")
    rows = [json.loads(line) for line in reg.registry_path.read_text().splitlines()]
    rows[0].pop("auth")
    reg.registry_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "registry line 1 HMAC authentication failed")


def test_invalid_registry_record_not_signed_into_trusted_state(tmp_path):
    reg = registry(tmp_path)
    reg.agents_dir.mkdir(parents=True, exist_ok=True)
    reg.registry_path.write_text(json.dumps({"rec": 2}) + "\n", encoding="utf-8")
    with pytest.raises(RegistryIntegrityError, match="malformed"):
        initialize_registry_auth(tmp_path, key_material())
    assert not reg.head_path.exists()


def test_valid_signed_head_but_corrupt_record_is_refused(tmp_path, monkeypatch):
    reg, _ = signed_empty(tmp_path, monkeypatch)
    reg.registry_path.write_text("{\n", encoding="utf-8")
    assert reg._verify_registry_auth() == (False, "registry line 1 is not JSON")
