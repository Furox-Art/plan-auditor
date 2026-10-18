"""Real registry migration failures, persistence I/O errors, and HMAC refusal paths."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import supervisor.agents as a
from scripts.integrity import KeyMaterial
from supervisor.agents import Agent, MultiAgentRegistry, RegistryIntegrityError


def _legacy(rec):
    return {"rec": rec, "hash": a._legacy_hash(rec)}


def _log(registry, records):
    registry.agents_dir.mkdir(parents=True, exist_ok=True)
    registry.registry_path.write_text("".join(json.dumps(r) + "\n" for r in records))


def test_legacy_reader_handles_absent_and_blank_lines(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    assert registry._legacy_records() == []
    _log(registry, [_legacy({"event": "join", "agent": {"agent_id": "a"}})])
    registry.registry_path.write_text("  \n" + registry.registry_path.read_text())
    assert len(registry._legacy_records()) == 1


@pytest.mark.parametrize(
    "value,description",
    [
        ({"rec": None, "hash": "wrong"}, "malformed"),
        ({"rec": {"event": "join"}, "hash": "wrong"}, "hash mismatch"),
        ({**_legacy({"event": "join"}), "seq": 1}, "mixed-format"),
    ],
)
def test_legacy_reader_rejects_untrusted_envelope(tmp_path, value, description):
    reg = MultiAgentRegistry(str(tmp_path))
    _log(reg, [value])
    with pytest.raises(RegistryIntegrityError, match=description):
        reg._legacy_records()


def test_legacy_migration_with_no_existing_log_writes_empty_trusted_v2_log(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg._ensure_dirs()
    reg._migrate_legacy_locked()
    assert reg.registry_path.is_file()
    assert reg.registry_path.read_text() == ""
    assert not reg.head_path.exists()
    assert reg._registry_seq == 0


def test_empty_legacy_migration_removes_existing_stale_head(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg._ensure_dirs()
    reg.head_path.write_text("untrusted old checkpoint")
    reg._migrate_legacy_locked()
    assert reg.registry_path.is_file()
    assert not reg.head_path.exists()


def test_legacy_reader_can_report_corrupt_second_line(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    _log(reg, [_legacy({"event": "join", "agent": {"agent_id": "a"}}), {"rec": []}])
    with pytest.raises(RegistryIntegrityError, match="line 2 malformed"):
        reg._legacy_records()


def test_authenticated_registry_logs_unreadable_refuses_head(monkeypatch, tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg.register(Agent("a", "t", "p"))
    key = KeyMaterial(b"t" * 32, "test fixture", "key-id")
    a.initialize_registry_auth(tmp_path, key)
    monkeypatch.setattr(a, "runtime_key", lambda root: key)
    original_read = Path.read_text

    def fail_registry_only(path, *args, **kwargs):
        if path == reg.registry_path:
            raise PermissionError("injected access denial")
        return original_read(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", fail_registry_only)
    ok, error = reg._verify_registry_auth()
    assert not ok
    assert "registry unreadable" in error


def test_authenticated_registry_blank_lines_are_allowed(monkeypatch, tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg.register(Agent("a", "t", "p"))
    key = KeyMaterial(b"t" * 32, "test fixture", "key-id")
    a.initialize_registry_auth(tmp_path, key)
    monkeypatch.setattr(a, "runtime_key", lambda root: key)
    reg.registry_path.write_text("\n" + reg.registry_path.read_text())
    assert reg._verify_registry_auth() == (True, "")


def test_authenticated_head_disagrees_with_persisted_sequence(monkeypatch, tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg.register(Agent("a", "t", "p"))
    key = KeyMaterial(b"t" * 32, "test fixture", "key-id")
    a.initialize_registry_auth(tmp_path, key)
    monkeypatch.setattr(a, "runtime_key", lambda root: key)
    assert reg._verify_registry_auth() == (True, "")
    reg._registry_seq += 1
    assert "checkpoint mismatch" in reg._verify_registry_auth()[1]


def test_legacy_agent_write_lock_file_error_is_refusal(monkeypatch, tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    original_write = Path.write_text

    def fail_only_lock(path, *args, **kwargs):
        if path.name == "test.lock":
            raise PermissionError("read-only disk")
        return original_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_only_lock)
    assert reg.write_lock("test") is None


def test_initialize_hmac_existing_empty_log_writes_signed_head(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg._ensure_dirs()
    reg.registry_path.write_text("")
    key = KeyMaterial(b"t" * 32, "test fixture", "key-id")
    a.initialize_registry_auth(tmp_path, key)
    assert reg.registry_path.read_text() == ""
    assert json.loads(reg.head_path.read_text())["seq"] == 0


def test_initialize_hmac_ignores_blank_existing_registry_lines(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    reg._ensure_dirs()
    reg.registry_path.write_text("\n  \n", encoding="utf-8")
    key = KeyMaterial(b"t" * 32, "test fixture", "key-id")
    a.initialize_registry_auth(tmp_path, key)
    assert json.loads(reg.head_path.read_text())["seq"] == 0
    assert reg.registry_path.read_text() == ""
