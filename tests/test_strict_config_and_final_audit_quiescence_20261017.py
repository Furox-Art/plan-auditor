"""Filesystem and policy settings cannot bypass the final independent audit."""

from __future__ import annotations

import contextlib
import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor import audit_session, config


def _write_config(root: Path, value: object):
    path = root / ".plan-auditor" / "supervisor.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("key", "bad_value", "error_fragment"),
    [
        ("profile", 1, "profile must be a string"),
        ("profile", "invented", "invalid profile"),
        ("tier", True, "invalid tier"),
        ("tier", 9, "invalid tier"),
        ("mode", 4, "mode must be a string"),
        ("mode", "invented", "invalid mode"),
        ("pg_dir", False, "pg_dir must be a string"),
        ("pg_dir", "custom", "pg_dir is fixed"),
        ("policies_dir", "../outside", "policies_dir must"),
        ("policies_dir", "/outside", "policies_dir must"),
        ("extra", [], "extra must be an object"),
        ("max_attempts", False, "max_attempts must be an integer"),
        ("max_attempts", 0, "max_attempts must be between"),
        ("heartbeat_sec", 3601, "heartbeat_sec must be between"),
    ],
)
def test_invalid_supervisor_configuration_never_silently_gets_permission(
    tmp_path, key, bad_value, error_fragment
):
    _write_config(tmp_path, {key: bad_value})
    out = config.load_config(str(tmp_path))
    assert out.valid is False
    assert any(error_fragment in error for error in out.errors)
    assert out.workspace_root == str(tmp_path.resolve())


@pytest.mark.parametrize("source", ["[]", '""', "bad JSON"])
def test_supervisor_config_refuses_nonobject_or_malformed_json(tmp_path, source):
    p = _write_config(tmp_path, {})
    p.write_text(source, encoding="utf-8")
    out = config.load_config(str(tmp_path))
    assert out.valid is False
    assert any("config" in error for error in out.errors)


def test_supervisor_config_refuses_directory_as_config_file(tmp_path):
    root = tmp_path / ".plan-auditor"
    root.mkdir()
    (root / "supervisor.json").mkdir()
    out = config.load_config(str(tmp_path))
    assert not out.valid
    assert any("regular file" in err for err in out.errors)


def test_valid_strict_profile_includes_extra_quiescence_layer(tmp_path):
    _write_config(
        tmp_path,
        {"profile": "STRICT", "tier": 1, "mode": "serial", "max_attempts": 7, "heartbeat_sec": 3},
    )
    out = config.load_config(str(tmp_path))
    assert out.valid, out.errors
    assert out.profile == config.Profile.STRICT
    assert "L12" in out.active_layers()
    assert out.max_attempts == 7
    assert out.heartbeat_sec == 3


def test_light_profile_cannot_be_claimed_to_have_strict_checks():
    light = config.Config(profile=config.Profile.LIGHT)
    standard = config.Config(profile=config.Profile.STANDARD)
    strict = config.Config(profile=config.Profile.STRICT)
    assert "L12" not in light.active_layers()
    assert "L12" not in standard.active_layers()
    assert "L12" in strict.active_layers()


def _fake_registry(*, agents=None, tampered=False, legacy=False):
    registry = SimpleNamespace()
    registry.registry_tampered = tampered
    registry.registry_problem = "refused hash chain" if tampered else ""
    registry.registry_legacy = legacy
    registry._agents = agents or {}
    registry.owner_timeout = 60
    registry._write_lock = lambda: contextlib.nullcontext()
    registry._refresh_from_disk = lambda: None
    registry._migrate_legacy_locked = lambda: None
    return registry


def test_malformed_freeze_marker_is_preserved_for_operator_review(tmp_path):
    path = audit_session.freeze_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("not-json")
    with pytest.raises(audit_session.AuditSessionError, match="malformed"):
        audit_session._remove_provably_stale(path)
    assert path.read_text() == "not-json"


def test_active_previous_audit_is_not_removed_or_overwritten(tmp_path, monkeypatch):
    path = audit_session.freeze_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"pid":123}', encoding="utf-8")
    monkeypatch.setattr(audit_session, "pid_alive", lambda pid: True)
    with pytest.raises(audit_session.AuditSessionError, match="another final audit is active"):
        audit_session._remove_provably_stale(path)
    assert path.exists()


def test_provably_dead_freeze_is_removed_before_new_audit(tmp_path, monkeypatch):
    path = audit_session.freeze_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"pid":123}', encoding="utf-8")
    monkeypatch.setattr(audit_session, "pid_alive", lambda pid: False)
    audit_session._remove_provably_stale(path)
    assert not path.exists()


def test_tampered_registry_prevents_final_audit_before_freezing(tmp_path):
    with pytest.raises(audit_session.AuditSessionError, match="registry integrity failed"):
        with audit_session.final_audit_session(tmp_path, _fake_registry(tampered=True)):
            pytest.fail("must not start audit")


def test_live_agent_prevents_quiescence_claim(tmp_path):
    actor = SimpleNamespace(agent_id="agent-01", state="active", last_heartbeat=time.time())
    registry = _fake_registry(agents={"agent-01": actor})
    with pytest.raises(audit_session.AuditSessionError, match="active agents: agent-01"):
        with audit_session.final_audit_session(tmp_path, registry):
            pytest.fail("must not audit a workspace while agents mutate it")


def test_clean_audit_freeze_is_removed_after_successful_invariant_check(tmp_path):
    (tmp_path / "source.txt").write_text("unchanged")
    with audit_session.final_audit_session(tmp_path, _fake_registry()) as before:
        assert before
        assert audit_session.freeze_path(tmp_path).is_file()
    assert not audit_session.freeze_path(tmp_path).exists()


def test_content_change_during_final_audit_refuses_completion(tmp_path):
    source = tmp_path / "source.txt"
    source.write_text("original", encoding="utf-8")
    with pytest.raises(
        audit_session.AuditSessionError, match="workspace content/type/mode changed"
    ):
        with audit_session.final_audit_session(tmp_path, _fake_registry()):
            source.write_text("changed", encoding="utf-8")
    assert not audit_session.freeze_path(tmp_path).exists()


def test_user_audit_failure_remains_original_not_replaced_by_secondary_state(tmp_path):
    (tmp_path / "source.txt").write_text("original")
    with pytest.raises(RuntimeError, match="original audit failure"):
        with audit_session.final_audit_session(tmp_path, _fake_registry()):
            raise RuntimeError("original audit failure")
    assert not audit_session.freeze_path(tmp_path).exists()


def test_external_change_to_freeze_refuses_claiming_success(tmp_path):
    (tmp_path / "source.txt").write_text("original")
    with pytest.raises(audit_session.AuditSessionError, match="freeze was modified"):
        with audit_session.final_audit_session(tmp_path, _fake_registry()):
            path = audit_session.freeze_path(tmp_path)
            record = json.loads(path.read_text())
            record["token"] = "tampered"
            path.write_text(json.dumps(record))
