"""Final audit never loses integrity errors while freezing or releasing the workspace."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor import audit_session


def registry(*, legacy=False):
    state = SimpleNamespace()
    state.registry_tampered = False
    state.registry_problem = ""
    state.registry_legacy = legacy
    state._agents = {}
    state.owner_timeout = 60
    state._write_lock = contextlib.nullcontext
    state._refresh_from_disk = lambda: None
    state._migrate_legacy_locked = lambda: None
    return state


def freeze_marker(root):
    path = audit_session.freeze_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def test_dead_audit_lock_failure_cannot_be_disguised_as_proven_stale(monkeypatch, tmp_path):
    path = freeze_marker(tmp_path)
    path.write_text('{"pid":98765}')
    monkeypatch.setattr(audit_session, "pid_alive", lambda _: False)
    original = Path.unlink

    def denied(self, *a, **kw):
        if self == path:
            raise OSError("sticky directory denies unlink")
        return original(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", denied)
    with pytest.raises(audit_session.AuditSessionError, match="cannot remove stale audit freeze"):
        audit_session._remove_provably_stale(path)
    assert path.exists()


def test_legacy_registry_migration_failure_blocks_final_audit():
    state = registry(legacy=True)

    def bad():
        raise OSError("migration audit required")

    state._migrate_legacy_locked = bad
    with pytest.raises(audit_session.AuditSessionError, match="registry migration failed"):
        audit_session._verify_registry_locked(state)


def test_registry_tamper_detected_after_legacy_migration_also_blocks_final_audit():
    state = registry(legacy=True)
    refreshes = []

    def refresh():
        refreshes.append(1)
        if len(refreshes) == 2:
            state.registry_tampered = True
            state.registry_problem = "newly detected tampering"

    state._refresh_from_disk = refresh
    with pytest.raises(audit_session.AuditSessionError, match="newly detected tampering"):
        audit_session._verify_registry_locked(state)


def test_final_audit_file_exists_race_returns_distinct_locked_error(monkeypatch, tmp_path):
    state = registry()
    original = audit_session.os.open
    path = freeze_marker(tmp_path)

    def contend(filename, *a, **kw):
        if str(filename) == str(path):
            raise FileExistsError("racing auditor lock")
        return original(filename, *a, **kw)

    monkeypatch.setattr(audit_session.os, "open", contend)
    with pytest.raises(audit_session.AuditSessionError, match="final audit freeze already exists"):
        with audit_session.final_audit_session(tmp_path, state):
            pytest.fail("must refuse a second audit")


def test_audit_freeze_release_failure_cannot_be_reported_as_success(monkeypatch, tmp_path):
    state = registry()
    path = freeze_marker(tmp_path)
    original = Path.unlink

    def unlink(self, *a, **kw):
        if self == path:
            raise OSError("read-only release path")
        return original(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", unlink)
    with pytest.raises(audit_session.AuditSessionError, match="cannot release final audit freeze"):
        with audit_session.final_audit_session(tmp_path, state):
            assert path.exists()
    assert path.exists()


def test_user_run_error_is_preserved_even_if_freeze_release_fails(monkeypatch, tmp_path):
    state = registry()
    path = freeze_marker(tmp_path)
    original = Path.unlink

    def fail(self, *a, **kw):
        if self == path:
            raise OSError("separate cleanup failure")
        return original(self, *a, **kw)

    monkeypatch.setattr(Path, "unlink", fail)
    try:
        with audit_session.final_audit_session(tmp_path, state):
            raise RuntimeError("original audit work failure")
    except RuntimeError as exc:
        assert "original audit work failure" in str(exc)
    else:
        raise AssertionError("expected the original audit failure to propagate")
    assert path.exists()


def test_original_audit_error_wins_when_attacker_also_mutates_freeze(tmp_path):
    state = registry()
    with pytest.raises(RuntimeError, match="original independent audit rejection"):
        with audit_session.final_audit_session(tmp_path, state):
            path = audit_session.freeze_path(tmp_path)
            record = json.loads(path.read_text())
            record["token"] = "tampered"
            path.write_text(json.dumps(record))
            raise RuntimeError("original independent audit rejection")
