"""Registry locking must never discard a live owner or report unsafe release as success."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor import lock_hardening as lh
from supervisor.agents import RegistryIntegrityError


def make_lock(path, pid=123456, token="old-owner"):
    path.write_text(json.dumps({"pid": pid, "token": token}))
    return lh._read_lock(path)


def hardened_stub(path, timeout=0.03):
    class Stub:
        REGISTRY_LOCK_TIMEOUT = timeout

        def __init__(self):
            self.lock_path = path

        def _ensure_dirs(self):
            self.lock_path.parent.mkdir(parents=True, exist_ok=True)

    lh.install_registry_lock_hardening(Stub)
    return Stub()


def test_missing_lock_record_has_no_fabricated_owner(tmp_path):
    assert lh._read_lock(tmp_path / "missing.json") is None


@pytest.mark.parametrize("raw", ["not json", "[]", '{"pid":'])
def test_malformed_partial_lock_payload_has_no_valid_owner_identity(tmp_path, raw):
    path = tmp_path / "lock"
    path.write_text(raw)
    out = lh._read_lock(path)
    assert out.get("malformed") is True


def test_inode_replacement_during_record_read_is_an_untrusted_identity(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    make_lock(lock)
    old_stat = Path.stat
    number = {"n": 0}

    def changing(self, *args, **kwargs):
        recorded = old_stat(self, *args, **kwargs)
        if self == lock:
            number["n"] += 1
            return SimpleNamespace(st_dev=recorded.st_dev, st_ino=recorded.st_ino + number["n"])
        return recorded

    monkeypatch.setattr(Path, "stat", changing)
    assert lh._read_lock(lock) == {"changed": True}


@pytest.mark.parametrize("pid", [None, True, 0, -1, "1000", 3.5])
def test_untrusted_lock_owner_pid_cannot_authorize_eviction(monkeypatch, tmp_path, pid):
    lock = tmp_path / "lock"
    owner = make_lock(lock)
    owner["pid"] = pid
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: False)
    assert lh._remove_dead_owner_lock(lock, owner) is False
    assert lock.exists()


def test_an_active_owner_lock_is_never_removed_even_if_old(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    owner = make_lock(lock, pid=os.getpid())
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: True)
    assert lh._remove_dead_owner_lock(lock, owner) is False
    assert lock.exists()


def test_proven_dead_owner_lock_can_be_recovered_with_unchanged_identity(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    owner = make_lock(lock)
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: False)
    assert lh._remove_dead_owner_lock(lock, owner) is True
    assert not lock.exists()


def test_dead_owner_recheck_refuses_pid_token_mutation(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    owner = make_lock(lock)
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: False)
    make_lock(lock, pid=123456, token="new-owner")
    assert lh._remove_dead_owner_lock(lock, owner) is False
    assert lock.exists()


def test_dead_owner_recheck_refuses_inode_mutation(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    owner = make_lock(lock)
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: False)
    new_owner = dict(owner, _identity=(0, 0))
    assert lh._remove_dead_owner_lock(lock, new_owner) is False
    assert lock.exists()


def test_dead_owner_lock_unlink_permission_error_returns_false(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    owner = make_lock(lock)
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: False)
    original = Path.unlink

    def refuse(self, *args, **kwargs):
        if self == lock:
            raise PermissionError("not permitted to unlink foreign lock")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    assert lh._remove_dead_owner_lock(lock, owner) is False


def test_live_registry_lock_is_acquired_and_released_with_real_process_id(tmp_path):
    lock = tmp_path / "registry.lock"
    stub = hardened_stub(lock)
    with stub._write_lock():
        recorded = lh._read_lock(lock)
        assert recorded["pid"] == os.getpid()
        assert len(recorded["token"]) > 12
    assert not lock.exists()


def test_existing_malformed_registry_lock_is_never_evicted_after_timeout(tmp_path):
    lock = tmp_path / "registry.lock"
    lock.write_text('{"pid":')
    stub = hardened_stub(lock, timeout=0.01)
    with pytest.raises(RegistryIntegrityError, match="remained malformed"):
        with stub._write_lock():
            pytest.fail("must not enter protected body")
    assert lock.exists()


def test_live_registry_lock_is_not_evicted_by_timeout(tmp_path):
    lock = tmp_path / "registry.lock"
    make_lock(lock, pid=os.getpid())
    stub = hardened_stub(lock, timeout=0.01)
    with pytest.raises(RegistryIntegrityError, match="write lock timeout"):
        with stub._write_lock():
            pytest.fail("must not enter protected body")
    assert lock.exists()


def test_registry_release_fails_closed_if_another_actor_replaces_owner(tmp_path):
    lock = tmp_path / "registry.lock"
    stub = hardened_stub(lock)
    with pytest.raises(RegistryIntegrityError, match="identity changed while held"):
        with stub._write_lock():
            make_lock(lock, pid=os.getpid(), token="someone-else")
    assert lock.exists()


def test_registry_held_body_error_is_not_silenced_even_when_lock_was_replaced(tmp_path):
    lock = tmp_path / "registry.lock"
    stub = hardened_stub(lock)
    failure = None
    try:
        with stub._write_lock():
            make_lock(lock, pid=os.getpid(), token="someone-else")
            raise RuntimeError("original verification failed")
    except RuntimeError as exc:
        failure = exc
    assert failure is not None
    assert "original verification failed" in str(failure)
    assert lock.exists()


def test_release_permission_error_must_block_success(monkeypatch, tmp_path):
    lock = tmp_path / "registry.lock"
    stub = hardened_stub(lock)
    original = Path.unlink

    def refuse(self, *args, **kwargs):
        if self == lock:
            raise PermissionError("simulated protected lock file")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    with pytest.raises(RegistryIntegrityError, match="cannot release agent registry write lock"):
        with stub._write_lock():
            assert lock.exists()


def test_install_registry_hardener_is_idempotent_on_explicit_throwaway_class(tmp_path):
    lock = tmp_path / "lock"
    stub = hardened_stub(lock)
    original = type(stub)._write_lock
    installed = lh.install_registry_lock_hardening(type(stub))
    assert type(stub)._write_lock is original
    assert installed["installed"] is True
    assert installed["_write_lock"] is True


def test_dead_owner_lock_removed_before_second_read_is_not_claimed_as_evicted(
    monkeypatch, tmp_path
):
    lock = tmp_path / "lock"
    owner = make_lock(lock)
    lock.unlink()
    monkeypatch.setattr(lh, "_safe_pid_alive", lambda _: False)
    assert lh._remove_dead_owner_lock(lock, owner) is False


def test_nonpositive_configured_lock_timeout_uses_bounded_default_and_can_acquire(tmp_path):
    lock = tmp_path / "lock"
    stub = hardened_stub(lock, timeout=-10.0)
    with stub._write_lock():
        assert lock.exists()
    assert not lock.exists()


def test_body_failure_is_preserved_when_lock_cleanup_is_also_denied(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    stub = hardened_stub(lock)
    original = Path.unlink

    def refuse(self, *args, **kwargs):
        if self == lock:
            raise PermissionError("cleanup unavailable")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    failure = None
    try:
        with stub._write_lock():
            raise RuntimeError("original protected body failure")
    except RuntimeError as exc:
        failure = exc
    assert failure is not None
    assert "original protected body failure" in str(failure)
    assert lock.exists()
