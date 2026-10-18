"""Real registry writer-lock boundaries with explicit filesystem fault injection."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from supervisor import agents


def test_registry_writer_lock_is_exclusive_and_removed_after_success(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    with registry._write_lock():
        assert registry.lock_path.is_file()
        assert registry.lock_path.stat().st_mode & 0o777 == 0o600
    assert not registry.lock_path.exists()


def test_registry_writer_lock_is_removed_after_body_error(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    with pytest.raises(RuntimeError, match="original audit failure"):
        with registry._write_lock():
            raise RuntimeError("original audit failure")
    assert not registry.lock_path.exists()


def test_registry_writer_lock_recovers_provably_stale_lock(tmp_path):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.lock_path.write_text('{"pid": 999999999, "token": "dead-lock-owner", "created": 0}', encoding="utf-8")
    old = time.time() - agents.REGISTRY_LOCK_STALE - 5
    os.utime(registry.lock_path, (old, old))
    with registry._write_lock():
        assert "dead-lock-owner" not in registry.lock_path.read_text(encoding="utf-8")
    assert not registry.lock_path.exists()


def test_live_registry_writer_lock_times_out_without_stealing_it(tmp_path, monkeypatch):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.lock_path.write_text(f'{{"pid": {os.getpid()}, "token": "live-lock-owner"}}', encoding="utf-8")
    monkeypatch.setattr(registry, "REGISTRY_LOCK_TIMEOUT", 0.001, raising=False)
    with pytest.raises(agents.RegistryIntegrityError, match="write lock timeout"):
        with registry._write_lock():
            pytest.fail("must never enter a locked registry")
    assert "live-lock-owner" in registry.lock_path.read_text(encoding="utf-8")


def test_lock_metadata_failure_never_makes_a_live_lock_look_stale(tmp_path, monkeypatch):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.lock_path.write_text("other writer", encoding="utf-8")
    original = Path.stat

    def inaccessible(self, *args, **kwargs):
        if self == registry.lock_path:
            raise OSError("simulated missing lock metadata")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", inaccessible)
    monkeypatch.setattr(registry, "REGISTRY_LOCK_TIMEOUT", 0.001, raising=False)
    with pytest.raises(agents.RegistryIntegrityError, match="remained malformed"):
        with registry._write_lock():
            pytest.fail("must not steal another writer's lock")
    assert registry.lock_path.read_text(encoding="utf-8") == "other writer"


def test_lock_release_failure_does_not_turn_successful_body_into_false_exception(
    tmp_path, monkeypatch
):
    registry = agents.MultiAgentRegistry(str(tmp_path))
    original = Path.unlink

    def refuse_release(self, *args, **kwargs):
        if self == registry.lock_path:
            raise OSError("simulated readonly lock directory")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse_release)
    with pytest.raises(agents.RegistryIntegrityError, match="cannot release agent registry write lock"):
        with registry._write_lock():
            assert registry.lock_path.is_file()
    assert registry.lock_path.is_file()
