"""Actual agent file ownership confinement and immutable final audit freeze."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor import agents_hardening as hard
from supervisor.agents import Agent, MultiAgentRegistry, RegistryIntegrityError


@pytest.mark.parametrize(
    "identifier", ["", ".", "..", "../outside", "bad name", "_bad", "x" * 129, None, True]
)
def test_agent_ids_are_safe_single_filename_components(identifier):
    with pytest.raises(ValueError, match="safe basename"):
        hard.validate_agent_id(identifier)


@pytest.mark.parametrize("identifier", ["agent-1", "node.test", "A_2", "z" * 128])
def test_valid_agent_ids_keep_an_exact_identity(identifier):
    assert hard.validate_agent_id(identifier) == identifier


@pytest.mark.parametrize(
    ("owned", "message"),
    [
        ("", "non-empty"),
        (None, "non-empty"),
        ("/tmp/outside", "workspace-relative"),
        ("../outside", "escapes workspace"),
        (".", "below the workspace"),
    ],
)
def test_file_ownership_must_be_workspace_confined(tmp_path, owned, message):
    with pytest.raises(ValueError, match=message):
        hard.canonical_owned_path(tmp_path, owned)


def test_valid_relative_file_path_is_canonicalized_without_dropping_identity(tmp_path):
    assert hard.canonical_owned_path(tmp_path, "a/../b/file.py") == "b/file.py"


def test_external_symlink_cannot_be_owned_as_an_internal_file(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-elsewhere")
    outside.mkdir()
    (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes workspace"):
        hard.canonical_owned_path(tmp_path, "escape/secret.txt")


@pytest.mark.parametrize("pid", [None, False, True, 0, -3, 1.1, "123"])
def test_invalid_pid_does_not_probe_an_unrelated_process(pid):
    assert hard._safe_pid_alive(pid) is False


def test_stale_final_audit_freeze_is_removed_only_on_proved_dead_pid(monkeypatch, tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    marker = hard._freeze_path(registry)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"pid": 321}))
    monkeypatch.setattr(hard, "_safe_pid_alive", lambda _: False)
    assert hard._audit_freeze_active(registry) is False
    assert not marker.exists()


def test_live_final_audit_freeze_blocks_registered_agent_write(monkeypatch, tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    marker = hard._freeze_path(registry)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps({"pid": 321}))
    monkeypatch.setattr(hard, "_safe_pid_alive", lambda _: True)
    with pytest.raises(RegistryIntegrityError, match="freeze is active"):
        registry.register(Agent("alpha", "task", "plan"))
    assert marker.is_file()
    assert not registry.registry_path.exists()


def test_malformed_freeze_is_an_active_barrier_not_a_stale_one(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    marker = hard._freeze_path(registry)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("not-json")
    assert hard._audit_freeze_active(registry)
    with pytest.raises(RegistryIntegrityError, match="freeze is active"):
        registry.register(Agent("alpha", "task", "plan"))


def test_unreadable_stale_freeze_cannot_be_deleted_or_construed_as_permission(
    monkeypatch, tmp_path
):
    registry = MultiAgentRegistry(str(tmp_path))
    marker = hard._freeze_path(registry)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text('{"pid":123}')
    monkeypatch.setattr(hard, "_safe_pid_alive", lambda _: False)
    original = Path.unlink

    def refuse(self, *args, **kwargs):
        if self == marker:
            raise PermissionError("simulated locked marker")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)
    assert hard._audit_freeze_active(registry)
    assert marker.exists()


def test_pid_permission_denied_still_means_a_foreign_process_may_be_alive(monkeypatch):
    def denied(*args):
        raise PermissionError("no permission to signal another user's PID")

    monkeypatch.setattr(hard.os, "kill", denied)
    assert hard._safe_pid_alive(87542)


def test_genuinely_missing_pid_is_not_assumed_alive(monkeypatch):
    def nonexistent(*args):
        raise ProcessLookupError("process exited")

    monkeypatch.setattr(hard.os, "kill", nonexistent)
    assert not hard._safe_pid_alive(87542)


def test_only_registered_agents_can_claim_a_file(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    with pytest.raises(RegistryIntegrityError, match="unknown agent"):
        registry.claim_files("ghost", {"file.py"})


def test_unknown_agent_cannot_change_ownership_or_heartbeat(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    with pytest.raises(RegistryIntegrityError, match="unknown agent"):
        registry.update_ownership("ghost", {"file.py"})
    with pytest.raises(RegistryIntegrityError, match="unknown agent"):
        registry.heartbeat("ghost")


def test_unapproved_parallel_mode_cannot_be_silent_warning(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("alice", "task", "plan"))
    with pytest.raises(ValueError, match="invalid agent coordination mode"):
        registry.claim_files("alice", {"file.py"}, mode="trust-everyone")


def test_untrusted_owned_file_from_another_workspace_is_not_a_conflict_report(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("alice", "task", "plan"))
    registry.register(Agent("bob", "task", "plan"))
    registry._agents["alice"].owned_files = {"/tmp/outside.txt"}
    with pytest.raises(RegistryIntegrityError, match="invalid persisted ownership path"):
        hard._current_conflicts_locked(registry, "bob", {"file.py"})
    assert registry.registry_tampered


def test_lock_file_with_boolean_pid_is_stale_not_authenticated(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.agents_dir.mkdir(parents=True, exist_ok=True)
    (registry.agents_dir / "alice.lock").write_text('{"pid":true}')
    assert registry.is_lock_stale("alice")


def test_agent_hardening_state_never_invents_methods_on_unpatched_class():
    class Unpatched:
        pass

    status = hard.agent_hardening_state(Unpatched)
    assert status["installed"] is False
    assert status["register"] is False
    assert status["is_lock_stale"] is False
