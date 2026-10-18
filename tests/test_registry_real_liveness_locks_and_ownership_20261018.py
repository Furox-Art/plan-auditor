"""Direct registry state transitions with authentic filesystem history and bounded locks."""

from __future__ import annotations

import json
import os
import time

import pytest

from supervisor import agents as reg


def member(name):
    return reg.Agent(agent_id=name, task_id="lab", plan_id="strict")


def test_two_real_agents_are_active_and_have_distinct_authority(tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(reg.time, "time", lambda: clock[0])
    state = reg.MultiAgentRegistry(str(tmp_path), owner_timeout=10)
    state.register(member("alice"))
    state.register(member("bob"))
    assert {a.agent_id for a in state.active_agents()} == {"alice", "bob"}
    assert state.stale_agents() == []
    assert state.verify_registry_chain()


def test_real_expiry_releases_only_stale_ownership_and_persists_historical_evidence(
    tmp_path, monkeypatch
):
    clock = [100.0]
    monkeypatch.setattr(reg.time, "time", lambda: clock[0])
    state = reg.MultiAgentRegistry(str(tmp_path), owner_timeout=10)
    state.register(member("alice"))
    state.update_ownership("alice", {"paper.md"})
    clock[0] = 105.0
    state.register(member("bob"))
    state.update_ownership("bob", {"second.txt"})
    clock[0] = 112.0
    assert {a.agent_id for a in state.stale_agents()} == {"alice"}
    assert {a.agent_id for a in state.active_agents()} == {"bob"}
    assert state.release_stale_ownership() == ["alice"]
    assert state.release_stale_ownership() == []
    state2 = reg.MultiAgentRegistry(str(tmp_path), owner_timeout=10)
    assert state2.verify_registry_chain()
    assert state2._agents["alice"].state == "stale"
    assert state2._agents["alice"].owned_files == set()
    assert state2._agents["bob"].owned_files == {"second.txt"}


def test_live_owner_blocks_strict_conflicting_claim_and_warn_mode_retains_warnings(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    state.register(member("alice"))
    state.register(member("bob"))
    state.update_ownership("alice", {"datasets/raw.csv"})
    allowed, conflicts = state.claim_files("bob", {"datasets/raw.csv"}, mode="parallel-strict")
    assert not allowed
    assert [(c.file_path, c.owner_agent, c.accessor_agent) for c in conflicts] == [
        ("datasets/raw.csv", "alice", "bob")
    ]
    allowed, conflicts = state.claim_files("bob", {"datasets/raw.csv"}, mode="parallel-warn")
    assert allowed
    assert len(conflicts) == 1
    assert "datasets/raw.csv" in state._agents["bob"].owned_files


def test_register_heartbeat_and_release_have_real_consistent_reloaded_logs(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    state.register(member("worker"))
    state.heartbeat("worker", action="read raw signal")
    assert state._agents["worker"].current_action == "read raw signal"
    state.update_ownership("worker", {"unprocessed.bin"})
    state.unregister("worker")
    reread = reg.MultiAgentRegistry(str(tmp_path))
    assert reread.verify_registry_chain()
    assert "worker" not in reread._agents


def test_heartbeat_for_missing_worker_does_not_create_undocumented_agent(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    with pytest.raises(reg.RegistryIntegrityError, match="unknown agent: ghost"):
        state.heartbeat("ghost", action="report PASS")
    with pytest.raises(reg.RegistryIntegrityError, match="unknown agent: ghost"):
        state.update_ownership("ghost", {"secrets.json"})
    assert state._agents == {}
    assert not state.registry_path.exists()


def test_unregistered_claim_can_never_create_a_new_ownership_record(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    with pytest.raises(reg.RegistryIntegrityError, match="unknown agent: ghost"):
        state.claim_files("ghost", {"source.py"}, mode="parallel-warn")
    assert state._agents == {}


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ("invalid json", True),
        ("[]", True),
        ('{"pid":-1}', True),
    ],
)
def test_invalid_worker_lock_is_treated_as_stale_not_active(tmp_path, payload, expected):
    state = reg.MultiAgentRegistry(str(tmp_path))
    lock = state.agents_dir / "worker.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    lock.write_text(payload, encoding="utf-8")
    assert state.is_lock_stale("worker") is expected


def test_real_owned_process_lock_is_live_and_then_removable(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    p = state.write_lock("worker")
    assert p is not None and p.exists()
    assert state.is_lock_stale("worker") is False
    p.unlink()
    assert state.is_lock_stale("worker") is False


def test_existing_write_lock_is_not_silently_stolen_when_writer_is_active(monkeypatch, tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    state._ensure_dirs()
    state.lock_path.write_text(json.dumps({"pid": os.getpid(), "ts": time.time()}))
    times = iter([0.0, reg.REGISTRY_LOCK_TIMEOUT + 1.0])
    monkeypatch.setattr(reg.time, "monotonic", lambda: next(times))
    with pytest.raises(reg.RegistryIntegrityError, match="registry write lock timeout"):
        with state._write_lock():
            pytest.fail("never acquire another live owner's lock")
    assert state.lock_path.exists()


def test_proven_stale_registry_write_lock_is_reclaimed_without_overwriting_the_evidence(
    monkeypatch, tmp_path
):
    state = reg.MultiAgentRegistry(str(tmp_path))
    state._ensure_dirs()
    state.lock_path.write_text(json.dumps({"pid": 99999999, "token": "provably-dead-owner", "created": 1}))
    old = time.time() - (reg.REGISTRY_LOCK_STALE + 30)
    os.utime(state.lock_path, (old, old))
    with state._write_lock():
        assert state.lock_path.exists()
        assert json.loads(state.lock_path.read_text())["pid"] == os.getpid()
    assert not state.lock_path.exists()


def test_registry_cannot_claim_a_valid_head_from_invalid_json(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    state._ensure_dirs()
    state.head_path.write_text("not-json", encoding="utf-8")
    assert state._read_head() == {"invalid": True}
    state.head_path.write_text("[]", encoding="utf-8")
    assert state._read_head() == {"invalid": True}


def test_unsigned_registry_head_is_written_only_from_recorded_tail(tmp_path):
    state = reg.MultiAgentRegistry(str(tmp_path))
    state.register(member("alice"))
    saved = json.loads(state.head_path.read_text())
    assert saved["seq"] == 1
    assert saved["format_version"] == reg.REGISTRY_FORMAT_VERSION
    assert saved["hash"] == state._registry_tail
    assert state.verify_registry_chain() is True


def test_pid_liveness_probe_rejects_nonexistent_pid_and_reports_access_issues(monkeypatch):
    assert reg._pid_alive(0) is False
    monkeypatch.setattr(reg.os, "kill", lambda *_: (_ for _ in ()).throw(OSError("not permitted")))
    assert reg._pid_alive(778899) is False
    monkeypatch.setattr(reg.os, "kill", lambda *_: None)
    assert reg._pid_alive(12345) is True
