"""Exercise platform-specific process liveness using a fake Win32 boundary.

These are controlled Win32 API contract tests; no process is created or killed.
"""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from supervisor import agents_hardening as hard
from supervisor.agents import Agent, MultiAgentRegistry, RegistryIntegrityError


class FakeWinFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


def fake_kernel(*, handle=1, alive=259, exit_ok=True, fail_api=False):
    closed = []

    def open_process(*_args):
        return handle

    def get_exit_code(_handle, pointer):
        if fail_api:
            raise OSError("Win32 process access failed")
        pointer._obj.value = alive
        return exit_ok

    def close_process(h):
        closed.append(h)
        return True

    lib = SimpleNamespace(
        OpenProcess=FakeWinFunction(open_process),
        GetExitCodeProcess=FakeWinFunction(get_exit_code),
        CloseHandle=FakeWinFunction(close_process),
    )
    return lib, closed


@pytest.mark.parametrize(
    ("handle", "status_code", "exit_ok", "expected"),
    [
        (None, 259, True, False),
        (1, 259, True, True),
        (1, 0, True, False),
        (1, 259, False, False),
    ],
)
def test_win32_pid_liveness_contract_does_not_infer_alive_without_actual_exit_code(
    monkeypatch, handle, status_code, exit_ok, expected
):
    monkeypatch.setattr(hard, "os", SimpleNamespace(name="nt"))
    kernel, closed = fake_kernel(handle=handle, alive=status_code, exit_ok=exit_ok)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **kw: kernel, raising=False)
    assert hard._safe_pid_alive(81234) is expected
    assert closed == ([handle] if handle else [])


def test_win32_pid_process_open_failure_or_missing_os_api_is_unknown_dead(monkeypatch):
    monkeypatch.setattr(hard, "os", SimpleNamespace(name="nt"))
    kernel, closed = fake_kernel(fail_api=True)
    monkeypatch.setattr(ctypes, "WinDLL", lambda *a, **kw: kernel, raising=False)
    assert hard._safe_pid_alive(81234) is False
    assert closed == [1]


def test_win32_pid_missing_native_implementation_does_not_fabricate_liveness(monkeypatch):
    monkeypatch.setattr(hard, "os", SimpleNamespace(name="nt"))

    def missing(*_args, **_kwargs):
        raise AttributeError("WinDLL unavailable")

    monkeypatch.setattr(ctypes, "WinDLL", missing, raising=False)
    assert hard._safe_pid_alive(81234) is False


def test_filename_separator_defense_still_rejects_separator_if_primary_regex_is_faulted(
    monkeypatch,
):
    monkeypatch.setattr(hard, "_ID_RE", SimpleNamespace(fullmatch=lambda _: True))
    with pytest.raises(ValueError, match="cannot contain path separators"):
        hard.validate_agent_id("agent/other")
    with pytest.raises(ValueError, match="cannot contain path separators"):
        hard.validate_agent_id("agent\\\\other")


def test_default_hardening_report_attests_the_actual_exported_registry():
    state = hard.agent_hardening_state()
    assert state["installed"] is True
    assert all(state[name] for name in hard.HARDENED_METHODS)


def test_default_install_is_idempotent_and_reports_no_new_fake_method():
    initial = hard.agent_hardening_state(MultiAgentRegistry)
    repeated = hard.install_agent_hardening()
    assert repeated == initial
    assert repeated["installed"] is True


def test_agent_registration_with_recorded_workspace_root_and_ownership(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    agent = Agent("owner", "task", "plan")
    agent.owned_files = {"data/../observed.txt"}
    registry.register(agent)
    assert registry._agents["owner"].owned_files == {"observed.txt"}
    assert registry._agents["owner"].workspace_root == str(tmp_path)
    assert registry.verify_registry_chain()
    # Caller-owned state is not modified by in-transaction canonicalization.
    assert agent.owned_files == {"data/../observed.txt"}


def test_legacy_hash_migration_failure_does_not_erase_original_error(monkeypatch, tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.registry_tampered = True
    registry.registry_problem = "previous hash mismatch"
    monkeypatch.setattr(registry, "_refresh_from_disk", lambda: None)
    with pytest.raises(RegistryIntegrityError, match="previous hash mismatch"):
        hard._require_integrity_locked(registry)


def test_actual_authenticated_agent_registry_append_has_verifiable_hmac_envelope(
    monkeypatch, tmp_path
):
    import json

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    key_file = tmp_path / "external-hmac.key"
    key_file.write_bytes(b"agent-hardening-ci-isolation-key-" * 2)
    key_file.chmod(0o600)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    from supervisor.integrity import initialize_integrity

    status = initialize_integrity(workspace)
    assert status["authenticated"] is True
    registry = MultiAgentRegistry(str(workspace))
    registry.register(Agent("signed", "task", "plan"))
    rows = [json.loads(line) for line in registry.registry_path.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["rec"]["agent"]["agent_id"] == "signed"
    assert rows[0]["auth"]
    assert registry.verify_registry_chain()
    assert MultiAgentRegistry(str(workspace)).verify_registry_chain()


def test_post_append_independent_integrity_failure_refuses_claiming_success(monkeypatch, tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    real_refresh = registry._refresh_from_disk
    seen = []

    def injected_refresh():
        real_refresh()
        seen.append(1)
        if len(seen) == 3:
            registry.registry_tampered = True
            registry.registry_problem = "injected independent verification mismatch"

    monkeypatch.setattr(registry, "_refresh_from_disk", injected_refresh)
    with pytest.raises(RegistryIntegrityError, match="independent verification mismatch"):
        registry.register(Agent("one", "task", "plan"))
    assert len(seen) == 3
    # Claim of success is denied even if a disk append was already attempted.
    assert registry.registry_tampered


def test_unregistering_unknown_agent_never_emits_an_unsubstantiated_leave_event(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.unregister("never-present")
    assert registry.verify_registry_chain()
    assert not registry.registry_path.exists()


def test_heartbeat_without_an_action_keeps_the_actual_last_known_action(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("owner", "task", "plan"))
    registry.heartbeat("owner", action="real processing")
    registry.heartbeat("owner", action="")
    assert registry._agents["owner"].current_action == "real processing"
    assert registry.verify_registry_chain()


def test_live_agent_is_neither_aged_out_nor_released_by_staleness_cleanup(tmp_path):
    registry = MultiAgentRegistry(str(tmp_path))
    registry.register(Agent("active", "task", "plan"))
    registry.update_ownership("active", {"actual-data.txt"})
    registry.owner_timeout = 3600
    assert registry.release_stale_ownership() == []
    assert registry._agents["active"].owned_files == {"actual-data.txt"}
    assert registry._agents["active"].state == "active"
    assert registry.verify_registry_chain()
