"""Windows PID adapter pure-protocol tests; never substitute for actual Windows CI."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

from supervisor import daemon


class ApiFunction:
    def __init__(self, callback):
        self.callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self.callback(*args)


@pytest.mark.parametrize(
    ("handle", "query_ok", "status_code", "expected"),
    [
        (0, True, 259, False),
        (42, False, 259, False),
        (42, True, 0, False),
        (42, True, 259, True),
    ],
)
def test_windows_process_query_has_separate_handle_query_and_exit_status_checks(
    monkeypatch, handle, query_ok, status_code, expected
):
    closed = []
    opened = []

    def open_process(permissions, inherit, pid):
        opened.append((permissions, inherit, pid))
        return handle

    def exit_code_query(h, pointer):
        if query_ok:
            pointer._obj.value = status_code
        return query_ok

    fake = SimpleNamespace(
        OpenProcess=ApiFunction(open_process),
        GetExitCodeProcess=ApiFunction(exit_code_query),
        CloseHandle=ApiFunction(lambda h: closed.append(h) or True),
    )
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: fake, raising=False)
    assert daemon._windows_pid_alive(12345) is expected
    assert opened == [(0x1000, False, 12345)]
    assert closed == ([42] if handle else [])


def test_windows_adapter_missing_native_api_is_unknown_not_live(monkeypatch):
    def missing(*a, **kw):
        raise OSError("Windows kernel API unavailable")

    monkeypatch.setattr(ctypes, "WinDLL", missing, raising=False)
    assert daemon._windows_pid_alive(12345) is False


def test_daemon_windows_pid_probe_routes_through_platform_dispatch(monkeypatch):
    monkeypatch.setattr(daemon.os, "name", "nt")
    calls = []
    monkeypatch.setattr(daemon, "_windows_pid_alive", lambda pid: calls.append(pid) or True)
    assert daemon.pid_alive(999) is True
    assert calls == [999]


def test_daemon_signal_handler_stops_one_local_poll_without_running_project_commands(
    monkeypatch, tmp_path
):
    signals = []
    monkeypatch.setattr(daemon.signal, "signal", lambda sig, callback: signals.append(callback))
    monkeypatch.setattr(daemon, "load_config", lambda _: SimpleNamespace(heartbeat_sec=0.5))
    monkeypatch.setattr(
        daemon,
        "_safe_assessment",
        lambda root, profile, mode: {
            "outcome": "UNKNOWN",
            "reason": "real gate not evaluated in fixture",
        },
    )
    observed = []

    class ObservedWatchdog:
        def __init__(self, *args, **kwargs):
            pass

        def poll(self):
            observed.append(True)
            # Exercise the exact production handler rather than a mock
            # status flag. The loop must then exit on the owned signal.
            signals[0](2, None)
            return SimpleNamespace(events=[])

    monkeypatch.setattr(daemon, "Watchdog", ObservedWatchdog)
    assert daemon.run_daemon(str(tmp_path), "strict", "serial") == 0
    assert observed == [True]
    status = daemon.read_state(tmp_path)
    assert status["state"] == "stopped"
    assert status["gate_outcome"] == "UNKNOWN"
