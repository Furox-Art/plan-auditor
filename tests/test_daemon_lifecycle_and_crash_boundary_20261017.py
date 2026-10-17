"""Supervision tests with actual workspace state files and bounded event polling."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from supervisor import daemon


def test_missing_or_nonobject_runtime_state_never_becomes_running(tmp_path):
    assert daemon.read_state(tmp_path) is None
    p = daemon.state_path(tmp_path)
    p.parent.mkdir(exist_ok=True)
    for content in ("not JSON", "[]", '""'):
        p.write_text(content, encoding="utf-8")
        assert daemon.read_state(tmp_path) is None
    p.write_text('{"state":"running","pid":123}', encoding="utf-8")
    assert daemon.read_state(tmp_path)["pid"] == 123


def test_missing_or_nonobject_assessment_never_becomes_pass(tmp_path):
    assert daemon.read_assessment(tmp_path) is None
    p = daemon.assessment_path(tmp_path)
    p.parent.mkdir(exist_ok=True)
    p.write_text("false", encoding="utf-8")
    assert daemon.read_assessment(tmp_path) is None
    p.write_text('{"outcome":"UNKNOWN"}', encoding="utf-8")
    assert daemon.read_assessment(tmp_path)["outcome"] == "UNKNOWN"


@pytest.mark.parametrize("pid", [-1, 0, None, True, "123"])
def test_invalid_pid_values_rejected_before_kill_probe(pid):
    assert daemon.pid_alive(pid) is False


@pytest.mark.parametrize(
    ("error_type", "expected"),
    [
        (PermissionError, True),
        (ProcessLookupError, False),
    ],
)
def test_pid_liveness_error_meaning_is_not_reversed(monkeypatch, error_type, expected):
    def fail(*args):
        raise error_type("injected probe")

    monkeypatch.setattr(daemon.os, "kill", fail)
    assert daemon.pid_alive(123) is expected


def test_windows_process_probe_is_fail_closed_on_unavailable_backend():
    if daemon.os.name != "nt":
        assert daemon._windows_pid_alive(999999999) is False


def test_atomic_state_writer_publishes_complete_json_and_removes_tmp(tmp_path):
    target = tmp_path / "state.json"
    daemon._atomic_write_json(target, {"state": "running", "seq": 1})
    assert json.loads(target.read_text()) == {"state": "running", "seq": 1}
    assert list(tmp_path.glob("*.tmp")) == []


def test_atomic_state_writer_retries_transient_sharing_error_without_inplace_fallback(
    monkeypatch, tmp_path
):
    target = tmp_path / "state.json"
    real_replace = daemon.os.replace
    events = []

    def sharing_error_once(src, dst):
        events.append(str(dst))
        if len(events) == 1:
            raise PermissionError("sharing violation")
        return real_replace(src, dst)

    monkeypatch.setattr(daemon.os, "replace", sharing_error_once)
    monkeypatch.setattr(daemon.time, "sleep", lambda secs: None)
    daemon._atomic_write_json(target, {"state": "running"})
    assert len(events) == 2
    assert json.loads(target.read_text())["state"] == "running"


def test_atomic_state_writer_refuses_permanently_locked_destination(monkeypatch, tmp_path):
    target = tmp_path / "state.json"
    call_times = iter([0.0, 4.0])
    monkeypatch.setattr(daemon.time, "monotonic", lambda: next(call_times))

    def deny(src, dst):
        raise PermissionError("locked destination")

    monkeypatch.setattr(daemon.os, "replace", deny)
    with pytest.raises(PermissionError, match="locked destination"):
        daemon._atomic_write_json(target, {"state": "running"})
    assert not target.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_stop_marker_interrupts_without_waiting_on_foreign_processes(tmp_path):
    marker = daemon.stop_path(tmp_path)
    marker.parent.mkdir(exist_ok=True)
    marker.write_text("stop", encoding="utf-8")
    assert daemon._interruptible_wait(tmp_path, 100.0, lambda: False) is True


def test_interruptible_wait_respects_immediate_stop_and_zero_budget(tmp_path):
    assert daemon._interruptible_wait(tmp_path, 0.0, lambda: True) is True
    assert daemon._interruptible_wait(tmp_path, 0.0, lambda: False) is False


def test_failing_workspace_assessment_is_recorded_as_unknown(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("simulated validation failure")

    monkeypatch.setattr(daemon, "evaluate_workspace", fail)
    out = daemon._safe_assessment(str(tmp_path), "strict", "serial")
    assert out["outcome"] == "UNKNOWN"
    assert "simulated validation failure" in out["error"]


def test_daemon_refuses_second_instance_when_existing_pid_is_live(monkeypatch, tmp_path):
    p = daemon.state_path(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text('{"state":"running","pid":123}', encoding="utf-8")
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    assert daemon.run_daemon(str(tmp_path), "strict", "serial") == 2


def test_actual_daemon_writes_start_heartbeat_event_and_stop_state(monkeypatch, tmp_path):
    states = []
    real_writer = daemon._atomic_write_json

    def spy_write(path, payload):
        if path.name == daemon.STATE_FILENAME:
            states.append(payload["state"])
        real_writer(path, payload)

    monkeypatch.setattr(daemon, "_atomic_write_json", spy_write)
    monkeypatch.setattr(daemon.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(daemon, "load_config", lambda _root: SimpleNamespace(heartbeat_sec=0.6))
    monkeypatch.setattr(
        daemon,
        "_safe_assessment",
        lambda root, profile, mode: {
            "outcome": "UNKNOWN",
            "profile": profile,
            "mode": mode,
            "basis": "no independent gate run (explicit)",
        },
    )
    evt = SimpleNamespace(
        ts="2026-10-17T20:00:00Z", kind="modify", path="evidence.json", detail="changed"
    )

    class LocalWatchdog:
        def __init__(self, *a, **kw):
            self.poll_count = 0

        def poll(self):
            self.poll_count += 1
            return SimpleNamespace(events=[evt])

    monkeypatch.setattr(daemon, "Watchdog", LocalWatchdog)
    monkeypatch.setattr(daemon, "_interruptible_wait", lambda *_args: True)
    assert daemon.run_daemon(str(tmp_path), "strict", "serial") == 0
    assert states == ["starting", "running", "running", "stopped"]
    assert daemon.read_state(tmp_path)["state"] == "stopped"
    assert daemon.read_state(tmp_path)["events_seen"] == 1
    event_lines = (
        daemon.runtime_dir(tmp_path).joinpath(daemon.EVENTS_FILENAME).read_text().splitlines()
    )
    assert len(event_lines) == 1
    assert json.loads(event_lines[0])["path"] == "evidence.json"
    assert daemon.read_assessment(tmp_path)["outcome"] == "UNKNOWN"


def test_cli_forwards_requested_verified_workspace_profile_and_mode(monkeypatch, tmp_path):
    args = []
    monkeypatch.setattr(
        daemon, "run_daemon", lambda root, profile, mode: args.append((root, profile, mode)) or 7
    )
    assert (
        daemon.main(
            ["--workspace", str(tmp_path), "--profile", "strict", "--mode", "parallel-strict"]
        )
        == 7
    )
    assert args == [(str(tmp_path), "strict", "parallel-strict")]
