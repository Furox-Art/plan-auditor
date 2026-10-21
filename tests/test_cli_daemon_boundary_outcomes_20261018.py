"""Controlled supervisor process-boundary tests; never launch or kill a real process."""

from __future__ import annotations

import argparse
import json
import os

import pytest

import supervisor.daemon as daemon
from supervisor import cli


class FakeProcess:
    def __init__(self, returncode=None):
        self.returncode = returncode

    def poll(self):
        return self.returncode


def _args(root):
    return argparse.Namespace(dir=str(root), profile="strict", mode="serial")


def test_spawn_checks_duplicate_live_daemon(monkeypatch, tmp_path):
    monkeypatch.setattr(daemon, "read_state", lambda _: {"state": "running", "pid": 123})
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: pid == 123)
    with pytest.raises(RuntimeError, match="already running with pid 123"):
        cli._spawn_daemon(tmp_path, "strict", "serial")
    assert not (tmp_path / ".plan-auditor" / "supervisor.log").exists()


@pytest.mark.skipif(os.name == "nt", reason="start_new_session is a POSIX spawn parameter")
def test_spawn_removes_stale_markers_and_never_invokes_shell(monkeypatch, tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    state = daemon.state_path(tmp_path)
    stop = daemon.stop_path(tmp_path)
    state.write_text("stale", encoding="utf-8")
    stop.write_text("stale", encoding="utf-8")
    monkeypatch.setattr(daemon, "read_state", lambda _: None)
    recorded = {}

    def popen(args, **kwargs):
        recorded.update(args=args, kwargs=kwargs)
        return FakeProcess()

    monkeypatch.setattr(cli.subprocess, "Popen", popen)
    result = cli._spawn_daemon(tmp_path, "strict", "parallel-strict")
    assert isinstance(result, FakeProcess)
    assert state.exists() is False
    assert stop.exists() is False
    assert recorded["args"] == [
        cli.sys.executable,
        "-m",
        "supervisor.daemon",
        "--workspace",
        str(tmp_path),
        "--profile",
        "strict",
        "--mode",
        "parallel-strict",
    ]
    assert recorded["kwargs"]["cwd"] == str(tmp_path)
    assert "shell" not in recorded["kwargs"]
    assert recorded["kwargs"]["stdin"] == cli.subprocess.DEVNULL
    assert recorded["kwargs"]["close_fds"] is True
    assert recorded["kwargs"].get("start_new_session") is True
    assert (pg / "supervisor.log").is_file()


def test_supervisor_start_rejects_live_duplicate(monkeypatch, tmp_path, capsys):
    def duplicate(*args):
        raise RuntimeError("already running")

    monkeypatch.setattr(cli, "_spawn_daemon", duplicate)
    rc = cli.cmd_supervisor_start(_args(tmp_path))
    assert rc == 1
    assert "already running" in capsys.readouterr().err
    assert (tmp_path / ".plan-auditor").is_dir()


def test_supervisor_start_acknowledges_running_state(monkeypatch, tmp_path, capsys):
    p = FakeProcess()
    monkeypatch.setattr(cli, "_spawn_daemon", lambda *args: p)
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "running", "pid": 777})
    rc = cli.cmd_supervisor_start(_args(tmp_path))
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["pid"] == 777


def test_supervisor_start_rejects_immediate_child_exit(monkeypatch, tmp_path, capsys):
    p = FakeProcess(1)
    monkeypatch.setattr(cli, "_spawn_daemon", lambda *args: p)
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "starting", "pid": 777})
    rc = cli.cmd_supervisor_start(_args(tmp_path))
    assert rc == 1
    assert "failed to start" in capsys.readouterr().err


def test_supervisor_start_timeout_is_refusal(monkeypatch, tmp_path, capsys):
    p = FakeProcess()
    monkeypatch.setattr(cli, "_spawn_daemon", lambda *args: p)
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "starting", "pid": 777})
    tick = iter([10, 10, 100])
    monkeypatch.setattr(cli.time, "time", lambda: next(tick))
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)
    rc = cli.cmd_supervisor_start(_args(tmp_path))
    assert rc == 1
    assert "failed to start" in capsys.readouterr().err


@pytest.mark.parametrize(
    "status,alive,expected", [("running", True, 0), ("running", False, 1), ("stopped", True, 1)]
)
def test_supervisor_status_distinguishes_stale_process(
    monkeypatch, tmp_path, capsys, status, alive, expected
):
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": status, "pid": 77})
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: alive)
    monkeypatch.setattr(daemon, "read_assessment", lambda root: {"outcome": "UNKNOWN"})
    rc = cli.cmd_supervisor_status(_args(tmp_path))
    assert rc == expected
    payload = json.loads(capsys.readouterr().out)
    assert payload["running"] == (status == "running" and alive)
    assert payload["state"] == ("stale" if status == "running" and not alive else status)
    assert payload["assessment"]["outcome"] == "UNKNOWN"


def test_stop_writes_marker_and_waits_for_cooperative_exit(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "running", "pid": 90})
    alive = iter([True, False])
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: next(alive))
    rc = cli.cmd_supervisor_stop(_args(tmp_path))
    assert rc == 0
    assert daemon.stop_path(tmp_path).read_text() == "stop\n"
    assert json.loads(capsys.readouterr().out)["pid"] == 90


def test_stop_fallback_signal_without_affecting_real_process(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "running", "pid": 90})
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    clock = iter([10.0, 20.0])
    monkeypatch.setattr(cli.time, "time", lambda: next(clock))
    calls = []
    monkeypatch.setattr(cli.os, "kill", lambda pid, signal: calls.append((pid, signal)))
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)
    rc = cli.cmd_supervisor_stop(_args(tmp_path))
    assert rc == 1
    assert calls == [(90, cli.signal.SIGTERM)]
    assert "did not stop" in capsys.readouterr().err


def test_stop_reports_success_after_signal_if_child_exits(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "running", "pid": 90})
    alive = iter([True, False])
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: next(alive))
    tick = iter([10.0, 20.0])
    monkeypatch.setattr(cli.time, "time", lambda: next(tick))
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: None)
    rc = cli.cmd_supervisor_stop(_args(tmp_path))
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["state"] == "stopped"


def test_stop_signal_failure_does_not_claim_exit(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "running", "pid": 90})
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: True)
    clock = iter([10.0, 20.0])
    monkeypatch.setattr(cli.time, "time", lambda: next(clock))
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)

    def cannot_signal(pid, sig):
        raise ProcessLookupError("simulated permission/failure")

    monkeypatch.setattr(cli.os, "kill", cannot_signal)
    rc = cli.cmd_supervisor_stop(_args(tmp_path))
    assert rc == 1
    assert "did not stop" in capsys.readouterr().err
