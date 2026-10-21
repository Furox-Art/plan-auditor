"""Portable process control and Windows argv faults without starting real processes."""

from __future__ import annotations

import io
import os
import subprocess

import pytest

from scripts import audit_check as ac


class OSFacade:
    def __init__(self, name):
        self.name = name

    def __getattr__(self, item):
        return getattr(os, item)


class FakeProcess:
    pid = 12345
    returncode = 0

    def __init__(self, *, output=b"", wait_errors=0, poll_result=0, closed_error=False):
        self.stdout = io.BytesIO(output)
        self.wait_errors = wait_errors
        self.poll_result = poll_result
        self.closed_error = closed_error
        self.killed = 0

    def poll(self):
        return self.poll_result

    def wait(self, timeout):
        if self.wait_errors:
            self.wait_errors -= 1
            raise subprocess.TimeoutExpired(cmd="fake", timeout=timeout)
        return self.returncode

    def kill(self):
        self.killed += 1


def test_windows_argv_parser_must_preserve_quoted_literal_backslash():
    assert ac._windows_argv(r"app \\work") == ["app", r"\\work"]


def test_windows_legacy_command_uses_windows_parser(monkeypatch):
    monkeypatch.setattr(ac, "os", OSFacade("nt"))
    assert ac._legacy_split(r"app \\work") == ["app", r"\\work"]


def test_windows_process_tree_fallback_if_taskkill_unavailable(monkeypatch):
    monkeypatch.setattr(ac, "os", OSFacade("nt"))
    monkeypatch.setattr(
        ac.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("taskkill unavailable")),
    )
    proc = FakeProcess(poll_result=None)
    ac._kill_process_tree(proc)
    assert proc.killed == 1


@pytest.mark.skipif(os.name == "nt", reason="exercises the POSIX process-group fallback")
def test_unix_process_tree_fallback_if_group_not_found(monkeypatch):
    class UnixFacade(OSFacade):
        def killpg(self, pid, sig):
            raise ProcessLookupError("already gone")

    monkeypatch.setattr(ac, "os", UnixFacade("posix"))
    proc = FakeProcess(poll_result=None)
    ac._kill_process_tree(proc)
    assert proc.killed == 1


@pytest.mark.skipif(os.name == "nt", reason="exercises POSIX group shutdown after kill failure")
def test_kill_failure_after_group_shutdown_is_conservatively_ignored(monkeypatch):
    class UnixFacade(OSFacade):
        def killpg(self, pid, sig):
            return None

    monkeypatch.setattr(ac, "os", UnixFacade("posix"))
    proc = FakeProcess(poll_result=None)

    def refuse():
        raise ProcessLookupError("already exited")

    proc.kill = refuse
    ac._kill_process_tree(proc)


def test_windows_process_spawn_uses_process_group_without_shell(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "os", OSFacade("nt"))
    monkeypatch.setattr(ac, "check_launch_options", lambda root: {})
    captured = []
    fake = FakeProcess(output=b"ok")
    monkeypatch.setattr(
        ac.subprocess, "Popen", lambda cmd, **kwargs: captured.append((cmd, kwargs)) or fake
    )
    ret, state, out, overflow = ac._bounded_command(["cmd", "arg"], str(tmp_path), 2, 1024)
    assert ret == 0
    assert state == "ok"
    assert out == "ok"
    assert overflow is False
    assert captured[0][1]["creationflags"] == getattr(ac.subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    assert captured[0][1]["shell"] is False


def test_pipe_read_errors_dont_claim_command_success_from_output(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "check_launch_options", lambda root: {})
    fake = FakeProcess()

    class BrokenPipe:
        def read(self, size):
            raise OSError("read error")

        def close(self):
            pass

    fake.stdout = BrokenPipe()
    monkeypatch.setattr(ac.subprocess, "Popen", lambda *args, **kwargs: fake)
    ret, state, out, overflow = ac._bounded_command(["fake"], str(tmp_path), 1, 1024)
    assert ret == 0
    assert state == "ok"
    assert out == ""
    assert overflow is False


def test_wait_timeout_at_reap_boundary_triggers_second_reap(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "check_launch_options", lambda root: {})
    fake = FakeProcess(wait_errors=2)
    monkeypatch.setattr(ac.subprocess, "Popen", lambda *args, **kwargs: fake)
    ret, state, out, overflow = ac._bounded_command(["fake"], str(tmp_path), 1, 1024)
    assert ret == 0
    assert state == "ok"


def test_unresponsive_output_drain_close_error_is_nonfatal(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "check_launch_options", lambda root: {})
    fake = FakeProcess()

    class BrokenOutput:
        def close(self):
            raise OSError("pipe lost")

    fake.stdout = BrokenOutput()
    monkeypatch.setattr(ac.subprocess, "Popen", lambda *args, **kwargs: fake)

    class FakeThread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            pass

        def join(self, timeout):
            pass

        def is_alive(self):
            return True

    monkeypatch.setattr(ac.threading, "Thread", FakeThread)
    ret, state, out, overflow = ac._bounded_command(["fake"], str(tmp_path), 1, 1024)
    assert ret == 0
    assert state == "ok"
    assert out == ""
