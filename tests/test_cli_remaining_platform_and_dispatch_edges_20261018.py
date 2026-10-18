"""Covered platform dispatch and error boundaries with no external process effects."""

from __future__ import annotations

import argparse
import json
import os
import runpy
import sys
from types import SimpleNamespace

import pytest

import supervisor.cli as cli
import supervisor.daemon as daemon


class OSFacade:
    def __init__(self, name):
        self.name = name

    def __getattr__(self, field):
        return getattr(os, field)


def test_missing_stale_daemon_markers_are_harmless(monkeypatch, tmp_path):
    monkeypatch.setattr(daemon, "read_state", lambda root: None)
    monkeypatch.setattr(
        cli.subprocess, "Popen", lambda *args, **kwargs: SimpleNamespace(poll=lambda: None)
    )
    assert cli._spawn_daemon(tmp_path, "strict", "serial").poll() is None


def test_windows_daemon_spawn_uses_process_group_flags_without_shell(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "os", OSFacade("nt"))
    monkeypatch.setattr(daemon, "read_state", lambda root: None)
    captured = []
    monkeypatch.setattr(
        cli.subprocess, "Popen", lambda args, **kwargs: captured.append(kwargs) or object()
    )
    cli._spawn_daemon(tmp_path, "light", "serial")
    assert captured[0]["creationflags"] & getattr(
        cli.subprocess, "CREATE_NEW_PROCESS_GROUP", 0
    ) == getattr(cli.subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    assert captured[0]["close_fds"] is True
    assert "shell" not in captured[0]


def test_stop_waits_for_cooperative_exit_without_signal(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda root: {"state": "running", "pid": 77})
    alive = iter([True, True, False])
    monkeypatch.setattr(daemon, "pid_alive", lambda pid: next(alive))
    monkeypatch.setattr(cli.time, "sleep", lambda wait: None)
    calls = []
    monkeypatch.setattr(cli.os, "kill", lambda *args: calls.append(args))
    args = argparse.Namespace(dir=str(tmp_path))
    assert cli.cmd_supervisor_stop(args) == 0
    assert calls == []
    assert json.loads(capsys.readouterr().out)["state"] == "stopped"


def test_request_gate_reports_corrupted_plan_without_claiming_alignment(monkeypatch, tmp_path):
    import supervisor.plans as plans
    import supervisor.request_contract as request

    status = SimpleNamespace(valid=True, request={}, reason="")
    monkeypatch.setattr(request, "verify_request_contract", lambda root: status)
    ref = SimpleNamespace(key="named")
    monkeypatch.setattr(plans, "all_plan_refs", lambda root: [ref])
    monkeypatch.setattr(
        plans, "load_plan_ref", lambda ref: (_ for _ in ()).throw(ValueError("malformed document"))
    )
    monkeypatch.setattr(
        request, "analyze_request_alignment", lambda plans, contract: SimpleNamespace(errors=[])
    )
    _status, _align, errors = cli._request_gate(tmp_path)
    assert errors == ["named: malformed document"]


def test_agent_action_outside_parser_is_never_silent_pass(tmp_path):
    args = argparse.Namespace(dir=str(tmp_path), action="alien")
    assert cli.cmd_agents(args) == 1


def test_dispatch_fallback_rejects_unknown_command(monkeypatch):
    parser = SimpleNamespace(
        parse_known_args=lambda args: (SimpleNamespace(cmd="not-supported"), [])
    )
    monkeypatch.setattr(cli, "_build_parser", lambda: parser)
    assert cli.main([]) == 1


def test_entrypoint_exit_status_reflects_return_code(monkeypatch):
    monkeypatch.setattr(cli, "main", lambda: 3)
    with pytest.raises(SystemExit) as result:
        cli.entrypoint()
    assert result.value.code == 3


def test_python_module_guard_invokes_cli_help(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["plan-auditor", "--help"])
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("supervisor.cli", run_name="__main__")
    assert raised.value.code == 0
    assert "supervisor" in capsys.readouterr().out
