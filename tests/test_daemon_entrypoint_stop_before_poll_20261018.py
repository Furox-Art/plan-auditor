"""A real stop marker prevents a second assessment and a fictitious poll."""

from __future__ import annotations

import runpy
import sys
from types import SimpleNamespace

import pytest

from supervisor import daemon


def test_stop_marker_arriving_during_initial_assessment_skips_poll(monkeypatch, tmp_path):
    observations = []

    class NotPolled:
        def __init__(self, root, poll_interval):
            assert root == str(tmp_path)
            assert poll_interval == 2.0

        def poll(self):
            pytest.fail("a stop marker must prevent daemon polling")

    monkeypatch.setattr(daemon, "Watchdog", NotPolled)
    monkeypatch.setattr(
        daemon,
        "load_config",
        lambda _: SimpleNamespace(heartbeat_sec=2.0),
    )

    def observe(root, profile, mode):
        observations.append((root, profile, mode))
        if len(observations) == 1:
            daemon.stop_path(root).touch()
        return {"outcome": "UNKNOWN", "reason": "no independent successful verification"}

    monkeypatch.setattr(daemon, "_safe_assessment", observe)
    out = daemon.run_daemon(str(tmp_path), "strict", "serial")
    assert out == 0
    assert len(observations) == 2
    assert daemon.read_state(tmp_path)["state"] == "stopped"
    assert daemon.read_state(tmp_path)["gate_outcome"] == "UNKNOWN"
    assert not daemon.stop_path(tmp_path).exists()


def test_real_module_main_guard_parses_help_without_starting_daemon(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["python -m supervisor.daemon", "--help"])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("supervisor.daemon", run_name="__main__")
    assert stopped.value.code == 0
    assert "--workspace" in capsys.readouterr().out
