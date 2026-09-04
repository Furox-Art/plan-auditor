"""Tests for the current process-based supervisor daemon runtime."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from supervisor.daemon import (
    pid_alive,
    read_state,
    run_daemon,
    runtime_dir,
    state_path,
    stop_path,
)


def _wait_for_state(workspace: Path, expected: str, timeout: float = 4.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = read_state(workspace)
        if state and state.get("state") == expected:
            return state
        time.sleep(0.05)
    raise AssertionError(f"daemon did not reach state {expected!r}")


def _start_thread(workspace: Path) -> threading.Thread:
    thread = threading.Thread(
        target=run_daemon,
        args=(str(workspace), "standard", "serial"),
        daemon=True,
    )
    thread.start()
    return thread


def _request_stop(workspace: Path) -> None:
    marker = stop_path(workspace)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("stop\n", encoding="utf-8")


def test_runtime_paths_are_workspace_local(tmp_path: Path) -> None:
    assert runtime_dir(tmp_path) == tmp_path.resolve() / ".plan-auditor"
    assert state_path(tmp_path).parent == runtime_dir(tmp_path)
    assert stop_path(tmp_path).parent == runtime_dir(tmp_path)


def test_pid_alive_handles_current_and_invalid_pids() -> None:
    assert pid_alive(os.getpid()) is True
    assert pid_alive(None) is False
    assert pid_alive(0) is False
    assert pid_alive(-1) is False


def test_read_state_missing_or_invalid_is_none(tmp_path: Path) -> None:
    assert read_state(tmp_path) is None
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("not-json", encoding="utf-8")
    assert read_state(tmp_path) is None


def test_daemon_writes_running_state_and_stops_cleanly(tmp_path: Path) -> None:
    thread = _start_thread(tmp_path)
    running = _wait_for_state(tmp_path, "running")
    assert running["pid"] == os.getpid()
    assert running["workspace"] == str(tmp_path.resolve())
    assert running["profile"] == "standard"
    assert running["mode"] == "serial"

    _request_stop(tmp_path)
    thread.join(timeout=4.0)
    assert not thread.is_alive()

    stopped = _wait_for_state(tmp_path, "stopped")
    assert stopped["pid"] == os.getpid()
    assert not stop_path(tmp_path).exists()


def test_duplicate_running_daemon_is_rejected(tmp_path: Path) -> None:
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"state": "running", "pid": os.getpid()}),
        encoding="utf-8",
    )
    assert run_daemon(str(tmp_path), "standard", "serial") == 2


def test_stale_running_state_is_replaced(tmp_path: Path) -> None:
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"state": "running", "pid": 99999999}),
        encoding="utf-8",
    )

    thread = _start_thread(tmp_path)
    running = _wait_for_state(tmp_path, "running")
    assert running["pid"] == os.getpid()

    _request_stop(tmp_path)
    thread.join(timeout=4.0)
    assert not thread.is_alive()
    assert _wait_for_state(tmp_path, "stopped")["state"] == "stopped"


def test_daemon_records_workspace_events(tmp_path: Path) -> None:
    thread = _start_thread(tmp_path)
    _wait_for_state(tmp_path, "running")

    observed = tmp_path / "observed.txt"
    observed.write_text("first", encoding="utf-8")

    events_path = runtime_dir(tmp_path) / "watchdog.jsonl"
    deadline = time.time() + 4.0
    while time.time() < deadline and not events_path.exists():
        time.sleep(0.05)

    _request_stop(tmp_path)
    thread.join(timeout=4.0)
    assert not thread.is_alive()
    assert events_path.exists()
    records = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
    assert any(record.get("path") == "observed.txt" for record in records)
