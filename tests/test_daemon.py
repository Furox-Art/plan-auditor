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


def _write_fast_config(workspace: Path) -> None:
    pg = runtime_dir(workspace)
    pg.mkdir(parents=True, exist_ok=True)
    (pg / "supervisor.json").write_text(
        json.dumps({"heartbeat_sec": 1}), encoding="utf-8"
    )


def _wait_for_state(
    workspace: Path,
    expected: str,
    timeout: float = 4.0,
    *,
    pid: int | None = None,
) -> dict:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        state = read_state(workspace)
        last = state
        if state and state.get("state") == expected:
            if pid is None or state.get("pid") == pid:
                return state
        time.sleep(0.05)
    raise AssertionError(
        f"daemon did not reach state {expected!r} with pid={pid!r}; last={last!r}"
    )


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
    _write_fast_config(tmp_path)
    thread = _start_thread(tmp_path)
    running = _wait_for_state(tmp_path, "running", pid=os.getpid())
    assert running["workspace"] == str(tmp_path.resolve())
    assert running["profile"] == "standard"
    assert running["mode"] == "serial"

    started = time.monotonic()
    _request_stop(tmp_path)
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert time.monotonic() - started < 2.0

    stopped = _wait_for_state(tmp_path, "stopped", pid=os.getpid())
    assert not stop_path(tmp_path).exists()
    assert stopped["state"] == "stopped"


def test_duplicate_running_daemon_is_rejected(tmp_path: Path) -> None:
    path = state_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({"state": "running", "pid": os.getpid()}),
        encoding="utf-8",
    )
    assert run_daemon(str(tmp_path), "standard", "serial") == 2


def test_stale_running_state_is_replaced(tmp_path: Path) -> None:
    _write_fast_config(tmp_path)
    path = state_path(tmp_path)
    path.write_text(
        json.dumps({"state": "running", "pid": 99999999}),
        encoding="utf-8",
    )

    thread = _start_thread(tmp_path)
    running = _wait_for_state(tmp_path, "running", pid=os.getpid())
    assert running["pid"] == os.getpid()

    _request_stop(tmp_path)
    thread.join(timeout=2.0)
    assert not thread.is_alive()
    assert _wait_for_state(tmp_path, "stopped", pid=os.getpid())["state"] == "stopped"


def test_daemon_records_workspace_events(tmp_path: Path) -> None:
    _write_fast_config(tmp_path)
    thread = _start_thread(tmp_path)
    _wait_for_state(tmp_path, "running", pid=os.getpid())

    observed = tmp_path / "observed.txt"
    observed.write_text("first", encoding="utf-8")

    events_path = runtime_dir(tmp_path) / "watchdog.jsonl"
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if events_path.exists():
            records = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
            ]
            if any(record.get("path") == "observed.txt" for record in records):
                break
        time.sleep(0.05)
    else:
        _request_stop(tmp_path)
        thread.join(timeout=2.0)
        raise AssertionError("watchdog did not record observed.txt")

    _request_stop(tmp_path)
    thread.join(timeout=2.0)
    assert not thread.is_alive()


def test_daemon_publishes_starting_state_before_initial_assessment(tmp_path: Path, monkeypatch) -> None:
    import supervisor.daemon as daemon_module

    _write_fast_config(tmp_path)
    release = threading.Event()

    def delayed_assessment(root: str, profile: str, mode: str) -> dict:
        release.wait(timeout=2.0)
        return {"outcome": "PASS", "workspace": root, "profile": profile, "mode": mode}

    monkeypatch.setattr(daemon_module, "_safe_assessment", delayed_assessment)
    thread = _start_thread(tmp_path)
    starting = _wait_for_state(tmp_path, "starting", timeout=1.0, pid=os.getpid())
    assert starting["gate_outcome"] == "UNKNOWN"

    release.set()
    _wait_for_state(tmp_path, "running", timeout=2.0, pid=os.getpid())
    _request_stop(tmp_path)
    thread.join(timeout=2.0)
    assert not thread.is_alive()


def test_atomic_write_json_retries_transient_permission_error(tmp_path: Path, monkeypatch) -> None:
    import supervisor.daemon as daemon_module

    target = tmp_path / "state.json"
    target.write_text('{"old": true}', encoding="utf-8")
    real_replace = daemon_module.os.replace
    calls = {"count": 0}

    def flaky_replace(src, dst):
        calls["count"] += 1
        if calls["count"] < 3:
            raise PermissionError("transient sharing violation")
        return real_replace(src, dst)

    monkeypatch.setattr(daemon_module.os, "replace", flaky_replace)
    daemon_module._atomic_write_json(target, {"new": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {"new": True}
    assert calls["count"] == 3
    assert list(tmp_path.glob("state.json.*.tmp")) == []
