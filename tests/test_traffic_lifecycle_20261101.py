"""Daemon, supervisor lifecycle, CLI dispatch, and the third-gate end-to-end proof."""
from __future__ import annotations

import json
import os
import runpy
import signal
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

import pytest

import scripts.audit_check as core
import scripts.traffic as traffic_core
import supervisor.traffic as sup
from scripts.traffic import (
    CertificateAuthority,
    CertificateError,
    TrafficProxy,
    load_state,
    log_path,
    pki_dir,
    plan_dir,
    run_daemon,
    session_record,
    stop_path,
    trust_path,
    write_state,
    write_trust_marker,
)
from supervisor.cli import main
from supervisor.gate import CompletionGate
from supervisor.integrity import initialize_integrity
from supervisor.plans import seal_path
from supervisor.policies import PolicyEngine
from supervisor.sealing import save_seal, seal_plan
from supervisor.traffic import (
    _mark_stale,
    _state_running,
    _tail,
    _wait_stopped,
    build_traffic_report,
    evaluate_traffic,
    install_ca,
    remove_ca,
    start_traffic,
    stop_traffic,
    traffic_records,
    traffic_status,
)

# --------------------------------------------------------------------- helpers


@pytest.fixture(autouse=True)
def _reset_daemon_globals():
    traffic_core._STOP_EVENT = False
    traffic_core._set_workspace(Path("."), "default")
    yield
    traffic_core._STOP_EVENT = False
    traffic_core._set_workspace(Path("."), "default")


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


def _write_plan(workspace: Path, *, hosts: tuple[str, ...] = ("api.test",)) -> dict:
    plan = {"task": "traffic lifecycle test", "traffic": {"allowed_hosts": list(hosts)}}
    target = workspace / ".plan-auditor" / "plan.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan), encoding="utf-8")
    return plan


def _write_valid_plan(workspace: Path, *, traffic: dict | None = None) -> dict:
    plan = {
        "task": "traffic plan verify",
        "created": "2026-11-01T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "exercise traffic", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "behavior",
                "covers": ["REQ-001"],
                "status": "pending",
                "verify": [{"type": "run", "cmd": "python -c \"print('ok')\""}],
            }
        ],
    }
    if traffic is not None:
        plan["traffic"] = traffic
    target = workspace / ".plan-auditor" / "plan.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan), encoding="utf-8")
    from tests.request_fixture import activate_for_plan

    activate_for_plan(workspace, plan)
    return plan


def _seal_plan(workspace: Path, plan: dict) -> None:
    seal = seal_plan(plan, "default", "2026-11-01T00:00:00+00:00")
    save_seal(seal, str(seal_path(workspace)))


class _FakeCA:
    def __init__(self, root, *, fail_ensure: bool = False) -> None:
        self.root = Path(root) / "pki"
        self.cert_path = self.root / "ca.pem"
        self.key_path = self.root / "ca-key.pem"
        self.fail_ensure = fail_ensure
        self.removed = False
        self._fingerprint = "F" * 64

    def ensure(self) -> None:
        if self.fail_ensure:
            raise CertificateError("fake CA unavailable")
        self.cert_path.parent.mkdir(parents=True, exist_ok=True)
        self.cert_path.write_text("cert", encoding="utf-8")
        self.key_path.write_text("key", encoding="utf-8")

    def fingerprint(self) -> str:
        return self._fingerprint

    def remove(self) -> None:
        self.removed = True
        for path in (self.cert_path, self.key_path):
            try:
                path.unlink()
            except OSError:
                pass


class _FakeChild:
    def __init__(self, *, pid: int = 777, exit_code: int | None = None) -> None:
        self.pid = pid
        self.exit_code = exit_code
        self.terminated = False

    def poll(self) -> int | None:
        return self.exit_code

    def terminate(self) -> None:
        self.terminated = True


def _fake_ca(monkeypatch, ca: _FakeCA) -> None:
    monkeypatch.setattr(sup, "CertificateAuthority", lambda root: ca)


def _running_spawn(monkeypatch, root: Path, child: _FakeChild, *, port: int = 5555):
    calls: list[dict] = []

    def real_spawn(root_path, plan, *, port, session_id, started_at):
        calls.append(
            {
                "root": root_path,
                "plan": plan,
                "port": port,
                "session_id": session_id,
                "started_at": started_at,
            }
        )
        plan_dir(root_path, plan).mkdir(parents=True, exist_ok=True)
        parent = load_state(root_path, plan) or {}
        preserved = {
            key: parent[key]
            for key in ("allowed_hosts", "trust_installed", "trust_detail")
            if key in parent
        }
        write_state(
            root_path,
            plan,
            {
                "running": True,
                "pid": child.pid,
                "port": port or 5555,
                "session_id": session_id,
                **preserved,
            },
        )
        return child

    monkeypatch.setattr(sup, "_spawn_daemon", real_spawn)
    return calls


# ---------------------------------------------------------------------- daemon


class TestDaemon:
    def test_stop_file_short_circuits_the_loop_and_closes_the_session(
        self, tmp_path, monkeypatch
    ):
        root = _workspace(tmp_path)
        write_state(
            root,
            "default",
            {
                "allowed_hosts": ["api.test"],
                "trust_installed": True,
                "trust_detail": "fake trust",
            },
        )
        stop_path(root, "default").parent.mkdir(parents=True, exist_ok=True)
        stop_path(root, "default").write_text("stop\n", encoding="utf-8")
        monkeypatch.setattr(traffic_core.signal, "signal", lambda *args: None)

        assert (
            run_daemon(
                root,
                plan="default",
                port=0,
                session_id="session-1",
                started_at="2026-11-01T00:00:00+00:00",
            )
            == 0
        )

        state = load_state(root, "default")
        assert state is not None
        assert state["running"] is False
        assert state["starting"] is False
        assert state["requests"] == 0
        assert state["silent"] is True
        assert state["allowed_hosts"] == ["api.test"]
        assert state["trust_installed"] is True
        assert state["trust_detail"] == "fake trust"
        assert not stop_path(root, "default").exists()

        records = [
            json.loads(line)
            for line in (root / ".plan-auditor" / "evidence.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert [record["mode"] for record in records] == ["traffic_session"]
        assert records[0]["requests"] == 0
        assert records[0]["silent"] is True

    def test_daemon_tolerates_unavailable_signal_registration(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        stop_path(root, "default").parent.mkdir(parents=True, exist_ok=True)
        stop_path(root, "default").write_text("stop\n", encoding="utf-8")

        def refuse(*args):
            raise ValueError("signal only works in the main thread")

        monkeypatch.setattr(traffic_core.signal, "signal", refuse)
        assert (
            run_daemon(
                root,
                plan="default",
                port=0,
                session_id="session-signal",
                started_at="2026-11-01T00:00:00+00:00",
            )
            == 0
        )
        assert load_state(root, "default")["running"] is False

    def test_daemon_captures_one_request_and_matches_the_session_count(
        self, tmp_path, monkeypatch
    ):
        root = _workspace(tmp_path)
        monkeypatch.setattr(traffic_core.signal, "signal", lambda *args: None)
        result: dict[str, int] = {}

        def run() -> None:
            result["rc"] = run_daemon(
                root,
                plan="default",
                port=0,
                session_id="session-live",
                started_at="2026-11-01T00:00:00+00:00",
            )

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        state = _wait_for_running(root, "default")
        port = int(state["port"])
        ca = CertificateAuthority(pki_dir(root))
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()
        response = _send_through_proxy(
            port,
            ca.cert_path,
            authority=f"127.0.0.1:{dead_port}",
            host="127.0.0.1",
            path="/v1/messages",
            body=b'{"messages": []}',
        )
        assert b"502" in response
        stop_path(root, "default").write_text("stop\n", encoding="utf-8")
        thread.join(timeout=20)
        assert not thread.is_alive()
        assert result["rc"] == 0

        state = load_state(root, "default")
        assert state is not None
        assert state["running"] is False
        assert state["requests"] == 1
        assert state["classes"]["prompt"] == 1

        records = [
            json.loads(line)
            for line in (root / ".plan-auditor" / "evidence.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        assert [record["mode"] for record in records] == [
            "traffic_request",
            "traffic_session",
        ]
        assert records[1]["requests"] == 1
        assert records[1]["session_id"] == "session-live"

    def test_startup_failure_writes_an_error_state(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)

        class BrokenCA(_FakeCA):
            def __init__(self, path) -> None:
                super().__init__(path, fail_ensure=True)

        monkeypatch.setattr(traffic_core, "CertificateAuthority", BrokenCA)

        assert (
            run_daemon(
                root,
                plan="default",
                port=0,
                session_id="session-fail",
                started_at="2026-11-01T00:00:00+00:00",
            )
            == 3
        )
        state = load_state(root, "default")
        assert state is not None
        assert state["running"] is False
        assert state["starting"] is False
        assert state["error"] == "fake CA unavailable"

    def test_closing_record_failure_is_reported_without_changing_exit(
        self, tmp_path, monkeypatch
    ):
        root = _workspace(tmp_path)
        stop_path(root, "default").parent.mkdir(parents=True, exist_ok=True)
        stop_path(root, "default").write_text("stop\n", encoding="utf-8")
        monkeypatch.setattr(traffic_core.signal, "signal", lambda *args: None)

        def boom(workspace, record):
            raise OSError("append failed")

        monkeypatch.setattr(core, "append_evidence", boom)

        assert (
            run_daemon(
                root,
                plan="default",
                port=0,
                session_id="session-boom",
                started_at="2026-11-01T00:00:00+00:00",
            )
            == 0
        )
        state = load_state(root, "default")
        assert state is not None
        assert "could not persist the closing session record" in state["error"]
        assert "append failed" in state["error"]

    def test_signal_handler_flips_the_stop_event(self, tmp_path):
        traffic_core._STOP_EVENT = False
        traffic_core._set_workspace(tmp_path, "default")
        assert traffic_core._stop_requested() is False
        traffic_core._handle_signal(signal.SIGTERM, None)
        assert traffic_core._stop_requested() is True

    def test_stop_requested_sees_the_stop_file(self, tmp_path):
        root = _workspace(tmp_path)
        stop_path(root, "default").parent.mkdir(parents=True, exist_ok=True)
        stop_path(root, "default").write_text("stop\n", encoding="utf-8")
        traffic_core._set_workspace(root, "default")
        assert traffic_core._stop_requested() is True

    def test_daemon_main_dispatches_parsed_arguments(self, monkeypatch):
        captured: dict[str, object] = {}

        def fake_run_daemon(workspace, *, plan, port, session_id, started_at):
            captured.update(
                {
                    "workspace": workspace,
                    "plan": plan,
                    "port": port,
                    "session_id": session_id,
                    "started_at": started_at,
                }
            )
            return 9

        monkeypatch.setattr(traffic_core, "run_daemon", fake_run_daemon)
        assert (
            traffic_core.main(
                [
                    "--workspace",
                    "somewhere",
                    "--plan",
                    "named",
                    "--port",
                    "1234",
                    "--session-id",
                    "sid",
                    "--started-at",
                    "then",
                ]
            )
            == 9
        )
        assert captured == {
            "workspace": "somewhere",
            "plan": "named",
            "port": 1234,
            "session_id": "sid",
            "started_at": "then",
        }

    def test_module_entry_point_requires_arguments(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["scripts.traffic"])
        with pytest.raises(SystemExit) as raised:
            runpy.run_module("scripts.traffic", run_name="__main__")
        assert raised.value.code == 2
        assert "required" in capsys.readouterr().err


def _wait_for_running(root: Path, plan: str, timeout: float = 20.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = load_state(root, plan)
        if state and state.get("running") is True and state.get("port"):
            return state
        time.sleep(0.05)
    raise AssertionError(f"traffic daemon never reported running under {root}")


# --------------------------------------------------------------- spawn/state


class TestSpawnAndState:
    def test_spawn_daemon_uses_the_temp_cwd_and_argv(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        calls: dict[str, object] = {}

        class FakePopen:
            pid = 4242

            def __init__(self, argv, **kwargs) -> None:
                calls["argv"] = argv
                calls["kwargs"] = kwargs

        monkeypatch.setattr(sup.subprocess, "Popen", FakePopen)
        monkeypatch.setattr(sup, "os", types.SimpleNamespace(name="posix"))
        child = sup._spawn_daemon(
            root, "default", port=4321, session_id="sid", started_at="now"
        )
        assert child.pid == 4242
        argv = calls["argv"]
        assert argv[:3] == [sys.executable, "-m", "scripts.traffic"]
        assert argv[3:] == [
            "--workspace",
            str(root),
            "--plan",
            "default",
            "--port",
            "4321",
            "--session-id",
            "sid",
            "--started-at",
            "now",
        ]
        kwargs = calls["kwargs"]
        assert kwargs["cwd"] == tempfile.gettempdir()
        assert kwargs["stdin"] is sup.subprocess.DEVNULL
        assert kwargs["close_fds"] is True
        assert kwargs["start_new_session"] is True
        assert "creationflags" not in kwargs
        assert log_path(root, "default").is_file()

    def test_spawn_daemon_uses_windows_creation_flags(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        calls: dict[str, object] = {}

        class FakePopen:
            pid = 7

            def __init__(self, argv, **kwargs) -> None:
                calls["kwargs"] = kwargs

        monkeypatch.setattr(sup.subprocess, "Popen", FakePopen)
        monkeypatch.setattr(sup, "os", types.SimpleNamespace(name="nt"))
        sup._spawn_daemon(root, "default", port=0, session_id="s", started_at="t")
        kwargs = calls["kwargs"]
        assert "creationflags" in kwargs
        assert "start_new_session" not in kwargs

    def test_spawn_daemon_propagates_popen_failure(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)

        class BoomPopen:
            def __init__(self, *args, **kwargs) -> None:
                raise OSError("cannot spawn")

        monkeypatch.setattr(sup.subprocess, "Popen", BoomPopen)
        with pytest.raises(OSError, match="cannot spawn"):
            sup._spawn_daemon(root, "default", port=0, session_id="s", started_at="t")

    def test_state_running_matrix(self, monkeypatch):
        assert _state_running(None) is False
        assert _state_running({"running": "yes"}) is False
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: True)
        assert _state_running({"running": True, "pid": 5}) is True

    def test_tail_reads_the_end_and_ignores_missing_files(self, tmp_path):
        missing = tmp_path / "missing.log"
        assert _tail(missing) == ""
        target = tmp_path / "daemon.log"
        target.write_text("x" * 30 + "tail", encoding="utf-8")
        assert _tail(target, limit=4) == "tail"

    def test_mark_stale_writes_a_stopped_state(self, tmp_path):
        root = _workspace(tmp_path)
        stale = _mark_stale(root, "default", {"running": True, "pid": 1})
        assert stale["stale"] is True
        assert stale["running"] is False
        assert load_state(root, "default")["stale"] is True

    def test_wait_stopped_returns_matching_state(self, tmp_path):
        root = _workspace(tmp_path)
        write_state(root, "default", {"running": False, "pid": 11})
        state = _wait_stopped(root, "default", 11, 0.5)
        assert state is not None and state["running"] is False

    def test_wait_stopped_returns_unrelated_stopped_state_after_exit(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        write_state(root, "default", {"running": False, "pid": 99})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: False)
        state = _wait_stopped(root, "default", 12, 0.5)
        assert state is not None and state["pid"] == 99

    def test_wait_stopped_returns_none_when_the_pid_vanishes(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        write_state(root, "default", {"running": True, "pid": 12})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: False)
        assert _wait_stopped(root, "default", 12, 0.5) is None

    def test_wait_stopped_times_out(self, tmp_path):
        root = _workspace(tmp_path)
        assert _wait_stopped(root, "default", 12, 0.0) is None

    def test_wait_stopped_keeps_polling_while_the_pid_is_alive(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        write_state(root, "default", {"running": True, "pid": 12})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: True)
        assert _wait_stopped(root, "default", 12, 0.01) is None


# -------------------------------------------------------------------- start


class TestStartTraffic:
    def test_requires_a_traffic_contract(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        target = root / ".plan-auditor" / "plan.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"task": "no traffic"}), encoding="utf-8")
        monkeypatch.setattr(sup, "CertificateAuthority", lambda root: _FakeCA(root))
        with pytest.raises(ValueError, match="does not declare a traffic contract"):
            start_traffic(root, None, {"task": "no traffic"})

    def test_rejects_an_out_of_range_port(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        monkeypatch.setattr(sup, "CertificateAuthority", lambda root: _FakeCA(root))
        with pytest.raises(ValueError, match="port out of range"):
            start_traffic(root, None, plan, port=70000)

    def test_is_idempotent_while_the_daemon_is_alive(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        write_state(root, "default", {"running": True, "pid": os.getpid()})

        def explode(root_path):
            raise AssertionError("a live daemon must not rebuild the CA")

        monkeypatch.setattr(sup, "CertificateAuthority", explode)
        result = start_traffic(root, None, plan)
        assert result["already_running"] is True
        assert result["pid"] == os.getpid()

    def test_ca_failure_is_wrapped(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root, fail_ensure=True))
        with pytest.raises(RuntimeError, match="certificate authority setup failed"):
            start_traffic(root, None, plan)

    def test_install_ca_failure_aborts_startup(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root))
        monkeypatch.setattr(sup, "install_trust", lambda cert, ca: (False, "no store"))
        with pytest.raises(RuntimeError, match="CA trust installation failed"):
            start_traffic(root, None, plan, install_ca=True)

    def test_install_ca_success_is_recorded(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        ca = _FakeCA(root)
        _fake_ca(monkeypatch, ca)
        monkeypatch.setattr(sup, "install_trust", lambda cert, ca: (True, "trusted"))
        child = _FakeChild()
        _running_spawn(monkeypatch, root, child)

        state = start_traffic(root, None, plan, install_ca=True)

        assert state["running"] is True
        assert state["trust_installed"] is True
        assert state["trust_detail"] == "trusted"
        marker = json.loads(trust_path(root).read_text(encoding="utf-8"))
        assert marker["fingerprint"] == ca.fingerprint()

    def test_trust_marker_is_honoured_without_reinstalling(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        ca = _FakeCA(root)
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint(), "detail": "old"})
        _running_spawn(monkeypatch, root, _FakeChild())

        def explode():
            raise AssertionError("install_trust must not run")

        monkeypatch.setattr(sup, "install_trust", explode)
        assert start_traffic(root, None, plan)["trust_installed"] is True

    def test_stale_trust_marker_is_not_trusted(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        ca = _FakeCA(root)
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": "OTHER"})
        _running_spawn(monkeypatch, root, _FakeChild())
        assert start_traffic(root, None, plan)["trust_installed"] is False

    def test_spawn_failure_is_wrapped(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root))

        def explode(*args, **kwargs):
            raise OSError("no process")

        monkeypatch.setattr(sup, "_spawn_daemon", explode)
        with pytest.raises(RuntimeError, match="could not start the traffic daemon"):
            start_traffic(root, None, plan)

    def test_readiness_succeeds_when_the_child_writes_state(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root))
        calls = _running_spawn(monkeypatch, root, _FakeChild(pid=321), port=6000)

        state = start_traffic(root, None, plan, port=6000)

        assert state["running"] is True
        assert state["pid"] == 321
        assert calls and calls[0]["plan"] == "default"
        assert calls[0]["port"] == 6000

    def test_readiness_timeout_terminates_the_child_and_reports_the_log(
        self, tmp_path, monkeypatch
    ):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root))
        child = _FakeChild(pid=654)

        def spawn(root_path, plan_name, *, port, session_id, started_at):
            plan_dir(root_path, plan_name).mkdir(parents=True, exist_ok=True)
            log_path(root_path, plan_name).write_text("daemon exploded", encoding="utf-8")
            return child

        monkeypatch.setattr(sup, "_spawn_daemon", spawn)
        with pytest.raises(RuntimeError, match="daemon exploded"):
            start_traffic(root, None, plan, timeout=0.05)
        assert child.terminated is True

    def test_child_exit_before_readiness_skips_terminate(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root))
        child = _FakeChild(pid=655, exit_code=1)

        def spawn(root_path, plan_name, *, port, session_id, started_at):
            plan_dir(root_path, plan_name).mkdir(parents=True, exist_ok=True)
            return child

        monkeypatch.setattr(sup, "_spawn_daemon", spawn)
        with pytest.raises(RuntimeError, match="traffic daemon did not become ready"):
            start_traffic(root, None, plan, timeout=0.5)
        assert child.terminated is False

    def test_a_leftover_stop_directory_does_not_block_startup(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        _fake_ca(monkeypatch, _FakeCA(root))
        _running_spawn(monkeypatch, root, _FakeChild())
        stop_path(root, "default").mkdir(parents=True)
        state = start_traffic(root, None, plan)
        assert state["running"] is True


# --------------------------------------------------------------------- stop


class TestStopTraffic:
    def test_missing_plan_and_state_are_errors(self, tmp_path):
        root = _workspace(tmp_path)
        with pytest.raises(FileNotFoundError):
            stop_traffic(root, None)
        _write_plan(root)
        with pytest.raises(FileNotFoundError, match="no traffic state"):
            stop_traffic(root, None)

    def test_dead_daemon_is_marked_stale(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": True, "pid": 123, "session_id": "s"})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: False)
        state = stop_traffic(root, None)
        assert state["stale"] is True
        assert state["running"] is False
        assert load_state(root, "default")["stale"] is True

    def test_stop_file_write_failure_is_wrapped(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": True, "pid": os.getpid()})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: True)
        stop_path(root, "default").mkdir(parents=True)
        with pytest.raises(RuntimeError, match="could not write the stop file"):
            stop_traffic(root, None)

    def test_wait_success_returns_the_stopped_state(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": True, "pid": os.getpid()})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(
            sup, "_wait_stopped", lambda root_path, plan, pid, timeout: {"running": False}
        )
        state = stop_traffic(root, None, timeout=0.1)
        assert state["running"] is False
        assert stop_path(root, "default").read_text(encoding="utf-8") == "stop\n"

    def test_sigterm_fallback_stops_the_daemon(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": True, "pid": 4242})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: True)
        results = iter([None, {"running": False}])
        monkeypatch.setattr(
            sup, "_wait_stopped", lambda root_path, plan, pid, timeout: next(results)
        )
        kills: list[tuple[int, int]] = []
        monkeypatch.setattr(sup.os, "kill", lambda pid, sig: kills.append((pid, sig)))
        state = stop_traffic(root, None, timeout=0.1)
        assert state["running"] is False
        assert kills == [(4242, signal.SIGTERM)]

    def test_terminal_timeout_refuses_completion(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": True, "pid": 4242})
        monkeypatch.setattr(sup, "pid_is_alive", lambda pid: True)
        monkeypatch.setattr(sup, "_wait_stopped", lambda *args: None)

        def no_kill(pid, sig):
            raise OSError("no such process")

        monkeypatch.setattr(sup.os, "kill", no_kill)
        with pytest.raises(RuntimeError, match="did not close its session"):
            stop_traffic(root, None, timeout=0.1)

    def test_remove_ca_without_a_marker_only_touches_the_pki_tree(
        self, tmp_path, monkeypatch
    ):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": 1})
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        state = stop_traffic(root, None, remove_ca=True)
        assert state["ca_removed"] is True
        assert state["trust_removed"] is False
        assert ca.removed is True
        assert not ca.cert_path.exists()
        assert state["trust_detail"] == (
            "no traffic trust-install marker; nothing removed from a store"
        )

    def test_remove_ca_refuses_when_the_certificate_is_missing(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": 1})
        _fake_ca(monkeypatch, _FakeCA(root))
        write_trust_marker(root, {"fingerprint": "F" * 64})
        with pytest.raises(RuntimeError, match="CA certificate is missing"):
            stop_traffic(root, None, remove_ca=True)

    def test_remove_ca_uninstall_failure_keeps_the_files(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": 1})
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        monkeypatch.setattr(sup, "uninstall_trust", lambda cert, ca: (False, "denied"))
        with pytest.raises(RuntimeError, match="CA trust removal failed"):
            stop_traffic(root, None, remove_ca=True)
        assert ca.cert_path.exists()

    def test_remove_ca_success_updates_state(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": 1})
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        monkeypatch.setattr(sup, "uninstall_trust", lambda cert, ca: (True, "gone"))
        state = stop_traffic(root, None, remove_ca=True)
        assert state["trust_removed"] is True
        assert state["trust_detail"] == "gone"
        assert not trust_path(root).exists()
        assert ca.removed is True

    def test_remove_ca_ignores_marker_unlink_failure(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": 1})
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        blocked = tmp_path / "trust-is-a-directory"
        blocked.mkdir()
        monkeypatch.setattr(sup, "trust_path", lambda root_path: blocked)
        monkeypatch.setattr(sup, "uninstall_trust", lambda cert, ca: (True, "gone"))
        state = stop_traffic(root, None, remove_ca=True)
        assert state["trust_removed"] is True

    def test_remove_ca_detects_incomplete_removal(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": 1})
        ca = _FakeCA(root)
        ca.ensure()
        ca.remove = lambda: None
        _fake_ca(monkeypatch, ca)
        with pytest.raises(RuntimeError, match="could not be removed completely"):
            stop_traffic(root, None, remove_ca=True)


# --------------------------------------------------------------- status/CA


class TestStatusAndCertificates:
    def test_status_requires_state(self, tmp_path):
        root = _workspace(tmp_path)
        with pytest.raises(FileNotFoundError):
            traffic_status(root, None)
        _write_plan(root)
        with pytest.raises(FileNotFoundError, match="no traffic state"):
            traffic_status(root, None)

    def test_status_reports_a_stopped_daemon(self, tmp_path):
        root = _workspace(tmp_path)
        _write_plan(root)
        write_state(root, "default", {"running": False, "pid": None, "port": None})
        result = traffic_status(root, None)
        assert result["alive"] is False
        assert result["port_open"] is False
        assert result["trust_installed"] is False

    def test_status_checks_the_port_and_the_trust_marker(self, tmp_path):
        root = _workspace(tmp_path)
        _write_plan(root)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            write_state(
                root,
                "default",
                {
                    "running": True,
                    "pid": os.getpid(),
                    "port": port,
                    "ca_fingerprint": "F" * 64,
                },
            )
            write_trust_marker(root, {"fingerprint": "F" * 64})
            result = traffic_status(root, None)
            assert result["alive"] is True
            assert result["port_open"] is True
            assert result["trust_installed"] is True
            write_trust_marker(root, {"fingerprint": "OTHER"})
            assert traffic_status(root, None)["trust_installed"] is False
        finally:
            listener.close()

    def test_status_survives_a_closed_port(self, tmp_path):
        root = _workspace(tmp_path)
        _write_plan(root)
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        write_state(
            root, "default", {"running": True, "pid": os.getpid(), "port": port}
        )
        result = traffic_status(root, None)
        assert result["alive"] is True
        assert result["port_open"] is False

    def test_install_ca_wraps_ca_failures(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _fake_ca(monkeypatch, _FakeCA(root, fail_ensure=True))
        with pytest.raises(RuntimeError, match="certificate authority setup failed"):
            install_ca(root)

    def test_install_ca_wraps_trust_failures(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _fake_ca(monkeypatch, _FakeCA(root))
        monkeypatch.setattr(sup, "install_trust", lambda cert, ca: (False, "no store"))
        with pytest.raises(RuntimeError, match="CA trust installation failed"):
            install_ca(root)

    def test_install_ca_records_the_marker(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        ca = _FakeCA(root)
        _fake_ca(monkeypatch, ca)
        monkeypatch.setattr(sup, "install_trust", lambda cert, ca: (True, "trusted"))
        result = install_ca(root)
        assert result["installed"] is True
        assert result["detail"] == "trusted"
        assert result["fingerprint"] == ca.fingerprint()
        marker = json.loads(trust_path(root).read_text(encoding="utf-8"))
        assert marker["fingerprint"] == ca.fingerprint()

    def test_remove_ca_without_marker_or_ca_files(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        ca = _FakeCA(root)
        _fake_ca(monkeypatch, ca)
        result = remove_ca(root)
        assert result["removed"] is True
        assert result["trust_removed"] is False
        assert ca.removed is False

    def test_remove_ca_refuses_when_the_certificate_is_missing(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        _fake_ca(monkeypatch, _FakeCA(root))
        write_trust_marker(root, {"fingerprint": "F" * 64})
        with pytest.raises(RuntimeError, match="CA certificate is missing"):
            remove_ca(root)

    def test_remove_ca_uninstall_failure_is_fatal(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        monkeypatch.setattr(sup, "uninstall_trust", lambda cert, ca: (False, "denied"))
        with pytest.raises(RuntimeError, match="CA trust removal failed"):
            remove_ca(root)

    def test_remove_ca_removes_the_marker_and_material(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        monkeypatch.setattr(sup, "uninstall_trust", lambda cert, ca: (True, "gone"))
        result = remove_ca(root)
        assert result == {"removed": True, "trust_removed": True, "detail": "gone"}
        assert ca.removed is True
        assert not trust_path(root).exists()

    def test_remove_ca_ignores_marker_unlink_failure(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        ca = _FakeCA(root)
        ca.ensure()
        _fake_ca(monkeypatch, ca)
        write_trust_marker(root, {"fingerprint": ca.fingerprint()})
        blocked = tmp_path / "blocked-marker"
        blocked.mkdir()
        monkeypatch.setattr(sup, "trust_path", lambda root_path: blocked)
        monkeypatch.setattr(sup, "uninstall_trust", lambda cert, ca: (True, "gone"))
        result = remove_ca(root)
        assert result["trust_removed"] is True
        assert ca.removed is True

    def test_remove_ca_detects_incomplete_removal(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        ca = _FakeCA(root)
        ca.ensure()
        ca.remove = lambda: None
        _fake_ca(monkeypatch, ca)
        with pytest.raises(RuntimeError, match="could not be removed completely"):
            remove_ca(root)


# ---------------------------------------------------------------------- CLI


def _last_json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


class TestTrafficCli:
    def test_default_action_is_status(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        seen: list[tuple] = []
        monkeypatch.setattr(
            sup,
            "traffic_status",
            lambda root_path, plan: seen.append((root_path, plan)) or {"running": False},
        )
        assert main(["traffic", str(root)]) == 0
        assert seen == [(root.resolve(), None)]
        assert _last_json(capsys) == {"running": False}

    def test_start_dispatches_the_loaded_plan(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        plan = _write_plan(root)
        calls: dict[str, object] = {}

        def fake_start(root_path, key, loaded, *, port, timeout):
            calls.update(
                {"root": root_path, "key": key, "plan": loaded, "port": port, "timeout": timeout}
            )
            return {"running": True, "port": 1234}

        monkeypatch.setattr(sup, "selected_plan", lambda root_path, name: ("default", plan))
        monkeypatch.setattr(sup, "start_traffic", fake_start)
        assert main(["traffic", str(root), "--start", "--port", "1234"]) == 0
        assert calls["plan"] is plan
        assert calls["port"] == 1234
        assert calls["timeout"] == 30.0
        assert _last_json(capsys) == {"running": True, "port": 1234}

    def test_stop_and_status_dispatch(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        monkeypatch.setattr(
            sup, "stop_traffic", lambda root_path, plan, timeout: {"running": False}
        )
        assert main(["traffic", str(root), "--stop"]) == 0
        assert _last_json(capsys) == {"running": False}
        monkeypatch.setattr(
            sup, "traffic_status", lambda root_path, plan: {"alive": True}
        )
        assert main(["traffic", str(root), "--status"]) == 0
        assert _last_json(capsys) == {"alive": True}

    def test_report_and_verify_use_the_report_outcome(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        report = {"plan": "default", "outcome": "OK", "ok": True, "requests": 2}
        monkeypatch.setattr(sup, "build_traffic_report", lambda root_path, plan: report)
        assert main(["traffic", str(root), "--report"]) == 0
        assert _last_json(capsys)["requests"] == 2
        assert main(["traffic", str(root), "--verify"]) == 0
        verified = _last_json(capsys)
        assert verified["verified"] is True
        assert verified["outcome"] == "OK"

    def test_verify_reports_a_violation_as_failure(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        monkeypatch.setattr(
            sup,
            "build_traffic_report",
            lambda root_path, plan: {"plan": "default", "outcome": "VIOLATION", "ok": False},
        )
        assert main(["traffic", str(root), "--verify"]) == 1
        assert _last_json(capsys)["verified"] is False

    def test_tampered_report_exits_with_refusal(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        monkeypatch.setattr(
            sup,
            "build_traffic_report",
            lambda root_path, plan: {"plan": "default", "outcome": "TAMPERED", "ok": False},
        )
        assert main(["traffic", str(root), "--report"]) == 2
        assert _last_json(capsys)["outcome"] == "TAMPERED"

    def test_install_and_remove_ca_dispatch(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        monkeypatch.setattr(sup, "install_ca", lambda root_path: {"installed": True})
        monkeypatch.setattr(sup, "remove_ca", lambda root_path: {"removed": True})
        assert main(["traffic", str(root), "--install-ca"]) == 0
        assert _last_json(capsys) == {"installed": True}
        assert main(["traffic", str(root), "--remove-ca"]) == 0
        assert _last_json(capsys) == {"removed": True}

    def test_missing_state_is_a_verification_failure(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)

        def missing(root_path, plan):
            raise FileNotFoundError("no traffic state here")

        monkeypatch.setattr(sup, "traffic_status", missing)
        assert main(["traffic", str(root)]) == 1
        captured = capsys.readouterr()
        assert "ERROR: no traffic state here" in captured.err
        assert captured.out == ""

    def test_operational_errors_are_refused(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)

        def broken(root_path, plan):
            raise ValueError("bad state")

        monkeypatch.setattr(sup, "traffic_status", broken)
        assert main(["traffic", str(root)]) == 2
        assert _last_json(capsys) == {"outcome": "FAIL", "error": "bad state"}


class TestPlanVerifyTraffic:
    def test_sealing_starts_the_watch(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        _write_valid_plan(root, traffic={"allowed_hosts": ["api.test"]})
        calls: list[tuple] = []
        monkeypatch.setattr(
            sup,
            "start_traffic",
            lambda root_path, key, plan: calls.append((root_path, key))
            or {
                "status": "running",
                "port": 7777,
                "session_id": "sid",
                "proxy_url": "http://127.0.0.1:7777",
                "trust_installed": False,
            },
        )
        assert main(["plan", "verify", str(root)]) == 0
        payload = _last_json(capsys)
        watch = payload["plans"]["default"]["traffic_watch"]
        assert watch["status"] == "running"
        assert watch["port"] == 7777
        assert calls and calls[0][1] == "default"

    def test_invalid_contract_is_reported(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        _write_valid_plan(root, traffic={"allowed_hosts": ["api.test"]})

        def broken(plan):
            raise ValueError("invalid traffic contract")

        monkeypatch.setattr(traffic_core, "traffic_contract", broken)
        assert main(["plan", "verify", str(root)]) == 2
        watch = _last_json(capsys)["plans"]["default"]["traffic_watch"]
        assert watch["status"] == "invalid"
        assert watch["error"] == "invalid traffic contract"

    def test_start_failure_is_reported(self, tmp_path, monkeypatch, capsys):
        root = _workspace(tmp_path)
        _write_valid_plan(root, traffic={"allowed_hosts": ["api.test"]})

        def broken(root_path, key, plan):
            raise RuntimeError("daemon unavailable")

        monkeypatch.setattr(sup, "start_traffic", broken)
        assert main(["plan", "verify", str(root)]) == 2
        watch = _last_json(capsys)["plans"]["default"]["traffic_watch"]
        assert watch["status"] == "error"
        assert watch["error"] == "daemon unavailable"


# ------------------------------------------------------------- end-to-end gate

class _UpstreamServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, ca: CertificateAuthority) -> None:
        self.ca = ca
        default = ca.issue("default.test")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(default.cert_path), str(default.key_path))
        self.context.set_servername_callback(self._select_context)
        super().__init__(("127.0.0.1", 0), _UpstreamHandler)

    def _select_context(self, ssl_socket, server_name, _context) -> None:
        if not server_name:
            return
        issued = self.ca.issue(server_name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(issued.cert_path), str(issued.key_path))
        ssl_socket.context = context

    @property
    def port(self) -> int:
        return self.server_address[1]


class _UpstreamHandler(socketserver.BaseRequestHandler):
    server: _UpstreamServer

    def handle(self) -> None:
        try:
            tls = self.server.context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        with tls:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0"))
            while len(body) < length:
                chunk = tls.recv(length - len(body))
                if not chunk:
                    break
                body += chunk
            payload = b'{"ok": true}'
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + payload
            )


@pytest.fixture(scope="module")
def e2e_upstream(tmp_path_factory):
    ca = CertificateAuthority(tmp_path_factory.mktemp("e2e-upstream-ca"))
    ca.ensure()
    server = _UpstreamServer(ca)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def e2e_watch_ca(tmp_path_factory):
    ca = CertificateAuthority(tmp_path_factory.mktemp("e2e-watch-ca"))
    ca.ensure()
    return ca


def _send_through_proxy(
    port: int,
    ca_cert: Path,
    *,
    authority: str,
    host: str,
    path: str,
    body: bytes,
) -> bytes:
    raw = socket.create_connection(("127.0.0.1", port), timeout=15)
    raw.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = raw.recv(4096)
        if not chunk:
            break
        head += chunk
    assert b" 200 " in head, head
    context = ssl.create_default_context(cafile=str(ca_cert))
    tls = context.wrap_socket(raw, server_hostname=host)
    try:
        request = (
            f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin-1") + body
        tls.sendall(request)
        response = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            response += chunk
        return response
    finally:
        tls.close()


def _run_e2e_session(
    tmp_path: Path,
    monkeypatch,
    watch_ca: CertificateAuthority,
    upstream: _UpstreamServer,
    *,
    path: str,
    body: bytes,
) -> Path:
    root = _workspace(tmp_path)
    plan = _write_valid_plan(root, traffic={"allowed_hosts": ["api.test"]})
    key_file = tmp_path / "outside-hmac.key"
    key_file.write_bytes(b"plan-auditor-traffic-e2e-key-" * 2)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    _seal_plan(root, plan)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    initialize_integrity(root)

    proxy = TrafficProxy(
        watch_ca,
        append_record=lambda record: core.append_evidence(str(root), record),
        plan="default",
        session_id="session-e2e",
        upstream_map={"api.test": ("127.0.0.1", upstream.port)},
        upstream_ca=upstream.ca.cert_path,
    )
    proxy.start()
    try:
        response = _send_through_proxy(
            proxy.port,
            watch_ca.cert_path,
            authority="api.test:443",
            host="api.test",
            path=path,
            body=body,
        )
        assert b"200 OK" in response
    finally:
        proxy.stop()
    records = [capture.record for capture in proxy.captures]
    core.append_evidence(
        str(root),
        session_record(
            plan="default",
            session_id="session-e2e",
            started_at="2026-11-01T00:00:00+00:00",
            stopped_at="2026-11-01T00:00:01+00:00",
            captures=records,
        ),
    )
    return root


def _gate_outcome(root: Path) -> tuple[dict, CompletionGate]:
    report = build_traffic_report(root, "default")
    check = evaluate_traffic(root, {"traffic": {"allowed_hosts": ["api.test"]}}, "default")
    gate = CompletionGate(PolicyEngine()).evaluate(
        deterministic_passed=True,
        pending_steps=[],
        workspace_context={},
        traffic_check=check,
    )
    return report, gate


class TestThirdGateEndToEnd:
    def test_clean_task_passes_with_authenticated_chain(
        self, tmp_path, monkeypatch, e2e_watch_ca, e2e_upstream, capsys
    ):
        root = _run_e2e_session(
            tmp_path,
            monkeypatch,
            e2e_watch_ca,
            e2e_upstream,
            path="/v1/messages",
            body=b'{"messages": [{"role": "user", "content": "hello"}]}',
        )
        report, gate = _gate_outcome(root)
        assert report["outcome"] == "OK"
        assert report["ok"] is True
        assert report["requests"] == 1
        assert report["classes"]["prompt"] == 1
        assert report["chain"]["authenticated"] is True
        assert report["chain"]["archive_anchored"] is True
        assert gate.outcome == "PASS"
        assert gate.traffic_check is not None and gate.traffic_check.ok is True
        assert len(traffic_records(root, "default")) == 2

        assert main(["traffic", str(root), "--verify"]) == 0
        verified = _last_json(capsys)
        assert verified["verified"] is True
        assert verified["requests"] == 1
        assert main(["traffic", str(root), "--report"]) == 0
        assert _last_json(capsys)["outcome"] == "OK"

    def test_transcript_upload_task_cannot_pass_the_gate(
        self, tmp_path, monkeypatch, e2e_watch_ca, e2e_upstream, capsys
    ):
        root = _run_e2e_session(
            tmp_path,
            monkeypatch,
            e2e_watch_ca,
            e2e_upstream,
            path="/upload",
            body=b'{"kind": "transcript", "data": "full history"}',
        )
        report, gate = _gate_outcome(root)
        assert report["outcome"] == "VIOLATION"
        assert report["ok"] is False
        kinds = {item["kind"] for item in report["violations"]}
        assert "transcript-upload" in kinds
        assert gate.outcome == "FAIL"
        assert gate.traffic_check is not None and gate.traffic_check.ok is False
        assert any("outbound traffic gate" in note for note in gate.notes)

        assert main(["traffic", str(root), "--verify"]) == 1
        verified = _last_json(capsys)
        assert verified["verified"] is False
        assert verified["outcome"] == "VIOLATION"
        assert main(["traffic", str(root), "--report"]) == 1
        assert _last_json(capsys)["ok"] is False

    def test_silence_alone_is_not_a_success(self, tmp_path, monkeypatch):
        root = _workspace(tmp_path)
        plan = _write_valid_plan(root, traffic={"allowed_hosts": ["api.test"]})
        key_file = tmp_path / "outside-hmac.key"
        key_file.write_bytes(b"plan-auditor-traffic-e2e-key-" * 2)
        monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
        monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
        _seal_plan(root, plan)
        monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
        initialize_integrity(root)
        core.append_evidence(
            str(root),
            session_record(
                plan="default",
                session_id="silent-session",
                started_at="2026-11-01T00:00:00+00:00",
                stopped_at="2026-11-01T00:00:01+00:00",
                captures=[],
            ),
        )
        report, gate = _gate_outcome(root)
        assert report["outcome"] == "SILENT"
        assert report["ok"] is False
        assert "silence is not proof of clean traffic" in report["reason"]
        assert gate.outcome == "FAIL"
