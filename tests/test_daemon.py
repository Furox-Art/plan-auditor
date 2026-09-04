"""Tests for the supervisor daemon."""
import sys
import os
import json
import tempfile
import threading
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.daemon import SupervisorDaemon


def _send_recv(daemon, req):
    resp = daemon.dispatch(req)
    return resp


def test_daemon_starts_and_pings(tmp_path):
    d = SupervisorDaemon(str(tmp_path))
    assert d.start()
    assert _send_recv(d, {"op": "ping"})["pong"] is True
    d.stop()


def test_daemon_health_returns_pid(tmp_path):
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    h = _send_recv(d, {"op": "health"})
    assert h["ok"] and h["pid"] == os.getpid()
    d.stop()


def test_daemon_audit_rejects_pending(tmp_path):
    plan = {"task": "t", "created": "2026-09-03T00:00:00",
            "steps": [{"id": 1, "status": "pending",
                        "verify": [{"type": "run", "cmd": "echo"}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    resp = _send_recv(d, {"op": "audit"})
    assert resp["ok"] is False and resp["outcome"] == "FAIL"
    d.stop()


def test_daemon_audit_passes_when_verified(tmp_path):
    plan = {"task": "t", "created": "2026-09-03T00:00:00",
            "steps": [{"id": 1, "status": "verified",
                        "verify": [{"type": "run", "cmd": "echo"}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    resp = _send_recv(d, {"op": "audit"})
    assert resp["ok"] is True and resp["outcome"] == "PASS"
    d.stop()


def test_daemon_rejects_duplicate_start(tmp_path):
    d1 = SupervisorDaemon(str(tmp_path))
    assert d1.start()
    d2 = SupervisorDaemon(str(tmp_path))
    assert not d2.start()  # lock held by d1
    d1.stop()
    assert d2.start()  # now free
    d2.stop()


def test_daemon_stale_lock_replaced(tmp_path):
    lock = tmp_path / ".plan-auditor" / "supervisor.lock"
    tmp_path.joinpath(".plan-auditor").mkdir(parents=True, exist_ok=True)
    lock.write_text(json.dumps({"pid": 99999999, "started": "old"}), encoding="utf-8")
    d = SupervisorDaemon(str(tmp_path))
    assert d.start()  # stale PID -> lock replaced
    d.stop()


def test_daemon_plan_verify(tmp_path):
    plan = {"task": "t", "steps": [{"id": 1, "verify": [{"type": "file_exists", "path": "x"}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    resp = _send_recv(d, {"op": "plan_verify"})
    assert resp["verdict"] == "REJECT"
    d.stop()


def test_daemon_conflict_check(tmp_path):
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    resp = _send_recv(d, {"op": "conflict_check", "agent_id": "a2", "files": ["x.py"]})
    assert resp["ok"] and isinstance(resp["conflicts"], list)
    d.stop()


def test_daemon_shutdown(tmp_path):
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    d.stop()
    assert d._stop.is_set()


def test_daemon_unknown_op(tmp_path):
    d = SupervisorDaemon(str(tmp_path))
    d.start()
    resp = _send_recv(d, {"op": "nonsense"})
    assert resp["ok"] is False and "unknown op" in resp["error"]
    d.stop()
