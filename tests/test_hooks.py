"""Tests for the platform-agnostic gate hook."""
import sys
import os
import json
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pathlib import Path
import subprocess


def _run_hook(cwd, fmt="text", warn_file=None):
    hook = Path(__file__).resolve().parent.parent / "hooks" / "gate_hook.py"
    cmd = [sys.executable, str(hook), cwd, "--format", fmt]
    if warn_file:
        cmd += ["--warn-file", warn_file]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r


def test_hook_pass_when_verified():
    with tempfile.TemporaryDirectory() as d:
        pg = Path(d) / ".plan-auditor"
        pg.mkdir()
        plan = {"task": "t", "created": "2026-09-03T00:00:00",
                "steps": [{"id": 1, "status": "verified",
                            "verify": [{"type": "run", "cmd": "echo"}]}]}
        (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        r = _run_hook(d)
        assert r.returncode == 0
        assert "PASS" in r.stdout


def test_hook_blocked_when_pending():
    with tempfile.TemporaryDirectory() as d:
        pg = Path(d) / ".plan-auditor"
        pg.mkdir()
        plan = {"task": "t", "created": "2026-09-03T00:00:00",
                "steps": [{"id": 1, "status": "pending",
                            "verify": [{"type": "run", "cmd": "echo"}]}]}
        (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        r = _run_hook(d)
        assert r.returncode == 1
        assert "BLOCKED" in r.stdout
        assert "1" in r.stdout  # pending step id


def test_hook_no_plan_skips():
    with tempfile.TemporaryDirectory() as d:
        r = _run_hook(d)
        assert "No active plan.json" in r.stdout


def test_hook_json_format():
    with tempfile.TemporaryDirectory() as d:
        pg = Path(d) / ".plan-auditor"
        pg.mkdir()
        (pg / "plan.json").write_text(json.dumps({"task": "t", "created": "x",
            "steps": [{"id": 1, "status": "verified", "verify": [{"type": "run", "cmd": "echo"}]}]}),
            encoding="utf-8")
        r = _run_hook(d, fmt="json")
        data = json.loads(r.stdout)
        assert data["outcome"] == "PASS"


def test_hook_warn_file_written():
    with tempfile.TemporaryDirectory() as d:
        pg = Path(d) / ".plan-auditor"
        pg.mkdir()
        plan = {"task": "t", "created": "x",
                "steps": [{"id": 1, "status": "pending",
                            "verify": [{"type": "run", "cmd": "echo"}]}]}
        (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
        warn = os.path.join(d, ".plan-auditor", "warn.json")
        r = _run_hook(d, warn_file=warn)
        assert r.returncode == 1
        assert os.path.isfile(warn)
        data = json.loads(Path(warn).read_text())
        assert data["outcome"] in ("FAIL", "UNKNOWN")
