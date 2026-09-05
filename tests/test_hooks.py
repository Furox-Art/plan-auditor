"""Tests for the platform-agnostic integrated gate hook."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.cli import main as cli_main


def _run_hook(cwd, fmt="text", warn_file=None):
    hook = Path(__file__).resolve().parent.parent / "hooks" / "gate_hook.py"
    cmd = [sys.executable, str(hook), cwd, "--format", fmt]
    if warn_file:
        cmd += ["--warn-file", warn_file]
    return subprocess.run(cmd, capture_output=True, text=True)


def _write_plan(root: Path, status="pending", *, named: str | None = None):
    pg = root / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    plan = {
        "task": "hook integration test",
        "created": "2026-09-03T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "Execute hook behavior", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [{
            "id": 1,
            "title": "behavior",
            "covers": ["REQ-001"],
            "status": status,
            "verify": [{"type": "run", "cmd": "python -c \"print('ok')\""}],
        }],
    }
    if named:
        plans = pg / "plans"
        plans.mkdir(exist_ok=True)
        path = plans / f"{named}.json"
    else:
        path = pg / "plan.json"
    path.write_text(json.dumps(plan), encoding="utf-8")


def _prepare_real_pass(root: Path):
    _write_plan(root)
    assert cli_main(["plan", "verify", str(root)]) == 0
    assert cli_main(["audit", str(root)]) == 0


def test_hook_pass_only_with_real_audit_and_seal():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _prepare_real_pass(root)
        result = _run_hook(d)
        assert result.returncode == 0
        assert "PASS" in result.stdout


def test_hook_blocks_verified_label_without_evidence():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="verified")
        result = _run_hook(d)
        assert result.returncode != 0
        assert "BLOCKED" in result.stdout
        assert "Seal" in result.stdout or "Fresh audit" in result.stdout


def test_hook_blocked_when_pending():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="pending")
        result = _run_hook(d)
        assert result.returncode == 1
        assert "BLOCKED" in result.stdout
        assert "default" in result.stdout


def test_hook_named_plan_is_active_even_without_default():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="pending", named="backend")
        result = _run_hook(d, fmt="json")
        data = json.loads(result.stdout)
        assert result.returncode != 0
        assert data["outcome"] == "FAIL"
        assert data["report"]["active_plan_count"] == 1
        assert "backend" in data["report"]["plans"]


def test_hook_no_plan_skips():
    with tempfile.TemporaryDirectory() as d:
        result = _run_hook(d)
        assert result.returncode == 0
        assert "No active plans" in result.stdout


def test_hook_json_format_reports_real_pass():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _prepare_real_pass(root)
        result = _run_hook(d, fmt="json")
        data = json.loads(result.stdout)
        assert data["outcome"] == "PASS"
        assert data["report"]["fresh_audit"]["valid"] is True


def test_hook_warn_file_written():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write_plan(root, status="pending")
        warn = os.path.join(d, ".plan-auditor", "warn.json")
        result = _run_hook(d, warn_file=warn)
        assert result.returncode in (1, 3)
        assert os.path.isfile(warn)
        data = json.loads(Path(warn).read_text(encoding="utf-8"))
        assert data["outcome"] in ("FAIL", "UNKNOWN")
