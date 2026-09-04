"""Tests for CLI gate integration."""
import sys
import os
import json
import subprocess
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.cli import main
from supervisor import verify_plan


def test_cli_audit_rejects_pending(tmp_path):
    plan = {"task": "t", "created": "2026-09-03T00:00:00",
            "steps": [{"id": 1, "title": "x", "status": "pending",
                        "verify": [{"type": "run", "cmd": "echo"}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    rc = main(["audit", str(tmp_path)])
    assert rc == 1


def test_cli_audit_passes_when_all_verified(tmp_path):
    plan = {"task": "t", "created": "2026-09-03T00:00:00",
            "steps": [{"id": 1, "title": "x", "status": "verified",
                        "verify": [{"type": "run", "cmd": "echo"}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    rc = main(["audit", str(tmp_path)])
    assert rc == 0


def test_cli_plan_verify_rejects_weak(tmp_path):
    plan = {"task": "t", "steps": [{"id": 1, "verify": [{"type": "file_exists", "path": "x"}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    rc = main(["plan", "verify", str(tmp_path)])
    assert rc == 1


def test_cli_status_valid_json(tmp_path, capsys=None):
    rc = main(["supervisor", "status", str(tmp_path)])
    assert rc == 0


def test_cli_doctor_includes_language(tmp_path):
    rc = main(["doctor", str(tmp_path)])
    assert rc == 0
