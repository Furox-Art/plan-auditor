"""Tests for CLI gate integration and packaging-facing behavior."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.cli import main
from tests.request_fixture import activate_for_plan


def _write_plan(tmp_path: Path, *, command: str = "python -c \"print('ok')\"") -> None:
    plan = {
        "task": "test task",
        "created": "2026-09-03T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "Execute the test behavior", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "behavior",
                "covers": ["REQ-001"],
                "status": "pending",
                "verify": [{"type": "run", "cmd": command}],
            }
        ],
    }
    pg = tmp_path / ".plan-auditor"
    pg.mkdir(exist_ok=True)
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    activate_for_plan(tmp_path, plan)


def test_cli_audit_requires_seal(tmp_path: Path) -> None:
    _write_plan(tmp_path)
    assert main(["audit", str(tmp_path)]) == 2


def test_cli_plan_verify_seals_full_contract(tmp_path: Path) -> None:
    _write_plan(tmp_path)
    assert main(["plan", "verify", str(tmp_path)]) == 0
    seal = json.loads((tmp_path / ".plan-auditor" / "seal.json").read_text(encoding="utf-8"))
    assert seal["format_version"] == 4
    assert seal["requirements"][0]["id"] == "REQ-001"
    assert seal["steps"][0]["covers"] == ["REQ-001"]
    assert seal["steps"][0]["verify"][0]["type"] == "run"
    assert seal["environment"]["profile"] == "standard"


def test_cli_audit_runs_fresh_core_and_passes(tmp_path: Path) -> None:
    _write_plan(tmp_path)
    assert main(["plan", "verify", str(tmp_path)]) == 0
    assert main(["audit", str(tmp_path)]) == 0
    plan = json.loads((tmp_path / ".plan-auditor" / "plan.json").read_text(encoding="utf-8"))
    assert plan["steps"][0]["status"] == "verified"


def test_cli_audit_rejects_post_seal_check_edit(tmp_path: Path) -> None:
    _write_plan(tmp_path)
    assert main(["plan", "verify", str(tmp_path)]) == 0
    path = tmp_path / ".plan-auditor" / "plan.json"
    plan = json.loads(path.read_text(encoding="utf-8"))
    plan["steps"][0]["verify"] = [{"type": "run", "cmd": "python -c \"print('weaker edit')\""}]
    path.write_text(json.dumps(plan), encoding="utf-8")
    assert main(["audit", str(tmp_path)]) == 2


def test_cli_plan_verify_rejects_missing_requirement_coverage(tmp_path: Path) -> None:
    plan = {
        "task": "t",
        "created": "2026-09-03T00:00:00",
        "requirements": [{"id": "REQ-1", "description": "must be covered", "priority": "must"}],
        "steps": [{
            "id": 1,
            "title": "behavior",
            "verify": [{"type": "run", "cmd": "python -c \"print(1)\""}],
        }],
    }
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
    assert main(["plan", "verify", str(tmp_path)]) == 2


def test_cli_status_reports_stopped_when_daemon_absent(tmp_path: Path) -> None:
    assert main(["supervisor", "status", str(tmp_path)]) == 1


def test_cli_doctor_no_plan_is_healthy(tmp_path: Path) -> None:
    assert main(["doctor", str(tmp_path)]) == 0


def test_cli_doctor_failed_plan_returns_nonzero(tmp_path: Path) -> None:
    _write_plan(tmp_path)
    assert main(["doctor", str(tmp_path)]) == 2


def test_cli_task_list_is_real(tmp_path: Path) -> None:
    _write_plan(tmp_path)
    assert main(["task", "list", str(tmp_path)]) == 0


def test_cli_agents_list_is_real_and_empty(tmp_path: Path) -> None:
    assert main(["agents", "list", str(tmp_path)]) == 0
