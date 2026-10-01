"""Regression coverage for the npm launcher in ``index.js``.

The launcher is the entry point ``npx plan-auditor`` uses. If it swallows the
child exit code then a failing audit silently becomes a passing one in CI, which
is the exact failure mode this project exists to prevent.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="node is required for the npm launcher"
)


def _failing_plan(workspace: Path) -> None:
    plan = {
        "task": "launcher must not mask a failing step",
        "created": "2026-10-01T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "a check that always fails", "priority": "must"}
        ],
        "steps": [
            {
                "id": 1,
                "title": "always fails",
                "covers": ["REQ-001"],
                "verify": [
                    {"type": "run", "cmd": "python -c \"import sys; sys.exit(3)\"", "expect_exit": 0}
                ],
                "status": "pending",
            }
        ],
    }
    (workspace / ".plan-auditor").mkdir(parents=True)
    (workspace / ".plan-auditor" / "plan.json").write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8"
    )


def _passing_plan(workspace: Path) -> None:
    plan = {
        "task": "launcher must report success when the step really passes",
        "created": "2026-10-01T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "a check that really passes", "priority": "must"}
        ],
        "steps": [
            {
                "id": 1,
                "title": "passes",
                "covers": ["REQ-001"],
                "verify": [
                    {
                        "type": "run",
                        "cmd": "python -c \"print('launcher ok')\"",
                        "expect_exit": 0,
                    }
                ],
                "status": "pending",
            }
        ],
    }
    (workspace / ".plan-auditor").mkdir(parents=True)
    (workspace / ".plan-auditor" / "plan.json").write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8"
    )


def _launch(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["node", str(INDEX), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_launcher_propagates_failure_exit_code(tmp_path: Path) -> None:
    """A failing step must not leave the launcher reporting success."""
    workspace = tmp_path / "failing"
    _failing_plan(workspace)
    result = _launch(["run", str(workspace), "1"])
    assert result.returncode != 0, (
        "launcher reported success for a failing step; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_launcher_propagates_blocked_audit_exit_code(tmp_path: Path) -> None:
    """A failing audit must surface the supervisor's blocking code (1 or 2)."""
    workspace = tmp_path / "blocked"
    _failing_plan(workspace)
    run = _launch(["run", str(workspace), "1"])
    audit = _launch(["audit", str(workspace)])
    assert audit.returncode in (1, 2), (
        f"expected the supervisor's FAIL/UNBLOCKED code, got {audit.returncode}; "
        f"stdout={audit.stdout[-800:]!r}"
    )
    assert audit.returncode == run.returncode or audit.returncode != 0


def test_launcher_reports_success_exit_code(tmp_path: Path) -> None:
    """The success path must stay 0, so the fix cannot simply always fail."""
    workspace = tmp_path / "passing"
    _passing_plan(workspace)
    result = _launch(["run", str(workspace), "1"])
    assert result.returncode == 0, (
        f"launcher must exit 0 on a verified step; stdout={result.stdout[-800:]!r} "
        f"stderr={result.stderr[-800:]!r}"
    )


def test_launcher_fails_closed_when_python_is_unavailable(tmp_path: Path) -> None:
    """An empty PATH makes the spawn fail; the launcher must not exit 0."""
    env = {"PATH": "", "SystemRoot": str(Path.home())}
    result = subprocess.run(
        ["node", str(INDEX), "--help"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert result.returncode != 0, "launcher must fail closed when it cannot start Python"


def test_launcher_help_succeeds() -> None:
    result = _launch(["--help"])
    assert result.returncode == 0, result.stderr[-800:]


def test_launcher_source_propagates_exit_code() -> None:
    source = INDEX.read_text(encoding="utf-8")
    assert "process.exit(code === null ? FAILURE_EXIT_CODE : code)" in source
    assert "child.on('close'" in source
    assert "child.on('error'" in source