"""Cover the legacy Stop-hook adapter's explicit fail-closed branches."""
from __future__ import annotations

import io
import json
import os

from scripts import stop_gate
from supervisor import orchestrator


def test_workspace_from_payload_when_no_environment_override(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(stop_gate.sys, "stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))
    assert stop_gate._workspace() == str(tmp_path)


def test_workspace_invalid_stdin_uses_current_directory(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(stop_gate.sys, "stdin", io.StringIO("{ invalid"))
    assert stop_gate._workspace() == os.fspath(tmp_path)


def test_workspace_environment_overrides_stdin(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(stop_gate.sys, "stdin", io.StringIO(json.dumps({"cwd": "/unused"})))
    assert stop_gate._workspace() == str(tmp_path)


def _run(monkeypatch, tmp_path, report=None, error=None):
    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(stop_gate.sys, "stdout", out)
    monkeypatch.setattr(stop_gate.sys, "stderr", err)
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(stop_gate.sys, "stdin", io.StringIO("{}"))
    if error is None:
        monkeypatch.setattr(orchestrator, "evaluate_workspace", lambda base: report)
    else:
        def raise_error(base):
            raise error
        monkeypatch.setattr(orchestrator, "evaluate_workspace", raise_error)
    return stop_gate.main(), err.getvalue()


def test_stop_adapter_allows_verified_completion(monkeypatch, tmp_path) -> None:
    rc, err = _run(monkeypatch, tmp_path, {"outcome": "PASS"})
    assert rc == 0
    assert err == ""


def test_stop_adapter_passes_no_plan_without_claiming_verification(
    monkeypatch, tmp_path
) -> None:
    rc, err = _run(monkeypatch, tmp_path, {"outcome": "NO_PLAN"})
    assert rc == 0
    assert err == ""


def test_stop_adapter_fails_closed_on_integrated_gate_exception(
    monkeypatch, tmp_path
) -> None:
    rc, err = _run(monkeypatch, tmp_path, error=RuntimeError("cannot inspect state"))
    assert rc == 2
    assert "UNKNOWN" in err and "cannot inspect state" in err


def test_stop_adapter_includes_failed_plan_diagnostics(monkeypatch, tmp_path) -> None:
    report = {
        "outcome": "FAIL",
        "plans": {
            "default": {
                "outcome": "FAIL",
                "gate": {"notes": ["seal invalid", "evidence unavailable"]},
                "fresh_audit": {"valid": False, "reason": "missing fresh evidence"},
            },
            "passing": {"outcome": "PASS"},
        },
    }
    rc, err = _run(monkeypatch, tmp_path, report)
    assert rc == 2
    assert "completion blocked" in err
    assert "default: FAIL" in err
    assert "missing fresh evidence" in err
    assert "seal invalid" in err
    assert "evidence unavailable" in err
    assert "passing: PASS" not in err
    assert "plan-auditor audit" in err


def test_stop_adapter_unknown_outcome_is_not_a_success(monkeypatch, tmp_path) -> None:
    rc, err = _run(monkeypatch, tmp_path, {"outcome": "UNKNOWN", "plans": {}})
    assert rc == 2 and "UNKNOWN" in err
