"""Stop-hook adapter consumes strict JSON and delegates decisions to the real gate."""

from __future__ import annotations

import io
import json
import runpy
import sys

import pytest

from scripts import stop_gate
from supervisor import orchestrator


def test_nonfinite_stop_hook_float_is_not_a_valid_json_number():
    with pytest.raises(ValueError, match="non-finite Stop-hook number"):
        stop_gate._finite_hook_float("1e309")


@pytest.mark.parametrize(
    ("source", "pattern"),
    [
        ('{"cwd":"." ,"cwd":".."}', "duplicate Stop-hook field"),
        ('{"cwd":""}', "cwd must be a non-empty"),
        ('{"cwd":3}', "cwd must be a non-empty"),
        ('["must be an object"]', "payload must be a JSON object"),
        ('{"progress":NaN}', "non-standard Stop-hook numeric constant"),
    ],
)
def test_inbound_json_requires_unambiguous_fields_and_top_level_object(
    monkeypatch, source, pattern
):
    monkeypatch.setattr(sys, "stdin", io.StringIO(source))
    with pytest.raises(ValueError, match=pattern):
        stop_gate._workspace()


def test_oversized_stop_hook_json_is_blocked_before_loading(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO(" " * (stop_gate.MAX_HOOK_JSON_CHARS + 1)))
    with pytest.raises(ValueError, match="exceeds bounded JSON size"):
        stop_gate._workspace()


def test_stop_hook_project_directory_environment_overrides_untrusted_cwd(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"cwd":"/not-trusted-as-root"}'))
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    assert stop_gate._workspace() == str(tmp_path)


def test_stop_hook_missing_payload_defaults_to_cwd_not_silent_pass(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert stop_gate._workspace() == str(tmp_path)


def test_stop_hook_fail_report_shows_fresh_audit_and_required_notes(monkeypatch, capsys, tmp_path):
    def inspected(root):
        assert root == str(tmp_path)
        return {
            "outcome": "FAIL",
            "plans": {
                "ready": {"outcome": "PASS"},
                "empty": "unstructured",
                "unsealed": {
                    "outcome": "FAIL",
                    "gate": {"notes": ["evidence HMAC unverified"]},
                    "fresh_audit": {"valid": False, "reason": "older than signed plan"},
                },
            },
        }

    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))
    monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(orchestrator, "evaluate_workspace", inspected)
    assert stop_gate.main() == 2
    stderr = capsys.readouterr().err
    assert "fresh audit: older than signed plan" in stderr
    assert "evidence HMAC unverified" in stderr
    assert "Run: plan-auditor plan verify" in stderr


@pytest.mark.parametrize("verified_outcome", ["PASS", "NO_PLAN"])
def test_stop_hook_only_allows_explicit_integrated_gate_success(
    monkeypatch, tmp_path, verified_outcome
):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(orchestrator, "evaluate_workspace", lambda _: {"outcome": verified_outcome})
    assert stop_gate.main() == 0


def test_stop_hook_unknown_if_integrated_verifier_raises(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))

    def deny(_root):
        raise RuntimeError("signed trust chain invalid")

    monkeypatch.setattr(orchestrator, "evaluate_workspace", deny)
    assert stop_gate.main() == 2
    assert "UNKNOWN" in capsys.readouterr().err


def test_stop_hook_importable_as_direct_program_still_invokes_gate(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"cwd": "."}'))
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(orchestrator, "evaluate_workspace", lambda _: {"outcome": "FAIL"})
    with pytest.raises(SystemExit) as e:
        runpy.run_module("scripts.stop_gate", run_name="__main__")
    assert e.value.code == 2


def test_stop_hook_without_reconfigure_support_still_calls_gate(monkeypatch, tmp_path):
    stream = io.StringIO()
    err = io.StringIO()
    monkeypatch.setattr(sys, "stdout", stream)
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(
        orchestrator, "evaluate_workspace", lambda _: {"outcome": "FAIL", "plans": {}}
    )
    assert stop_gate.main() == 2
    assert "completion blocked" in err.getvalue()


def test_valid_json_float_is_preserved_without_weakening_finite_bounds():
    assert stop_gate._finite_hook_float("0.125") == 0.125


def test_nonmapping_plans_report_never_bypasses_failed_completeness(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(
        orchestrator,
        "evaluate_workspace",
        lambda _root: {"outcome": "FAIL", "plans": ["not a structured plan"]},
    )
    assert stop_gate.main() == 2
    assert "completion blocked" in capsys.readouterr().err


def test_fresh_passed_audit_does_not_become_a_missing_audit_note(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(sys, "stdin", io.StringIO("{}"))
    monkeypatch.setenv("COMMANDCODE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(
        orchestrator,
        "evaluate_workspace",
        lambda _root: {
            "outcome": "FAIL",
            "plans": {
                "case": {
                    "outcome": "FAIL",
                    "gate": {"notes": ["seal is unverified"]},
                    "fresh_audit": {"valid": True},
                }
            },
        },
    )
    assert stop_gate.main() == 2
    err = capsys.readouterr().err
    assert "seal is unverified" in err
    assert "fresh audit:" not in err
