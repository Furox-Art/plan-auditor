"""Final audit fail-closed paths, malformed graph, and command status branches."""

from __future__ import annotations

import argparse
import json

import pytest

from scripts import audit_check as ac
from scripts.plan_graph import PlanGraphError


def _plan():
    return {
        "task": "test",
        "steps": [{"id": 1, "title": "step", "verify": [{"type": "file_exists", "path": "x.txt"}]}],
    }


def _minimal(monkeypatch):
    monkeypatch.setattr(ac, "_runtime_limits", lambda base: (3, 2000000))
    monkeypatch.setattr(ac, "save_plan", lambda *args, **kwargs: None)


def test_invalid_output_dependency_graph_refuses_execution(monkeypatch, tmp_path, capsys):
    _minimal(monkeypatch)
    monkeypatch.setattr(ac, "validate_output_links", lambda plan: ["unproven dependency"])
    assert ac.audit_steps(str(tmp_path), _plan()) is False
    assert "unproven dependency" in capsys.readouterr().out


def test_unknown_step_selection_is_error_not_silent_success(monkeypatch, tmp_path):
    _minimal(monkeypatch)
    with pytest.raises(SystemExit, match="planda yok"):
        ac.audit_steps(str(tmp_path), _plan(), ids=[999])


def test_explicit_empty_selection_exits_without_claiming_coverage(monkeypatch, tmp_path):
    _minimal(monkeypatch)
    assert ac.audit_steps(str(tmp_path), _plan(), ids=[]) is True


def test_final_audit_detects_workspace_modification_before_first_step(monkeypatch, tmp_path):
    _minimal(monkeypatch)
    states = iter(["original", "changed", "changed"])
    monkeypatch.setattr(ac, "workspace_fingerprint", lambda root: next(states))
    evidence = []
    monkeypatch.setattr(ac, "append_evidence", lambda root, rec: evidence.append(rec))
    plan = _plan()
    assert ac.audit_steps(str(tmp_path), plan, mode="audit") is False
    assert plan["steps"][0]["status"] == "failed"
    assert any(row["mode"] == "audit_guard" and row["status"] == "failed" for row in evidence)


def test_runtime_output_graph_exception_cannot_be_pass(monkeypatch, tmp_path, capsys):
    _minimal(monkeypatch)
    monkeypatch.setattr(ac, "failed_attempt_counts", lambda base, mode="run": {})
    monkeypatch.setattr(ac, "_prerequisite_gate", lambda *args: (True, [], [], []))
    monkeypatch.setattr(
        ac,
        "_run_check_list",
        lambda *args: (
            True,
            [{"passed": True, "detail": "ok", "output_tail": "", "check": {"type": "check"}}],
        ),
    )
    monkeypatch.setattr(
        ac, "output_index", lambda step: (_ for _ in ()).throw(PlanGraphError("bad output"))
    )
    monkeypatch.setattr(ac, "append_evidence", lambda root, rec: None)
    plan = _plan()
    assert ac.audit_steps(str(tmp_path), plan, mode="run") is False
    assert plan["steps"][0]["status"] == "failed"
    assert "bad output" in capsys.readouterr().out


def test_failed_result_prints_bounded_output_tail(monkeypatch, tmp_path, capsys):
    _minimal(monkeypatch)
    monkeypatch.setattr(ac, "failed_attempt_counts", lambda base, mode="run": {})
    monkeypatch.setattr(ac, "_prerequisite_gate", lambda *args: (True, [], [], []))
    monkeypatch.setattr(
        ac,
        "_run_check_list",
        lambda *args: (
            False,
            [
                {
                    "passed": False,
                    "detail": "error",
                    "output_tail": "LAST ERROR\nDETAIL",
                    "check": {"type": "run"},
                }
            ],
        ),
    )
    monkeypatch.setattr(ac, "append_evidence", lambda root, rec: None)
    assert ac.audit_steps(str(tmp_path), _plan(), mode="run") is False
    assert "LAST ERROR | DETAIL" in capsys.readouterr().out


def test_explicit_named_plan_display_is_not_ambiguous(capsys):
    ac.print_table(
        {"steps": [{"id": 1, "title": "step", "verify": [], "status": "pending"}]}, "versioned"
    )
    assert "PLAN: versioned" in capsys.readouterr().out


def test_schema_valid_command_reports_count(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ac, "_validated_runtime_config", lambda root: {})
    monkeypatch.setattr(ac, "load_plan", lambda root, name: {"steps": [{"id": 1}]})
    monkeypatch.setattr(ac, "validate_plan", lambda plan: [])
    args = argparse.Namespace(dir=str(tmp_path), plan=None)
    assert ac.cmd_validate(args) == 0
    assert "Schema valid: 1 steps" in capsys.readouterr().out


def test_invalid_scheme_validation_is_refused(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ac, "_validated_runtime_config", lambda root: {})
    monkeypatch.setattr(ac, "load_plan", lambda root, name: {"steps": []})
    assert ac.cmd_validate(argparse.Namespace(dir=str(tmp_path), plan=None)) == 1
    assert "SCHEMA ERROR" in capsys.readouterr().out


def test_non_object_evidence_record_is_explicit_integrity_failure(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "evidence.jsonl").write_text("[]\n", encoding="utf-8")
    ok, count, reason = ac.verify_chain(str(tmp_path))
    assert ok is False
    assert count == 0
    assert "not a JSON object" in reason


def test_evidence_head_without_key_is_not_authenticated(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "evidence.head.json").write_text("{}", encoding="utf-8")
    ok, count, reason = ac.verify_chain(str(tmp_path))
    assert ok is False
    assert "requires HMAC key" in reason


def test_snapshot_explicit_missing_path_records_absence(tmp_path, monkeypatch):
    monkeypatch.setattr(ac, "append_evidence", lambda *args: None)
    zip_path = ac.make_snapshot(str(tmp_path), {"snapshot": ["not-yet-created.txt"]})
    import zipfile

    with zipfile.ZipFile(zip_path) as archive:
        doc = json.loads(archive.read(ac.SNAPSHOT_MANIFEST))
    assert doc["scope"] == "explicit"
    assert doc["roots"] == ["not-yet-created.txt"]
    assert doc["absent"] == ["not-yet-created.txt"]
