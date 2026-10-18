"""Read-only CLI validation and explicit refusal paths on isolated fixture trees."""

from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from supervisor import cli


def test_single_named_plan_ref_resolves_real_file(tmp_path):
    directory = tmp_path / ".plan-auditor" / "plans"
    directory.mkdir(parents=True)
    (directory / "named.json").write_text(
        json.dumps({"id": "named", "steps": []}), encoding="utf-8"
    )
    refs = cli._selected_refs(tmp_path, "named")
    assert len(refs) == 1
    assert refs[0].path.read_text(encoding="utf-8").startswith("{")


@pytest.mark.parametrize("name", ["unknown", "missing.json"])
def test_named_plan_not_found_fails_instead_of_selecting_default(tmp_path, name):
    with pytest.raises(FileNotFoundError, match="plan not found"):
        cli._selected_refs(tmp_path, name)


def test_plan_inspect_reads_one_named_plan_without_changing_it(tmp_path, capsys):
    directory = tmp_path / ".plan-auditor" / "plans"
    directory.mkdir(parents=True)
    original = {"id": "test", "steps": [{"id": 1}]}
    path = directory / "named.json"
    path.write_text(json.dumps(original), encoding="utf-8")
    rc = cli.cmd_plan_inspect(argparse.Namespace(dir=str(tmp_path), plan="named"))
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == original
    assert json.loads(path.read_text()) == original


def test_plan_inspect_reads_multiple_distinct_plans(tmp_path, capsys):
    directory = tmp_path / ".plan-auditor" / "plans"
    directory.mkdir(parents=True)
    for name in ("first", "second"):
        (directory / f"{name}.json").write_text(json.dumps({"id": name}), encoding="utf-8")
    rc = cli.cmd_plan_inspect(argparse.Namespace(dir=str(tmp_path), plan=None))
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc) == 2
    assert {value["id"] for value in doc.values()} == {"first", "second"}


def test_plan_inspect_rejects_corrupt_real_file(tmp_path, capsys):
    directory = tmp_path / ".plan-auditor" / "plans"
    directory.mkdir(parents=True)
    (directory / "bad.json").write_text("{", encoding="utf-8")
    rc = cli.cmd_plan_inspect(argparse.Namespace(dir=str(tmp_path), plan="bad"))
    assert rc == 1
    assert "ERROR:" in capsys.readouterr().err


def test_task_inspect_rejects_corrupt_real_json(tmp_path, capsys):
    directory = tmp_path / ".plan-auditor" / "plans"
    directory.mkdir(parents=True)
    (directory / "bad.json").write_text("{", encoding="utf-8")
    rc = cli.cmd_task_inspect(argparse.Namespace(dir=str(tmp_path), task_id="bad"))
    assert rc == 1
    assert "ERROR:" in capsys.readouterr().err


def test_invalid_request_json_fails_activation_without_false_success(tmp_path, capsys):
    request = tmp_path / "bad.json"
    request.write_text("{", encoding="utf-8")
    rc = cli.cmd_request(
        argparse.Namespace(dir=str(tmp_path), action="init", request_file=str(request))
    )
    assert rc == 2
    doc = json.loads(capsys.readouterr().out)
    assert doc["valid"] is False
    assert doc["activated"] is False


def test_request_status_includes_alignment_findings_when_available(monkeypatch, tmp_path, capsys):
    status = SimpleNamespace(valid=True, as_dict=lambda: {"valid": True})
    alignment = SimpleNamespace(as_dict=lambda: {"aligned": False})
    monkeypatch.setattr(cli, "_request_gate", lambda root: (status, alignment, ["not aligned"]))
    rc = cli.cmd_request(argparse.Namespace(dir=str(tmp_path), action="status"))
    assert rc == 2
    doc = json.loads(capsys.readouterr().out)
    assert doc["alignment"] == {"aligned": False}
    assert doc["errors"] == ["not aligned"]


def test_request_status_valid_alignment_reports_only_verified_status(monkeypatch, tmp_path, capsys):
    status = SimpleNamespace(valid=True, as_dict=lambda: {"valid": True})
    alignment = SimpleNamespace(as_dict=lambda: {"aligned": True})
    monkeypatch.setattr(cli, "_request_gate", lambda root: (status, alignment, []))
    rc = cli.cmd_request(argparse.Namespace(dir=str(tmp_path), action="status"))
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["errors"] == []


def test_incorrect_hmac_configuration_refuses_integrity_status(monkeypatch, tmp_path, capsys):
    import supervisor.integrity as integrity

    monkeypatch.setattr(
        integrity, "integrity_status", lambda root: {"authenticated": False, "configured": True}
    )
    rc = cli.cmd_integrity(argparse.Namespace(dir=str(tmp_path), action="status"))
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["authenticated"] is False


def test_integrity_initialization_propagates_unsafe_input_failure(monkeypatch, tmp_path, capsys):
    import supervisor.integrity as integrity

    def refuse(root):
        raise ValueError("unauthenticated registry")

    monkeypatch.setattr(integrity, "initialize_integrity", refuse)
    rc = cli.cmd_integrity(argparse.Namespace(dir=str(tmp_path), action="init"))
    assert rc == 2
    doc = json.loads(capsys.readouterr().out)
    assert doc["authenticated"] is False
    assert "unauthenticated registry" in doc["error"]


def test_integrity_initialization_only_passes_when_backend_returns_normally(
    monkeypatch, tmp_path, capsys
):
    import supervisor.integrity as integrity

    monkeypatch.setattr(integrity, "initialize_integrity", lambda root: {"authenticated": True})
    rc = cli.cmd_integrity(argparse.Namespace(dir=str(tmp_path), action="init"))
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["authenticated"] is True


def test_active_evidence_failure_is_not_downgraded_by_good_archive(monkeypatch, tmp_path, capsys):
    import supervisor.evidence as evidence
    from scripts import audit_check

    monkeypatch.setattr(audit_check, "verify_chain", lambda root: (False, 1, "truncated log"))
    monkeypatch.setattr(evidence, "verify_anchor_chain", lambda path: {"anchored": True})
    rc = cli.cmd_evidence_verify(argparse.Namespace(dir=str(tmp_path)))
    assert rc == 2
    doc = json.loads(capsys.readouterr().out)
    assert doc["active"]["problem"] == "truncated log"
    assert doc["valid"] is False


def test_missing_archive_anchor_is_not_downgraded_by_good_log(monkeypatch, tmp_path, capsys):
    import supervisor.evidence as evidence
    from scripts import audit_check

    monkeypatch.setattr(audit_check, "verify_chain", lambda root: (True, 2, ""))
    monkeypatch.setattr(evidence, "verify_anchor_chain", lambda path: {"anchored": False})
    rc = cli.cmd_evidence_verify(argparse.Namespace(dir=str(tmp_path)))
    assert rc == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False


def test_separate_config_and_policy_directories_are_checked_once_each(monkeypatch, tmp_path):
    import supervisor.policies as policies

    observed = []

    def inspect(path, errors):
        observed.append(path)
        errors.append("simulated parser failure")

    monkeypatch.setattr(policies, "load_policy_rules_from_dir", inspect)
    cfg = SimpleNamespace(policies_dir=".plan-auditor/policies")
    errors = cli._policy_errors(tmp_path, cfg)
    assert len(observed) == 1
    assert errors == ["simulated parser failure"]
