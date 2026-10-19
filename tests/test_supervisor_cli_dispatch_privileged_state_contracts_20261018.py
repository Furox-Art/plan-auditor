"""CLI dispatch cannot label stale daemons, unsigned evidence, or missing plans PASS."""

from __future__ import annotations

import argparse
import json

import pytest

from supervisor import cli, daemon, integrity


def args(root, action="status", **kw):
    return argparse.Namespace(dir=str(root), action=action, **kw)


def test_real_missing_supervisor_project_has_explicit_failure(tmp_path, capsys):
    out = cli.cmd_supervisor_start(
        args(tmp_path / "no-directory", action="start", profile="strict", mode="serial")
    )
    assert out == 1
    assert "directory not found" in capsys.readouterr().err


def test_start_refuses_a_confirmed_already_running_daemon_without_duplicate_launch(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(daemon, "read_state", lambda _: {"state": "running", "pid": 12})
    monkeypatch.setattr(daemon, "pid_alive", lambda _: True)
    with pytest.raises(RuntimeError, match="already running"):
        cli._spawn_daemon(tmp_path, "strict", "serial")


def test_start_configuration_writes_actual_atomic_profile_and_preserves_existing_fields(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text('{"tier":3,"max_attempts":5}')
    cli._persist_supervisor_config(tmp_path, "strict", "parallel-strict")
    persisted = json.loads((pg / "supervisor.json").read_text())
    assert persisted == {
        "tier": 3,
        "max_attempts": 5,
        "profile": "strict",
        "mode": "parallel-strict",
    }
    assert not (pg / "supervisor.json.tmp").exists()


def test_malformed_old_config_is_not_treated_as_a_trusted_valid_configuration(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text("{not-json")
    cli._persist_supervisor_config(tmp_path, "light", "serial")
    assert json.loads((pg / "supervisor.json").read_text()) == {
        "profile": "light",
        "mode": "serial",
        "tier": 1,
    }


def test_stopped_supervisor_status_is_not_running_even_if_assessment_carries_pass(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(daemon, "read_state", lambda _: None)
    monkeypatch.setattr(daemon, "read_assessment", lambda _: {"outcome": "PASS", "source": "old"})
    assert cli.cmd_supervisor_status(args(tmp_path)) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["running"] is False
    assert report["assessment"]["outcome"] == "PASS"


def test_stale_supervisor_pid_is_not_reported_as_live(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda _: {"state": "running", "pid": 777})
    monkeypatch.setattr(daemon, "pid_alive", lambda _: False)
    monkeypatch.setattr(daemon, "read_assessment", lambda _: None)
    assert cli.cmd_supervisor_status(args(tmp_path)) == 1
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "stale"
    assert result["running"] is False


def test_live_supervisor_status_exposes_authenticated_current_pid(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda _: {"state": "running", "pid": 777})
    monkeypatch.setattr(daemon, "pid_alive", lambda _: True)
    monkeypatch.setattr(daemon, "read_assessment", lambda _: {"outcome": "UNKNOWN"})
    assert cli.cmd_supervisor_status(args(tmp_path)) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["state"] == "running"
    assert report["running"] is True
    assert report["assessment"]["outcome"] == "UNKNOWN"


def test_stop_does_not_send_signal_to_a_pid_without_liveness_evidence(
    monkeypatch, tmp_path, capsys
):
    monkeypatch.setattr(daemon, "read_state", lambda _: {"state": "running", "pid": 123})
    monkeypatch.setattr(daemon, "pid_alive", lambda _: False)

    def forbidden(*_args):
        pytest.fail("signal must not be sent for missing process")

    monkeypatch.setattr(cli.os, "kill", forbidden)
    assert cli.cmd_supervisor_stop(args(tmp_path)) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "stopped"


def test_stop_writes_its_marker_when_an_actual_live_process_is_known(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(daemon, "read_state", lambda _: {"state": "running", "pid": 123})
    responses = iter([True, False])
    monkeypatch.setattr(daemon, "pid_alive", lambda _: next(responses))
    assert cli.cmd_supervisor_stop(args(tmp_path)) == 0
    assert (tmp_path / ".plan-auditor" / daemon.STOP_FILENAME).read_text() == "stop\n"
    assert json.loads(capsys.readouterr().out)["pid"] == 123


def test_failed_daemon_start_reports_no_false_start_success(monkeypatch, tmp_path, capsys):
    def unavailable(*_):
        raise RuntimeError("simulated incompatible daemon")

    monkeypatch.setattr(cli, "_spawn_daemon", unavailable)
    assert (
        cli.cmd_supervisor_start(args(tmp_path, action="start", profile="strict", mode="serial"))
        == 1
    )
    assert "simulated incompatible daemon" in capsys.readouterr().err


def test_plan_inspection_never_invents_a_missing_named_plan(tmp_path, capsys):
    assert cli.cmd_plan_inspect(args(tmp_path, action="inspect", plan="absent")) == 1
    assert "not found" in capsys.readouterr().err


def test_plan_inspection_real_named_json_file_preserves_source_fields(tmp_path, capsys):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    (folder / "experiment.json").write_text('{"task":"real recorded plan","steps":[]}')
    assert cli.cmd_plan_inspect(args(tmp_path, action="inspect", plan="experiment")) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["task"] == "real recorded plan"


def test_multiple_existing_plans_are_returned_as_distinct_named_objects(tmp_path, capsys):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    for name in ("one", "two"):
        (folder / f"{name}.json").write_text(json.dumps({"task": name, "steps": []}))
    assert cli.cmd_plan_inspect(args(tmp_path, action="inspect", plan=None)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["one"]["task"] == "one"
    assert result["two"]["task"] == "two"


@pytest.mark.parametrize(
    ("authenticated", "configured", "expected"),
    [
        (True, True, 0),
        (False, False, 0),
        (False, True, 2),
    ],
)
def test_integrity_status_distinguishes_configured_failed_hmac_from_no_external_key(
    monkeypatch, tmp_path, capsys, authenticated, configured, expected
):
    monkeypatch.setattr(
        integrity,
        "integrity_status",
        lambda _: {"authenticated": authenticated, "configured": configured},
    )
    rc = cli.cmd_integrity(args(tmp_path, action="status"))
    assert rc == expected
    result = json.loads(capsys.readouterr().out)
    assert result["authenticated"] is authenticated


def test_real_empty_evidence_archive_never_requires_fabricated_records(tmp_path, capsys):
    result = cli.cmd_evidence_verify(args(tmp_path, action="verify"))
    report = json.loads(capsys.readouterr().out)
    assert report["active"]["records"] == 0
    assert report["valid"] is (result == 0)


def test_actual_task_summary_counts_invalid_steps_separately(tmp_path):
    plan = tmp_path / "study.json"
    plan.write_text(
        json.dumps(
            {
                "id": "case-1",
                "steps": [{"id": 1, "status": "verified"}, {"id": 2, "status": "failed"}, 42],
            }
        )
    )
    out = cli._task_summary(plan)
    assert out["task_id"] == "case-1"
    assert out["steps"] == 3
    assert out["statuses"] == {"verified": 1, "failed": 1, "invalid": 1}


def test_task_summary_corrupt_json_is_never_reported_as_completed_task(tmp_path):
    plan = tmp_path / "broken.json"
    plan.write_text("not-json")
    out = cli._task_summary(plan)
    assert "error" in out
    assert "task_id" not in out


def test_task_list_real_repository_has_no_fabricated_tasks(tmp_path, capsys):
    assert cli.cmd_task_list(args(tmp_path, action="list")) == 0
    assert json.loads(capsys.readouterr().out) == []


def test_cli_unsupported_verb_does_not_continue_into_core_without_parser_approval():
    with pytest.raises(SystemExit) as exc:
        cli.main(["unknown-verb"])
    assert exc.value.code == 2


def test_cli_requires_explicit_subcommand_not_a_default_unsafe_action():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2
