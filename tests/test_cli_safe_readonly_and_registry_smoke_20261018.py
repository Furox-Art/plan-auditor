"""Real CLI dispatch and fail-closed lifecycle tests on isolated workspaces."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor import cli


def call_cli(capsys, *args):
    result = cli.main(list(args))
    output = capsys.readouterr()
    return result, output


@pytest.mark.parametrize(
    "subcommand,expected_rc,expected_fragment",
    [
        (("supervisor", "status"), 1, "stopped"),
        (("supervisor", "stop"), 0, "stopped"),
        (("task", "list"), 0, "[]"),
        (("task", "inspect", "unknown"), 1, "task not found"),
        (("plan", "inspect"), 1, "no active plans"),
        (("plan", "verify"), 1, "no active plans"),
        (("audit",), 1, "no active plans"),
        (("request", "status"), 2, "valid"),
        (("agents", "list"), 0, "registry_valid"),
    ],
)
def test_cli_dispatch_stays_bounded_to_empty_temp_workspace(
    tmp_path,
    capsys,
    subcommand,
    expected_rc,
    expected_fragment,
):
    args = list(subcommand)
    if subcommand[:2] == ("task", "inspect"):
        args += ["--dir", str(tmp_path)]
    elif subcommand[:2] == ("agents", "list"):
        args += [str(tmp_path)]
    else:
        args += [str(tmp_path)]
    rc, output = call_cli(capsys, *args)
    assert rc == expected_rc
    assert expected_fragment in output.out + output.err


def test_missing_supervisor_root_does_not_spawn_daemon(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    rc, output = call_cli(capsys, "supervisor", "start", str(missing))
    assert rc == 1
    assert "directory not found" in output.err
    assert not missing.exists()


def test_cli_rejects_unknown_arguments_before_actions(tmp_path):
    with pytest.raises(SystemExit) as exc:
        cli.main(["supervisor", "status", str(tmp_path), "--unexpected"])
    assert exc.value.code == 2


def test_task_list_and_inspect_report_real_plans(tmp_path, capsys):
    plan_dir = tmp_path / ".plan-auditor" / "plans"
    plan_dir.mkdir(parents=True)
    path = plan_dir / "example.json"
    payload = {"id": "task-e2e", "steps": [{"status": "verified"}, {}, None]}
    path.write_text(json.dumps(payload), encoding="utf-8")
    rc, output = call_cli(capsys, "task", "list", str(tmp_path))
    assert rc == 0
    assert "task-e2e" in output.out
    assert "verified" in output.out
    assert "pending" in output.out
    assert "invalid" in output.out
    rc, output = call_cli(capsys, "task", "inspect", "task-e2e", "--dir", str(tmp_path))
    assert rc == 0
    assert json.loads(output.out) == payload


def test_task_list_exposes_invalid_json_instead_of_silently_ignoring(tmp_path, capsys):
    plan_dir = tmp_path / ".plan-auditor" / "plans"
    plan_dir.mkdir(parents=True)
    (plan_dir / "broken.json").write_text("{", encoding="utf-8")
    rc, output = call_cli(capsys, "task", "list", str(tmp_path))
    assert rc == 0
    records = json.loads(output.out)
    assert len(records) == 1
    assert "error" in records[0]


def test_cli_agent_registration_heartbeat_and_release(tmp_path, capsys):
    root = str(tmp_path)
    rc, output = call_cli(capsys, "agents", "register", "agent1", "--dir", root)
    assert rc == 0
    assert "agent1" in output.out
    rc, output = call_cli(
        capsys, "agents", "heartbeat", "agent1", "--action-text", "checking", "--dir", root
    )
    assert rc == 0
    assert "agent1" in output.out
    rc, output = call_cli(capsys, "agents", "list", root)
    assert rc == 0
    assert json.loads(output.out)["count"] == 1
    rc, output = call_cli(capsys, "agents", "release", "agent1", "--dir", root)
    assert rc == 0
    assert "agent1" in output.out
    rc, output = call_cli(capsys, "agents", "list", root)
    assert rc == 0
    assert json.loads(output.out)["count"] == 0


def test_persist_supervisor_settings_preserves_unrelated_fields(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    from supervisor.config import CONFIG_FILENAME

    path = pg / CONFIG_FILENAME
    path.write_text(json.dumps({"custom": "preserved", "mode": "old"}), encoding="utf-8")
    cli._persist_supervisor_config(tmp_path, "strict", "serial")
    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["profile"] == "strict"
    assert config["mode"] == "serial"
    assert config["custom"] == "preserved"
    assert config["tier"] == 1
    path.write_text("not JSON", encoding="utf-8")
    cli._persist_supervisor_config(tmp_path, "light", "parallel-warn")
    assert json.loads(path.read_text(encoding="utf-8"))["profile"] == "light"


def test_cli_supervisor_start_invalid_root_returns_before_config_write(tmp_path, capsys):
    nonexistent = Path(tmp_path) / "missing"
    rc, output = call_cli(capsys, "supervisor", "start", str(nonexistent))
    assert rc == 1
    assert "ERROR:" in output.err
    assert not nonexistent.exists()


def test_cli_evidence_verifier_reports_empty_authenticated_chain_state(tmp_path, capsys):
    rc, output = call_cli(capsys, "evidence", "verify", str(tmp_path))
    assert rc == 0
    document = json.loads(output.out)
    assert document["valid"] is True
    assert document["active"]["records"] == 0
    assert document["archive"]["anchored"] is True


def test_cli_integrity_status_does_not_invent_authentication(tmp_path, capsys):
    rc, output = call_cli(capsys, "integrity", "status", str(tmp_path))
    assert rc == 0
    document = json.loads(output.out)
    assert document["authenticated"] is False
    assert document["configured"] is False


def test_cli_doctor_reports_no_active_plan_not_verified_completion(tmp_path, capsys):
    rc, output = call_cli(capsys, "doctor", str(tmp_path))
    assert rc == 0
    document = json.loads(output.out)
    assert document["assessment"]["outcome"] == "NO_PLAN"
    assert document["workspace"]["repository_root"] == str(tmp_path)


def test_cli_request_init_refuses_missing_file(tmp_path, capsys):
    rc, output = call_cli(
        capsys,
        "request",
        "init",
        str(tmp_path),
        "--file",
        str(tmp_path / "missing.json"),
    )
    assert rc == 2
    document = json.loads(output.out)
    assert document["activated"] is False
    assert document["valid"] is False
    assert "error" in document


def test_cli_heartbeat_unknown_agent_refuses_without_spawning_agent(tmp_path, capsys):
    rc, output = call_cli(capsys, "agents", "heartbeat", "missing", "--dir", str(tmp_path))
    assert rc == 2
    assert json.loads(output.out)["registry_valid"] is False
    rc, output = call_cli(capsys, "agents", "list", str(tmp_path))
    assert rc == 0
    assert json.loads(output.out)["count"] == 0


def test_cli_parallel_strict_rejects_conflicting_real_file_claim(tmp_path, capsys):
    root = str(tmp_path)
    cli._persist_supervisor_config(tmp_path, "strict", "parallel-strict")
    for agent in ("first", "second"):
        rc, _ = call_cli(capsys, "agents", "register", agent, "--dir", root)
        assert rc == 0
    rc, output = call_cli(capsys, "agents", "claim", "first", "artifact.txt", "--dir", root)
    assert rc == 0
    assert json.loads(output.out)["claimed"] is True
    rc, output = call_cli(capsys, "agents", "claim", "second", "artifact.txt", "--dir", root)
    assert rc == 2
    document = json.loads(output.out)
    assert document["claimed"] is False
    assert document["conflicts"][0]["owner_agent"] == "first"
    assert document["conflicts"][0]["accessor_agent"] == "second"
