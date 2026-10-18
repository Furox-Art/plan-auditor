"""The deterministic core must refuse invalid authorization, evidence and commands."""

from __future__ import annotations

import argparse
import sys

import pytest

from scripts import audit_check as ac


def args(tmp_path, *, plan=None, ids=None, force=False, to=None):
    return argparse.Namespace(dir=str(tmp_path), plan=plan, ids=ids, force=force, to=to)


@pytest.mark.parametrize(
    "command",
    [
        ac.cmd_validate,
        ac.cmd_run,
        ac.cmd_audit,
    ],
)
def test_malformed_runtime_config_is_explicit_failure_not_the_default(
    monkeypatch, tmp_path, command, capsys
):
    monkeypatch.setattr(
        ac,
        "_validated_runtime_config",
        lambda _: (_ for _ in ()).throw(ValueError("tampered config")),
    )
    result = command(args(tmp_path))
    assert result in (1, 2)
    assert "CONFIG HATASI" in capsys.readouterr().out


@pytest.mark.parametrize(
    "command",
    [
        ac.cmd_run,
        ac.cmd_audit,
        ac.cmd_status,
        ac.cmd_snapshot,
        ac.cmd_rollback,
    ],
)
def test_broken_evidence_chain_cannot_be_made_successful_by_command(
    monkeypatch, tmp_path, command, capsys
):
    monkeypatch.setattr(ac, "_validated_runtime_config", lambda _: {})
    monkeypatch.setattr(ac, "verify_chain", lambda _: (False, 0, "tampered chain"))
    monkeypatch.setattr(ac, "load_plan", lambda *_: {"steps": []})
    result = command(args(tmp_path))
    assert result == 2
    assert "EVIDENCE CHAIN TAMPERED" in capsys.readouterr().out


@pytest.mark.parametrize(
    "command",
    [
        ac.cmd_validate,
        ac.cmd_run,
        ac.cmd_audit,
    ],
)
def test_schema_failure_is_printed_and_never_produces_execution(
    monkeypatch, tmp_path, command, capsys
):
    monkeypatch.setattr(ac, "_validated_runtime_config", lambda _: {})
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(ac, "load_plan", lambda *_: {"steps": []})
    monkeypatch.setattr(ac, "validate_plan", lambda _: ["no behavioral verifier"])
    monkeypatch.setattr(ac, "audit_steps", lambda *_a, **_kw: pytest.fail("execution forbidden"))
    assert command(args(tmp_path)) == 1
    assert "SCHEMA ERROR" in capsys.readouterr().out


def prepare_run(monkeypatch):
    monkeypatch.setattr(ac, "_validated_runtime_config", lambda _: {})
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(
        ac,
        "load_plan",
        lambda *_: {"steps": [{"id": 1, "status": "verified"}, {"id": 2, "status": "pending"}]},
    )
    monkeypatch.setattr(ac, "validate_plan", lambda _: [])


@pytest.mark.parametrize("command", [ac.cmd_run, ac.cmd_audit])
def test_untrusted_plan_rejected_even_if_some_steps_were_previously_verified(
    monkeypatch, tmp_path, command, capsys
):
    prepare_run(monkeypatch)

    def no_trust(*_):
        raise ac.PlanTrustError("unsigned plan cannot execute")

    monkeypatch.setattr(ac, "require_plan_trust", no_trust)
    monkeypatch.setattr(ac, "audit_steps", lambda *_a, **_kw: pytest.fail("execution forbidden"))
    assert command(args(tmp_path)) == 2
    assert "unsigned plan" in capsys.readouterr().out


@pytest.mark.parametrize(("explicit_ids", "expected"), [(None, [2]), ([1], [1]), ([], [2])])
def test_run_selects_only_unverified_steps_by_default_and_preserves_explicit_selection(
    monkeypatch, tmp_path, explicit_ids, expected
):
    prepare_run(monkeypatch)
    monkeypatch.setattr(ac, "require_plan_trust", lambda *_a: None)
    calls = []
    monkeypatch.setattr(ac, "audit_steps", lambda root, plan, **kw: calls.append(kw) or True)
    assert ac.cmd_run(args(tmp_path, ids=explicit_ids, force=True)) == 0
    assert len(calls) == 1
    assert calls[0]["ids"] == expected
    assert calls[0]["mode"] == "run"
    assert calls[0]["force"] is True


def test_run_reports_actual_audit_failure_without_renaming_it_to_success(monkeypatch, tmp_path):
    prepare_run(monkeypatch)
    monkeypatch.setattr(ac, "require_plan_trust", lambda *_a: None)
    monkeypatch.setattr(ac, "audit_steps", lambda *_a, **_kw: False)
    assert ac.cmd_run(args(tmp_path)) == 1


@pytest.mark.parametrize(
    ("audited", "authenticated", "expected"),
    [
        (False, True, 1),
        (True, False, 2),
        (True, True, 0),
    ],
)
def test_audit_completion_is_authentication_gated_after_actual_retest(
    monkeypatch, tmp_path, audited, authenticated, expected, capsys
):
    prepare_run(monkeypatch)
    monkeypatch.setattr(ac, "require_plan_trust", lambda *_a: None)
    monkeypatch.setattr(ac, "audit_steps", lambda *_a, **_kw: audited)
    monkeypatch.setattr(ac, "evidence_is_authenticated", lambda _: (authenticated, "key missing"))
    monkeypatch.setattr(ac, "print_table", lambda *_: None)
    assert ac.cmd_audit(args(tmp_path)) == expected
    printed = capsys.readouterr().out
    assert ("audit PASSED" in printed) == (expected == 0)
    if expected == 2:
        assert "not authenticated" in printed


def test_status_counts_only_explicit_verified_states(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 3, None))
    monkeypatch.setattr(
        ac,
        "load_plan",
        lambda *_: {
            "steps": [{"status": "verified"}, {"status": "pending"}, {"status": "VERIFIED"}]
        },
    )
    monkeypatch.setattr(ac, "print_table", lambda *_: None)
    assert ac.cmd_status(args(tmp_path)) == 0
    assert "1/3 steps verified" in capsys.readouterr().out


@pytest.mark.parametrize(("snap_ok", "expected"), [(True, 0), (False, 1)])
def test_snapshot_does_not_hide_real_write_outcome(monkeypatch, tmp_path, snap_ok, expected):
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(ac, "load_plan", lambda *_: {"steps": []})
    monkeypatch.setattr(ac, "make_snapshot", lambda *_: snap_ok)
    assert ac.cmd_snapshot(args(tmp_path)) == expected


@pytest.mark.parametrize("failure", ["invalid zip", "invalid manifest"])
def test_rollback_handles_corrupt_archive_as_failure_not_success(
    monkeypatch, tmp_path, failure, capsys
):
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(ac, "latest_snapshot", lambda _: "/tmp/documented-existing-audit.zip")
    monkeypatch.setattr(
        ac, "restore_snapshot", lambda *_a: (_ for _ in ()).throw(ValueError(failure))
    )
    assert ac.cmd_rollback(args(tmp_path)) == 1
    assert "safe rollback failed" in capsys.readouterr().out


def test_rollback_must_see_a_real_recorded_snapshot_first(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(ac, "latest_snapshot", lambda _: None)
    with pytest.raises(SystemExit, match="no snapshot exists"):
        ac.cmd_rollback(args(tmp_path))


def test_explicit_rollback_missing_file_is_never_substituted_by_another_snapshot(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(ac, "snapshots_dir", lambda _: str(tmp_path))
    with pytest.raises(SystemExit, match="snapshot not found"):
        ac.cmd_rollback(args(tmp_path, to="nonexistent-zip"))


def test_explicit_real_snapshot_path_is_passed_without_shell_expansion(monkeypatch, tmp_path):
    a = tmp_path / "recorded.zip"
    a.write_bytes(b"fake archive only; adapter check")
    monkeypatch.setattr(ac, "verify_chain", lambda _: (True, 0, None))
    monkeypatch.setattr(ac, "snapshots_dir", lambda _: str(tmp_path))
    called = []
    monkeypatch.setattr(ac, "restore_snapshot", lambda root, filename: called.append(filename))
    assert ac.cmd_rollback(args(tmp_path, to="recorded.zip")) == 0
    assert called == [str(a)]


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["validate", "--plan", "../escape"], 1),
        (["validate", "--plan", "invalid space"], 1),
    ],
)
def test_core_entrypoint_cannot_escape_named_plan_basename(monkeypatch, tmp_path, argv, expected):
    monkeypatch.setattr(sys, "argv", ["audit_check", argv[0], str(tmp_path), *argv[1:]])
    assert ac.main() == expected


def test_missing_working_directory_is_an_explicit_exit_not_a_success(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "argv", ["audit_check", "status", str(tmp_path / "nonexistent")])
    with pytest.raises(SystemExit, match="dizin yok"):
        ac.main()


@pytest.mark.parametrize(
    "name",
    [
        "run",
        "audit",
        "validate",
        "status",
        "snapshot",
        "rollback",
    ],
)
def test_main_dispatch_uses_exact_known_command_and_absolutizes_root(monkeypatch, tmp_path, name):
    calls = []
    monkeypatch.setattr(ac, "cmd_" + name, lambda opts: calls.append(opts) or 0)
    monkeypatch.setattr(sys, "argv", ["audit_check", name, str(tmp_path)])
    assert ac.main() == 0
    assert calls[0].dir == str(tmp_path)
    assert calls[0].mode == name
