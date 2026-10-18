"""Physical filesystem and process-evidence error paths in the installed audit core."""

from __future__ import annotations

import builtins
import json
import os
import socket
import stat
import sys
from types import SimpleNamespace

import pytest

from scripts import audit_check as core


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("default", None),
        ("named.plan-01", "named.plan-01"),
    ],
)
def test_real_plan_name_canonicalization_cannot_change_a_named_plan(value, expected):
    assert core.validate_plan_name(value) == expected


@pytest.mark.parametrize("name", ["..", ".", "../outside", "x/y", "a\\b", "unsafe whitespace"])
def test_untrusted_plan_basename_cannot_escape_workspace(name):
    with pytest.raises(ValueError, match="invalid plan name"):
        core.validate_plan_name(name)


def test_named_plan_containment_is_checked_again_after_resolving_realpath(monkeypatch, tmp_path):
    original = core.os.path.commonpath

    def outside(_paths):
        return str(tmp_path.parent)

    monkeypatch.setattr(core.os.path, "commonpath", outside)
    with pytest.raises(ValueError, match="plan path escapes"):
        core.plan_path(str(tmp_path), "named")
    monkeypatch.setattr(core.os.path, "commonpath", original)


def test_missing_and_invalid_named_plan_are_real_explicit_errors(tmp_path):
    with pytest.raises(SystemExit, match="plan yok"):
        core.load_plan(str(tmp_path))
    with pytest.raises(SystemExit, match="invalid plan name"):
        core.load_plan(str(tmp_path), "../unsafe")


def test_oversized_plan_never_allocates_or_parses_large_untrusted_json(tmp_path):
    plan = tmp_path / ".plan-auditor" / "plan.json"
    plan.parent.mkdir()
    with plan.open("wb") as f:
        f.truncate(core.MAX_PLAN_BYTES + 1)
    with pytest.raises(SystemExit, match="plan cok buyuk"):
        core.load_plan(str(tmp_path))


def test_real_valid_named_plan_is_loaded_without_substituting_default(tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    (folder / "experiment.json").write_text('{"steps":[{"id":1}]}', encoding="utf-8")
    assert core.load_plan(str(tmp_path), "experiment") == {"steps": [{"id": 1}]}


def test_workspace_fingerprint_binds_symlink_target_text_without_following_it(tmp_path):
    link = tmp_path / "observed-link"
    link.symlink_to("../external-name-1")
    one = core.workspace_fingerprint(str(tmp_path))
    link.unlink()
    link.symlink_to("../external-name-2")
    two = core.workspace_fingerprint(str(tmp_path))
    assert one != two


def test_workspace_fingerprint_binds_unreadable_metadata_as_distinct_failure(monkeypatch, tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("real byte content")
    normal = core.workspace_fingerprint(str(tmp_path))
    original = core.os.lstat

    def deny(src, *a, **kw):
        if str(src) == str(path):
            raise OSError("simulated unreadable inode")
        return original(src, *a, **kw)

    monkeypatch.setattr(core.os, "lstat", deny)
    unavailable = core.workspace_fingerprint(str(tmp_path))
    assert normal != unavailable
    assert unavailable == core.workspace_fingerprint(str(tmp_path))


def test_unknown_filesystem_object_has_explicit_other_fingerprint_not_file_content(
    monkeypatch, tmp_path
):
    path = tmp_path / "unknown-entry"
    path.write_text("ignored file bytes after kernel reclassification")
    baseline = core.workspace_fingerprint(str(tmp_path))
    original = core.os.lstat

    def reclassify(src, *a, **kw):
        if str(src) == str(path):
            return SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)
        return original(src, *a, **kw)

    monkeypatch.setattr(core.os, "lstat", reclassify)
    other = core.workspace_fingerprint(str(tmp_path))
    assert other != baseline


def test_missing_archive_directory_cannot_produce_a_nonzero_rotation_checkpoint(tmp_path):
    assert core._next_rotation_sequence(str(tmp_path)) == 1


def test_rotation_seq_advances_by_maximum_recorded_sequence_not_filename_count(tmp_path):
    archive = tmp_path / ".plan-auditor" / "archive"
    archive.mkdir(parents=True)
    (archive / "evidence-seq00000003-old.jsonl").write_text("{}")
    (archive / "evidence-seq00000012-new.jsonl").write_text("{}")
    (archive / "evidence-wrong-name.jsonl").write_text("{}")
    assert core._next_rotation_sequence(str(tmp_path)) == 13


def test_nonexistent_log_and_failed_read_are_not_counted_as_verified_evidence(
    monkeypatch, tmp_path
):
    path = tmp_path / "events.jsonl"
    assert core._record_count(str(path)) == 0
    path.write_text("{}\n{}\n")
    assert core._record_count(str(path)) == 2
    orig = builtins.open

    def denied(p, *a, **kw):
        if str(p) == str(path):
            raise OSError("deliberately inaccessible log")
        return orig(p, *a, **kw)

    monkeypatch.setattr(builtins, "open", denied)
    assert core._record_count(str(path)) == 0


def test_archive_tail_uses_explicit_authenticated_checkpoint_if_present(monkeypatch, tmp_path):
    monkeypatch.setattr(
        core, "_load_evidence_head", lambda _: {"archive_tail": "recorded-chain-tail"}
    )
    assert core._current_archive_tail(str(tmp_path)) == "recorded-chain-tail"


def test_archive_tail_does_not_coerce_invalid_checkpoint_into_hash(monkeypatch, tmp_path):
    monkeypatch.setattr(core, "_load_evidence_head", lambda _: {"archive_tail": 17})
    assert core._current_archive_tail(str(tmp_path)) is None


def test_archive_tail_reads_actual_latest_archive_only_when_checkpoint_unavailable(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(core, "_load_evidence_head", lambda _: None)
    monkeypatch.setattr(core, "_latest_archive_tail", lambda _: "archived-sha")
    assert core._current_archive_tail(str(tmp_path)) == "archived-sha"


@pytest.mark.parametrize(
    ("condition", "value"),
    [
        ("notfound", False),
        ("permission", True),
        ("windows_notfound", False),
    ],
)
def test_pid_liveness_uses_real_process_probe_error_semantics(monkeypatch, condition, value):
    def simulate(_pid, _signal):
        if condition == "notfound":
            raise ProcessLookupError("process gone")
        failure = PermissionError("permission denied")
        if condition == "windows_notfound":
            failure.winerror = 87
        raise failure

    monkeypatch.setattr(core.os, "kill", simulate)
    assert core._pid_is_alive(12345) is value


def test_current_pid_is_live_without_spawning_a_child_process():
    assert core._pid_is_alive(os.getpid()) is True


@pytest.mark.parametrize(
    "contents",
    [
        "not-json",
        "[]",
        '{"host":"different-machine","pid":123}',
    ],
)
def test_unverifiable_lock_holder_is_not_reclaimed_as_dead(tmp_path, contents):
    lock = tmp_path / "lock"
    lock.write_text(contents)
    assert core._lock_holder_dead(str(lock)) is False


def test_lock_may_be_reclaimed_only_for_same_host_and_provably_dead_pid(monkeypatch, tmp_path):
    lock = tmp_path / "lock"
    lock.write_text(json.dumps({"host": socket.gethostname(), "pid": 456}))
    monkeypatch.setattr(core, "_pid_is_alive", lambda _: False)
    assert core._lock_holder_dead(str(lock)) is True
    monkeypatch.setattr(core, "_pid_is_alive", lambda _: True)
    assert core._lock_holder_dead(str(lock)) is False


@pytest.mark.parametrize(
    "spec",
    [
        {"argv": []},
        {"argv": ["python", 2]},
        {"cmd": ""},
        {"shell": True, "argv": ["python"]},
    ],
)
def test_runtime_shell_and_nonargv_descriptions_are_refused_before_execution(spec):
    with pytest.raises(ValueError):
        core._command_spec(spec)


def test_real_subprocess_execution_is_bounded_without_shell_or_secret_inheritance(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY", "must-not-leak-to-child")
    program = "import os; print('secret='+str(os.getenv('PLAN_AUDITOR_HMAC_KEY')))"
    exit_code, status, output, overflow = core._bounded_command(
        [sys.executable, "-c", program],
        str(tmp_path),
        timeout=5,
        max_output=2048,
    )
    assert exit_code == 0
    assert status == "ok"
    assert "secret=None" in output
    assert overflow is False
