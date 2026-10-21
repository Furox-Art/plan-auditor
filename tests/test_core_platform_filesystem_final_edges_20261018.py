"""Low-level path, evidence and CLI entrypoint tests without reducing the coverage denominator."""

from __future__ import annotations

import builtins
import json
import os
import runpy
import sys
from types import SimpleNamespace

import pytest

from scripts import audit_check as ac
from scripts.integrity import KeyMaterial


@pytest.mark.skipif(os.name == "nt", reason="os.mkfifo is unavailable on Windows")
def test_workspace_fingerprint_distinguishes_nonregular_file_from_plain_file(tmp_path):
    fifo = tmp_path / "named-pipe"
    os.mkfifo(fifo)
    actual = ac.workspace_fingerprint(str(tmp_path))
    fifo.unlink()
    (tmp_path / "named-pipe").write_bytes(b"")
    assert ac.workspace_fingerprint(str(tmp_path)) != actual


def test_workspace_fingerprint_cannot_treat_lstat_error_as_normal_file(monkeypatch, tmp_path):
    target = tmp_path / "payload.txt"
    target.write_text("content")
    original = ac.os.lstat

    def unreadable(path):
        if os.fspath(path) == str(target):
            raise PermissionError("injected unreadability")
        return original(path)

    monkeypatch.setattr(ac.os, "lstat", unreadable)
    bad = ac.workspace_fingerprint(str(tmp_path))
    monkeypatch.setattr(ac.os, "lstat", original)
    good = ac.workspace_fingerprint(str(tmp_path))
    assert bad != good


def test_named_plan_path_escapes_are_refused_by_common_root_guard(monkeypatch, tmp_path):
    monkeypatch.setattr(ac.os.path, "commonpath", lambda paths: "/elsewhere")
    with pytest.raises(ValueError, match="escapes"):
        ac.plan_path(str(tmp_path), "normal")


def test_uncreated_plan_folder_and_empty_plan_folder_have_no_active_plans(tmp_path):
    assert ac.all_plan_paths(str(tmp_path)) == []
    (tmp_path / ".plan-auditor" / "plans").mkdir(parents=True)
    assert ac.all_plan_paths(str(tmp_path)) == []


def test_windows_tokenizer_accepts_no_started_tokens():
    assert ac._windows_argv("   \t") == []
    assert ac._windows_argv("arg    ") == ["arg"]


def test_empty_windows_parsed_command_must_be_refused(monkeypatch):
    class Facade:
        name = "nt"

        def __getattr__(self, prop):
            return getattr(os, prop)

    monkeypatch.setattr(ac, "os", Facade())
    with pytest.raises(ValueError, match="empty command"):
        ac._legacy_split(" \t  ")


def test_missing_regex_target_is_explicit_failure(tmp_path):
    passed, detail, _ = ac.run_check(
        {"type": "regex", "path": "absent.txt", "pattern": "a"}, str(tmp_path)
    )
    assert passed is False
    assert "MISSING" in detail


def test_evidence_last_hash_unreadable_directory_returns_genesis(tmp_path):
    assert ac._last_record_hash(str(tmp_path)) == "GENESIS"


def test_archive_record_without_predecessor_uses_genesis(tmp_path):
    archive = tmp_path / ".plan-auditor" / "archive"
    archive.mkdir(parents=True)
    path = archive / "evidence-seq00000001-20261018T120000000000.jsonl"
    ac._write_evidence_record(str(path), {"mode": "run", "step": 1})
    record = json.loads(path.read_text().splitlines()[0])
    assert record["prev"] == "GENESIS"


def test_failed_attempt_history_unreadable_file_cannot_invent_failures(monkeypatch, tmp_path):
    target = tmp_path / "f.jsonl"
    target.write_text("ignored")
    original = builtins.open
    monkeypatch.setattr(ac, "_all_evidence_paths", lambda root: [str(target)])

    def deny(path, *args, **kwargs):
        if os.fspath(path) == str(target):
            raise PermissionError("access denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny)
    assert ac.failed_attempt_counts(str(tmp_path)) == {}


def test_lock_release_failure_does_not_invent_successful_unlink(monkeypatch, tmp_path):
    original = ac.os.unlink

    def refuse(path, *args, **kwargs):
        if os.fspath(path).endswith("evidence.write.lock"):
            raise OSError("cannot remove lock")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(ac.os, "unlink", refuse)
    with ac._evidence_lock(str(tmp_path)):
        assert (tmp_path / ".plan-auditor" / "evidence.write.lock").is_file()
    assert (tmp_path / ".plan-auditor" / "evidence.write.lock").is_file()


def test_authenticated_rotation_rewrites_head_checkpoint(monkeypatch, tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "evidence.jsonl").write_text("not a trusted record but rotation path only")
    key = KeyMaterial(b"m" * 32, "test", "key")
    observed = []
    monkeypatch.setattr(ac, "_runtime_limits", lambda root: (3, 1))
    monkeypatch.setattr(ac, "runtime_key", lambda root: key)
    monkeypatch.setattr(ac, "_write_evidence_record", lambda *args: None)
    monkeypatch.setattr(
        ac, "_write_evidence_head", lambda root, supplied: observed.append(supplied)
    )
    ac.maybe_rotate(str(tmp_path))
    assert observed == [key]
    assert (pg / "archive").is_dir()


def test_main_handles_streams_without_reconfigure(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "sys", SimpleNamespace(stdout=object(), stderr=object()))
    monkeypatch.setattr(sys, "argv", ["audit-check", "validate", str(tmp_path)])
    monkeypatch.setattr(ac, "cmd_validate", lambda args: 0)
    assert ac.main() == 0


def test_main_handles_streams_that_reject_reconfigure(monkeypatch, tmp_path):
    class LockedStream:
        def reconfigure(self, **kwargs):
            raise ValueError("cannot reconfigure")

    monkeypatch.setattr(ac, "sys", SimpleNamespace(stdout=LockedStream(), stderr=LockedStream()))
    monkeypatch.setattr(sys, "argv", ["audit-check", "validate", str(tmp_path)])
    monkeypatch.setattr(ac, "cmd_validate", lambda args: 0)
    assert ac.main() == 0


def test_direct_python_module_guard_invokes_real_argument_parser(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["audit_check", "--help"])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_module("scripts.audit_check", run_name="__main__")
    assert stopped.value.code == 0
    assert "Plan Auditor" in capsys.readouterr().out
