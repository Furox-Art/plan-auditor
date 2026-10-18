"""Previously uncovered real security, snapshot, process and parser decisions."""

from __future__ import annotations

import argparse
import builtins
import hashlib
import json
import os
import time
import zipfile

import pytest

from scripts import audit_check as ac
from supervisor import cli


class OSFacade:
    def __init__(self, name="posix"):
        self.name = name

    def __getattr__(self, attr):
        return getattr(os, attr)


def _snapshot(tmp_path, document, payloads=()):
    storage = tmp_path / ".plan-auditor" / "snapshots"
    storage.mkdir(parents=True, exist_ok=True)
    archive_path = storage / "replay.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(ac.SNAPSHOT_MANIFEST, json.dumps(document))
        for name, payload in payloads:
            archive.writestr(name, payload)
    return archive_path


def _file_entry(path, content):
    return {
        "path": path,
        "type": "file",
        "mode": 0o644,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def test_valid_runtime_and_snapshot_fields_take_nonerror_branch():
    plan = {
        "task": "verify truthful command execution",
        "created": "2026-10-18T15:00:00Z",
        "snapshot": ["artifact.txt"],
        "requirements": ["verified behavior"],
        "steps": [
            {
                "id": 1,
                "title": "test",
                "verify": [
                    {
                        "type": "run",
                        "argv": ["python3", "--version"],
                        "timeout": 10,
                        "max_output_bytes": 1024,
                    }
                ],
            }
        ],
    }
    errors = ac.validate_plan(plan)
    assert not any(
        "timeout must" in error or "max_output_bytes must" in error or "snapshot:" in error
        for error in errors
    ), errors


def test_no_unreadable_last_record_can_serve_as_evidence_head(monkeypatch, tmp_path):
    path = tmp_path / "chain.jsonl"
    path.write_text("data", encoding="utf-8")
    actual = builtins.open

    def fail(filename, *args, **kwargs):
        if os.fspath(filename) == str(path):
            raise PermissionError("unreadable head")
        return actual(filename, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail)
    assert ac._last_record_hash(str(path)) == "GENESIS"


def test_pipe_without_stdout_is_safe_when_collecting_bounded_output(monkeypatch, tmp_path):
    class NoStdout:
        returncode = 0
        stdout = None

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(ac, "check_launch_options", lambda root: {})
    monkeypatch.setattr(ac.subprocess, "Popen", lambda *args, **kwargs: NoStdout())
    assert ac._bounded_command(["unused"], str(tmp_path), 1, 1024) == (0, "ok", "", False)


def test_group_kill_does_not_kill_process_again_when_it_has_already_exited(monkeypatch):
    class Finishing:
        pid = 424242

        def __init__(self):
            self.calls = 0

        def poll(self):
            self.calls += 1
            return None if self.calls == 1 else 0

        def kill(self):
            raise AssertionError("process was already gone")

    monkeypatch.setattr(ac.os, "killpg", lambda pid, signal: None)
    ac._kill_process_tree(Finishing())


def test_evidence_lock_stat_failure_times_out_without_stealing_unknown_lock(monkeypatch, tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    lock = pg / "evidence.write.lock"
    lock.write_text("unknown owner", encoding="utf-8")

    class StatErrorFacade(OSFacade):
        def stat(self, path, *args, **kwargs):
            if os.fspath(path) == str(lock):
                raise PermissionError("owner cannot be inspected")
            return os.stat(path, *args, **kwargs)

    monkeypatch.setattr(ac, "os", StatErrorFacade())
    monkeypatch.setattr(ac, "EVIDENCE_LOCK_TIMEOUT", 0)
    with pytest.raises(RuntimeError, match="lock timeout"):
        with ac._evidence_lock(str(tmp_path)):
            pass
    assert lock.exists()


def test_evidence_lock_retries_after_failed_stale_lock_unlink(monkeypatch, tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    lock = pg / "evidence.write.lock"
    lock.write_text("proven dead", encoding="utf-8")
    old = time.time() - ac.EVIDENCE_LOCK_STALE - 120
    os.utime(lock, (old, old))
    monkeypatch.setattr(ac, "_lock_holder_dead", lambda _: True)
    original_unlink = os.unlink
    attempted = []

    def fail_once(path, *args, **kwargs):
        if os.fspath(path) == str(lock):
            attempted.append(path)
            if len(attempted) == 1:
                raise PermissionError("simulated racing unlink")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(ac.os, "unlink", fail_once)
    with ac._evidence_lock(str(tmp_path)):
        assert lock.exists()
    assert len(attempted) >= 2
    assert not lock.exists()


def test_walk_snapshot_root_skips_symlinked_directory_as_directory(tmp_path):
    (tmp_path / "real-folder").mkdir()
    (tmp_path / "real-folder" / "data.txt").write_text("safe", encoding="utf-8")
    (tmp_path / "link-folder").symlink_to("real-folder", target_is_directory=True)
    records = ac._walk_snapshot_tree(str(tmp_path))
    assert records["real-folder"]["type"] == "dir"
    assert records["link-folder"]["type"] == "symlink"
    assert "link-folder/data.txt" not in records


def test_duplicate_explicit_snapshot_root_is_recorded_only_once(monkeypatch, tmp_path):
    data = tmp_path / "data.txt"
    data.write_text("content", encoding="utf-8")
    monkeypatch.setattr(ac, "append_evidence", lambda *args: None)
    archive_path = ac.make_snapshot(str(tmp_path), {"snapshot": ["data.txt", "data.txt"]})
    with zipfile.ZipFile(archive_path) as archive:
        manifest = json.loads(archive.read(ac.SNAPSHOT_MANIFEST))
    assert manifest["roots"] == ["data.txt"]


def test_windows_v3_restoration_preserves_manifest_without_unix_chmod(monkeypatch, tmp_path):
    content = b"ok"
    manifest = {
        "format_version": 3,
        "scope": "explicit",
        "roots": ["dir"],
        "absent": [],
        "entries": [
            {"path": "dir", "type": "dir", "mode": 0o755},
            _file_entry("dir/data.txt", content),
        ],
    }
    archive_path = _snapshot(tmp_path, manifest, [("dir/data.txt", content)])
    monkeypatch.setattr(ac, "os", OSFacade("nt"))
    monkeypatch.setattr(ac, "append_evidence", lambda *args: None)
    ac.restore_snapshot(str(tmp_path), str(archive_path))
    assert (tmp_path / "dir" / "data.txt").read_bytes() == content


def test_v3_empty_absence_contract_completes_without_fabricating_files(monkeypatch, tmp_path):
    archive_path = _snapshot(
        tmp_path,
        {
            "format_version": 3,
            "scope": "explicit",
            "roots": [],
            "absent": ["missing.txt"],
            "entries": [],
        },
    )
    monkeypatch.setattr(ac, "append_evidence", lambda *args: None)
    ac.restore_snapshot(str(tmp_path), str(archive_path))
    assert not (tmp_path / "missing.txt").exists()


def test_v2_full_workspace_replay_keeps_existing_allowlisted_file_and_prunes_extra(
    monkeypatch, tmp_path
):
    content = b"trusted"
    (tmp_path / "keep.txt").write_bytes(b"changed")
    (tmp_path / "drop.txt").write_bytes(b"temporary")
    archive_path = _snapshot(
        tmp_path,
        {
            "format_version": 2,
            "scope": "full-workspace",
            "files": [_file_entry("keep.txt", content)],
        },
        [("keep.txt", content)],
    )
    monkeypatch.setattr(ac, "append_evidence", lambda *args: None)
    ac.restore_snapshot(str(tmp_path), str(archive_path))
    assert (tmp_path / "keep.txt").read_bytes() == content
    assert not (tmp_path / "drop.txt").exists()


def test_task_inspect_searches_past_a_nonmatching_plan(tmp_path, capsys):
    plans = tmp_path / ".plan-auditor" / "plans"
    plans.mkdir(parents=True)
    (plans / "first.json").write_text(json.dumps({"id": "first", "steps": []}), encoding="utf-8")
    (plans / "second.json").write_text(json.dumps({"id": "second", "steps": []}), encoding="utf-8")
    result = cli.cmd_task_inspect(argparse.Namespace(dir=str(tmp_path), task_id="second"))
    assert result == 0
    assert json.loads(capsys.readouterr().out)["id"] == "second"
