"""Real v3 archive verification must refuse payload/hash/symlink drift after replay."""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import zipfile

import pytest

from scripts import audit_check as ac


def _file_record(name, content):
    return {
        "path": name,
        "type": "file",
        "mode": 0o644,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _make_archive(tmp_path, entries, payloads=(), *, absent=(), scope="explicit", roots=()):
    path = tmp_path / "trusted-archive.zip"
    manifest = {
        "format_version": 3,
        "entries": entries,
        "roots": list(roots),
        "absent": list(absent),
        "scope": scope,
    }
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr(ac.SNAPSHOT_MANIFEST, json.dumps(manifest))
        for name, value in payloads:
            handle.writestr(name, value)
    return path


def _restore_without_evidence(monkeypatch, tmp_path, archive):
    monkeypatch.setattr(ac, "append_evidence", lambda *args: None)
    ac.restore_snapshot(str(tmp_path), str(archive))


def test_v3_real_archive_file_hash_mismatch_is_refused(tmp_path, monkeypatch):
    record = _file_record("data.txt", b"authentic")
    archive = _make_archive(tmp_path, [record], [("data.txt", b"tampered")])
    with pytest.raises(ValueError, match="snapshot hash mismatch"):
        _restore_without_evidence(monkeypatch, tmp_path, archive)


def test_v3_real_archive_rejects_wrong_restored_file_type(tmp_path, monkeypatch):
    content = b"valid"
    archive = _make_archive(tmp_path, [_file_record("data.txt", content)], [("data.txt", content)])
    monkeypatch.setattr(ac, "_entry_kind", lambda path: "dir")
    with pytest.raises(ValueError, match="restore type verification failed"):
        _restore_without_evidence(monkeypatch, tmp_path, archive)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink restore semantics")
def test_v3_real_archive_rejects_symlink_target_mutation(tmp_path, monkeypatch):
    (tmp_path / "target.txt").write_text("safe", encoding="utf-8")
    archive = _make_archive(
        tmp_path, [{"path": "link", "type": "symlink", "mode": 0o777, "target": "target.txt"}]
    )
    monkeypatch.setattr(ac.os, "readlink", lambda path: "changed.txt")
    with pytest.raises(ValueError, match="snapshot symlink verification failed"):
        _restore_without_evidence(monkeypatch, tmp_path, archive)


def test_v3_real_archive_rejects_postrestore_sha_failure(tmp_path, monkeypatch):
    content = b"original"
    archive = _make_archive(tmp_path, [_file_record("data.txt", content)], [("data.txt", content)])
    original_open = builtins.open

    def manipulated(path, mode="r", *args, **kwargs):
        if os.fspath(path) == str(tmp_path / "data.txt") and mode == "rb":
            return io.BytesIO(b"modified-after-replay")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", manipulated)
    with pytest.raises(ValueError, match="restore hash verification failed"):
        _restore_without_evidence(monkeypatch, tmp_path, archive)


def test_v3_archive_must_observe_paths_intended_to_be_absent(tmp_path, monkeypatch):
    unwanted = tmp_path / "deleted.txt"
    unwanted.write_text("not erased", encoding="utf-8")
    archive = _make_archive(tmp_path, [], absent=["deleted.txt"])
    monkeypatch.setattr(ac, "_remove_snapshot_path", lambda root, rel: None)
    with pytest.raises(ValueError, match="absent path could not be restored"):
        _restore_without_evidence(monkeypatch, tmp_path, archive)


def test_missing_path_removal_is_noop_and_does_not_create_content(tmp_path):
    ac._remove_snapshot_path(str(tmp_path), "absent.txt")
    assert not (tmp_path / "absent.txt").exists()


def test_snapshot_path_commonroot_guard_fails_with_drive_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(ac.os.path, "commonpath", lambda items: "other-volume")
    with pytest.raises(ValueError, match="snapshot path escapes"):
        ac._snapshot_lexical_path(str(tmp_path), "safe.txt")


def test_snapshot_can_replay_directory_and_file_in_v3_manifest(tmp_path, monkeypatch):
    content = b"safe"
    entries = [
        {"path": "folder", "type": "dir", "mode": 0o755},
        _file_record("folder/data.txt", content),
    ]
    archive = _make_archive(tmp_path, entries, [("folder/data.txt", content)])
    _restore_without_evidence(monkeypatch, tmp_path, archive)
    assert (tmp_path / "folder" / "data.txt").read_bytes() == content
