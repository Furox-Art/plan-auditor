"""Legacy v2 snapshot and v3 archive integrity tests with real ZIP payloads."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile

import pytest

from scripts import audit_check as ac


def _archive(tmp_path, manifest, payloads=(), duplicate=None):
    archive = tmp_path / "repro-archive.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr(ac.SNAPSHOT_MANIFEST, json.dumps(manifest))
        for name, payload in payloads:
            stream.writestr(name, payload)
        if duplicate:
            stream.writestr(duplicate[0], duplicate[1])
    return archive


def _file(name, content, **options):
    return {"path": name, "type": "file", "sha256": hashlib.sha256(content).hexdigest(), **options}


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits and symlink restore semantics")
def test_v2_real_archive_restores_content_and_sha(tmp_path):
    original = b"exact-data\n"
    (tmp_path / "record.bin").write_bytes(b"modified")
    archive = _archive(
        tmp_path,
        {"format_version": 2, "files": [_file("record.bin", original, mode=0o600)]},
        [("record.bin", original)],
    )
    ac.restore_snapshot(str(tmp_path), str(archive))
    assert (tmp_path / "record.bin").read_bytes() == original
    assert stat.S_IMODE((tmp_path / "record.bin").stat().st_mode) == 0o600
    assert ac.verify_chain(str(tmp_path))[0] is True


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits and symlink restore semantics")
def test_v2_real_archive_full_workspace_prunes_untracked_files(tmp_path):
    (tmp_path / "untracked.txt").write_text("must be removed", encoding="utf-8")
    content = b"trusted"
    archive = _archive(
        tmp_path,
        {"format_version": 2, "scope": "full-workspace", "files": [_file("ok.txt", content)]},
        [("ok.txt", content)],
    )
    ac.restore_snapshot(str(tmp_path), str(archive))
    assert not (tmp_path / "untracked.txt").exists()
    assert (tmp_path / "ok.txt").read_bytes() == content


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits and symlink restore semantics")
def test_v2_symlink_restore_is_bounded_to_workspace(tmp_path):
    (tmp_path / "destination.txt").write_text("ok", encoding="utf-8")
    archive = _archive(
        tmp_path,
        {
            "format_version": 2,
            "files": [{"path": "pointer", "type": "symlink", "target": "destination.txt"}],
        },
    )
    ac.restore_snapshot(str(tmp_path), str(archive))
    assert (tmp_path / "pointer").is_symlink()
    assert (tmp_path / "pointer").resolve() == (tmp_path / "destination.txt")


@pytest.mark.parametrize("value", [None, False, {}, "files", 12])
def test_v2_rejects_non_list_manifest_files(tmp_path, value):
    archive = _archive(tmp_path, {"format_version": 2, "files": value})
    with pytest.raises(ValueError, match="manifest files list is invalid"):
        ac.restore_snapshot(str(tmp_path), str(archive))


@pytest.mark.parametrize("entry", [None, "not an object", {}, {"path": 1}])
def test_v2_rejects_nonobject_or_unaddressed_entries(tmp_path, entry):
    archive = _archive(tmp_path, {"format_version": 2, "files": [entry]})
    with pytest.raises(ValueError):
        ac.restore_snapshot(str(tmp_path), str(archive))


def test_v2_rejects_missing_archive_payload(tmp_path):
    archive = _archive(tmp_path, {"format_version": 2, "files": [_file("absent.txt", b"ok")]})
    with pytest.raises(ValueError, match="archive file missing"):
        ac.restore_snapshot(str(tmp_path), str(archive))


def test_v2_rejects_mismatched_sha256(tmp_path):
    archive = _archive(
        tmp_path,
        {"format_version": 2, "files": [_file("payload.txt", b"expected")]},
        [("payload.txt", b"tampered")],
    )
    with pytest.raises(ValueError, match="snapshot hash mismatch"):
        ac.restore_snapshot(str(tmp_path), str(archive))


def test_v2_rejects_symlinks_pointing_outside_workspace(tmp_path):
    archive = _archive(
        tmp_path,
        {
            "format_version": 2,
            "files": [{"path": "link", "type": "symlink", "target": "../../outside"}],
        },
    )
    with pytest.raises(ValueError, match="escapes the workspace"):
        ac.restore_snapshot(str(tmp_path), str(archive))
    assert not (tmp_path / "link").exists()


@pytest.mark.parametrize(
    "manifest,reason",
    [
        ({"format_version": 3, "scope": "bad", "entries": []}, "manifest is invalid"),
        ({"format_version": 3, "scope": "explicit", "entries": None}, "manifest is invalid"),
        (
            {"format_version": 3, "scope": "explicit", "entries": [], "roots": 9},
            "roots/absent list",
        ),
        (
            {"format_version": 3, "scope": "full-workspace", "entries": [None]},
            "entry must be an object",
        ),
        (
            {
                "format_version": 3,
                "scope": "full-workspace",
                "entries": [{"path": "a", "type": "other", "mode": 0}],
            },
            "type is invalid",
        ),
        (
            {
                "format_version": 3,
                "scope": "full-workspace",
                "entries": [{"path": "a", "type": "file", "mode": True}],
            },
            "mode is invalid",
        ),
        (
            {
                "format_version": 3,
                "scope": "full-workspace",
                "entries": [{"path": "a", "type": "file", "mode": 0}],
            },
            "file hash",
        ),
        (
            {
                "format_version": 3,
                "scope": "full-workspace",
                "entries": [
                    {"path": "a", "type": "dir", "mode": 493},
                    {"path": "a", "type": "dir", "mode": 493},
                ],
            },
            "duplicate path",
        ),
        (
            {
                "format_version": 3,
                "scope": "full-workspace",
                "entries": [
                    {"path": "a", "type": "file", "mode": 420, "sha256": "x"},
                    {"path": "a/b", "type": "file", "mode": 420, "sha256": "x"},
                ],
            },
            "non-directory parent",
        ),
    ],
)
def test_v3_manifest_validation_fails_before_replaying_untrusted_payload(
    tmp_path, manifest, reason
):
    archive = _archive(tmp_path, manifest)
    with pytest.raises(ValueError, match=reason):
        ac.restore_snapshot(str(tmp_path), str(archive))


def test_v3_archive_rejects_duplicate_members(tmp_path):
    manifest = {"format_version": 3, "scope": "explicit", "entries": [], "roots": [], "absent": []}
    with pytest.warns(UserWarning, match="Duplicate name"):
        archive = _archive(
            tmp_path, manifest, duplicate=(ac.SNAPSHOT_MANIFEST, json.dumps(manifest))
        )
    with pytest.raises(ValueError, match="duplicate member"):
        ac.restore_snapshot(str(tmp_path), str(archive))


def test_v3_archive_rejects_off_manifest_payload(tmp_path):
    manifest = {"format_version": 3, "scope": "explicit", "entries": [], "roots": [], "absent": []}
    archive = _archive(tmp_path, manifest, [("unexpected.txt", b"malicious")])
    with pytest.raises(ValueError, match="off-manifest"):
        ac.restore_snapshot(str(tmp_path), str(archive))


def test_legacy_archive_without_manifest_cannot_be_restored(tmp_path):
    archive = tmp_path / "no-manifest.zip"
    with zipfile.ZipFile(archive, "w") as stream:
        stream.writestr("data.txt", "legacy")
    with pytest.raises(ValueError, match="no manifest"):
        ac.restore_snapshot(str(tmp_path), str(archive))


@pytest.mark.parametrize(
    "manifest,reason",
    [(None, "must be an object"), ({"format_version": 7}, "unsupported snapshot")],
)
def test_invalid_or_unknown_archive_version_refuses_mutation(tmp_path, manifest, reason):
    archive = _archive(tmp_path, manifest)
    with pytest.raises(ValueError, match=reason):
        ac.restore_snapshot(str(tmp_path), str(archive))
