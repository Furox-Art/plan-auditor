"""V3 snapshot ZIP is authenticated by manifest contents, not archive member names."""

from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

from scripts import audit_check as core


def archive(root, manifest, files=None, extra=None):
    output = root.parent / (root.name + "-snapshot-fixture.zip")
    with zipfile.ZipFile(output, "w") as z:
        z.writestr(core.SNAPSHOT_MANIFEST, json.dumps(manifest))
        for name, data in (files or {}).items():
            z.writestr(name, data)
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return output


def manifest(*entries, scope="full-workspace", roots=None, absent=None):
    return {
        "format_version": 3,
        "scope": scope,
        "roots": roots or [],
        "absent": absent or [],
        "entries": list(entries),
    }


def declared(name="observed.txt", data=b"first", mode=0o644):
    return {
        "path": name,
        "type": "file",
        "mode": mode,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ({"scope": "not-snapshot"}, "snapshot v3 manifest is invalid"),
        ({"entries": []}, ""),  # valid empty schema, tested separately below
        ({"roots": "all"}, "roots/absent list is invalid"),
        ({"absent": "all"}, "roots/absent list is invalid"),
    ],
)
def test_snapshot_manifest_header_has_explicit_version_scope_and_array_contract(
    tmp_path, change, expected
):
    doc = manifest(declared())
    doc.update(change)
    with zipfile.ZipFile(archive(tmp_path, doc, files={"observed.txt": b"first"})) as z:
        if expected:
            with pytest.raises(ValueError, match=expected):
                core._restore_snapshot_v3(str(tmp_path), z, doc)
        else:
            with pytest.raises(ValueError, match="off-manifest"):
                core._restore_snapshot_v3(str(tmp_path), z, doc)


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        ({"path": "../escape", "type": "file", "mode": 0, "sha256": "0" * 64}, "snapshot path"),
        ({"path": "/tmp/external", "type": "file", "mode": 0, "sha256": "0" * 64}, "snapshot path"),
        ({"path": "observed.txt", "type": "unexpected", "mode": 0}, "type is invalid"),
        (
            {"path": "observed.txt", "type": "file", "mode": False, "sha256": "0" * 64},
            "mode is invalid",
        ),
        (
            {"path": "observed.txt", "type": "file", "mode": -1, "sha256": "0" * 64},
            "mode is invalid",
        ),
        ({"path": "observed.txt", "type": "file", "mode": 0}, "file hash eksik"),
        (
            {"path": "link", "type": "symlink", "mode": 0, "target": "../../escape"},
            "symlink target escapes",
        ),
        (
            {"path": "link", "type": "symlink", "mode": 0, "target": ""},
            "symlink target must not be empty",
        ),
    ],
)
def test_restore_refuses_unsafe_manifest_entries_before_mutating_real_files(tmp_path, bad, message):
    existing = tmp_path / "protected.txt"
    existing.write_text("must stay unchanged")
    m = manifest(bad)
    with zipfile.ZipFile(archive(tmp_path, m)) as z:
        with pytest.raises(ValueError, match=message):
            core._restore_snapshot_v3(str(tmp_path), z, m)
    assert existing.read_text() == "must stay unchanged"


def test_duplicate_manifest_paths_cannot_erase_one_another(tmp_path):
    entry = declared()
    m = manifest(entry, dict(entry))
    with zipfile.ZipFile(archive(tmp_path, m)) as z:
        with pytest.raises(ValueError, match="duplicate path"):
            core._restore_snapshot_v3(str(tmp_path), z, m)


def test_file_as_parent_of_another_file_is_rejected_without_writing(tmp_path):
    m = manifest(declared("file", b"one"), declared("file/child", b"two"))
    with zipfile.ZipFile(archive(tmp_path, m)) as z:
        with pytest.raises(ValueError, match="non-directory parent"):
            core._restore_snapshot_v3(str(tmp_path), z, m)


def test_extra_off_manifest_member_cannot_be_extracted_into_workspace(tmp_path):
    m = manifest(declared())
    destination = tmp_path / "protected.txt"
    destination.write_text("untouched")
    zpath = archive(
        tmp_path, m, {"observed.txt": b"first"}, extra={"../../protected.txt": b"attacker"}
    )
    with zipfile.ZipFile(zpath) as z:
        with pytest.raises(ValueError, match="off-manifest"):
            core._restore_snapshot_v3(str(tmp_path), z, m)
    assert destination.read_text() == "untouched"


def test_missing_file_payload_is_not_inferred_from_file_name(tmp_path):
    m = manifest(declared())
    with zipfile.ZipFile(archive(tmp_path, m)) as z:
        with pytest.raises(ValueError, match="off-manifest"):
            core._restore_snapshot_v3(str(tmp_path), z, m)


def test_duplicate_zip_member_names_cannot_be_resolved_by_insecure_first_match(tmp_path):
    out = tmp_path.parent / (tmp_path.name + "-duplicate-snapshot.zip")
    m = manifest(declared())
    with zipfile.ZipFile(out, "w") as z:
        z.writestr(core.SNAPSHOT_MANIFEST, json.dumps(m))
        z.writestr("observed.txt", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            z.writestr("observed.txt", b"forged")
    with zipfile.ZipFile(out) as z:
        with pytest.raises(ValueError, match="duplicate member"):
            core._restore_snapshot_v3(str(tmp_path), z, m)


def test_snapshot_payload_checksum_mismatch_does_not_report_restoration_as_success(tmp_path):
    m = manifest(declared(data=b"correct"))
    with zipfile.ZipFile(archive(tmp_path, m, {"observed.txt": b"tampered"})) as z:
        with pytest.raises(ValueError, match="snapshot hash mismatch"):
            core._restore_snapshot_v3(str(tmp_path), z, m)


def test_actual_v3_snapshot_restores_verified_bytes_and_drops_new_unrecorded_files(tmp_path):
    original = tmp_path / "recorded.txt"
    original.write_text("signed-original")
    m = manifest(declared("recorded.txt", b"signed-original"))
    output = archive(tmp_path, m, {"recorded.txt": b"signed-original"})
    original.write_text("changed")
    (tmp_path / "unrecorded.txt").write_text("not in snapshot")
    with zipfile.ZipFile(output) as z:
        restored = core._restore_snapshot_v3(str(tmp_path), z, m)
    assert restored == ["recorded.txt"]
    assert original.read_text() == "signed-original"
    assert not (tmp_path / "unrecorded.txt").exists()


def test_actual_explicit_v3_snapshot_does_not_modify_unrelated_files(tmp_path):
    root = tmp_path / "scoped"
    root.mkdir()
    (root / "recorded.txt").write_text("old")
    untouched = tmp_path / "unrelated.txt"
    untouched.write_text("do-not-delete")
    m = manifest(declared("scoped/recorded.txt", b"saved"), scope="explicit", roots=["scoped"])
    with zipfile.ZipFile(archive(tmp_path, m, {"scoped/recorded.txt": b"saved"})) as z:
        core._restore_snapshot_v3(str(tmp_path), z, m)
    assert (root / "recorded.txt").read_text() == "saved"
    assert untouched.read_text() == "do-not-delete"


def test_restoring_legacy_zip_without_manifest_is_explicitly_rejected(tmp_path):
    zpath = tmp_path / "legacy.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("untrusted.txt", "contents")
    with pytest.raises(ValueError, match="legacy snapshot has no manifest"):
        core.restore_snapshot(str(tmp_path), str(zpath))


def test_unknown_zip_snapshot_version_is_rejected(tmp_path):
    m = {"format_version": 999}
    with pytest.raises(ValueError, match="unsupported snapshot format"):
        core.restore_snapshot(str(tmp_path), str(archive(tmp_path, m)))
