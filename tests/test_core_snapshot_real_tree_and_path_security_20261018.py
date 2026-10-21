"""The snapshot manifest is explicit, bounded, and never follows external links."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from scripts import audit_check as ac


@pytest.mark.parametrize(
    "source",
    [
        None,
        4,
        "",
        "  ",
        "/etc/passwd",
        "../escape",
        "./file",
        "dir/../escape",
        "dir//file",
        ".git/config",
        ".plan-auditor/seal.json",
        "folder/",
        r"..\\escape",
    ],
)
def test_snapshot_name_rejects_absolute_ambiguous_and_auditor_metadata(source):
    with pytest.raises(ValueError, match="snapshot path|auditor/git/cache"):
        ac._normalize_snapshot_rel(source)


def test_safe_mixed_separator_is_canonical_without_losing_true_nested_name():
    assert ac._normalize_snapshot_rel(r"models\results.csv") == "models/results.csv"


def test_nested_snapshot_path_is_bounded_inside_real_workspace(tmp_path):
    folder = tmp_path / "models"
    folder.mkdir()
    expected = folder / "results.csv"
    assert ac._snapshot_lexical_path(str(tmp_path), "models/results.csv") == str(expected)


def test_symlinked_parent_cannot_redirect_snapshot_outside_workspace(tmp_path):
    out = tmp_path.parent / (tmp_path.name + "-external")
    (tmp_path / "outside").symlink_to(out, target_is_directory=True)
    with pytest.raises(ValueError, match="snapshot parent symlink escapes"):
        ac._snapshot_lexical_path(str(tmp_path), "outside/stolen.txt")


@pytest.mark.parametrize("target", ["", "/etc/passwd", "../../escape"])
def test_snapshot_symlink_cannot_resolve_external_target(tmp_path, target):
    with pytest.raises(ValueError, match="symlink target|external-target"):
        ac._safe_snapshot_symlink_target(str(tmp_path), "link", target)


def test_relative_symlink_inside_workspace_is_supported_as_symlink_not_file_content(tmp_path):
    original = tmp_path / "original.txt"
    original.write_text("recorded")
    link = tmp_path / "link.txt"
    link.symlink_to("original.txt")
    result = ac._snapshot_manifest_entry(str(tmp_path), "link.txt")
    assert result["type"] == "symlink"
    assert result["target"] == "original.txt"
    assert "sha256" not in result


def test_regular_file_manifest_hashes_exact_file_bytes(tmp_path):
    raw = b"observed\x00exact\xff"
    (tmp_path / "data.bin").write_bytes(raw)
    result = ac._snapshot_manifest_entry(str(tmp_path), "data.bin")
    assert result["type"] == "file"
    assert result["sha256"] == hashlib.sha256(raw).hexdigest()
    assert result["path"] == "data.bin"


def test_directory_manifest_retains_type_and_actual_mode(tmp_path):
    (tmp_path / "data").mkdir()
    result = ac._snapshot_manifest_entry(str(tmp_path), "data")
    assert result["type"] == "dir"
    assert result["mode"] == 0o755 or result["mode"] & 0o700 == 0o700


@pytest.mark.skipif(os.name == "nt", reason="os.mkfifo is unavailable on Windows")
def test_snapshot_rejects_fifo_instead_of_deadlocking_on_special_file(tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.fail("platform must use a supported FIFO test or provide equivalent coverage")
    path = tmp_path / "unsupported.fifo"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="only regular"):
        ac._snapshot_manifest_entry(str(tmp_path), "unsupported.fifo")


def test_real_snapshot_walk_ignores_internal_auditor_state_and_does_not_follow_symlinks(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "secret").write_text("should not capture")
    (tmp_path / ".plan-auditor").mkdir()
    (tmp_path / ".plan-auditor" / "private").write_text("should not capture")
    root = tmp_path / "research"
    root.mkdir()
    (root / "data.csv").write_text("x,y\n1,2\n")
    (root / "empty").mkdir()
    (root / "shortcut").symlink_to("data.csv")
    out = ac._walk_snapshot_tree(str(tmp_path))
    assert {"research", "research/data.csv", "research/empty", "research/shortcut"} <= set(out)
    assert not any(name.startswith(".git/") or name.startswith(".plan-auditor") for name in out)
    assert out["research/shortcut"]["type"] == "symlink"
    assert out["research/data.csv"]["type"] == "file"


def test_scoped_tree_returns_single_file_without_unrelated_workspace_content(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    out = ac._walk_snapshot_tree(str(tmp_path), "a.txt")
    assert list(out) == ["a.txt"]


def test_scoped_directory_contains_only_descendant_evidence(tmp_path):
    selected = tmp_path / "selected"
    selected.mkdir()
    (selected / "included").write_text("inside")
    (tmp_path / "excluded").write_text("outside")
    out = ac._walk_snapshot_tree(str(tmp_path), "selected")
    assert set(out) == {"selected", "selected/included"}


def test_sequence_increments_only_properly_named_snapshot_archives(tmp_path):
    root = Path(ac.snapshots_dir(str(tmp_path)))
    root.mkdir(parents=True)
    for filename in (
        "a-seq00000003.zip",
        "b-seq00000011.zip",
        "not-snapshot.zip",
        "b-seq99999999.txt",
        "no-seqINVALID.zip",
    ):
        (root / filename).touch()
    assert ac._next_snapshot_sequence(str(tmp_path)) == 12


def test_nonexistent_archive_directory_starts_at_sequence_one(tmp_path):
    assert ac._next_snapshot_sequence(str(tmp_path)) == 1
