"""Deterministic, unambiguous and atomic workspace state snapshots."""

from __future__ import annotations

import json

import pytest

from supervisor import workspace


@pytest.mark.parametrize(
    "raw",
    [
        '{"git":{"branch":"main","branch":"feature"}}',
        '{"repository_root":"one","repository_root":"two"}',
        '{"available_tools":{"git":true,"git":false}}',
        '{"available_tools":{"python":NaN}}',
        '{"available_tools":{"python":Infinity}}',
        '{"ignored_number":1e9999}',
        '[]',
        'null',
        '{"git":[]}',
        '{"exists_files":17}',
        '{"exists_files":[1]}',
        '{"missing_files":[null]}',
        '{"available_tools":{"git":1}}',
        '{"repository_root":123}',
        '{"git":',
    ],
)
def test_workspace_rejects_ambiguous_and_malformed_snapshot(tmp_path, raw):
    path = tmp_path / "snapshot.json"
    path.write_text(raw)
    assert workspace.load_workspace(str(path)) is None


def test_snapshot_roundtrip_preserves_inventory_and_git_state(tmp_path):
    state = workspace.WorkspaceState(
        repository_root=str(tmp_path),
        git=workspace.GitState(
            branch="main", is_repo=True, head_sha="ab" * 20,
            dirty_files=["src/a.py"], untracked=["new.txt"],
        ),
        exists_files={"README.md", "src/a.py"},
        missing_files={"requirements.txt"},
        available_tools={"python": True, "git": False},
        language="python",
    )
    destination = tmp_path / "state.json"
    workspace.save_workspace(state, str(destination))
    assert destination.is_file()
    restored = workspace.load_workspace(str(destination))
    assert restored is not None
    assert restored.to_dict() == state.to_dict()
    assert restored.missing_files == {"requirements.txt"}
    assert json.loads(destination.read_text())["git"]["is_repo"]
    assert not list(tmp_path.glob(".state.json.*.tmp"))


def test_predictable_old_temporary_symlink_cannot_redirect_write(tmp_path):
    victim = tmp_path / "unrelated.json"
    victim.write_text("original")
    target = tmp_path / "state.json"
    (tmp_path / "state.json.tmp").symlink_to(victim)
    workspace.save_workspace(workspace.WorkspaceState(str(tmp_path)), str(target))
    assert target.exists()
    assert victim.read_text() == "original"
    assert (tmp_path / "state.json.tmp").is_symlink()


def test_atomic_replace_failure_preserves_prior_state(tmp_path, monkeypatch):
    target = tmp_path / "state.json"
    previous = b'{"repository_root":"original"}'
    target.write_bytes(previous)

    def fail(*args):
        raise OSError("simulated unexpected disk failure")

    monkeypatch.setattr(workspace.os, "replace", fail)
    with pytest.raises(OSError, match="simulated"):
        workspace.save_workspace(workspace.WorkspaceState(str(tmp_path)), str(target))
    assert target.read_bytes() == previous
    assert not list(tmp_path.glob(".state.json.*.tmp"))


def test_nonexistent_and_bad_utf8_workspace_is_absent(tmp_path):
    assert workspace.load_workspace(str(tmp_path / "missing")) is None
    path = tmp_path / "broken"
    path.write_bytes(b"\xff\xfe")
    assert workspace.load_workspace(str(path)) is None
