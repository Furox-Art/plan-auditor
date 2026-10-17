"""Workspace state is derived from real git/filesystem evidence, never guessed."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor import workspace as ws


def test_real_clean_nonrepo_workspace_has_no_fake_git_branch(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[package]\nname='observed'\nversion='0.1.0'")
    result = ws.capture_workspace(str(tmp_path), extra_tools=["pytest"])
    assert result.git.is_repo is False
    assert result.git.branch is None
    assert result.language == "rust"
    assert "Cargo.toml" in result.exists_files
    assert result.available_tools["pytest"] is (ws.shutil.which("pytest") is not None)
    assert result.available_tools["python"] is True
    saved = result.to_dict()
    assert saved["git"]["head_sha"] is None


def test_real_git_repository_tracks_branch_untracked_and_dirty_paths(tmp_path):
    def command(*args):
        return subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            capture_output=True,
            text=True,
            check=True,
        )

    command("init", "-b", "audit-branch")
    (tmp_path / "README.md").write_text("source")
    command("add", "README.md")
    command(
        "-c",
        "user.name=Audit Fixture",
        "-c",
        "user.email=audit-fixture@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    (tmp_path / "README.md").write_text("changed")
    (tmp_path / "new.txt").write_text("new")
    recorded = ws.capture_workspace(str(tmp_path))
    assert recorded.git.is_repo
    assert recorded.git.branch == "audit-branch"
    assert recorded.git.head_sha is not None and len(recorded.git.head_sha) == 40
    assert "README.md" in recorded.git.dirty_files
    assert "new.txt" in recorded.git.untracked
    assert "README.md" in recorded.exists_files
    assert not any(".git/" in p for p in recorded.exists_files)


def test_git_failed_command_and_expired_subprocess_are_not_reported_as_success(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        ws.subprocess,
        "run",
        lambda *_a, **_kw: SimpleNamespace(returncode=1, stdout="fabricated branch"),
    )
    assert ws._run(["git", "status"], str(tmp_path)) is None

    def timeout(*_a, **_kw):
        raise subprocess.TimeoutExpired(["git"], 30)

    monkeypatch.setattr(ws.subprocess, "run", timeout)
    assert ws._run(["git", "status"], str(tmp_path)) is None


def test_git_probe_uses_an_argv_vector_and_no_shell_expansion(monkeypatch, tmp_path):
    seen = []

    def verify(argv, **kw):
        seen.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout=" measured \n")

    monkeypatch.setattr(ws.subprocess, "run", verify)
    # Leading/trailing spaces can be significant in git porcelain output.
    assert ws._run(["git", "rev-parse", "--abbrev-ref", "HEAD"], str(tmp_path)) == " measured "
    assert seen[0][1]["shell"] is False
    assert seen[0][1]["cwd"] == str(tmp_path)


@pytest.mark.parametrize(
    ("marker", "language"),
    [
        ("pyproject.toml", "python"),
        ("package.json", "node"),
        ("Cargo.toml", "rust"),
        ("go.mod", "go"),
        ("pom.xml", "java"),
    ],
)
def test_language_is_inferred_only_from_real_top_level_files(tmp_path, marker, language):
    (tmp_path / marker).write_text("recorded file")
    assert ws._detect_language(str(tmp_path)) == language


def test_empty_directory_has_unknown_language_without_guessing(tmp_path):
    assert ws._detect_language(str(tmp_path)) is None


def test_invalid_or_missing_tool_names_have_no_executable_claim():
    assert ws.tool_available("") is False
    assert ws.tool_available(None) is False
    assert ws.tool_available("a-nonexistent-executable-5293174") is False


def test_python_binary_check_handles_filesystem_error_without_fake_availability(monkeypatch):
    original = Path.is_file

    def inaccessible(self, *args, **kwargs):
        if str(self) == ws.sys.executable:
            raise OSError("simulated denied metadata")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", inaccessible)
    assert ws.tool_available("python") is False


def test_invalid_extra_tool_entries_are_excluded_from_real_inventory(tmp_path):
    recorded = ws._detect_tools(str(tmp_path), extra_tools=["python", None, False, "  "])
    assert "python" in recorded
    assert None not in recorded
    assert False not in recorded


def test_status_parser_never_claims_an_empty_change_path(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()

    def observed(argv, root, timeout=30):
        if argv[-1] == "--porcelain":
            return "M \n?? fresh.txt\n M real.txt\n"
        return "observed-sha"

    monkeypatch.setattr(ws, "_run", observed)
    out = ws.capture_workspace(str(tmp_path))
    assert out.git.is_repo is True
    assert out.git.untracked == ["fresh.txt"]
    assert out.git.dirty_files == ["real.txt"]


def test_actual_workspace_file_diff_retains_created_deleted_and_tool_changes():
    before = ws.WorkspaceState(
        "source",
        git=ws.GitState(branch="main"),
        exists_files={"first.txt"},
        available_tools={"numpy": False},
    )
    after = ws.WorkspaceState(
        "source",
        git=ws.GitState(branch="feature", dirty_files=["second.txt"]),
        exists_files={"second.txt"},
        available_tools={"numpy": True},
    )
    diff = ws.diff_workspaces(before, after)
    assert diff["created_files"] == ["second.txt"]
    assert diff["deleted_files"] == ["first.txt"]
    assert diff["new_dirty"] == ["second.txt"]
    assert diff["branch_changed"]
    assert diff["tools_changed"] == {"numpy": (False, True)}


def test_snapshot_save_reload_is_an_exact_roundtrip(tmp_path):
    original = ws.WorkspaceState(
        repository_root=str(tmp_path),
        git=ws.GitState(
            branch="main",
            is_repo=True,
            dirty_files=["modified.txt"],
            head_sha="a" * 40,
            untracked=["untracked.txt"],
        ),
        exists_files={"README.md"},
        available_tools={"git": True},
        language="python",
    )
    file = tmp_path / "state.json"
    ws.save_workspace(original, str(file))
    reloaded = ws.load_workspace(str(file))
    assert reloaded is not None
    assert reloaded.to_dict() == original.to_dict()


@pytest.mark.parametrize(
    "invalid_json",
    [
        '{"a":1,"a":2}',
        '{"confidence":NaN}',
        '{"confidence":1e309}',
        '["not an object"]',
        '{"available_tools":{"python":"maybe"}}',
    ],
)
def test_untrusted_snapshot_json_cannot_be_reported_as_recorded_workspace(tmp_path, invalid_json):
    file = tmp_path / "state.json"
    file.write_text(invalid_json)
    assert ws.load_workspace(str(file)) is None


def test_snapshot_missing_path_remains_unknown_not_empty_verified_workspace(tmp_path):
    assert ws.load_workspace(str(tmp_path / "not-observed.json")) is None


def test_valid_workspace_float_keeps_exact_provenance():
    assert ws._finite_json_float("1.25") == 1.25


def test_directory_walk_file_escape_is_never_reported_as_a_local_file(monkeypatch, tmp_path):
    original = Path.relative_to

    def reject_one(self, other, *args, **kwargs):
        if self.name == "untrusted.txt":
            raise ValueError("inconsistent filesystem ancestry")
        return original(self, other, *args, **kwargs)

    (tmp_path / "untrusted.txt").write_text("unexpected mount")
    (tmp_path / "confirmed.txt").write_text("local")
    monkeypatch.setattr(Path, "relative_to", reject_one)
    result = ws._inventory_files(tmp_path)
    assert result == {"confirmed.txt"}


def test_empty_git_status_line_does_not_manufacture_a_changed_file(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()

    def simulate(argv, *args, **kwargs):
        if argv[-1] == "--porcelain":
            return "\n?? measured.txt\n"
        return "observed"

    monkeypatch.setattr(ws, "_run", simulate)
    result = ws.capture_workspace(str(tmp_path))
    assert result.git.untracked == ["measured.txt"]
    assert result.git.dirty_files == []


def test_workspace_atomic_snapshot_open_failure_cannot_claim_a_saved_file(monkeypatch, tmp_path):
    target = tmp_path / "snapshot.json"

    def refuse(*args, **kwargs):
        raise OSError("open refused before temp file allocation")

    monkeypatch.setattr(ws.tempfile, "NamedTemporaryFile", refuse)
    with pytest.raises(OSError, match="open refused"):
        ws.save_workspace(ws.WorkspaceState(str(tmp_path)), str(target))
    assert not target.exists()
    assert list(tmp_path.glob("*.tmp")) == []
