"""Regression coverage for the ``.plan-auditor`` generated-state ignore contract.

The tool writes evidence chains, seals, the agent registry, rotation archives and
daemon state into ``.plan-auditor/``. Before the deny-by-default rule existed,
only the runtime files somebody had already noticed were named one by one in the
repository ``.gitignore``, so every runtime file added later — ``facts.json``,
``supervisor.json``, or any checkpoint a new monitor writes — was committable
until the next person got burned by it. ``plan.json``, named plans and
``request-source.json`` are hand-authored input and must stay committable, so the
rule has to be selective rather than a blanket ignore of the directory.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Files the tool writes into a workspace. Every one must be ignored. The last
#: three are deliberately names no ``.gitignore`` line spells out: they stand in
#: for whatever the next feature adds, and they are what proves the rule is
#: deny-by-default instead of an allowlist that has to be edited first.
GENERATED_RUNTIME_STATE = (
    "evidence.jsonl",
    "evidence.head.json",
    "evidence.write.lock",
    "evidence.tmp",
    "archive/evidence-20261013T000000000000.jsonl",
    "snapshots/snapshot-20261013T000000000000.zip",
    "audit.freeze.lock",
    "request.json",
    "activation.json",
    "integrity.json",
    "seal.json",
    "seals/plan-20261013.json",
    "supervisor.json",
    "supervisor-runtime.json",
    "supervisor-assessment.json",
    "supervisor.stop",
    "supervisor.log",
    "watchdog.jsonl",
    "gate-warning.json",
    "facts.json",
    "agents/registry.jsonl",
    "agents/registry.head.json",
    "agents/registry.write.lock",
    "agents/a1.lock",
    "monitor-checkpoint.json",
    "registry-state.json",
    "rotate.lock",
)

#: Hand-authored input. Every one must stay committable.
HAND_AUTHORED_INPUT = (
    ".gitignore",
    "plan.json",
    "request-source.json",
    "plans/named.json",
    "plans/nested/deep.json",
)

requires_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git is not installed; the rules cannot be exercised"
)


def _git(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        # ``core.quotePath=false`` keeps paths literal, otherwise git escapes
        # them and every comparison below starts failing on quoting rather than
        # on the rule under test.
        ["git", "-c", "core.quotePath=false", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
    )


def _is_ignored(path: str, cwd: Path) -> bool:
    """Ask git itself, index-independent, whether ``path`` is ignored."""
    proc = _git("check-ignore", "-q", "--no-index", path, cwd=cwd)
    if proc.returncode not in (0, 1):
        raise AssertionError(
            f"git check-ignore failed for {path}: rc={proc.returncode} {proc.stderr}"
        )
    return proc.returncode == 0


def _workspace(tmp_path: Path) -> Path:
    """A fresh repository carrying only this repository's ignore rules."""
    nested = ROOT / ".plan-auditor" / ".gitignore"
    assert nested.is_file(), (
        ".plan-auditor/.gitignore is missing: runtime state is protected only "
        "for the file names somebody already listed in the repository .gitignore"
    )
    workspace = tmp_path / "project"
    workspace.mkdir()
    _git("init", "--quiet", cwd=workspace)
    shutil.copyfile(ROOT / ".gitignore", workspace / ".gitignore")
    plan_dir = workspace / ".plan-auditor"
    plan_dir.mkdir()
    shutil.copyfile(nested, plan_dir / ".gitignore")
    return workspace


@requires_git
def test_nested_gitignore_exists_and_denies_generated_state(tmp_path: Path):
    """The deny-by-default rule itself must be committed, not just assumed."""
    workspace = _workspace(tmp_path)
    for name in GENERATED_RUNTIME_STATE:
        assert _is_ignored(f".plan-auditor/{name}", workspace), (
            f".plan-auditor/{name} is committable; a new runtime file must not "
            "require a new .gitignore line first"
        )


@requires_git
def test_hand_authored_input_stays_committable(tmp_path: Path):
    """The rule must not silently hide the human-written plan and request."""
    workspace = _workspace(tmp_path)
    for name in HAND_AUTHORED_INPUT:
        assert not _is_ignored(f".plan-auditor/{name}", workspace), (
            f".plan-auditor/{name} is hand-authored input and must stay committable"
        )


@requires_git
def test_git_add_refuses_runtime_state_and_accepts_plan(tmp_path: Path):
    """End to end through ``git add``, which is the operation that leaks state."""
    workspace = _workspace(tmp_path)
    plan_dir = workspace / ".plan-auditor"
    (plan_dir / "evidence.jsonl").write_text('{"hash":"h"}\n', encoding="utf-8")
    (plan_dir / "facts.json").write_text("[]\n", encoding="utf-8")
    (workspace / "committed.txt").write_text("x", encoding="utf-8")
    (plan_dir / "plans").mkdir()
    (plan_dir / "plans" / "named.json").write_text("{}\n", encoding="utf-8")

    proc = _git("add", "-A", cwd=workspace)
    assert proc.returncode == 0, proc.stderr
    staged = {
        line.strip().strip('"')
        for line in _git("diff", "--cached", "--name-only", cwd=workspace).stdout.splitlines()
        if line.strip()
    }
    assert "committed.txt" in staged
    assert ".plan-auditor/plans/named.json" in staged, "named plans are hand-authored input"
    assert ".plan-auditor/.gitignore" in staged
    assert ".plan-auditor/evidence.jsonl" not in staged
    assert ".plan-auditor/facts.json" not in staged


@requires_git
def test_tracked_runtime_state_is_not_untracked_by_the_new_rule(tmp_path: Path):
    """A workspace that already committed state is reported as untracked-clean.

    This is the operational check: after the rule lands, ``git status`` in a
    dogfooded workspace must stop showing the generated files as modifications
    of tracked files.
    """
    workspace = _workspace(tmp_path)
    plan_dir = workspace / ".plan-auditor"
    (plan_dir / "evidence.jsonl").write_text('{"hash":"h"}\n', encoding="utf-8")
    _git("add", "-A", cwd=workspace)
    _git(
        "-c",
        "user.email=t@example.invalid",
        "-c",
        "user.name=t",
        "commit",
        "--quiet",
        "-m",
        "seed",
        cwd=workspace,
    )
    (plan_dir / "evidence.jsonl").write_text('{"hash":"changed"}\n', encoding="utf-8")
    (plan_dir / "seal.json").write_text("{}\n", encoding="utf-8")
    status = _git("status", "--porcelain", cwd=workspace).stdout.splitlines()
    assert not [line for line in status if "evidence.jsonl" in line], status
    assert not [line for line in status if "seal.json" in line], status
