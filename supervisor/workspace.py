"""L2 — side-effect-free workspace / world model.

Captures repository, filesystem, language and tool state without mutating the
workspace being observed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class GitState:
    branch: Optional[str] = None
    dirty_files: List[str] = field(default_factory=list)
    untracked: List[str] = field(default_factory=list)
    head_sha: Optional[str] = None
    is_repo: bool = False


@dataclass
class WorkspaceState:
    repository_root: str
    git: GitState = field(default_factory=GitState)
    exists_files: Set[str] = field(default_factory=set)
    missing_files: Set[str] = field(default_factory=set)
    available_tools: Dict[str, bool] = field(default_factory=dict)
    build_commands: List[str] = field(default_factory=list)
    test_commands: List[str] = field(default_factory=list)
    language: Optional[str] = None
    raw: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "repository_root": self.repository_root,
            "git": {
                "branch": self.git.branch,
                "is_repo": self.git.is_repo,
                "head_sha": self.git.head_sha,
                "dirty_files": self.git.dirty_files,
                "untracked": self.git.untracked,
            },
            "exists_files": sorted(self.exists_files),
            "missing_files": sorted(self.missing_files),
            "available_tools": self.available_tools,
            "language": self.language,
        }


def _run(cmd: str, cwd: str, timeout: int = 30) -> Optional[str]:
    try:
        process = subprocess.run(
            cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        if process.returncode != 0:
            return None
        return process.stdout.strip()
    except Exception:
        return None


def _detect_language(root: str) -> Optional[str]:
    markers = {
        "python": ["pyproject.toml", "setup.py", "requirements.txt", "Pipfile"],
        "node": ["package.json", "package-lock.json"],
        "rust": ["Cargo.toml"],
        "go": ["go.mod"],
        "java": ["pom.xml", "build.gradle"],
    }
    files = {path.name.lower() for path in Path(root).glob("*") if path.is_file()}
    for language, names in markers.items():
        if any(name.lower() in files for name in names):
            return language
    return None


def _detect_tools(_root: str) -> Dict[str, bool]:
    """Detect executables without shell redirections or workspace writes."""
    tools = [
        "git", "python", "python3", "node", "npm", "cargo", "go",
        "pytest", "make", "docker", "gcc", "clang",
    ]
    return {tool: shutil.which(tool) is not None for tool in tools}


def _inventory_files(root: Path) -> Set[str]:
    ignored = {".git", ".plan-auditor", "__pycache__", ".pytest_cache"}
    files: Set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in ignored]
        for filename in filenames:
            path = Path(dirpath) / filename
            try:
                files.add(path.relative_to(root).as_posix())
            except ValueError:
                continue
    return files


def capture_workspace(root: str) -> WorkspaceState:
    """Capture a point-in-time, read-only snapshot of the workspace."""
    root_path = Path(root).resolve()
    state = WorkspaceState(repository_root=str(root_path))

    git_dir = root_path / ".git"
    if git_dir.exists():
        state.git.is_repo = True
        state.git.branch = _run("git rev-parse --abbrev-ref HEAD", str(root_path))
        state.git.head_sha = _run("git rev-parse HEAD", str(root_path))
        status = _run("git status --porcelain", str(root_path)) or ""
        for raw_line in status.splitlines():
            if not raw_line:
                continue
            code = raw_line[:2]
            path = raw_line[3:].strip() if len(raw_line) > 3 else ""
            if code == "??":
                state.git.untracked.append(path)
            elif path:
                state.git.dirty_files.append(path)

    state.exists_files = _inventory_files(root_path)
    state.language = _detect_language(str(root_path))
    state.available_tools = _detect_tools(str(root_path))
    return state


def diff_workspaces(before: WorkspaceState, after: WorkspaceState) -> Dict:
    return {
        "created_files": sorted(after.exists_files - before.exists_files),
        "deleted_files": sorted(before.exists_files - after.exists_files),
        "new_dirty": sorted(set(after.git.dirty_files) - set(before.git.dirty_files)),
        "branch_changed": before.git.branch != after.git.branch,
        "tools_changed": {
            key: (before.available_tools.get(key), after.available_tools.get(key))
            for key in set(before.available_tools) | set(after.available_tools)
            if before.available_tools.get(key) != after.available_tools.get(key)
        },
    }


def load_workspace(path: str) -> Optional[WorkspaceState]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    git = data.get("git", {})
    return WorkspaceState(
        repository_root=data.get("repository_root", "."),
        git=GitState(
            branch=git.get("branch"),
            is_repo=git.get("is_repo", False),
            head_sha=git.get("head_sha"),
            dirty_files=git.get("dirty_files", []),
            untracked=git.get("untracked", []),
        ),
        exists_files=set(data.get("exists_files", [])),
        missing_files=set(data.get("missing_files", [])),
        available_tools=dict(data.get("available_tools", {})),
        language=data.get("language"),
    )


def save_workspace(state: WorkspaceState, path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp = path + ".tmp"
    Path(tmp).write_text(json.dumps(state.to_dict(), indent=2), encoding="utf-8")
    os.replace(tmp, path)
