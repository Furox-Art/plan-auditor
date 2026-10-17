"""L2 — side-effect-free workspace / world model."""
from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set


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


def _run(argv: Sequence[str], cwd: str, timeout: int = 30) -> Optional[str]:
    try:
        process = subprocess.run(
            list(argv), shell=False, cwd=cwd, capture_output=True, text=True, timeout=timeout,
        )
        if process.returncode != 0:
            return None
        # Git porcelain status uses a leading blank as a meaningful XY status
        # character (" M file"). Generic strip() destroys that character and
        # silently truncates filenames when capture_workspace slices at index 3.
        # Remove only the record terminator, never leading status bytes.
        return process.stdout.rstrip("\r\n")
    except (OSError, subprocess.TimeoutExpired):
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


def tool_available(tool: str) -> bool:
    """Resolve an arbitrary executable name without executing it."""
    if not isinstance(tool, str) or not tool.strip():
        return False
    value = tool.strip()
    if value == "python":
        try:
            return bool(sys.executable) and Path(sys.executable).is_file()
        except OSError:
            return False
    return shutil.which(value) is not None


def _detect_tools(_root: str, extra_tools: Iterable[str] = ()) -> Dict[str, bool]:
    common = {
        "git", "python", "python3", "node", "npm", "cargo", "go",
        "pytest", "make", "docker", "gcc", "clang", "java", "dotnet",
    }
    common.update(tool for tool in extra_tools if isinstance(tool, str) and tool.strip())
    return {tool: tool_available(tool) for tool in sorted(common)}


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


def capture_workspace(root: str, extra_tools: Iterable[str] = ()) -> WorkspaceState:
    root_path = Path(root).resolve()
    state = WorkspaceState(repository_root=str(root_path))

    git_dir = root_path / ".git"
    if git_dir.exists():
        state.git.is_repo = True
        state.git.branch = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], str(root_path))
        state.git.head_sha = _run(["git", "rev-parse", "HEAD"], str(root_path))
        status = _run(["git", "status", "--porcelain"], str(root_path)) or ""
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
    state.available_tools = _detect_tools(str(root_path), extra_tools)
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


def _unique_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError(f"duplicate workspace JSON field: {key}")
        values[key] = value
    return values


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard workspace JSON numeric constant: {value}")


def _finite_json_float(source: str) -> float:
    number = float(source)
    if not math.isfinite(number):
        raise ValueError("non-finite workspace JSON number")
    return number


def load_workspace(path: str) -> Optional[WorkspaceState]:
    """Decode only a well-formed, unambiguous workspace snapshot."""
    try:
        data = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_keys,
            parse_float=_finite_json_float,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, OSError, UnicodeError):
        return None

    if not isinstance(data, dict):
        return None
    git = data.get("git", {})
    files = data.get("exists_files", [])
    missing = data.get("missing_files", [])
    tools = data.get("available_tools", {})
    if (
        not isinstance(git, dict)
        or not isinstance(data.get("repository_root", "."), str)
        or not isinstance(files, list)
        or not all(isinstance(item, str) for item in files)
        or not isinstance(missing, list)
        or not all(isinstance(item, str) for item in missing)
        or not isinstance(tools, dict)
        or not all(isinstance(key, str) and isinstance(value, bool)
                   for key, value in tools.items())
    ):
        return None
    return WorkspaceState(
        repository_root=data.get("repository_root", "."),
        git=GitState(
            branch=git.get("branch"),
            is_repo=git.get("is_repo", False),
            head_sha=git.get("head_sha"),
            dirty_files=git.get("dirty_files", []),
            untracked=git.get("untracked", []),
        ),
        exists_files=set(files),
        missing_files=set(missing),
        available_tools=dict(tools),
        language=data.get("language"),
    )


def save_workspace(state: WorkspaceState, path: str) -> None:
    """Write and fsync a same-directory temporary file, then atomically swap.

    No predictable temporary name is used, so an attacker cannot plant a
    symlink at path + ".tmp" to redirect writes outside the workspace.
    """
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(state.to_dict(), indent=2, ensure_ascii=False, allow_nan=False)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
