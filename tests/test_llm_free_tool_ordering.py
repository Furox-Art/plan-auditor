"""Hash-seed invariance for the LLM-free supervisor tools' serialised order.

The watchdog publishes filesystem/git events and the workspace diff publishes
tool transitions. Both are built from sets, so their order previously followed
CPython's string hash randomisation. The same bytes are appended to evidence
logs and compared by the determinism matrix, so ordering must not move between
two interpreters that differ only by ``PYTHONHASHSEED``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from functools import cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

CHILD = r'''
import json
import os
import sys
import tempfile
from pathlib import Path

repo_root = Path(sys.argv[1])
sys.path.insert(0, str(repo_root))

from supervisor import watchdog
from supervisor.workspace import GitState, WorkspaceState, diff_workspaces

# A real git probe would add host-dependent output; pin the observed git set.
watchdog._git_changed_files = lambda _root: {"git-only.txt", "alpha.txt"}

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / "nested").mkdir()
    for name in ("keep.txt", "change.txt", "gone.txt"):
        (root / name).write_text(name, encoding="utf-8")
    watcher = watchdog.Watchdog(str(root))
    for name in ("zeta.txt", "alpha.txt", "nested/beta.txt"):
        (root / name).write_text(name, encoding="utf-8")
    os.utime(root / "change.txt", (1_000_000_000, 1_000_000_000))
    (root / "gone.txt").unlink()
    result = watcher.poll()
    events = [[event.kind, event.path] for event in result.events]
    observed = {
        "created": sorted(result.created),
        "deleted": sorted(result.deleted),
        "changed": sorted(result.changed_files),
    }

before = WorkspaceState(
    repository_root="/workspace",
    git=GitState(),
    available_tools={"zzz": True, "aaa": False, "mmm": True},
)
after = WorkspaceState(
    repository_root="/workspace",
    git=GitState(),
    available_tools={"bbb": True, "aaa": True, "zzz": False, "mmm": True},
)
diff = diff_workspaces(before, after)

print(json.dumps({
    "events": events,
    "observed": observed,
    "created_files": diff["created_files"],
    "tools_changed": [[key, list(value)] for key, value in diff["tools_changed"].items()],
}, ensure_ascii=False))
'''


@cache
def _run_with_hash_seed(seed: str) -> dict:
    env = {
        **os.environ,
        "PYTHONHASHSEED": seed,
        "PYTHONIOENCODING": "utf-8",
    }
    completed = subprocess.run(
        [sys.executable, "-c", CHILD, str(REPO_ROOT)],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_watchdog_event_order_is_hash_seed_invariant_and_paths_are_posix() -> None:
    first = _run_with_hash_seed("0")
    second = _run_with_hash_seed("12345")
    assert first == second
    assert first["events"] == [
        ["fs_create", "alpha.txt"],
        ["fs_create", "nested/beta.txt"],
        ["fs_create", "zeta.txt"],
        ["fs_delete", "gone.txt"],
        ["fs_modify", "change.txt"],
        ["git_change", "git-only.txt"],
    ]
    assert first["observed"] == {
        "created": ["alpha.txt", "nested/beta.txt", "zeta.txt"],
        "deleted": ["gone.txt"],
        "changed": ["change.txt", "git-only.txt"],
    }


def test_workspace_tool_transitions_are_sorted_and_hash_seed_invariant() -> None:
    payload = _run_with_hash_seed("0")
    assert payload == _run_with_hash_seed("12345")
    assert payload["tools_changed"] == [
        ["aaa", [False, True]],
        ["bbb", [None, True]],
        ["zzz", [True, False]],
    ]
