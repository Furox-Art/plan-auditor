"""Deterministic plan/evidence workload sampled by the determinism matrix."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any


def main() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo_root))
    sys.path.insert(0, str(repo_root / "scripts"))

    from scripts import audit_check as ac
    from scripts.contract import canonical_digest, canonical_json, plan_hash
    from supervisor import watchdog
    from supervisor.workspace import GitState, WorkspaceState, diff_workspaces

    # audit_check predates strict typing; bind the two entry points through a
    # typed callable so this workload does not add no-untyped-call findings to
    # the ratchet baseline.
    append_evidence: Callable[..., Any] = ac.append_evidence
    verify_chain: Callable[..., Any] = ac.verify_chain

    plan = {
        "task": "determinism matrix",
        "requirements": ["r2", "r1"],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "compute",
                "verify": [{"type": "run", "cmd": 'python -c "print(1)"', "expect_exit": 0}],
                "status": "pending",
            }
        ],
    }
    unordered = {key: len(key) for key in {"zeta", "alpha", "mu", "beta"}}

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        hashes = [
            append_evidence(
                base,
                {"mode": "audit", "step": step, "status": "ok", "n": step, "labels": ["b", "a"]},
            )
            for step in (1, 2, 3)
        ]
        ok, count, problem = verify_chain(base)

    # The watchdog and workspace diff serialise sets; pin their ordering as a
    # matrix workload so a hash-seed dependency fails the same gate that
    # protects the canonical hashes above.
    def _fixed_git_changes(root: str) -> set[str]:
        return {"git-only.txt", "alpha.txt"}

    watchdog._git_changed_files = _fixed_git_changes
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
        observed = watcher.poll()
        supervisor_events = [[event.kind, event.path] for event in observed.events]

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
    tools_changed = [
        [key, list(value)]
        for key, value in diff_workspaces(before, after)["tools_changed"].items()
    ]
    expected_events = [
        ["fs_create", "alpha.txt"],
        ["fs_create", "nested/beta.txt"],
        ["fs_create", "zeta.txt"],
        ["fs_delete", "gone.txt"],
        ["fs_modify", "change.txt"],
        ["git_change", "git-only.txt"],
    ]
    if supervisor_events != expected_events:
        raise SystemExit(f"watchdog event order is not deterministic: {supervisor_events!r}")
    if tools_changed != [["aaa", [False, True]], ["bbb", [None, True]], ["zzz", [True, False]]]:
        raise SystemExit(f"workspace tool order is not deterministic: {tools_changed!r}")

    payload: dict[str, Any] = {
        "plan_hash": plan_hash(plan),
        "canonical": canonical_json(unordered),
        "digest": canonical_digest(unordered),
        "evidence_hashes": hashes,
        "verify": {"ok": ok, "count": count, "problem": problem},
        "supervisor": {"events": supervisor_events, "tools_changed": tools_changed},
    }
    if not payload["verify"]["ok"] or payload["verify"]["count"] != 3:
        raise SystemExit("evidence chain did not verify; the workload is vacuous")
    artifact_dir = os.environ.get("DETERMINISM_ARTIFACT_DIR")
    if artifact_dir:
        Path(artifact_dir, "payload.json").write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
            newline="\n",
        )
    print(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    main()
