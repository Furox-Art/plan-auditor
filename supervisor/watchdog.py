"""L9 — Execution watchdog.

Observes the workspace while the main agent works: filesystem changes,
git diff, build/test exit codes, agent heartbeats, timeouts. Best-effort
per platform — uses capability detection and degrades to polling when
inotify/FSEvents is unavailable.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set


@dataclass
class WatchEvent:
    ts: float
    kind: str          # fs_create | fs_delete | fs_modify | git_change | timeout | heartbeat_miss
    path: str = ""
    detail: str = ""


@dataclass
class WatchResult:
    events: List[WatchEvent]
    changed_files: Set[str]
    created: Set[str]
    deleted: Set[str]


def _snapshot_files(root: str) -> Dict[str, float]:
    """Map relative path -> mtime for regular files under root."""
    state: Dict[str, float] = {}
    for dirpath, _, filenames in os.walk(root):
        if ".plan-auditor" in dirpath or ".git" in dirpath:
            continue
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                rel = os.path.relpath(p, root)
                state[rel] = os.path.getmtime(p)
            except OSError:
                continue
    return state


def _git_changed_files(root: str) -> Set[str]:
    try:
        out = subprocess.run("git diff --name-only && git diff --cached --name-only",
                             shell=True, cwd=root, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return set()
        return {l.strip() for l in out.stdout.splitlines() if l.strip()}
    except Exception:
        return set()


class Watchdog:
    def __init__(self, root: str, poll_interval: float = 5.0):
        self.root = root
        self.poll_interval = poll_interval
        self._baseline: Dict[str, float] = _snapshot_files(root)
        self._handlers: List[Callable[[WatchEvent], None]] = []

    def on_event(self, handler: Callable[[WatchEvent], None]) -> None:
        self._handlers.append(handler)

    def poll(self) -> WatchResult:
        now = time.time()
        events: List[WatchEvent] = []
        current = _snapshot_files(self.root)
        created = set(current) - set(self._baseline)
        deleted = set(self._baseline) - set(current)
        changed: Set[str] = set()

        for path, mtime in current.items():
            if path in self._baseline and mtime != self._baseline[path]:
                changed.add(path)

        for p in created:
            events.append(WatchEvent(ts=now, kind="fs_create", path=p))
        for p in deleted:
            events.append(WatchEvent(ts=now, kind="fs_delete", path=p))
        for p in changed:
            events.append(WatchEvent(ts=now, kind="fs_modify", path=p))

        git_changed = _git_changed_files(self.root)
        for p in git_changed - created - deleted - changed:
            events.append(WatchEvent(ts=now, kind="git_change", path=p))
            changed.add(p)

        result = WatchResult(events=events, changed_files=changed,
                             created=created, deleted=deleted)
        for ev in events:
            for h in self._handlers:
                h(ev)

        self._baseline = current
        return result

    def has_activity(self, since_seconds: float) -> bool:
        cutoff = time.time() - since_seconds
        return any(mtime > cutoff for mtime in self._baseline.values())
