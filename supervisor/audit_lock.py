"""Workspace-wide final-audit freeze shared by CLI and agent registry."""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

LOCK_TIMEOUT = 10.0
LOCK_STALE = 3600.0
LOCK_NAME = "workspace.audit.lock"


def lock_path(root: str | Path) -> Path:
    return Path(root).resolve() / ".plan-auditor" / LOCK_NAME


def audit_frozen(root: str | Path) -> bool:
    return lock_path(root).exists()


@contextmanager
def audit_freeze(root: str | Path) -> Iterator[None]:
    target = lock_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.write(fd, json.dumps({"pid": os.getpid(), "ts": time.time()}).encode("utf-8"))
            finally:
                os.close(fd)
            break
        except FileExistsError:
            try:
                if time.time() - target.stat().st_mtime > LOCK_STALE:
                    target.unlink()
                    continue
            except OSError:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("workspace final-audit lock timeout")
            time.sleep(0.02)
    try:
        yield
    finally:
        try:
            target.unlink()
        except OSError:
            pass
