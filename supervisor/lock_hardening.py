"""PID-aware cross-process lock hardening for the agent registry.

A live writer is never evicted merely because a wall-clock timeout elapsed.
Stale recovery is allowed only when the recorded PID is provably dead and the
lock identity is unchanged at removal time.
"""
from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from .agents import MultiAgentRegistry, RegistryIntegrityError
from .agents_hardening import _safe_pid_alive


def _read_lock(path: Path):
    try:
        stat_before = path.stat()
        value = json.loads(path.read_text(encoding="utf-8"))
        stat_after = path.stat()
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError):
        return {"malformed": True}
    if not isinstance(value, dict):
        return {"malformed": True}
    if (stat_before.st_dev, stat_before.st_ino) != (stat_after.st_dev, stat_after.st_ino):
        return {"changed": True}
    value = dict(value)
    value["_identity"] = (stat_after.st_dev, stat_after.st_ino)
    return value


def _remove_dead_owner_lock(path: Path, observed: dict) -> bool:
    pid = observed.get("pid")
    token = observed.get("token")
    identity = observed.get("_identity")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 0
        or not isinstance(token, str)
        or not token
        or not isinstance(identity, tuple)
        or len(identity) != 2
    ):
        return False
    if _safe_pid_alive(pid):
        return False
    current = _read_lock(path)
    if not isinstance(current, dict):
        return False
    if current.get("pid") != pid or current.get("token") != token:
        return False
    if current.get("_identity") != identity:
        return False
    try:
        path.unlink()
        return True
    except OSError:
        return False


def install_registry_lock_hardening() -> None:
    if getattr(MultiAgentRegistry, "_pid_aware_write_lock_installed", False):
        return

    @contextmanager
    def _write_lock(self: MultiAgentRegistry):
        self._ensure_dirs()
        deadline = time.monotonic() + float(getattr(self, "REGISTRY_LOCK_TIMEOUT", 5.0) or 5.0)
        # Constants live at module level in older releases; preserve their public
        # behavior while making stale eviction owner-based rather than age-based.
        if deadline <= time.monotonic():
            deadline = time.monotonic() + 5.0
        token = uuid.uuid4().hex
        payload = {"pid": os.getpid(), "token": token, "created": time.time()}

        while True:
            try:
                fd = os.open(
                    str(self.lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                try:
                    os.write(fd, json.dumps(payload, sort_keys=True).encode("utf-8"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
                break
            except FileExistsError:
                observed = _read_lock(self.lock_path)
                if isinstance(observed, dict) and _remove_dead_owner_lock(self.lock_path, observed):
                    continue
                if isinstance(observed, dict) and observed.get("malformed"):
                    raise RegistryIntegrityError(
                        "agent registry write lock is malformed; refusing unsafe stale-lock eviction"
                    )
                if time.monotonic() >= deadline:
                    owner = observed.get("pid") if isinstance(observed, dict) else None
                    raise RegistryIntegrityError(
                        "agent registry write lock timeout"
                        + (f"; live/unknown owner pid={owner}" if owner else "")
                    )
                time.sleep(0.02)

        body_error = None
        try:
            yield
        except BaseException as exc:
            body_error = exc
            raise
        finally:
            current = _read_lock(self.lock_path)
            owned = (
                isinstance(current, dict)
                and current.get("pid") == os.getpid()
                and current.get("token") == token
            )
            if owned:
                try:
                    self.lock_path.unlink()
                except OSError as exc:
                    if body_error is None:
                        raise RegistryIntegrityError(
                            f"cannot release agent registry write lock: {exc}"
                        ) from exc
            elif body_error is None:
                raise RegistryIntegrityError(
                    "agent registry write lock identity changed while held"
                )

    MultiAgentRegistry._write_lock = _write_lock
    MultiAgentRegistry._pid_aware_write_lock_installed = True
