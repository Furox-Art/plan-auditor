"""Workspace-wide quiescence guard for the final deterministic audit."""
from __future__ import annotations

import json
import os
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from scripts import audit_check as core

from .agents import MultiAgentRegistry, RegistryIntegrityError
from .daemon import pid_alive

FREEZE_NAME = "audit.freeze.lock"


class AuditSessionError(RuntimeError):
    """Raised when a final audit cannot establish or preserve quiescence."""


def freeze_path(root: str | Path) -> Path:
    return Path(root).resolve() / ".plan-auditor" / FREEZE_NAME


def _read_freeze(path: Path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _remove_provably_stale(path: Path) -> None:
    if not path.exists():
        return
    value = _read_freeze(path)
    pid = value.get("pid") if isinstance(value, dict) else None
    if not isinstance(pid, int) or pid <= 0:
        raise AuditSessionError("existing audit freeze is malformed; refusing to remove it")
    if pid_alive(pid):
        raise AuditSessionError(f"another final audit is active with pid {pid}")
    try:
        path.unlink()
    except OSError as exc:
        raise AuditSessionError(f"cannot remove stale audit freeze: {exc}") from exc


def _verify_registry_locked(registry: MultiAgentRegistry) -> None:
    registry._refresh_from_disk()
    if registry.registry_tampered:
        raise AuditSessionError(
            "agent registry integrity failed before final audit"
            + (f": {registry.registry_problem}" if registry.registry_problem else "")
        )
    if registry.registry_legacy:
        try:
            registry._migrate_legacy_locked()
            registry._refresh_from_disk()
        except (OSError, json.JSONDecodeError, UnicodeError, RegistryIntegrityError) as exc:
            raise AuditSessionError(f"agent registry migration failed before final audit: {exc}") from exc
    if registry.registry_tampered:
        raise AuditSessionError(
            "agent registry integrity failed before final audit"
            + (f": {registry.registry_problem}" if registry.registry_problem else "")
        )


def _active_agents_locked(registry: MultiAgentRegistry):
    now = time.time()
    return [
        agent
        for agent in registry._agents.values()
        if agent.state == "active" and now - agent.last_heartbeat < registry.owner_timeout
    ]


@contextmanager
def final_audit_session(
    root: str | Path,
    registry: MultiAgentRegistry,
) -> Iterator[str]:
    """Freeze cooperating agent mutations and prove product state stayed unchanged.

    The registry lock is held while checking for live agents and creating the
    freeze file, closing the race where an agent could register between the
    quiescence check and freeze activation.  Product state is fingerprinted at
    both ends; ``.plan-auditor`` metadata is intentionally excluded by the core
    fingerprint.
    """
    workspace = Path(root).resolve()
    path = freeze_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    token = uuid.uuid4().hex
    payload = {"pid": os.getpid(), "token": token, "created": time.time()}

    with registry._write_lock():
        _remove_provably_stale(path)
        _verify_registry_locked(registry)
        active = _active_agents_locked(registry)
        if active:
            names = sorted(agent.agent_id for agent in active)
            raise AuditSessionError(
                "final audit requires a quiescent workspace; active agents: " + ", ".join(names)
            )
        try:
            fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise AuditSessionError("final audit freeze already exists") from exc
        try:
            os.write(fd, json.dumps(payload, sort_keys=True).encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)

    before = core.workspace_fingerprint(str(workspace))
    body_error = None
    try:
        yield before
    except BaseException as exc:  # preserve the original audit failure
        body_error = exc
        raise
    finally:
        current = _read_freeze(path)
        freeze_ok = isinstance(current, dict) and current.get("pid") == os.getpid() and current.get("token") == token
        after = core.workspace_fingerprint(str(workspace))
        if freeze_ok:
            try:
                path.unlink()
            except OSError as exc:
                if body_error is None:
                    raise AuditSessionError(f"cannot release final audit freeze: {exc}") from exc
        elif body_error is None:
            raise AuditSessionError("final audit freeze was modified or removed during verification")
        if body_error is None and after != before:
            raise AuditSessionError(
                "workspace content/type/mode changed during the full final-audit session"
            )
