"""Runtime hardening wrappers for the persisted multi-agent registry.

This layer owns path canonicalisation plus the cross-process transaction boundary
for every registry read/modify/write operation.  The codec stays in
``supervisor.agents``; mutations here hold the registry write lock from the
fresh read through the chained append/head checkpoint so concurrent agents
cannot lose ownership or heartbeat updates.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import List, Set

from . import agents as _agents
from .agents import Agent, Conflict, MultiAgentRegistry, RegistryIntegrityError

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_AUDIT_FREEZE = "audit.freeze.lock"


def _safe_pid_alive(pid: int) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            process_query_limited_information = 0x1000
            still_active = 259
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            open_process = kernel32.OpenProcess
            open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            open_process.restype = wintypes.HANDLE
            get_exit_code = kernel32.GetExitCodeProcess
            get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            get_exit_code.restype = wintypes.BOOL
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            handle = open_process(process_query_limited_information, False, pid)
            if not handle:
                return False
            try:
                code = wintypes.DWORD()
                return bool(get_exit_code(handle, ctypes.byref(code))) and code.value == still_active
            finally:
                close_handle(handle)
        except (AttributeError, OSError, ValueError):
            return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        return True
    except OSError:
        return False


def validate_agent_id(value: str) -> str:
    if not isinstance(value, str) or value in {".", ".."} or not _ID_RE.fullmatch(value):
        raise ValueError("agent_id must be a safe basename using only [A-Za-z0-9._-]")
    if "/" in value or "\\" in value:
        raise ValueError("agent_id cannot contain path separators")
    return value


def canonical_owned_path(root: Path, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("owned file path must be a non-empty string")
    raw = Path(value)
    if raw.is_absolute():
        raise ValueError("owned file path must be workspace-relative")
    target = (root / raw).resolve(strict=False)
    try:
        rel = target.relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"owned file path escapes workspace: {value}") from exc
    if rel in {".", ""}:
        raise ValueError("owned file path must name a file/path below the workspace")
    return os.path.normcase(rel).replace("\\", "/")


def _normalize_set(registry: MultiAgentRegistry, files: Set[str]) -> Set[str]:
    return {canonical_owned_path(registry.root, value) for value in files}


def _freeze_path(registry: MultiAgentRegistry) -> Path:
    return registry.pg / _AUDIT_FREEZE


def _audit_freeze_active(registry: MultiAgentRegistry) -> bool:
    """Return True for a live/malformed freeze; remove only provably stale locks."""
    path = _freeze_path(registry)
    if not path.exists():
        return False
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        pid = value.get("pid") if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return True
    if isinstance(pid, int) and pid > 0 and not _safe_pid_alive(pid):
        try:
            path.unlink()
            return False
        except OSError:
            return True
    return True


def _require_mutation_allowed(registry: MultiAgentRegistry) -> None:
    if _audit_freeze_active(registry):
        raise RegistryIntegrityError("workspace final-audit freeze is active; agent mutation is blocked")


def _verify_locked(registry: MultiAgentRegistry) -> bool:
    """Verify/migrate while the caller owns ``registry._write_lock``."""
    registry._refresh_from_disk()
    if registry.registry_tampered:
        return False
    if registry.registry_legacy:
        try:
            registry._migrate_legacy_locked()
            registry._refresh_from_disk()
        except (OSError, json.JSONDecodeError, UnicodeError, RegistryIntegrityError) as exc:
            registry.registry_tampered = True
            registry.registry_problem = f"legacy migration failed: {exc}"
            return False
    return not registry.registry_tampered


def _require_integrity_locked(registry: MultiAgentRegistry) -> None:
    if not _verify_locked(registry):
        raise RegistryIntegrityError(
            "agent registry integrity check failed"
            + (f": {registry.registry_problem}" if registry.registry_problem else "")
        )


def _append_locked(registry: MultiAgentRegistry, event: str, agent: Agent) -> None:
    """Append one event while the caller holds the registry transaction lock."""
    _require_integrity_locked(registry)
    rec = {"ts": time.time(), "event": event, "agent": agent.to_dict()}
    seq = registry._registry_seq + 1
    prev = registry._registry_tail
    current_hash = _agents._registry_hash(seq, prev, rec)
    envelope = {
        "format_version": _agents.REGISTRY_FORMAT_VERSION,
        "seq": seq,
        "prev": prev,
        "hash": current_hash,
        "rec": rec,
    }
    key = _agents.runtime_key(registry.root)
    if key is not None:
        envelope["auth"] = _agents.make_auth(
            key,
            _agents.REGISTRY_RECORD_DOMAIN,
            _agents._registry_auth_payload(envelope),
        )
    registry._ensure_dirs()
    with registry.registry_path.open("a", encoding="utf-8") as handle:
        handle.write(_agents._canonical(envelope) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    registry._write_head(seq, current_hash)
    registry._refresh_from_disk()
    if registry.registry_tampered:
        raise RegistryIntegrityError(
            "registry failed self-verification after append"
            + (f": {registry.registry_problem}" if registry.registry_problem else "")
        )


def _current_conflicts_locked(
    registry: MultiAgentRegistry,
    agent_id: str,
    requested: Set[str],
) -> List[Conflict]:
    conflicts: List[Conflict] = []
    now = time.time()
    for other in registry._agents.values():
        if other.agent_id == agent_id or other.state != "active":
            continue
        if now - other.last_heartbeat >= registry.owner_timeout:
            continue
        try:
            owned = _normalize_set(registry, set(other.owned_files))
        except ValueError as exc:
            registry.registry_tampered = True
            registry.registry_problem = f"invalid persisted ownership path: {exc}"
            raise RegistryIntegrityError(registry.registry_problem) from exc
        for path in sorted(requested & owned):
            conflicts.append(Conflict(path, other.agent_id, agent_id))
    return conflicts


def _copy_agent(agent: Agent) -> Agent:
    return Agent.from_dict(agent.to_dict())


def install_agent_hardening() -> None:
    if getattr(MultiAgentRegistry, "_canonical_path_hardening_installed", False):
        return

    original_write_lock = MultiAgentRegistry.write_lock

    def verify_registry_chain(self: MultiAgentRegistry) -> bool:
        with self._write_lock():
            return _verify_locked(self)

    def register(self: MultiAgentRegistry, agent: Agent) -> None:
        validate_agent_id(agent.agent_id)
        agent = _copy_agent(agent)
        agent.owned_files = _normalize_set(self, set(agent.owned_files))
        agent.workspace_root = str(self.root)
        agent.last_heartbeat = time.time()
        agent.state = "active"
        with self._write_lock():
            _require_mutation_allowed(self)
            _require_integrity_locked(self)
            _append_locked(self, "join", agent)

    def unregister(self: MultiAgentRegistry, agent_id: str) -> None:
        validate_agent_id(agent_id)
        with self._write_lock():
            _require_mutation_allowed(self)
            _require_integrity_locked(self)
            agent = self._agents.get(agent_id)
            if agent is not None:
                updated = _copy_agent(agent)
                updated.state = "left"
                updated.owned_files = set()
                updated.last_heartbeat = time.time()
                _append_locked(self, "leave", updated)
        lock = self.agents_dir / f"{agent_id}.lock"
        if lock.exists():
            try:
                lock.unlink()
            except OSError:
                pass

    def heartbeat(self: MultiAgentRegistry, agent_id: str, action: str = "") -> None:
        validate_agent_id(agent_id)
        with self._write_lock():
            _require_mutation_allowed(self)
            _require_integrity_locked(self)
            agent = self._agents.get(agent_id)
            if agent is None:
                raise RegistryIntegrityError(f"unknown agent: {agent_id}")
            updated = _copy_agent(agent)
            updated.last_heartbeat = time.time()
            updated.state = "active"
            if action:
                updated.current_action = action
            _append_locked(self, "heartbeat", updated)

    def update_ownership(self: MultiAgentRegistry, agent_id: str, files: Set[str]) -> None:
        validate_agent_id(agent_id)
        normalized = _normalize_set(self, set(files))
        with self._write_lock():
            _require_mutation_allowed(self)
            _require_integrity_locked(self)
            agent = self._agents.get(agent_id)
            if agent is None:
                raise RegistryIntegrityError(f"unknown agent: {agent_id}")
            updated = _copy_agent(agent)
            updated.owned_files = normalized
            updated.last_heartbeat = time.time()
            updated.state = "active"
            _append_locked(self, "ownership", updated)

    def active_agents(self: MultiAgentRegistry):
        with self._write_lock():
            if not _verify_locked(self):
                return []
            now = time.time()
            result = []
            for agent in self._agents.values():
                if agent.state != "active" or now - agent.last_heartbeat >= self.owner_timeout:
                    continue
                try:
                    clone = _copy_agent(agent)
                    clone.owned_files = _normalize_set(self, set(clone.owned_files))
                except ValueError as exc:
                    self.registry_tampered = True
                    self.registry_problem = f"invalid persisted ownership path: {exc}"
                    return []
                result.append(clone)
            return result

    def stale_agents(self: MultiAgentRegistry):
        with self._write_lock():
            if not _verify_locked(self):
                return []
            now = time.time()
            return [
                _copy_agent(agent)
                for agent in self._agents.values()
                if agent.state == "active" and now - agent.last_heartbeat >= self.owner_timeout
            ]

    def release_stale_ownership(self: MultiAgentRegistry):
        with self._write_lock():
            if not _verify_locked(self):
                return []
            now = time.time()
            released: List[str] = []
            for agent in list(self._agents.values()):
                if agent.state != "active" or now - agent.last_heartbeat < self.owner_timeout:
                    continue
                updated = _copy_agent(agent)
                if updated.owned_files:
                    released.append(updated.agent_id)
                updated.owned_files = set()
                updated.state = "stale"
                _append_locked(self, "stale", updated)
            return released

    def check_conflicts(self: MultiAgentRegistry, agent_id: str, files: Set[str]):
        validate_agent_id(agent_id)
        requested = _normalize_set(self, set(files))
        with self._write_lock():
            if not _verify_locked(self):
                return []
            return _current_conflicts_locked(self, agent_id, requested)

    def claim_files(self: MultiAgentRegistry, agent_id: str, files: Set[str], mode: str = "parallel-warn"):
        validate_agent_id(agent_id)
        normalized = _normalize_set(self, set(files))
        if mode not in {"serial", "parallel-warn", "parallel-strict"}:
            raise ValueError(f"invalid agent coordination mode: {mode}")
        with self._write_lock():
            _require_mutation_allowed(self)
            _require_integrity_locked(self)
            agent = self._agents.get(agent_id)
            if agent is None:
                raise RegistryIntegrityError(f"unknown agent: {agent_id}")
            conflicts = _current_conflicts_locked(self, agent_id, normalized)
            if conflicts and mode == "parallel-strict":
                return False, conflicts
            updated = _copy_agent(agent)
            updated.owned_files = normalized
            updated.last_heartbeat = time.time()
            updated.state = "active"
            _append_locked(self, "ownership", updated)
            return True, conflicts

    def write_lock(self: MultiAgentRegistry, agent_id: str):
        validate_agent_id(agent_id)
        _require_mutation_allowed(self)
        return original_write_lock(self, agent_id)

    def is_lock_stale(self: MultiAgentRegistry, agent_id: str) -> bool:
        validate_agent_id(agent_id)
        lock_path = self.agents_dir / f"{agent_id}.lock"
        if not lock_path.exists():
            return False
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return True
        pid = data.get("pid")
        return not (isinstance(pid, int) and not isinstance(pid, bool) and _safe_pid_alive(pid))

    MultiAgentRegistry.verify_registry_chain = verify_registry_chain
    MultiAgentRegistry.register = register
    MultiAgentRegistry.unregister = unregister
    MultiAgentRegistry.heartbeat = heartbeat
    MultiAgentRegistry.update_ownership = update_ownership
    MultiAgentRegistry.active_agents = active_agents
    MultiAgentRegistry.stale_agents = stale_agents
    MultiAgentRegistry.release_stale_ownership = release_stale_ownership
    MultiAgentRegistry.check_conflicts = check_conflicts
    MultiAgentRegistry.claim_files = claim_files
    MultiAgentRegistry.write_lock = write_lock
    MultiAgentRegistry.is_lock_stale = is_lock_stale
    MultiAgentRegistry._canonical_path_hardening_installed = True
