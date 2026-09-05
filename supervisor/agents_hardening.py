"""Runtime hardening wrappers for the persisted multi-agent registry.

Kept separate from the registry codec so v1/v2 migration logic stays stable.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Set

from .agents import Agent, Conflict, MultiAgentRegistry, RegistryIntegrityError

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


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


def install_agent_hardening() -> None:
    if getattr(MultiAgentRegistry, "_canonical_path_hardening_installed", False):
        return

    original_register = MultiAgentRegistry.register
    original_unregister = MultiAgentRegistry.unregister
    original_heartbeat = MultiAgentRegistry.heartbeat
    original_update = MultiAgentRegistry.update_ownership
    original_active = MultiAgentRegistry.active_agents
    original_write_lock = MultiAgentRegistry.write_lock
    original_is_lock_stale = MultiAgentRegistry.is_lock_stale

    def register(self: MultiAgentRegistry, agent: Agent) -> None:
        validate_agent_id(agent.agent_id)
        agent.owned_files = _normalize_set(self, set(agent.owned_files))
        original_register(self, agent)

    def unregister(self: MultiAgentRegistry, agent_id: str) -> None:
        validate_agent_id(agent_id)
        original_unregister(self, agent_id)

    def heartbeat(self: MultiAgentRegistry, agent_id: str, action: str = "") -> None:
        validate_agent_id(agent_id)
        original_heartbeat(self, agent_id, action=action)

    def update_ownership(self: MultiAgentRegistry, agent_id: str, files: Set[str]) -> None:
        validate_agent_id(agent_id)
        original_update(self, agent_id, _normalize_set(self, set(files)))

    def active_agents(self: MultiAgentRegistry):
        agents = original_active(self)
        try:
            for agent in agents:
                agent.owned_files = _normalize_set(self, set(agent.owned_files))
        except ValueError as exc:
            self.registry_tampered = True
            self.registry_problem = f"invalid persisted ownership path: {exc}"
            return []
        return agents

    def check_conflicts(self: MultiAgentRegistry, agent_id: str, files: Set[str]):
        validate_agent_id(agent_id)
        requested = _normalize_set(self, set(files))
        if not self.verify_registry_chain():
            return []
        self.release_stale_ownership()
        self._refresh_from_disk()
        conflicts = []
        now = time.time()
        for other in self._agents.values():
            if other.agent_id == agent_id or other.state != "active":
                continue
            if now - other.last_heartbeat >= self.owner_timeout:
                continue
            try:
                owned = _normalize_set(self, set(other.owned_files))
            except ValueError as exc:
                self.registry_tampered = True
                self.registry_problem = f"invalid persisted ownership path: {exc}"
                return []
            for path in sorted(requested & owned):
                conflicts.append(Conflict(path, other.agent_id, agent_id))
        return conflicts

    def claim_files(self: MultiAgentRegistry, agent_id: str, files: Set[str], mode: str = "parallel-warn"):
        validate_agent_id(agent_id)
        normalized = _normalize_set(self, set(files))
        if not self.verify_registry_chain():
            return False, []
        conflicts = check_conflicts(self, agent_id, normalized)
        if conflicts and mode == "parallel-strict":
            return False, conflicts
        update_ownership(self, agent_id, normalized)
        return agent_id in self._agents, conflicts

    def write_lock(self: MultiAgentRegistry, agent_id: str):
        validate_agent_id(agent_id)
        return original_write_lock(self, agent_id)

    def is_lock_stale(self: MultiAgentRegistry, agent_id: str) -> bool:
        validate_agent_id(agent_id)
        return original_is_lock_stale(self, agent_id)

    MultiAgentRegistry.register = register
    MultiAgentRegistry.unregister = unregister
    MultiAgentRegistry.heartbeat = heartbeat
    MultiAgentRegistry.update_ownership = update_ownership
    MultiAgentRegistry.active_agents = active_agents
    MultiAgentRegistry.check_conflicts = check_conflicts
    MultiAgentRegistry.claim_files = claim_files
    MultiAgentRegistry.write_lock = write_lock
    MultiAgentRegistry.is_lock_stale = is_lock_stale
    MultiAgentRegistry._canonical_path_hardening_installed = True
