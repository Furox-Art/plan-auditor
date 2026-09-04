"""L14 — Multi-Agent Orchestrator (parallel agent support).

Tracks concurrent agents on a shared workspace: agent registry, file
ownership, conflict detection, heartbeats, and lock management.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class Agent:
    agent_id: str
    task_id: str
    plan_id: str
    pid: Optional[int] = None
    workspace_root: str = "."
    owned_files: Set[str] = field(default_factory=set)
    current_action: str = ""
    retries: Dict[int, int] = field(default_factory=dict)
    state: str = "active"
    last_heartbeat: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "pid": self.pid,
            "workspace_root": self.workspace_root,
            "owned_files": sorted(self.owned_files),
            "current_action": self.current_action,
            "retries": {str(k): v for k, v in self.retries.items()},
            "state": self.state,
            "last_heartbeat": self.last_heartbeat,
        }


@dataclass
class Conflict:
    file_path: str
    owner_agent: str
    accessor_agent: str
    kind: str = "write_overlap"


def _now() -> float:
    return time.time()


class MultiAgentRegistry:
    def __init__(self, root: str, owner_timeout: float = 300.0):
        self.root = Path(root)
        self.pg = self.root / ".plan-auditor"
        self.agents_dir = self.pg / "agents"
        self.registry_path = self.agents_dir / "registry.jsonl"
        self.owner_timeout = owner_timeout
        self._agents: Dict[str, Agent] = {}

    def _ensure_dirs(self) -> None:
        self.agents_dir.mkdir(parents=True, exist_ok=True)

    def register(self, agent: Agent) -> None:
        agent.last_heartbeat = _now()
        self._agents[agent.agent_id] = agent
        self._append_registry_event("join", agent)

    def unregister(self, agent_id: str) -> None:
        agent = self._agents.pop(agent_id, None)
        if agent:
            self._append_registry_event("leave", agent)
            lock = self.agents_dir / ("%s.lock" % agent_id)
            if lock.exists():
                try:
                    lock.unlink()
                except OSError:
                    pass

    def heartbeat(self, agent_id: str, action: str = "") -> None:
        agent = self._agents.get(agent_id)
        if agent:
            agent.last_heartbeat = _now()
            if action:
                agent.current_action = action

    def update_ownership(self, agent_id: str, files: Set[str]) -> None:
        agent = self._agents.get(agent_id)
        if agent:
            agent.owned_files = set(files)

    def active_agents(self) -> List[Agent]:
        now = _now()
        return [a for a in self._agents.values()
                if a.state == "active" and now - a.last_heartbeat < self.owner_timeout]

    def stale_agents(self) -> List[Agent]:
        now = _now()
        return [a for a in self._agents.values()
                if now - a.last_heartbeat >= self.owner_timeout]

    def release_stale_ownership(self) -> List[str]:
        released: List[str] = []
        for agent in self.stale_agents():
            if agent.owned_files:
                released.append(agent.agent_id)
                agent.owned_files = set()
                agent.state = "stale"
        return released

    def check_conflicts(self, agent_id: str, files: Set[str]) -> List[Conflict]:
        """Detect file ownership overlap for a prospective write set."""
        conflicts: List[Conflict] = []
        self.release_stale_ownership()
        for other in self.active_agents():
            if other.agent_id == agent_id:
                continue
            overlap = files & other.owned_files
            for f in overlap:
                conflicts.append(Conflict(file_path=f, owner_agent=other.agent_id,
                                          accessor_agent=agent_id))
        return conflicts

    def _append_registry_event(self, event: str, agent: Agent) -> None:
        self._ensure_dirs()
        rec = {"ts": _now(), "event": event, "agent": agent.to_dict()}
        h = hashlib.sha256(json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest()
        line = json.dumps({"hash": h, "rec": rec}, ensure_ascii=False)
        with open(self.registry_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def write_lock(self, agent_id: str) -> Optional[Path]:
        self._ensure_dirs()
        lock_path = self.agents_dir / ("%s.lock" % agent_id)
        try:
            pid = os.getpid()
            lock_path.write_text(json.dumps({"agent_id": agent_id, "pid": pid, "ts": _now()}),
                                 encoding="utf-8")
            return lock_path
        except OSError:
            return None

    def is_lock_stale(self, agent_id: str) -> bool:
        lock_path = self.agents_dir / ("%s.lock" % agent_id)
        if not lock_path.exists():
            return False
        try:
            data = json.loads(lock_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return True
        pid = data.get("pid")
        if pid and _pid_alive(pid):
            return False
        return True


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False
