"""L14 — Multi-Agent Orchestrator with persisted shared state.

The registry is append-only. Every public read refreshes from disk so separate
agent processes observe the same ownership and heartbeat information.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


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

    @classmethod
    def from_dict(cls, data: Dict) -> "Agent":
        retries: Dict[int, int] = {}
        for key, value in dict(data.get("retries", {})).items():
            try:
                retries[int(key)] = int(value)
            except (TypeError, ValueError):
                pass
        return cls(
            agent_id=str(data.get("agent_id", "")),
            task_id=str(data.get("task_id", "")),
            plan_id=str(data.get("plan_id", "")),
            pid=data.get("pid") if isinstance(data.get("pid"), int) else None,
            workspace_root=str(data.get("workspace_root", ".")),
            owned_files=set(data.get("owned_files", []) or []),
            current_action=str(data.get("current_action", "")),
            retries=retries,
            state=str(data.get("state", "active")),
            last_heartbeat=float(data.get("last_heartbeat", 0.0) or 0.0),
        )


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
        self.root = Path(root).resolve()
        self.pg = self.root / ".plan-auditor"
        self.agents_dir = self.pg / "agents"
        self.registry_path = self.agents_dir / "registry.jsonl"
        self.owner_timeout = owner_timeout
        self._agents: Dict[str, Agent] = {}
        self.registry_tampered = False
        self._refresh_from_disk()

    def _ensure_dirs(self) -> None:
        self.agents_dir.mkdir(parents=True, exist_ok=True)

    def _refresh_from_disk(self) -> None:
        agents: Dict[str, Agent] = {}
        tampered = False
        if self.registry_path.exists():
            try:
                lines = self.registry_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
                tampered = True
            for line in lines:
                if not line.strip():
                    continue
                try:
                    envelope = json.loads(line)
                    rec = envelope.get("rec", {})
                    expected = hashlib.sha256(json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest()
                    if envelope.get("hash") != expected:
                        tampered = True
                    raw = rec.get("agent", {})
                    agent = Agent.from_dict(raw)
                    if not agent.agent_id:
                        continue
                    if rec.get("event") == "leave":
                        agents.pop(agent.agent_id, None)
                    else:
                        agents[agent.agent_id] = agent
                except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
                    tampered = True
        self._agents = agents
        self.registry_tampered = tampered

    def verify_registry_chain(self) -> bool:
        self._refresh_from_disk()
        return not self.registry_tampered

    def register(self, agent: Agent) -> None:
        self._refresh_from_disk()
        agent.workspace_root = str(self.root)
        agent.last_heartbeat = _now()
        agent.state = "active"
        self._agents[agent.agent_id] = agent
        self._append_registry_event("join", agent)

    def unregister(self, agent_id: str) -> None:
        self._refresh_from_disk()
        agent = self._agents.pop(agent_id, None)
        if agent:
            agent.state = "left"
            self._append_registry_event("leave", agent)
        lock = self.agents_dir / ("%s.lock" % agent_id)
        if lock.exists():
            try:
                lock.unlink()
            except OSError:
                pass

    def heartbeat(self, agent_id: str, action: str = "") -> None:
        self._refresh_from_disk()
        agent = self._agents.get(agent_id)
        if agent:
            agent.last_heartbeat = _now()
            agent.state = "active"
            if action:
                agent.current_action = action
            self._append_registry_event("heartbeat", agent)

    def update_ownership(self, agent_id: str, files: Set[str]) -> None:
        self._refresh_from_disk()
        agent = self._agents.get(agent_id)
        if agent:
            agent.owned_files = set(files)
            agent.last_heartbeat = _now()
            self._append_registry_event("ownership", agent)

    def claim_files(self, agent_id: str, files: Set[str], mode: str = "parallel-warn") -> Tuple[bool, List[Conflict]]:
        conflicts = self.check_conflicts(agent_id, files)
        if conflicts and mode == "parallel-strict":
            return False, conflicts
        self.update_ownership(agent_id, files)
        return agent_id in self._agents, conflicts

    def active_agents(self) -> List[Agent]:
        self._refresh_from_disk()
        now = _now()
        return [a for a in self._agents.values()
                if a.state == "active" and now - a.last_heartbeat < self.owner_timeout]

    def stale_agents(self) -> List[Agent]:
        self._refresh_from_disk()
        now = _now()
        return [a for a in self._agents.values()
                if a.state == "active" and now - a.last_heartbeat >= self.owner_timeout]

    def release_stale_ownership(self) -> List[str]:
        self._refresh_from_disk()
        now = _now()
        released: List[str] = []
        for agent in list(self._agents.values()):
            if agent.state == "active" and now - agent.last_heartbeat >= self.owner_timeout:
                if agent.owned_files:
                    released.append(agent.agent_id)
                agent.owned_files = set()
                agent.state = "stale"
                self._append_registry_event("stale", agent)
        return released

    def check_conflicts(self, agent_id: str, files: Set[str]) -> List[Conflict]:
        self.release_stale_ownership()
        self._refresh_from_disk()
        conflicts: List[Conflict] = []
        now = _now()
        for other in self._agents.values():
            if other.agent_id == agent_id or other.state != "active":
                continue
            if now - other.last_heartbeat >= self.owner_timeout:
                continue
            for path in files & other.owned_files:
                conflicts.append(Conflict(path, other.agent_id, agent_id))
        return conflicts

    def _append_registry_event(self, event: str, agent: Agent) -> None:
        self._ensure_dirs()
        rec = {"ts": _now(), "event": event, "agent": agent.to_dict()}
        h = hashlib.sha256(json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest()
        line = json.dumps({"hash": h, "rec": rec}, ensure_ascii=False)
        with self.registry_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        self._agents[agent.agent_id] = Agent.from_dict(agent.to_dict())

    def write_lock(self, agent_id: str) -> Optional[Path]:
        self._ensure_dirs()
        lock_path = self.agents_dir / ("%s.lock" % agent_id)
        try:
            lock_path.write_text(json.dumps({"agent_id": agent_id, "pid": os.getpid(), "ts": _now()}),
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
