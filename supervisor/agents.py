"""L14 — Multi-Agent Orchestrator with persisted, hash-chained shared state.

Registry v2 records are append-only and carry ``seq + prev + hash``. A separate
head checkpoint detects tail truncation when it remains intact. Existing v1
per-record-hash registries are validated and migrated atomically on first
verification/write.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple


REGISTRY_FORMAT_VERSION = 2
REGISTRY_GENESIS = "GENESIS"
REGISTRY_LOCK_TIMEOUT = 5.0
REGISTRY_LOCK_STALE = 30.0


class RegistryIntegrityError(RuntimeError):
    """Raised when a registry mutation is attempted on untrusted state."""


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


def _canonical(value: Dict) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


def _registry_hash(seq: int, prev: str, rec: Dict) -> str:
    payload = {
        "format_version": REGISTRY_FORMAT_VERSION,
        "seq": seq,
        "prev": prev,
        "rec": rec,
    }
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _legacy_hash(rec: Dict) -> str:
    # Exact v1 encoding, retained only so existing registries can be validated
    # before the one-time migration to the chained format.
    return hashlib.sha256(json.dumps(rec, sort_keys=True).encode("utf-8")).hexdigest()


class MultiAgentRegistry:
    def __init__(self, root: str, owner_timeout: float = 300.0):
        self.root = Path(root).resolve()
        self.pg = self.root / ".plan-auditor"
        self.agents_dir = self.pg / "agents"
        self.registry_path = self.agents_dir / "registry.jsonl"
        self.head_path = self.agents_dir / "registry.head.json"
        self.lock_path = self.agents_dir / "registry.write.lock"
        self.owner_timeout = owner_timeout
        self._agents: Dict[str, Agent] = {}
        self._registry_seq = 0
        self._registry_tail = REGISTRY_GENESIS
        self.registry_tampered = False
        self.registry_legacy = False
        self.registry_problem = ""
        self._refresh_from_disk()

    def _ensure_dirs(self) -> None:
        self.agents_dir.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def _write_lock(self) -> Iterator[None]:
        """Serialize append/migration across independent agent processes."""
        self._ensure_dirs()
        deadline = time.monotonic() + REGISTRY_LOCK_TIMEOUT
        acquired = False
        while not acquired:
            try:
                fd = os.open(
                    str(self.lock_path),
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                try:
                    os.write(
                        fd,
                        json.dumps({"pid": os.getpid(), "ts": _now()}).encode("utf-8"),
                    )
                finally:
                    os.close(fd)
                acquired = True
            except FileExistsError:
                try:
                    age = _now() - self.lock_path.stat().st_mtime
                    if age > REGISTRY_LOCK_STALE:
                        self.lock_path.unlink()
                        continue
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise RegistryIntegrityError("agent registry write lock timeout")
                time.sleep(0.02)
        try:
            yield
        finally:
            try:
                self.lock_path.unlink()
            except OSError:
                pass

    def _read_head(self) -> Optional[Dict]:
        if not self.head_path.exists():
            return None
        try:
            value = json.loads(self.head_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"invalid": True}
        return value if isinstance(value, dict) else {"invalid": True}

    def _write_head(self, seq: int, tail_hash: str) -> None:
        self._ensure_dirs()
        payload = {
            "format_version": REGISTRY_FORMAT_VERSION,
            "seq": seq,
            "hash": tail_hash,
        }
        tmp = self.head_path.with_name(self.head_path.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write(_canonical(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.head_path)

    @staticmethod
    def _apply_record(agents: Dict[str, Agent], rec: Dict) -> None:
        raw = rec.get("agent", {})
        if not isinstance(raw, dict):
            return
        agent = Agent.from_dict(raw)
        if not agent.agent_id:
            return
        if rec.get("event") == "leave":
            agents.pop(agent.agent_id, None)
        else:
            agents[agent.agent_id] = agent

    def _refresh_from_disk(self) -> None:
        agents: Dict[str, Agent] = {}
        tampered = False
        legacy = False
        problem = ""
        seq = 0
        tail = REGISTRY_GENESIS
        saw_v2 = False
        saw_legacy = False

        if self.registry_path.exists():
            try:
                lines = self.registry_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError as exc:
                lines = []
                tampered = True
                problem = "registry unreadable: %s" % type(exc).__name__

            for line_no, line in enumerate(lines, 1):
                if not line.strip():
                    continue
                try:
                    envelope = json.loads(line)
                except json.JSONDecodeError:
                    tampered = True
                    problem = problem or "line %s is not JSON" % line_no
                    continue
                if not isinstance(envelope, dict):
                    tampered = True
                    problem = problem or "line %s envelope is not an object" % line_no
                    continue
                rec = envelope.get("rec")
                if not isinstance(rec, dict):
                    tampered = True
                    problem = problem or "line %s rec is not an object" % line_no
                    continue

                is_v2 = (
                    envelope.get("format_version") == REGISTRY_FORMAT_VERSION
                    and isinstance(envelope.get("seq"), int)
                    and isinstance(envelope.get("prev"), str)
                )
                if is_v2:
                    if saw_legacy:
                        tampered = True
                        problem = problem or "mixed legacy/v2 registry format"
                    saw_v2 = True
                    current_seq = envelope.get("seq")
                    actual_hash = envelope.get("hash")
                    if current_seq != seq + 1:
                        tampered = True
                        problem = problem or "line %s sequence discontinuity" % line_no
                    if envelope.get("prev") != tail:
                        tampered = True
                        problem = problem or "line %s prev hash mismatch" % line_no
                    expected_hash = _registry_hash(current_seq, envelope.get("prev"), rec)
                    if actual_hash != expected_hash:
                        tampered = True
                        problem = problem or "line %s hash mismatch" % line_no
                    seq = current_seq
                    tail = actual_hash if isinstance(actual_hash, str) else ""
                else:
                    if saw_v2:
                        tampered = True
                        problem = problem or "mixed v2/legacy registry format"
                    saw_legacy = True
                    legacy = True
                    expected_hash = _legacy_hash(rec)
                    if envelope.get("hash") != expected_hash:
                        tampered = True
                        problem = problem or "legacy line %s hash mismatch" % line_no

                self._apply_record(agents, rec)

            head = self._read_head()
            if saw_v2:
                if not isinstance(head, dict) or head.get("invalid"):
                    tampered = True
                    problem = problem or "registry head checkpoint missing or invalid"
                elif (
                    head.get("format_version") != REGISTRY_FORMAT_VERSION
                    or head.get("seq") != seq
                    or head.get("hash") != tail
                ):
                    tampered = True
                    problem = problem or "registry head checkpoint mismatch"
            elif saw_legacy:
                if head is not None:
                    tampered = True
                    problem = problem or "legacy registry unexpectedly has v2 head checkpoint"
            elif head is not None:
                tampered = True
                problem = problem or "registry head exists without records"
        elif self.head_path.exists():
            tampered = True
            problem = "registry log missing while head checkpoint exists"

        self._agents = agents
        self._registry_seq = seq
        self._registry_tail = tail
        self.registry_tampered = tampered
        self.registry_legacy = legacy
        self.registry_problem = problem

    def _legacy_records(self) -> List[Dict]:
        records: List[Dict] = []
        if not self.registry_path.exists():
            return records
        for line_no, line in enumerate(
            self.registry_path.read_text(encoding="utf-8", errors="strict").splitlines(), 1
        ):
            if not line.strip():
                continue
            envelope = json.loads(line)
            if not isinstance(envelope, dict) or not isinstance(envelope.get("rec"), dict):
                raise RegistryIntegrityError("legacy registry line %s malformed" % line_no)
            rec = envelope["rec"]
            if envelope.get("hash") != _legacy_hash(rec):
                raise RegistryIntegrityError("legacy registry line %s hash mismatch" % line_no)
            if "seq" in envelope or "prev" in envelope or "format_version" in envelope:
                raise RegistryIntegrityError("legacy registry contains mixed-format record")
            records.append(rec)
        return records

    def _migrate_legacy_locked(self) -> None:
        records = self._legacy_records()
        tmp = self.registry_path.with_name(self.registry_path.name + ".v2.tmp")
        seq = 0
        prev = REGISTRY_GENESIS
        with tmp.open("w", encoding="utf-8") as handle:
            for rec in records:
                seq += 1
                current_hash = _registry_hash(seq, prev, rec)
                envelope = {
                    "format_version": REGISTRY_FORMAT_VERSION,
                    "seq": seq,
                    "prev": prev,
                    "hash": current_hash,
                    "rec": rec,
                }
                handle.write(_canonical(envelope) + "\n")
                prev = current_hash
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.registry_path)
        if records:
            self._write_head(seq, prev)
        elif self.head_path.exists():
            self.head_path.unlink()

    def verify_registry_chain(self) -> bool:
        self._refresh_from_disk()
        if self.registry_tampered:
            return False
        if self.registry_legacy:
            try:
                with self._write_lock():
                    self._refresh_from_disk()
                    if self.registry_tampered:
                        return False
                    if self.registry_legacy:
                        self._migrate_legacy_locked()
                self._refresh_from_disk()
            except (
                OSError,
                json.JSONDecodeError,
                UnicodeError,
                RegistryIntegrityError,
            ) as exc:
                self.registry_tampered = True
                self.registry_problem = "legacy migration failed: %s" % exc
                return False
        return not self.registry_tampered

    def _require_integrity(self) -> None:
        if not self.verify_registry_chain():
            raise RegistryIntegrityError(
                "agent registry integrity check failed"
                + (": %s" % self.registry_problem if self.registry_problem else "")
            )

    def register(self, agent: Agent) -> None:
        self._require_integrity()
        agent.workspace_root = str(self.root)
        agent.last_heartbeat = _now()
        agent.state = "active"
        self._append_registry_event("join", agent)

    def unregister(self, agent_id: str) -> None:
        self._require_integrity()
        self._refresh_from_disk()
        agent = self._agents.get(agent_id)
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
        self._require_integrity()
        self._refresh_from_disk()
        agent = self._agents.get(agent_id)
        if agent:
            agent.last_heartbeat = _now()
            agent.state = "active"
            if action:
                agent.current_action = action
            self._append_registry_event("heartbeat", agent)

    def update_ownership(self, agent_id: str, files: Set[str]) -> None:
        self._require_integrity()
        self._refresh_from_disk()
        agent = self._agents.get(agent_id)
        if agent:
            agent.owned_files = set(files)
            agent.last_heartbeat = _now()
            self._append_registry_event("ownership", agent)

    def claim_files(
        self,
        agent_id: str,
        files: Set[str],
        mode: str = "parallel-warn",
    ) -> Tuple[bool, List[Conflict]]:
        if not self.verify_registry_chain():
            return False, []
        conflicts = self.check_conflicts(agent_id, files)
        if conflicts and mode == "parallel-strict":
            return False, conflicts
        self.update_ownership(agent_id, files)
        return agent_id in self._agents, conflicts

    def active_agents(self) -> List[Agent]:
        self._refresh_from_disk()
        if self.registry_tampered:
            return []
        now = _now()
        return [
            a
            for a in self._agents.values()
            if a.state == "active" and now - a.last_heartbeat < self.owner_timeout
        ]

    def stale_agents(self) -> List[Agent]:
        self._refresh_from_disk()
        if self.registry_tampered:
            return []
        now = _now()
        return [
            a
            for a in self._agents.values()
            if a.state == "active" and now - a.last_heartbeat >= self.owner_timeout
        ]

    def release_stale_ownership(self) -> List[str]:
        if not self.verify_registry_chain():
            return []
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
        if not self.verify_registry_chain():
            return []
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
        with self._write_lock():
            self._refresh_from_disk()
            if self.registry_tampered:
                raise RegistryIntegrityError(
                    "refusing registry append after integrity failure"
                    + (": %s" % self.registry_problem if self.registry_problem else "")
                )
            if self.registry_legacy:
                self._migrate_legacy_locked()
                self._refresh_from_disk()
                if self.registry_tampered:
                    raise RegistryIntegrityError("registry migration produced invalid state")

            seq = self._registry_seq + 1
            prev = self._registry_tail
            current_hash = _registry_hash(seq, prev, rec)
            envelope = {
                "format_version": REGISTRY_FORMAT_VERSION,
                "seq": seq,
                "prev": prev,
                "hash": current_hash,
                "rec": rec,
            }
            with self.registry_path.open("a", encoding="utf-8") as handle:
                handle.write(_canonical(envelope) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._write_head(seq, current_hash)

        self._refresh_from_disk()
        if self.registry_tampered:
            raise RegistryIntegrityError(
                "registry failed self-verification after append: %s" % self.registry_problem
            )
        self._agents[agent.agent_id] = Agent.from_dict(agent.to_dict())

    def write_lock(self, agent_id: str) -> Optional[Path]:
        self._ensure_dirs()
        lock_path = self.agents_dir / ("%s.lock" % agent_id)
        try:
            lock_path.write_text(
                json.dumps({"agent_id": agent_id, "pid": os.getpid(), "ts": _now()}),
                encoding="utf-8",
            )
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
