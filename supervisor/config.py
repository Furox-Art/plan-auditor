"""Supervisor configuration: profiles, tiers, runtime config."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List


class Profile(str, Enum):
    LIGHT = "light"
    STANDARD = "standard"
    STRICT = "strict"


class Tier(int, Enum):
    NO_LLM = 1
    SMALL_LOCAL = 2
    STRONG_LOCAL = 3
    REMOTE = 4


@dataclass
class Config:
    profile: Profile = Profile.STANDARD
    tier: Tier = Tier.NO_LLM
    mode: str = "serial"
    workspace_root: str = "."
    pg_dir: str = ".plan-auditor"
    max_attempts: int = 3
    owner_timeout_sec: int = 300
    heartbeat_sec: int = 30
    rotate_bytes: int = 2_000_000
    policies_dir: str = "policies"
    extra: Dict = field(default_factory=dict)

    @property
    def pg_path(self) -> Path:
        return Path(self.workspace_root) / self.pg_dir

    def active_layers(self) -> List[str]:
        if self.profile == Profile.LIGHT:
            return ["L0", "L2", "L3", "L10", "L13"]
        layers = [
            "L0", "L1", "L2", "L3", "L4", "L5", "L6", "L7",
            "L8", "L9", "L10", "L11", "L13", "L14",
        ]
        if self.profile == Profile.STRICT:
            layers.insert(12, "L12")
        return layers


CONFIG_FILENAME = "supervisor.json"
_VALID_MODES = {"serial", "parallel-warn", "parallel-strict"}


def _profile(value) -> Profile:
    try:
        return Profile(str(value).lower())
    except ValueError:
        return Profile.STANDARD


def _tier(value) -> Tier:
    try:
        return Tier(int(value))
    except (TypeError, ValueError):
        return Tier.NO_LLM


def load_config(workspace_root: str = ".") -> Config:
    """Load ``<root>/.plan-auditor/supervisor.json`` conservatively."""
    path = Path(workspace_root) / ".plan-auditor" / CONFIG_FILENAME
    if not path.exists():
        return Config(workspace_root=workspace_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return Config(workspace_root=workspace_root)
    if not isinstance(data, dict):
        return Config(workspace_root=workspace_root)

    mode = str(data.get("mode", "serial"))
    if mode not in _VALID_MODES:
        mode = "serial"
    return Config(
        profile=_profile(data.get("profile", "standard")),
        tier=_tier(data.get("tier", 1)),
        mode=mode,
        workspace_root=workspace_root,
        pg_dir=str(data.get("pg_dir", ".plan-auditor")),
        max_attempts=int(data.get("max_attempts", 3)),
        owner_timeout_sec=int(data.get("owner_timeout_sec", 300)),
        heartbeat_sec=int(data.get("heartbeat_sec", 30)),
        rotate_bytes=int(data.get("rotate_bytes", 2_000_000)),
        policies_dir=str(data.get("policies_dir", "policies")),
        extra=data.get("extra", {}) if isinstance(data.get("extra", {}), dict) else {},
    )
