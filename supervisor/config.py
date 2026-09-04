"""Supervisor configuration: profiles, tiers, runtime config."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

import json
import os


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
    mode: str = "serial"  # serial | parallel-warn | parallel-strict
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
        layers = ["L0", "L2", "L3", "L10", "L13"]
        if self.profile in (Profile.STANDARD, Profile.STRICT):
            layers += ["L1", "L4", "L5", "L6", "L7", "L8", "L9", "L11", "L14"]
        if self.profile == Profile.STRICT:
            layers += ["L12"]
        if self.tier == Tier.NO_LLM:
            # L1/L5/L12 may be LLM-backed; they degrade gracefully.
            pass
        return layers


CONFIG_FILENAME = "supervisor.json"


def load_config(workspace_root: str = ".") -> Config:
    """Load supervisor config from <root>/.plan-auditor/supervisor.json."""
    path = Path(workspace_root) / ".plan-auditor" / CONFIG_FILENAME
    if not path.exists():
        return Config(workspace_root=workspace_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return Config(workspace_root=workspace_root)
    return Config(
        profile=Profile(data.get("profile", "standard")),
        tier=Tier(data.get("tier", 1)),
        mode=data.get("mode", "serial"),
        workspace_root=workspace_root,
        max_attempts=int(data.get("max_attempts", 3)),
        owner_timeout_sec=int(data.get("owner_timeout_sec", 300)),
        heartbeat_sec=int(data.get("heartbeat_sec", 30)),
        extra=data.get("extra", {}),
    )
