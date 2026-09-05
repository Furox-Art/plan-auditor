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
    errors: List[str] = field(default_factory=list)

    @property
    def pg_path(self) -> Path:
        return Path(self.workspace_root) / self.pg_dir

    @property
    def valid(self) -> bool:
        return not self.errors

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


def _relative_safe(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def _int_value(data: Dict, key: str, default: int, minimum: int, maximum: int,
               errors: List[str]) -> int:
    raw = data.get(key, default)
    if isinstance(raw, bool) or not isinstance(raw, int):
        errors.append(f"{key} must be an integer")
        return default
    if not minimum <= raw <= maximum:
        errors.append(f"{key} must be between {minimum} and {maximum}")
        return default
    return raw


def load_config(workspace_root: str = ".") -> Config:
    """Load and strictly validate ``.plan-auditor/supervisor.json``.

    Conservative defaults remain available for diagnostics, but every malformed
    value is retained in ``errors`` and therefore blocks the integrated gate.
    No string/float-to-integer coercion is performed at the trust boundary.
    """
    path = Path(workspace_root) / ".plan-auditor" / CONFIG_FILENAME
    if not path.exists():
        return Config(workspace_root=workspace_root)

    errors: List[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return Config(
            workspace_root=workspace_root,
            errors=[f"invalid supervisor config: {type(exc).__name__}: {exc}"],
        )
    if not isinstance(data, dict):
        return Config(workspace_root=workspace_root, errors=["supervisor config root must be an object"])

    raw_profile = data.get("profile", "standard")
    if not isinstance(raw_profile, str):
        profile = Profile.STANDARD
        errors.append("profile must be a string")
    else:
        try:
            profile = Profile(raw_profile.lower())
        except ValueError:
            profile = Profile.STANDARD
            errors.append(f"invalid profile: {raw_profile!r}")

    raw_tier = data.get("tier", 1)
    if isinstance(raw_tier, bool) or not isinstance(raw_tier, int):
        tier = Tier.NO_LLM
        errors.append(f"invalid tier: {raw_tier!r}")
    else:
        try:
            tier = Tier(raw_tier)
        except ValueError:
            tier = Tier.NO_LLM
            errors.append(f"invalid tier: {raw_tier!r}")

    raw_mode = data.get("mode", "serial")
    if not isinstance(raw_mode, str):
        mode = "serial"
        errors.append("mode must be a string")
    else:
        mode = raw_mode
        if mode not in _VALID_MODES:
            errors.append(f"invalid mode: {mode!r}")
            mode = "serial"

    raw_pg_dir = data.get("pg_dir", ".plan-auditor")
    if not isinstance(raw_pg_dir, str):
        pg_dir = ".plan-auditor"
        errors.append("pg_dir must be a string")
    else:
        pg_dir = raw_pg_dir
        if pg_dir != ".plan-auditor":
            errors.append("pg_dir is fixed to '.plan-auditor' in supervisor mode")
            pg_dir = ".plan-auditor"

    raw_policies_dir = data.get("policies_dir", "policies")
    if not isinstance(raw_policies_dir, str) or not _relative_safe(raw_policies_dir):
        policies_dir = "policies"
        errors.append("policies_dir must be a non-empty relative path inside the workspace")
    else:
        policies_dir = raw_policies_dir

    raw_extra = data.get("extra", {})
    if not isinstance(raw_extra, dict):
        extra: Dict = {}
        errors.append("extra must be an object")
    else:
        extra = raw_extra

    return Config(
        profile=profile,
        tier=tier,
        mode=mode,
        workspace_root=workspace_root,
        pg_dir=pg_dir,
        max_attempts=_int_value(data, "max_attempts", 3, 1, 100, errors),
        owner_timeout_sec=_int_value(data, "owner_timeout_sec", 300, 1, 86_400, errors),
        heartbeat_sec=_int_value(data, "heartbeat_sec", 30, 1, 3_600, errors),
        rotate_bytes=_int_value(data, "rotate_bytes", 2_000_000, 1_024, 1_000_000_000, errors),
        policies_dir=policies_dir,
        extra=extra,
        errors=errors,
    )
