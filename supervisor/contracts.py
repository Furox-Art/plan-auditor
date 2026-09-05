"""Deterministic supervisor environment contract used by plan seals."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from .config import Config


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def policy_fingerprint(root: str | Path, cfg: Config) -> str:
    workspace = Path(root).resolve()
    candidates = [workspace / cfg.policies_dir, workspace / ".plan-auditor" / "policies"]
    entries: list[dict[str, str]] = []
    seen: set[Path] = set()
    for directory in candidates:
        directory = directory.resolve()
        if directory in seen or not directory.is_dir():
            continue
        seen.add(directory)
        for path in sorted(directory.iterdir()):
            if not path.is_file() or path.suffix.lower() not in {".json", ".toml"}:
                continue
            try:
                data = path.read_bytes()
            except OSError:
                data = b"<unreadable>"
            try:
                rel = path.resolve().relative_to(workspace).as_posix()
            except ValueError:
                rel = str(path.resolve())
            entries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest()})
    return hashlib.sha256(_canonical(entries)).hexdigest()


def environment_contract(root: str | Path, cfg: Config) -> Dict[str, Any]:
    return {
        "profile": cfg.profile.value,
        "mode": cfg.mode,
        "tier": int(cfg.tier),
        "policies_sha256": policy_fingerprint(root, cfg),
    }
