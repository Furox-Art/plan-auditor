"""Deterministic supervisor environment contract used by plan seals."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

from .config import Config
from .control_plane import ControlPlanePathError, confined_workspace_path


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _policy_directory(workspace: Path, relative: str) -> Path:
    try:
        return confined_workspace_path(
            workspace, relative, require_directory=True
        )
    except ControlPlanePathError as exc:
        raise ValueError(f"unsafe policy directory {relative!r}: {exc}") from exc


def policy_fingerprint(root: str | Path, cfg: Config) -> str:
    workspace = Path(root).resolve()
    candidates = [cfg.policies_dir, ".plan-auditor/policies"]
    entries: list[dict[str, str]] = []
    seen: set[Path] = set()
    for relative in candidates:
        directory = _policy_directory(workspace, relative)
        if not directory.exists():
            continue
        # Directory components were lstat-validated by confined_workspace_path.
        canonical_directory = directory.resolve(strict=True)
        if canonical_directory in seen:
            continue
        seen.add(canonical_directory)
        for path in sorted(directory.iterdir()):
            if path.suffix.lower() not in {".json", ".toml"}:
                continue
            if path.is_symlink():
                raise ValueError(f"policy file is a symlink: {path}")
            if not path.is_file():
                continue
            try:
                safe = confined_workspace_path(
                    workspace, path.relative_to(workspace), require_file=True
                )
                data = safe.read_bytes()
                rel = safe.relative_to(workspace).as_posix()
            except (ControlPlanePathError, OSError, ValueError) as exc:
                raise ValueError(f"cannot fingerprint policy file {path}: {exc}") from exc
            entries.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest()})
    return hashlib.sha256(_canonical(entries)).hexdigest()


def environment_contract(root: str | Path, cfg: Config) -> Dict[str, Any]:
    from .request_contract import verify_request_contract

    request = verify_request_contract(root)
    return {
        "profile": cfg.profile.value,
        "mode": cfg.mode,
        "tier": int(cfg.tier),
        "max_attempts": int(cfg.max_attempts),
        "owner_timeout_sec": int(cfg.owner_timeout_sec),
        "heartbeat_sec": int(cfg.heartbeat_sec),
        "rotate_bytes": int(cfg.rotate_bytes),
        "policies_dir": cfg.policies_dir,
        "policies_sha256": policy_fingerprint(root, cfg),
        "request_sha256": request.request_sha256 if request.valid else None,
    }
