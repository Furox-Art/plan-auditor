"""Symlink-safe workspace/control-plane path confinement helpers.

All Plan Auditor metadata and configured policy paths must remain lexically and
physically below the selected workspace.  Existing path components are checked
with ``lstat`` so a symlinked parent cannot redefine the confinement root.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Iterable


class ControlPlanePathError(ValueError):
    """Raised when a trusted control-plane path is unsafe or escapes workspace."""


def _parts(value: str | Path) -> tuple[str, ...]:
    path = Path(value)
    if path.is_absolute():
        raise ControlPlanePathError("control-plane path must be workspace-relative")
    parts = path.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ControlPlanePathError("control-plane path must not contain empty, '.' or '..' components")
    if os.path.splitdrive(str(value))[0]:
        raise ControlPlanePathError("control-plane path must not contain a drive prefix")
    return tuple(parts)


def _assert_no_symlink_components(workspace: Path, parts: Iterable[str]) -> Path:
    current = workspace
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            # Remaining lexical components are still below the already-validated
            # workspace; callers may create them later.
            continue
        except OSError as exc:
            raise ControlPlanePathError(f"cannot inspect control-plane path {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ControlPlanePathError(f"control-plane path component is a symlink: {current}")
    return current


def confined_workspace_path(
    root: str | Path,
    relative: str | Path,
    *,
    require_exists: bool = False,
    require_directory: bool = False,
    require_file: bool = False,
) -> Path:
    """Return a workspace-confined path while rejecting symlinked components.

    ``relative`` is interpreted lexically under the resolved workspace.  Every
    existing component is inspected with ``lstat`` before any ``resolve`` based
    containment check, preventing a symlinked ``.plan-auditor``/``plans``/
    ``policies`` parent from moving the effective trust root outside workspace.
    """
    workspace = Path(root).expanduser().resolve()
    if not workspace.is_dir():
        raise ControlPlanePathError(f"workspace is not a directory: {workspace}")
    parts = _parts(relative)
    target = _assert_no_symlink_components(workspace, parts)

    # Existing parents were proven non-symlink. ``strict=False`` is therefore a
    # second, physical containment assertion rather than the primary defense.
    resolved = target.resolve(strict=False)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ControlPlanePathError(f"control-plane path escapes workspace: {relative}") from exc

    if require_exists and not target.exists():
        raise ControlPlanePathError(f"required control-plane path does not exist: {target}")
    if require_directory and target.exists() and not target.is_dir():
        raise ControlPlanePathError(f"control-plane path is not a directory: {target}")
    if require_file and target.exists() and not target.is_file():
        raise ControlPlanePathError(f"control-plane path is not a file: {target}")
    return target


def ensure_control_plane_root(root: str | Path) -> Path:
    """Validate ``.plan-auditor`` itself and return its lexical workspace path."""
    return confined_workspace_path(root, ".plan-auditor")
