"""Opt-in Linux privilege separation for project-controlled verification checks.

This is a UID/GID security boundary, not a container, seccomp or kernel sandbox.
A trusted root-owned supervisor and a root-owned key/control plane are required.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path
from typing import Any

MODE_ENV = "PLAN_AUDITOR_CHECK_ISOLATION"
UID_ENV = "PLAN_AUDITOR_CHECK_UID"
GID_ENV = "PLAN_AUDITOR_CHECK_GID"
KEY_ENV = "PLAN_AUDITOR_HMAC_KEY"
KEY_FILE_ENV = "PLAN_AUDITOR_HMAC_KEY_FILE"

# The isolated child must not inherit arbitrary supervisor secrets.
_SAFE_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM", "PYTHONIOENCODING", "PYTHONUTF8")


class CheckIsolationError(ValueError):
    """Refuse execution if the requested OS boundary cannot be established."""


def _positive_id(raw: str | None, name: str) -> int:
    if not raw or not raw.isascii() or not raw.isdecimal():
        raise CheckIsolationError(f"{name} must be a positive numeric Linux ID")
    value = int(raw)
    if not 0 < value < 2**31:
        raise CheckIsolationError(f"{name} must be a non-root Linux ID")
    return value


def _root_owned_private_control(root: Path) -> None:
    workspace = root.resolve(strict=True)
    # The agent must not be able to rename the workspace itself through a
    # writable ancestor: private permissions on .plan-auditor alone are not enough.
    for current in (workspace, *workspace.parents):
        st = current.stat()
        if st.st_uid != 0 or not stat.S_ISDIR(st.st_mode):
            raise CheckIsolationError("workspace and ancestors must be root-owned directories")
        if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
            raise CheckIsolationError(
                "writable workspace/ancestor directories require root ownership and the sticky bit"
            )
    control = workspace / ".plan-auditor"
    try:
        control_stat = control.lstat()
    except OSError as exc:
        raise CheckIsolationError(f"cannot inspect trusted control directory: {exc}") from exc
    if (not stat.S_ISDIR(control_stat.st_mode)
            or control_stat.st_uid != 0 or control_stat.st_mode & 0o077):
        raise CheckIsolationError(
            "isolated checks require a root-owned, private (0700) .plan-auditor directory"
        )


def _private_root_key_file(root: Path) -> None:
    value = os.environ.get(KEY_FILE_ENV)
    if not value:
        return
    supplied = Path(value).expanduser()
    if supplied.is_symlink():
        raise CheckIsolationError("isolated checks reject HMAC key symlinks")
    try:
        path = supplied.resolve(strict=True)
        info = path.stat()
    except OSError as exc:
        raise CheckIsolationError(f"cannot inspect HMAC key: {exc}") from exc
    if path.is_relative_to(root):
        raise CheckIsolationError("HMAC key must be outside the workspace")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise CheckIsolationError("isolated checks require a root-owned 0600 HMAC key file")
    # Neither the check user nor the agent should be able to replace the key
    # by writing to one of its parent directories.
    for parent in path.parents:
        parent_stat = parent.stat()
        if parent_stat.st_uid != 0 or parent_stat.st_mode & 0o022:
            raise CheckIsolationError("HMAC key directory chain must be root-owned and non-writable")


def check_launch_options(base: str | os.PathLike[str]) -> dict[str, Any]:
    """Return safe subprocess options; fail closed on partial/invalid configuration."""
    mode = os.environ.get(MODE_ENV)
    uid_raw = os.environ.get(UID_ENV)
    gid_raw = os.environ.get(GID_ENV)
    child_env = os.environ.copy()
    child_env.pop(KEY_ENV, None)
    child_env.pop(KEY_FILE_ENV, None)
    if mode is None and uid_raw is None and gid_raw is None:
        return {"env": child_env}
    if mode != "required":
        raise CheckIsolationError(
            "check identity settings require PLAN_AUDITOR_CHECK_ISOLATION=required"
        )
    if not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise CheckIsolationError("required check isolation only supports a trusted root-run Linux verifier")
    uid = _positive_id(uid_raw, UID_ENV)
    gid = _positive_id(gid_raw, GID_ENV)
    root = Path(base).resolve(strict=True)
    _root_owned_private_control(root)
    _private_root_key_file(root)
    # Never pass through arbitrary environment variables such as API tokens,
    # HOME, GITHUB_TOKEN, SSH_AUTH_SOCK or the verifier's Python import paths.
    isolated_env = {k: os.environ[k] for k in _SAFE_ENV if k in os.environ}
    isolated_env["HOME"] = "/nonexistent"
    isolated_env["PYTHONDONTWRITEBYTECODE"] = "1"
    return {
        "env": isolated_env,
        "user": uid,
        "group": gid,
        "extra_groups": [],
    }
