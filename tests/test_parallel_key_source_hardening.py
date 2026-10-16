"""Regression coverage for HMAC key-source confusion and workspace escape."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.integrity import IntegrityKeyError, load_key


def test_key_sources_cannot_be_mixed(tmp_path: Path, monkeypatch) -> None:
    outside = tmp_path / "outside.key"
    outside.write_bytes(b"a" * 40)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY", "b" * 40)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(outside))
    with pytest.raises(IntegrityKeyError, match="only one"):
        load_key(workspace, required=True)


def test_workspace_symlink_cannot_expose_key(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    internal = workspace / "secret.key"
    internal.write_bytes(b"k" * 40)
    outside_alias = tmp_path / "alias.key"
    try:
        outside_alias.symlink_to(internal)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not supported")
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(outside_alias))
    with pytest.raises(IntegrityKeyError, match="outside the workspace"):
        load_key(workspace, required=True)


def test_short_hmac_key_is_rejected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY_FILE", raising=False)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY", "short")
    with pytest.raises(IntegrityKeyError, match="at least"):
        load_key(tmp_path, required=True)
