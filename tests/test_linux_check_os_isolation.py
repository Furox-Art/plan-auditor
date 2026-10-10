"""Checks for the opt-in Linux root-supervisor / unprivileged-check boundary."""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

from scripts import audit_check as core
from scripts.check_isolation import CheckIsolationError, check_launch_options


def _request_isolation(monkeypatch, uid="65534", gid="65534"):
    monkeypatch.setenv("PLAN_AUDITOR_CHECK_ISOLATION", "required")
    monkeypatch.setenv("PLAN_AUDITOR_CHECK_UID", uid)
    monkeypatch.setenv("PLAN_AUDITOR_CHECK_GID", gid)


def test_partial_configuration_refuses_to_run(tmp_path, monkeypatch):
    monkeypatch.setenv("PLAN_AUDITOR_CHECK_UID", "65534")
    rc, state, reason, _overflow = core._bounded_command(
        [sys.executable, "-c", "print('must not execute')"], str(tmp_path), 5, 2048
    )
    assert rc is None and state == "start"
    assert "require PLAN_AUDITOR_CHECK_ISOLATION=required" in reason


@pytest.mark.parametrize("uid,gid", [("0", "65534"), ("65534", "0"), ("bad", "65534"), ("", "65534")])
def test_invalid_identity_fails_closed(tmp_path, monkeypatch, uid, gid):
    _request_isolation(monkeypatch, uid=uid, gid=gid)
    # Simulate a privileged host to inspect the identity validator on all OSes.
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    with pytest.raises(CheckIsolationError, match="non-root|positive"):
        check_launch_options(tmp_path)


def test_required_isolation_refuses_unprivileged_verifier(tmp_path, monkeypatch):
    _request_isolation(monkeypatch)
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(CheckIsolationError, match="root-run Linux"):
        check_launch_options(tmp_path)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="real kernel UID/GID isolation needs root-run Linux")
def test_real_unprivileged_check_cannot_read_hmac_or_control_plane(monkeypatch):
    import pwd

    check_user = pwd.getpwnam("nobody")
    # root-owned sticky workspace allows agent-owned product files without
    # permitting rename/replacement of root-owned .plan-auditor control state.
    with tempfile.TemporaryDirectory(prefix="pa-os-check-", dir="/tmp") as folder, \
            tempfile.TemporaryDirectory(prefix="pa-os-key-", dir="/root") as key_folder:
        workspace = Path(folder)
        workspace.chmod(0o1777)
        control = workspace / ".plan-auditor"
        control.mkdir(mode=0o700)
        marker = control / "seal.json"
        marker.write_text("trusted", encoding="utf-8")
        key = Path(key_folder) / "secret.key"
        key.write_text("not-a-real-credential", encoding="utf-8")
        key.chmod(0o600)

        _request_isolation(monkeypatch, str(check_user.pw_uid), str(check_user.pw_gid))
        monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key))
        monkeypatch.setenv("GITHUB_TOKEN", "do-not-inherit-test-token")
        script = (
            "import json,os,pathlib,sys;"
            "key=pathlib.Path(sys.argv[1]);control=pathlib.Path(sys.argv[2]);"
            "definitely_no_key=os.getenv('PLAN_AUDITOR_HMAC_KEY_FILE') is None;"
            "denied=[];"
            "\nfor p in (key,control):"
            "\n try: p.read_bytes();denied.append(False)"
            "\n except PermissionError: denied.append(True)"
            "\nprint(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),"
            "'denied':denied,'key_hidden':definitely_no_key,"
            "'other_secret_hidden':os.getenv('GITHUB_TOKEN') is None}))"
        )
        passed, detail, output = core.run_check(
            {"type": "run", "argv": [sys.executable, "-c", script, str(key), str(marker)],
             "expect_exit": 0, "output_regex": "key_hidden"},
            str(workspace),
        )
        assert passed, (detail, output)
        rc, state, raw, overflow = core._bounded_command(
            [sys.executable, "-c", script, str(key), str(marker)], str(workspace), 15, 8192
        )
        assert (rc, state, overflow) == (0, "ok", False), raw
        result = json.loads(raw.strip())
        assert result == {
            "uid": check_user.pw_uid, "gid": check_user.pw_gid,
            "denied": [True, True], "key_hidden": True, "other_secret_hidden": True,
        }
        assert marker.read_text(encoding="utf-8") == "trusted"
        assert stat.S_IMODE(key.stat().st_mode) == 0o600


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="real kernel filesystem policy needs root-run Linux")
def test_insecure_external_key_file_is_rejected(monkeypatch):
    import pwd

    user = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="pa-os-check-", dir="/tmp") as folder, \
            tempfile.TemporaryDirectory(prefix="pa-os-key-", dir="/root") as key_folder:
        root = Path(folder)
        root.chmod(0o1777)
        (root / ".plan-auditor").mkdir(mode=0o700)
        key = Path(key_folder) / "secret.key"
        key.write_text("test-only-key", encoding="utf-8")
        key.chmod(0o644)
        _request_isolation(monkeypatch, str(user.pw_uid), str(user.pw_gid))
        monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key))
        with pytest.raises(CheckIsolationError, match="0600"):
            check_launch_options(root)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="real Linux ownership checks need root")
def test_insecure_workspace_can_not_replace_trusted_control_state(monkeypatch):
    import pwd

    check_user = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="pa-os-check-", dir="/tmp") as folder:
        workspace = Path(folder)
        workspace.chmod(0o777)  # world writable without sticky bit
        (workspace / ".plan-auditor").mkdir(mode=0o700)
        _request_isolation(monkeypatch, str(check_user.pw_uid), str(check_user.pw_gid))
        with pytest.raises(CheckIsolationError, match="sticky bit"):
            check_launch_options(workspace)


@pytest.mark.skipif(not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0,
                    reason="real Linux ownership checks need root")
def test_insecure_control_directory_is_rejected(monkeypatch):
    import pwd

    check_user = pwd.getpwnam("nobody")
    with tempfile.TemporaryDirectory(prefix="pa-os-check-", dir="/tmp") as folder:
        workspace = Path(folder)
        workspace.chmod(0o1777)
        (workspace / ".plan-auditor").mkdir(mode=0o755)
        _request_isolation(monkeypatch, str(check_user.pw_uid), str(check_user.pw_gid))
        with pytest.raises(CheckIsolationError, match="private"):
            check_launch_options(workspace)
