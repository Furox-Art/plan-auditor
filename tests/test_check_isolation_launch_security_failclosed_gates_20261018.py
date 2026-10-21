"""Separate unit-level argument rejection from real root OS boundary verification."""

from __future__ import annotations

import os

import pytest

from scripts import check_isolation as isolation


@pytest.mark.parametrize(
    ("supplied", "reason"),
    [
        (None, "positive numeric"),
        ("", "positive numeric"),
        ("-1", "positive numeric"),
        ("2.5", "positive numeric"),
        ("２", "positive numeric"),
        ("0", "non-root Linux ID"),
        (str(2**31), "non-root Linux ID"),
    ],
)
def test_linux_child_identity_is_never_inferred_from_invalid_user_input(supplied, reason):
    with pytest.raises(isolation.CheckIsolationError, match=reason):
        isolation._positive_id(supplied, "PLAN_AUDITOR_CHECK_UID")


@pytest.mark.parametrize("value", [1, 1000, 2**31 - 1])
def test_valid_linux_child_id_is_exactly_preserved(value):
    assert isolation._positive_id(str(value), "gid") == value


def test_default_no_isolation_mode_removes_verifier_hmac_secrets(monkeypatch, tmp_path):
    for field in (isolation.MODE_ENV, isolation.UID_ENV, isolation.GID_ENV):
        monkeypatch.delenv(field, raising=False)
    monkeypatch.setenv(isolation.KEY_ENV, "never in checked command")
    monkeypatch.setenv(isolation.KEY_FILE_ENV, "/tmp/secret")
    out = isolation.check_launch_options(str(tmp_path))
    assert "env" in out
    assert isolation.KEY_ENV not in out["env"]
    assert isolation.KEY_FILE_ENV not in out["env"]
    assert "user" not in out


@pytest.mark.parametrize(
    ("mode", "uid", "gid"),
    [
        (None, "1000", None),
        ("optional", "1000", "1000"),
        ("", None, "1000"),
    ],
)
def test_partial_child_identity_cannot_be_interpreted_as_optional_security(
    monkeypatch, tmp_path, mode, uid, gid
):
    for key, value in (
        (isolation.MODE_ENV, mode),
        (isolation.UID_ENV, uid),
        (isolation.GID_ENV, gid),
    ):
        if value is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, value)
    with pytest.raises(
        isolation.CheckIsolationError, match="require PLAN_AUDITOR_CHECK_ISOLATION=required"
    ):
        isolation.check_launch_options(str(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="Linux root-isolation path uses os.geteuid")
def test_required_isolation_cannot_be_claimed_in_unprivileged_process(monkeypatch, tmp_path):
    monkeypatch.setenv(isolation.MODE_ENV, "required")
    monkeypatch.setenv(isolation.UID_ENV, "1000")
    monkeypatch.setenv(isolation.GID_ENV, "1000")
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 1000)
    with pytest.raises(isolation.CheckIsolationError, match="trusted root-run Linux verifier"):
        isolation.check_launch_options(str(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="Linux root-isolation path uses os.geteuid")
def test_child_command_in_strict_mode_receives_only_safe_environment_allowlist(
    monkeypatch, tmp_path
):
    monkeypatch.setenv(isolation.MODE_ENV, "required")
    monkeypatch.setenv(isolation.UID_ENV, "1001")
    monkeypatch.setenv(isolation.GID_ENV, "1002")
    monkeypatch.setenv("GITHUB_TOKEN", "PRIVATE")
    monkeypatch.setenv(isolation.KEY_ENV, "PRIVATE_HMAC")
    monkeypatch.setenv("PYTHONPATH", "/injected-path")
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)
    inspected = []
    monkeypatch.setattr(
        isolation, "_root_owned_private_control", lambda root: inspected.append(root)
    )
    monkeypatch.setattr(isolation, "_private_root_key_file", lambda root: inspected.append(root))
    out = isolation.check_launch_options(str(tmp_path))
    assert inspected == [tmp_path, tmp_path]
    assert out["user"] == 1001
    assert out["group"] == 1002
    assert out["extra_groups"] == []
    assert out["env"]["HOME"] == "/nonexistent"
    assert out["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    for denied in ("PYTHONPATH", "GITHUB_TOKEN", isolation.KEY_ENV, isolation.KEY_FILE_ENV):
        assert denied not in out["env"]


@pytest.mark.skipif(os.name == "nt", reason="Linux root-isolation path uses os.geteuid")
def test_required_isolation_invokes_both_root_control_plane_and_key_checks(monkeypatch, tmp_path):
    monkeypatch.setenv(isolation.MODE_ENV, "required")
    monkeypatch.setenv(isolation.UID_ENV, "1000")
    monkeypatch.setenv(isolation.GID_ENV, "1000")
    monkeypatch.setattr(isolation.sys, "platform", "linux")
    monkeypatch.setattr(isolation.os, "geteuid", lambda: 0)

    def fail(_root):
        raise isolation.CheckIsolationError("unsafe filesystem control root")

    monkeypatch.setattr(isolation, "_root_owned_private_control", fail)
    with pytest.raises(isolation.CheckIsolationError, match="unsafe filesystem control root"):
        isolation.check_launch_options(str(tmp_path))
