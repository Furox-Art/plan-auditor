"""Deterministic unit contracts for the isolation prerequisites and PASS coverage.

The positive identity test simulates root privileges only at the syscall
boundary. It does not assert that an unprivileged environment provides real
kernel UID separation; the kernel integration suite is a separate gate.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_isolation as iso
from supervisor.coverage import CoverageResult, analyze_coverage


def _requirement(id_: str, priority: str = "must", desc: str = "evidence") -> dict:
    return {"id": id_, "priority": priority, "description": desc}


def _step(id_: object, covers: object) -> dict:
    return {"id": id_, "covers": covers}


def test_complete_plan_requires_explicit_unique_requirement_ids() -> None:
    plan = {
        "requirements": [
            "First need",
            _requirement("S", "should"),
            _requirement("M", "may"),
        ],
        "steps": [_step(1, ["REQ-001", "S"])],
    }
    report = analyze_coverage(plan)
    assert isinstance(report, CoverageResult)
    assert report.valid
    assert report.required_ids == ["REQ-001", "S"]
    assert report.mapping["M"] == []
    assert report.as_dict()["covered_ids"] == ["REQ-001", "S"]


@pytest.mark.parametrize(
    ("requirements", "expected"),
    [
        ([], "explicit non-empty"),
        ("text", "explicit non-empty"),
        ([123], "must be an object or string"),
        ([{"id": "", "description": "what"}], "non-empty id"),
        ([_requirement("A"), _requirement("A")], "duplicate requirement id"),
        ([_requirement("A", desc="")], "non-empty description"),
        ([_requirement("A", priority="ALMOST")], "invalid priority"),
    ],
)
def test_requirement_gate_rejects_malformed_or_ambiguous_claims(requirements, expected):
    result = analyze_coverage({"requirements": requirements, "steps": []})
    assert not result.valid
    assert expected in ";".join(result.errors)


@pytest.mark.parametrize(
    ("covers", "expected"),
    [
        ("REQ", "covers must be a list"),
        ([False], "invalid requirement id"),
        (["R", "R"], "repeats coverage"),
        (["absent"], "unknown requirement"),
    ],
)
def test_malformed_step_coverage_fails_closed(covers, expected):
    plan = {"requirements": [_requirement("R")], "steps": [_step(1, covers)]}
    report = analyze_coverage(plan)
    assert not report.valid
    assert expected in ";".join(report.errors)


def test_coverage_rejects_noninteger_step_ids_without_crediting_them():
    plan = {
        "requirements": [_requirement("R")],
        "steps": [
            "untrusted",
            _step("not-numeric", ["R"]),
            _step(10, None),
            _step(11, ["R"]),
        ],
    }
    result = analyze_coverage(plan)
    assert not result.valid
    assert "step id must be a positive integer" in ";".join(result.errors)
    assert result.mapping == {"R": [11]}
    assert result.missing_ids == []


@pytest.mark.parametrize("bad_id", [True, False, None, 0, -1, "1", 1.0])
def test_boolean_or_nonpositive_step_id_cannot_falsely_prove_coverage(bad_id):
    report = analyze_coverage({
        "requirements": [_requirement("R")],
        "steps": [_step(bad_id, ["R"])],
    })
    assert not report.valid
    assert report.mapping == {"R": []}
    assert report.missing_ids == ["R"]
    assert "step id must be a positive integer" in ";".join(report.errors)


def test_uncovered_must_is_failure_even_when_may_is_covered():
    result = analyze_coverage({
        "requirements": [_requirement("A"), _requirement("B", "may")],
        "steps": [_step(7, ["B"])],
    })
    assert not result.valid
    assert result.missing_ids == ["A"]
    assert "not covered" in result.errors[-1]


@pytest.mark.parametrize("raw", [None, "", "-1", "0", "0x10", " 1", "+1", "1.0", "²", str(2**31)])
def test_isolation_identity_must_be_canonical_nonroot_id(raw):
    with pytest.raises(iso.CheckIsolationError):
        iso._positive_id(raw, iso.UID_ENV)


def test_isolation_identity_accepts_deterministic_nonroot_ids():
    assert iso._positive_id("1001", iso.GID_ENV) == 1001
    assert iso._positive_id(str(2**31 - 1), iso.UID_ENV) == 2**31 - 1


def test_disabled_isolation_strips_secrets_even_without_user_switch(monkeypatch):
    monkeypatch.delenv(iso.MODE_ENV, raising=False)
    monkeypatch.delenv(iso.UID_ENV, raising=False)
    monkeypatch.delenv(iso.GID_ENV, raising=False)
    monkeypatch.setenv(iso.KEY_ENV, "never-log-this")
    monkeypatch.setenv(iso.KEY_FILE_ENV, "/private/key")
    options = iso.check_launch_options("/path/does/not/need/to/exist")
    assert iso.KEY_ENV not in options["env"]
    assert iso.KEY_FILE_ENV not in options["env"]
    assert "user" not in options


@pytest.mark.parametrize("mode", [None, "", "optional", "REQUIRED"])
def test_identity_settings_require_explicit_isolation(monkeypatch, mode):
    if mode is None:
        monkeypatch.delenv(iso.MODE_ENV, raising=False)
    else:
        monkeypatch.setenv(iso.MODE_ENV, mode)
    monkeypatch.setenv(iso.UID_ENV, "1001")
    monkeypatch.setenv(iso.GID_ENV, "1001")
    with pytest.raises(iso.CheckIsolationError, match="ISOLATION=required"):
        iso.check_launch_options("/no/workspace")


@pytest.mark.skipif(os.name == "nt", reason="os.geteuid is unavailable on Windows")
def test_requested_isolation_rejects_unprivileged_linux(monkeypatch):
    monkeypatch.setenv(iso.MODE_ENV, "required")
    monkeypatch.setenv(iso.UID_ENV, "1001")
    monkeypatch.setenv(iso.GID_ENV, "1001")
    monkeypatch.setattr(iso.os, "geteuid", lambda: 1001)
    with pytest.raises(iso.CheckIsolationError, match="root-run Linux verifier"):
        iso.check_launch_options("/no/workspace")


@pytest.mark.skipif(os.name == "nt", reason="os.geteuid is unavailable on Windows")
def test_privilege_switch_constructs_minimal_child_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setenv(iso.MODE_ENV, "required")
    monkeypatch.setenv(iso.UID_ENV, "1001")
    monkeypatch.setenv(iso.GID_ENV, "1002")
    monkeypatch.setenv("PRIVATE_API_TOKEN", "secret")
    monkeypatch.setenv("PATH", "/safe/bin")
    monkeypatch.setattr(iso.os, "geteuid", lambda: 0)
    monkeypatch.setattr(iso, "_root_owned_private_control", lambda path: None)
    monkeypatch.setattr(iso, "_private_root_key_file", lambda path: None)
    opts = iso.check_launch_options(tmp_path)
    assert opts["user"] == 1001 and opts["group"] == 1002
    assert opts["extra_groups"] == []
    assert opts["env"]["HOME"] == "/nonexistent"
    assert opts["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    assert opts["env"]["PATH"] == "/safe/bin"
    assert "PRIVATE_API_TOKEN" not in opts["env"]
    assert iso.MODE_ENV not in opts["env"]


class FakePath:
    def __init__(self, name, *, mode=stat.S_IFDIR | 0o700, uid=0, parents=()):
        self.name = name
        self.mode = mode
        self.uid = uid
        self.parents = tuple(parents)
        self.children = {}

    def resolve(self, strict=False):
        return self

    def stat(self):
        return SimpleNamespace(st_mode=self.mode, st_uid=self.uid)

    def lstat(self):
        return self.stat()

    def __truediv__(self, name):
        return self.children[name]


@pytest.mark.parametrize(
    ("owner", "mode", "message"),
    [
        (1000, stat.S_IFDIR | 0o700, "root-owned"),
        (0, stat.S_IFREG | 0o700, "root-owned"),
        (0, stat.S_IFDIR | 0o777, "sticky bit"),
    ],
)
def test_root_control_refuses_untrusted_workspace_ancestry(owner, mode, message):
    workspace = FakePath("workspace", mode=mode, uid=owner)
    with pytest.raises(iso.CheckIsolationError, match=message):
        iso._root_owned_private_control(workspace)


@pytest.mark.parametrize(
    ("uid", "mode"),
    [
        (1001, stat.S_IFDIR | 0o700),
        (0, stat.S_IFDIR | 0o770),
        (0, stat.S_IFLNK | 0o700),
    ],
)
def test_root_control_refuses_nonprivate_or_nonroot_state(uid, mode):
    workspace = FakePath("workspace")
    workspace.children[".plan-auditor"] = FakePath("control", uid=uid, mode=mode)
    with pytest.raises(iso.CheckIsolationError, match="private"):
        iso._root_owned_private_control(workspace)


def test_root_control_accepts_strict_private_chain():
    parent = FakePath("/tmp", mode=stat.S_IFDIR | 0o1777)
    workspace = FakePath("trusted", parents=(parent,))
    workspace.children[".plan-auditor"] = FakePath("control", mode=stat.S_IFDIR | 0o700)
    iso._root_owned_private_control(workspace)


def test_root_control_reports_unreadable_control():
    workspace = FakePath("trusted")
    with pytest.raises(KeyError):
        iso._root_owned_private_control(workspace)


def test_isolation_key_location_missing_is_noop(monkeypatch, tmp_path):
    monkeypatch.delenv(iso.KEY_FILE_ENV, raising=False)
    assert iso._private_root_key_file(tmp_path) is None


def test_isolation_key_symlinks_rejected(tmp_path: Path, monkeypatch):
    target = tmp_path / "actual"
    target.write_text("a key")
    link = tmp_path / "key"
    link.symlink_to(target)
    monkeypatch.setenv(iso.KEY_FILE_ENV, str(link))
    with pytest.raises(iso.CheckIsolationError, match="key symlinks"):
        iso._private_root_key_file(tmp_path)


def test_isolation_key_unreadable_rejected(tmp_path: Path, monkeypatch):
    monkeypatch.setenv(iso.KEY_FILE_ENV, str(tmp_path / "absent"))
    with pytest.raises(iso.CheckIsolationError, match="cannot inspect HMAC key"):
        iso._private_root_key_file(tmp_path)


def test_isolation_key_inside_workspace_rejected(tmp_path: Path, monkeypatch):
    path = tmp_path / "secret"
    path.write_text("test")
    monkeypatch.setenv(iso.KEY_FILE_ENV, str(path))
    with pytest.raises(iso.CheckIsolationError, match="outside the workspace"):
        iso._private_root_key_file(tmp_path)


def test_root_control_unreadable_metadata_fails_closed():
    workspace = FakePath("trusted")

    class Unreadable(FakePath):
        def lstat(self):
            raise OSError("restricted control directory")

    workspace.children[".plan-auditor"] = Unreadable("control")
    with pytest.raises(iso.CheckIsolationError, match="cannot inspect trusted control"):
        iso._root_owned_private_control(workspace)


class FakeKeyPath(FakePath):
    def __init__(
        self, name: str, *,
        uid: int = 0, mode: int = stat.S_IFREG | 0o600,
        parents=(), inside: bool = False,
    ):
        super().__init__(name, mode=mode, uid=uid, parents=parents)
        self.inside = inside

    def expanduser(self):
        return self

    def is_symlink(self):
        return False

    def is_relative_to(self, root):
        return self.inside


@pytest.mark.parametrize(
    ("uid", "mode"),
    [(1001, stat.S_IFREG | 0o600), (0, stat.S_IFREG | 0o640),
     (0, stat.S_IFDIR | 0o600), (0, stat.S_IFREG | 0o777)],
)
def test_isolated_root_key_must_be_private_regular_root_file(
    monkeypatch: pytest.MonkeyPatch, uid, mode,
):
    key = FakeKeyPath("/control/secret", uid=uid, mode=mode)
    monkeypatch.setenv(iso.KEY_FILE_ENV, "/control/secret")
    monkeypatch.setattr(iso, "Path", lambda path: key)
    with pytest.raises(iso.CheckIsolationError, match="root-owned 0600 HMAC"):
        iso._private_root_key_file(FakePath("workspace"))


@pytest.mark.parametrize(
    ("uid", "mode"),
    [(1001, stat.S_IFDIR | 0o700), (0, stat.S_IFDIR | 0o770)],
)
def test_isolated_root_key_rejects_untrusted_parent_chain(
    monkeypatch: pytest.MonkeyPatch, uid, mode,
):
    parent = FakePath("/control", uid=uid, mode=mode)
    key = FakeKeyPath("/control/secret", parents=(parent,))
    monkeypatch.setenv(iso.KEY_FILE_ENV, "/control/secret")
    monkeypatch.setattr(iso, "Path", lambda path: key)
    with pytest.raises(iso.CheckIsolationError, match="directory chain"):
        iso._private_root_key_file(FakePath("workspace"))


def test_isolated_root_key_valid_private_chain_reaches_positive_path(
    monkeypatch: pytest.MonkeyPatch,
):
    parent = FakePath("/control", mode=stat.S_IFDIR | 0o700, uid=0)
    key = FakeKeyPath("/control/secret", parents=(parent,))
    monkeypatch.setenv(iso.KEY_FILE_ENV, "/control/secret")
    monkeypatch.setattr(iso, "Path", lambda path: key)
    assert iso._private_root_key_file(FakePath("workspace")) is None
