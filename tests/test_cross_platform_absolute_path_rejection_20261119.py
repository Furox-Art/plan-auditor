"""Absolute paths are rejected under both path flavours on every host OS.

``ntpath.isabs()`` calls ``/tmp/x`` drive-relative (not absolute) on Windows,
and ``posixpath`` never sees ``C:/x``, ``C:x`` or a UNC root. A validator that
only asks the host's ``os.path`` therefore accepts an absolute path authored on
the *other* OS. These tests pin the cross-platform contract for the plan
grammar's ``safe_relative`` gate (file/regex check paths and snapshot entries)
without any platform skip: the same inputs must fail on Linux and Windows.
"""

from __future__ import annotations

import pytest

from scripts import audit_check as core

ABSOLUTE_PATHS = [
    "/tmp/outside",  # POSIX-absolute; ntpath treats it as drive-relative
    "\\tmp\\outside",  # rooted Windows path without a drive
    "C:/outside",  # Windows-absolute, forward slashes
    "C:\\outside",  # Windows-absolute, backslashes
    "C:outside",  # drive-relative Windows path
    "//server/share/outside",  # UNC root
    "\\\\server\\share\\outside",  # UNC root, backslashes
]


def plan():
    return {
        "task": "reproduce audited evidence",
        "created": "2026-11-19T02:00:00Z",
        "steps": [
            {
                "id": 1,
                "title": "verify collected records",
                "depends_on": [],
                "verify": [{"type": "pytest", "args": ["tests", "-q"]}],
            }
        ],
    }


@pytest.mark.parametrize("kind", ["file_exists", "regex"])
@pytest.mark.parametrize("path", ABSOLUTE_PATHS)
def test_file_based_checks_reject_absolute_paths_from_either_os(kind, path):
    p = plan()
    check = {"type": kind, "path": path}
    if kind == "regex":
        check["pattern"] = "matches"
    p["steps"][0]["verify"].append(check)
    errs = core.validate_plan(p)
    assert any("safe relative" in e for e in errs), errs


@pytest.mark.parametrize("path", ABSOLUTE_PATHS)
def test_snapshot_entries_reject_absolute_paths_from_either_os(path):
    p = plan()
    p["snapshot"] = [path]
    errs = core.validate_plan(p)
    assert any("snapshot: must be a list of safe relative" in e for e in errs), errs


@pytest.mark.parametrize(
    "path", ["evidence.txt", "nested/evidence.txt", "nested\\evidence.txt"]
)
def test_genuinely_relative_paths_still_validate_on_every_host(path):
    p = plan()
    p["steps"][0]["verify"].append({"type": "file_exists", "path": path})
    p["snapshot"] = [path]
    assert core.validate_plan(p) == []
