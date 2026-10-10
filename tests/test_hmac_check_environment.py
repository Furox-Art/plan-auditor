"""Regression tests for HMAC credential isolation from behavioral checks.

These tests cover environment inheritance only. Same-user filesystem access to
an external key file still requires OS/container isolation by the operator.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

from scripts import audit_check as core


@pytest.mark.parametrize("key_name", ["PLAN_AUDITOR_HMAC_KEY", "PLAN_AUDITOR_HMAC_KEY_FILE"])
def test_behavioral_check_does_not_inherit_hmac_credentials(tmp_path, monkeypatch, key_name):
    secret_value = "never-visible-to-checks"
    monkeypatch.setenv(key_name, secret_value)
    monkeypatch.setenv("PLAN_AUDITOR_TEST_BENIGN_VAR", "preserved")

    probe = (
        "import json, os; "
        "print(json.dumps({"
        "'key': os.getenv('PLAN_AUDITOR_HMAC_KEY'), "
        "'file': os.getenv('PLAN_AUDITOR_HMAC_KEY_FILE'), "
        "'benign': os.getenv('PLAN_AUDITOR_TEST_BENIGN_VAR')"
        "}))"
    )
    rc, state, output, overflow = core._bounded_command(
        [sys.executable, "-c", probe], str(tmp_path), 20, 8192
    )
    assert (rc, state, overflow) == (0, "ok", False), output
    assert json.loads(output.strip()) == {"key": None, "file": None, "benign": "preserved"}
    # Sanitising a child's environment must not break the parent's HMAC key.
    assert os.environ[key_name] == secret_value


def test_run_check_uses_the_sanitised_child_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY", "test-only-key-secret")
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", "/test-only/key/path")
    probe = (
        "import os, sys; "
        "sys.exit(int(bool(os.getenv('PLAN_AUDITOR_HMAC_KEY') "
        "or os.getenv('PLAN_AUDITOR_HMAC_KEY_FILE'))))"
    )
    passed, detail, tail = core.run_check(
        {"type": "run", "argv": [sys.executable, "-c", probe], "expect_exit": 0},
        str(tmp_path),
    )
    assert passed, (detail, tail)
