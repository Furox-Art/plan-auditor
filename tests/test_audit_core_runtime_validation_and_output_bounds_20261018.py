"""Checks use real bounded subprocesses and actual file observations, never shell success."""

from __future__ import annotations

import json
import sys

import pytest

from scripts import audit_check as core


def _command(code: str, **kw):
    return {
        "type": "run",
        "argv": [sys.executable, "-c", code],
        "max_output_bytes": 1024,
        "timeout": 4,
        **kw,
    }


def test_successful_real_child_is_verified_from_return_code_and_emitted_stdout(tmp_path):
    valid, detail, output = core.run_check(_command("print('measured=42')"), str(tmp_path))
    assert valid and "exit=0" in detail
    assert "measured=42" in output


def test_real_failing_child_is_not_successful_when_expected_zero(tmp_path):
    valid, detail, output = core.run_check(_command("import sys;sys.exit(7)"), str(tmp_path))
    assert not valid
    assert "exit=7 (expected 0)" in detail


def test_real_nonzero_exit_code_may_be_an_explicit_expected_failure(tmp_path):
    valid, detail, _ = core.run_check(
        _command("import sys;sys.exit(7)", expect_exit=7), str(tmp_path)
    )
    assert valid
    assert "expected 7" in detail


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        ({"argv": []}, "argv must be a non-empty list"),
        ({"argv": [sys.executable, True]}, "argv must be a non-empty list"),
        ({"timeout": 0}, "timeout must be a number"),
        ({"timeout": True}, "timeout must be a number"),
        ({"max_output_bytes": False}, "max_output_bytes must be an int"),
        ({"max_output_bytes": 100}, "max_output_bytes must be an int"),
        ({"expect_exit": True}, "expect_exit must be an int"),
        ({"expect_exit": 256}, "expect_exit must be an int"),
    ],
)
def test_bounded_runner_refuses_invalid_process_configuration(tmp_path, bad, message):
    check = _command("print('would execute')")
    check.update(bad)
    passed, reason, output = core.run_check(check, str(tmp_path))
    assert not passed and message in reason and output == ""


def test_approved_child_execution_is_never_implicitly_a_shell(tmp_path):
    passed, detail, _ = core.run_check(
        {"type": "run", "cmd": "printf 'hello; rm data'", "shell": True}, str(tmp_path)
    )
    assert not passed
    assert "shell execution was removed" in detail


def test_missing_binary_reports_spawn_failure_without_fake_exit_zero(tmp_path):
    cmd = {"type": "run", "argv": ["/no-such-plan-auditor-executable-192487"]}
    passed, detail, output = core.run_check(cmd, str(tmp_path))
    assert not passed
    assert "command could not start" in detail
    assert output == ""


def test_hard_stdout_overflow_refuses_child_and_truncates_collected_output(tmp_path):
    cmd = _command("print('X'*5000)")
    passed, detail, output = core.run_check(cmd, str(tmp_path))
    assert not passed
    assert "output limit exceeded" in detail
    assert len(output) <= 1024


def test_real_timeout_is_not_counted_as_approved_process_execution(tmp_path):
    check = _command("import time;time.sleep(5)", timeout=0.1)
    passed, detail, _ = core.run_check(check, str(tmp_path))
    assert not passed
    assert "command timed out" in detail


@pytest.mark.parametrize(
    ("regex", "expected"),
    [
        ("measured=42", True),
        ("does-not-exist", False),
    ],
)
def test_stdout_regex_pass_requires_real_matching_observation(tmp_path, regex, expected):
    passed, detail, _ = core.run_check(
        _command("print('measured=42')", output_regex=regex), str(tmp_path)
    )
    assert passed is expected
    assert ("matched" if expected else "DID NOT MATCH") in detail


@pytest.mark.parametrize(
    ("regex", "message"),
    [
        ("", "output_regex must be a non-empty string"),
        (False, "output_regex must be a non-empty string"),
        ("[", "invalid output_regex"),
    ],
)
def test_invalid_runtime_output_regex_never_claims_pass(tmp_path, regex, message):
    passed, detail, _ = core.run_check(_command("print('hi')", output_regex=regex), str(tmp_path))
    assert not passed and message in detail


def test_file_exists_check_is_grounded_in_real_file_presence(tmp_path):
    file = tmp_path / "observed.txt"
    assert (
        core.run_check({"type": "file_exists", "path": "observed.txt"}, str(tmp_path))[0] is False
    )
    file.write_text("real file")
    passed, detail, _ = core.run_check(
        {"type": "file_exists", "path": "observed.txt"}, str(tmp_path)
    )
    assert passed and "EXISTS" in detail


@pytest.mark.parametrize("path", ["../secret", "/etc/passwd"])
def test_file_checks_cannot_escape_workspace_scope(tmp_path, path):
    passed, detail, _ = core.run_check({"type": "file_exists", "path": path}, str(tmp_path))
    assert not passed
    assert "path" in detail.lower()


def test_file_check_with_no_path_is_an_error_not_a_glob(tmp_path):
    passed, detail, _ = core.run_check({"type": "file_exists"}, str(tmp_path))
    assert not passed and "path" in detail.lower()


def test_regex_requires_actual_existing_file(tmp_path):
    passed, detail, _ = core.run_check(
        {"type": "regex", "path": "no-file", "pattern": "PASS"}, str(tmp_path)
    )
    assert not passed and "MISSING" in detail


@pytest.mark.parametrize(
    ("regex", "expected"),
    [
        ("approved", True),
        ("unrecorded", False),
    ],
)
def test_file_regex_reports_real_matching_and_negative_evidence(tmp_path, regex, expected):
    (tmp_path / "report.txt").write_text("recorded measurement approved\n", encoding="utf-8")
    passed, detail, _ = core.run_check(
        {"type": "regex", "path": "report.txt", "pattern": regex},
        str(tmp_path),
    )
    assert passed is expected
    assert ("matched" if expected else "DID NOT MATCH") in detail


def test_regex_file_truncation_is_explicitly_reported_when_not_full_scan(tmp_path):
    (tmp_path / "large.txt").write_text("A" * 1500 + "MATCH_AT_END")
    passed, detail, _ = core.run_check(
        {"type": "regex", "path": "large.txt", "pattern": "MATCH_AT_END", "max_bytes": 1024},
        str(tmp_path),
    )
    assert not passed
    assert "truncated at 1024 bytes" in detail


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"max_bytes": 1}, "max_bytes must be an int"),
        ({"max_bytes": False}, "max_bytes must be an int"),
        ({"pattern": []}, "regex pattern must be a non-empty string"),
        ({"pattern": ""}, "regex pattern must be a non-empty string"),
        ({"pattern": "["}, "invalid regex"),
    ],
)
def test_regex_configuration_refuses_invalid_unbounded_scans(tmp_path, change, message):
    (tmp_path / "observed.txt").write_text("real")
    check = {"type": "regex", "path": "observed.txt", "pattern": "real"}
    check.update(change)
    passed, detail, _ = core.run_check(check, str(tmp_path))
    assert not passed and message in detail


def test_unknown_check_type_never_gets_implicit_pass(tmp_path):
    assert core.run_check({"type": "invented-check"}, str(tmp_path)) == (
        False,
        "unknown check type: invented-check",
        "",
    )


def test_latest_hash_is_the_actual_final_nonblank_evidence_record(tmp_path):
    evidence = tmp_path / "evidence.jsonl"
    evidence.write_text('{"hash":"first"}\n{"hash":"second"}\n  \n', encoding="utf-8")
    assert core._last_record_hash(str(evidence)) == "second"


@pytest.mark.parametrize(
    "content",
    [
        "",
        "\n",
        "this-is-not-json\n",
        '["not-a-record"]\n',
        '{"event":"no-hash"}\n',
    ],
)
def test_invalid_or_absent_tail_never_becomes_an_invented_checksum(tmp_path, content):
    evidence = tmp_path / "evidence.jsonl"
    evidence.write_text(content, encoding="utf-8")
    assert core._last_record_hash(str(evidence)) == "GENESIS"


def test_unreadable_evidence_tail_is_not_reported_as_verified(monkeypatch, tmp_path):
    file = tmp_path / "evidence.jsonl"
    file.write_text('{"hash":"true-hash"}\n')
    orig = core.os.path.isfile
    monkeypatch.setattr(
        core.os.path, "isfile", lambda path: True if str(path) == str(file) else orig(path)
    )
    orig_open = core.open if hasattr(core, "open") else open
    import builtins

    def fail(filename, *args, **kwargs):
        if str(filename) == str(file):
            raise OSError("unreadable")
        return orig_open(filename, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail)
    assert core._last_record_hash(str(file)) == "GENESIS"


def test_long_single_line_tail_expands_bounded_window_instead_of_truncating_the_record(tmp_path):
    record = {"hash": "verified-last-record", "padding": "x" * 70_000}
    file = tmp_path / "evidence.jsonl"
    file.write_text(json.dumps({"hash": "old"}) + "\n" + json.dumps(record) + "\n")
    assert core._last_record_hash(str(file)) == "verified-last-record"
