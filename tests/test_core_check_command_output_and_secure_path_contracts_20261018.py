"""Deterministic audit check refuses guessed results and unsafe execution parameters."""

from __future__ import annotations

import pytest

from scripts import audit_check as ac


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("max_output_bytes", True),
        ("max_output_bytes", 1023),
        ("max_output_bytes", 50_000_001),
        ("timeout", 0),
        ("timeout", False),
        ("timeout", 86_401),
        ("expect_exit", True),
        ("expect_exit", 256),
        ("expect_exit", -256),
    ],
)
def test_runtime_check_resource_bounds_fail_before_any_child_launch(
    monkeypatch, tmp_path, name, bad
):
    monkeypatch.setattr(ac, "_bounded_command", lambda *_a: pytest.fail("must not launch"))
    data = {"type": "run", "argv": ["python", "-V"], name: bad}
    ok, reason, output = ac.run_check(data, str(tmp_path))
    assert not ok
    assert name in reason
    assert output == ""


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"type": "run", "argv": []}, "argv must be"),
        ({"type": "run", "argv": ["python", None]}, "argv must be"),
        ({"type": "run", "cmd": ""}, "cmd must be"),
        ({"type": "run", "shell": True, "argv": ["echo"]}, "shell execution was removed"),
    ],
)
def test_command_spec_never_implicitly_invokes_shell(monkeypatch, tmp_path, raw, message):
    monkeypatch.setattr(ac, "_bounded_command", lambda *_: pytest.fail("untrusted launch"))
    ok, reason, _ = ac.run_check(raw, str(tmp_path))
    assert not ok and message in reason


@pytest.mark.parametrize(
    ("state", "rc", "overflow", "expected"),
    [
        ("timeout", None, False, "timed out"),
        ("overflow", None, True, "output limit exceeded"),
        ("start", None, False, "could not start"),
        ("ok", 1, False, "exit=1 (expected 0)"),
    ],
)
def test_process_exit_causes_are_reported_as_they_occurred(
    monkeypatch, tmp_path, state, rc, overflow, expected
):
    monkeypatch.setattr(ac, "_bounded_command", lambda *_: (rc, state, "observed stderr", overflow))
    ok, reason, output = ac.run_check({"type": "run", "argv": ["checker"]}, str(tmp_path))
    assert not ok and expected in reason
    if state == "start":
        assert output == ""
    else:
        assert output == "observed stderr"


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("", "output_regex must be a non-empty string"),
        (5, "output_regex must be a non-empty string"),
        ("[", "invalid output_regex"),
        ("expected", "output_regex=DID NOT MATCH"),
    ],
)
def test_reported_output_match_is_based_on_actual_output_and_valid_regex(
    monkeypatch, tmp_path, pattern, message
):
    monkeypatch.setattr(ac, "_bounded_command", lambda *_: (0, "ok", "real output", False))
    ok, reason, actual = ac.run_check(
        {"type": "run", "argv": ["checker"], "output_regex": pattern}, str(tmp_path)
    )
    assert not ok and message in reason
    assert actual == "real output"


def test_exact_reported_output_match_allows_expected_zero_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(ac, "_bounded_command", lambda *_: (0, "ok", "checksum verified 23", False))
    ok, reason, out = ac.run_check(
        {"type": "run", "argv": ["checker"], "output_regex": r"verified \d+"}, str(tmp_path)
    )
    assert ok
    assert "output_regex=matched" in reason
    assert out == "checksum verified 23"


@pytest.mark.parametrize(
    ("check", "message"),
    [
        ({"type": "file_exists"}, "path"),
        ({"type": "regex"}, "path"),
        ({"type": "file_exists", "path": "../secret"}, "escapes the workspace"),
        ({"type": "regex", "path": "../secret", "pattern": "a"}, "escapes the workspace"),
    ],
)
def test_real_file_checks_refuse_malformed_or_out_of_workspace_paths(tmp_path, check, message):
    ok, reason, _ = ac.run_check(check, str(tmp_path))
    assert not ok and message in reason


@pytest.mark.parametrize(
    ("check", "message"),
    [
        ({"max_bytes": True, "pattern": "ok"}, "max_bytes"),
        ({"max_bytes": 1023, "pattern": "ok"}, "max_bytes"),
        ({"pattern": 5}, "regex pattern"),
        ({"pattern": "["}, "invalid regex"),
    ],
)
def test_file_regex_validation_denies_invalid_or_unbounded_scans(tmp_path, check, message):
    (tmp_path / "sample.txt").write_text("observed")
    ok, reason, _ = ac.run_check({"type": "regex", "path": "sample.txt", **check}, str(tmp_path))
    assert not ok and message in reason


def test_file_regex_reports_truncated_scan_instead_of_claiming_full_file_review(tmp_path):
    source = tmp_path / "large.txt"
    source.write_text("a" * 1024 + "OBSERVED_TAIL")
    ok, reason, _ = ac.run_check(
        {"type": "regex", "path": "large.txt", "pattern": "OBSERVED_TAIL", "max_bytes": 1024},
        str(tmp_path),
    )
    assert not ok
    assert "truncated at 1024" in reason


def test_file_regex_reports_true_match_not_guessed_whole_file_match(tmp_path):
    (tmp_path / "sample.txt").write_text("observed: pass")
    ok, reason, _ = ac.run_check(
        {"type": "regex", "path": "sample.txt", "pattern": "observed: pass"},
        str(tmp_path),
    )
    assert ok and "pattern matched" in reason


def test_unknown_audit_check_type_is_not_implicitly_successful(tmp_path):
    assert ac.run_check({"type": "invented"}, str(tmp_path))[0] is False


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        ("  ", "cmd parsed to an empty command"),
        ('"unclosed', "cmd could not be parsed"),
    ],
)
def test_legacy_command_parser_never_falls_back_to_shell(cmd, expected):
    with pytest.raises(ValueError, match=expected):
        ac._legacy_split(cmd)


def test_argument_vector_preserves_shell_metacharacters_as_literal_strings():
    assert ac._command_spec({"argv": ["printf", "%s", "a; rm -rf /"]}) == [
        "printf",
        "%s",
        "a; rm -rf /",
    ]
