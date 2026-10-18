"""Audit input grammars reject implicit shell commands, unsupported evidence, and bad paths."""

from __future__ import annotations

import sys

import pytest

from scripts import audit_check as core


def plan():
    return {
        "task": "reproduce audited evidence",
        "created": "2026-10-18T02:00:00Z",
        "steps": [
            {
                "id": 1,
                "title": "verify collected records",
                "depends_on": [],
                "verify": [{"type": "pytest", "args": ["tests", "-q"]}],
            }
        ],
    }


def checked(**kw):
    p = plan()
    p["steps"][0]["verify"] = [kw]
    return p


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"created": "invalid"}, "created: must be a valid ISO"),
        ({"created": False}, "created: must be an ISO"),
        ({"created": ""}, "created: must be an ISO"),
        ({"snapshot": "unstructured"}, "snapshot: must be a list"),
        ({"snapshot": ["../escape"]}, "snapshot: must be a list"),
        ({"required_tools": [1]}, "required_tools: must"),
        ({"required_tools": "git"}, "required_tools: must"),
        ({"requirements": []}, "requirements: if given"),
        ({"requirements": "not a list"}, "requirements: if given"),
        ({"requirements": [""]}, "requirement 1 must"),
        ({"requirements": [7]}, "requirement 1 must be an object"),
        (
            {
                "requirements": [
                    {"id": "one", "description": "good", "priority": "MUST"},
                    {"id": "one", "description": "also good", "priority": "must"},
                ]
            },
            "duplicate requirement id",
        ),
        ({"requirements": [{"id": 1, "description": "title", "priority": "must"}]}, "id ister"),
        (
            {"requirements": [{"id": "one", "description": "", "priority": "must"}]},
            "description ister",
        ),
        (
            {"requirements": [{"id": "one", "description": "title", "priority": "inferred"}]},
            "priority must",
        ),
    ],
)
def test_invalid_plan_metadata_never_silently_approved(override, message):
    p = plan()
    p.update(override)
    errors = core.validate_plan(p)
    assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"id": False}, "step id must be a positive int"),
        ({"id": 0}, "step id must be a positive int"),
        ({"id": "01"}, "step id must be a positive int"),
        ({"title": ""}, "title must not be empty"),
        ({"covers": "REQ-1"}, "covers must be a list"),
        ({"covers": [1]}, "covers must be a list"),
        ({"verify": []}, "verify must not be empty"),
        ({"verify": "not a check"}, "verify must not be empty"),
        ({"verify": [{"type": "file_exists", "path": "a.txt"}]}, "BEHAVIORAL check"),
        ({"verify": [{"type": "not-authorized"}]}, "invalid check"),
    ],
)
def test_invalid_step_shape_cannot_be_the_basis_of_scientific_success(override, message):
    p = plan()
    p["steps"][0].update(override)
    errs = core.validate_plan(p)
    assert any(message in err for err in errs), errs


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ({"type": "run"}, "tam olarak bir"),
        ({"type": "run", "cmd": ""}, "non-empty string"),
        ({"type": "exec", "cmd": False}, "non-empty string"),
        ({"type": "run", "argv": []}, "non-empty list"),
        ({"type": "run", "argv": [sys.executable, ""]}, "non-empty list"),
        ({"type": "run", "argv": [sys.executable], "cmd": "echo checked"}, "tam olarak bir"),
        ({"type": "run", "argv": [sys.executable], "shell": True}, "shell was removed"),
        ({"type": "pytest", "cmd": "pytest"}, "does not accept cmd"),
        ({"type": "pytest", "args": True}, "args must be a string"),
        ({"type": "pytest", "args": [True]}, "args must be a string"),
    ],
)
def test_unapproved_executable_check_forms_are_rejected_before_spawn(args, message):
    errors = core.validate_plan(checked(**args))
    assert any(message in e for e in errors), errors


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"timeout": 0}, "timeout must be"),
        ({"timeout": True}, "timeout must be"),
        ({"timeout": 100000}, "timeout must be"),
        ({"expect_exit": False}, "expect_exit must be"),
        ({"expect_exit": 500}, "expect_exit must be"),
        ({"max_output_bytes": 1}, "max_output_bytes must"),
        ({"max_output_bytes": False}, "max_output_bytes must"),
        ({"output_regex": ""}, "output_regex must"),
        ({"output_regex": "("}, "invalid output_regex"),
    ],
)
def test_bounded_run_parameters_reject_untrusted_resource_or_regex_overrides(overrides, message):
    check = {"type": "run", "argv": [sys.executable, "-c", "print(1)"]}
    check.update(overrides)
    errs = core.validate_plan(checked(**check))
    assert any(message in e for e in errs), errs


@pytest.mark.parametrize(
    ("kind", "path", "pattern", "message"),
    [
        ("file_exists", "../outside", None, "safe relative"),
        ("file_exists", "/tmp/outside", None, "safe relative"),
        ("file_exists", None, None, "safe relative"),
        ("regex", "../outside", "matches", "safe relative"),
        ("regex", "evidence.txt", None, "non-empty"),
        ("regex", "evidence.txt", "(", "invalid regex pattern"),
    ],
)
def test_file_based_check_cannot_follow_untrusted_path_or_unknown_regex(
    kind, path, pattern, message
):
    check = {"type": kind, "path": path}
    if pattern is not None:
        check["pattern"] = pattern
    p = plan()
    p["steps"][0]["verify"].append(check)
    errs = core.validate_plan(p)
    assert any(message in e for e in errs), errs


def test_duplicate_metadata_errors_are_not_reported_multiple_times_for_same_problem():
    p = plan()
    p["steps"] = [
        {"id": 1, "title": "a", "depends_on": [], "verify": [{"type": "pytest", "args": ""}]},
        {"id": 2, "title": "b", "depends_on": [], "verify": [{"type": "pytest", "args": ""}]},
    ]
    assert core.validate_plan(p) == []


def test_normalized_pytest_check_preserves_explicit_timeout_and_failure_exit_contract():
    norm = core.norm_check(
        {
            "type": "pytest",
            "args": ["tests", "-q"],
            "timeout": 5,
            "expect_exit": 1,
            "output_regex": "FAIL",
            "max_output_bytes": 2048,
        }
    )
    assert norm["type"] == "run"
    assert norm["argv"] == [sys.executable, "-m", "pytest", "tests", "-q"]
    assert norm["expect_exit"] == 1
    assert norm["timeout"] == 5
    assert norm["output_regex"] == "FAIL"
    assert norm["max_output_bytes"] == 2048


def test_normalized_exec_argv_is_copied_without_rewriting_original_command():
    source = {"type": "exec", "argv": ["python", "-V"], "timeout": 4, "expect_exit": 0}
    normalized = core.norm_check(source)
    assert normalized["type"] == "run"
    assert normalized["argv"] == ["python", "-V"]
    normalized["argv"].append("malicious")
    assert source["argv"] == ["python", "-V"]


def test_named_plans_discovery_ignores_unsafe_basename_and_nonjson_files(tmp_path):
    pg = tmp_path / ".plan-auditor"
    named = pg / "plans"
    named.mkdir(parents=True)
    (pg / "plan.json").write_text("{}")
    (named / "good.json").write_text("{}")
    (named / "bad name.json").write_text("{}")
    (named / "ignored.txt").write_text("{}")
    discovered = core.all_plan_paths(str(tmp_path))
    assert [name for name, _ in discovered] == [None, "good"]


def test_missing_plan_file_reports_explicit_operator_failure_not_success(tmp_path):
    with pytest.raises(SystemExit, match="plan yok"):
        core.load_plan(str(tmp_path))


def test_large_plan_is_rejected_before_json_parse(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "MAX_PLAN_BYTES", 100)
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_bytes(b"{" * 102)
    with pytest.raises(SystemExit, match="plan cok buyuk"):
        core.load_plan(str(tmp_path))


def test_named_plan_save_load_roundtrip_preserves_exact_original_verification(tmp_path):
    real = plan()
    core.save_plan(str(tmp_path), real, name="science-case")
    loaded = core.load_plan(str(tmp_path), name="science-case")
    assert loaded == real
    assert not (tmp_path / ".plan-auditor" / "plans" / "science-case.json.tmp").exists()


def test_symlinked_file_beyond_workspace_is_never_an_authorized_check_path(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside-source")
    (tmp_path / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        core._safe_path(str(tmp_path), "escape/secret.json")


def test_path_to_missing_file_inside_workspace_keeps_correct_confined_target(tmp_path):
    assert core._safe_path(str(tmp_path), "recorded/data.json") == str(
        tmp_path / "recorded" / "data.json"
    )
