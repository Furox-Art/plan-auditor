"""External planner process protocol is verified independently of a planner's claims.

The command stub exercises PDDL adapter input/output and fault paths; it does
not stand in for a real Fast Downward proof and is never labelled as one.
"""

from __future__ import annotations

import json
import sys

import pytest

from supervisor import formal_planning as formal


def problem():
    contract = {
        "version": 1,
        "initial_facts": ["ready"],
        "goal_facts": ["done"],
        "actions": [
            {"step": 1, "preconditions": ["ready"], "add_effects": ["mid"], "del_effects": []},
            {"step": 2, "preconditions": ["mid"], "add_effects": ["done"], "del_effects": []},
        ],
    }
    plan = {
        "steps": [
            {"id": 1, "depends_on": [], "verify": [formal.make_formal_check(contract)]},
            {"id": 2, "depends_on": [1], "verify": []},
        ]
    }
    return plan, contract


def protocol_stub(tmp_path, text: str) -> str:
    script = tmp_path / "simulated-planner-protocol.py"
    script.write_text(text, encoding="utf-8")
    return str(script)


@pytest.mark.parametrize("option", [None, "", "off", "none"])
def test_external_planner_opt_out_does_not_launch_any_process(option):
    assert formal._fast_downward_base(option) is None


def test_missing_external_planner_must_stay_unavailable(tmp_path):
    plan, contract = problem()
    output = formal.run_fast_downward(plan, contract, executable=str(tmp_path / "missing"))
    assert output.status == "UNAVAILABLE"
    assert "not found" in output.reason


def test_python_external_command_is_spawned_as_arg_vector_not_shell(tmp_path):
    source = protocol_stub(tmp_path, "print('protocol only')")
    assert formal._fast_downward_base(source) == [sys.executable, source]


def test_solver_adapter_exports_valid_pddl_and_checks_explicit_solution_steps(tmp_path):
    script = protocol_stub(
        tmp_path,
        "from pathlib import Path\n"
        "Path('sas_plan').write_text('(step-1)\\n(step-2)\\n')\n"
        "print('protocol stub output')\n",
    )
    plan, contract = problem()
    out = formal.run_fast_downward(plan, contract, executable=script, timeout=5.0)
    assert out.status == "SOLVED"
    assert out.solution_order == [1, 2]
    assert out.command[:2] == [sys.executable, script]
    assert "protocol stub output" in out.output_tail


@pytest.mark.parametrize(
    "bad_steps",
    [
        "(step-1)\\n",
        "(step-1)\\n(step-1)\\n",
        "(step-2)\\n(step-3)\\n",
    ],
)
def test_external_plan_cannot_claim_success_with_missing_or_duplicate_actions(tmp_path, bad_steps):
    script = protocol_stub(
        tmp_path, f"from pathlib import Path\nPath('sas_plan').write_text({bad_steps!r})\n"
    )
    p, c = problem()
    result = formal.run_fast_downward(p, c, executable=script, timeout=5.0)
    assert result.status == "ERROR"
    assert "every Plan Auditor step exactly once" in result.reason


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("No solution exists", "UNSOLVABLE"),
        ("unsolvable", "UNSOLVABLE"),
        ("search stopped without finding a solution", "UNSOLVABLE"),
        ("optimizer exited without a valid plan", "ERROR"),
    ],
)
def test_external_planner_logs_are_interpreted_conservatively(tmp_path, output, expected):
    script = protocol_stub(tmp_path, f"print({output!r})")
    p, c = problem()
    result = formal.run_fast_downward(p, c, executable=script, timeout=5.0)
    assert result.status == expected
    assert result.solution_order == []


def test_invalid_pddl_contract_is_rejected_before_external_solver_execution(tmp_path):
    script = protocol_stub(tmp_path, "raise RuntimeError('this must never run')\n")
    p, c = problem()
    c["goal_facts"] = ["undocumented"]
    result = formal.run_fast_downward(p, c, executable=script, timeout=5.0)
    assert result.status == "ERROR"
    assert "no initial/producer source" in result.reason


def test_timeout_kills_owned_protocol_process_group_and_reports_nonpass(tmp_path):
    script = protocol_stub(tmp_path, "import time\ntime.sleep(10)\n")
    p, c = problem()
    result = formal.run_fast_downward(p, c, executable=script, timeout=0.2)
    assert result.status == "TIMEOUT"
    assert result.solution_order == []
    assert "exceeded" in result.reason


def test_external_planner_process_spawn_failure_is_reported_not_success(tmp_path, monkeypatch):
    from supervisor import formal_planning as mod

    plan, contract = problem()
    script = protocol_stub(tmp_path, "pass")

    def cannot_spawn(*a, **kw):
        raise OSError("simulated executable refusal")

    monkeypatch.setattr(mod.subprocess, "Popen", cannot_spawn)
    result = formal.run_fast_downward(plan, contract, executable=script, timeout=2.0)
    assert result.status == "ERROR"
    assert "start failed" in result.reason


def test_external_plan_file_parser_ignores_untrusted_nonnumeric_metadata(tmp_path):
    path = tmp_path / "sas_plan"
    path.write_text("; commentary\n(step-3)\nSTEP-4\n(step-2) ; checksum\n(step--1)\n")
    assert formal._parse_fd_plan(path) == [3, 2]


def test_missing_plan_file_is_not_assumed_to_contain_valid_steps(tmp_path):
    assert formal._parse_fd_plan(tmp_path / "missing") == []


def test_tail_reader_honours_hard_output_byte_bound(tmp_path):
    path = tmp_path / "external.log"
    path.write_bytes(b"0123456789" * 500)
    assert formal._tail_text(path, limit=21) == ("0123456789" * 500)[-21:]


def test_unreadable_external_log_returns_empty_without_fake_diagnostics(tmp_path):
    assert formal._tail_text(tmp_path / "missing") == ""


def test_real_workspace_internal_formal_verification_needs_only_recorded_contract(tmp_path):
    p, c = problem()
    directory = tmp_path / ".plan-auditor"
    directory.mkdir()
    (directory / "plan.json").write_text(json.dumps(p))
    ok, out = formal.verify_workspace(tmp_path)
    assert ok is True
    assert out["outcome"] == "PASS"
    assert out["contracts"][0]["analysis"]["solution_order"] == [1, 2]


def test_workspace_planner_digest_mismatch_cannot_match_another_plan(tmp_path):
    p, c = problem()
    directory = tmp_path / ".plan-auditor"
    directory.mkdir()
    (directory / "plan.json").write_text(json.dumps(p))
    ok, out = formal.verify_workspace(tmp_path, digest="1" * 64)
    assert ok is False
    assert out["outcome"] == "FAIL"
    assert "no formal planning contract" in out["error"]


@pytest.mark.parametrize("limit", [True, 0, -1, 100000001, "unbounded"])
def test_workspace_planner_budget_refuses_invalid_requested_state_limit(tmp_path, limit):
    ok, out = formal.verify_workspace(tmp_path, max_states=limit)
    assert ok is False
    assert "--max-states" in out["error"]


def test_workspace_planner_explicit_external_backend_missing_with_required_flag_fails(
    monkeypatch, tmp_path
):
    p, c = problem()
    folder = tmp_path / ".plan-auditor"
    folder.mkdir()
    (folder / "plan.json").write_text(json.dumps(p))
    monkeypatch.setattr(
        formal,
        "run_fast_downward",
        lambda *a, **kw: formal.ExternalPlannerResult(status="UNAVAILABLE", reason="not installed"),
    )
    ok, out = formal.verify_workspace(tmp_path, require_fast_downward=True)
    assert ok is False
    assert out["outcome"] == "FAIL"
    assert out["contracts"][0]["fast_downward"]["status"] == "UNAVAILABLE"
