"""Last STRIPS/PDDL gate branches: no silent goal assumptions or false success."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from supervisor import formal_planning as fp


def simple_raw():
    return {
        "version": 1,
        "initial_facts": ["start"],
        "goal_facts": ["done"],
        "actions": [
            {"step": 1, "preconditions": ["start"], "add_effects": ["done"], "del_effects": []}
        ],
    }


def simple_plan(raw=None):
    raw = simple_raw() if raw is None else raw
    return {"steps": [{"id": 1, "depends_on": [], "verify": [fp.make_formal_check(raw)]}]}


def test_duplicate_plan_step_ids_cannot_degrade_exactly_one_action_check():
    raw = simple_raw()
    plan = {"steps": [{"id": 1}, {"id": 1}]}
    parsed, errors, _ = fp._parse_contract(plan, raw)
    assert parsed is None
    assert any("exactly one action per plan step" in e for e in errors)


def test_nonmonotone_search_rejects_completed_plan_with_false_final_goal():
    contract = fp.FormalContract(
        frozenset(["start", "goal"]),
        frozenset(["goal"]),
        (fp.FormalAction(1, frozenset(["start"]), frozenset(), frozenset(["goal"])),),
    )
    verdict, order, explored, reason = fp._search_solve(contract, {1: []}, 100)
    assert verdict == "REJECT"
    assert order == []
    assert explored >= 2
    assert "no dependency-respecting" in reason


def test_two_independent_action_orders_do_not_duplicate_reached_state():
    def no_change(sid):
        return fp.FormalAction(sid, frozenset(["start"]), frozenset(), frozenset())

    contract = fp.FormalContract(
        frozenset(["start"]),
        frozenset(["start"]),
        (no_change(1), no_change(2)),
    )
    verdict, order, explored, reason = fp._search_solve(contract, {1: [], 2: []}, 100)
    assert verdict == "PASS"
    assert sorted(order) == [1, 2]
    assert explored <= 5
    assert "reachable" in reason


def test_terminated_external_process_is_not_killed_again_after_group_cleanup(monkeypatch):
    sequence = [None, 0]
    calls = []
    proc = SimpleNamespace(
        pid=39349, poll=lambda: sequence.pop(0), kill=lambda: calls.append("kill")
    )
    monkeypatch.setattr(fp.os, "killpg", lambda *_: calls.append("group"))
    fp._kill_process_group(proc)
    assert calls == ["group"]


def test_multiple_bad_contracts_cannot_reduce_a_previous_failure_rank(monkeypatch, tmp_path):
    plan = simple_plan()
    plan["steps"][0]["verify"][0]["type"] = "unapproved-shell"
    bad = plan["steps"][0]["verify"][0]
    monkeypatch.setattr(
        fp,
        "_matching_workspace_contracts",
        lambda *_: [("first", plan, bad), ("second", plan, bad)],
    )
    ok, report = fp.verify_workspace(tmp_path)
    assert not ok and report["outcome"] == "FAIL"
    assert len(report["contracts"]) == 2
    assert all(x["analysis"]["verdict"] == "REJECT" for x in report["contracts"])


def test_require_external_with_no_selected_executable_must_not_pass_on_unverified_result(
    monkeypatch, tmp_path
):
    plan = simple_plan()
    match = plan["steps"][0]["verify"][0]
    monkeypatch.setattr(fp, "_matching_workspace_contracts", lambda *_: [("default", plan, match)])
    monkeypatch.setattr(
        fp, "run_fast_downward", lambda *_a, **_kw: fp.ExternalPlannerResult(status="UNAVAILABLE")
    )
    ok, report = fp.verify_workspace(tmp_path, require_fast_downward=True)
    assert not ok
    assert report["outcome"] == "FAIL"
    assert report["contracts"][0]["fast_downward"]["status"] == "UNAVAILABLE"


def test_optional_auto_backend_contract_does_not_accept_fake_success_when_inactive(
    monkeypatch, tmp_path
):
    plan = simple_plan()
    match = plan["steps"][0]["verify"][0]
    monkeypatch.setattr(fp, "_matching_workspace_contracts", lambda *_: [("default", plan, match)])
    seen = []

    def simulated_solver(*args, **kwargs):
        seen.append(kwargs["executable"])
        return fp.ExternalPlannerResult(status="SOLVED", solution_order=[1])

    monkeypatch.setattr(fp, "run_fast_downward", simulated_solver)
    ok, report = fp.verify_workspace(tmp_path, require_fast_downward=True)
    assert ok and report["outcome"] == "PASS"
    assert seen == ["auto"]
    assert report["contracts"][0]["fast_downward"]["status"] == "SOLVED"


def test_formal_backend_flag_missing_argv_value_cannot_turn_into_implicit_solver(
    tmp_path, monkeypatch
):
    plan = simple_plan()
    anchor = plan["steps"][0]["verify"][0]
    anchor["argv"].append("--fast-downward")
    monkeypatch.setattr(
        fp,
        "_matching_workspace_contracts",
        lambda *_args: [("default", plan, anchor)],
    )
    ok, report = fp.verify_workspace(tmp_path)
    assert not ok
    assert report["outcome"] == "FAIL"
    assert "fast_downward" not in report["contracts"][0]
    assert any(
        "--fast-downward requires" in error
        for error in report["contracts"][0]["analysis"]["errors"]
    )


def test_required_external_verification_never_substitutes_unknown_for_nonobject_contract(
    monkeypatch, tmp_path
):
    plan = simple_plan()
    anchor = plan["steps"][0]["verify"][0]
    anchor["formal_planning"] = []
    monkeypatch.setattr(
        fp,
        "_matching_workspace_contracts",
        lambda *_args: [("default", plan, anchor)],
    )

    def must_not_spawn(*_args, **_kwargs):
        pytest.fail("nonobject contract must never launch an external process")

    monkeypatch.setattr(fp, "run_fast_downward", must_not_spawn)
    ok, result = fp.verify_workspace(tmp_path, require_fast_downward=True)
    assert not ok
    assert result["outcome"] == "FAIL"
    assert "fast_downward" not in result["contracts"][0]
    assert result["contracts"][0]["analysis"]["verdict"] == "REJECT"
