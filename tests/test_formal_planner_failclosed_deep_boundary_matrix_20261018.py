"""Source-backed STRIPS guard tests: malformed contracts, dead-ends and untrusted argv."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from scripts.plan_graph import PlanGraphError
from supervisor import formal_planning as fp


def model():
    return {
        "version": 1,
        "initial_facts": ["start"],
        "goal_facts": ["done"],
        "actions": [
            {
                "step": 1,
                "preconditions": ["start"],
                "add_effects": ["done"],
                "del_effects": [],
            },
        ],
    }


def plan(raw=None):
    raw = model() if raw is None else raw
    return {"steps": [{"id": 1, "depends_on": [], "verify": [fp.make_formal_check(raw)]}]}


@pytest.mark.parametrize(
    ("invalid", "message"),
    [
        (None, "not an object"),
        ([], "not an object"),
        ("unsafe", "not an object"),
    ],
)
def test_nonobject_formal_contract_refuses_without_computing_digest(invalid, message):
    p = plan()
    p["steps"][0]["verify"][0]["formal_planning"] = invalid
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert message in out.reason


@pytest.mark.parametrize(
    ("token", "message"),
    [
        ("--fast-downward", "requires a non-empty"),
        ("--unknown-switch", "unsupported formal planner argv token"),
        ("--require-fast-downward", ""),
        ("--fast-downward VALUE --fast-downward", "unsupported formal planner argv token"),
    ],
)
def test_formal_argv_does_not_accept_implicit_shell_flags_or_missing_backends(token, message):
    p = plan()
    check = p["steps"][0]["verify"][0]
    base = check["argv"][:]
    if token == "--fast-downward VALUE --fast-downward":
        extra = ["--fast-downward", "tool", "--fast-downward"]
    else:
        extra = [token]
    check["argv"] = base + extra
    out = fp.analyze_formal_contract(p)
    if token == "--require-fast-downward":
        assert out.verdict == "PASS"
        return
    assert out.verdict == "REJECT"
    assert any(message in x for x in out.errors)


def test_explicit_fast_downward_and_require_argv_have_canonical_order_and_no_surprise_tokens():
    p = plan()
    check = p["steps"][0]["verify"][0]
    check["argv"] = check["argv"] + ["--fast-downward", "executable", "--require-fast-downward"]
    assert fp.analyze_formal_contract(p).verdict == "PASS"


def test_duplicate_formal_action_ids_cannot_be_passed_as_distinct_steps():
    p = plan()
    contract = p["steps"][0]["verify"][0]["formal_planning"]
    contract["actions"].append(contract["actions"][0].copy())
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("id repeated" in x for x in out.errors)


def test_nonobject_action_is_not_ignored_and_later_interpreted_as_proof():
    p = plan()
    p["steps"][0]["verify"][0]["formal_planning"]["actions"] = ["not-an-action"]
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("must be an object" in x for x in out.errors)


def test_missing_real_step_id_refuses_implicit_action_mapping():
    p = plan()
    p["steps"][0]["id"] = "string-id"
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("without a valid integer id" in x for x in out.errors)


def test_too_many_action_declarations_are_rejected_without_searching_unbounded_space(monkeypatch):
    monkeypatch.setattr(fp, "MAX_ACTIONS", 1)
    p = plan()
    raw = p["steps"][0]["verify"][0]["formal_planning"]
    raw["actions"].append({"step": 2, "preconditions": [], "add_effects": [], "del_effects": []})
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("action limit" in x for x in out.errors)


def test_too_many_facts_are_rejected_before_considering_formal_success(monkeypatch):
    monkeypatch.setattr(fp, "MAX_FACTS", 1)
    p = plan()
    raw = p["steps"][0]["verify"][0]["formal_planning"]
    raw["initial_facts"] = ["start", "also-observed"]
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("fact limit" in x for x in out.errors)


def test_invalid_real_plan_dependencies_are_an_explicit_formal_error(monkeypatch):
    p = plan()
    monkeypatch.setattr(
        fp,
        "effective_dependencies",
        lambda _: (_ for _ in ()).throw(PlanGraphError("measured graph mismatch")),
    )
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert any("dependency graph invalid" in x for x in out.errors)


def test_graph_that_changes_between_parser_and_solver_cannot_claim_proof(monkeypatch):
    p = plan()
    orig = fp.effective_dependencies
    calls = []

    def unreliable(g):
        calls.append(1)
        if len(calls) == 2:
            raise PlanGraphError("independent graph changed")
        return orig(g)

    monkeypatch.setattr(fp, "effective_dependencies", unreliable)
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert "independent graph changed" in out.reason


def test_monotone_cycle_of_fact_dependencies_has_no_applicable_start_action():
    raw = {
        "version": 1,
        "initial_facts": [],
        "goal_facts": ["done"],
        "actions": [
            {"step": 1, "preconditions": ["unlocked"], "add_effects": ["done"], "del_effects": []},
            {"step": 2, "preconditions": ["done"], "add_effects": ["unlocked"], "del_effects": []},
        ],
    }
    p = {
        "steps": [
            {"id": 1, "depends_on": [], "verify": [fp.make_formal_check(raw)]},
            {"id": 2, "depends_on": [], "verify": []},
        ]
    }
    out = fp.analyze_formal_contract(p)
    assert out.verdict == "REJECT"
    assert "symbolic dead-end" in out.reason


def test_no_remaining_future_action_can_satisfy_missing_goal_is_proven_impossible():
    contract = fp.FormalContract(
        frozenset(["start"]),
        frozenset(["done"]),
        tuple([fp.FormalAction(1, frozenset(["start"]), frozenset(["used"]), frozenset())]),
    )
    assert fp._future_impossible(contract, frozenset(["start"]), frozenset()) is True


def test_private_monotone_evaluator_rejects_false_final_goal_without_inventing_it():
    contract = fp.FormalContract(
        frozenset(["start", "done"]),
        frozenset(["done"]),
        tuple([fp.FormalAction(1, frozenset(["start"]), frozenset(), frozenset(["done"]))]),
    )
    verdict, order, explored, reason = fp._monotonic_solve(contract, {1: []})
    assert verdict == "REJECT"
    assert order == [1]
    assert "final goal" in reason


def test_empty_conjunction_is_exported_as_valid_pddl_and_not_scalar_true():
    assert fp._and([]) == "(and)"


def test_external_planner_auto_absent_reports_unavailable(monkeypatch):
    monkeypatch.delenv("FAST_DOWNWARD", raising=False)
    monkeypatch.setattr(fp.shutil, "which", lambda _: None)
    assert fp._fast_downward_base("auto") is None


def test_external_planner_auto_uses_explicit_recorded_environment_without_searching_path(
    monkeypatch,
):
    monkeypatch.setenv("FAST_DOWNWARD", "explicit-fast-downward")
    monkeypatch.setattr(fp.shutil, "which", lambda _: None)
    assert fp._fast_downward_base("auto") == ["explicit-fast-downward"]


def test_external_planner_executable_discovery_uses_single_argv_and_no_shell(monkeypatch):
    monkeypatch.setattr(fp.shutil, "which", lambda _: "/trusted/bin/planner")
    assert fp._fast_downward_base("planner") == ["/trusted/bin/planner"]


@pytest.mark.skipif(os.name == "nt", reason="os.killpg is unavailable on Windows")
def test_external_planner_process_is_not_killed_again_if_already_exited(monkeypatch):
    process = SimpleNamespace(poll=lambda: 0)
    monkeypatch.setattr(fp.os, "killpg", lambda *_: pytest.fail("must not kill exited PID"))
    fp._kill_process_group(process)


@pytest.mark.skipif(os.name == "nt", reason="os.killpg is unavailable on Windows")
def test_external_planner_kill_failure_does_not_leave_an_unbounded_owned_process(monkeypatch):
    seen = []
    process = SimpleNamespace(
        pid=9513,
        poll=lambda: None,
        kill=lambda: seen.append("fallback-kill"),
    )

    def no_group(*args):
        raise ProcessLookupError("already reaped")

    monkeypatch.setattr(fp.os, "killpg", no_group)
    fp._kill_process_group(process)
    assert seen == ["fallback-kill"]


@pytest.mark.skipif(os.name == "nt", reason="os.killpg is unavailable on Windows")
def test_external_planner_failed_individual_kill_is_handled_without_false_success(monkeypatch):
    process = SimpleNamespace(
        pid=9513,
        poll=lambda: None,
        kill=lambda: (_ for _ in ()).throw(OSError("simulated kill refused")),
    )
    monkeypatch.setattr(fp.os, "killpg", lambda *_: None)
    fp._kill_process_group(process)


def test_invalid_contract_sha_is_rejected_before_active_plan_file_loading(tmp_path):
    ok, result = fp.verify_workspace(tmp_path, digest="NOT-A-SHA")
    assert not ok
    assert "--contract-sha" in result["error"]


def test_symlinked_or_malformed_plan_loader_exception_yields_fail_not_unhandled_exception(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(
        fp,
        "_matching_workspace_contracts",
        lambda *_: (_ for _ in ()).throw(ValueError("untrusted plan path")),
    )
    ok, result = fp.verify_workspace(tmp_path)
    assert not ok
    assert "cannot load active plans" in result["error"]


def test_structural_nonmapping_contract_does_not_match_any_active_sha(tmp_path):

    invalid = {"steps": [{"id": 1, "verify": [{"formal_planning": []}]}]}
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plan.json").write_text(__import__("json").dumps(invalid))
    assert fp._matching_workspace_contracts(tmp_path, None) == []
