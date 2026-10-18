"""Actual PDDL protocol roundtrips and fault-injected external-solver boundaries.

A local protocol stub is *not* a verified Fast Downward theorem/proof.
Internal STRIPS proof status and the external protocol status remain separate.
"""

from __future__ import annotations

import json
import runpy
import subprocess
import sys
import warnings
from types import SimpleNamespace

import pytest

from supervisor import formal_planning as fp


def paired_contract():
    return {
        "version": 1,
        "initial_facts": ["start"],
        "goal_facts": ["a", "b"],
        "actions": [
            {"step": 1, "preconditions": ["start"], "add_effects": ["a"], "del_effects": []},
            {"step": 2, "preconditions": ["start"], "add_effects": ["b"], "del_effects": []},
        ],
    }


def case(tmp_path, *, contract=None, external=None, require=False):
    raw = paired_contract() if contract is None else contract
    plan = {
        "steps": [
            {
                "id": 1,
                "depends_on": [],
                "verify": [
                    fp.make_formal_check(raw, fast_downward=external, require_fast_downward=require)
                ],
            },
            {"id": 2, "depends_on": [], "verify": []},
        ]
    }
    folder = tmp_path / ".plan-auditor"
    folder.mkdir()
    (folder / "plan.json").write_text(json.dumps(plan))
    return plan


def solver_script(root, body):
    path = root / "protocol-stub.py"
    path.write_text(body)
    return str(path)


def test_explicit_alternate_valid_step_order_is_reported_without_rejecting_real_goal_proof(
    tmp_path,
):
    script = solver_script(
        tmp_path,
        "from pathlib import Path\nPath('sas_plan').write_text('(step-2)\\n(step-1)\\n')\n",
    )
    case(tmp_path)
    ok, report = fp.verify_workspace(tmp_path, fast_downward=script, require_fast_downward=True)
    assert ok and report["outcome"] == "PASS"
    assertion = report["contracts"][0]
    assert assertion["analysis"]["solution_order"] == [1, 2]
    assert assertion["fast_downward"]["status"] == "SOLVED"
    assert assertion["fast_downward"]["solution_order"] == [2, 1]
    assert "different valid orderings" in assertion["ordering_note"]


def test_sealed_external_backend_path_is_honored_and_no_implicit_substitution(tmp_path):
    script = solver_script(
        tmp_path,
        "from pathlib import Path\nPath('sas_plan').write_text('(step-1)\\n(step-2)\\n')\n",
    )
    case(tmp_path, external=script, require=True)
    ok, report = fp.verify_workspace(tmp_path)
    assert ok
    assertion = report["contracts"][0]
    assert assertion["fast_downward"]["status"] == "SOLVED"
    assert assertion["fast_downward"]["solution_order"] == [1, 2]


def test_external_solver_known_unreached_goal_rejects_irrespective_of_internal_pass(tmp_path):
    script = solver_script(tmp_path, "print('search stopped without finding a solution')\n")
    case(tmp_path)
    ok, report = fp.verify_workspace(tmp_path, fast_downward=script)
    assert not ok
    assert report["outcome"] == "FAIL"
    assert report["contracts"][0]["fast_downward"]["status"] == "UNSOLVABLE"


def test_optional_external_solver_unavailable_does_not_claim_independent_replication(
    monkeypatch, tmp_path
):
    case(tmp_path)
    monkeypatch.setattr(fp, "_fast_downward_base", lambda *_: None)
    ok, report = fp.verify_workspace(tmp_path, fast_downward="missing", require_fast_downward=False)
    assert ok
    assert report["outcome"] == "PASS"
    assert report["contracts"][0]["fast_downward"]["status"] == "UNAVAILABLE"
    assert report["contracts"][0]["analysis"]["verdict"] == "PASS"


def test_required_external_solver_unavailable_blocks_all_completion(monkeypatch, tmp_path):
    case(tmp_path)
    monkeypatch.setattr(fp, "_fast_downward_base", lambda *_: None)
    ok, report = fp.verify_workspace(tmp_path, require_fast_downward=True)
    assert not ok
    assert report["outcome"] == "FAIL"
    assert report["contracts"][0]["fast_downward"]["status"] == "UNAVAILABLE"


def test_real_external_protocol_that_returns_no_solution_file_does_not_claim_solved(tmp_path):
    script = solver_script(tmp_path, "print('no plan result produced')\n")
    case(tmp_path)
    ok, report = fp.verify_workspace(tmp_path, fast_downward=script, require_fast_downward=True)
    assert not ok
    assert report["contracts"][0]["fast_downward"]["status"] == "ERROR"


def test_nonrun_formal_anchor_is_rejected_before_there_is_any_symbolic_acceptance():
    check = fp.make_formal_check(paired_contract())
    check["type"] = "shell"
    assert any(
        "must be a run check" in e
        for e in fp._anchor_argv_errors(check, fp.contract_sha256(paired_contract()))
    )


def test_parser_refuses_nonobject_contract_directly_even_if_called_below_primary_gate():
    contract, errors, _warnings = fp._parse_contract({"steps": []}, [])
    assert contract is None
    assert "must be an object" in errors[0]


def test_worst_case_incomplete_external_bounded_wait_does_not_leak_process(monkeypatch, tmp_path):
    script = solver_script(tmp_path, "print('not executed by the simulated launch')\n")
    p = {
        "steps": [
            {
                "id": 1,
                "depends_on": [],
                "verify": [
                    fp.make_formal_check(
                        {
                            "version": 1,
                            "initial_facts": ["yes"],
                            "goal_facts": ["yes"],
                            "actions": [
                                {
                                    "step": 1,
                                    "preconditions": ["yes"],
                                    "add_effects": [],
                                    "del_effects": [],
                                }
                            ],
                        }
                    )
                ],
            }
        ]
    }
    raw = p["steps"][0]["verify"][0]["formal_planning"]

    class Unresponsive:
        returncode = None
        pid = 30011

        def wait(self, timeout):
            raise subprocess.TimeoutExpired(["simulated planner"], timeout)

    monkeypatch.setattr(fp.subprocess, "Popen", lambda *a, **kw: Unresponsive())
    seen = []
    monkeypatch.setattr(fp, "_kill_process_group", lambda proc: seen.append(proc.pid))
    result = fp.run_fast_downward(p, raw, executable=script, timeout=0.01)
    assert result.status == "TIMEOUT"
    assert seen == [30011]
    assert result.solution_order == []


def test_windows_process_group_cleanup_uses_argv_only_and_fallback_kill(monkeypatch):
    seen = []

    class Process:
        pid = 234

        def poll(self):
            return None

        def kill(self):
            seen.append(("direct", self.pid))

    monkeypatch.setattr(fp, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(
        fp.subprocess,
        "run",
        lambda args, **kw: seen.append(("windows", args, kw)) or SimpleNamespace(returncode=0),
    )
    fp._kill_process_group(Process())
    assert seen[0][0] == "windows"
    assert seen[0][1] == ["taskkill", "/PID", "234", "/T", "/F"]
    assert seen[0][2]["check"] is False
    assert seen[-1] == ("direct", 234)


def test_windows_taskkill_failure_still_attempts_direct_process_termination(monkeypatch):
    killed = []
    proc = SimpleNamespace(pid=123, poll=lambda: None, kill=lambda: killed.append(True))
    monkeypatch.setattr(fp, "os", SimpleNamespace(name="nt"))

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(["taskkill"], 2)

    monkeypatch.setattr(fp.subprocess, "run", timeout)
    fp._kill_process_group(proc)
    assert killed == [True]


def test_windows_argv_process_creation_flags_do_not_leak_into_shell_execution(
    monkeypatch, tmp_path
):
    script = solver_script(tmp_path, "print('dummy')\n")
    case_data = case(tmp_path)
    raw = case_data["steps"][0]["verify"][0]["formal_planning"]
    captured = []

    class Result:
        returncode = 0

        def wait(self, timeout):
            return 0

    def fake_popen(argv, **kwargs):
        captured.append((argv, kwargs))
        return Result()

    monkeypatch.setattr(fp, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(fp.subprocess, "Popen", fake_popen)
    result = fp.run_fast_downward(case_data, raw, executable=script)
    assert result.status == "ERROR"
    assert captured[0][1]["creationflags"] == getattr(fp.subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    assert isinstance(captured[0][0], list)
    assert "shell" not in captured[0][1]


def test_formal_pddl_cli_export_rejects_nonmapping_raw_contract_even_if_accessor_corrupt(
    monkeypatch, tmp_path, capsys
):
    plan_data = case(tmp_path)
    check = {"type": "run", "formal_planning": False}
    monkeypatch.setattr(
        fp, "_matching_workspace_contracts", lambda *_: [("default", plan_data, check)]
    )
    assert (
        fp.main(
            [
                "export-pddl",
                str(tmp_path),
                "--contract-sha",
                "1" * 64,
                "--output",
                str(tmp_path / "not-exported"),
            ]
        )
        == 2
    )
    out = json.loads(capsys.readouterr().out)
    assert out["outcome"] == "FAIL"
    assert "invalid contract" in out["error"]


def test_module_cli_direct_entrypoint_uses_same_status_contract(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        fp,
        "verify_workspace",
        lambda *_a, **_kw: (False, {"outcome": "FAIL", "error": "real negative verification"}),
    )
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            category=RuntimeWarning,
            message="'supervisor.formal_planning' found in sys.modules",
        )
        # runpy executes a separate namespace, so the ordinary parser with no
        # required subcommand must reject before executing any untrusted work.
        monkeypatch.setattr(sys, "argv", ["plan-auditor-formal"])
        with pytest.raises(SystemExit) as e:
            runpy.run_module("supervisor.formal_planning", run_name="__main__")
    assert e.value.code == 2
