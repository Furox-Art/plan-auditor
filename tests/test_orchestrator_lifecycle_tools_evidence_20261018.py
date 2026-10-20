"""Exercise supervisor lifecycle, tool availability, and log evidence contracts."""

from __future__ import annotations

import pytest

import supervisor.orchestrator as orchestrator
from supervisor.lifecycle import States
from supervisor.sealing import MonotonicCheck


def test_proof_serialization_preserves_unverified_state():
    proof = orchestrator.FreshAuditProof(False, "chain invalid", None, 0)
    assert proof.as_dict() == {
        "valid": False,
        "reason": "chain invalid",
        "audited_at": None,
        "steps": 0,
    }


@pytest.mark.parametrize(
    "plan_ok,seal_ok,pending,proof_valid,outcome,expected",
    [
        (False, True, [], True, "PASS", States.REVISION_REQUIRED),
        (True, False, [], True, "PASS", States.PLAN_APPROVED),
        (True, True, [1], True, "PASS", States.IMPLEMENTING),
        (True, True, [], True, "PASS", States.PASSED),
        (True, True, [], False, "PASS", States.FINAL_AUDIT),
        (True, True, [], True, "UNKNOWN", States.UNKNOWN),
        (True, True, [], True, "FAIL", States.FAILED),
        (True, True, [], True, "UNRECOGNIZED", States.FINAL_AUDIT),
    ],
)
def test_lifecycle_never_marks_incomplete_verification_as_pass(
    plan_ok,
    seal_ok,
    pending,
    proof_valid,
    outcome,
    expected,
):
    proof = orchestrator.FreshAuditProof(proof_valid, "check")
    lifecycle = orchestrator._lifecycle_for(plan_ok, seal_ok, pending, proof, outcome)
    assert lifecycle.state == expected
    assert lifecycle.history
    assert lifecycle.history[-1].to == expected
    assert lifecycle.rejected_plans == (0 if plan_ok else 1)


def test_no_seal_checks_yield_no_merged_verdict():
    assert orchestrator._merge_checks(None, None) is None


def test_merge_checks_preserves_all_violations_and_improvements():
    first = MonotonicCheck(True, [], ["more_checks"])
    second = MonotonicCheck(False, ["environment_changed", "seal_changed"], [])
    result = orchestrator._merge_checks(None, first, second)
    assert result is not None
    assert result.ok is False
    assert result.violations == ["environment_changed", "seal_changed"]
    assert result.improvements == ["more_checks"]
    assert orchestrator._merge_checks(first).ok is True


def test_invalid_required_tool_structure_is_rejected():
    available = {}
    assert orchestrator._required_tools({"required_tools": "git"}, available) == ["<invalid required_tools>"]
    assert available == {}


def test_available_tools_not_reclassified_unavailable(monkeypatch):
    import supervisor.orchestrator as module

    probed = []
    monkeypatch.setattr(module, "tool_available", lambda name: probed.append(name) or False)
    available = {"git": True}
    assert orchestrator._required_tools({"required_tools": ["git"]}, available) == []
    assert probed == []


def test_missing_and_discoverable_tools_are_recorded(monkeypatch):
    import supervisor.orchestrator as module

    checked = []

    def resolve(tool):
        checked.append(tool)
        return tool == "available_binary"

    monkeypatch.setattr(module, "tool_available", resolve)
    available = {"known_missing": False}
    missing = orchestrator._required_tools(
        {"required_tools": ["unavailable_binary", "known_missing", "available_binary"]},
        available,
    )
    assert missing == ["known_missing", "unavailable_binary"]
    assert available == {
        "known_missing": False,
        "unavailable_binary": False,
        "available_binary": True,
    }
    assert checked == ["unavailable_binary", "known_missing", "available_binary"]


def test_log_tail_reads_evidence_then_watchdog_and_binds_count(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    assert orchestrator._tail_logs(tmp_path) == []
    (pg / "evidence.jsonl").write_text("e0\ne1\ne2\n", encoding="utf-8")
    (pg / "watchdog.jsonl").write_text("w0\nw1\n", encoding="utf-8")
    assert orchestrator._tail_logs(tmp_path, limit=3) == ["e2", "w0", "w1"]
    assert orchestrator._tail_logs(tmp_path, limit=1) == ["w1"]
