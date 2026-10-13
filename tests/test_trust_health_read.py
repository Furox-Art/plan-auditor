"""Regression coverage for the trust-health read path.

``audit_steps`` needs the failed-attempt count for every step it is about to run.
It asked for them one step at a time, and each ask re-read the entire evidence
log — every archive plus the active one — so a plan with N steps against a log of
N records parsed the log N times. Quadratic in the number of steps is the same
kind of drift a perf regression in a gate produces: nothing fails, the command
just gets slower until someone notices.

The counts themselves are unchanged; only the number of passes over the log is.
The recording wrapper below counts the passes, so the assertion is deterministic
rather than wall-clock, and it fails on the old per-step read without depending
on how fast the machine is.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import audit_check as core

STEPS = 12
FAILED_PER_STEP = 2


def _plan(step_count: int) -> dict:
    return {
        "task": "perf smoke for the trust-health read",
        "created": "2026-10-13T00:00:00Z",
        "requirements": [{"id": "REQ-1", "description": "the declared check", "priority": "must"}],
        "required_tools": [],
        "steps": [
            {
                "id": index,
                "title": f"step {index}",
                "depends_on": [],
                "requires_outputs": [],
                "covers": ["REQ-1"] if index == 1 else [],
                "verify": [],
                "outputs": [],
            }
            for index in range(1, step_count + 1)
        ],
    }


def _history(base: Path, step_count: int, failed_per_step: int) -> None:
    """A chained evidence log holding ``failed_per_step`` failures per step."""
    (base / ".plan-auditor" / "supervisor.json").write_text(
        json.dumps({"max_attempts": 99, "rotate_bytes": 2_000_000}), encoding="utf-8"
    )
    for step_id in range(1, step_count + 1):
        for _ in range(failed_per_step):
            core._write_evidence_record(
                core.evidence_path(base),
                {"mode": "run", "step": step_id, "plan": "default", "status": "failed"},
            )


@pytest.fixture
def pass_counter(monkeypatch):
    """Count how many times the evidence log is enumerated, without changing it."""
    calls = {"paths": 0}
    original = core._all_evidence_paths

    def counting(base):
        calls["paths"] += 1
        return original(base)

    monkeypatch.setattr(core, "_all_evidence_paths", counting)
    return calls


def test_one_pass_over_the_log_answers_every_step(tmp_path: Path, pass_counter):
    """The whole log is enumerated once, not once per step."""
    (tmp_path / ".plan-auditor").mkdir()
    _history(tmp_path, STEPS, FAILED_PER_STEP)
    base = str(tmp_path)

    counts = core.failed_attempt_counts(base)
    assert counts[("default", 1)] == FAILED_PER_STEP
    assert len(counts) == STEPS

    pass_counter["paths"] = 0
    assert core.failed_attempt_counts(base) == counts
    assert pass_counter["paths"] == 1, (
        "failed_attempt_counts enumerated the evidence paths "
        f"{pass_counter['paths']} times; it must be a single pass"
    )


def test_audit_steps_reads_the_log_once(tmp_path: Path, pass_counter):
    """``audit_steps`` must not re-read the evidence per step it is about to run."""
    (tmp_path / ".plan-auditor").mkdir()
    _history(tmp_path, STEPS, FAILED_PER_STEP)
    base = str(tmp_path)

    pass_counter["paths"] = 0
    ok = core.audit_steps(base, _plan(STEPS), mode="run")
    assert ok is True

    assert pass_counter["paths"] == 1, (
        f"audit_steps enumerated the evidence log {pass_counter['paths']} times "
        f"for a {STEPS}-step plan; the attempt limit must be read in one pass, "
        "not once per step"
    )


def test_the_aggregate_equals_the_per_step_reader(tmp_path: Path):
    """The single source of truth must give the same numbers the old reader did."""
    base = str(tmp_path)
    (tmp_path / ".plan-auditor").mkdir()
    for step_id in (1, 2, 3):
        for _ in range(2):
            core._write_evidence_record(
                core.evidence_path(base),
                {"mode": "run", "step": step_id, "plan": "default", "status": "failed"},
            )
    for step_id in (1, 3):
        core._write_evidence_record(
            core.evidence_path(base),
            {"mode": "run", "step": step_id, "plan": "other", "status": "failed"},
        )
    # Non-counting shapes: a different mode, a success, a non-record line.
    core._write_evidence_record(
        core.evidence_path(base),
        {"mode": "audit", "step": 1, "plan": "default", "status": "failed"},
    )
    core._write_evidence_record(
        core.evidence_path(base),
        {"mode": "run", "step": 2, "plan": "default", "status": "verified"},
    )

    counts = core.failed_attempt_counts(base)
    assert counts[("default", 1)] == 2
    assert counts[("default", 2)] == 2
    assert counts[("default", 3)] == 2
    assert counts[("other", 1)] == 1
    assert core.count_failed_attempts(base, 2, plan="default") == 2
    assert core.count_failed_attempts(base, 1, plan="other") == 1
    assert core.count_failed_attempts(base, 3, plan="default") == 2
    assert core.count_failed_attempts(base, 99, plan="default") == 0


def test_the_attempt_limit_still_blocks_a_repeatedly_failing_step(tmp_path: Path):
    """Aggregation must not weaken the limit it was measuring."""
    base = str(tmp_path)
    (tmp_path / ".plan-auditor").mkdir()
    (tmp_path / ".plan-auditor" / "supervisor.json").write_text(
        json.dumps({"max_attempts": 2}), encoding="utf-8"
    )
    for _ in range(3):
        core._write_evidence_record(
            core.evidence_path(base),
            {"mode": "run", "step": 1, "plan": "default", "status": "failed"},
        )
    plan = _plan(1)
    ok = core.audit_steps(base, plan, mode="run")
    assert ok is False, "a step over its genuine failed-attempt limit must be skipped"
