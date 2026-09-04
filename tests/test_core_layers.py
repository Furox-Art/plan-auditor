"""Tests for L2 workspace, L3 policy, L6 lifecycle."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.workspace import WorkspaceState, GitState, diff_workspaces
from supervisor.policies import (
    PolicyEngine, default_engine, required_tests_passing, no_pending_steps,
    seal_not_violated, no_secret_leak, RuleResult,
)
from supervisor.lifecycle import TaskLifecycle, States


# --------------------------------------------------------------- L2 workspace

def test_workspace_to_dict():
    ws = WorkspaceState(
        repository_root="/repo",
        git=GitState(branch="main", is_repo=True, dirty_files=["a.py"]),
        exists_files={"a.py", "b.py"},
        language="python",
    )
    d = ws.to_dict()
    assert d["repository_root"] == "/repo"
    assert d["git"]["branch"] == "main"
    assert d["language"] == "python"
    assert "a.py" in d["exists_files"]


def test_diff_workspaces_detects_created_and_deleted():
    before = WorkspaceState(repository_root=".", exists_files={"a.py"}, git=GitState(dirty_files=[]))
    after = WorkspaceState(repository_root=".", exists_files={"a.py", "b.py"}, git=GitState(dirty_files=["b.py"]))
    diff = diff_workspaces(before, after)
    assert diff["created_files"] == ["b.py"]
    assert diff["deleted_files"] == []
    assert "b.py" in diff["new_dirty"]


# --------------------------------------------------------------- L3 policy

def test_required_tests_passes_when_no_failures():
    ctx = {"plan_steps": [{"results": [{"passed": True}]}]}
    r = required_tests_passing(ctx)
    assert not r.triggered and r.level == 2


def test_required_tests_triggered_on_failure():
    ctx = {"plan_steps": [{"results": [{"passed": False}]}]}
    r = required_tests_passing(ctx)
    assert r.triggered and "fail" in r.detail.lower()


def test_no_pending_triggered_when_unverified():
    ctx = {"plan_steps": [{"status": "pending"}]}
    r = no_pending_steps(ctx)
    assert r.triggered


def test_seal_intact_passes():
    ctx = {"seal_hash": "abc", "current_hash": "abc"}
    assert not seal_not_violated(ctx).triggered


def test_seal_violated_when_changed():
    ctx = {"seal_hash": "abc", "current_hash": "xyz"}
    assert seal_not_violated(ctx).triggered


def test_secret_leak_detected():
    ctx = {"logs": ["api_key=supersecret123"]}
    r = no_secret_leak(ctx)
    assert r.triggered and r.evidence


def test_default_engine_evaluates_all_rules():
    engine = default_engine()
    ctx = {
        "plan_steps": [{"status": "verified", "results": [{"passed": True}]}],
        "seal_hash": "abc", "current_hash": "abc",
        "evidence_valid": True, "logs": [],
        "missing_required_tools": [],
    }
    failures = engine.failures(ctx)
    assert failures == []


# --------------------------------------------------------------- L6 lifecycle

def test_lifecycle_starts_new():
    lc = TaskLifecycle(task_id="t1")
    assert lc.state == States.NEW
    assert not lc.terminal()


def test_valid_transition():
    lc = TaskLifecycle(task_id="t1")
    assert lc.transition(States.DISCOVERED, operator="start")
    assert lc.state == States.DISCOVERED


def test_invalid_transition_rejected():
    lc = TaskLifecycle(task_id="t1")
    assert not lc.transition(States.PASSED)  # cannot jump to PASSED from NEW
    assert lc.state == States.NEW


def test_full_happy_path():
    lc = TaskLifecycle(task_id="t1")
    path = [
        States.DISCOVERED, States.ANALYZING, States.REQUIREMENTS_READY,
        States.PLAN_PROPOSED, States.PLAN_REVIEW, States.PLAN_APPROVED,
        States.SEALED, States.IMPLEMENTING, States.VERIFYING, States.PASSED,
    ]
    for s in path:
        assert lc.transition(s, operator="op"), f"failed at {s}"
    assert lc.terminal() and lc.state == States.PASSED


def test_retry_increments_counter():
    lc = TaskLifecycle(task_id="t1")
    path = [
        States.DISCOVERED, States.ANALYZING, States.REQUIREMENTS_READY,
        States.PLAN_PROPOSED, States.PLAN_REVIEW, States.PLAN_APPROVED,
        States.SEALED, States.IMPLEMENTING, States.RETRYING,
    ]
    for s in path:
        assert lc.transition(s), f"transition to {s} failed"
    assert lc.retries == 1


def test_progress_fraction():
    lc = TaskLifecycle(task_id="t1")
    assert lc.progress_fraction() == 0.0
    for s in [States.DISCOVERED, States.ANALYZING, States.REQUIREMENTS_READY,
              States.PLAN_PROPOSED, States.PLAN_REVIEW, States.PLAN_APPROVED, States.SEALED]:
        assert lc.transition(s)
    assert 0.0 < lc.progress_fraction() < 1.0
    for s in [States.IMPLEMENTING, States.VERIFYING, States.PASSED]:
        lc.transition(s)
    assert lc.progress_fraction() == 1.0
