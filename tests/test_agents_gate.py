"""Tests for L7 priority, L8 sealing, L13 gate, L14 multi-agent."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.priority import (
    resolve_priority, PriorityVerdict,
    LEVEL_DETERMINISTIC_VERIFICATION, LEVEL_AI_SEMANTIC_JUDGMENT,
)
from supervisor.sealing import (
    plan_hash, seal_plan, check_monotonic, MonotonicCheck,
)
from supervisor.gate import CompletionGate
from supervisor.policies import PolicyEngine, PolicyRule, RuleResult
from supervisor.agents import Agent, MultiAgentRegistry, Conflict


# --------------------------------------------------------------- L7 priority

def test_resolve_pass_when_no_findings():
    v = resolve_priority([])
    assert v.outcome == "PASS"


def test_low_level_failure_wins_over_high_level():
    findings = [
        RuleResult("R1", triggered=True, level=LEVEL_DETERMINISTIC_VERIFICATION, detail="test fail"),
        RuleResult("R2", triggered=False, level=LEVEL_AI_SEMANTIC_JUDGMENT, detail=""),
    ]
    v = resolve_priority(findings)
    assert v.outcome == "FAIL"
    assert v.blocking_level == LEVEL_DETERMINISTIC_VERIFICATION


# --------------------------------------------------------------- L8 sealing

def test_plan_hash_is_stable():
    p = {"task": "x", "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "echo"}]}]}
    assert plan_hash(p) == plan_hash(p)
    assert plan_hash(p) != plan_hash({**p, "task": "y"})


def test_seal_records_criteria_count():
    plan = {"task": "t", "steps": [
        {"id": 1, "verify": [{"type": "run", "cmd": "x"}, {"type": "file_exists", "path": "y"}]},
    ]}
    s = seal_plan(plan, "p1", "2026-09-03T00:00:00")
    assert s.criteria_count == 2
    assert s.plan_hash == plan_hash(plan)


def test_monotonic_ok_when_tightened():
    before = {"task": "t", "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}]}
    after = {"task": "t", "steps": [{"id": 1, "verify": [
        {"type": "run", "cmd": "x"}, {"type": "file_exists", "path": "y"}]}]}
    r = check_monotonic(before, after)
    assert r.ok and len(r.improvements) == 1


def test_monotonic_violated_when_weakened():
    before = {"task": "t", "steps": [{"id": 1, "verify": [
        {"type": "run", "cmd": "x"}, {"type": "file_exists", "path": "y"}]}]}
    after = {"task": "t", "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}]}
    r = check_monotonic(before, after)
    assert not r.ok and any(
        "removed" in v or "reduced" in v or "weaken" in v for v in r.violations
    )


def test_monotonic_violated_when_step_removed():
    before = {"task": "t", "steps": [
        {"id": 1, "verify": [{"type": "run", "cmd": "x"}]},
        {"id": 2, "verify": [{"type": "run", "cmd": "y"}]},
    ]}
    after = {"task": "t", "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}]}
    r = check_monotonic(before, after)
    assert not r.ok and any("removed" in v for v in r.violations)


# --------------------------------------------------------------- L13 gate

def _engine_with_rule(triggered: bool, level: int = 2) -> PolicyEngine:
    def fn(ctx):
        return RuleResult("TEST", triggered=triggered, level=level, detail="test" if triggered else "")
    return PolicyEngine([PolicyRule("TEST", level, "q", fn)])


def test_gate_pass_when_everything_ok():
    gate = CompletionGate(_engine_with_rule(False))
    report = gate.evaluate(deterministic_passed=True, pending_steps=[],
                          workspace_context={}, seal_check=MonotonicCheck(ok=True, violations=[], improvements=[]))
    assert report.outcome == "PASS"


def test_gate_fail_on_pending_steps():
    gate = CompletionGate(_engine_with_rule(False))
    report = gate.evaluate(deterministic_passed=True, pending_steps=[2], workspace_context={})
    assert report.outcome == "FAIL"


def test_gate_fail_on_deterministic_failure():
    gate = CompletionGate(_engine_with_rule(False))
    report = gate.evaluate(deterministic_passed=False, pending_steps=[], workspace_context={})
    assert report.outcome == "FAIL"


def test_gate_fail_on_seal_violation():
    gate = CompletionGate(_engine_with_rule(False))
    report = gate.evaluate(deterministic_passed=True, pending_steps=[], workspace_context={},
                           seal_check=MonotonicCheck(ok=False, violations=["weakened"], improvements=[]))
    assert report.outcome == "FAIL"


# --------------------------------------------------------------- L14 multi-agent

def test_registry_register_and_active(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    a = Agent(agent_id="a1", task_id="t1", plan_id="p1", owned_files={"src/x.py"})
    reg.register(a)
    assert len(reg.active_agents()) == 1


def test_conflict_detected(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    a1 = Agent(agent_id="a1", task_id="t1", plan_id="p1", owned_files={"src/x.py"})
    a2 = Agent(agent_id="a2", task_id="t2", plan_id="p2", owned_files=set())
    reg.register(a1)
    reg.register(a2)
    conflicts = reg.check_conflicts("a2", {"src/x.py"})
    assert len(conflicts) == 1
    assert conflicts[0].owner_agent == "a1"


def test_no_conflict_on_disjoint_files(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path))
    a1 = Agent(agent_id="a1", task_id="t1", plan_id="p1", owned_files={"src/x.py"})
    reg.register(a1)
    assert reg.check_conflicts("a2", {"src/y.py"}) == []


def test_stale_ownership_released(tmp_path):
    reg = MultiAgentRegistry(str(tmp_path), owner_timeout=0.0)
    a1 = Agent(agent_id="a1", task_id="t1", plan_id="p1", owned_files={"src/x.py"})
    reg.register(a1)
    import time
    time.sleep(0.05)
    released = reg.release_stale_ownership()
    assert "a1" in released
    assert reg.check_conflicts("a2", {"src/x.py"}) == []
