"""Tests for L0 event layer."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.events import EventBus, Trigger, PatternRule, DEFAULT_RULES
import re


def test_detects_completion_claim():
    bus = EventBus()
    events = bus.scan_message("All tests pass, the task is done.")
    assert any(e.trigger == Trigger.FINAL_AUDIT for e in events)


def test_detects_criteria_weakening():
    bus = EventBus()
    events = bus.scan_message("I weakened the acceptance criteria to make it pass.")
    assert any(e.trigger == Trigger.PLAN_INTEGRITY for e in events)


def test_detects_test_disabled():
    bus = EventBus()
    events = bus.scan_file_event("plan.json", 'I disabled the required test in verify.')
    assert any(e.trigger == Trigger.PLAN_INTEGRITY for e in events)


def test_detects_repeated_failure():
    bus = EventBus()
    events = bus.scan_message("This is the third retry, the test is flaky.")
    assert any(e.trigger == Trigger.RETRY_OR_ESCALATION for e in events)


def test_detects_security_reference():
    bus = EventBus()
    events = bus.scan_message("The api_key is logged in the output.")
    assert any(e.trigger == Trigger.SECURITY_REVIEW for e in events)


def test_no_false_positive_on_normal_work():
    bus = EventBus()
    events = bus.scan_message("Implementing the fib function now, writing the loop body.")
    assert events == []


def test_handler_receives_event():
    bus = EventBus()
    captured = []
    bus.on(Trigger.FINAL_AUDIT, lambda e: captured.append(e))
    bus.scan_message("All checks green, we are finished.")
    assert len(captured) == 1
    assert captured[0].trigger == Trigger.FINAL_AUDIT


def test_dedup_window_collapses_same_span():
    bus = EventBus()
    for _ in range(5):
        bus.scan_message("done done done")
    deduped = bus.dedup_window(window=50)
    assert len(deduped) == 1


def test_custom_rule():
    rule = PatternRule(
        trigger=Trigger.FINAL_AUDIT,
        source="message",
        patterns=[re.compile(r"\bship\s*it\b", re.I)],
        description="ship it phrase",
    )
    bus = EventBus(rules=[rule])
    events = bus.scan_message("Let's ship it now.")
    assert any(e.trigger == Trigger.FINAL_AUDIT for e in events)


def test_default_rules_nonempty():
    assert len(DEFAULT_RULES) >= 4
