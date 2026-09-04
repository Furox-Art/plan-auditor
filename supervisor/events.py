"""L0 — ELIZA-like local event / pattern detection layer.

Deliberately tiny and deterministic: it scans messages and file events
for known patterns and emits trigger signals. It does NOT judge
semantic correctness, does NOT issue PASS/FAIL, and does NOT do
requirement reasoning. It only detects, routes, and triggers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Pattern
import re


class Trigger(str, Enum):
    FINAL_AUDIT = "final_audit"
    PLAN_INTEGRITY = "plan_integrity"
    RETRY_OR_ESCALATION = "retry_or_escalation"
    SECURITY_REVIEW = "security_review"
    MONOTONIC_CHECK = "monotonic_check"


@dataclass
class Event:
    trigger: Trigger
    source: str              # "message" | "file" | "heartbeat" | "timer"
    raw: str
    span: Optional[str] = None
    metadata: Dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"Event({self.trigger.value}, src={self.source}, span={self.span!r})"


@dataclass
class PatternRule:
    trigger: Trigger
    source: str
    patterns: List[Pattern[str]]
    description: str = ""

    def matches(self, text: str) -> Optional[str]:
        for p in self.patterns:
            m = p.search(text)
            if m:
                return m.group(0)
        return None


# Heuristic patterns that suggest an agent is claiming completion.
_COMPLETION_PATTERNS = [
    re.compile(r"\b(done|complete[sd]?|finished|all (tests|checks|steps) (pass|ok|green))\b", re.I),
    re.compile(r"\b(ship (it|this)|ready to (merge|deploy|ship))\b", re.I),
    re.compile(r"\b(no (further|more) (changes?|work|action))\b", re.I),
]

# Patterns suggesting a verification config changed (both orderings).
_CONFIG_CHANGE = [
    re.compile(r"\b(verify|acceptance|criteria|threshold)\w*\s*(changed?|weaken(ed)?|relax(ed)?|lowered?|disabled?|removed?)\b", re.I),
    re.compile(r"\b(weaken(ed)?|relax(ed)?|lowered?|disabled?|removed?|disabled?)\b[^.]*\b(verify|acceptance|criteria|threshold|test|check)\b", re.I),
    re.compile(r"\b(disabl(ed|ing)|skip(ped|ping)|bypass(ed|ing)|commented out)\b.+\b(test|check)\b", re.I),
]

# Repeated failure.
_REPEATED_FAILURE = [
    re.compile(r"\b(retry|attempt|try again|flak(?:y|ing)|intermittent)\w*\b", re.I),
]

# Security-relevant events.
_SECURITY = [
    re.compile(r"\b(secret|token|key|password|credential|api[_-]?key)\w*\b", re.I),
    re.compile(r"\b(curl|wget)\b[^|]{0,80}\|[\s]*(sh|bash)\b", re.I),
]

DEFAULT_RULES: List[PatternRule] = [
    PatternRule(Trigger.FINAL_AUDIT, "message", _COMPLETION_PATTERNS,
                "agent appears to claim completion"),
    PatternRule(Trigger.PLAN_INTEGRITY, "message", _CONFIG_CHANGE,
                "verification criteria appear weakened or disabled"),
    PatternRule(Trigger.PLAN_INTEGRITY, "file", _CONFIG_CHANGE,
                "plan/check config file changed"),
    PatternRule(Trigger.RETRY_OR_ESCALATION, "message", _REPEATED_FAILURE,
                "repeated failure / retry language"),
    PatternRule(Trigger.SECURITY_REVIEW, "message", _SECURITY,
                "possible secret or destructive command"),
]


class EventBus:
    """Tiny synchronous event bus. Routes matched patterns to handlers."""

    def __init__(self, rules: Optional[List[PatternRule]] = None):
        self.rules = rules or list(DEFAULT_RULES)
        self.handlers: Dict[Trigger, List[Callable[[Event], None]]] = {}
        self.history: List[Event] = []

    def on(self, trigger: Trigger, handler: Callable[[Event], None]) -> None:
        self.handlers.setdefault(trigger, []).append(handler)

    def emit(self, event: Event) -> None:
        self.history.append(event)
        for handler in self.handlers.get(event.trigger, []):
            handler(event)

    def scan_message(self, text: str) -> List[Event]:
        events = self._scan(text, "message")
        for ev in events:
            self.emit(ev)
        return events

    def scan_file_event(self, path: str, content: str) -> List[Event]:
        events = self._scan(content, "file")
        for ev in events:
            ev.metadata["path"] = path
            self.emit(ev)
        return events

    def scan_file(self, path: str) -> List[Event]:
        p = Path(path)
        if not p.is_file():
            return []
        try:
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        return self.scan_file_event(str(p), content)

    def _scan(self, text: str, source: str) -> List[Event]:
        out: List[Event] = []
        seen: set = set()
        for rule in self.rules:
            if rule.source and rule.source != source:
                continue
            span = rule.matches(text)
            if span is None:
                continue
            key = (rule.trigger, span)
            if key in seen:
                continue
            seen.add(key)
            out.append(Event(trigger=rule.trigger, source=source, raw=text, span=span,
                            metadata={"rule": rule.description}))
        return out

    def dedup_window(self, window: int = 50) -> List[Event]:
        """Return events whose (trigger, span) is unique within the last `window` events."""
        out: List[Event] = []
        seen: set = set()
        for ev in reversed(self.history[-window:]):
            key = (ev.trigger, ev.span)
            if key in seen:
                continue
            seen.add(key)
            out.append(ev)
        return list(reversed(out))
