"""L3 — deterministic policy engine.

Rules are plain IF/THEN checks over a structured context. They never execute
model-provided code. Unknown integrity state is fail-closed.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional


@dataclass
class RuleResult:
    rule_id: str
    triggered: bool
    level: int
    detail: str = ""
    evidence: str = ""


RuleFn = Callable[[Dict[str, Any]], RuleResult]


@dataclass
class PolicyRule:
    rule_id: str
    level: int
    question: str
    fn: RuleFn


class PolicyEngine:
    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self.rules: List[PolicyRule] = rules or []

    def add(self, rule: PolicyRule) -> None:
        self.rules.append(rule)

    def extend(self, rules: Iterable[PolicyRule]) -> None:
        self.rules.extend(rules)

    def evaluate(self, context: Dict[str, Any]) -> List[RuleResult]:
        return [r.fn(context) for r in self.rules]

    def failures(self, context: Dict[str, Any]) -> List[RuleResult]:
        return [r for r in self.evaluate(context) if r.triggered]


def _has_pending(state: Dict) -> bool:
    return any(step.get("status") != "verified" for step in state.get("plan_steps", []))


def _has_failed_test(state: Dict) -> bool:
    for step in state.get("plan_steps", []):
        for check in step.get("results", []):
            if check.get("passed") is False:
                return True
    return False


def _seal_intact(state: Dict) -> bool:
    # Prefer the real monotonic seal verdict produced by L8. Missing integrity
    # state is NOT equivalent to a valid seal.
    if "seal_ok" in state:
        return state.get("seal_ok") is True
    sealed = state.get("seal_hash")
    current = state.get("current_hash")
    if not sealed or not current:
        return False
    return sealed == current


def _secret_in_log(state: Dict) -> Optional[str]:
    patterns = [r"(api[_-]?key|token|password|secret)\s*[:=]\s*\S+"]
    for log in state.get("logs", []):
        for pat in patterns:
            m = re.search(pat, str(log), re.I)
            if m:
                return m.group(0)
    return None


def required_tests_passing(ctx: Dict) -> RuleResult:
    hit = _has_failed_test(ctx)
    return RuleResult("REQ_TESTS_PASS", hit, 2, "A required test failed" if hit else "")


def no_pending_steps(ctx: Dict) -> RuleResult:
    hit = _has_pending(ctx)
    return RuleResult("NO_PENDING", hit, 2, "Plan has steps not marked verified" if hit else "")


def seal_not_violated(ctx: Dict) -> RuleResult:
    intact = _seal_intact(ctx)
    return RuleResult(
        "SEAL_INTACT", not intact, 1,
        "Plan seal is missing, legacy, or monotonic verification failed" if not intact else "",
    )


def no_secret_leak(ctx: Dict) -> RuleResult:
    hit = _secret_in_log(ctx)
    return RuleResult(
        "NO_SECRET_LEAK", hit is not None, 3,
        "Possible secret in logs" if hit else "", hit or "",
    )


def evidence_chain_valid(ctx: Dict) -> RuleResult:
    valid = ctx.get("evidence_valid") is True
    return RuleResult(
        "EVIDENCE_VALID", not valid, 2,
        "Evidence integrity check failed or is unknown" if not valid else "",
    )


def required_tool_present(ctx: Dict) -> RuleResult:
    missing = ctx.get("missing_required_tools", [])
    return RuleResult(
        "TOOLS_PRESENT", bool(missing), 2,
        "Missing required tools: %s" % ", ".join(missing) if missing else "",
    )


DEFAULT_RULES: List[PolicyRule] = [
    PolicyRule("REQ_TESTS_PASS", 2, "Do all required tests pass?", required_tests_passing),
    PolicyRule("NO_PENDING", 2, "Are all plan steps verified?", no_pending_steps),
    PolicyRule("SEAL_INTACT", 1, "Is the sealed plan intact?", seal_not_violated),
    PolicyRule("NO_SECRET_LEAK", 3, "Any secret leaked to logs?", no_secret_leak),
    PolicyRule("EVIDENCE_VALID", 2, "Is the evidence chain valid?", evidence_chain_valid),
    PolicyRule("TOOLS_PRESENT", 2, "Are required tools present?", required_tool_present),
]


def default_engine() -> PolicyEngine:
    return PolicyEngine(list(DEFAULT_RULES))


def _ctx_get(ctx: Dict[str, Any], field: str) -> Any:
    cur: Any = ctx
    for part in field.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _as_text(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        return "\n".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return "" if value is None else str(value)


def _compile_policy(spec: Dict[str, Any]) -> Optional[PolicyRule]:
    rule_id = str(spec.get("id") or spec.get("rule_id") or "").strip()
    kind = str(spec.get("kind") or "").strip()
    field = str(spec.get("field") or "").strip()
    if not rule_id or not kind or not field:
        return None
    try:
        level = int(spec.get("level", 3))
    except (TypeError, ValueError):
        return None
    detail = str(spec.get("detail") or rule_id)
    question = str(spec.get("question") or detail)

    if kind == "forbid_regex":
        pattern = str(spec.get("pattern") or "")
        if not pattern:
            return None
        try:
            rx = re.compile(pattern, re.I)
        except re.error:
            return None

        def fn(ctx: Dict[str, Any], *, _rx=rx, _field=field, _id=rule_id,
               _level=level, _detail=detail) -> RuleResult:
            text = _as_text(_ctx_get(ctx, _field))
            match = _rx.search(text)
            return RuleResult(_id, match is not None, _level,
                              _detail if match else "", match.group(0) if match else "")

    elif kind == "require_truthy":
        def fn(ctx: Dict[str, Any], *, _field=field, _id=rule_id,
               _level=level, _detail=detail) -> RuleResult:
            ok = bool(_ctx_get(ctx, _field))
            return RuleResult(_id, not ok, _level, _detail if not ok else "")

    elif kind == "require_empty":
        def fn(ctx: Dict[str, Any], *, _field=field, _id=rule_id,
               _level=level, _detail=detail) -> RuleResult:
            value = _ctx_get(ctx, _field)
            hit = bool(value)
            return RuleResult(_id, hit, _level, _detail if hit else "", _as_text(value) if hit else "")

    else:
        return None

    return PolicyRule(rule_id, level, question, fn)


def _parse_scalar(raw: str) -> Any:
    raw = raw.strip()
    lowered = raw.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        return ast.literal_eval(raw)
    except (ValueError, SyntaxError):
        try:
            return int(raw)
        except ValueError:
            return raw.strip('"\'')


def _parse_simple_toml_rules(text: str) -> List[Dict[str, Any]]:
    """Parse the small TOML subset used by policies without extra deps.

    Supported shape: repeated ``[[rules]]`` tables with scalar key/value pairs.
    This keeps Python 3.10 compatibility while avoiding executable config.
    """
    out: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[rules]]":
            current = {}
            out.append(current)
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        current[key.strip()] = _parse_scalar(value.split("#", 1)[0].strip())
    return out


def load_policy_rules_from_dir(dirpath: str) -> List[PolicyRule]:
    """Load deterministic user policies from ``*.toml`` or ``*.json``.

    Supported kinds: ``forbid_regex``, ``require_truthy``, ``require_empty``.
    Invalid files/rules are ignored rather than executed or guessed.
    """
    root = Path(dirpath)
    if not root.is_dir():
        return []
    specs: List[Dict[str, Any]] = []
    for path in sorted(root.iterdir()):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        try:
            if path.suffix.lower() == ".json":
                data = json.loads(text)
                items = data.get("rules", []) if isinstance(data, dict) else data
                if isinstance(items, list):
                    specs.extend(item for item in items if isinstance(item, dict))
            elif path.suffix.lower() == ".toml":
                specs.extend(_parse_simple_toml_rules(text))
        except (json.JSONDecodeError, ValueError):
            continue

    rules: List[PolicyRule] = []
    for spec in specs:
        rule = _compile_policy(spec)
        if rule is not None:
            rules.append(rule)
    return rules
