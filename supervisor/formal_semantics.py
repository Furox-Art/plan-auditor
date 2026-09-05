"""Deterministic requirement-to-formal-goal alignment for classical planning.

This layer prevents a syntactically valid STRIPS model from being disconnected
from the requirements it is supposed to prove. It does not interpret natural
language. Instead it composes with the host-owned request alignment layer:

request text/acceptance checks -> exact plan requirement -> canonical formal goal
fact -> covering plan step -> symbolic action effect.

For contracts produced by the deterministic auto-formalizer, this module also
recompiles the expected contract from structured plan primitives and requires an
exact match. That closes the "AI generated a weaker symbolic model" gap without
asking another LLM to judge the first LLM.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping

FORMAL_KEY = "formal_planning"
REQUIREMENT_FACT_PREFIX = "requirement-satisfied:"
FORMALIZATION_SOURCE_PREFIX = "formalization-source:"
_GENERATED_STRUCTURAL_PREFIXES = (
    "step-completed:",
    "output-available:",
)


@dataclass
class FormalSemanticResult:
    enabled: bool = False
    valid: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    requirement_facts: Dict[str, str] = field(default_factory=dict)
    producer_steps: Dict[str, List[int]] = field(default_factory=dict)
    generated: bool = False

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "requirement_facts": dict(self.requirement_facts),
            "producer_steps": {k: list(v) for k, v in self.producer_steps.items()},
            "generated": self.generated,
        }


def requirement_goal_fact(requirement_id: str) -> str:
    value = f"{REQUIREMENT_FACT_PREFIX}{requirement_id.strip()}"
    if len(value) > 256:
        raise ValueError("requirement id is too long for a canonical formal goal fact")
    return value


def _requirements(plan: Mapping[str, Any]) -> List[Dict[str, str]]:
    result: List[Dict[str, str]] = []
    raw = plan.get("requirements", [])
    if not isinstance(raw, list):
        return result
    for index, item in enumerate(raw, 1):
        if isinstance(item, str):
            result.append(
                {"id": f"REQ-{index:03d}", "description": item, "priority": "must"}
            )
            continue
        if not isinstance(item, Mapping):
            continue
        req_id = item.get("id")
        if not isinstance(req_id, str) or not req_id.strip():
            continue
        result.append(
            {
                "id": req_id.strip(),
                "description": str(item.get("description", "")),
                "priority": str(item.get("priority", "must")).lower(),
            }
        )
    return result


def _anchors(plan: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    found: List[Mapping[str, Any]] = []
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping):
            continue
        for check in step.get("verify", []) or []:
            if isinstance(check, Mapping) and FORMAL_KEY in check:
                found.append(check)
    return found


def analyze_formal_semantics(plan: Mapping[str, Any]) -> FormalSemanticResult:
    anchors = _anchors(plan)
    if not anchors:
        return FormalSemanticResult()
    result = FormalSemanticResult(enabled=True)
    if len(anchors) != 1:
        result.valid = False
        result.errors.append(
            f"formal semantic alignment requires exactly one formal_planning anchor; "
            f"found {len(anchors)}"
        )
        return result

    contract = anchors[0].get(FORMAL_KEY)
    if not isinstance(contract, Mapping):
        result.valid = False
        result.errors.append(
            "formal_planning must be an object for semantic alignment"
        )
        return result

    goals_raw = contract.get("goal_facts", [])
    initial_raw = contract.get("initial_facts", [])
    actions_raw = contract.get("actions", [])
    goals = (
        {x for x in goals_raw if isinstance(x, str)}
        if isinstance(goals_raw, list)
        else set()
    )
    initial = (
        {x for x in initial_raw if isinstance(x, str)}
        if isinstance(initial_raw, list)
        else set()
    )

    source_markers = sorted(
        fact
        for fact in initial
        if fact.startswith(FORMALIZATION_SOURCE_PREFIX)
    )
    if source_markers:
        result.generated = True
        if len(source_markers) != 1:
            result.errors.append(
                "generated formal contract must contain exactly one formalization-source marker"
            )
        try:
            from .formal_compiler import validate_generated_contract

            result.errors.extend(validate_generated_contract(plan, contract))
        except (ImportError, ValueError) as exc:
            result.errors.append(
                f"generated formal contract could not be independently recompiled: {exc}"
            )

    step_covers: Dict[int, set[str]] = {}
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping) or not isinstance(step.get("id"), int):
            continue
        covers = step.get("covers", [])
        step_covers[int(step["id"])] = (
            {
                x.strip()
                for x in covers
                if isinstance(x, str) and x.strip()
            }
            if isinstance(covers, list)
            else set()
        )

    producers: Dict[str, List[int]] = {}
    effect_free: List[int] = []
    if isinstance(actions_raw, list):
        for action in actions_raw:
            if not isinstance(action, Mapping) or not isinstance(action.get("step"), int):
                continue
            sid = int(action["step"])
            adds = (
                {
                    x
                    for x in action.get("add_effects", [])
                    if isinstance(x, str)
                }
                if isinstance(action.get("add_effects", []), list)
                else set()
            )
            deletes = (
                {
                    x
                    for x in action.get("del_effects", [])
                    if isinstance(x, str)
                }
                if isinstance(action.get("del_effects", []), list)
                else set()
            )
            if not adds and not deletes:
                effect_free.append(sid)
            for fact in adds:
                producers.setdefault(fact, []).append(sid)

    for sid in sorted(effect_free):
        result.errors.append(
            f"formal action for step {sid} has no symbolic effect; "
            "every plan step must participate in the formal model"
        )

    for req in _requirements(plan):
        if req["priority"] not in {"must", "should"}:
            continue
        req_id = req["id"]
        try:
            fact = requirement_goal_fact(req_id)
        except ValueError as exc:
            result.errors.append(f"requirement {req_id}: {exc}")
            continue
        result.requirement_facts[req_id] = fact
        if fact not in goals:
            result.errors.append(
                f"required requirement {req_id} is not bound to formal goal fact {fact!r}"
            )
            continue
        if fact in initial:
            result.errors.append(
                f"required requirement {req_id} formal goal fact is already true initially; "
                "it must be produced by verified work"
            )
        fact_producers = sorted(set(producers.get(fact, [])))
        result.producer_steps[req_id] = fact_producers
        if not fact_producers:
            result.errors.append(
                f"required requirement {req_id} formal goal fact has no producing action"
            )
            continue
        bad = [
            sid
            for sid in fact_producers
            if req_id not in step_covers.get(sid, set())
        ]
        if bad:
            result.errors.append(
                f"requirement {req_id} goal fact is produced by non-covering step(s): {bad}"
            )
        if not any(
            req_id in step_covers.get(sid, set()) for sid in fact_producers
        ):
            result.errors.append(
                f"requirement {req_id} goal fact is not produced by any step "
                "that covers the requirement"
            )

    required_goal_facts = set(result.requirement_facts.values())
    if result.generated:
        unbound = sorted(
            fact
            for fact in goals - required_goal_facts
            if not fact.startswith(_GENERATED_STRUCTURAL_PREFIXES)
        )
    else:
        unbound = sorted(goals - required_goal_facts)
    if unbound:
        result.warnings.append(
            "formal goal fact(s) are not direct must/should requirement bindings: "
            + ", ".join(unbound)
        )

    result.valid = not result.errors
    return result
