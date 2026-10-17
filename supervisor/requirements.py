"""L1 — Requirement interpretation.

Turns a free-form task into structured requirements with acceptance
criteria, dependencies, ambiguity flags, and a verification strategy.
This layer has NO final PASS/FAIL authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Requirement:
    id: str
    description: str
    source: str = "explicit"  # explicit | implicit
    priority: str = "should"  # must | should | may
    dependencies: list[str] = field(default_factory=list)
    acceptance_criteria: list[str] = field(default_factory=list)
    verification_strategy: str = "deterministic"
    risks: list[str] = field(default_factory=list)
    ambiguity: str = "none"  # none | low | medium | high


_AMBIGUITY_MARKERS = [
    re.compile(r"\b(maybe|perhaps|somehow|not sure|unclear|vague)\b", re.I),
    re.compile(r"\b(etc\.?|and so on|something like)\b", re.I),
]

_MUST_MARKERS = re.compile(r"\b(must|required|mandatory|critical|shall)\b", re.I)


def _assess_ambiguity(text: str) -> str:
    hits = sum(1 for p in _AMBIGUITY_MARKERS if p.search(text))
    if hits >= 2:
        return "high"
    if hits == 1:
        return "medium"
    return "none"


def parse_requirements(task: str) -> list[Requirement]:
    """Lightweight heuristic requirement extraction.

    Splits on sentence boundaries and bullet markers. Real projects may
    replace this with an LLM-backed extractor (TIER 2+).
    """
    chunks = re.split(r"(?:\n+|(?:[-*•]\s+)|(?:\d+[.)]\s+))", task)
    reqs: list[Requirement] = []
    for i, raw in enumerate(chunks):
        text = raw.strip().strip(".")
        if not text or len(text) < 5:
            continue
        priority = "must" if _MUST_MARKERS.search(text) else "should"
        ambiguity = _assess_ambiguity(text)
        reqs.append(
            Requirement(
                id=f"REQ-{len(reqs) + 1:03d}",
                description=text,
                priority=priority,
                acceptance_criteria=["implementation exists", "behavior is verifiable"],
                verification_strategy="deterministic",
                ambiguity=ambiguity,
            )
        )
    if not reqs:
        reqs.append(
            Requirement(
                id="REQ-001",
                description=task.strip(),
                acceptance_criteria=["implementation exists", "behavior is verifiable"],
            )
        )
    return reqs


def requirements_to_verification_plan(reqs: list[Requirement]) -> list[dict]:
    """Map each requirement to a suggested verification action."""
    plan: list[dict] = []
    seen_ids: set[str] = set()
    for req in reqs:
        if not isinstance(req, Requirement):
            raise TypeError("verification plan entries must be Requirement instances")
        if not isinstance(req.id, str) or not req.id.strip():
            raise ValueError("requirement id must be a non-empty string")
        requirement_id = req.id.strip()
        if requirement_id in seen_ids:
            raise ValueError(f"duplicate requirement id: {requirement_id}")
        seen_ids.add(requirement_id)
        plan.append(
            {
                "requirement_id": requirement_id,
                "description": req.description,
                "strategy": req.verification_strategy,
                "acceptance_criteria": list(req.acceptance_criteria),
            }
        )
    return plan
