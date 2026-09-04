"""L1 — Requirement interpretation.

Turns a free-form task into structured requirements with acceptance
criteria, dependencies, ambiguity flags, and a verification strategy.
This layer has NO final PASS/FAIL authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class Requirement:
    id: str
    description: str
    source: str = "explicit"          # explicit | implicit
    priority: str = "should"          # must | should | may
    dependencies: List[str] = field(default_factory=list)
    acceptance_criteria: List[str] = field(default_factory=list)
    verification_strategy: str = "deterministic"
    risks: List[str] = field(default_factory=list)
    ambiguity: str = "none"           # none | low | medium | high


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


def parse_requirements(task: str) -> List[Requirement]:
    """Lightweight heuristic requirement extraction.

    Splits on sentence boundaries and bullet markers. Real projects may
    replace this with an LLM-backed extractor (TIER 2+).
    """
    chunks = re.split(r"(?:\n+|(?:[-*•]\s+)|(?:\d+[.)]\s+))", task)
    reqs: List[Requirement] = []
    for i, raw in enumerate(chunks):
        text = raw.strip().strip(".")
        if not text or len(text) < 5:
            continue
        priority = "must" if _MUST_MARKERS.search(text) else "should"
        ambiguity = _assess_ambiguity(text)
        reqs.append(Requirement(
            id="REQ-%03d" % (len(reqs) + 1),
            description=text,
            priority=priority,
            acceptance_criteria=["implementation exists", "behavior is verifiable"],
            verification_strategy="deterministic",
            ambiguity=ambiguity,
        ))
    if not reqs:
        reqs.append(Requirement(
            id="REQ-001",
            description=task.strip(),
            acceptance_criteria=["implementation exists", "behavior is verifiable"],
        ))
    return reqs


def requirements_to_verification_plan(reqs: List[Requirement]) -> List[Dict]:
    """Map each requirement to a suggested verification action."""
    plan: List[Dict] = []
    for req in reqs:
        plan.append({
            "requirement_id": req.id,
            "description": req.description,
            "strategy": req.verification_strategy,
            "acceptance_criteria": req.acceptance_criteria,
        })
    return plan
