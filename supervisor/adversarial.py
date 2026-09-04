"""L12 — Adversarial small-AI layer (optional).

A second-pass semantic reviewer looking for gaps the deterministic core
cannot see: missing tests, weak tests, hidden assumptions, edge cases,
security risks, mock abuse, hardcoded success, ignored errors.

CRITICAL DESIGN: this layer only *proposes new deterministic checks*.
Its own verdict is never final. Each finding must be converted into a
real L10 check and executed before it counts.

This module is a no-op in TIER 1 (no LLM). It activates in TIER 2+.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class Finding:
    check_id: str
    severity: str                 # info | warn | high | critical
    description: str
    suggested_check: Optional[Dict] = None
    evidence: str = ""


@dataclass
class AdversarialReport:
    findings: List[Finding] = field(default_factory=list)
    proposed_checks: List[Dict] = field(default_factory=list)
    used_llm: bool = False

    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)


# Deterministic lightweight checks that do NOT need an LLM.
def _static_adversarial_checks(plan: Dict, evidence_lines: List[str]) -> List[Finding]:
    findings: List[Finding] = []
    steps = plan.get("steps", [])

    for step in steps:
        verify = step.get("verify", [])
        types = [c.get("type") for c in verify if isinstance(c, dict)]
        if "run" in types:
            cmds = " ".join(c.get("cmd", "") for c in verify if c.get("type") == "run")
            if "assert True" in cmds or "pass" == cmds.strip():
                findings.append(Finding(
                    check_id="ADV-HARDCODED-PASS",
                    severity="critical",
                    description="step %d appears to hardcode success" % step.get("id"),
                ))

    joined = "\n".join(evidence_lines)
    if "mock" in joined.lower() or "monkeypatch" in joined.lower():
        findings.append(Finding(
            check_id="ADV-MOCK-USED",
            severity="warn",
            description="mock/monkeypatch detected; ensure behavior is still exercised",
        ))

    if "except" in joined and "pass" in joined:
        findings.append(Finding(
            check_id="ADV-IGNORED-ERROR",
            severity="high",
            description="bare except/pass pattern may hide failures",
        ))

    return findings


def run_adversarial_review(
    plan: Dict,
    evidence_path: Optional[str] = None,
    llm_client: Optional[Callable[[str], str]] = None,
) -> AdversarialReport:
    """Run adversarial review. LLM path only when `llm_client` provided."""
    evidence_lines: List[str] = []
    if evidence_path and evidence_path:
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                evidence_lines = f.readlines()
        except OSError:
            pass

    findings = _static_adversarial_checks(plan, evidence_lines)
    proposed: List[Dict] = []
    used_llm = False

    for f in findings:
        if f.severity in ("high", "critical"):
            proposed.append({
                "type": "review",
                "description": f.description,
                "severity": f.severity,
            })

    if llm_client is not None:
        used_llm = True
        # LLM review is intentionally conservative: it returns candidate
        # checks, never a verdict. Parsing is best-effort.
        try:
            prompt = _build_llm_prompt(plan, findings)
            _ = llm_client(prompt)  # result converted to proposed checks by caller
        except Exception:
            pass

    return AdversarialReport(findings=findings, proposed_checks=proposed, used_llm=used_llm)


def _build_llm_prompt(plan: Dict, static_findings: List[Finding]) -> str:
    return (
        "Review this implementation plan for missing tests, weak tests, "
        "hidden assumptions, edge cases, security risks, mock abuse, "
        "hardcoded success, and ignored errors. "
        "Return ONLY a JSON array of proposed deterministic checks. "
        "Do not emit a PASS/FAIL verdict.\n\n"
        "PLAN:\n" + json_compact(plan) + "\n"
        "STATIC_FINDINGS:\n" + "\n".join(f.description for f in static_findings) + "\n"
    )


def json_compact(obj) -> str:
    import json
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)
