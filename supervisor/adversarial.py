"""L12 — Adversarial small-AI layer (optional).

A second-pass semantic reviewer looking for gaps the deterministic core
cannot see: missing tests, weak tests, hidden assumptions, edge cases,
security risks, mock abuse, hardcoded success, ignored errors.

CRITICAL DESIGN: this layer only *proposes new deterministic checks*.
Its own verdict is never final. Each finding must be converted into a
real L10 check and executed before it counts.

This module is a no-op in TIER 1 (no LLM). It activates in TIER 2+ with
a real LLM client, or with a mock client for testing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
import json
import re


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
    raw_llm_output: str = ""

    def has_critical(self) -> bool:
        return any(f.severity == "critical" for f in self.findings)

    def has_high_or_worse(self) -> bool:
        return any(f.severity in ("high", "critical") for f in self.findings)


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

    # Weak verification: only file_exists/regex across ALL steps.
    all_types = set()
    for step in steps:
        for c in step.get("verify", []):
            if isinstance(c, dict):
                all_types.add(c.get("type"))
    if all_types and all_types <= {"file_exists", "regex"}:
        findings.append(Finding(
            check_id="ADV-WEAK-ONLY",
            severity="high",
            description="plan uses only weak checks (file_exists/regex)",
            suggested_check={"type": "pytest", "args": "."},
        ))

    # No negative-path testing mentioned.
    if not any("negative" in l.lower() or "fail" in l.lower() for l in evidence_lines):
        findings.append(Finding(
            check_id="ADV-NEGATIVE-PATH",
            severity="warn",
            description="no negative-path / failure-case testing evidence found",
            suggested_check={"type": "review", "description": "add a test for invalid inputs"},
        ))

    return findings


def _parse_llm_findings(raw: str) -> List[Finding]:
    """Parse an LLM response into findings. Tolerates free text or JSON."""
    findings: List[Finding] = []
    if not raw:
        return findings
    # Try JSON array of objects.
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    findings.append(Finding(
                        check_id="ADV-LLM-%d" % (len(findings) + 1),
                        severity=item.get("severity", "warn"),
                        description=item.get("description", str(item)),
                        suggested_check=item.get("suggested_check"),
                    ))
            return findings
    except json.JSONDecodeError:
        pass
    # Fallback: split on lines, look for [SEVERITY] markers.
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"\[(critical|high|warn|info)\]\s*(.+)", line, re.I)
        if m:
            findings.append(Finding(check_id="ADV-LLM-%d" % (len(findings) + 1),
                                   severity=m.group(1).lower(), description=m.group(2)))
        elif len(line) > 10:
            findings.append(Finding(check_id="ADV-LLM-%d" % (len(findings) + 1),
                                   severity="warn", description=line))
    return findings


def _build_llm_prompt(plan: Dict, static_findings: List[Finding]) -> str:
    return (
        "You are an adversarial code reviewer. Review this implementation "
        "plan for: missing tests, weak tests, hidden assumptions, edge cases, "
        "security risks, mock abuse, hardcoded success, ignored errors.\n\n"
        "CRITICAL: do NOT emit a PASS/FAIL verdict. Only propose specific "
        "deterministic checks that could be run as shell commands or pytest.\n\n"
        "PLAN:\n" + json.dumps(plan, sort_keys=True, ensure_ascii=False, indent=2) + "\n\n"
        "STATIC_FINDINGS:\n" + "\n".join("- " + f.description for f in static_findings) + "\n\n"
        "Reply with a JSON array of objects: "
        "[{\"severity\": \"info|warn|high|critical\", "
        "\"description\": \"...\", "
        "\"suggested_check\": {\"type\": \"run\", \"cmd\": \"...\"}}].\n"
        "If nothing needs attention, reply []."
    )


def run_adversarial_review(
    plan: Dict,
    evidence_path: Optional[str] = None,
    llm_client: Optional[Callable[[str], str]] = None,
) -> AdversarialReport:
    """Run adversarial review. LLM path only when `llm_client` provided."""
    evidence_lines: List[str] = []
    if evidence_path:
        try:
            with open(evidence_path, encoding="utf-8", errors="replace") as f:
                evidence_lines = f.readlines()
        except OSError:
            pass

    findings = _static_adversarial_checks(plan, evidence_lines)
    proposed: List[Finding] = [f for f in findings if f.suggested_check]
    used_llm = False
    raw_output = ""

    if llm_client is not None:
        used_llm = True
        try:
            prompt = _build_llm_prompt(plan, findings)
            raw_output = llm_client(prompt) or ""
            if raw_output:
                llm_findings = _parse_llm_findings(raw_output)
                findings.extend(llm_findings)
                for f in llm_findings:
                    if f.suggested_check:
                        proposed.append(f)
        except Exception:
            # LLM failures must not break the gate; record and continue.
            findings.append(Finding(check_id="ADV-LLM-ERROR", severity="info",
                                    description="adversarial LLM review skipped (error)"))

    return AdversarialReport(
        findings=findings,
        proposed_checks=[f.suggested_check for f in proposed if f.suggested_check],
        used_llm=used_llm,
        raw_llm_output=raw_output,
    )
