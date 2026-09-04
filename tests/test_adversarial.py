"""Tests for L12 adversarial layer, including mock LLM client."""
import sys
import os
import json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from supervisor.adversarial import (
    run_adversarial_review, _parse_llm_findings, _static_adversarial_checks,
    Finding,
)


def test_static_detects_hardcoded_pass():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "assert True"}]}]}
    findings = _static_adversarial_checks(plan, [])
    assert any(f.check_id == "ADV-HARDCODED-PASS" for f in findings)


def test_static_detects_mocked_evidence():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "pytest"}]}]}
    findings = _static_adversarial_checks(plan, ["    user = MagicMock()"])
    assert any(f.check_id == "ADV-MOCK-USED" for f in findings)


def test_static_detects_weak_only_checks():
    plan = {"steps": [{"id": 1, "verify": [{"type": "file_exists", "path": "x"},
                                             {"type": "regex", "path": "y", "pattern": "z"}]}]}
    findings = _static_adversarial_checks(plan, [])
    assert any("weak" in f.description.lower() for f in findings)


def test_adversarial_no_llm_is_tier1():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "assert True"}]}]}
    report = run_adversarial_review(plan)
    assert report.used_llm is False
    assert report.has_critical()


def test_adversarial_with_mock_llm():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "echo ok"}]}]}

    def mock_llm(prompt):
        return json.dumps([
            {"severity": "high", "description": "missing edge-case test",
             "suggested_check": {"type": "pytest", "args": "tests/ -q -k edge"}},
            {"severity": "info", "description": "looks okay overall"},
        ])

    report = run_adversarial_review(plan, llm_client=mock_llm)
    assert report.used_llm is True
    assert len(report.proposed_checks) >= 1
    assert report.raw_llm_output


def test_adversarial_llm_error_does_not_crash():
    plan = {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}]}

    def bad_llm(prompt):
        raise RuntimeError("network down")

    report = run_adversarial_review(plan, llm_client=bad_llm)
    assert report.used_llm is True
    assert report.has_critical() is False  # static is clean


def test_parse_llm_json_array():
    raw = json.dumps([{"severity": "critical", "description": "hole found"}])
    findings = _parse_llm_findings(raw)
    assert len(findings) == 1 and findings[0].severity == "critical"


def test_parse_llm_free_text():
    raw = "[high] missing authz check\n[info] minor style note"
    findings = _parse_llm_findings(raw)
    assert len(findings) == 2


def test_parse_llm_empty():
    assert _parse_llm_findings("") == []


def test_adversarial_finding_equality():
    f = Finding(check_id="x", severity="high", description="d")
    assert f.severity == "high"
