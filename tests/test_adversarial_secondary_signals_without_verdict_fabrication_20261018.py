"""Semantic reviewer is only a source of proposed tests, never an audit PASS."""

from __future__ import annotations

import json

from supervisor import adversarial as adv


def test_high_findings_and_critical_findings_remain_distinct():
    high = adv.AdversarialReport(findings=[adv.Finding("one", "high", "not verified")])
    assert high.has_high_or_worse() is True
    assert high.has_critical() is False
    critical = adv.AdversarialReport(findings=[adv.Finding("two", "critical", "unsafe")])
    assert critical.has_high_or_worse() is True
    assert critical.has_critical() is True


def test_ignored_except_pass_in_real_evidence_is_a_high_review_signal(tmp_path):
    evidence = tmp_path / "observations.txt"
    evidence.write_text("except Exception:\n    pass\nfailure reproduced\n")
    out = adv.run_adversarial_review({"steps": []}, evidence_path=str(evidence))
    assert any(x.check_id == "ADV-IGNORED-ERROR" and x.severity == "high" for x in out.findings)
    assert all("PASS" not in x.check_id for x in out.findings)


def test_negative_path_evidence_does_not_trigger_missing_negative_path_warning():
    observed = adv._static_adversarial_checks(
        {"steps": []}, ["real failing input reproduced by test"]
    )
    assert all(f.check_id != "ADV-NEGATIVE-PATH" for f in observed)


def test_empty_file_and_missing_evidence_are_not_relabelled_as_verified(monkeypatch, tmp_path):
    marker = tmp_path / "no-evidence.txt"
    marker.write_text("undocumented")
    import builtins

    original = builtins.open

    def deny(name, *args, **kwargs):
        if str(name) == str(marker):
            raise OSError("read failed")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny)
    report = adv.run_adversarial_review({"steps": []}, evidence_path=str(marker))
    assert report.used_llm is False
    assert any(f.check_id == "ADV-NEGATIVE-PATH" for f in report.findings)


def test_json_review_input_treats_nonobject_entries_as_untrusted_not_findings():
    text = json.dumps(["untrusted", 42, {"severity": "high", "description": "missing boundary"}])
    findings = adv._parse_llm_findings(text)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_non_array_json_is_not_silently_treated_as_authoritative_json_review():
    results = adv._parse_llm_findings('{"severity":"critical"}')
    assert isinstance(results, list)
    assert not any(f.severity == "critical" for f in results)


def test_free_text_markers_and_blank_lines_are_parsed_without_fabricated_checks():
    result = adv._parse_llm_findings("\n[HIGH] coverage gap\n\nonly 5\nA detailed risk remains\n")
    assert len(result) == 2
    assert result[0].severity == "high"
    assert result[1].severity == "warn"


def test_optional_review_returns_no_llm_findings_for_empty_review_output():
    seen = []

    def client(prompt):
        seen.append(prompt)
        return ""

    result = adv.run_adversarial_review(
        {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "pytest real-tests"}]}]},
        evidence_path=None,
        llm_client=client,
    )
    assert result.used_llm is True
    assert result.raw_llm_output == ""
    assert len(seen) == 1
    assert all(not f.check_id.startswith("ADV-LLM") for f in result.findings)


def test_llm_review_failure_is_recorded_without_preventing_independent_gate():
    def bad_client(prompt):
        raise ConnectionError("provider offline")

    report = adv.run_adversarial_review({"steps": []}, llm_client=bad_client)
    assert report.used_llm is True
    assert any(f.check_id == "ADV-LLM-ERROR" for f in report.findings)


def test_weak_only_checks_raise_high_warning_and_propose_deterministic_pytest():
    report = adv.run_adversarial_review(
        {
            "steps": [
                {"id": 1, "verify": [{"type": "file_exists", "path": "README.md"}]},
                {"id": 2, "verify": [{"type": "regex", "path": "README.md", "regex": "PASS"}]},
            ]
        }
    )
    findings = {f.check_id: f for f in report.findings}
    assert findings["ADV-WEAK-ONLY"].severity == "high"
    assert {"type": "pytest", "args": "."} in report.proposed_checks


def test_hardcoded_shell_success_is_critical_and_never_accepted_as_proof():
    report = adv.run_adversarial_review(
        {"steps": [{"id": 1, "verify": [{"type": "run", "cmd": "python -c 'assert True'"}]}]}
    )
    assert report.has_critical()
    assert any(f.check_id == "ADV-HARDCODED-PASS" for f in report.findings)


def test_second_llm_suggestion_is_preserved_as_proposed_check_not_performed_one():
    returned = '[{"severity":"high","description":"unverified","suggested_check":{"type":"pytest","args":"tests"}}]'
    report = adv.run_adversarial_review({"steps": []}, llm_client=lambda _: returned)
    assert {"type": "pytest", "args": "tests"} in report.proposed_checks
    assert report.used_llm
    assert report.has_high_or_worse()


def test_nonmapping_review_entries_are_ignored_before_check_type_classification():
    report = adv.run_adversarial_review(
        {
            "steps": [
                {
                    "id": 1,
                    "verify": [
                        "not an actual structured verification check",
                        {"type": "file_exists", "path": "README.md"},
                    ],
                }
            ]
        },
        evidence_path=None,
    )
    assert any(f.check_id == "ADV-WEAK-ONLY" for f in report.findings)
