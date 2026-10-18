"""Reject malformed audit evidence without raising or accepting partial proof."""

from __future__ import annotations

import pytest

from supervisor.orchestrator import (
    _checks_match,
    _iter_evidence_records,
    _result_checks_match,
)


@pytest.mark.parametrize("malformed", [None, {}, "", "verified", 1, True])
def test_result_checks_reject_non_lists(malformed):
    assert _result_checks_match([], malformed) is False


@pytest.mark.parametrize(
    "actual",
    [
        [{}],
        [None],
        ["passed"],
        [{"check": {"type": "file_exists"}, "passed": False}],
        [{"check": {"type": "different"}, "passed": True}],
    ],
)
def test_result_checks_require_exact_successful_contract(actual):
    expected = [{"type": "file_exists"}]
    assert _result_checks_match(expected, actual) is False


def test_result_checks_accept_exact_successful_contract():
    expected = [{"type": "file_exists"}]
    assert _result_checks_match(expected, [{"check": expected[0], "passed": True}]) is True


@pytest.mark.parametrize("key", ["results", "outputs", "required_outputs"])
@pytest.mark.parametrize("malformed", [None, {}, "untrusted", 14, True])
def test_malformed_audit_field_fails_closed(key, malformed):
    step = {"id": 1, "verify": []}
    record = {"results": [], "dependencies": [], "outputs": [], "required_outputs": []}
    record[key] = malformed
    assert _checks_match(step, record, [], {1: step}) is False


def test_matching_empty_contract_is_allowed():
    step = {"id": 1, "verify": []}
    record = {"results": [], "dependencies": [], "outputs": [], "required_outputs": []}
    assert _checks_match(step, record, [], {1: step}) is True


def test_evidence_record_stream_skips_invalid_lines_but_preserves_archive_order(tmp_path):
    base = tmp_path / ".plan-auditor"
    archive = base / "archive"
    archive.mkdir(parents=True)
    (archive / "evidence-002.jsonl").write_text('{"n":2}\nnull\n', encoding="utf-8")
    (archive / "evidence-001.jsonl").write_text('\nNOT-JSON\n{"n":1}\n', encoding="utf-8")
    (base / "evidence.jsonl").write_text('{"n":3}\n[]\n', encoding="utf-8")
    assert list(_iter_evidence_records(tmp_path)) == [{"n": 1}, {"n": 2}, {"n": 3}]


def _verified_check(contract):
    from scripts.audit_check import norm_check

    return {"check": norm_check(contract), "passed": True}


def _output_steps():
    check = {"type": "file_exists", "path": "artifact.txt"}
    producer = {
        "id": 1,
        "verify": [],
        "outputs": [{"name": "artifact", "verify": [check]}],
    }
    consumer = {
        "id": 2,
        "verify": [],
        "requires_outputs": [{"step": 1, "name": "artifact"}],
    }
    output = {"name": "artifact", "passed": True, "results": [_verified_check(check)]}
    requirement = {"step": 1, **output}
    return producer, consumer, output, requirement


def test_producer_output_exact_evidence_is_accepted():
    producer, consumer, output, _ = _output_steps()
    record = {"results": [], "dependencies": [], "outputs": [output], "required_outputs": []}
    assert _checks_match(producer, record, [], {1: producer, 2: consumer}) is True


def test_consumer_dependency_exact_evidence_is_accepted():
    producer, consumer, _, requirement = _output_steps()
    record = {"results": [], "dependencies": [1], "outputs": [], "required_outputs": [requirement]}
    assert _checks_match(consumer, record, [1], {1: producer, 2: consumer}) is True


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r["outputs"].append({"name": "extra"}),
        lambda r: r["outputs"].__setitem__(0, None),
        lambda r: r["outputs"][0].update(name="other"),
        lambda r: r["outputs"][0].update(passed=False),
        lambda r: r["outputs"][0].update(results=[]),
        lambda r: r["outputs"][0].update(results=None),
        lambda r: r["outputs"][0]["results"][0].update(passed=False),
        lambda r: r["outputs"][0]["results"][0].update(check={"type": "other"}),
    ],
)
def test_producer_output_incomplete_or_altered_evidence_is_rejected(mutator):
    from copy import deepcopy

    producer, consumer, output, _ = _output_steps()
    record = {
        "results": [],
        "dependencies": [],
        "outputs": [deepcopy(output)],
        "required_outputs": [],
    }
    mutator(record)
    assert _checks_match(producer, record, [], {1: producer, 2: consumer}) is False


@pytest.mark.parametrize(
    "mutator",
    [
        lambda r: r["required_outputs"].append({"step": 1}),
        lambda r: r["required_outputs"].__setitem__(0, None),
        lambda r: r["required_outputs"][0].update(step=2),
        lambda r: r["required_outputs"][0].update(name="other"),
        lambda r: r["required_outputs"][0].update(passed=False),
        lambda r: r["required_outputs"][0].update(results=[]),
        lambda r: r["required_outputs"][0].update(results=None),
        lambda r: r["required_outputs"][0]["results"][0].update(passed=False),
    ],
)
def test_consumer_required_output_incomplete_or_altered_evidence_is_rejected(mutator):
    from copy import deepcopy

    producer, consumer, _, requirement = _output_steps()
    record = {
        "results": [],
        "dependencies": [1],
        "outputs": [],
        "required_outputs": [deepcopy(requirement)],
    }
    mutator(record)
    assert _checks_match(consumer, record, [1], {1: producer, 2: consumer}) is False


def test_required_output_is_rejected_if_producer_has_no_matching_declaration():
    producer, consumer, _, requirement = _output_steps()
    record = {
        "results": [],
        "dependencies": [1],
        "outputs": [],
        "required_outputs": [requirement],
    }
    assert _checks_match(consumer, record, [1], {2: consumer}) is False
    producer["outputs"] = []
    assert _checks_match(consumer, record, [1], {1: producer, 2: consumer}) is False


def test_invalid_plan_output_and_required_output_contracts_are_rejected():
    producer, consumer, output, requirement = _output_steps()
    producer["outputs"] = {"invalid": output}
    assert _checks_match(producer, {"results": [], "outputs": [output]}, [], {}) is False
    consumer["requires_outputs"] = {"invalid": requirement}
    assert _checks_match(consumer, {"results": [], "outputs": []}, [1], {}) is False


def test_wrong_dependency_list_is_rejected_before_output_check():
    producer, consumer, _, requirement = _output_steps()
    record = {"results": [], "dependencies": [], "outputs": [], "required_outputs": [requirement]}
    assert _checks_match(consumer, record, [1], {1: producer, 2: consumer}) is False
