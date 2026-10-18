"""Host-approved requirements cannot be rewritten by plans or their metadata.

This suite exercises real JSON and request authorization boundaries. It does not
pretend an unexecuted check constitutes a successful deterministic validation.
"""

from __future__ import annotations

import json
import sys
from copy import deepcopy

import pytest

from supervisor import request_contract as request


def acceptance():
    return {"type": "run", "argv": [sys.executable, "-c", "print('verified')"]}


def approved_requirement(priority="must"):
    item = {"id": "REQ-1", "description": "record independent evidence", "priority": priority}
    if priority in {"must", "should"}:
        item["acceptance_checks"] = [acceptance()]
    return item


def approved_request(priority="must"):
    return {"task": "authorized study", "requirements": [approved_requirement(priority)]}


def matching_plan():
    return {
        "task": "scientific implementation",
        "requirements": [
            {"id": "REQ-1", "description": "record independent evidence", "priority": "must"}
        ],
        "steps": [{"id": 1, "covers": ["REQ-1"], "verify": [acceptance()], "depends_on": []}],
    }


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda x: x.update(format_version=99), "unsupported request contract"),
        (lambda x: x.update(task=""), "task must be"),
        (lambda x: x.update(requirements=[]), "requirements must"),
        (lambda x: x.update(requirements=[42]), "must be an object"),
        (lambda x: x["requirements"][0].update(id=""), "non-empty id"),
        (lambda x: x["requirements"][0].update(description=""), "non-empty description"),
        (lambda x: x["requirements"][0].update(priority="admin"), "invalid priority"),
        (
            lambda x: x["requirements"][0].update(acceptance_checks=[]),
            "non-empty acceptance_checks",
        ),
        (lambda x: x["requirements"].append(deepcopy(x["requirements"][0])), "duplicate"),
    ],
)
def test_authoritative_contract_rejects_ambiguous_or_undocumented_requirements(mutate, expected):
    source = approved_request()
    mutate(source)
    assert any(expected in msg for msg in request.validate_request(source))


def test_only_optional_may_requirement_does_not_require_fabricated_approval_check():
    source = approved_request("may")
    assert request.validate_request(source) == []


def test_request_status_never_invents_signed_or_activated_state():
    status = request.RequestStatus(activated=True, valid=False, reason="hash mismatch")
    assert status.as_dict() == {
        "activated": True,
        "valid": False,
        "reason": "hash mismatch",
        "request_sha256": None,
        "authenticated": False,
    }


def test_request_alignment_requires_actual_check_on_correct_covering_step():
    expected = request.analyze_request_alignment({"default": matching_plan()}, approved_request())
    assert expected.valid
    assert expected.mapping["REQ-1"] == [{"plan": "default", "step": 1}]


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda p: p["requirements"].clear(), "missing from every active plan"),
        (
            lambda p: p["requirements"][0].update(description="replaced goal"),
            "modified in plan requirements",
        ),
        (lambda p: p["steps"][0].update(covers=[]), "not covered by any active plan step"),
        (lambda p: p["steps"][0].update(verify=[]), "not executed by any covering step"),
    ],
)
def test_plan_cannot_silently_override_request_and_simulate_acceptance(mutator, message):
    plan = matching_plan()
    mutator(plan)
    status = request.analyze_request_alignment({"default": plan}, approved_request())
    assert not status.valid
    assert any(message in err for err in status.errors)


def test_nonobject_plan_cannot_claim_authoritative_requirements():
    result = request.analyze_request_alignment({"default": []}, approved_request())
    assert not result.valid
    assert "missing from every active plan" in result.errors[0]


def test_partial_plan_coverage_does_not_become_complete_when_check_is_on_another_step():
    p = matching_plan()
    p["steps"][0]["verify"] = []
    p["steps"].append({"id": 2, "covers": [], "verify": [acceptance()]})
    out = request.analyze_request_alignment({"default": p}, approved_request())
    assert not out.valid
    assert any("not executed" in problem for problem in out.errors)


def test_request_check_normalization_failure_is_not_accepted_as_check(monkeypatch):
    def corrupt(_check):
        raise ValueError("signed validator unavailable")

    monkeypatch.setattr(request, "_normalized_check", corrupt)
    out = request.analyze_request_alignment({"default": matching_plan()}, approved_request())
    assert not out.valid
    assert any("cannot be normalized" in err for err in out.errors)


def test_activation_absence_is_explicit_not_a_pass(tmp_path):
    status = request.verify_request_contract(tmp_path)
    assert not status.activated and not status.valid
    assert status.reason == "request contract is not activated"


def test_only_one_activation_file_has_fail_closed_incomplete_pair(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "request.json").write_text(json.dumps(approved_request("may")))
    status = request.verify_request_contract(tmp_path)
    assert status.activated and not status.valid
    assert "incomplete" in status.reason


def test_authoritative_activation_is_immutable_and_preserves_original_hash(tmp_path):
    source = approved_request("may")
    first = request.initialize_request(tmp_path, source)
    assert first.valid and first.activated
    original = (tmp_path / ".plan-auditor" / "request.json").read_bytes()
    with pytest.raises(ValueError, match="already activated and immutable"):
        request.initialize_request(tmp_path, source)
    assert original == (tmp_path / ".plan-auditor" / "request.json").read_bytes()


def test_unknown_approval_metadata_on_activation_does_not_bypass_request_digest(tmp_path):
    request.initialize_request(tmp_path, approved_request("may"))
    path = request.activation_path(tmp_path)
    state = json.loads(path.read_text())
    state["unreviewed_override"] = "ALLOW"
    path.write_text(json.dumps(state))
    out = request.verify_request_contract(tmp_path)
    assert out.activated and not out.valid
    assert "metadata/hash mismatch" in out.reason


def test_stale_request_digest_fails_closed_even_if_activation_json_is_well_formed(tmp_path):
    request.initialize_request(tmp_path, approved_request("may"))
    path = request.request_path(tmp_path)
    data = json.loads(path.read_text())
    data["task"] = "a different project"
    path.write_text(json.dumps(data))
    out = request.verify_request_contract(tmp_path)
    assert out.activated and not out.valid
    assert "metadata/hash mismatch" in out.reason


def test_control_float_parser_allows_only_finite_nonambiguous_values():
    assert request._finite_control_float("1.25") == 1.25
    with pytest.raises(ValueError, match="non-finite request JSON number"):
        request._finite_control_float("1e309")


def test_duplicate_request_json_key_is_rejected_before_authentication():
    with pytest.raises(ValueError, match="duplicate request JSON field"):
        request._unique_control_fields([("allow", True), ("allow", False)])


def test_inactive_workspace_stays_inactive_for_unrelated_logs_and_config(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "supervisor.json").write_text("{}")
    (pg / "debug.log").write_text("no plan")
    assert request.auditor_state_present(tmp_path) is False


@pytest.mark.parametrize(
    ("dirname", "filename"),
    [
        ("plans", "study.json"),
        ("seals", "sealed.json"),
        ("archive", "evidence.jsonl"),
        ("snapshots", "before.zip"),
    ],
)
def test_directory_artifacts_keep_activated_workspace_from_falsely_becoming_unused(
    tmp_path, dirname, filename
):
    pg = tmp_path / ".plan-auditor"
    folder = pg / dirname
    folder.mkdir(parents=True)
    (folder / filename).write_bytes(b"recorded")
    assert request.auditor_state_present(tmp_path) is True


def test_symlinked_runtime_state_folder_is_not_considered_an_unused_workspace(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "plans").symlink_to(tmp_path.parent / "outside-authorization", target_is_directory=True)
    # A dangling symlink is not safe evidence of activation on its own.
    assert request.auditor_state_present(tmp_path) is False


@pytest.mark.parametrize(
    ("mutator", "reason"),
    [
        (lambda p: p["steps"][0].update(covers="REQ-1"), "covers"),
        (lambda p: p["steps"][0].update(verify=None), "verify"),
        (lambda p: p["steps"][0].update(verify={}), "verify"),
        (lambda p: p.update(requirements=None), "requirements"),
        (lambda p: p.update(steps="not-an-array"), "steps"),
    ],
)
def test_malformed_containers_never_count_as_approved_execution(mutator,reason):
    p=matching_plan()
    mutator(p)
    out=request.analyze_request_alignment({"default":p},approved_request())
    assert not out.valid
    assert any(reason in error for error in out.errors)


@pytest.mark.parametrize(
    ("plans", "source"),
    [
        ({"default":matching_plan()}, {"requirements":None}),
        ({"default":matching_plan()}, {"requirements":"REQ-1"}),
        ({"default":matching_plan()}, {"requirements":[12]}),
        (None, approved_request()),
    ],
)
def test_direct_alignment_on_invalid_untrusted_request_is_explicitly_invalid(plans,source):
    out=request.analyze_request_alignment(plans,source)
    assert not out.valid
    assert out.errors


def test_truncated_step_without_structured_verify_cannot_cover_required_check():
    p=matching_plan()
    p["steps"][0]["verify"]=[False,"printed PASS"]
    out=request.analyze_request_alignment({"default":p},approved_request())
    assert not out.valid
    assert any("not executed" in err for err in out.errors)
