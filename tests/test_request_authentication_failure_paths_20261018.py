"""Host request records must remain immutable, authenticated and fail-closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.integrity import IntegrityKeyError, KeyMaterial
from supervisor import request_contract as ctrl
from supervisor.control_plane import ControlPlanePathError


def request_payload():
    return {
        "task": "authorized study",
        "requirements": [{"id": "R-1", "description": "direct measurements", "priority": "may"}],
    }


def test_invalid_request_root_is_refused_without_accidental_activation():
    assert "root must be an object" in ctrl.validate_request(None)[0]


def test_request_control_path_refuses_failed_workspace_confinement(monkeypatch, tmp_path):
    def denied(*_args, **_kwargs):
        raise ControlPlanePathError("simulated symlink redirection")

    monkeypatch.setattr(ctrl, "confined_workspace_path", denied)
    with pytest.raises(ValueError, match="unsafe request control-plane path"):
        ctrl.request_path(tmp_path)
    assert ctrl.verify_request_contract(tmp_path).valid is False


def test_untrusted_symlinked_source_is_not_a_safe_regular_request_file(tmp_path):
    source = tmp_path / "approved.json"
    source.write_text(json.dumps(request_payload()), encoding="utf-8")
    symlink = tmp_path / "link.json"
    symlink.symlink_to(source)
    with pytest.raises(ValueError, match="not a safe regular file"):
        ctrl._read_object(symlink)


def test_initialize_rejects_invalid_contract_before_writing_control_plane(tmp_path):
    payload = request_payload()
    payload["requirements"][0]["priority"] = "unapproved-role"
    with pytest.raises(ValueError, match="invalid request contract"):
        ctrl.initialize_request(tmp_path, payload)
    assert not ctrl.request_path(tmp_path).exists()


def test_host_key_load_failure_does_not_write_partial_auth_metadata(monkeypatch, tmp_path):
    def inaccessible(*a, **kw):
        raise IntegrityKeyError("external HMAC key access denied")

    monkeypatch.setattr(ctrl, "load_key", inaccessible)
    with pytest.raises(ValueError, match="external HMAC key access denied"):
        ctrl.initialize_request(tmp_path, request_payload())
    assert not ctrl.request_path(tmp_path).exists()


def test_untrusted_stale_request_file_with_invalid_structure_never_verifies(tmp_path):
    ctrl.initialize_request(tmp_path, request_payload())
    path = ctrl.request_path(tmp_path)
    invalid = json.loads(path.read_text())
    invalid["requirements"] = []
    path.write_text(json.dumps(invalid))
    result = ctrl.verify_request_contract(tmp_path)
    assert not result.valid
    assert "requirements must be a non-empty list" in result.reason


def test_initialize_auth_requires_existing_exact_pair(tmp_path):
    key = KeyMaterial(key=b"request-test-key-2026" * 3, source="fixture", key_id="test-key")
    with pytest.raises(ValueError, match="activated before authenticated integrity"):
        ctrl.initialize_request_auth(tmp_path, key)


def test_initialize_auth_refuses_invalid_existing_request_even_with_a_valid_key(tmp_path):
    ctrl.initialize_request(tmp_path, request_payload())
    path = ctrl.request_path(tmp_path)
    invalid = json.loads(path.read_text())
    invalid["task"] = ""
    path.write_text(json.dumps(invalid))
    key = KeyMaterial(key=b"request-test-key-2026" * 3, source="fixture", key_id="test-key")
    with pytest.raises(ValueError, match="cannot authenticate invalid request contract"):
        ctrl.initialize_request_auth(tmp_path, key)


def test_initialize_auth_refuses_stale_digest_even_with_a_valid_key(tmp_path):
    ctrl.initialize_request(tmp_path, request_payload())
    path = ctrl.activation_path(tmp_path)
    data = json.loads(path.read_text())
    data["request_sha256"] = "0" * 64
    path.write_text(json.dumps(data))
    key = KeyMaterial(key=b"request-test-key-2026" * 3, source="fixture", key_id="test-key")
    with pytest.raises(ValueError, match="request activation hash mismatch"):
        ctrl.initialize_request_auth(tmp_path, key)


def signed_request(tmp_path, monkeypatch):
    ctrl.initialize_request(tmp_path, request_payload())
    key = KeyMaterial(key=b"request-test-key-2026" * 3, source="fixture", key_id="test-key")
    ctrl.initialize_request_auth(tmp_path, key)
    monkeypatch.setattr(ctrl, "load_key", lambda *_a, **_kw: key)
    assert ctrl.verify_request_contract(tmp_path).authenticated
    return key


def test_real_signed_request_and_activation_are_authenticated_with_real_hmac(tmp_path, monkeypatch):
    signed_request(tmp_path, monkeypatch)
    result = ctrl.verify_request_contract(tmp_path)
    assert result.activated and result.valid and result.authenticated
    assert result.reason == "request contract active"


@pytest.mark.parametrize(
    ("filename", "message"),
    [
        ("request.json", "request contract HMAC authentication failed"),
        ("activation.json", "request activation HMAC authentication failed"),
    ],
)
def test_changed_hmac_tag_is_rejected_even_when_payload_digest_is_unchanged(
    tmp_path, monkeypatch, filename, message
):
    signed_request(tmp_path, monkeypatch)
    file = tmp_path / ".plan-auditor" / filename
    value = json.loads(file.read_text())
    value["auth"]["mac"] = "tampered"
    file.write_text(json.dumps(value))
    outcome = ctrl.verify_request_contract(tmp_path)
    assert not outcome.valid
    assert outcome.reason == message


def test_missing_key_for_signed_request_is_unknown_not_authenticated(monkeypatch, tmp_path):
    signed_request(tmp_path, monkeypatch)
    monkeypatch.setattr(ctrl, "load_key", lambda *_a, **_kw: None)
    result = ctrl.verify_request_contract(tmp_path)
    assert not result.valid
    assert not result.authenticated
    assert "requires HMAC key" in result.reason


def test_key_backend_exception_cannot_downgrade_signed_request_to_unsigned_success(
    monkeypatch, tmp_path
):
    signed_request(tmp_path, monkeypatch)

    def unreachable(*a, **kw):
        raise IntegrityKeyError("real signature backend unavailable")

    monkeypatch.setattr(ctrl, "load_key", unreachable)
    result = ctrl.verify_request_contract(tmp_path)
    assert not result.valid
    assert result.reason == "real signature backend unavailable"


def test_untrusted_request_alignment_rejects_nonobject_request():
    out = ctrl.analyze_request_alignment({}, [])
    assert not out.valid
    assert "authoritative request must be an object" in out.errors[0]


def test_request_alignment_invalid_identifier_never_maps_to_signed_plan():
    out = ctrl.analyze_request_alignment({}, {"requirements": [{"id": None}]})
    assert not out.valid
    assert "no valid id" in out.errors[0]


def test_malformed_plan_step_is_an_explicit_alignment_error():
    source = request_payload()
    source["requirements"][0].update(
        priority="must", acceptance_checks=[{"type": "file_exists", "path": "real"}]
    )
    plan = {
        "requirements": [{"id": "R-1", "description": "direct measurements", "priority": "must"}],
        "steps": [
            False,
            {"id": 1, "covers": ["R-1"], "verify": [{"type": "file_exists", "path": "real"}]},
        ],
    }
    out = ctrl.analyze_request_alignment({"default": plan}, source)
    assert not out.valid
    assert any("must be an object" in reason for reason in out.errors)


def test_request_alignment_rejects_nonlist_acceptance_checks():
    source = request_payload()
    source["requirements"][0].update(priority="must", acceptance_checks=None)
    plan = {
        "requirements": [{"id": "R-1", "description": "direct measurements", "priority": "must"}],
        "steps": [
            {"id": 1, "covers": ["R-1"], "verify": [{"type": "file_exists", "path": "real"}]}
        ],
    }
    outcome = ctrl.analyze_request_alignment({"default": plan}, source)
    assert not outcome.valid
    assert any("acceptance_checks must be a list" in s for s in outcome.errors)


def test_active_agent_registry_file_prevents_false_never_started_status(tmp_path):
    folder = tmp_path / ".plan-auditor" / "agents"
    folder.mkdir(parents=True)
    (folder / "registry.jsonl").write_text("{}\\n")
    assert ctrl.auditor_state_present(tmp_path)


def test_os_error_during_saved_artifact_enumeration_is_fail_closed(monkeypatch, tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    original = Path.iterdir

    def inaccessible(self, *a, **kw):
        if self == folder:
            raise OSError("permissions revoked")
        return original(self, *a, **kw)

    monkeypatch.setattr(Path, "iterdir", inaccessible)
    assert ctrl.auditor_state_present(tmp_path)


def test_live_symlinked_plan_directory_cannot_be_reclassified_as_unused(tmp_path):
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    target = tmp_path / "actual-directory"
    target.mkdir()
    (pg / "plans").symlink_to(target, target_is_directory=True)
    assert ctrl.auditor_state_present(tmp_path)


def test_reverse_plan_binding_requires_actual_approved_plan_digest(monkeypatch, tmp_path):
    from supervisor import plans

    class Ref:
        key = "default"

    monkeypatch.setattr(plans, "all_plan_refs", lambda _: [Ref()])

    def cannot_load(_):
        raise ValueError("plan content not valid")

    monkeypatch.setattr(plans, "load_plan_ref", cannot_load)
    payload = request_payload()
    ctrl._stamp_plan_binding(tmp_path, payload)
    assert "plan_bindings" not in payload


def test_unavailable_plan_index_cannot_create_fake_plan_binding(monkeypatch, tmp_path):
    from supervisor import plans

    def fail(_):
        raise ValueError("unreadable plan folder")

    monkeypatch.setattr(plans, "all_plan_refs", fail)
    payload = request_payload()
    ctrl._stamp_plan_binding(tmp_path, payload)
    assert ctrl.REQUEST_PLAN_BINDING_FIELD not in payload


def test_request_alignment_result_serialization_keeps_explicit_mapping_and_errors():
    record = ctrl.RequestAlignment(
        valid=False,
        errors=["missing independent gate"],
        mapping={"R-1": [{"plan": "default", "step": 1}]},
    )
    assert record.as_dict() == {
        "valid": False,
        "errors": ["missing independent gate"],
        "mapping": {"R-1": [{"plan": "default", "step": 1}]},
    }


def test_existing_plan_is_reverse_bound_to_the_exact_canonical_plan_hash(tmp_path):
    from scripts.contract import plan_hash

    approved_plan = {
        "task": "independent measurement",
        "created": "2026-10-18T00:00:00Z",
        "steps": [
            {
                "id": 1,
                "title": "record",
                "verify": [{"type": "file_exists", "path": "observed.csv"}],
            }
        ],
    }
    folder = tmp_path / ".plan-auditor"
    folder.mkdir()
    (folder / "plan.json").write_text(json.dumps(approved_plan))
    payload = request_payload()
    ctrl._stamp_plan_binding(tmp_path, payload)
    assert payload[ctrl.REQUEST_PLAN_BINDING_FIELD] == {"default": plan_hash(approved_plan)}


def test_file_based_host_approval_reads_exact_structured_json_and_activates(tmp_path):
    source = tmp_path / "host-approved-request.json"
    source.write_text(json.dumps(request_payload()), encoding="utf-8")
    out = ctrl.initialize_request_from_file(tmp_path, source)
    assert out.valid and out.activated
    assert out.request["task"] == "authorized study"


def test_confined_control_plane_failure_is_detected_as_existing_auditor_state(
    monkeypatch, tmp_path
):
    def denied(*_args, **_kw):
        raise ControlPlanePathError("malformed control-plane link")

    monkeypatch.setattr(ctrl, "confined_workspace_path", denied)
    assert ctrl.auditor_state_present(tmp_path) is True


def test_workspace_without_an_auditor_folder_is_not_a_false_activation(tmp_path):
    assert ctrl.auditor_state_present(tmp_path) is False


def test_real_plan_marker_remains_auditor_activation_even_without_request_pair(tmp_path):
    folder = tmp_path / ".plan-auditor"
    folder.mkdir()
    (folder / "plan.json").write_text("{}")
    assert ctrl.auditor_state_present(tmp_path)


def test_plan_folder_with_only_unrelated_file_does_not_fabricate_activation(tmp_path):
    folder = tmp_path / ".plan-auditor" / "plans"
    folder.mkdir(parents=True)
    (folder / "info.txt").write_text("not a plan")
    assert ctrl.auditor_state_present(tmp_path) is False


def test_temp_creation_failure_never_writes_unfsynced_request_or_stale_temp(monkeypatch, tmp_path):
    destination = tmp_path / "request.json"

    def creation_failed(*_a, **_kw):
        raise OSError("simulated disk allocation failure")

    monkeypatch.setattr(ctrl.tempfile, "NamedTemporaryFile", creation_failed)
    with pytest.raises(OSError, match="simulated disk allocation failure"):
        ctrl._atomic_write(destination, request_payload())
    assert not destination.exists()
    assert list(tmp_path.glob(".request.json.*.tmp")) == []
