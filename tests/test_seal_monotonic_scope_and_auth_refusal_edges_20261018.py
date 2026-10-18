"""Sealed plans only permit monotonic evidence strengthening without new host scope."""

from __future__ import annotations

import copy
import json

import pytest

from supervisor import sealing


def plan():
    return {
        "task": "direct physical measurement",
        "requirements": [{"id": "R-1", "description": "measured output"}],
        "required_tools": ["pytest"],
        "steps": [
            {
                "id": 1,
                "title": "record measured input",
                "depends_on": [],
                "covers": ["R-1"],
                "verify": [{"type": "pytest", "args": "tests"}],
                "requires_outputs": [],
                "outputs": [
                    {
                        "name": "observed.csv",
                        "unit": "metre",
                        "verify": [{"type": "hash", "algorithm": "sha256"}],
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize(
    ("changed", "fragment"),
    [
        (lambda x: x["steps"][0].update(title="different task"), "sealed title changed"),
        (lambda x: x["steps"][0].update(verify=[]), "sealed verification check removed"),
        (lambda x: x["steps"][0].update(covers=[]), "sealed requirement coverage changed"),
        (lambda x: x["steps"][0].update(outputs=[]), "declared output scope changed"),
        (lambda x: x["steps"][0]["outputs"][0].update(unit="second"), "metadata changed"),
        (lambda x: x["steps"][0]["outputs"][0].update(verify=[]), "verification weakened"),
        (lambda x: x.update(task="unauthorized different task"), "field 'task' changed"),
        (lambda x: x.update(required_tools=["unapproved-tool"]), "required-tool scope changed"),
        (lambda x: x.update(requirements=[]), "requirement scope changed"),
    ],
)
def test_scope_weakening_or_change_is_rejected_instead_of_silently_resealed(changed, fragment):
    before = plan()
    after = copy.deepcopy(before)
    changed(after)
    result = sealing.check_monotonic(before, after)
    assert result.ok is False
    assert any(fragment in message for message in result.violations)


@pytest.mark.parametrize(
    ("changed", "fragment"),
    [
        (
            lambda x: x["steps"][0]["verify"].append({"type": "run", "cmd": "verify"}),
            "verification checks increased",
        ),
        (lambda x: x["steps"][0]["depends_on"].append(4), "dependencies tightened"),
        (
            lambda x: x["steps"][0]["requires_outputs"].append({"step": 4, "name": "measured"}),
            "required outputs increased",
        ),
        (
            lambda x: x["steps"][0]["outputs"][0]["verify"].append({"type": "pytest"}),
            "verification checks increased",
        ),
    ],
)
def test_monotonic_proof_strengthening_is_recorded_as_improvement(changed, fragment):
    before = plan()
    after = copy.deepcopy(before)
    changed(after)
    result = sealing.check_monotonic(before, after)
    assert result.ok
    assert any(fragment in message for message in result.improvements)


def test_seal_payload_copies_mutable_fields_without_exposing_signature_mutation():
    state = sealing.seal_plan(plan(), "plan-1", "2026-10-18T00:00:00Z")
    state.auth = {"alg": "hmac-sha256", "tag": "signed"}
    rendered = state.to_dict()
    assert rendered["auth"] == state.auth
    rendered["auth"]["tag"] = "corrupted"
    rendered["steps"][0]["verify"].clear()
    assert state.auth["tag"] == "signed"
    assert state.steps[0]["verify"]


def test_seal_criteria_count_does_not_count_nonobject_verification_claims():
    tampered = plan()
    tampered["steps"].append("not a real step")
    tampered["steps"][0]["verify"].append("fictional success")
    tampered["steps"][0]["outputs"][0]["verify"].append("also fictional")
    assert sealing._criteria_count(tampered) == 2


def test_invalid_seal_numeric_metadata_is_not_cast_into_a_trusted_seal():
    with pytest.raises(sealing.SealIntegrityError, match="invalid seal numeric metadata"):
        sealing._parse_seal_data({"criteria_count": "this is not a count"})


def test_old_seal_format_without_a_full_contract_does_not_claim_cryptographic_authority():
    seal = sealing.Seal(
        plan_id="legacy",
        sealed_at="",
        plan_hash="untrusted",
        criteria_count=0,
        steps=[],
        format_version=1,
    )
    assert sealing._validate_seal_self_consistency(seal) is None


def test_modifying_a_sealed_check_changes_its_actual_canonical_digest():
    seal = sealing.seal_plan(plan(), "plan-1", "2026-10-18T00:00:00Z")
    seal.steps[0]["verify"] = [{"type": "file_exists", "path": "fictional"}]
    with pytest.raises(sealing.SealIntegrityError, match="contract hash mismatch"):
        sealing._validate_seal_self_consistency(seal)


def test_undeclared_seal_location_cannot_be_loaded_as_control_plane_file(tmp_path):
    with pytest.raises(sealing.SealIntegrityError, match="not under .plan-auditor"):
        sealing._workspace_from_seal(tmp_path / "foreign-seal.json")


def test_load_seal_never_accepts_scalar_or_invalid_json_as_signed_plan(tmp_path):
    source = tmp_path / "seal.json"
    source.write_text("42")
    with pytest.raises(sealing.SealIntegrityError, match="root must be an object"):
        sealing.load_seal(str(source))
    source.write_text("not-json")
    with pytest.raises(sealing.SealIntegrityError, match="invalid seal file"):
        sealing.load_seal(str(source))
    source.unlink()
    assert sealing.load_seal(str(source)) is None


def test_unverifiable_signature_without_runtime_hmac_key_blocks_seal_loading(monkeypatch, tmp_path):
    monkeypatch.setattr(sealing, "runtime_key", lambda _: None)
    seal = sealing.seal_plan(plan(), "plan-1", "2026-10-18T00:00:00Z")
    path = tmp_path / ".plan-auditor" / "seal.json"
    path.parent.mkdir()
    data = seal.to_dict()
    data["auth"] = {"alg": "hmac-sha256", "tag": "not a real signature"}
    path.write_text(json.dumps(data))
    with pytest.raises(sealing.SealIntegrityError, match="requires HMAC key"):
        sealing.load_seal(str(path))


def test_symlinked_temporary_seal_destination_is_never_written(tmp_path):
    path = tmp_path / "seal.json"
    target = tmp_path / "target.outside"
    target.write_text("unaltered")
    path.with_name(path.name + ".tmp").symlink_to(target)
    with pytest.raises(sealing.SealIntegrityError, match="symlinked seal temp path"):
        sealing._write_seal_payload({"test": True}, path, key=None)
    assert target.read_text() == "unaltered"


def test_environment_drift_blocks_reuse_of_a_previous_signed_execution_context():
    state = sealing.seal_plan(
        plan(), "plan-1", "2026-10-18T00:00:00Z", environment={"runner": "authorized"}
    )
    assert sealing.check_environment(state, {"runner": "authorized"}).ok is True
    altered = sealing.check_environment(state, {"runner": "unapproved"})
    assert altered.ok is False
    assert "environment changed" in altered.violations[0]


def test_requirements_structure_mutation_never_counts_as_monotonic_improvement():
    before = plan()
    after = copy.deepcopy(before)
    after["requirements"] = {"not": "the approved array"}
    out = sealing.check_monotonic(before, after)
    assert not out.ok
    assert any("field 'requirements' changed" in error for error in out.violations)


def test_missing_sealed_step_is_rejected_even_if_original_count_matches():
    before = plan()
    after = copy.deepcopy(before)
    after["steps"] = []
    out = sealing.check_monotonic(before, after)
    assert not out.ok
    assert any("removed after seal" in problem for problem in out.violations)


def test_output_map_does_not_count_nonobject_or_nameless_descriptions_as_evidence():
    assert sealing._output_map(
        {"outputs": [12, {}, {"name": 3}, {"name": "measured", "verify": []}]}
    ) == {"measured": {"name": "measured", "verify": []}}


def test_auth_key_required_for_saved_seal_but_runtime_key_error_blocks_save(monkeypatch, tmp_path):
    from scripts.integrity import IntegrityKeyError

    def fail(_):
        raise IntegrityKeyError("external key unavailable")

    monkeypatch.setattr(sealing, "runtime_key", fail)
    source = sealing.seal_plan(plan(), "case", "2026-10-18T00:00:00Z")
    path = tmp_path / ".plan-auditor" / "seal.json"
    with pytest.raises(sealing.SealIntegrityError, match="external key unavailable"):
        sealing.save_seal(source, str(path))
    assert not path.exists()


def test_real_signed_seal_persists_and_roundtrips_without_changing_criteria(monkeypatch, tmp_path):
    from scripts.integrity import KeyMaterial

    key = KeyMaterial(key=b"test-only-key-for-sealing" * 3, source="fixture", key_id="key-1")
    monkeypatch.setattr(sealing, "runtime_key", lambda _: key)
    obj = sealing.seal_plan(plan(), "case", "2026-10-18T00:00:00Z", environment={"mode": "strict"})
    path = tmp_path / ".plan-auditor" / "seal.json"
    sealing.save_seal(obj, str(path))
    loaded = sealing.load_seal(str(path))
    assert loaded is not None
    assert loaded.plan_hash == obj.plan_hash
    assert loaded.criteria_count == obj.criteria_count
    assert loaded.environment == {"mode": "strict"}
    assert loaded.auth is not None


def test_real_signed_seal_does_not_authenticate_under_an_unrelated_key(monkeypatch, tmp_path):
    from scripts.integrity import KeyMaterial

    key = KeyMaterial(key=b"first-test-hmac-key" * 3, source="fixture", key_id="first")
    alternate = KeyMaterial(key=b"second-test-hmac-key" * 3, source="fixture", key_id="second")
    monkeypatch.setattr(sealing, "runtime_key", lambda _: key)
    state = sealing.seal_plan(plan(), "case", "2026-10-18T00:00:00Z")
    path = tmp_path / ".plan-auditor" / "seal.json"
    sealing.save_seal(state, str(path))
    monkeypatch.setattr(sealing, "runtime_key", lambda _: alternate)
    with pytest.raises(sealing.SealIntegrityError, match="HMAC authentication failed"):
        sealing.load_seal(str(path))


def test_seal_initializer_authenticates_default_and_named_plans_without_missing_sources(
    monkeypatch, tmp_path
):
    from scripts.integrity import KeyMaterial

    key = KeyMaterial(key=b"test-only-key-for-sealing" * 3, source="fixture", key_id="key-1")
    pg = tmp_path / ".plan-auditor"
    named = pg / "seals"
    named.mkdir(parents=True)
    source = sealing.seal_plan(plan(), "case", "2026-10-18T00:00:00Z")
    (pg / "seal.json").write_text(json.dumps(source.to_dict()))
    (named / "case.json").write_text(json.dumps(source.to_dict()))
    (named / "notes.txt").write_text("not a signed plan")
    sealing.initialize_seal_auth(tmp_path, key)
    monkeypatch.setattr(sealing, "runtime_key", lambda _: key)
    assert sealing.load_seal(str(pg / "seal.json")).auth is not None
    assert sealing.load_seal(str(named / "case.json")).auth is not None


def test_seal_initializer_refuses_symlinked_named_plan_path(tmp_path):
    from scripts.integrity import KeyMaterial

    key = KeyMaterial(key=b"test-only-key-for-sealing" * 3, source="fixture", key_id="key-1")
    named = tmp_path / ".plan-auditor" / "seals"
    named.mkdir(parents=True)
    external = tmp_path.parent / (tmp_path.name + "-untrusted-plan")
    external.write_text("{}")
    (named / "redirected.json").symlink_to(external)
    with pytest.raises(sealing.SealIntegrityError, match="unsafe seal entry"):
        sealing.initialize_seal_auth(tmp_path, key)
    external.unlink()


@pytest.mark.parametrize("content", ["broken-json", "[1]"])
def test_seal_initializer_rejects_malformed_named_plan_evidence(tmp_path, content):
    from scripts.integrity import KeyMaterial

    key = KeyMaterial(key=b"test-only-key-for-sealing" * 3, source="fixture", key_id="key-1")
    pg = tmp_path / ".plan-auditor"
    pg.mkdir()
    (pg / "seal.json").write_text(content)
    with pytest.raises(sealing.SealIntegrityError, match="invalid seal"):
        sealing.initialize_seal_auth(tmp_path, key)


def test_nonobject_output_declarations_are_not_counted_as_verified_criteria():
    model = plan()
    model["steps"][0]["outputs"].append("not a declared output object")
    assert sealing._criteria_count(model) == 2


def test_seal_path_confinement_failure_is_not_converted_to_trusted_workspace(monkeypatch, tmp_path):
    from supervisor.control_plane import ControlPlanePathError

    def reject(*a, **kw):
        raise ControlPlanePathError("forced control-plane traversal refusal")

    monkeypatch.setattr(sealing, "confined_workspace_path", reject)
    with pytest.raises(sealing.SealIntegrityError, match="unsafe seal control-plane path"):
        sealing._workspace_from_seal(tmp_path / ".plan-auditor" / "seal.json")


def test_existing_consistent_seal_fails_closed_if_runtime_key_provider_fails(monkeypatch, tmp_path):
    from scripts.integrity import IntegrityKeyError

    path = tmp_path / ".plan-auditor" / "seal.json"
    path.parent.mkdir()
    path.write_text(json.dumps(sealing.seal_plan(plan(), "case", "2026-10-18T00:00:00Z").to_dict()))

    def reject(*_):
        raise IntegrityKeyError("external key provider unavailable")

    monkeypatch.setattr(sealing, "runtime_key", reject)
    with pytest.raises(sealing.SealIntegrityError, match="external key provider unavailable"):
        sealing.load_seal(str(path))


def test_seal_initializer_refuses_redirected_control_plane_directory(monkeypatch, tmp_path):
    from scripts.integrity import KeyMaterial
    from supervisor.control_plane import ControlPlanePathError

    key = KeyMaterial(key=b"test-only-key-for-sealing" * 3, source="fixture", key_id="fixture")

    def reject(*a, **kw):
        raise ControlPlanePathError("unsafe directory traversal")

    monkeypatch.setattr(sealing, "confined_workspace_path", reject)
    with pytest.raises(sealing.SealIntegrityError, match="unsafe directory traversal"):
        sealing.initialize_seal_auth(tmp_path, key)
