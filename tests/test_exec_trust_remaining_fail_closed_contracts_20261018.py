"""A sealed plan must have verified, current and explicitly bound provenance."""

from __future__ import annotations

import json
import runpy
import sys

import pytest

from scripts import contract, exec_trust


def save_request(tmp_path, payload):
    folder = tmp_path / ".plan-auditor"
    folder.mkdir(exist_ok=True)
    (folder / "request.json").write_text(json.dumps(payload))


def save_seal(tmp_path, payload):
    folder = tmp_path / ".plan-auditor"
    folder.mkdir(exist_ok=True)
    (folder / "seal.json").write_text(json.dumps(payload))


def test_untrusted_symlinked_seal_never_establishes_execution_authority(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-untrusted-record")
    outside.write_text("{}")
    seal = tmp_path / "seal.json"
    seal.symlink_to(outside)
    with pytest.raises(contract.PlanTrustError, match="symlink"):
        exec_trust._read_json_object(str(seal), "plan seal")
    outside.unlink()


def test_untrusted_scalar_json_cannot_establish_a_seal(tmp_path):
    path = tmp_path / "seal.json"
    path.write_text("42")
    with pytest.raises(contract.PlanTrustError, match="root must be a JSON object"):
        exec_trust._read_json_object(str(path), "plan seal")


def test_missing_plan_seal_is_explicit_trust_refusal(tmp_path):
    with pytest.raises(contract.PlanTrustError, match="is absent"):
        exec_trust.require_plan_trust(str(tmp_path), {"steps": []})


def test_invalid_named_plan_path_is_mapped_to_trust_error(tmp_path):
    with pytest.raises(contract.PlanTrustError, match="invalid plan name"):
        exec_trust.require_plan_trust(str(tmp_path), {"steps": []}, "../outside")


@pytest.mark.parametrize("version", [None, True, "4", 4.5])
def test_invalid_seal_format_version_cannot_claim_still_valid_cryptography(tmp_path, version):
    save_seal(tmp_path, {"format_version": version, "plan_hash": "pretend"})
    with pytest.raises(contract.PlanTrustError, match="no usable format_version"):
        exec_trust.require_plan_trust(str(tmp_path), {"steps": []})


def test_seal_with_no_hmac_key_must_reject_unverifiable_auth(monkeypatch, tmp_path):
    monkeypatch.setattr(exec_trust, "runtime_key", lambda _: None)
    with pytest.raises(contract.PlanTrustError, match="carries an HMAC"):
        exec_trust._verify_seal_mac(str(tmp_path), {"auth": {"tag": "bogus"}}, "seal")


def test_seal_environment_wrong_type_cannot_be_construed_as_active_commitment():
    assert exec_trust._seal_environment({"environment": "unstructured"}) == {}


def test_request_bound_by_seal_cannot_disappear_without_trust_failure(tmp_path):
    sealed = {"environment": {"request_sha256": "a" * 64}}
    with pytest.raises(contract.PlanTrustError, match="missing but the seal committed"):
        exec_trust._verify_request_binding(str(tmp_path), sealed, "default", "b" * 64, "seal")


def test_active_request_not_committed_by_seal_is_rejected(tmp_path):
    save_request(tmp_path, {"request": "new unsanctioned work"})
    with pytest.raises(contract.PlanTrustError, match="did not bind it"):
        exec_trust._verify_request_binding(str(tmp_path), {}, "default", "b" * 64, "seal")


def test_legacy_request_without_per_plan_bindings_requires_committed_digest(tmp_path):
    request = {"request": "explicit"}
    save_request(tmp_path, request)
    data = {"environment": {"request_sha256": contract.canonical_digest(request)}}
    # Historical activated requests may not carry the later per-plan hash map.
    assert (
        exec_trust._verify_request_binding(str(tmp_path), data, "default", "a" * 64, "seal") is None
    )


def test_request_with_different_plan_hash_cannot_authorize_sealed_work(tmp_path):
    request = {"request": "explicit", contract.REQUEST_PLAN_BINDING_FIELD: {"default": "a" * 64}}
    save_request(tmp_path, request)
    data = {"environment": {"request_sha256": contract.canonical_digest(request)}}
    with pytest.raises(contract.PlanTrustError, match="derived from a different plan"):
        exec_trust._verify_request_binding(str(tmp_path), data, "default", "b" * 64, "seal")


def test_request_digest_mismatch_after_activation_is_detected(tmp_path):
    save_request(tmp_path, {"request": "changed after sealing"})
    data = {"environment": {"request_sha256": "a" * 64}}
    with pytest.raises(contract.PlanTrustError, match="request was swapped"):
        exec_trust._verify_request_binding(str(tmp_path), data, "default", "b" * 64, "seal")


def test_direct_script_import_fallback_uses_same_sealed_contract(monkeypatch):
    import builtins

    import scripts.contract as canonical
    import scripts.integrity as signed

    existing_import = builtins.__import__

    def simulate_direct_script(name, *args, **kwargs):
        if name in {"scripts.contract", "scripts.integrity"}:
            raise ImportError("direct-script interpreter uses standalone imports")
        return existing_import(name, *args, **kwargs)

    monkeypatch.setitem(sys.modules, "contract", canonical)
    monkeypatch.setitem(sys.modules, "integrity", signed)
    monkeypatch.setattr(builtins, "__import__", simulate_direct_script)
    loaded = runpy.run_path(exec_trust.__file__)
    assert loaded["plan_hash"] is canonical.plan_hash
    assert loaded["verify_auth"] is signed.verify_auth


def test_matching_request_plan_hash_is_allowed_only_when_request_digest_also_matches(tmp_path):
    plan_digest = "b" * 64
    request = {
        "request": "approved measured activity",
        contract.REQUEST_PLAN_BINDING_FIELD: {"default": plan_digest},
    }
    save_request(tmp_path, request)
    sealed = {"environment": {"request_sha256": contract.canonical_digest(request)}}
    assert exec_trust._verify_request_binding(
        str(tmp_path), sealed, "default", plan_digest, "seal"
    ) is None
