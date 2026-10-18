"""No implicit implementation proofs from text parsing or unsigned evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from scripts.integrity import IntegrityKeyError
from supervisor import integrity, requirements


@pytest.mark.parametrize(
    ("task", "priority", "ambiguity"),
    [
        ("must verify the file hash", "must", "none"),
        ("Perhaps the report will be complete", "should", "medium"),
        ("Maybe check etc.", "should", "high"),
        ("Write an independent regression test", "should", "none"),
    ],
)
def test_heuristic_requirements_are_not_claimed_as_completed_implementation(
    task, priority, ambiguity
):
    reqs = requirements.parse_requirements(task)
    assert len(reqs) == 1
    assert reqs[0].priority == priority
    assert reqs[0].ambiguity == ambiguity
    assert reqs[0].verification_strategy == "deterministic"
    assert "implementation exists" in reqs[0].acceptance_criteria


def test_bullet_requirements_have_stable_nonduplicated_identifiers():
    reqs = requirements.parse_requirements(
        "- required hash validation\n- optional diagnostic details\n- must reject tampering"
    )
    assert [r.id for r in reqs] == ["REQ-001", "REQ-002", "REQ-003"]
    assert [r.priority for r in reqs] == ["must", "should", "must"]


def test_empty_requirement_text_is_retained_as_open_task_not_auto_pass():
    reqs = requirements.parse_requirements("   ")
    assert len(reqs) == 1
    assert reqs[0].description == ""
    assert reqs[0].id == "REQ-001"


@pytest.mark.parametrize(
    ("reqs", "expected"),
    [
        ([object()], "Requirement instances"),
        ([requirements.Requirement(id="", description="valid")], "non-empty"),
        (
            [
                requirements.Requirement(id="REQ-1", description="one"),
                requirements.Requirement(id="REQ-1", description="two"),
            ],
            "duplicate requirement id",
        ),
    ],
)
def test_verification_plan_rejects_malformed_duplicate_and_unbound_requirements(reqs, expected):
    with pytest.raises((TypeError, ValueError), match=expected):
        requirements.requirements_to_verification_plan(reqs)


def test_verification_plan_preserves_exact_acceptance_criteria_and_strategy():
    req = requirements.Requirement(
        id=" REQ-123 ",
        description="verify the actual run evidence",
        verification_strategy="deterministic",
        acceptance_criteria=["hashes match", "CI run passes"],
    )
    plan = requirements.requirements_to_verification_plan([req])
    assert plan == [
        {
            "requirement_id": "REQ-123",
            "description": "verify the actual run evidence",
            "strategy": "deterministic",
            "acceptance_criteria": ["hashes match", "CI run passes"],
        }
    ]


def test_status_exposes_missing_key_as_unsigned_not_authenticated(tmp_path, monkeypatch):
    monkeypatch.setattr(integrity, "load_key", lambda *a, **kw: None)
    out = integrity.integrity_status(tmp_path)
    assert out["authenticated"] is False
    assert out["configured"] is False
    assert out["mode"] == "unsigned-compatibility"


def test_invalid_key_load_fails_closed_without_clearing_configured_flag(tmp_path, monkeypatch):
    def fail(*a, **kw):
        raise IntegrityKeyError("invalid local key reference")

    monkeypatch.setattr(integrity, "load_key", fail)
    out = integrity.integrity_status(tmp_path)
    assert out["authenticated"] is False
    assert out["configured"] is True
    assert "invalid local key reference" in out["problem"]


def test_key_exists_without_marker_remains_uninitialized(tmp_path, monkeypatch):
    key = SimpleNamespace(key_id="known-key", source="external")
    monkeypatch.setattr(integrity, "load_key", lambda *a, **kw: key)
    out = integrity.integrity_status(tmp_path)
    assert out["authenticated"] is False
    assert out["problem"] == "integrity not initialized"
    assert out["key_id"] == "known-key"


def test_failed_marker_hmac_cannot_be_relabelled_authenticated(tmp_path, monkeypatch):
    marker = tmp_path / "marker.json"
    marker.write_text("tampered marker")
    monkeypatch.setattr(integrity, "marker_path", lambda *a: marker)
    monkeypatch.setattr(
        integrity, "load_key", lambda *a, **kw: SimpleNamespace(key_id="key", source="external")
    )
    monkeypatch.setattr(integrity, "verify_marker", lambda *a, **kw: False)
    out = integrity.integrity_status(tmp_path)
    assert out["authenticated"] is False
    assert out["marker_present"] is True
    assert out["problem"] == "integrity marker verification failed"


def test_initialize_refuses_to_overwrite_mismatched_existing_marker(tmp_path, monkeypatch):
    marker = tmp_path / "marker.json"
    marker.write_text("existing")
    monkeypatch.setattr(integrity, "marker_path", lambda *a: marker)
    monkeypatch.setattr(integrity, "load_key", lambda *a, **kw: SimpleNamespace(key_id="key"))
    monkeypatch.setattr(integrity, "verify_marker", lambda *a, **kw: False)
    with pytest.raises(IntegrityKeyError, match="marker is invalid"):
        integrity.initialize_integrity(tmp_path)


@pytest.mark.parametrize("authenticated", [True, False])
def test_initialize_existing_valid_marker_only_returns_real_verified_status(
    tmp_path, monkeypatch, authenticated
):
    marker = tmp_path / "marker.json"
    marker.write_text("signed")
    monkeypatch.setattr(integrity, "marker_path", lambda *a: marker)
    monkeypatch.setattr(integrity, "load_key", lambda *a, **kw: SimpleNamespace(key_id="key"))
    monkeypatch.setattr(integrity, "verify_marker", lambda *a, **kw: True)
    monkeypatch.setattr(integrity, "integrity_status", lambda *a: {"authenticated": authenticated})
    if authenticated:
        assert integrity.initialize_integrity(tmp_path) == {"authenticated": True}
    else:
        with pytest.raises(IntegrityKeyError, match="current state no longer verifies"):
            integrity.initialize_integrity(tmp_path)
