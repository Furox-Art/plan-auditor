"""Reject filesystem prefix ambiguity and malformed cryptographic marker payloads."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts import integrity


def test_cross_drive_path_comparison_failure_never_treats_external_path_as_internal(
    monkeypatch, tmp_path
):
    def cross_drive(*args, **kwargs):
        raise ValueError("different physical volumes")

    monkeypatch.setattr(integrity.os.path, "commonpath", cross_drive)
    assert integrity._inside(tmp_path, tmp_path.parent / "elsewhere.key") is False


def test_external_key_file_read_failure_does_not_leak_or_fallback_to_unsigned(
    monkeypatch, tmp_path
):
    work = tmp_path / "workspace"
    work.mkdir()
    key = tmp_path / "outside.key"
    key.write_bytes(b"x" * 64)
    monkeypatch.delenv(integrity.ENV_KEY, raising=False)
    monkeypatch.setenv(integrity.ENV_KEY_FILE, str(key))
    original = Path.read_bytes

    def inaccessible(self, *args, **kwargs):
        if self == key:
            raise OSError("simulated external key read refusal")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", inaccessible)
    with pytest.raises(integrity.IntegrityKeyError, match="cannot read HMAC key file"):
        integrity.load_key(work, required=True)


def test_nonfinite_integrity_marker_json_number_is_rejected_before_authentication():
    with pytest.raises(ValueError, match="non-finite integrity marker JSON number"):
        integrity._finite_json_number("1e309")


def test_scalar_marker_payload_can_never_be_interpreted_as_authenticated(tmp_path):
    marker = integrity.marker_path(tmp_path)
    marker.parent.mkdir(parents=True)
    marker.write_text("42")
    real_key = integrity.KeyMaterial(
        key=b"x" * 64,
        source="external test-only fixture",
        key_id="test-key",
    )
    assert integrity.verify_marker(tmp_path, real_key) is False


def test_finite_integrity_marker_json_number_keeps_its_exact_float_value():
    assert integrity._finite_json_number("1.25") == 1.25
