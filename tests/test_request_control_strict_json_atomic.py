"""Ambiguous request approval bytes must never verify or corrupt existing state."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor import request_contract as control


def _request() -> dict:
    return {
        "task": "authoritative human-approved requirements",
        "requirements": [{
            "id": "R1",
            "description": "make a safe change",
            "priority": "may",
        }],
    }


@pytest.mark.parametrize(
    "mutant",
    [
        '{"task":"bad","task":"good"}',
        '{"requirements":[{"id":"R1","id":"R2"}]}',
        '{"task":"good","unused":NaN}',
        '{"task":"good","unused":Infinity}',
        '{"task":"good","unused":1e9999}',
        '{"task":"good","unused":"\\ud800"}',
        '[]',
        '{',
    ],
)
def test_request_control_parser_rejects_ambiguous_json(tmp_path: Path, mutant: str) -> None:
    path = tmp_path / "request.json"
    path.write_text(mutant, encoding="utf-8")
    with pytest.raises((ValueError, UnicodeError, json.JSONDecodeError)):
        control._read_object(path)


def test_request_approval_activation_roundtrip_and_provenance(tmp_path: Path) -> None:
    result = control.initialize_request(tmp_path, _request())
    assert result.valid
    assert result.activated
    assert result.request_sha256
    assert result.request is not None
    assert result.request["task"] == _request()["task"]
    assert control.verify_request_contract(tmp_path).valid
    assert not list((tmp_path / ".plan-auditor").glob(".*.tmp"))


@pytest.mark.parametrize("filename", ["request.json", "activation.json"])
def test_authenticated_or_keyless_request_mutation_with_duplicate_keys_is_denied(
    tmp_path: Path, filename: str,
) -> None:
    control.initialize_request(tmp_path, _request())
    path = tmp_path / ".plan-auditor" / filename
    original = path.read_text()
    path.write_text('{"fake":"unreviewed",' + original.lstrip()[1:])
    # This extra field breaks the canonical digest, never verifies.
    assert not control.verify_request_contract(tmp_path).valid
    path.write_text(original.replace(
        '"format_version": 1', '"format_version": 2, "format_version": 1', 1,
    ))
    result = control.verify_request_contract(tmp_path)
    assert not result.valid
    assert "unreadable" in result.reason


def test_request_control_limit_is_applied_before_json_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "request.json"
    path.write_text('{"payload":"' + "x" * 128 + '"}')
    monkeypatch.setattr(control, "MAX_REQUEST_CONTROL_BYTES", 32)
    with pytest.raises(ValueError, match="exceeds bounded"):
        control._read_object(path)


def test_request_atomic_failure_preserves_original_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "request.json"
    path.write_bytes(b"before")
    def reject(*args, **kwargs):
        raise OSError("simulated atomic rename error")
    monkeypatch.setattr(control.os, "replace", reject)
    with pytest.raises(OSError, match="simulated"):
        control._atomic_write(path, _request())
    assert path.read_bytes() == b"before"
    assert not list(tmp_path.glob(".request.json.*.tmp"))


def test_untrusted_predictable_tmp_symlink_cannot_redirect_request_write(tmp_path: Path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("unchanged")
    (tmp_path / "request.json.tmp").symlink_to(victim)
    destination = tmp_path / "request.json"
    control._atomic_write(destination, _request())
    assert victim.read_text() == "unchanged"
    assert control._read_object(destination)["task"] == _request()["task"]


def test_direct_destination_symlink_is_rejected_before_writing(tmp_path: Path) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("unchanged")
    destination = tmp_path / "request.json"
    destination.symlink_to(victim)
    with pytest.raises(ValueError, match="symlink"):
        control._atomic_write(destination, _request())
    assert victim.read_text() == "unchanged"
