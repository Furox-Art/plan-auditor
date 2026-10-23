"""Regressions for strict plan/seal JSON parsing."""
from __future__ import annotations

import pytest

from supervisor import formal_compiler as compiler
from supervisor import sealing
from supervisor.plans import PlanRef, load_plan_ref
from supervisor.sealing import SealIntegrityError, load_seal


def _load(tmp_path, text: str) -> dict:
    path = tmp_path / "plan.json"
    path.write_text(text, encoding="utf-8")
    return load_plan_ref(PlanRef("default", path))


def test_plan_loader_rejects_duplicate_keys(tmp_path) -> None:
    with pytest.raises(ValueError, match="duplicate plan JSON key"):
        _load(tmp_path, '{"task": "first", "task": "second"}')


def test_plan_loader_rejects_nonstandard_constants(tmp_path) -> None:
    with pytest.raises(ValueError, match="non-standard plan JSON constant"):
        _load(tmp_path, '{"task": NaN, "steps": []}')


def test_plan_loader_rejects_nonfinite_numbers(tmp_path) -> None:
    with pytest.raises(ValueError, match="non-finite plan JSON number"):
        _load(tmp_path, '{"task": "x", "weight": 1e999}')


def test_plan_loader_accepts_finite_numbers(tmp_path) -> None:
    assert _load(tmp_path, '{"task": "x", "weight": 1.5}')["weight"] == 1.5


def test_seal_loader_rejects_duplicate_keys(tmp_path) -> None:
    path = tmp_path / "seal.json"
    path.write_text('{"format_version": 4, "format_version": 3}', encoding="utf-8")
    with pytest.raises(SealIntegrityError, match="duplicate seal JSON key"):
        load_seal(str(path))


def test_seal_loader_rejects_nonstandard_constants(tmp_path) -> None:
    path = tmp_path / "seal.json"
    path.write_text('{"format_version": Infinity}', encoding="utf-8")
    with pytest.raises(SealIntegrityError, match="non-standard seal JSON constant"):
        load_seal(str(path))


def test_atomic_plan_write_refuses_an_occupied_temp_path(tmp_path) -> None:
    path = tmp_path / "plan.json"
    (tmp_path / "plan.json.formalize.tmp").write_text("occupied", encoding="utf-8")
    with pytest.raises(ValueError, match="temporary plan path already exists"):
        compiler._write_json_atomic(path, {"task": "x"})
    assert not path.exists()


def test_atomic_plan_write_removes_its_temp_file_when_replace_fails(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "plan.json"

    def fail_replace(*_args, **_kwargs):
        raise RuntimeError("replace failed")

    monkeypatch.setattr(compiler.os, "replace", fail_replace)
    with pytest.raises(RuntimeError, match="replace failed"):
        compiler._write_json_atomic(path, {"task": "x"})
    assert not (tmp_path / "plan.json.formalize.tmp").exists()
    assert not path.exists()


def test_atomic_seal_write_refuses_an_occupied_temp_path(tmp_path) -> None:
    path = tmp_path / "seal.json"
    (tmp_path / "seal.json.tmp").write_text("occupied", encoding="utf-8")
    with pytest.raises(SealIntegrityError, match="seal temp path already exists"):
        sealing._write_seal_payload({}, path, None)
    assert not path.exists()


def test_atomic_seal_write_removes_its_temp_file_when_replace_fails(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "seal.json"

    def fail_replace(*_args, **_kwargs):
        raise RuntimeError("replace failed")

    monkeypatch.setattr(sealing.os, "replace", fail_replace)
    with pytest.raises(RuntimeError, match="replace failed"):
        sealing._write_seal_payload({}, path, None)
    assert not (tmp_path / "seal.json.tmp").exists()
    assert not path.exists()
