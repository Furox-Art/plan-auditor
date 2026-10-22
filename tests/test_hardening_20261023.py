"""Regressions for strict plan/seal JSON parsing."""
from __future__ import annotations

import pytest

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
