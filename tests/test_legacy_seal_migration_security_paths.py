"""Reproducible seal-migration refusal and plan-scope invariance tests."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from supervisor import seal_migration as migration
from supervisor.plans import PlanRef


def _plan():
    return {"task": "do work", "steps": [{"id": 1, "verify": [{"type": "manual"}]}]}


def _ref(tmp_path):
    return PlanRef("reference", tmp_path / "ref.json")


def _old_seal(**overrides):
    values = {
        "format_version": 3, "environment": {"runtime": "fixed"},
        "plan_id": "approved-plan", "plan_hash": "historic-hash",
        "as_plan": _plan,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _setup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    seal=None,
    plan=None,
    environment=None,
    errors=(),
):
    monkeypatch.setattr(migration, "load_plan_ref", lambda ref: plan or _plan())
    monkeypatch.setattr(migration, "seal_path", lambda root, name: root / "seal.json")
    monkeypatch.setattr(migration, "load_seal", lambda path: seal)
    monkeypatch.setattr(migration, "load_config", lambda root: SimpleNamespace(errors=errors))
    monkeypatch.setattr(
        migration, "environment_contract",
        lambda root, cfg: environment or {"runtime": "fixed", "request_sha256": "digest"},
    )


@pytest.mark.parametrize(
    ("old", "error"),
    [
        (None, "seal is missing"),
        (_old_seal(format_version=2), "only full-contract v3"),
        (_old_seal(format_version=77), "only full-contract v3"),
    ],
)
def test_old_seal_missing_or_unsupported_format_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, old, error: str,
) -> None:
    _setup(tmp_path, monkeypatch, seal=old)
    result = migration.migrate_one(tmp_path, _ref(tmp_path))
    assert result["status"] == "error"
    assert error in result["error"]


def test_current_format_seal_is_preserved_without_rewriting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(tmp_path, monkeypatch, seal=_old_seal(format_version=migration.SEAL_FORMAT_VERSION))
    monkeypatch.setattr(
        migration, "save_seal",
        lambda *args: pytest.fail("current seal must not be rewritten"),
    )
    assert migration.migrate_one(tmp_path, _ref(tmp_path)) == {
        "status": "current", "format_version": migration.SEAL_FORMAT_VERSION,
    }


def test_legacy_seal_scope_change_is_never_migrated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(
        tmp_path, monkeypatch, seal=_old_seal(),
        plan={"task": "new objectives", "steps": []},
    )
    assert "cannot change scope" in migration.migrate_one(
        tmp_path, _ref(tmp_path)
    )["error"]


def test_supervisor_config_failure_prevents_new_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(tmp_path, monkeypatch, seal=_old_seal(), errors=["unsafe profile"])
    result = migration.migrate_one(tmp_path, _ref(tmp_path))
    assert result == {
        "status": "error", "error": "invalid supervisor config",
        "details": ["unsafe profile"],
    }


@pytest.mark.parametrize(
    ("environment", "reason"),
    [
        ({"request_sha256": "digest"}, "field disappeared"),
        ({"runtime": "altered", "request_sha256": "digest"}, "changed"),
        ({"runtime": "fixed"}, "request fingerprint"),
    ],
)
def test_legacy_seal_environment_cannot_change_during_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    environment: dict, reason: str,
) -> None:
    _setup(tmp_path, monkeypatch, seal=_old_seal(), environment=environment)
    result = migration.migrate_one(tmp_path, _ref(tmp_path))
    assert result["status"] == "error"
    assert reason in result["error"]


def test_successful_migration_seals_same_effective_scope_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setup(tmp_path, monkeypatch, seal=_old_seal())
    calls = []

    def create(plan, plan_id, timestamp, *, environment):
        calls.append(("create", plan, plan_id, timestamp, environment))
        return SimpleNamespace(plan_hash="new-v4-hash")

    def save(document, path):
        calls.append(("save", document.plan_hash, path))

    monkeypatch.setattr(migration, "seal_plan", create)
    monkeypatch.setattr(migration, "save_seal", save)
    result = migration.migrate_one(tmp_path, _ref(tmp_path))
    assert result == {
        "status": "migrated", "from": 3,
        "to": migration.SEAL_FORMAT_VERSION, "plan_hash": "new-v4-hash",
    }
    assert calls[0][0] == "create"
    assert calls[0][1] == _plan()
    assert calls[0][2] == "approved-plan"
    assert calls[0][4]["request_sha256"] == "digest"
    assert calls[1] == ("save", "new-v4-hash", str(tmp_path / "seal.json"))


def test_selected_plan_requires_real_file_and_rejects_invalid_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(migration, "plan_path", lambda root, name: tmp_path / "absent.json")
    with pytest.raises(ValueError, match="plan not found"):
        migration._selected(tmp_path, "reference")
    with pytest.raises(ValueError):
        migration._selected(tmp_path, "../outside")
    monkeypatch.setattr(migration, "all_plan_refs", lambda root: [])
    with pytest.raises(ValueError, match="no active plans"):
        migration._selected(tmp_path, None)


def test_request_alignment_detects_missing_contract_before_any_plan_migration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        migration, "verify_request_contract",
        lambda root: SimpleNamespace(valid=False, request=None, reason="unsigned request"),
    )
    assert migration._request_alignment(tmp_path) == ["unsigned request"]


def test_request_alignment_propagates_bad_plan_and_scope_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        migration, "verify_request_contract",
        lambda root: SimpleNamespace(valid=True, request={"requirements": []}, reason=""),
    )
    monkeypatch.setattr(migration, "all_plan_refs", lambda root: [_ref(tmp_path)])

    def bad_plan(ref):
        raise ValueError("invalid plan")

    monkeypatch.setattr(migration, "load_plan_ref", bad_plan)
    assert migration._request_alignment(tmp_path) == ["reference: invalid plan"]
    monkeypatch.setattr(migration, "load_plan_ref", lambda ref: _plan())
    monkeypatch.setattr(
        migration, "analyze_request_alignment",
        lambda plans, req: SimpleNamespace(errors=["scope missing"]),
    )
    assert migration._request_alignment(tmp_path) == ["scope missing"]


def test_cli_never_migrates_when_request_is_invalid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    monkeypatch.setattr(migration, "_request_alignment", lambda root: ["missing HMAC"])
    assert migration.main([str(tmp_path)]) == 2
    assert json.loads(capsys.readouterr().err)["outcome"] == "FAIL"


def test_cli_select_failure_and_migration_error_propagate_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    monkeypatch.setattr(migration, "_request_alignment", lambda root: [])
    monkeypatch.setattr(
        migration, "_selected",
        lambda root, name: (_ for _ in ()).throw(ValueError("no approved plan")),
    )
    assert migration.main([str(tmp_path)]) == 2
    assert "no approved plan" in capsys.readouterr().err
    monkeypatch.setattr(migration, "_selected", lambda root, name: [_ref(tmp_path)])
    monkeypatch.setattr(
        migration, "migrate_one",
        lambda root, ref: (_ for _ in ()).throw(migration.SealIntegrityError("bad HMAC")),
    )
    assert migration.main([str(tmp_path)]) == 2
    assert "bad HMAC" in capsys.readouterr().out


def test_cli_reports_all_selected_plans_and_mixed_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys,
) -> None:
    monkeypatch.setattr(migration, "_request_alignment", lambda root: [])
    refs = [PlanRef("good", tmp_path / "good.json"), PlanRef("bad", tmp_path / "bad.json")]
    monkeypatch.setattr(migration, "_selected", lambda root, name: refs)
    monkeypatch.setattr(
        migration, "migrate_one",
        lambda root, ref: (
            {"status": "migrated"} if ref.name == "good"
            else {"status": "error", "error": "scope changed"}
        ),
    )
    assert migration.main([str(tmp_path)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["outcome"] == "FAIL"
    assert set(result["plans"]) == {"good", "bad"}
    monkeypatch.setattr(
        migration, "migrate_one", lambda root, ref: {"status": "current"},
    )
    assert migration.main([str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["outcome"] == "PASS"


def test_selected_plan_returns_exact_valid_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    refs = [PlanRef("first", tmp_path / "one.json")]
    monkeypatch.setattr(migration, "all_plan_refs", lambda root: refs)
    assert migration._selected(tmp_path, None) == refs
    filename = tmp_path / "two.json"
    filename.write_text("{}")
    monkeypatch.setattr(migration, "plan_path", lambda root, name: filename)
    assert migration._selected(tmp_path, "second") == [PlanRef("second", filename)]


def test_python_module_cli_guard_fails_without_authenticated_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", [
        "plan-auditor-migrate-seal", str(tmp_path),
    ])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("supervisor.seal_migration", run_name="__main__")
    assert exc.value.code == 2
