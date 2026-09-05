"""Safe one-way migration of legacy full-contract v3 seals to v4.

Migration is representation-only: the current effective plan contract must match
what the v3 seal approved. It cannot add/remove requirements, steps, tools,
coverage, outputs or checks. A valid host request contract must also align with
all active plans before the v4 environment/request fingerprint is introduced.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any

from .config import load_config
from .contracts import environment_contract
from .plans import PlanRef, all_plan_refs, load_plan_ref, plan_path, seal_path, validate_plan_name
from .request_contract import analyze_request_alignment, verify_request_contract
from .sealing import (
    SEAL_FORMAT_VERSION,
    SealIntegrityError,
    canonical_plan,
    load_seal,
    save_seal,
    seal_plan,
)


def _selected(root: Path, name: str | None) -> list[PlanRef]:
    if not name:
        refs = all_plan_refs(root)
        if not refs:
            raise ValueError("no active plans to migrate")
        return refs
    safe = validate_plan_name(name)
    path = plan_path(root, safe)
    if not path.is_file():
        raise ValueError(f"plan not found: {path}")
    return [PlanRef(safe, path)]


def _request_alignment(root: Path) -> list[str]:
    status = verify_request_contract(root)
    if not status.valid or not isinstance(status.request, dict):
        return [status.reason or "request contract invalid"]
    plans: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for ref in all_plan_refs(root):
        try:
            plans[ref.key] = load_plan_ref(ref)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{ref.key}: {exc}")
    if errors:
        return errors
    alignment = analyze_request_alignment(plans, status.request)
    return list(alignment.errors)


def _legacy_environment_compatible(legacy: dict[str, Any], current: dict[str, Any]) -> tuple[bool, str]:
    """Permit only new v4 fields; every legacy-bound value must remain identical."""
    for key, value in legacy.items():
        if key not in current:
            return False, f"legacy sealed environment field disappeared: {key}"
        if current[key] != value:
            return False, f"legacy sealed environment changed for {key!r}: {value!r} -> {current[key]!r}"
    if current.get("request_sha256") is None:
        return False, "v4 migration requires an active valid request fingerprint"
    return True, ""


def migrate_one(root: Path, ref: PlanRef) -> dict[str, Any]:
    plan = load_plan_ref(ref)
    target = seal_path(root, ref.name)
    seal = load_seal(str(target))
    if seal is None:
        return {"status": "error", "error": "seal is missing"}
    if seal.format_version == SEAL_FORMAT_VERSION:
        return {"status": "current", "format_version": seal.format_version}
    if seal.format_version != 3:
        return {
            "status": "error",
            "error": f"only full-contract v3 seals can be migrated safely; found v{seal.format_version}",
        }

    # ``load_seal`` already verifies the genuine historical v3 hash encoding,
    # criteria_count and HMAC (when configured). Compare v4 canonical effective
    # graphs here so adding explicit dependencies that are identical to the old
    # implicit sequential semantics counts as representation migration, not a
    # scope change. Any actual contract/scope difference is rejected.
    if canonical_plan(seal.as_plan()) != canonical_plan(plan):
        return {
            "status": "error",
            "error": "current effective plan contract differs from the approved v3 seal; migration cannot change scope",
        }

    cfg = load_config(str(root))
    if cfg.errors:
        return {"status": "error", "error": "invalid supervisor config", "details": cfg.errors}
    current_env = environment_contract(root, cfg)
    compatible, problem = _legacy_environment_compatible(seal.environment or {}, current_env)
    if not compatible:
        return {"status": "error", "error": problem}

    migrated = seal_plan(
        plan,
        seal.plan_id or str(plan.get("id") or plan.get("task") or ref.key),
        dt.datetime.now(dt.timezone.utc).isoformat(),
        environment=current_env,
    )
    save_seal(migrated, str(target))
    return {
        "status": "migrated",
        "from": 3,
        "to": SEAL_FORMAT_VERSION,
        "plan_hash": migrated.plan_hash,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="plan-auditor-migrate-seal",
        description="Safely migrate exact full-contract v3 seals to v4 without changing approved scope.",
    )
    parser.add_argument("dir", nargs="?", default=".")
    parser.add_argument("--plan", help="named plan; omitted = every active plan")
    args = parser.parse_args(argv)
    root = Path(args.dir).expanduser().resolve()

    request_errors = _request_alignment(root)
    if request_errors:
        print(json.dumps({"outcome": "FAIL", "request_errors": request_errors}, indent=2), file=sys.stderr)
        return 2
    try:
        refs = _selected(root, args.plan)
    except (OSError, ValueError) as exc:
        print(json.dumps({"outcome": "FAIL", "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    results: dict[str, Any] = {}
    failed = False
    for ref in refs:
        try:
            result = migrate_one(root, ref)
        except (OSError, ValueError, json.JSONDecodeError, SealIntegrityError) as exc:
            result = {"status": "error", "error": str(exc)}
        results[ref.key] = result
        if result.get("status") == "error":
            failed = True

    print(json.dumps({"outcome": "FAIL" if failed else "PASS", "plans": results}, indent=2))
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
