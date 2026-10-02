"""Canonical serialization, plan-contract hashing and seal addressing.

This module owns every byte-level decision a digest or HMAC depends on. It is
standard-library only, so the deterministic core stays dependency-free, and it
lives in ``scripts`` so both ``scripts`` and ``supervisor`` hash a plan exactly
the same way.

Canonical JSON is sorted-key, minimal-whitespace and non-escaping separators, so
two structurally equal documents always produce identical bytes. That removes
key-order and pretty-print ambiguity from every signature input in the project.

A plan is untrusted input until a format-v4 (or newer) seal binds its full
verification contract. ``exec_trust`` enforces that before anything executes.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional

try:
    from scripts.plan_graph import effective_dependencies
except ImportError:  # pragma: no cover - direct-script execution fallback
    from plan_graph import effective_dependencies

PG_DIR = ".plan-auditor"

#: Field in an activated request contract holding ``{plan_key: plan_hash}``, the
#: cryptographic binding from the host request back to the plans it approves. A
#: workspace may seal several plans under one request, so the binding is per plan.
REQUEST_PLAN_BINDING_FIELD = "plan_contract_sha256s"

SEAL_FORMAT_VERSION = 4
#: Seals older than this do not bind the full contract and cannot authorise
#: execution. They still require the explicit migration/reseal step.
MINIMUM_TRUSTED_SEAL_FORMAT = 4

PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

#: Recovery instructions quoted verbatim in trust failures so the operator is
#: told exactly which command establishes trust instead of guessing.
SEALING_HINT = (
    "run 'plan-auditor plan verify <workspace>' to seal this plan, then "
    "'plan-auditor request init <workspace> --file <host-request.json>'"
)


class PlanTrustError(RuntimeError):
    """A plan is not sealed/authorised, so its commands must not execute."""


def canonical_json(value: Any) -> str:
    """Return canonical JSON text for any digest or HMAC input."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def canonical_digest(value: Any) -> str:
    """SHA-256 of ``value``'s canonical JSON encoding."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def payload_without_auth(value: Dict[str, Any]) -> Dict[str, Any]:
    """Strip the ``auth`` envelope so a MAC never covers itself."""
    return {k: v for k, v in value.items() if k != "auth"}


def validate_plan_name(name: Optional[str]) -> Optional[str]:
    """Return a safe named-plan basename, or ``None`` for the default plan."""
    if name in (None, "", "default"):
        return None
    value = str(name)
    if value in {".", ".."} or not PLAN_NAME_RE.fullmatch(value):
        raise ValueError(
            "geçersiz plan adı; yalnız [A-Za-z0-9._-] ve güvenli basename kullanılabilir"
        )
    if "/" in value or "\\" in value:
        raise ValueError("geçersiz plan adı; yol ayırıcı içeremez")
    return value


def contract_step(step: Dict[str, Any]) -> Dict[str, Any]:
    """Project the sealed portion of a step, excluding mutable runtime status."""
    return {
        "id": step.get("id"),
        "title": copy.deepcopy(step.get("title")),
        "depends_on": copy.deepcopy(step.get("depends_on")),
        "requires_outputs": copy.deepcopy(step.get("requires_outputs", [])),
        "outputs": copy.deepcopy(step.get("outputs", [])),
        "covers": copy.deepcopy(step.get("covers", [])),
        "verify": copy.deepcopy([c for c in step.get("verify", []) if isinstance(c, dict)]),
    }


def legacy_v3_contract_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Reproduce the exact v2.1.0/v3 seal hashing contract.

    v3 stored raw ``depends_on`` values. v4 canonicalizes the effective graph,
    so genuine legacy seals must be self-checked with the historical encoding
    before they can be migrated.
    """
    return {
        "task": copy.deepcopy(plan.get("task")),
        "requirements": copy.deepcopy(plan.get("requirements")),
        "required_tools": copy.deepcopy(plan.get("required_tools", [])),
        "steps": [
            contract_step(step)
            for step in plan.get("steps", [])
            if isinstance(step, dict)
        ],
    }


def legacy_v3_plan_hash(plan: Dict[str, Any]) -> str:
    return canonical_digest(legacy_v3_contract_plan(plan))


def contract_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Return the v4 sealed contract: task, requirements, tools and the DAG."""
    try:
        dependencies = effective_dependencies(plan)
    except Exception:
        # An invalid graph has no effective dependencies. Callers validate the
        # graph separately, and a plan that reaches here fails closed on the
        # resulting hash mismatch rather than being silently sealed.
        dependencies = {}
    steps: List[Dict[str, Any]] = []
    for step in plan.get("steps", []):
        if not isinstance(step, dict):
            continue
        contracted = contract_step(step)
        sid = step.get("id")
        if isinstance(sid, int) and sid in dependencies:
            contracted["depends_on"] = copy.deepcopy(dependencies[sid])
        steps.append(contracted)
    return {
        "task": copy.deepcopy(plan.get("task")),
        "requirements": copy.deepcopy(plan.get("requirements")),
        "required_tools": copy.deepcopy(plan.get("required_tools", [])),
        "steps": steps,
    }


def canonical_plan(plan: Dict[str, Any]) -> str:
    return canonical_json(contract_plan(plan))


def plan_hash(plan: Dict[str, Any]) -> str:
    """SHA-256 of the canonical v4 contract — the value a seal must carry."""
    return hashlib.sha256(canonical_plan(plan).encode("utf-8")).hexdigest()


def seal_path(base: str | os.PathLike, name: Optional[str] = None) -> str:
    """Resolve the seal that authorises ``name`` under ``base``."""
    safe = validate_plan_name(name)
    root = os.path.realpath(os.fspath(base))
    if safe is None:
        return os.path.join(root, PG_DIR, "seal.json")
    container = os.path.realpath(os.path.join(root, PG_DIR, "seals"))
    target = os.path.realpath(os.path.join(container, safe + ".json"))
    if os.path.commonpath([container, target]) != container:
        raise ValueError("seal yolu .plan-auditor/seals dışına çıkıyor")
    return target