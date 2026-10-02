"""Pre-execution trust gate for plan-supplied commands.

A plan JSON is untrusted input: any repository can ship one. Its ``run``/``exec``
checks name arbitrary programs and arguments, so treating a plan file as
authority to execute would turn ``plan-auditor`` into a remote-code-execution
launcher for anyone who clones a hostile repository and runs the CLI in it.

The gate therefore refuses to execute anything until the plan is authorised:

1. a format-v4 (or newer) full-contract seal must exist for that exact plan;
2. the seal's ``plan_hash`` must equal the canonical hash of the plan on disk,
   so the plan cannot be edited after approval;
3. when an external HMAC key is configured, the seal's MAC must verify, and a
   MAC without a key is rejected rather than silently downgraded;
4. when a host request contract is active, the request must be the one the seal
   committed to, and a request derived from a different plan is rejected.

This is deliberately strict: absence, ambiguity and tamper all fail closed.
"""
from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - type checkers see the single package import
    from scripts.contract import (
        MINIMUM_TRUSTED_SEAL_FORMAT,
        PG_DIR,
        REQUEST_PLAN_BINDING_FIELD,
        SEALING_HINT,
        PlanTrustError,
        canonical_digest,
        payload_without_auth,
        plan_hash,
        seal_path,
        validate_plan_name,
    )
    from scripts.integrity import (
        SEAL_DOMAIN,
        IntegrityKeyError,
        runtime_key,
        verify_auth,
    )
else:
    # Direct-script execution of ``scripts/audit_check.py`` puts ``scripts/`` on
    # sys.path, so these modules are importable unprefixed. The runtime fallback
    # is required; the TYPE_CHECKING branch keeps static analysis from seeing the
    # same names bound twice.
    try:
        from scripts.contract import (
            MINIMUM_TRUSTED_SEAL_FORMAT,
            PG_DIR,
            REQUEST_PLAN_BINDING_FIELD,
            SEALING_HINT,
            PlanTrustError,
            canonical_digest,
            payload_without_auth,
            plan_hash,
            seal_path,
            validate_plan_name,
        )
        from scripts.integrity import (
            SEAL_DOMAIN,
            IntegrityKeyError,
            runtime_key,
            verify_auth,
        )
    except ImportError:
        from contract import (
            MINIMUM_TRUSTED_SEAL_FORMAT,
            PG_DIR,
            REQUEST_PLAN_BINDING_FIELD,
            SEALING_HINT,
            PlanTrustError,
            canonical_digest,
            payload_without_auth,
            plan_hash,
            seal_path,
            validate_plan_name,
        )
        from integrity import (
            SEAL_DOMAIN,
            IntegrityKeyError,
            runtime_key,
            verify_auth,
        )

REQUEST_NAME = "request.json"


def _read_json_object(path: str, label: str) -> dict[str, Any]:
    """Read a JSON object, treating symlinks and unreadable files as fatal."""
    if os.path.islink(path):
        raise PlanTrustError(
            f"{label} is a symlink and cannot establish trust: {path}"
        )
    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle)
    except FileNotFoundError:
        raise
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanTrustError(f"{label} is unreadable ({exc}): {path}") from exc
    if not isinstance(value, dict):
        raise PlanTrustError(f"{label} root must be a JSON object: {path}")
    return value


def _seal_environment(data: dict[str, Any]) -> dict[str, Any]:
    environment = data.get("environment")
    return environment if isinstance(environment, dict) else {}


def _verify_seal_mac(base: str, data: dict[str, Any], label: str) -> None:
    """Require a valid HMAC when a key is configured; never downgrade silently."""
    try:
        key = runtime_key(base)
    except IntegrityKeyError as exc:
        raise PlanTrustError(f"{label}: {exc}") from exc
    auth = data.get("auth")
    if key is None:
        if auth is not None:
            raise PlanTrustError(
                f"{label} carries an HMAC but no PLAN_AUDITOR_HMAC_KEY/"
                "PLAN_AUDITOR_HMAC_KEY_FILE is configured; refusing to trust an "
                "unverifiable seal"
            )
        return
    if not verify_auth(key, SEAL_DOMAIN, payload_without_auth(data), auth):
        raise PlanTrustError(
            f"{label} HMAC authentication failed; the seal was not produced by "
            "the configured integrity key"
        )


def _verify_request_binding(
    base: str,
    data: dict[str, Any],
    plan_key: str,
    expected_plan_hash: str,
    label: str,
) -> None:
    """Bind the activated request contract to the sealed plan, both ways."""
    committed = _seal_environment(data).get("request_sha256")
    request_file = os.path.join(os.path.realpath(base), PG_DIR, REQUEST_NAME)
    try:
        request = _read_json_object(request_file, "request contract")
    except FileNotFoundError:
        if committed is not None:
            raise PlanTrustError(
                "request contract is missing but the seal committed to one; "
                f"restore {request_file} or re-seal the workspace ({SEALING_HINT})"
            )
        return
    digest = canonical_digest(payload_without_auth(request))
    if committed is None:
        raise PlanTrustError(
            "request contract is active but the seal did not bind it; re-seal the "
            f"workspace so the request is committed ({SEALING_HINT})"
        )
    if digest != committed:
        raise PlanTrustError(
            "request contract does not match the request sealed in this workspace; "
            f"the request was swapped after sealing ({SEALING_HINT})"
        )
    bindings = request.get(REQUEST_PLAN_BINDING_FIELD)
    if not isinstance(bindings, dict):
        return  # activated before plan binding existed; the seal digest still binds it
    stamped = bindings.get(plan_key)
    if isinstance(stamped, str) and stamped and stamped != expected_plan_hash:
        raise PlanTrustError(
            f"request contract was derived from a different plan {plan_key!r} "
            f"(plan_contract_sha256={stamped}, sealed plan={expected_plan_hash}); "
            f"re-run request init for the current plan ({SEALING_HINT})"
        )


def require_plan_trust(
    base: str, plan: dict[str, Any], name: str | None = None
) -> dict[str, Any]:
    """Authorise ``plan`` to execute, or raise :class:`PlanTrustError`.

    Returns the trusted seal payload so callers can bind their environment
    contract to the exact authority that permitted execution.
    """
    try:
        safe_name = validate_plan_name(name)
    except ValueError as exc:
        raise PlanTrustError(str(exc)) from exc

    plan_key = safe_name or "default"
    label = f"plan seal for {plan_key!r}"
    expected = plan_hash(plan)
    target = seal_path(base, name)
    try:
        data = _read_json_object(target, label)
    except FileNotFoundError as exc:
        raise PlanTrustError(
            f"{label} is absent: the plan is untrusted input and its commands must "
            f"not run. {SEALING_HINT}"
        ) from exc

    version = data.get("format_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise PlanTrustError(f"{label} has no usable format_version")
    if version < MINIMUM_TRUSTED_SEAL_FORMAT:
        raise PlanTrustError(
            f"{label} uses format_version={version}, which does not bind the full "
            "verification contract; run 'plan-auditor-migrate-seal' or "
            "'plan-auditor plan verify --reseal'"
        )

    sealed_hash = data.get("plan_hash")
    if not isinstance(sealed_hash, str) or not sealed_hash:
        raise PlanTrustError(f"{label} has no plan_hash")
    if sealed_hash != expected:
        raise PlanTrustError(
            f"{label} does not match the plan on disk (sealed={sealed_hash}, "
            f"current={expected}); the plan was changed after it was sealed, so "
            "its commands must not run"
        )

    _verify_seal_mac(base, data, label)
    _verify_request_binding(base, data, plan_key, expected, label)
    return data