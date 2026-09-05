"""Deterministic compiler from structured Plan Auditor plans to sealed STRIPS contracts.

This module does not interpret free-form natural language. It compiles already
approved Plan Auditor primitives (requirements, coverage, dependencies, named
outputs, and verification checks) into a conservative symbolic model. A source
fingerprint is embedded as a reserved initial fact so the generated contract can
be independently recomputed and compared with the plan before PASS.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from scripts.plan_graph import PlanGraphError, effective_dependencies, required_outputs

from .formal_planning import FORMAL_KEY, contract_sha256, find_formal_anchors, make_formal_check
from .plans import PlanRef, all_plan_refs, load_plan_ref, plan_path, seal_path, validate_plan_name

FORMALIZER_EXECUTABLE = "plan-auditor-formalize"
FORMALIZATION_VERSION = 1
FORMALIZATION_SOURCE_PREFIX = "formalization-source:"
STEP_FACT_PREFIX = "step-completed:"
OUTPUT_FACT_PREFIX = "output-available:"
REQUIREMENT_FACT_PREFIX = "requirement-satisfied:"
MAX_FACT_LEN = 256
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class CompilationResult:
    valid: bool
    changed: bool = False
    plan_name: str = "default"
    contract_sha256: Optional[str] = None
    anchor_step: Optional[int] = None
    errors: List[str] = field(default_factory=list)
    contract: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "changed": self.changed,
            "plan": self.plan_name,
            "contract_sha256": self.contract_sha256,
            "anchor_step": self.anchor_step,
            "errors": list(self.errors),
            "contract": self.contract,
        }


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _normalized_requirements(plan: Mapping[str, Any]) -> Tuple[List[Dict[str, str]], List[str]]:
    raw = plan.get("requirements")
    if not isinstance(raw, list) or not raw:
        return [], ["automatic formalization requires non-empty plan.requirements"]
    result: List[Dict[str, str]] = []
    errors: List[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw, 1):
        if isinstance(item, str):
            item = {"id": f"REQ-{index:03d}", "description": item, "priority": "must"}
        if not isinstance(item, Mapping):
            errors.append(f"requirement {index} must be an object or string")
            continue
        req_id = item.get("id")
        description = item.get("description")
        priority = str(item.get("priority", "must")).lower()
        if not isinstance(req_id, str) or not req_id.strip():
            errors.append(f"requirement {index} requires a non-empty id")
            continue
        req_id = req_id.strip()
        if req_id in seen:
            errors.append(f"duplicate requirement id: {req_id}")
            continue
        seen.add(req_id)
        if not isinstance(description, str) or not description.strip():
            errors.append(f"requirement {req_id} requires a non-empty description")
        if priority not in {"must", "should", "may"}:
            errors.append(f"requirement {req_id} has invalid priority {priority!r}")
        result.append(
            {"id": req_id, "description": str(description or ""), "priority": priority}
        )
    return result, errors


def requirement_goal_fact(requirement_id: str) -> str:
    value = f"{REQUIREMENT_FACT_PREFIX}{requirement_id.strip()}"
    if len(value) > MAX_FACT_LEN:
        raise ValueError("requirement id is too long for a canonical formal goal fact")
    return value


def step_fact(step_id: int) -> str:
    return f"{STEP_FACT_PREFIX}{step_id}"


def output_fact(step_id: int, name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", name.strip()).strip("-") or "output"
    clean = clean[:80]
    digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    value = f"{OUTPUT_FACT_PREFIX}{step_id}:{clean}:{digest}"
    if len(value) > MAX_FACT_LEN:
        raise ValueError(f"output fact for step {step_id} exceeds {MAX_FACT_LEN} characters")
    return value


def _is_generated_semantic_check(check: Any) -> bool:
    if not isinstance(check, Mapping) or check.get("type") != "run":
        return False
    argv = check.get("argv")
    return (
        isinstance(argv, list)
        and bool(argv)
        and isinstance(argv[0], str)
        and argv[0] == FORMALIZER_EXECUTABLE
    )


def _source_projection(plan: Mapping[str, Any]) -> Dict[str, Any]:
    """Return exactly the structured plan data that drives compilation.

    Formal anchors and generated semantic-verifier checks are excluded to avoid
    circular fingerprints. Everything else relevant to user intent, coverage,
    dataflow, and deterministic verification remains in the projection.
    """
    projected_steps: List[Dict[str, Any]] = []
    for raw_step in plan.get("steps", []) if isinstance(plan.get("steps"), list) else []:
        if not isinstance(raw_step, Mapping):
            projected_steps.append({"invalid_step": raw_step})
            continue
        verify = []
        for check in raw_step.get("verify", []) if isinstance(raw_step.get("verify"), list) else []:
            if isinstance(check, Mapping) and FORMAL_KEY in check:
                continue
            if _is_generated_semantic_check(check):
                continue
            verify.append(copy.deepcopy(check))
        projected_steps.append(
            {
                "id": raw_step.get("id"),
                "depends_on": copy.deepcopy(raw_step.get("depends_on", [])),
                "requires_outputs": copy.deepcopy(raw_step.get("requires_outputs", [])),
                "covers": copy.deepcopy(raw_step.get("covers", [])),
                "outputs": copy.deepcopy(raw_step.get("outputs", [])),
                "verify": verify,
            }
        )
    return {
        "task": plan.get("task"),
        "requirements": copy.deepcopy(plan.get("requirements")),
        "steps": projected_steps,
    }


def source_sha256(plan: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(_source_projection(plan))).hexdigest()


def source_fact(plan: Mapping[str, Any]) -> str:
    return FORMALIZATION_SOURCE_PREFIX + source_sha256(plan)


def is_generated_contract(contract: Any) -> bool:
    if not isinstance(contract, Mapping):
        return False
    initial = contract.get("initial_facts")
    if not isinstance(initial, list):
        return False
    return any(
        isinstance(fact, str) and fact.startswith(FORMALIZATION_SOURCE_PREFIX)
        for fact in initial
    )


def _step_output_names(step: Mapping[str, Any]) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    names: List[str] = []
    outputs = step.get("outputs", [])
    if outputs is None:
        outputs = []
    if not isinstance(outputs, list):
        return [], [f"step {step.get('id')} outputs must be a list"]
    seen: set[str] = set()
    for index, item in enumerate(outputs, 1):
        if isinstance(item, str):
            name = item.strip()
        elif isinstance(item, Mapping):
            raw = item.get("name")
            name = raw.strip() if isinstance(raw, str) else ""
        else:
            name = ""
        if not name:
            errors.append(f"step {step.get('id')} output {index} requires a non-empty name")
            continue
        if name in seen:
            errors.append(f"step {step.get('id')} repeats output name {name!r}")
            continue
        seen.add(name)
        names.append(name)
    return names, errors


def compile_contract(plan: Mapping[str, Any]) -> Dict[str, Any]:
    """Compile a conservative, deterministic STRIPS contract from plan structure.

    No domain fact is guessed from natural-language prose. The only generated
    facts are source-fingerprint, step-completion, named-output availability, and
    canonical must/should requirement-satisfaction facts.
    """
    requirements, errors = _normalized_requirements(plan)
    if errors:
        raise ValueError("; ".join(errors))
    required = {
        item["id"]: item
        for item in requirements
        if item.get("priority") in {"must", "should"}
    }
    if not required:
        raise ValueError("automatic formalization requires at least one must/should requirement")

    raw_steps = plan.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("automatic formalization requires non-empty plan.steps")

    try:
        dependencies = effective_dependencies(plan)
    except PlanGraphError as exc:
        raise ValueError(f"cannot formalize invalid dependency graph: {exc}") from exc

    marker = source_fact(plan)
    actions: List[Dict[str, Any]] = []
    produced_requirement_ids: set[str] = set()
    all_output_facts: List[str] = []
    all_step_facts: List[str] = []
    seen_steps: set[int] = set()
    known_requirement_ids = {item["id"] for item in requirements}

    for index, raw_step in enumerate(raw_steps, 1):
        if not isinstance(raw_step, Mapping):
            raise ValueError(f"step {index} must be an object")
        sid = raw_step.get("id")
        if isinstance(sid, bool) or not isinstance(sid, int) or sid < 1:
            raise ValueError(f"step {index} requires a positive integer id")
        if sid in seen_steps:
            raise ValueError(f"duplicate step id: {sid}")
        seen_steps.add(sid)

        output_names, output_errors = _step_output_names(raw_step)
        if output_errors:
            raise ValueError("; ".join(output_errors))
        output_facts = [output_fact(sid, name) for name in output_names]
        all_output_facts.extend(output_facts)

        try:
            refs = required_outputs(dict(raw_step))
        except PlanGraphError as exc:
            raise ValueError(str(exc)) from exc
        preconditions = {marker}
        for ref in refs:
            preconditions.add(output_fact(int(ref["step"]), str(ref["name"])))

        covers_raw = raw_step.get("covers", [])
        if covers_raw is None:
            covers_raw = []
        if not isinstance(covers_raw, list):
            raise ValueError(f"step {sid} covers must be a list")
        covers: List[str] = []
        seen_covers: set[str] = set()
        for item in covers_raw:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"step {sid} covers contains an invalid requirement id")
            req_id = item.strip()
            if req_id in seen_covers:
                raise ValueError(f"step {sid} repeats coverage for {req_id}")
            seen_covers.add(req_id)
            if req_id not in known_requirement_ids:
                raise ValueError(f"step {sid} covers unknown requirement {req_id}")
            covers.append(req_id)

        adds = {step_fact(sid), *output_facts}
        all_step_facts.append(step_fact(sid))
        for req_id in covers:
            if req_id in required:
                adds.add(requirement_goal_fact(req_id))
                produced_requirement_ids.add(req_id)

        # Dependencies are enforced independently by the planner, but requiring
        # concrete upstream outputs here binds the symbolic state to dataflow too.
        linked_sources = {int(ref["step"]) for ref in refs}
        for parent in dependencies.get(sid, []):
            if parent not in linked_sources:
                raise ValueError(
                    f"dependency edge {parent} -> {sid} has no requires_outputs link"
                )

        actions.append(
            {
                "step": sid,
                "preconditions": sorted(preconditions),
                "add_effects": sorted(adds),
                "del_effects": [],
            }
        )

    missing = sorted(set(required) - produced_requirement_ids)
    if missing:
        raise ValueError(
            "required requirements are not covered by any formalized step: " + ", ".join(missing)
        )

    goals = {requirement_goal_fact(req_id) for req_id in required}
    goals.update(all_output_facts)
    goals.update(all_step_facts)
    return {
        "version": 1,
        "initial_facts": [marker],
        "goal_facts": sorted(goals),
        "actions": actions,
    }


def validate_generated_contract(plan: Mapping[str, Any], contract: Any) -> List[str]:
    """Recompile from plan sources and compare exactly with a generated contract."""
    if not isinstance(contract, Mapping):
        return ["generated formal contract must be an object"]
    initial = contract.get("initial_facts")
    if not isinstance(initial, list):
        return ["generated formal contract initial_facts must be a list"]
    markers = [
        fact
        for fact in initial
        if isinstance(fact, str) and fact.startswith(FORMALIZATION_SOURCE_PREFIX)
    ]
    if not markers:
        return []
    if len(markers) != 1:
        return ["generated formal contract must contain exactly one formalization-source marker"]
    expected_marker = source_fact(plan)
    errors: List[str] = []
    if markers[0] != expected_marker:
        errors.append(
            "generated formal contract source fingerprint does not match current plan structure"
        )
    try:
        expected = compile_contract(plan)
    except ValueError as exc:
        errors.append(f"cannot deterministically recompile formal contract: {exc}")
        return errors
    if _canonical(dict(contract)) != _canonical(expected):
        errors.append(
            "generated formal contract differs from deterministic recompilation; "
            "manual weakening, omission, or stale formalization is not accepted"
        )
    return errors


def make_semantic_check(digest: str) -> Dict[str, Any]:
    if not _SHA256_RE.fullmatch(digest):
        raise ValueError("contract digest must be lowercase SHA-256")
    return {
        "type": "run",
        "argv": [
            FORMALIZER_EXECUTABLE,
            "verify",
            ".",
            "--contract-sha",
            digest,
        ],
    }


def _strip_generated_checks(plan: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[int], bool]:
    value = copy.deepcopy(plan)
    existing_anchor: Optional[int] = None
    changed = False
    anchors = find_formal_anchors(value)
    if len(anchors) > 1:
        raise ValueError("cannot auto-formalize a plan with multiple formal_planning anchors")
    if anchors:
        sid, _index, check = anchors[0]
        raw = check.get(FORMAL_KEY)
        if not is_generated_contract(raw):
            raise ValueError(
                "plan contains a manual formal_planning contract; automatic compiler will not overwrite it"
            )
        existing_anchor = sid

    for step in value.get("steps", []) if isinstance(value.get("steps"), list) else []:
        if not isinstance(step, dict):
            continue
        verify = step.get("verify", [])
        if not isinstance(verify, list):
            continue
        filtered = []
        for check in verify:
            if isinstance(check, Mapping) and FORMAL_KEY in check:
                changed = True
                continue
            if _is_generated_semantic_check(check):
                changed = True
                continue
            filtered.append(check)
        step["verify"] = filtered
    return value, existing_anchor, changed


def compile_plan(
    plan: Mapping[str, Any],
    *,
    anchor_step: Optional[int] = None,
    fast_downward: Optional[str] = None,
    require_fast_downward: bool = False,
) -> Tuple[Dict[str, Any], Dict[str, Any], int]:
    """Return a copy of plan with one generated formal anchor + semantic verifier."""
    base, existing_anchor, _ = _strip_generated_checks(dict(plan))
    raw_steps = base.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("plan has no steps")

    step_ids = [
        step.get("id")
        for step in raw_steps
        if isinstance(step, Mapping) and isinstance(step.get("id"), int)
    ]
    if len(step_ids) != len(raw_steps):
        raise ValueError("every plan step must have an integer id before automatic formalization")
    selected = anchor_step if anchor_step is not None else existing_anchor
    if selected is None:
        try:
            dependencies = effective_dependencies(base)
        except PlanGraphError as exc:
            raise ValueError(str(exc)) from exc
        roots = sorted(sid for sid, parents in dependencies.items() if not parents)
        selected = roots[0] if roots else int(step_ids[0])
    if selected not in step_ids:
        raise ValueError(f"anchor step {selected} does not exist")

    contract = compile_contract(base)
    formal_check = make_formal_check(
        contract,
        fast_downward=fast_downward,
        require_fast_downward=require_fast_downward,
    )
    digest = contract_sha256(contract)
    semantic_check = make_semantic_check(digest)

    anchor = next(
        step
        for step in raw_steps
        if isinstance(step, dict) and step.get("id") == selected
    )
    verify = anchor.get("verify", [])
    if verify is None:
        verify = []
    if not isinstance(verify, list):
        raise ValueError(f"step {selected} verify must be a list")
    anchor["verify"] = [formal_check, semantic_check, *verify]
    return base, contract, selected


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    if path.is_symlink():
        raise ValueError(f"refusing to write through symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".formalize.tmp")
    if tmp.exists() and tmp.is_symlink():
        raise ValueError(f"refusing symlinked temporary plan path: {tmp}")
    tmp.write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp.replace(path)


def _compile_ref(
    root: Path,
    ref: PlanRef,
    *,
    write: bool,
    anchor_step: Optional[int],
    fast_downward: Optional[str],
    require_fast_downward: bool,
) -> CompilationResult:
    plan = load_plan_ref(ref)
    try:
        compiled, contract, selected = compile_plan(
            plan,
            anchor_step=anchor_step,
            fast_downward=fast_downward,
            require_fast_downward=require_fast_downward,
        )
    except ValueError as exc:
        return CompilationResult(False, plan_name=ref.key, errors=[str(exc)])

    digest = contract_sha256(contract)
    changed = _canonical(plan) != _canonical(compiled)
    if write and changed:
        seal = seal_path(root, ref.name)
        if seal.exists():
            return CompilationResult(
                False,
                plan_name=ref.key,
                contract_sha256=digest,
                anchor_step=selected,
                contract=contract,
                errors=[
                    "refusing to mutate a sealed plan; create/update the plan before sealing "
                    "or start a new approval generation"
                ],
            )
        _write_json_atomic(plan_path(root, ref.name), compiled)
    return CompilationResult(
        True,
        changed=changed,
        plan_name=ref.key,
        contract_sha256=digest,
        anchor_step=selected,
        contract=contract,
    )


def compile_workspace(
    root: str | Path,
    *,
    plan_name: Optional[str] = None,
    write: bool = True,
    anchor_step: Optional[int] = None,
    fast_downward: Optional[str] = None,
    require_fast_downward: bool = False,
) -> List[CompilationResult]:
    workspace = Path(root).expanduser().resolve()
    refs = all_plan_refs(workspace)
    if plan_name not in (None, "", "all"):
        safe = validate_plan_name(plan_name)
        refs = [ref for ref in refs if ref.name == safe]
    if not refs:
        return [CompilationResult(False, errors=["no matching active plan found"])]
    return [
        _compile_ref(
            workspace,
            ref,
            write=write,
            anchor_step=anchor_step,
            fast_downward=fast_downward,
            require_fast_downward=require_fast_downward,
        )
        for ref in refs
    ]


def verify_workspace(
    root: str | Path,
    *,
    digest: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    workspace = Path(root).expanduser().resolve()
    if digest is not None and not _SHA256_RE.fullmatch(digest):
        return False, {"outcome": "FAIL", "error": "--contract-sha must be lowercase SHA-256"}

    records: List[Dict[str, Any]] = []
    try:
        refs = all_plan_refs(workspace)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, {"outcome": "FAIL", "error": f"cannot load active plans: {exc}"}

    for ref in refs:
        plan = load_plan_ref(ref)
        for _sid, _index, check in find_formal_anchors(plan):
            raw = check.get(FORMAL_KEY)
            if not isinstance(raw, Mapping) or not is_generated_contract(raw):
                continue
            current = contract_sha256(raw)
            if digest is not None and current != digest:
                continue
            generated_errors = validate_generated_contract(plan, raw)
            from .formal_semantics import analyze_formal_semantics

            semantic = analyze_formal_semantics(plan)
            errors = list(generated_errors)
            errors.extend(error for error in semantic.errors if error not in errors)
            records.append(
                {
                    "plan": ref.key,
                    "contract_sha256": current,
                    "valid": not errors,
                    "errors": errors,
                }
            )

    if not records:
        target = f" matching {digest}" if digest else ""
        return False, {
            "outcome": "FAIL",
            "error": f"no generated formal planning contract{target} found",
        }
    ok = all(record["valid"] for record in records)
    return ok, {"outcome": "PASS" if ok else "FAIL", "formalizations": records}


def _cmd_compile(args: argparse.Namespace) -> int:
    results = compile_workspace(
        args.dir,
        plan_name=args.plan,
        write=not args.dry_run,
        anchor_step=args.anchor_step,
        fast_downward=args.fast_downward,
        require_fast_downward=args.require_fast_downward,
    )
    payload = {
        "outcome": "PASS" if all(item.valid for item in results) else "FAIL",
        "written": not args.dry_run,
        "results": [item.as_dict() for item in results],
    }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if payload["outcome"] == "PASS" else 2


def _cmd_verify(args: argparse.Namespace) -> int:
    ok, payload = verify_workspace(args.dir, digest=args.contract_sha)
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if ok else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=FORMALIZER_EXECUTABLE,
        description=(
            "Deterministically compile structured Plan Auditor requirements and "
            "dataflow into sealed STRIPS contracts without guessing natural-language semantics."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    compile_cmd = sub.add_parser(
        "compile",
        help="compile and install generated formal contracts before plan sealing",
    )
    compile_cmd.add_argument("dir", nargs="?", default=".")
    compile_cmd.add_argument("--plan", help="named plan; omitted = all active plans")
    compile_cmd.add_argument("--anchor-step", type=int)
    compile_cmd.add_argument("--dry-run", action="store_true")
    compile_cmd.add_argument("--fast-downward")
    compile_cmd.add_argument("--require-fast-downward", action="store_true")
    compile_cmd.set_defaults(func=_cmd_compile)

    verify = sub.add_parser(
        "verify",
        help="recompile generated contracts from sealed plan sources and compare exactly",
    )
    verify.add_argument("dir", nargs="?", default=".")
    verify.add_argument("--contract-sha")
    verify.set_defaults(func=_cmd_verify)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
