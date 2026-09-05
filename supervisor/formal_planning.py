"""Classical symbolic planning for sealed Plan Auditor verification checks.

This module deliberately does not use an LLM.  A formal planning contract is
embedded inside an ordinary ``run`` verification check under the
``formal_planning`` key.  Because Plan Auditor already seals and fingerprints the
complete verification-check object, the symbolic model is covered by the
existing plan seal, fresh-audit evidence, and monotonic verification machinery.

The internal planner is a grounded STRIPS-style planner.  It enforces the plan's
existing dependency DAG, symbolic preconditions, add effects, delete effects,
and final goals.  Monotonic (no-delete) models are solved in polynomial time by a
deterministic forward pass; delete-effect models use bounded state-space search.

The same contract can be exported to PDDL 1.x ``:strips`` and independently
cross-checked with Fast Downward when that executable is available.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from scripts.plan_graph import PlanGraphError, effective_dependencies

FORMAL_VERSION = 1
MAX_FACTS = 4096
MAX_ACTIONS = 2048
MAX_SEARCH_STATES = 100_000
MAX_PLANNER_LOG_BYTES = 2_000_000
FORMAL_KEY = "formal_planning"
FORMAL_EXECUTABLE = "plan-auditor-formal"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class FormalAction:
    step_id: int
    preconditions: frozenset[str]
    add_effects: frozenset[str]
    del_effects: frozenset[str]


@dataclass(frozen=True)
class FormalContract:
    initial_facts: frozenset[str]
    goal_facts: frozenset[str]
    actions: Tuple[FormalAction, ...]

    @property
    def by_step(self) -> Dict[int, FormalAction]:
        return {action.step_id: action for action in self.actions}

    @property
    def monotonic(self) -> bool:
        return not any(action.del_effects for action in self.actions)


@dataclass
class FormalPlanningResult:
    enabled: bool = False
    verdict: str = "PASS"  # PASS | REJECT | UNKNOWN
    reason: str = "no formal planning contract"
    contract_sha256: Optional[str] = None
    anchor_step: Optional[int] = None
    solution_order: List[int] = field(default_factory=list)
    explored_states: int = 0
    monotonic: bool = True
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "verdict": self.verdict,
            "reason": self.reason,
            "contract_sha256": self.contract_sha256,
            "anchor_step": self.anchor_step,
            "solution_order": list(self.solution_order),
            "explored_states": self.explored_states,
            "monotonic": self.monotonic,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }


@dataclass
class ExternalPlannerResult:
    status: str  # SOLVED | UNSOLVABLE | UNAVAILABLE | TIMEOUT | ERROR
    command: List[str] = field(default_factory=list)
    returncode: Optional[int] = None
    output_tail: str = ""
    solution_order: List[int] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "command": list(self.command),
            "returncode": self.returncode,
            "output_tail": self.output_tail,
            "solution_order": list(self.solution_order),
            "reason": self.reason,
        }


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def contract_sha256(contract: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(contract)).hexdigest()


def make_formal_check(
    contract: Mapping[str, Any],
    *,
    fast_downward: Optional[str] = None,
    require_fast_downward: bool = False,
) -> Dict[str, Any]:
    """Build the canonical sealed ``run`` check for a formal contract."""
    payload = json.loads(json.dumps(contract, ensure_ascii=False))
    digest = contract_sha256(payload)
    argv = [FORMAL_EXECUTABLE, "verify", ".", "--contract-sha", digest]
    if fast_downward is not None:
        argv.extend(["--fast-downward", str(fast_downward)])
    if require_fast_downward:
        argv.append("--require-fast-downward")
    return {"type": "run", "argv": argv, FORMAL_KEY: payload}


def _fact_list(
    raw: Any,
    label: str,
    errors: List[str],
    *,
    allow_empty: bool = True,
) -> frozenset[str]:
    if not isinstance(raw, list):
        errors.append(f"{label} must be a list of non-empty strings")
        return frozenset()
    if not allow_empty and not raw:
        errors.append(f"{label} must not be empty")
        return frozenset()
    if len(raw) > MAX_FACTS:
        errors.append(f"{label} exceeds the {MAX_FACTS}-fact limit")
    values: List[str] = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, str) or not item.strip():
            errors.append(f"{label}[{index}] must be a non-empty string")
            continue
        if len(item) > 256:
            errors.append(f"{label}[{index}] exceeds 256 characters")
            continue
        values.append(item)
    if len(values) != len(set(values)):
        errors.append(f"{label} contains duplicate facts")
    return frozenset(values)


def _parse_contract(
    plan: Mapping[str, Any], contract: Any
) -> Tuple[Optional[FormalContract], List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []
    if not isinstance(contract, dict):
        return None, ["formal_planning must be an object"], warnings

    allowed_root = {"version", "initial_facts", "goal_facts", "actions"}
    unknown_root = sorted(set(contract) - allowed_root)
    if unknown_root:
        errors.append(f"formal_planning contains unknown field(s): {unknown_root}")

    version = contract.get("version")
    if version != FORMAL_VERSION:
        errors.append(f"formal_planning.version must be {FORMAL_VERSION}")

    initial = _fact_list(contract.get("initial_facts"), "initial_facts", errors)
    goals = _fact_list(
        contract.get("goal_facts"), "goal_facts", errors, allow_empty=False
    )

    raw_actions = contract.get("actions")
    if not isinstance(raw_actions, list):
        errors.append("actions must be a list")
        raw_actions = []
    elif len(raw_actions) > MAX_ACTIONS:
        errors.append(f"actions exceeds the {MAX_ACTIONS}-action limit")

    plan_steps = [step for step in plan.get("steps", []) if isinstance(step, Mapping)]
    plan_ids = [step.get("id") for step in plan_steps if isinstance(step.get("id"), int)]
    actions: List[FormalAction] = []
    seen_steps: set[int] = set()
    allowed_action = {"step", "preconditions", "add_effects", "del_effects"}

    for index, raw_action in enumerate(raw_actions, 1):
        if not isinstance(raw_action, dict):
            errors.append(f"actions[{index}] must be an object")
            continue
        unknown = sorted(set(raw_action) - allowed_action)
        if unknown:
            errors.append(f"actions[{index}] contains unknown field(s): {unknown}")
        sid = raw_action.get("step")
        if isinstance(sid, bool) or not isinstance(sid, int) or sid < 1:
            errors.append(f"actions[{index}].step must be a positive integer")
            continue
        if sid in seen_steps:
            errors.append(f"formal action step id repeated: {sid}")
            continue
        seen_steps.add(sid)
        pre = _fact_list(
            raw_action.get("preconditions", []),
            f"actions[{index}].preconditions",
            errors,
        )
        add = _fact_list(
            raw_action.get("add_effects", []),
            f"actions[{index}].add_effects",
            errors,
        )
        delete = _fact_list(
            raw_action.get("del_effects", []),
            f"actions[{index}].del_effects",
            errors,
        )
        overlap = add & delete
        if overlap:
            errors.append(
                f"step {sid} adds and deletes the same fact(s): {sorted(overlap)}"
            )
        actions.append(FormalAction(sid, pre, add, delete))

    if len(plan_ids) != len(plan_steps):
        errors.append("plan contains a step without a valid integer id")
    if set(seen_steps) != set(plan_ids) or len(actions) != len(plan_ids):
        missing = sorted(set(plan_ids) - seen_steps)
        extra = sorted(seen_steps - set(plan_ids))
        if missing:
            errors.append(f"formal_planning is missing action(s) for step(s): {missing}")
        if extra:
            errors.append(f"formal_planning references unknown step(s): {extra}")
        if not missing and not extra and len(actions) != len(plan_ids):
            errors.append("formal_planning must contain exactly one action per plan step")

    all_added = frozenset().union(*(action.add_effects for action in actions)) if actions else frozenset()
    known_sources = initial | all_added
    for action in actions:
        impossible = action.preconditions - known_sources
        if impossible:
            errors.append(
                f"step {action.step_id} has precondition(s) with no initial/producer source: "
                f"{sorted(impossible)}"
            )
        meaningless_deletes = action.del_effects - known_sources
        if meaningless_deletes:
            errors.append(
                f"step {action.step_id} deletes fact(s) that can never exist: "
                f"{sorted(meaningless_deletes)}"
            )
    impossible_goals = goals - known_sources
    if impossible_goals:
        errors.append(
            f"goal fact(s) have no initial/producer source: {sorted(impossible_goals)}"
        )

    try:
        effective_dependencies(plan)
    except PlanGraphError as exc:
        errors.append(f"dependency graph invalid for formal planner: {exc}")

    if not errors and all(not action.add_effects and not action.del_effects for action in actions):
        warnings.append("all formal actions are effect-free; symbolic model adds little evidence")

    if errors:
        return None, errors, warnings
    return FormalContract(initial, goals, tuple(actions)), errors, warnings


def _anchor_argv_errors(check: Mapping[str, Any], digest: str) -> List[str]:
    errors: List[str] = []
    if check.get("type") != "run":
        return ["formal_planning anchor must be a run check"]
    argv = check.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        return ["formal_planning anchor must use structured argv"]
    expected = [FORMAL_EXECUTABLE, "verify", ".", "--contract-sha", digest]
    if argv[:5] != expected:
        errors.append(
            "formal_planning run check must begin with canonical argv "
            f"{expected!r}"
        )
        return errors

    index = 5
    seen_fast = False
    seen_require = False
    while index < len(argv):
        item = argv[index]
        if item == "--fast-downward" and not seen_fast:
            if index + 1 >= len(argv) or not argv[index + 1].strip():
                errors.append("--fast-downward requires a non-empty command/path")
                break
            seen_fast = True
            index += 2
            continue
        if item == "--require-fast-downward" and not seen_require:
            seen_require = True
            index += 1
            continue
        errors.append(f"unsupported formal planner argv token: {item!r}")
        break
    return errors


def find_formal_anchors(plan: Mapping[str, Any]) -> List[Tuple[int, int, Mapping[str, Any]]]:
    anchors: List[Tuple[int, int, Mapping[str, Any]]] = []
    for step in plan.get("steps", []) or []:
        if not isinstance(step, Mapping):
            continue
        sid = step.get("id")
        if not isinstance(sid, int):
            continue
        for index, check in enumerate(step.get("verify", []) or []):
            if isinstance(check, Mapping) and FORMAL_KEY in check:
                anchors.append((sid, index, check))
    return anchors


def _applicable(
    action: FormalAction,
    facts: frozenset[str],
    done: frozenset[int],
    dependencies: Mapping[int, Sequence[int]],
) -> bool:
    return (
        set(dependencies.get(action.step_id, ())).issubset(done)
        and action.preconditions.issubset(facts)
    )


def _apply(action: FormalAction, facts: frozenset[str]) -> frozenset[str]:
    return frozenset((facts - action.del_effects) | action.add_effects)


def _blocked_detail(
    contract: FormalContract,
    facts: frozenset[str],
    done: frozenset[int],
    dependencies: Mapping[int, Sequence[int]],
) -> str:
    by_step = contract.by_step
    details: List[str] = []
    for sid in sorted(set(by_step) - set(done))[:8]:
        action = by_step[sid]
        missing_deps = sorted(set(dependencies.get(sid, ())) - set(done))
        missing_facts = sorted(action.preconditions - facts)
        details.append(
            f"step {sid}: missing_deps={missing_deps}, missing_facts={missing_facts}"
        )
    return "; ".join(details)


def _monotonic_solve(
    contract: FormalContract,
    dependencies: Mapping[int, Sequence[int]],
) -> Tuple[str, List[int], int, str]:
    facts = contract.initial_facts
    done = frozenset()
    order: List[int] = []
    by_step = contract.by_step
    explored = 1
    while len(done) < len(by_step):
        candidates = [
            by_step[sid]
            for sid in sorted(set(by_step) - set(done))
            if _applicable(by_step[sid], facts, done, dependencies)
        ]
        if not candidates:
            return (
                "REJECT",
                order,
                explored,
                "symbolic dead-end before all plan steps could execute: "
                + _blocked_detail(contract, facts, done, dependencies),
            )
        action = candidates[0]
        facts = _apply(action, facts)
        done = frozenset(set(done) | {action.step_id})
        order.append(action.step_id)
        explored += 1
    missing = contract.goal_facts - facts
    if missing:
        return (
            "REJECT",
            order,
            explored,
            f"all steps execute but final goal fact(s) are false: {sorted(missing)}",
        )
    return "PASS", order, explored, "formal STRIPS contract is reachable"


def _future_impossible(
    contract: FormalContract,
    facts: frozenset[str],
    done: frozenset[int],
) -> bool:
    remaining = [action for action in contract.actions if action.step_id not in done]
    future_adds = frozenset().union(*(action.add_effects for action in remaining)) if remaining else frozenset()
    if not (contract.goal_facts - facts).issubset(future_adds):
        return True
    for action in remaining:
        missing = action.preconditions - facts
        other_adds = frozenset().union(
            *(
                other.add_effects
                for other in remaining
                if other.step_id != action.step_id
            )
        ) if len(remaining) > 1 else frozenset()
        if not missing.issubset(other_adds):
            return True
    return False


def _search_solve(
    contract: FormalContract,
    dependencies: Mapping[int, Sequence[int]],
    max_states: int,
) -> Tuple[str, List[int], int, str]:
    start = (contract.initial_facts, frozenset(), tuple())
    queue = deque([start])
    seen = {(start[0], start[1])}
    by_step = contract.by_step
    explored = 0

    while queue:
        facts, done, order = queue.popleft()
        explored += 1
        if explored > max_states:
            return (
                "UNKNOWN",
                list(order),
                explored,
                f"formal state-space exceeded {max_states} states",
            )
        if len(done) == len(by_step):
            if contract.goal_facts.issubset(facts):
                return "PASS", list(order), explored, "formal STRIPS contract is reachable"
            continue
        if _future_impossible(contract, facts, done):
            continue

        for sid in sorted(set(by_step) - set(done)):
            action = by_step[sid]
            if not _applicable(action, facts, done, dependencies):
                continue
            next_facts = _apply(action, facts)
            next_done = frozenset(set(done) | {sid})
            key = (next_facts, next_done)
            if key in seen:
                continue
            seen.add(key)
            queue.append((next_facts, next_done, order + (sid,)))

    detail = _blocked_detail(
        contract, contract.initial_facts, frozenset(), dependencies
    )
    return (
        "REJECT",
        [],
        explored,
        "no dependency-respecting action ordering reaches all final goals"
        + (f"; initial blockers: {detail}" if detail else ""),
    )


def analyze_formal_contract(
    plan: Mapping[str, Any],
    *,
    max_states: int = MAX_SEARCH_STATES,
) -> FormalPlanningResult:
    anchors = find_formal_anchors(plan)
    if not anchors:
        return FormalPlanningResult()
    if len(anchors) != 1:
        return FormalPlanningResult(
            enabled=True,
            verdict="REJECT",
            reason="plan must contain exactly one formal_planning anchor check",
            errors=[f"found {len(anchors)} formal_planning anchor checks"],
        )

    sid, _index, check = anchors[0]
    raw_contract = check.get(FORMAL_KEY)
    digest = contract_sha256(raw_contract) if isinstance(raw_contract, Mapping) else None
    result = FormalPlanningResult(
        enabled=True,
        anchor_step=sid,
        contract_sha256=digest,
    )
    if digest is None:
        result.verdict = "REJECT"
        result.reason = "formal_planning contract is not an object"
        result.errors.append(result.reason)
        return result

    argv_errors = _anchor_argv_errors(check, digest)
    contract, errors, warnings = _parse_contract(plan, raw_contract)
    result.errors.extend(argv_errors)
    result.errors.extend(errors)
    result.warnings.extend(warnings)
    if result.errors or contract is None:
        result.verdict = "REJECT"
        result.reason = "formal planning contract is structurally invalid"
        return result

    result.monotonic = contract.monotonic
    try:
        dependencies = effective_dependencies(plan)
    except PlanGraphError as exc:
        result.verdict = "REJECT"
        result.reason = f"dependency graph invalid: {exc}"
        result.errors.append(result.reason)
        return result

    if contract.monotonic:
        verdict, order, explored, reason = _monotonic_solve(contract, dependencies)
    else:
        verdict, order, explored, reason = _search_solve(contract, dependencies, max_states)
    result.verdict = verdict
    result.solution_order = order
    result.explored_states = explored
    result.reason = reason
    if verdict == "REJECT":
        result.errors.append(reason)
    elif verdict == "UNKNOWN":
        result.warnings.append(reason)
    return result


def _fact_mapping(contract: FormalContract) -> Dict[str, str]:
    universe = set(contract.initial_facts) | set(contract.goal_facts)
    for action in contract.actions:
        universe.update(action.preconditions)
        universe.update(action.add_effects)
        universe.update(action.del_effects)
    return {fact: f"f{index:04d}" for index, fact in enumerate(sorted(universe), 1)}


def _and(items: Iterable[str]) -> str:
    values = list(items)
    if not values:
        return "(and)"
    return "(and " + " ".join(values) + ")"


def export_pddl(
    plan: Mapping[str, Any], contract_raw: Mapping[str, Any]
) -> Tuple[str, str, Dict[str, str]]:
    contract, errors, _warnings = _parse_contract(plan, contract_raw)
    if errors or contract is None:
        raise ValueError("invalid formal planning contract: " + "; ".join(errors))
    dependencies = effective_dependencies(plan)
    mapping = _fact_mapping(contract)
    predicates: List[str] = [f"({mapping[fact]})" for fact in sorted(mapping)]
    for action in sorted(contract.actions, key=lambda item: item.step_id):
        predicates.append(f"(unused-step-{action.step_id})")
        predicates.append(f"(done-step-{action.step_id})")

    domain_lines = [
        "(define (domain plan-auditor-formal)",
        "  (:requirements :strips)",
        "  (:predicates",
    ]
    domain_lines.extend(f"    {predicate}" for predicate in predicates)
    domain_lines.append("  )")

    for action in sorted(contract.actions, key=lambda item: item.step_id):
        preconditions = [f"(unused-step-{action.step_id})"]
        preconditions.extend(
            f"(done-step-{parent})" for parent in sorted(dependencies.get(action.step_id, ()))
        )
        preconditions.extend(f"({mapping[fact]})" for fact in sorted(action.preconditions))
        effects = [
            f"(done-step-{action.step_id})",
            f"(not (unused-step-{action.step_id}))",
        ]
        effects.extend(f"({mapping[fact]})" for fact in sorted(action.add_effects))
        effects.extend(f"(not ({mapping[fact]}))" for fact in sorted(action.del_effects))
        domain_lines.extend(
            [
                f"  (:action step-{action.step_id}",
                f"    :precondition {_and(preconditions)}",
                f"    :effect {_and(effects)}",
                "  )",
            ]
        )
    domain_lines.append(")")

    init = [f"({mapping[fact]})" for fact in sorted(contract.initial_facts)]
    init.extend(
        f"(unused-step-{action.step_id})"
        for action in sorted(contract.actions, key=lambda item: item.step_id)
    )
    goals = [f"({mapping[fact]})" for fact in sorted(contract.goal_facts)]
    goals.extend(
        f"(done-step-{action.step_id})"
        for action in sorted(contract.actions, key=lambda item: item.step_id)
    )
    problem_lines = [
        "(define (problem plan-auditor-problem)",
        "  (:domain plan-auditor-formal)",
        "  (:init " + " ".join(init) + ")",
        f"  (:goal {_and(goals)})",
        ")",
    ]
    return "\n".join(domain_lines) + "\n", "\n".join(problem_lines) + "\n", mapping


def _fast_downward_base(spec: Optional[str]) -> Optional[List[str]]:
    if spec in (None, "", "off", "none"):
        return None
    candidate: Optional[str]
    if spec == "auto":
        candidate = os.environ.get("FAST_DOWNWARD")
        if not candidate:
            candidate = shutil.which("fast-downward.py") or shutil.which("fast-downward")
        if not candidate:
            return None
    else:
        candidate = str(spec)
        resolved = shutil.which(candidate)
        if resolved:
            candidate = resolved
        elif not Path(candidate).is_file():
            return None
    if candidate.lower().endswith(".py"):
        return [sys.executable, candidate]
    return [candidate]


def _kill_process_group(proc: subprocess.Popen[Any]) -> None:
    if proc.poll() is not None:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass


def _tail_text(path: Path, limit: int = MAX_PLANNER_LOG_BYTES) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > limit:
                handle.seek(size - limit)
            data = handle.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _parse_fd_plan(path: Path) -> List[int]:
    order: List[int] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return order
    for line in lines:
        match = re.match(r"^\s*\(step-(\d+)\)\s*(?:;.*)?$", line, flags=re.IGNORECASE)
        if match:
            order.append(int(match.group(1)))
    return order


def run_fast_downward(
    plan: Mapping[str, Any],
    contract_raw: Mapping[str, Any],
    *,
    executable: str = "auto",
    timeout: float = 300.0,
) -> ExternalPlannerResult:
    base = _fast_downward_base(executable)
    if base is None:
        return ExternalPlannerResult(
            status="UNAVAILABLE",
            reason="Fast Downward executable was not found",
        )
    try:
        domain, problem, _mapping = export_pddl(plan, contract_raw)
    except (ValueError, PlanGraphError) as exc:
        return ExternalPlannerResult(status="ERROR", reason=str(exc))

    with tempfile.TemporaryDirectory(prefix="plan-auditor-pddl-") as tmp:
        root = Path(tmp)
        domain_path = root / "domain.pddl"
        problem_path = root / "problem.pddl"
        log_path = root / "fast-downward.log"
        domain_path.write_text(domain, encoding="utf-8")
        problem_path.write_text(problem, encoding="utf-8")
        command = base + [
            "--alias",
            "lama-first",
            str(domain_path),
            str(problem_path),
        ]
        kwargs: Dict[str, Any] = {
            "cwd": str(root),
            "stdin": subprocess.DEVNULL,
            "stdout": None,
            "stderr": subprocess.STDOUT,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            kwargs["start_new_session"] = True
        try:
            with log_path.open("wb") as log_handle:
                kwargs["stdout"] = log_handle
                proc = subprocess.Popen(command, **kwargs)
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    _kill_process_group(proc)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    return ExternalPlannerResult(
                        status="TIMEOUT",
                        command=command,
                        returncode=proc.returncode,
                        output_tail=_tail_text(log_path),
                        reason=f"Fast Downward exceeded {timeout:g}s",
                    )
        except (OSError, ValueError) as exc:
            return ExternalPlannerResult(
                status="ERROR", command=command, reason=f"Fast Downward start failed: {exc}"
            )

        output = _tail_text(log_path)
        candidates = sorted(root.glob("sas_plan*"))
        plan_file = candidates[0] if candidates else None
        if plan_file is not None and plan_file.is_file():
            order = _parse_fd_plan(plan_file)
            expected = sorted(action.step_id for action in _parse_contract(plan, contract_raw)[0].actions)  # type: ignore[union-attr]
            if sorted(order) != expected or len(order) != len(expected):
                return ExternalPlannerResult(
                    status="ERROR",
                    command=command,
                    returncode=proc.returncode,
                    output_tail=output,
                    solution_order=order,
                    reason="Fast Downward plan does not execute every Plan Auditor step exactly once",
                )
            return ExternalPlannerResult(
                status="SOLVED",
                command=command,
                returncode=proc.returncode,
                output_tail=output,
                solution_order=order,
                reason="Fast Downward independently found a valid PDDL plan",
            )

        lower = output.lower()
        if (
            "no solution" in lower
            or "unsolvable" in lower
            or "search stopped without finding a solution" in lower
        ):
            return ExternalPlannerResult(
                status="UNSOLVABLE",
                command=command,
                returncode=proc.returncode,
                output_tail=output,
                reason="Fast Downward reported the PDDL problem unsolvable",
            )
        return ExternalPlannerResult(
            status="ERROR",
            command=command,
            returncode=proc.returncode,
            output_tail=output,
            reason="Fast Downward produced no plan and no recognized unsolvable result",
        )


def _matching_workspace_contracts(
    root: Path, digest: Optional[str]
) -> List[Tuple[str, Dict[str, Any], Mapping[str, Any]]]:
    from .plans import all_plan_refs, load_plan_ref

    matches: List[Tuple[str, Dict[str, Any], Mapping[str, Any]]] = []
    for ref in all_plan_refs(root):
        plan = load_plan_ref(ref)
        for _sid, _index, check in find_formal_anchors(plan):
            raw = check.get(FORMAL_KEY)
            if not isinstance(raw, Mapping):
                continue
            current = contract_sha256(raw)
            if digest is None or current == digest:
                matches.append((ref.key, plan, check))
    return matches


def verify_workspace(
    root: str | Path,
    *,
    digest: Optional[str] = None,
    fast_downward: Optional[str] = None,
    require_fast_downward: bool = False,
) -> Tuple[bool, Dict[str, Any]]:
    workspace = Path(root).expanduser().resolve()
    if digest is not None and not _SHA256_RE.fullmatch(digest):
        return False, {"outcome": "FAIL", "error": "--contract-sha must be lowercase SHA-256"}
    try:
        matches = _matching_workspace_contracts(workspace, digest)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return False, {"outcome": "FAIL", "error": f"cannot load active plans: {exc}"}
    if not matches:
        target = f" matching {digest}" if digest else ""
        return False, {"outcome": "FAIL", "error": f"no formal planning contract{target} found"}

    records: List[Dict[str, Any]] = []
    overall = True
    for plan_name, plan, check in matches:
        analysis = analyze_formal_contract(plan)
        record: Dict[str, Any] = {
            "plan": plan_name,
            "analysis": analysis.as_dict(),
        }
        if analysis.verdict != "PASS":
            overall = False
        raw = check.get(FORMAL_KEY)
        external: Optional[ExternalPlannerResult] = None
        selected = fast_downward
        if selected is None:
            argv = check.get("argv", [])
            if isinstance(argv, list) and "--fast-downward" in argv:
                index = argv.index("--fast-downward")
                if index + 1 < len(argv):
                    selected = argv[index + 1]
            if isinstance(argv, list) and "--require-fast-downward" in argv:
                require_fast_downward = True
        if selected is not None and isinstance(raw, Mapping) and analysis.verdict == "PASS":
            external = run_fast_downward(plan, raw, executable=selected)
            record["fast_downward"] = external.as_dict()
            if external.status == "UNAVAILABLE" and require_fast_downward:
                overall = False
            elif external.status not in {"SOLVED", "UNAVAILABLE"}:
                overall = False
            elif external.status == "SOLVED":
                if external.solution_order != analysis.solution_order:
                    # Multiple valid orderings are allowed.  Both engines need only
                    # execute the same step set exactly once; the PDDL goal encodes that.
                    record["ordering_note"] = (
                        "internal and Fast Downward found different valid orderings"
                    )
        elif require_fast_downward and selected is None:
            external = run_fast_downward(plan, raw, executable="auto") if isinstance(raw, Mapping) else None
            if external is not None:
                record["fast_downward"] = external.as_dict()
            if external is None or external.status != "SOLVED":
                overall = False
        records.append(record)

    return overall, {"outcome": "PASS" if overall else "FAIL", "contracts": records}


def _cmd_verify(args: argparse.Namespace) -> int:
    ok, payload = verify_workspace(
        args.dir,
        digest=args.contract_sha,
        fast_downward=args.fast_downward,
        require_fast_downward=args.require_fast_downward,
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0 if ok else 2


def _cmd_export(args: argparse.Namespace) -> int:
    root = Path(args.dir).expanduser().resolve()
    matches = _matching_workspace_contracts(root, args.contract_sha)
    if len(matches) != 1:
        print(
            json.dumps(
                {"outcome": "FAIL", "error": f"expected exactly one matching contract, found {len(matches)}"},
                indent=2,
            )
        )
        return 2
    plan_name, plan, check = matches[0]
    raw = check.get(FORMAL_KEY)
    if not isinstance(raw, Mapping):
        print(json.dumps({"outcome": "FAIL", "error": "invalid contract"}, indent=2))
        return 2
    try:
        domain, problem, mapping = export_pddl(plan, raw)
    except (ValueError, PlanGraphError) as exc:
        print(json.dumps({"outcome": "FAIL", "error": str(exc)}, indent=2))
        return 2
    output = Path(args.output).expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / "domain.pddl").write_text(domain, encoding="utf-8")
    (output / "problem.pddl").write_text(problem, encoding="utf-8")
    (output / "facts.json").write_text(
        json.dumps(mapping, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "outcome": "PASS",
                "plan": plan_name,
                "output": str(output),
                "contract_sha256": contract_sha256(raw),
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


def _cmd_make_check(args: argparse.Namespace) -> int:
    try:
        raw = json.loads(Path(args.contract).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"outcome": "FAIL", "error": str(exc)}, indent=2))
        return 2
    if not isinstance(raw, dict):
        print(json.dumps({"outcome": "FAIL", "error": "contract JSON root must be an object"}, indent=2))
        return 2
    check = make_formal_check(
        raw,
        fast_downward=args.fast_downward,
        require_fast_downward=args.require_fast_downward,
    )
    print(json.dumps(check, indent=2, ensure_ascii=False))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=FORMAL_EXECUTABLE,
        description="LLM-free STRIPS/PDDL verification for sealed Plan Auditor plans.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify embedded formal planning contracts")
    verify.add_argument("dir", nargs="?", default=".")
    verify.add_argument("--contract-sha")
    verify.add_argument(
        "--fast-downward",
        help="Fast Downward executable/path or 'auto'; omitted = internal planner only",
    )
    verify.add_argument("--require-fast-downward", action="store_true")
    verify.set_defaults(func=_cmd_verify)

    export = sub.add_parser("export-pddl", help="export one embedded contract to PDDL")
    export.add_argument("dir", nargs="?", default=".")
    export.add_argument("--contract-sha", required=True)
    export.add_argument("--output", required=True)
    export.set_defaults(func=_cmd_export)

    make = sub.add_parser("make-check", help="wrap a formal-contract JSON file in a sealed run check")
    make.add_argument("contract")
    make.add_argument("--fast-downward")
    make.add_argument("--require-fast-downward", action="store_true")
    make.set_defaults(func=_cmd_make_check)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
