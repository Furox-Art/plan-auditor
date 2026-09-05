"""Deterministic dependency/output contracts for Plan Auditor plans.

The graph is deliberately data-only: no model judgement and no filesystem IO.
Legacy plans that do not declare ``depends_on`` keep sequential semantics so
existing plans gain prerequisite enforcement without a schema migration.
"""
from __future__ import annotations

from collections import deque
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set


class PlanGraphError(ValueError):
    """Raised when a plan dependency/output contract is structurally invalid."""


def _steps(plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    if isinstance(plan_or_steps, Mapping):
        value = plan_or_steps.get("steps", [])
    else:
        value = plan_or_steps
    return [step for step in value if isinstance(step, Mapping)]


def step_index(plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> Dict[int, Mapping[str, Any]]:
    result: Dict[int, Mapping[str, Any]] = {}
    for step in _steps(plan_or_steps):
        sid = step.get("id")
        if not isinstance(sid, int) or sid < 1:
            raise PlanGraphError("step id must be a positive integer")
        if sid in result:
            raise PlanGraphError("duplicate step id %s" % sid)
        result[sid] = step
    return result


def explicit_graph(plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> bool:
    return any("depends_on" in step for step in _steps(plan_or_steps))


def effective_dependencies(
    plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> Dict[int, List[int]]:
    """Return the effective prerequisite graph.

    When no step declares ``depends_on``, legacy plans are treated as a strict
    sequential chain: each step depends on the preceding step. Once any step
    explicitly declares dependencies, the plan is treated as an explicit DAG
    and omitted ``depends_on`` means a root step.
    """
    steps = _steps(plan_or_steps)
    by_id = step_index(steps)
    use_explicit = explicit_graph(steps)
    deps: Dict[int, List[int]] = {}
    previous: int | None = None
    for step in steps:
        sid = int(step["id"])
        if use_explicit:
            raw = step.get("depends_on", [])
            if not isinstance(raw, list):
                raise PlanGraphError("step %s depends_on must be a list" % sid)
            if any(not isinstance(dep, int) or dep < 1 for dep in raw):
                raise PlanGraphError("step %s depends_on must contain positive integer ids" % sid)
            if len(raw) != len(set(raw)):
                raise PlanGraphError("step %s has duplicate dependencies" % sid)
            current = list(raw)
        else:
            current = [] if previous is None else [previous]
        if sid in current:
            raise PlanGraphError("step %s cannot depend on itself" % sid)
        unknown = [dep for dep in current if dep not in by_id]
        if unknown:
            raise PlanGraphError("step %s depends on unknown step(s): %s" % (sid, unknown))
        deps[sid] = current
        previous = sid
    return deps


def topological_order(
    plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> List[int]:
    steps = _steps(plan_or_steps)
    deps = effective_dependencies(steps)
    order_hint = [int(step["id"]) for step in steps]
    rank = {sid: index for index, sid in enumerate(order_hint)}
    outgoing: Dict[int, Set[int]] = {sid: set() for sid in deps}
    indegree = {sid: len(parents) for sid, parents in deps.items()}
    for sid, parents in deps.items():
        for parent in parents:
            outgoing[parent].add(sid)

    ready = [sid for sid in order_hint if indegree[sid] == 0]
    result: List[int] = []
    while ready:
        ready.sort(key=rank.__getitem__)
        sid = ready.pop(0)
        result.append(sid)
        for child in sorted(outgoing[sid], key=rank.__getitem__):
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)
    if len(result) != len(deps):
        cycle_nodes = [sid for sid in order_hint if indegree[sid] > 0]
        raise PlanGraphError("dependency cycle detected involving step(s): %s" % cycle_nodes)
    return result


def transitive_dependencies(
    plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> Dict[int, Set[int]]:
    deps = effective_dependencies(plan_or_steps)
    order = topological_order(plan_or_steps)
    closure: Dict[int, Set[int]] = {sid: set() for sid in deps}
    for sid in order:
        for parent in deps[sid]:
            closure[sid].add(parent)
            closure[sid].update(closure[parent])
    return closure


def output_index(step: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    sid = step.get("id")
    raw = step.get("outputs", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise PlanGraphError("step %s outputs must be a list" % sid)
    result: Dict[str, Mapping[str, Any]] = {}
    for item in raw:
        if not isinstance(item, Mapping):
            raise PlanGraphError("step %s output must be an object" % sid)
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PlanGraphError("step %s output name must be a non-empty string" % sid)
        if name in result:
            raise PlanGraphError("step %s has duplicate output %r" % (sid, name))
        verify = item.get("verify")
        if not isinstance(verify, list) or not verify:
            raise PlanGraphError("step %s output %r requires non-empty verify checks" % (sid, name))
        result[name] = item
    return result


def required_outputs(step: Mapping[str, Any]) -> List[Dict[str, Any]]:
    sid = step.get("id")
    raw = step.get("requires_outputs", [])
    if raw is None:
        raw = []
    if not isinstance(raw, list):
        raise PlanGraphError("step %s requires_outputs must be a list" % sid)
    result: List[Dict[str, Any]] = []
    seen: Set[tuple[int, str]] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise PlanGraphError("step %s required output must be an object" % sid)
        source = item.get("step")
        name = item.get("name")
        if not isinstance(source, int) or source < 1:
            raise PlanGraphError("step %s required output source must be a positive step id" % sid)
        if not isinstance(name, str) or not name.strip():
            raise PlanGraphError("step %s required output name must be non-empty" % sid)
        key = (source, name)
        if key in seen:
            raise PlanGraphError("step %s repeats required output %s:%s" % (sid, source, name))
        seen.add(key)
        result.append({"step": source, "name": name})
    return result


def validate_output_links(
    plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]],
) -> List[str]:
    """Validate that required outputs exist and come from prerequisite steps."""
    steps = _steps(plan_or_steps)
    try:
        by_id = step_index(steps)
        closure = transitive_dependencies(steps)
    except PlanGraphError as exc:
        return [str(exc)]

    errors: List[str] = []
    outputs: Dict[int, Dict[str, Mapping[str, Any]]] = {}
    for step in steps:
        sid = int(step["id"])
        try:
            outputs[sid] = output_index(step)
        except PlanGraphError as exc:
            errors.append(str(exc))

    for step in steps:
        sid = int(step["id"])
        try:
            required = required_outputs(step)
        except PlanGraphError as exc:
            errors.append(str(exc))
            continue
        for ref in required:
            source = int(ref["step"])
            name = str(ref["name"])
            if source not in by_id:
                errors.append("step %s requires output from unknown step %s" % (sid, source))
                continue
            if source not in closure.get(sid, set()):
                errors.append(
                    "step %s requires output %s:%s but source is not a dependency"
                    % (sid, source, name)
                )
                continue
            if name not in outputs.get(source, {}):
                errors.append(
                    "step %s requires undeclared output %s:%s" % (sid, source, name)
                )
    return errors


def graph_summary(plan_or_steps: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    steps = _steps(plan_or_steps)
    deps = effective_dependencies(steps)
    order = topological_order(steps)
    return {
        "explicit": explicit_graph(steps),
        "dependencies": {str(sid): list(deps[sid]) for sid in order},
        "topological_order": order,
        "outputs": {
            str(int(step["id"])): sorted(output_index(step))
            for step in steps
            if step.get("outputs")
        },
    }
