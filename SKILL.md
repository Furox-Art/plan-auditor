---
name: plan-auditor
description: Invoke this skill by name as `plan-auditor` for non-trivial build/implement/fix work or whenever the user wants independent proof that an AI actually completed the requested work. It converts the task into explicit requirements and machine-verifiable steps, adds sealed LLM-free classical planning for non-trivial multi-step plans, proves every step with real command evidence, and blocks completion until every active plan has an intact contract and a fresh deterministic audit.
argument-hint: "<task description>"
metadata:
  version: "2.2.0"
---

# Plan Auditor — strict plan + independent verification

The main agent's narration is never evidence. The workflow has two conceptual
roles that must remain separate:

- **Planner / implementer:** converts the user's exact requirements into work.
- **Auditor / supervisor:** decides completion only from reproducible checks and
  the sealed verification contract.

## Direct invocation

When this skill is selected or called by its name, `plan-auditor`, run the full
workflow described below. The user should not need to know the internal plan JSON,
formal-planning schema, sealing commands, or evidence format.

Examples of user intent that should invoke this skill:

```text
plan-auditor
plan-auditor: implement this and prove it is complete
Use plan-auditor for this task.
```

Treat the user's task text as the authoritative input. Build the requirements,
plan, formal contract when applicable, deterministic checks, seal, implementation
verification, and final audit on the user's behalf.

For non-trivial multi-step plans, create exactly one sealed `formal_planning`
anchor by default so the LLM-free STRIPS-style planner checks symbolic
reachability in addition to the existing dependency/output graph. Every
`must`/`should` requirement must also be bound to the canonical formal goal fact
`requirement-satisfied:<REQ-ID>`. That fact must be a final goal, must not be true
in `initial_facts`, and must be added by an action whose Plan Auditor step covers
the same requirement. Every formal action must have at least one symbolic add or
delete effect. This prevents a decorative STRIPS model from being disconnected
from the requirements it claims to prove.

Use `plan-auditor-formal make-check` to generate the canonical check and SHA. Fast
Downward is an optional independent cross-check; the internal planner remains the
default and requires no GPU, model API, or network connection.

A trivial one-step task may omit formal planning when a symbolic state model adds
no meaningful assurance. Never fabricate facts merely to force a formal model.

## Non-negotiable rules

1. **No deterministic evidence = not done.**
2. **Every user requirement must be explicit.** Supervisor Mode requires
   `plan.requirements`, and every `must`/`should` requirement must be linked from
   one or more steps through `covers`.
3. **Every step needs real behavior.** At least one `run`, `exec`, or `pytest`
   check is mandatory; existence/regex checks may supplement but not replace it.
4. **Dependencies must be concrete.** In explicit DAG plans, every dependency
   edge must be backed by a named upstream output and `requires_outputs`.
5. **Non-trivial multi-step plans get symbolic reachability proof.** Create one
   sealed `formal_planning` anchor with initial facts, preconditions, add/delete
   effects, and final goals unless the task is genuinely too trivial for that
   model to add assurance.
6. **Formal goals must prove requirements, not merely exist.** For every
   `must`/`should` requirement `REQ-X`, include `requirement-satisfied:REQ-X` in
   `goal_facts` and have a covering step produce it. Never place a required
   requirement goal in `initial_facts`; every formal action must have a symbolic
   effect.
7. **Sealed criteria can only tighten.** Do not remove or edit sealed checks,
   dependencies, required outputs, outputs, coverage, requirements, formal
   planning data, or supervisor policy/profile settings to manufacture PASS.
8. **All active plans count.** A passing default plan never hides an unfinished
   `.plan-auditor/plans/<name>.json` plan.
9. **Full audit is the completion gate.** Do not claim completion until
   `plan-auditor audit <project>` exits 0.
10. **Semantic judgment can only tighten.** If the deterministic checks miss a
   real defect, add a stronger deterministic check and rerun; prose cannot turn a
   failure into PASS.

## Plan files

- Default: `<project>/.plan-auditor/plan.json`
- Named: `<project>/.plan-auditor/plans/<safe-name>.json`
- Format reference: `references/plan-format.md`
- Formal planning reference: `docs/formal-planning.md`
- Evidence: `<project>/.plan-auditor/evidence.jsonl` plus anchored archives

A plan should contain explicit `requirements` and use stable IDs such as
`REQ-001`. Each implementation step names the requirements it proves:

```json
{
  "task": "implement the requested behavior",
  "created": "2026-09-05T00:00:00Z",
  "requirements": [
    {"id": "REQ-001", "description": "requested behavior works", "priority": "must"}
  ],
  "required_tools": ["python"],
  "steps": [
    {
      "id": 1,
      "title": "implement and prove behavior",
      "covers": ["REQ-001"],
      "verify": [
        {"type": "run", "argv": ["python", "-m", "pytest", "tests/", "-q"]}
      ]
    }
  ]
}
```

Prefer structured `argv`. Shell interpretation is disabled by default and
`"shell": true` is an explicit trust-boundary opt-in.

## Workflow

### 1. Capture the full requirement set

Translate every material user requirement into a stable requirement object.
Do not omit a requested feature merely because the implementation plan is
shorter. Ambiguous requirements must be clarified or represented explicitly;
they must not disappear.

### 2. Build a measurable plan

Break the work into steps with machine-executable checks. For multi-step work,
model prerequisites and concrete outputs. Example:

```json
{
  "id": 2,
  "title": "consume verified upstream result",
  "depends_on": [1],
  "requires_outputs": [{"step": 1, "name": "artifact"}],
  "covers": ["REQ-002"],
  "verify": [{"type": "run", "argv": ["python", "tests/check_consumer.py"]}]
}
```

Run schema validation while drafting:

```bash
plan-auditor validate <project>
```

For a named plan, the deterministic core also accepts `--plan <name>`.

### 3. Add sealed classical planning for non-trivial multi-step plans

Model the symbolic state using facts, preconditions, add effects, delete effects,
and final goals. The action set must contain exactly one action for every Plan
Auditor step. Existing `depends_on` edges are enforced automatically by the
classical planner.

In addition to ordinary domain facts, create a deterministic requirement binding
for every `must`/`should` requirement. For example, if step 1 covers `REQ-001`,
its `add_effects` must include `requirement-satisfied:REQ-001`, and that fact must
also appear in `goal_facts`. The required fact cannot appear in `initial_facts`.
The integrated L5 verifier rejects missing bindings, bindings produced only by
non-covering steps, or effect-free formal actions.

Generate the canonical anchored check rather than hand-writing its SHA:

```bash
plan-auditor-formal make-check formal-contract.json
```

Put the generated check into exactly one step's `verify` array before sealing.
Use Fast Downward only when an additional external planner cross-check is desired:

```bash
plan-auditor-formal make-check formal-contract.json \
  --fast-downward auto \
  --require-fast-downward
```

The internal planner is authoritative for the built-in formal layer and remains
fully local/CPU-only. Formal planning proves the declared symbolic model; the
requirement-binding layer proves that the symbolic end state is connected to the
requirements covered by the plan. Neither replaces concrete execution checks or
the host-owned request acceptance checks.

### 4. Implement and verify after each step

Run pending/given step checks through the auditor. A failed check means the step
is not finished. Diagnose the real failure, fix the implementation, and rerun.
Never weaken a check just to obtain PASS.

The deterministic core caps normal failed attempts per step and counts failures
across evidence rotations. Use force only when the user explicitly authorizes an
exceptional retry.

### 5. Seal the complete verification contract

Before final audit:

```bash
plan-auditor plan verify <project>
```

With no `--plan`, Supervisor Mode verifies and seals **all active plans**. The
format-v4 seal binds requirements, coverage, DAG/output contracts, checks,
required tools, and supervisor profile/mode/policy fingerprint. Because formal
planning is embedded inside an ordinary sealed verification check, its facts,
actions, effects, goals, and required external-planner flags are covered by the
same seal and plan fingerprint.

If external-key authenticated integrity is configured, initialize it after the
seals exist:

```bash
plan-auditor integrity init <project>
```

The key must be outside the workspace (or supplied through the environment).
This authenticates evidence, checkpoints, registry state, and seals.

### 6. Run the final integrated audit

```bash
plan-auditor audit <project>
```

PASS requires every active plan to have:

- valid schema and explicit requirement coverage,
- successful formal reachability when a `formal_planning` anchor is present,
- deterministic formal requirement-to-goal alignment for every `must`/`should`
  requirement when formal planning is present,
- intact full-contract seal,
- unchanged sealed supervisor environment/policies,
- all steps verified,
- valid dependency/output evidence,
- a fresh plan/workspace fingerprint from a complete audit,
- valid active + archived evidence chains,
- valid agent-registry state,
- required tools present,
- no blocking policy result.

Only exit code 0 means completion is proven.

### 7. Report with evidence

Report which plan/steps were audited and the final PASS/FAIL/UNKNOWN outcome.
Do not substitute “I did it” for the audit result.

## Hook enforcement

`hooks/gate_hook.py` is the authoritative platform-neutral gate. The legacy
`scripts/stop_gate.py` filename remains only as a compatibility adapter for tools
whose Stop hook expects exit code 2; it delegates to the same integrated gate and
does **not** trust `status=verified`.

- Blocking-hook platforms can prevent turn completion when the integrated gate
  is not PASS.
- Advisory-only platforms can write/inject the gate result, but cannot physically
  block the host application.

The hook and the CLI use the same aggregate multi-plan completion decision.

## Snapshot / rollback

The deterministic core supports `snapshot` and `rollback`. A default snapshot
captures the full workspace product state (excluding auditor/git/cache metadata)
and writes a manifest with file type, mode and hash; full-scope rollback restores
those files and removes files introduced after the snapshot. An explicit
`snapshot` list intentionally limits the rollback scope.

## Trust boundary

The purpose of Plan Auditor is to determine whether the AI actually completed the
planned/user-requested work, not to sandbox the AI. Formal planning still cannot
understand whether a human-language requirement was translated into the right
symbolic meaning. The deterministic binding layer closes omission/disconnection
between approved requirements and formal goals, while the host-owned request
contract and acceptance checks remain authoritative for user intent. External
HMAC improves tamper detection, but a same-user process that can read the HMAC key
is outside that integrity guarantee. See `docs/threat-model.md`.
