---
name: plan-auditor
description: Independent plan verification for AI coding agents — converts a task into explicit requirements and machine-verifiable steps, proves every step with real command evidence, and blocks completion until every active plan has requirement coverage, an intact sealed contract, and a fresh deterministic audit. Use for non-trivial build/implement/fix work or whenever the user asks whether the work was actually completed.
argument-hint: "<task description>"
metadata:
  version: "2.1.0"
---

# Plan Auditor — strict plan + independent verification

The main agent's narration is never evidence. The workflow has two conceptual
roles that must remain separate:

- **Planner / implementer:** converts the user's exact requirements into work.
- **Auditor / supervisor:** decides completion only from reproducible checks and
  the sealed verification contract.

## Non-negotiable rules

1. **No deterministic evidence = not done.**
2. **Every user requirement must be explicit.** Supervisor Mode requires
   `plan.requirements`, and every `must`/`should` requirement must be linked from
   one or more steps through `covers`.
3. **Every step needs real behavior.** At least one `run`, `exec`, or `pytest`
   check is mandatory; existence/regex checks may supplement but not replace it.
4. **Dependencies must be concrete.** In explicit DAG plans, every dependency
   edge must be backed by a named upstream output and `requires_outputs`.
5. **Sealed criteria can only tighten.** Do not remove or edit sealed checks,
   dependencies, required outputs, outputs, coverage, requirements, or supervisor
   policy/profile settings to manufacture PASS.
6. **All active plans count.** A passing default plan never hides an unfinished
   `.plan-auditor/plans/<name>.json` plan.
7. **Full audit is the completion gate.** Do not claim completion until
   `plan-auditor audit <project>` exits 0.
8. **Semantic judgment can only tighten.** If the deterministic checks miss a
   real defect, add a stronger deterministic check and rerun; prose cannot turn a
   failure into PASS.

## Plan files

- Default: `<project>/.plan-auditor/plan.json`
- Named: `<project>/.plan-auditor/plans/<safe-name>.json`
- Format reference: `references/plan-format.md`
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

### 3. Implement and verify after each step

Run pending/given step checks through the auditor. A failed check means the step
is not finished. Diagnose the real failure, fix the implementation, and rerun.
Never weaken a check just to obtain PASS.

The deterministic core caps normal failed attempts per step and counts failures
across evidence rotations. Use force only when the user explicitly authorizes an
exceptional retry.

### 4. Seal the complete verification contract

Before final audit:

```bash
plan-auditor plan verify <project>
```

With no `--plan`, Supervisor Mode verifies and seals **all active plans**. The
format-v3 seal binds requirements, coverage, DAG/output contracts, checks,
required tools, and supervisor profile/mode/policy fingerprint.

If external-key authenticated integrity is configured, initialize it after the
seals exist:

```bash
plan-auditor integrity init <project>
```

The key must be outside the workspace (or supplied through the environment).
This authenticates evidence, checkpoints, registry state, and seals.

### 5. Run the final integrated audit

```bash
plan-auditor audit <project>
```

PASS requires every active plan to have:

- valid schema and explicit requirement coverage,
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

### 6. Report with evidence

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
planned/user-requested work, not to sandbox the AI. External HMAC improves tamper
detection, but a same-user process that can read the HMAC key is outside that
integrity guarantee. See `docs/threat-model.md`.
