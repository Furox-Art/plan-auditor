---
name: plan-auditor
description: Invoke this skill by name as `plan-auditor` for non-trivial build/implement/fix work or whenever the user wants independent proof that an AI actually completed the requested work. It converts the task into explicit requirements and machine-verifiable steps, automatically compiles those structured requirements/dataflow into a sealed LLM-free STRIPS contract, proves every step with real command evidence, and blocks completion until every active plan has an intact contract and a fresh deterministic audit.
argument-hint: "<task description>"
metadata:
  version: "2.4.0"
---

# Plan Auditor — strict plan + independent verification

The main agent's narration is never evidence. The workflow has two separate roles:

- **Planner / implementer:** converts the user's exact requirements into work.
- **Auditor / supervisor:** decides completion only from reproducible checks and the sealed verification contract.

## Direct invocation

When this skill is selected or called by its name, `plan-auditor`, run the full workflow automatically. The user should not need to know or hand-write plan JSON, STRIPS/PDDL, seal metadata, evidence files, or source fingerprints.

Examples:

```text
plan-auditor
plan-auditor: implement this and prove it is complete
Use plan-auditor for this task.
```

Treat the user's task as the authoritative intent. Capture it in the host-owned request contract and explicit plan requirements, then build measurable steps and deterministic acceptance checks.

For non-trivial multi-step plans, use the deterministic auto-formalizer before sealing:

```bash
plan-auditor-formalize compile <project>
```

The compiler does **not** ask an LLM to invent symbolic semantics. It derives a conservative formal model only from already structured Plan Auditor primitives:

- `must` / `should` requirement IDs,
- step `covers` bindings,
- dependency edges,
- named `outputs`,
- `requires_outputs` dataflow,
- deterministic verification checks.

It creates exactly one generated `formal_planning` anchor plus an independent semantic-recompilation check. Generated facts are limited to:

- `formalization-source:<SHA256>` — fingerprint of the structured source plan,
- `step-completed:<STEP-ID>`,
- `output-available:<STEP-ID>:...`,
- `requirement-satisfied:<REQ-ID>`.

The source fingerprint is recomputed from the current plan during verification. A generated contract that omits a requirement, drops an output precondition, weakens a goal, or becomes stale after the plan changes is rejected even if its internal contract SHA was recomputed.

Manual domain-specific STRIPS contracts remain supported, but the auto-formalizer will not overwrite them. If a domain fact cannot be derived safely from structured plan data, do not guess it; keep it in a manually reviewed contract or rely on deterministic acceptance checks.

## Non-negotiable rules

1. **No deterministic evidence = not done.**
2. **Every user requirement must be explicit.** Supervisor Mode requires non-empty `plan.requirements`; every `must`/`should` requirement must be linked from one or more steps through `covers`.
3. **Every step needs real behavior.** At least one `run`, `exec`, or `pytest` check is mandatory; existence/regex checks may supplement but not replace behavioral proof.
4. **Dependencies must be concrete.** Every explicit dependency edge must be backed by a named upstream output and `requires_outputs`.
5. **Auto-formalize non-trivial multi-step work before sealing.** Run `plan-auditor-formalize compile <project>` unless a deliberate, reviewed manual formal contract is used.
6. **Generated formalization is independently recomputed.** Never edit generated STRIPS facts/actions by hand to manufacture PASS. Change the structured plan source and re-run the compiler.
7. **Formal goals must prove requirements.** Every `must`/`should` requirement gets canonical `requirement-satisfied:<REQ-ID>` final-state proof produced only by covering steps.
8. **Sealed criteria can only tighten.** Do not remove or weaken sealed checks, dependencies, required outputs, outputs, coverage, requirements, formal planning data, or supervisor policy/profile settings.
9. **All active plans count.** A passing default plan never hides an unfinished named plan.
10. **Full audit is the completion gate.** Do not claim completion until `plan-auditor audit <project>` exits 0.
11. **Semantic judgment can only tighten.** If deterministic checks miss a real defect, add a stronger deterministic check and rerun; prose cannot convert failure into PASS.

## Workflow

### 1. Capture the request contract

Convert every material user requirement into a stable requirement object with an ID, description, priority, and deterministic acceptance checks. The host-owned request contract remains the authority for user intent.

### 2. Build a measurable plan

Each step must declare what it covers, how it is verified, and—when relevant—its outputs and required upstream outputs.

Example:

```json
{
  "task": "build and consume a verified artifact",
  "created": "2026-09-06T00:00:00Z",
  "requirements": [
    {"id": "REQ-001", "description": "produce the artifact", "priority": "must"},
    {"id": "REQ-002", "description": "consume the verified artifact", "priority": "must"}
  ],
  "steps": [
    {
      "id": 1,
      "title": "produce",
      "depends_on": [],
      "covers": ["REQ-001"],
      "verify": [{"type": "run", "argv": ["python", "tests/build.py"]}],
      "outputs": [{"name": "artifact", "verify": [{"type": "file_exists", "path": "result.json"}]}]
    },
    {
      "id": 2,
      "title": "consume",
      "depends_on": [1],
      "requires_outputs": [{"step": 1, "name": "artifact"}],
      "covers": ["REQ-002"],
      "verify": [{"type": "run", "argv": ["python", "tests/use.py"]}]
    }
  ]
}
```

Validate while drafting:

```bash
plan-auditor validate <project>
```

### 3. Automatically compile the formal contract

For non-trivial multi-step work:

```bash
plan-auditor-formalize compile <project>
```

For a named plan:

```bash
plan-auditor-formalize compile <project> --plan <name>
```

The command installs two sealed behavioral checks into one step:

1. `plan-auditor-formal verify ...` — grounded STRIPS reachability,
2. `plan-auditor-formalize verify ...` — deterministic source recompile/equality check.

The compiler creates output-availability preconditions from `requires_outputs`, canonical requirement goals from `covers`, and a source fingerprint over the structured plan while excluding its own generated checks to avoid circular hashing.

Optional external Fast Downward cross-check:

```bash
plan-auditor-formalize compile <project> \
  --fast-downward auto \
  --require-fast-downward
```

### 4. Implement and verify

Run the real checks after each step. A failed check means the step is unfinished. Fix the implementation; do not weaken the proof.

### 5. Seal the complete verification contract

```bash
plan-auditor plan verify <project>
```

The format-v4 seal binds requirements, coverage, DAG/output contracts, verification checks, generated formal checks, source fingerprint, required tools, and supervisor environment/policy state.

The auto-formalizer refuses to mutate a plan once a seal file exists. Formalize first, then seal.

### 6. Run the final integrated audit

```bash
plan-auditor audit <project>
```

PASS requires every active plan to have:

- valid schema and explicit requirement coverage,
- valid dependency/output contracts,
- successful formal reachability when formal planning is present,
- valid requirement-to-formal-goal alignment,
- exact deterministic recompilation match for generated formal contracts,
- intact full-contract seal,
- unchanged sealed environment/policies,
- all behavioral checks verified,
- fresh plan/workspace fingerprints,
- valid evidence chains and registry state,
- required tools present,
- no blocking policy result.

Only exit code 0 means completion is proven.

## Manual formal models

Advanced users may still construct a reviewed domain-specific STRIPS contract and wrap it with:

```bash
plan-auditor-formal make-check formal-contract.json
```

Use manual facts only when they add real domain semantics that cannot be derived from the structured plan. The automatic compiler intentionally refuses to infer such semantics from prose.

## Trust boundary

Plan Auditor verifies completion; it is not an OS sandbox. The deterministic auto-formalizer removes the need to trust an LLM-generated symbolic model for the structural layer, but it cannot prove that arbitrary natural-language domain concepts were perfectly formalized. That last semantic gap is handled conservatively: host-owned requirements and acceptance checks remain authoritative, and unprovable domain semantics must be reviewed rather than guessed.

External HMAC improves tamper detection, but a same-user hostile process that can read the HMAC key is outside that integrity guarantee. See `docs/threat-model.md` and `docs/formal-planning.md`.
