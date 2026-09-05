# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)

**Independent deterministic verification for AI coding-agent work.**

`plan-auditor` answers one question:

> Did the AI actually complete the user's requirements and approved plan, or did it only say that it did?

PASS is not based on the agent's narration. It requires explicit requirements, real behavioral checks, dependency/output proof, formal plan validation when enabled, an intact seal, fresh execution evidence, and an aggregate gate across every active plan.

## Use it directly by skill name

In a skill-capable coding environment, call:

```text
plan-auditor
```

or:

```text
plan-auditor: implement this change and prove it is complete
```

The normal skill workflow handles the internal plan, automatic formalization, sealing, evidence, and final audit. The user does not need to hand-write STRIPS/PDDL or auditor metadata.

## Automatic formalization

For non-trivial multi-step work, Plan Auditor can now compile the structured plan into a conservative STRIPS contract automatically:

```bash
plan-auditor-formalize compile .
```

The compiler does **not** ask an LLM to invent symbolic semantics. It derives only from explicit Plan Auditor structure:

- `must` / `should` requirement IDs,
- step `covers` bindings,
- `depends_on`,
- named `outputs`,
- `requires_outputs`,
- deterministic verification checks.

Generated facts are limited to:

```text
formalization-source:<SHA256>
step-completed:<STEP-ID>
output-available:<STEP-ID>:...
requirement-satisfied:<REQ-ID>
```

A generated contract is checked twice:

1. **STRIPS reachability** — `plan-auditor-formal verify` proves the symbolic plan can reach all goals while respecting dependencies and dataflow.
2. **Independent deterministic recompilation** — `plan-auditor-formalize verify` rebuilds the expected contract from the current structured plan and requires exact equality.

This blocks a generated formal model from silently omitting a requirement, dropping an output precondition, weakening a goal, or becoming stale after the plan changes—even if someone recomputes the contract SHA.

Manual domain-specific STRIPS contracts remain supported and are never overwritten by the automatic compiler.

## Completion model

```text
Host-owned request + acceptance checks
        |
        v
Explicit requirements + covers
        |
        v
Dependency / output dataflow DAG
        |
        v
Deterministic auto-formalizer
        |
        +--> source SHA-256
        +--> requirement goals
        +--> output facts / preconditions
        +--> one action per step
        |
        v
Independent deterministic recompilation
        |
        v
Grounded STRIPS reachability
        |
        +--> PDDL / Fast Downward (optional)
        |
        v
Format-v4 sealed verification contract
        |
        v
Real subprocess/filesystem checks
        |
        v
Hash-chained fresh evidence
        |
        v
Aggregate supervisor gate
        |
        v
PASS / FAIL / UNKNOWN
```

## What PASS requires

In Supervisor Mode, every active plan must satisfy the full contract, including:

- valid plan schema,
- explicit non-empty requirements,
- complete `must`/`should` coverage,
- real behavioral verification for every step,
- valid dependency DAG,
- concrete `requires_outputs` backing for explicit dependency edges,
- successful formal reachability when a formal anchor is present,
- canonical requirement-to-formal-goal binding,
- exact deterministic recompilation for auto-generated formal contracts,
- intact format-v4 seal,
- unchanged sealed supervisor environment/policies,
- fresh full-audit plan/workspace fingerprints,
- valid active and archived evidence chains,
- valid agent registry,
- required tools present,
- no blocking policy result.

A passing default plan cannot hide an unfinished named plan.

## Example structured plan

```json
{
  "task": "build and consume a verified artifact",
  "created": "2026-09-06T00:00:00Z",
  "requirements": [
    {"id": "REQ-001", "description": "produce the artifact", "priority": "must"},
    {"id": "REQ-002", "description": "consume the artifact", "priority": "must"}
  ],
  "steps": [
    {
      "id": 1,
      "title": "produce",
      "depends_on": [],
      "covers": ["REQ-001"],
      "verify": [{"type": "run", "argv": ["python", "tests/build.py"]}],
      "outputs": [
        {
          "name": "artifact",
          "verify": [{"type": "file_exists", "path": "result.json"}]
        }
      ]
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

Then:

```bash
plan-auditor validate .
plan-auditor-formalize compile .
plan-auditor plan verify .
plan-auditor audit .
```

The auto-formalizer runs **before** sealing and refuses to mutate an already sealed plan.

## Classical STRIPS / PDDL

The built-in grounded STRIPS-style planner is local and CPU-only.

- no-delete contracts use deterministic forward reasoning,
- delete-effect contracts use bounded state-space search,
- state-limit exhaustion returns UNKNOWN/REVISE rather than PASS,
- every Plan Auditor step must execute exactly once in the formal solution.

PDDL export:

```bash
plan-auditor-formal export-pddl . \
  --contract-sha <sha256> \
  --output ./pddl-proof
```

Optional Fast Downward cross-check can be embedded during automatic compilation:

```bash
plan-auditor-formalize compile . \
  --fast-downward auto \
  --require-fast-downward
```

For reviewed domain-specific models, manual contracts can still be wrapped with:

```bash
plan-auditor-formal make-check formal-contract.json
```

See `docs/formal-planning.md`.

## Deterministic checks

Prefer structured argv:

```json
{
  "type": "run",
  "argv": ["python", "-m", "pytest", "tests/", "-q"],
  "expect_exit": 0
}
```

Shell interpretation is disabled by default. `"shell": true` is an explicit trust-boundary opt-in. Verifier output is bounded.

## Sealing and evidence

Seal the complete verification contract with:

```bash
plan-auditor plan verify .
```

The v4 seal binds requirements, coverage, tools, step identity, checks, dependencies, outputs, generated/manual formal-planning data, and supervisor environment/policy fingerprints.

Evidence is append-only JSONL with SHA-256 chain continuity across rotations. Optional external-key HMAC authenticates evidence, checkpoints, registry state, seals, and integrity metadata.

```bash
# set PLAN_AUDITOR_HMAC_KEY or PLAN_AUDITOR_HMAC_KEY_FILE first
plan-auditor integrity init .
plan-auditor audit .
```

The key file must resolve outside the workspace.

## Multi-plan and multi-agent state

Default plan:

```text
.plan-auditor/plan.json
```

Named plans:

```text
.plan-auditor/plans/<name>.json
```

The aggregate gate includes every active plan.

Agent registry modes:

- `serial`
- `parallel-warn`
- `parallel-strict`

Ownership paths are canonicalized to prevent alternate-path conflict bypasses.

## Snapshot / rollback

Default snapshots capture product state while excluding `.git`, `.plan-auditor`, and cache metadata. Manifests include file type, mode, and hash. Full-scope rollback restores the snapshot and removes files introduced afterwards.

## CLI

```text
plan-auditor validate <dir> [--plan NAME]
plan-auditor plan verify <dir> [--plan NAME] [--reseal]
plan-auditor plan inspect <dir> [--plan NAME]
plan-auditor run <dir> [step ids ...] [--plan NAME]
plan-auditor audit <dir> [--plan NAME]
plan-auditor evidence verify <dir>
plan-auditor integrity init|status <dir>
plan-auditor doctor <dir>
plan-auditor task list <dir>
plan-auditor agents list|register|heartbeat|claim|release ...
plan-auditor supervisor start|stop|status ...

plan-auditor-formalize compile <dir> [--plan NAME]
plan-auditor-formalize verify <dir> --contract-sha <sha256>

plan-auditor-formal make-check <formal-contract.json>
plan-auditor-formal verify <dir> --contract-sha <sha256>
plan-auditor-formal export-pddl <dir> --contract-sha <sha256> --output <dir>
```

## Cross-platform packaging

CI builds and installs real wheels in clean environments on:

- Ubuntu,
- Windows,
- macOS.

Python compatibility is tested on 3.10, 3.11, 3.12, and 3.13.

## Architecture

The project combines deterministic requirement alignment, workspace observation, rule/policy evaluation, explicit plan DAGs, BDI-inspired goal state, grounded STRIPS planning, Soar-like lifecycle control, subsumption-inspired authority, cryptographic sealing, evidence integrity, watchdog supervision, and multi-agent coordination.

See:

- `docs/architecture.md`
- `docs/dependency-graph.md`
- `docs/formal-planning.md`
- `docs/threat-model.md`
- `references/plan-format.md`

## Trust boundary

Plan Auditor verifies completion; it is not an OS sandbox.

Automatic formalization removes the need to trust an LLM-generated symbolic model for the structural layer, but it does not claim perfect arbitrary natural-language theorem formalization. The host-owned request and deterministic acceptance checks remain authoritative. Domain semantics that cannot be derived mechanically should be reviewed explicitly rather than guessed.

A malicious same-OS-user process that can read external integrity key material remains outside the local integrity guarantee; use a separate OS account, container, or VM when that attacker is in scope.

## Version

Latest stable release: **2.4.0**  
Current source version: **2.4.0**

## License

MIT
