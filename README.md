# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)

**Independent deterministic verification for AI coding-agent plans.**

`plan-auditor` is designed to answer a narrow question reliably:

> Did the AI actually complete the user's requirements and its approved plan, or
> did it only say that it did?

The main agent's narration and persisted `status=verified` labels are not enough.
PASS requires reproducible behavioral checks, explicit requirement coverage, an
intact sealed verification contract, fresh audit evidence, and a valid aggregate
completion gate across **every active plan**.

## Use it directly by skill name

In a skill-capable AI coding environment, call/select the skill simply as:

```text
plan-auditor
```

or give the task in the same invocation:

```text
plan-auditor: implement this change and prove it is complete
```

You should not need to hand-write the internal plan JSON, formal STRIPS contract,
seal metadata, or evidence files. The `plan-auditor` skill is instructed to build
those artifacts, verify them, and run the final audit on your behalf.

For non-trivial multi-step work, the skill now creates a sealed LLM-free
`formal_planning` contract by default, so the plan is checked twice at different
levels:

1. **Classical symbolic planning** — can the declared preconditions/effects reach
   the final goals while respecting dependencies?
2. **Deterministic execution audit** — was the concrete work actually executed
   and proven by real checks?

The built-in classical planner uses only Python/CPU. PDDL export and Fast Downward
are available as an optional independent planner cross-check. See
`docs/formal-planning.md`.

## Core completion model

```text
User requirements
      │
      ▼
Explicit requirement IDs ──► plan steps (`covers`)
      │                         │
      │                         ├─ depends_on
      │                         ├─ outputs
      │                         └─ requires_outputs
      │
      ▼
Sealed STRIPS-style symbolic plan (non-trivial multi-step work)
      │
      ├─ internal classical reachability check
      └─ PDDL / Fast Downward cross-check (optional)
      │
      ▼
Format-v4 full-contract seal
      │
      ▼
Deterministic execution / tests
      │
      ▼
Hash-chained evidence + fresh workspace/plan fingerprint
      │
      ▼
Aggregate supervisor gate
      │
      ├─ default plan PASS
      ├─ named plan A PASS
      ├─ named plan B PASS
      └─ policies / tools / registry / integrity PASS
      │
      ▼
PASS / FAIL / UNKNOWN
```

## What a PASS means

In Supervisor Mode, PASS requires all active plans to satisfy all of the
following:

- valid plan schema,
- explicit non-empty `requirements`,
- every `must`/`should` requirement covered by at least one step,
- at least one behavioral check (`run`, `exec`, `pytest`) per step,
- valid dependency DAG,
- concrete output contract for every explicit dependency edge,
- successful formal reachability when a `formal_planning` anchor is present,
- when formal planning is present, every `must`/`should` requirement is bound to
  a non-initial canonical `requirement-satisfied:<REQ-ID>` goal produced by a
  step that covers the same requirement,
- intact format-v4 seal,
- unchanged sealed supervisor profile/mode/tier/policy fingerprint,
- all steps verified in a fresh full audit,
- current plan contract matches the audited plan fingerprint,
- current workspace content/type/mode matches the audited workspace fingerprint,
- active and archived evidence chains valid,
- agent registry valid,
- required tools present,
- no blocking policy result.

If any active named plan is unfinished, the whole workspace is non-PASS. A
passing `plan.json` cannot hide `.plan-auditor/plans/backend.json`.

## Deterministic checks

Checks run as real subprocesses/filesystem assertions. Structured `argv` is
preferred:

```json
{
  "type": "run",
  "argv": ["python", "-m", "pytest", "tests/", "-q"],
  "expect_exit": 0
}
```

Shell interpretation is disabled by default. Legacy `cmd` strings are parsed into
an argument vector. Shell behavior requires explicit `"shell": true` and cannot
be combined with `argv`.

Verifier output is bounded to avoid unbounded-memory capture.

## Requirements, dependencies, and outputs

Example plan fragment:

```json
{
  "task": "build and consume a verified model artifact",
  "created": "2026-09-05T00:00:00Z",
  "requirements": [
    {"id": "REQ-001", "description": "produce the model artifact", "priority": "must"},
    {"id": "REQ-002", "description": "consume the verified artifact", "priority": "must"}
  ],
  "required_tools": ["python"],
  "steps": [
    {
      "id": 1,
      "title": "produce artifact",
      "depends_on": [],
      "covers": ["REQ-001"],
      "verify": [{"type": "run", "argv": ["python", "tests/build_artifact.py"]}],
      "outputs": [
        {
          "name": "artifact",
          "verify": [{"type": "file_exists", "path": "results/model.json"}]
        }
      ]
    },
    {
      "id": 2,
      "title": "consume artifact",
      "depends_on": [1],
      "requires_outputs": [{"step": 1, "name": "artifact"}],
      "covers": ["REQ-002"],
      "verify": [{"type": "run", "argv": ["python", "tests/use_artifact.py"]}]
    }
  ]
}
```

A downstream step cannot pass until the prerequisite passed and the upstream
output contract is independently rechecked.

## Classical STRIPS/PDDL planning

For non-trivial multi-step plans, `plan-auditor` can embed a symbolic contract
inside one ordinary sealed `run` check. The contract includes:

- initial facts,
- final goal facts,
- one action per Plan Auditor step,
- symbolic preconditions,
- add effects,
- delete effects.

The internal grounded STRIPS-style planner checks whether all steps can execute
while reaching the declared goals. Plans with no delete effects use an efficient
deterministic forward solver; delete-effect plans use bounded state-space search.

For every `must`/`should` requirement `REQ-X`, a formal plan must also include the
canonical goal fact `requirement-satisfied:REQ-X`. That fact cannot be pre-satisfied
in `initial_facts`; it must be produced by a formal action whose Plan Auditor step
covers `REQ-X`. Missing, pre-satisfied, non-covering, and effect-free bindings are
rejected before a formal PASS can contribute to completion.

The canonical check is generated with:

```bash
plan-auditor-formal make-check formal-contract.json
```

Optional PDDL/Fast Downward cross-check:

```bash
plan-auditor-formal make-check formal-contract.json \
  --fast-downward auto \
  --require-fast-downward
```

Because the formal contract is stored inside the normal verification check, its
facts/actions/effects/goals are covered by the existing plan fingerprint and
seal. Changing or removing them after sealing is not a silent escape hatch.

Formal planning proves the declared symbolic model; it does not replace concrete
execution evidence. See `docs/formal-planning.md`.

## Full-contract sealing

```bash
plan-auditor plan verify .
```

The v4 seal binds:

- task and requirements,
- required tools,
- step identity/order/title,
- `covers`,
- dependencies and required outputs,
- outputs and their checks,
- step verification checks,
- embedded formal-planning data when present,
- supervisor `profile`, `mode`, `tier`,
- configured-policy fingerprint.

Existing criteria may be strengthened, but removing/changing sealed criteria or
downgrading the sealed environment blocks completion.

## Evidence integrity

Evidence records are append-only JSONL records with SHA-256 `prev + hash`
continuity. The chain spans log rotations; the active log links the latest archive
tail. Concurrent evidence append/rotation is serialized with an exclusive lock.
Failed-attempt limits are counted across archived and active evidence.

Optional external-key HMAC adds authentication and signed tail checkpoints for:

- active/archive evidence records,
- evidence head,
- agent registry records/head,
- plan seals,
- integrity marker.

Initialize after sealing:

```bash
# set PLAN_AUDITOR_HMAC_KEY or PLAN_AUDITOR_HMAC_KEY_FILE first
plan-auditor plan verify .
plan-auditor integrity init .
plan-auditor audit .
```

A key file must resolve outside the workspace.

## Multi-agent state

The persisted agent registry uses `format_version + seq + prev + hash` and an
anti-truncation head checkpoint. Agent IDs are safe basenames and ownership paths
are canonical workspace-relative paths, so spellings such as
`src/../src/shared.py` and `./src/shared.py` cannot evade conflict detection.

Modes:

- `serial`
- `parallel-warn`
- `parallel-strict`

## Snapshot / rollback

Default snapshots capture the full workspace product state while excluding
`.git`, `.plan-auditor`, and cache metadata. The snapshot manifest stores file
type, mode and hash. Full-scope rollback restores the snapshot and removes files
introduced afterwards. A plan's explicit `snapshot` list deliberately creates a
narrower rollback scope.

## CLI

```text
plan-auditor plan verify <dir> [--plan NAME] [--reseal]
plan-auditor plan inspect <dir> [--plan NAME]
plan-auditor validate <dir> [--plan NAME]
plan-auditor run <dir> [step ids ...] [--plan NAME]
plan-auditor audit <dir> [--plan NAME]
plan-auditor evidence verify <dir>
plan-auditor integrity init|status <dir>
plan-auditor doctor <dir>
plan-auditor task list <dir>
plan-auditor agents list|register|heartbeat|claim|release ...
plan-auditor supervisor start|stop|status ...
plan-auditor-formal make-check <formal-contract.json>
plan-auditor-formal verify <dir> --contract-sha <sha256>
plan-auditor-formal export-pddl <dir> --contract-sha <sha256> --output <dir>
```

With no `--plan`, `plan verify` and the integrated final gate operate across all
active default/named plans.

`doctor` exits nonzero when an active workspace assessment is FAIL/UNKNOWN; JSON
consumers no longer need to detect a hidden failed assessment behind exit code 0.

## Hooks

`hooks/gate_hook.py` is the platform-neutral authoritative gate. It uses the same
aggregate supervisor assessment as the CLI.

`scripts/stop_gate.py` is only a compatibility adapter for hosts whose Stop hook
expects exit code `2`; it delegates to the same integrated gate and no longer
implements status-only verification.

See `docs/integrations.md`.

## Cross-platform packaging gate

GitHub Actions builds a real wheel independently on:

- Ubuntu,
- Windows,
- macOS.

Each job installs the wheel into a clean virtual environment outside the source
checkout and exercises the installed console script through:

- multi-plan discovery,
- explicit DAG/output contracts,
- requirement coverage,
- full-contract sealing,
- external-key HMAC initialization,
- integrated audit,
- doctor PASS,
- evidence/integrity verification.

Release publishing is additionally gated on the same three-platform wheel smoke,
so PyPI publishing cannot race ahead of platform packaging validation.

## Architecture

The supervisor combines deterministic layers for requirements, workspace state,
policy evaluation, plan/DAG validation, BDI-inspired goal state, sealed
STRIPS-style symbolic reachability, Soar-like lifecycle, subsumption authority,
sealing, watchdog observation, evidence integrity, completion gating, and
multi-agent coordination. Optional semantic/adversarial review may propose
stronger deterministic checks but cannot create PASS.

See:

- `docs/architecture.md`
- `docs/dependency-graph.md`
- `docs/formal-planning.md`
- `docs/threat-model.md`
- `references/plan-format.md`

## Trust boundary

Plan Auditor verifies completion; it is not an OS sandbox. Formal planning cannot
repair an incorrect formalization: a planner can prove a wrong symbolic model
correctly. External-key HMAC protects against workspace-only rewriting while the
untrusted process cannot read the key. A deliberately malicious same-user process
that can obtain the key is outside that guarantee. See the threat model for exact
boundaries.

## Version

Current development version: **2.3.0**.

## License

MIT
