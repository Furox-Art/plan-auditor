# `plan.json` format — v2.1

Default plan: `<project>/.plan-auditor/plan.json`  
Named plans: `<project>/.plan-auditor/plans/<safe-name>.json`

Named plan identifiers are basenames only and must match
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. Path separators and traversal such as
`../` are rejected.

## Top-level fields

| Field | Type | Supervisor PASS | Meaning |
|---|---|---:|---|
| `task` | string | required | Exact task statement |
| `created` | string | required | Creation timestamp |
| `requirements` | list | **required** | Explicit acceptance requirements |
| `required_tools` | list[string] | optional | Executables that must be available at final gate |
| `steps` | list | required | Machine-verifiable implementation plan |
| `snapshot` | list[string] | optional | Explicit rollback scope; absent means full-workspace snapshot scope |

### Requirements

Supervisor Mode requires explicit requirement coverage. Recommended form:

```json
{
  "id": "REQ-001",
  "description": "Passwords are stored using the required password-hashing behavior",
  "priority": "must"
}
```

Priorities: `must`, `should`, `may`. Every `must` and `should` requirement must
be referenced by at least one step's `covers` field. Unknown, duplicated, or
uncovered requirement IDs prevent Supervisor PASS.

## Step fields

| Field | Type | Meaning |
|---|---|---|
| `id` | positive int | Unique step ID |
| `title` | string | Stable step title |
| `covers` | list[string] | Requirement IDs proved by this step |
| `depends_on` | list[int] | Direct prerequisite step IDs |
| `requires_outputs` | list[object] | Concrete outputs required from prerequisite steps |
| `outputs` | list[object] | Named output contracts produced by the step |
| `verify` | list[check] | Step-level deterministic checks |
| `status` | string | Runtime field written by the auditor |

If no step declares `depends_on`, legacy plans use strict sequential semantics.
Once any step declares it, the plan is an explicit DAG. Every explicit dependency
edge must be backed by at least one `requires_outputs` reference to a declared
upstream output; this prevents dependency edges that have no concrete evidence.

Example:

```json
{
  "id": 2,
  "title": "consume fitted parameters",
  "depends_on": [1],
  "requires_outputs": [{"step": 1, "name": "fit-parameters"}],
  "covers": ["REQ-002"],
  "verify": [
    {"type": "run", "argv": ["python", "tests/check_consumer.py"]}
  ]
}
```

Upstream output:

```json
{
  "name": "fit-parameters",
  "verify": [
    {"type": "file_exists", "path": "results/fit.json"},
    {"type": "regex", "path": "results/fit.json", "pattern": "\\\"parameters\\\""}
  ]
}
```

The downstream step cannot pass until the upstream step passed in the current
full audit and the required output contract is independently rechecked.

## Verification checks

| Type | Important fields | Meaning |
|---|---|---|
| `run` | `argv` or `cmd`, `expect_exit`, `output_regex`, `timeout`, `max_output_bytes` | Execute a real command |
| `exec` | same as `run` | Polyglot/compiled external checker; normalized to `run` |
| `pytest` | `args` | `python -m pytest ...`, normalized to `run` |
| `file_exists` | `path` | Workspace-confined regular file must exist |
| `regex` | `path`, `pattern` | Workspace-confined file content must match regex |

Every step must contain at least one **behavioral** check (`run`, `exec`, or
`pytest`). `file_exists`/`regex` alone cannot verify a step.

### Command execution safety

Structured `argv` is preferred and is the most portable form:

```json
{
  "type": "run",
  "argv": ["python", "-m", "pytest", "tests/", "-q"],
  "expect_exit": 0
}
```

Shell interpretation is **disabled by default**. Legacy `cmd` strings are parsed
into an argument vector and executed directly. Operators such as `>`, `&&`,
pipes, glob expansion, and environment-variable expansion are inert unless the
check explicitly opts into the shell:

```json
{"type": "run", "cmd": "tool-a | tool-b", "shell": true}
```

`"shell": true` is an explicit trust-boundary opt-in and cannot be combined with
`argv`. Generated plans should use `argv` whenever possible.

Command output is bounded by default so a verifier cannot exhaust memory merely
by printing unbounded output. `max_output_bytes` can be set within the supported
limit when a check legitimately needs more output.

## Full-contract sealing

`plan-auditor plan verify .` creates a format-v3 seal. It binds:

- task and requirements,
- required tools,
- step identity and order,
- titles,
- requirement coverage,
- dependencies and required outputs,
- output contracts and their checks,
- step verification checks,
- supervisor `profile`, `mode`, `tier`, and configured-policy fingerprint.

After sealing, existing criteria may be strengthened but not removed or changed.
A profile/policy downgrade is a seal violation. When external HMAC integrity is
initialized, plan seals are authenticated as well as evidence and agent-registry
state.

## Evidence and final gate

A full audit writes per-step evidence and an `audit_complete` marker bound to:

- the full plan-contract fingerprint,
- the current workspace content/type/mode fingerprint,
- dependency order and output evidence.

Evidence is hash-chained across rotations, optional external-key HMAC protects
records and signed tail checkpoints, and concurrent append operations are
serialized by the auditor.

Supervisor PASS requires **every active default/named plan** to pass. A named
plan cannot be hidden by a passing default plan.

Recommended final sequence:

```bash
plan-auditor plan verify .
plan-auditor audit .
```

For authenticated integrity, seal first, then initialize the external-key state:

```bash
plan-auditor plan verify .
plan-auditor integrity init .
plan-auditor audit .
```
