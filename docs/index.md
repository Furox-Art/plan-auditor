# Plan Auditor documentation

Plan Auditor turns "the agent says it is done" into a checkable fact. A step is
`verified` only when a deterministic check, executed in a fresh subprocess by a
separate process, actually passed — and the result is appended to a hash-chained
evidence log that later audits re-verify.

Nothing on this site requires an LLM, a GPU, or a network connection.

## Start here

| If you want to… | Read |
|---|---|
| See a verified task end to end in five minutes | [Quick start](quickstart.md) |
| Look up a command or exit code | [CLI reference](cli.md) |
| Understand the supervision layers | [Architecture](architecture.md) |
| Understand step DAGs and requirement coverage | [Dependency graph](dependency-graph.md) |
| Understand what is and is not provable | [Formal planning](formal-planning.md) |
| Know the limits before relying on it | [Threat model](threat-model.md) |
| Isolate against a deliberately hostile agent | [Deployment isolation](deployment-isolation.md) |
| Wire it into a host or CI | [Integrations](integrations.md) |
| Know what can actually be measured here | [What is measurable](benchmark.md) |
| Contribute a check type or fix a doc | [Contributing guide](https://github.com/Furox-Art/plan-auditor/blob/main/CONTRIBUTING.md) |

## The five rules

1. **No deterministic evidence, no completion.** Every step needs at least one
   `run`, `pytest`, or `exec` check.
2. **Requirements are host-owned.** The request contract is sealed before work
   starts; the agent cannot rewrite what you asked for.
3. **Evidence is append-only and hash-chained.** `plan-auditor evidence verify`
   re-checks the chain, including rotated archives.
4. **Sealed criteria only tighten.** Post-approval, criteria may be added but
   never removed or weakened.
5. **Unprovable is a failure, not a pass.** Unknown resolves to `FAIL` or
   `UNKNOWN`, never to success.

## Concepts in one paragraph each

**Request contract** — A JSON document you write that states the task and its
requirements with deterministic acceptance checks. Activating it computes a
digest; the supervisor refuses to pass a plan whose requirements drifted from it.

**Plan** — `.plan-auditor/plan.json` (plus any `.plan-auditor/plans/<name>.json`).
Requirements, steps, `covers` bindings, dependencies, named outputs, and `verify`
checks. Every active plan must pass; a passing default plan cannot hide an
unfinished named plan.

**Seal** — A hash over the full verification contract: requirements, coverage,
the dependency DAG, output contracts, every check, and the supervisor
profile/mode/policy fingerprint. `plan verify` creates it; later audits detect any
attempt to weaken it.

**Evidence** — An append-only JSONL log where every record carries the SHA-256 of
the previous one. Tampering with a past record breaks the chain.

**Fresh full audit** — `plan-auditor audit` re-runs every check in a new
subprocess while the workspace is frozen, and fails if the workspace changed
during the run. It is the only command whose exit code `0` means "complete".

## The 30-second mental model

```text
you (host)                agent                    supervisor (separate process)
    |                        |                              |
    |-- request-source.json ->|                              |
    |-- plan.json ----------->|-- implements step ----------->|
    |                        |-- "done!" ---------> run checks in fresh subprocess
    |                        |                              |--> append hashed evidence
    |                        |<-- non-zero until proven -----|
    |                        |                              |
    |<---------------- audit . (exit 0) --------------------|
```

## Scope and non-goals

Plan Auditor is **not** an OS sandbox and does not claim kernel isolation; in a
default install the agent and the verifier run as the same OS user. It is
*tamper-evident*, not tamper-proof. See [Threat model](threat-model.md) and
[Deployment isolation](deployment-isolation.md) for the boundary and for what to
change when the agent is assumed hostile.