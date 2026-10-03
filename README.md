# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)
[![release](https://github.com/Furox-Art/plan-auditor/actions/workflows/release.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/release.yml)
[![PyPI](https://img.shields.io/pypi/v/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![Python](https://img.shields.io/pypi/pyversions/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![npm](https://img.shields.io/npm/v/plan-auditor)](https://www.npmjs.com/package/plan-auditor)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Download numbers live on the package pages themselves, where they are always current:
[PyPI](https://pypi.org/project/plan-auditor/) |
[npm](https://www.npmjs.com/package/plan-auditor)

**An AI agent says "done." This tool makes "done" mean "here is the command output that proves it."**

## The problem

Ask a coding agent to change something and it reports success with confident prose.
Sometimes it never ran the tests. Sometimes it ran them once, failed, and edited the
test until it went green. What you are left with is narration, and narration looks
identical to a result until you re-run everything yourself.

## The solution

Verification runs in a **separate process with its own check implementation**. The
implementing agent's claims carry no weight; only sealed command output does.

- Every step is a machine-checkable requirement, not a prose bullet.
- Every step needs at least one **behavioral** check (`run`, `pytest`, `exec`). A
  file-existence check can never verify a step on its own.
- Output is appended to a SHA-256 hash-chained, tamper-evident log.
- The plan's verification contract is **sealed** on approval and can only be
  strengthened afterwards, never weakened.
- A failed check fails closed: `audit` exits non-zero until every check really passes.

There is no LLM in the verification path, and no network call.

## Who it is for

- Anyone who ships AI-generated code and needs receipts before merge.
- Agent-skill authors who want a gate an agent cannot talk its way past.
- Teams adding a required CI step for "the agent must prove it".
- Researchers who want LLM-free STRIPS/PDDL-style reachability checks over a plan.

## Install

```bash
pipx install plan-auditor          # isolated CLI, recommended
pip install plan-auditor           # into the current environment / virtualenv
```

Python 3.10 or newer, no third-party runtime dependencies. The npm package is a
thin Node launcher for the same CLI and needs Python on `PATH`; prefer `pipx`
unless you already manage Node tooling.

The examples invoke the interpreter as `python`. On a system that only ships
`python3`, activate a virtualenv that provides `python` or change the plan's `cmd`
to `python3`.

**Release status:** `2.4.2` is current on both registries. npm has no provenance
attestation and returns `404` for one; PyPI publishes with a PEP 740 attestation.
The full check, including which older versions were defective, is in
[docs/release-status.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/release-status.md).

## Quick start (verified, 5 minutes)

Every hash, key and output line below is re-derived by
`tests/test_readme_quickstart.py` on each CI run, which executes these commands and
compares the transcript against real output without normalising hash values. A
throwaway directory keeps the walkthrough self-contained.

**1. Create the project and the plan.**

```bash
mkdir plan-auditor-demo && cd plan-auditor-demo
mkdir .plan-auditor
```

`.plan-auditor/plan.json`:

```json
{
  "task": "Prove that README.md exists in this scratch project",
  "created": "2026-07-24T00:00:00",
  "requirements": [
    { "id": "REQ-001", "description": "README.md must exist in the project root and print its first line.", "priority": "must" }
  ],
  "steps": [
    {
      "id": 1,
      "title": "README.md exists and is readable",
      "covers": ["REQ-001"],
      "verify": [
        { "type": "file_exists", "path": "README.md" },
        { "type": "run", "cmd": "python -c \"print(open('README.md', encoding='utf-8').read().strip())\"", "expect_exit": 0 }
      ],
      "status": "pending"
    }
  ]
}
```

`request-source.json` — the host-owned statement of what you actually asked for. It
is sealed on activation, so the agent cannot restate your requirements later. This
file is the input to the `request_sha256` below, so copy it exactly:

```json
{
  "format_version": 1,
  "task": "Prove that README.md exists in this scratch project",
  "requirements": [
    {
      "id": "REQ-001",
      "description": "README.md must exist in the project root and print its first line.",
      "priority": "must",
      "acceptance_checks": [
        { "type": "file_exists", "path": "README.md" },
        { "type": "run", "cmd": "python -c \"print(open('README.md', encoding='utf-8').read().strip())\"", "expect_exit": 0 }
      ]
    }
  ]
}
```

**2. Run the gate.**

```bash
plan-auditor request init . --file request-source.json
plan-auditor plan verify .
plan-auditor run . 1
plan-auditor audit .
```

Real output. A lone `...` marks fields omitted for length; every other line is
verbatim, and the omission note below says exactly what is elided.

```console
$ plan-auditor request init . --file request-source.json
{
  "activated": true,
  "valid": true,
  "reason": "request contract active",
  "request_sha256": "d7d47e409fc1c53b9830346740bac2a20e716aefc71e7396ad3db0ebbdd837f2",
  "authenticated": false
}
$ plan-auditor plan verify .
{
  "plans": {
    "default": {
      "verdict": "PASS",
      ...
      "seal": {
        "status": "sealed",
        ...
      }
    }
  },
  "outcome": "PASS"
}
$ plan-auditor run . 1
[OK ] adım 1: README.md exists and is readable (deneme 1/3)
       - geçti | README.md VAR
       - geçti | exit=0 (beklenen 0)
$ plan-auditor audit .
TAM DENETİM: tüm adımlar taze subprocess ile yeniden test ediliyor...
...
SONUÇ: audit GEÇTİ — tüm adımlar kanıtlı.
{
  "outcome": "PASS",
  "plans": {
    "default": "PASS"
  },
  "deterministic_core": "fresh audit PASS for every active plan under workspace-wide freeze",
  "gate": {
    "outcome": "PASS",
    "deterministic_passed": true,
    "pending_steps": [],
    ...
    "seal_ok": true,
    "seal_violations": [],
    "adversarial_findings": [],
    "notes": []
  }
}
```

Scoped omission: the elided `...` fields are the plan-inspection block
(`rationale`, `weakest_verification`, `graph_errors`, `coverage`,
`topological_order`, `dependencies`), the rest of `seal` including `plan_hash`
and `environment`, the per-step progress lines and verdict table, and the gate's
`policy_findings` and `verdict`. Every line shown is verbatim and in order, and
every JSON level that is not elided documents exactly the keys the tool emits.

`audit` re-runs every check in a fresh subprocess. Only exit code `0` means the work
is proven. The progress lines are Turkish because that is the tool's UI language;
the JSON verdict is the stable machine interface, so parse `"outcome"`.

## How it works: 15 supervision layers

Verification is layered so that a weaker signal can never overrule a stronger one.
L10 is the only component that can mark a step `verified`; L13 is the only one that
emits a final `PASS`/`FAIL`/`UNKNOWN`.

| Layer | Module | Single responsibility |
|---|---|---|
| L0 | `events.py` | Detect patterns, route and trigger |
| L1 | `requirements.py` | Task to structured requirements |
| L2 | `workspace.py` | Structured repo/workspace state |
| L3 | `policies.py` | Deterministic IF/THEN rules, fail-closed |
| L4 | `goals.py` | Beliefs / desires / intention state |
| L5 | `plan_verifier.py` | Preconditions, effects, coverage, contradictions |
| L6 | `lifecycle.py` | Task state machine and operators |
| L7 | `priority.py` | Subsumption authority resolver |
| L8 | `sealing.py` | Canonical plan hash and monotonic diff |
| L9 | `watchdog.py` | fs / git / build / test / agent heartbeat monitor |
| L10 | `scripts/audit_check.py` | Real checks via fresh subprocess — **the only source of `verified`** |
| L11 | `evidence.py` | Cross-archive anchored, tamper-evident chain |
| L12 | `adversarial.py` | Optional semantic review proposing candidate checks |
| L13 | `gate.py` | Aggregate every layer into PASS / FAIL / UNKNOWN |
| L14 | `agents.py` | Parallel agents, file ownership, conflict detection, locking |

A failure at subsumption level N cannot be overridden by a PASS from any higher
level. Profiles are `light`/`standard`/`strict`, run modes are
`serial`/`parallel-warn`/`parallel-strict`, and LLM tiers are `NO_LLM`,
`SMALL_LOCAL`, `STRONG_LOCAL`, `REMOTE`. Full detail in
[docs/architecture.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/architecture.md).

## Command surface

| Command | Purpose |
|---|---|
| `request init` / `request status` | Activate and inspect the host-owned request contract |
| `plan verify` / `plan inspect` | Seal the full contract; show structure, coverage, seal |
| `run` / `validate` | Execute step checks; validate the plan schema |
| `audit` | Integrated final gate across every active plan |
| `evidence verify` | Re-verify the active and archived evidence chains |
| `integrity init` / `integrity status` | Create and report external HMAC integrity material |
| `supervisor start` / `stop` / `status` | Background supervisor lifecycle |
| `task list` / `task inspect` | Plans as supervisor tasks |
| `agents list` / `register` / `heartbeat` / `claim` / `release` | Multi-agent registry and file ownership |
| `doctor` | Machine-readable health and capability report |
| `plan-auditor-formalize compile` | Derive a grounded STRIPS contract from structured primitives |
| `plan-auditor-formal verify` / `export-pddl` / `make-check` | Verify, export to PDDL, wrap a contract in a sealed check |
| `plan-auditor-migrate-seal` | Representation-only seal migration |
| `python scripts/audit_check.py` | The core directly: `validate`, `run`, `audit`, `status`, `snapshot`, `rollback` |

Check types are `run`, `exec`, `pytest`, `regex` and `file_exists`; the last two are
non-behavioural and cannot verify a step alone. Plan schema is documented in
[references/plan-format.md](https://github.com/Furox-Art/plan-auditor/blob/main/references/plan-format.md)
and every command in
[docs/cli.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md).

## What it writes to your workspace

Everything lives under `.plan-auditor/` in the project you are auditing. Nothing is
written outside it.

| File | What it is |
|---|---|
| `plan.json` | Your plan. You write this; the tool rewrites step `status`. |
| `request.json`, `activation.json` | The activated request contract and its digest |
| `seal.json` | The seal over the whole verification contract |
| `evidence.jsonl`, `evidence.head.json` | Append-only hash-chained evidence and its head pointer |
| `agents/registry.jsonl`, `registry.head.json`, `registry.write.lock` | Multi-agent registry, head and lock |
| `watchdog.jsonl` | Heartbeat and filesystem events |
| `supervisor.json`, `supervisor.log`, `supervisor-runtime.json`, `supervisor-assessment.json` | Supervisor config, log, runtime state, persisted assessment |
| `integrity.json` | External HMAC integrity marker |
| `facts.json` | Generated STRIPS facts from `plan-auditor-formalize` |
| `*.tmp`, `archive/`, `seals/`, `snapshots/`, `*.lock`, `supervisor.stop` | Scratch, rotated history and locks |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Proven. Only `audit` treats this as "complete". |
| `1` | Failed: a check did not pass, or a gate requirement was not met. |
| `2` | Blocked or refused: attempt budget exhausted, seal violated, tampered evidence. |
| `3` | `UNKNOWN`: the assessment could not be determined, so it did not pass either. |

The npm launcher mirrors these and fails closed if Python cannot start.

## Use it as an Agent Skill

The skill is `SKILL.md` plus `scripts/`, `references/` and `hooks/`. From a
checkout, or from a `pip` install, which ships them under `plan_auditor_skill/`:

```bash
git clone https://github.com/Furox-Art/plan-auditor.git
cp -r plan-auditor/SKILL.md plan-auditor/scripts plan-auditor/references plan-auditor/hooks \
      ~/.config/opencode/skills/plan-auditor/
```

| Host | User-level path | Project-level path | Invoke |
|---|---|---|---|
| Claude Code | `~/.claude/skills/plan-auditor/` | `.claude/skills/plan-auditor/` | `/plan-auditor` |
| Command Code | `~/.commandcode/skills/plan-auditor/` | `.commandcode/skills/plan-auditor/` | `/plan-auditor` |
| OpenCode | `~/.config/opencode/skills/plan-auditor/` | `.opencode/skills/plan-auditor/` | `/plan-auditor` |
| Codex CLI | `~/.codex/skills/plan-auditor/` | `.codex/skills/plan-auditor/` | `$plan-auditor` |

Restart the host if it only discovers skills at startup. `hooks/gate_hook.py` is the
single authoritative hook gate — there are no per-host adapter files; wire each
host's blocking stop or lifecycle hook to that one command. See
[docs/integrations.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md).

## Use it in CI

```yaml
- uses: Furox-Art/plan-auditor@main
  with:
    path: .
```

## Documentation

Canonical entry point:
<https://github.com/Furox-Art/plan-auditor/blob/main/docs/index.md>

| Document | Covers |
|---|---|
| [docs/quickstart.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/quickstart.md) | First verified task, and a troubleshooting entry per real error message |
| [docs/cli.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md) | Every subcommand with real invocations and exit codes |
| [docs/architecture.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/architecture.md) | The layer model, subsumption order, profiles and tiers |
| [docs/dependency-graph.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/dependency-graph.md) | Step DAGs, output contracts, requirement coverage |
| [docs/formal-planning.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/formal-planning.md) | LLM-free STRIPS reachability and PDDL export |
| [docs/threat-model.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/threat-model.md) | Trust boundary and what is explicitly *not* guaranteed |
| [docs/deployment-isolation.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/deployment-isolation.md) | Running against a deliberately hostile agent |
| [docs/integrations.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md) | Skill hosts, blocking hooks, CI |
| [docs/release-status.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/release-status.md) | What is published where, defects, and attestations |
| [docs/benchmark.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/benchmark.md) | What is measurable, what is not, and where each number comes from |
| [CONTRIBUTING.md](https://github.com/Furox-Art/plan-auditor/blob/main/CONTRIBUTING.md) | Tests, the ratchet gates, the release procedure |
| [CHANGELOG.md](https://github.com/Furox-Art/plan-auditor/blob/main/CHANGELOG.md) · [SECURITY.md](https://github.com/Furox-Art/plan-auditor/blob/main/SECURITY.md) | History; how to report a vulnerability |

Runnable example: [`examples/fib/`](https://github.com/Furox-Art/plan-auditor/tree/main/examples/fib)
is a complete two-step plan whose second step is a real pytest run.
[docs/benchmark.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/benchmark.md)
shows how to break the implementation yourself and watch the gate refuse to pass.

There is no rendered documentation site yet. `mkdocs build --strict` is a required
CI check, so the Markdown is known to build, but nothing serves it. Build it
yourself with `python -m pip install mkdocs-material && mkdocs serve`.

## Honest limits

- **Not an OS sandbox.** In a normal install the agent and the verifier run as the
  same OS user.
- Evidence is **tamper-evident**, not tamper-proof; HMAC integrity is only as strong
  as the secrecy of the key.
- It verifies that *declared, checkable* requirements were met. Domain meaning that
  cannot be a deterministic check is reviewed by a human, not guessed.
- Progress output is Turkish-only; the JSON verdict is the stable interface.
- The npm package needs Python on `PATH` and ships no Sigstore attestation, unlike
  the PyPI release.
- No comparison against other tools has been measured, no telemetry is collected,
  and no download or usage figure is printed anywhere in this repository.
- Maintained by one person, pre-1.0, with no external contributors yet. That means
  slow review, not unwanted contributions.
