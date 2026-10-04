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

Verification runs in a **separate process with its own check implementation**, so the
implementing agent's claims carry no weight — only sealed command output does.

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

Python 3.10 or newer, no third-party runtime dependencies. The npm package is a thin Node
launcher for the same CLI and needs Python on `PATH`. The examples call the interpreter
`python`; on a system that only ships `python3`, use a virtualenv that provides `python`.
In CI, add `- uses: Furox-Art/plan-auditor@main` with `path: .` — see
[integrations](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md).

**Release status:** `2.4.3` is current on both registries. PyPI publishes every artifact
with a PEP 740 provenance attestation; npm has **no** provenance attestation and its
attestations endpoint returns `404` for one. Measured per channel in
[docs/release-status.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/release-status.md).

## Quick start (verified, 5 minutes)

`tests/test_readme_quickstart.py` runs these commands on every CI run and compares the
transcript to real output without normalising hash values, so it cannot drift. Copy the
two files verbatim — `request-source.json` is the input to the `request_sha256` below.

**1. Create the project and the plan.**

```bash
mkdir plan-auditor-demo && cd plan-auditor-demo
mkdir .plan-auditor
```

`.plan-auditor/plan.json`, and `request-source.json` beside it — the host-owned
statement of what you asked for, sealed on activation so the agent cannot restate it:

```json
{
  "task": "Prove README.md exists and prints its first line",
  "created": "2026-07-24T00:00:00",
  "requirements": [{ "id": "REQ-001", "description": "README.md must exist in the project root and print its first line.", "priority": "must" }],
  "steps": [{
    "id": 1, "title": "README.md exists and is readable", "covers": ["REQ-001"], "status": "pending",
    "verify": [
      { "type": "file_exists", "path": "README.md" },
      { "type": "run", "cmd": "python -c \"print(open('README.md', encoding='utf-8').read().strip())\"", "expect_exit": 0 }
    ]
  }]
}
```

```json
{
  "format_version": 1,
  "task": "Prove README.md exists and prints its first line",
  "requirements": [{
    "id": "REQ-001", "description": "README.md must exist in the project root and print its first line.", "priority": "must",
    "acceptance_checks": [
      { "type": "file_exists", "path": "README.md" },
      { "type": "run", "cmd": "python -c \"print(open('README.md', encoding='utf-8').read().strip())\"", "expect_exit": 0 }
    ]
  }]
}
```

**2. Run the gate.**

```bash
plan-auditor request init . --file request-source.json
plan-auditor plan verify .
plan-auditor run . 1
plan-auditor audit .
```

Real output. A lone `...` marks fields omitted for length; every other line is verbatim,
and every JSON level that is not elided lists exactly the keys the tool emits.

```console
$ plan-auditor request init . --file request-source.json
{
  "activated": true,
  "valid": true,
  "reason": "request contract active",
  "request_sha256": "d39e577eb0577d8c0c81231fdd7fc559d1c6045ecc5e5bd3a00e7e8f2f49197b",
  "authenticated": false
}
$ plan-auditor plan verify .
{
  "plans": {
    ...
  },
  "outcome": "PASS"
}
$ plan-auditor run . 1
[OK ] adım 1: README.md exists and is readable (deneme 1/3)
       - geçti | README.md VAR
       - geçti | exit=0 (beklenen 0)
$ plan-auditor audit .
...
{
  "outcome": "PASS",
  "plans": {
    "default": "PASS"
  },
  "deterministic_core": "fresh audit PASS for every active plan under workspace-wide freeze",
  "gate": {
    "outcome": "PASS",
    ...
  }
}
```

Scoped omission: the elided fields are the plan-inspection block and `seal`, the per-step
progress lines and verdict table, and the gate's remaining fields including
`policy_findings`, `verdict` and `seal_ok`. [docs/cli.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md)
shows each command's full output.

`audit` re-runs every check in a fresh subprocess, and only exit code `0` means the work is
proven. Progress lines are Turkish because that is the tool's UI language; the JSON verdict
is the stable machine interface, so parse `"outcome"`.

## How it works

Fifteen layers, arranged so a weaker signal can never overrule a stronger one. Two
facts carry the design: **L10 (`scripts/audit_check.py`) is the only component that can
mark a step `verified`**, and **L13 (`gate.py`) is the only one that emits a final
`PASS`/`FAIL`/`UNKNOWN`**. Everything else feeds those two.

| Band | Layers | Role |
|---|---|---|
| Sense | L0 `events`, L1 `requirements`, L2 `workspace`, L5 `plan_verifier` | Read the task, the tree and the plan |
| Decide | L3 `policies`, L4 `goals`, L7 `priority` | Deterministic rules; subsumption authority |
| Protect | L8 `sealing`, L9 `watchdog`, L11 `evidence`, L12 `adversarial` | Seal, monitor, chain, propose |
| Execute | **L10 `audit_check`**, L6 `lifecycle` | Run real checks; drive the state machine |
| Gate | **L13 `gate`**, L14 `agents` | Emit the verdict; coordinate parallel agents |

A failure at subsumption level N cannot be overridden by a PASS from any higher level.
Per-layer detail, profiles (`light`/`standard`/`strict`), run modes
(`serial`/`parallel-warn`/`parallel-strict`) and LLM tiers (`NO_LLM`, `SMALL_LOCAL`,
`STRONG_LOCAL`, `REMOTE`) are in
[docs/architecture.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/architecture.md).

## Use it as an Agent Skill

The skill is `SKILL.md` plus `scripts/`, `references/` and `hooks/`, either from a
checkout or from a `pip` install, which ships them under `plan_auditor_skill/`. Copy
them into your host's skills directory — `~/.claude/`, `~/.commandcode/`,
`~/.config/opencode/` or `~/.codex/`, each with a `skills/plan-auditor/` subdirectory.
`hooks/gate_hook.py` is the single authoritative hook gate; there are no per-host
adapter files, so wire each host's blocking stop or lifecycle hook to that one command.
Per-host paths and CI wiring:
[docs/integrations.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md).

## Documentation

Reading order starts at [docs/index.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/index.md).

| You want | Go to |
|---|---|
| A verified task end to end; troubleshooting per real error | [quickstart](https://github.com/Furox-Art/plan-auditor/blob/main/docs/quickstart.md) |
| Every subcommand, real invocations, exit codes `0`/`1`/`2`/`3` | [cli](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md) |
| Per-layer detail, profiles, run modes, LLM tiers | [architecture](https://github.com/Furox-Art/plan-auditor/blob/main/docs/architecture.md) |
| What the tool writes into `.plan-auditor/`, and why | [workspace artifacts](https://github.com/Furox-Art/plan-auditor/blob/main/docs/workspace-artifacts.md) |
| Step DAGs, formal planning, threat model, deployment isolation | [dependency graph](https://github.com/Furox-Art/plan-auditor/blob/main/docs/dependency-graph.md) · [formal planning](https://github.com/Furox-Art/plan-auditor/blob/main/docs/formal-planning.md) · [threat model](https://github.com/Furox-Art/plan-auditor/blob/main/docs/threat-model.md) · [deployment isolation](https://github.com/Furox-Art/plan-auditor/blob/main/docs/deployment-isolation.md) |
| Skill hosts, blocking hooks, CI | [integrations](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md) |
| Published versions, defects, attestations; what is measurable | [release status](https://github.com/Furox-Art/plan-auditor/blob/main/docs/release-status.md) · [benchmark](https://github.com/Furox-Art/plan-auditor/blob/main/docs/benchmark.md) |
| Plan schema and check types | [plan-format.md](https://github.com/Furox-Art/plan-auditor/blob/main/references/plan-format.md) |

Entry points: the `plan-auditor` CLI (`request`, `plan`, `evidence`, `integrity`,
`supervisor`, `task`, `agents`, `run`, `validate`, `audit`, `doctor`); the core
`python scripts/audit_check.py` (`validate`, `run`, `audit`, `status`, `snapshot`,
`rollback`); and `plan-auditor-formalize`, `plan-auditor-formal` (`verify`,
`export-pddl`, `make-check`) and `plan-auditor-migrate-seal`.

Check types are `run`, `exec`, `pytest`, `regex` and `file_exists`; `regex` and
`file_exists` are non-behavioural and cannot verify a step alone. Exit codes are `0`
proven, `1` failed, `2` blocked, `3` `UNKNOWN` — and `3` withholds completion rather than
passing it. The npm launcher mirrors them and fails closed. Runnable example:
[`examples/fib/`](https://github.com/Furox-Art/plan-auditor/tree/main/examples/fib).

No rendered documentation site exists yet. `mkdocs build --strict` is a required CI check,
so the Markdown is known to build, but nothing serves it; build it with
`python -m pip install mkdocs-material && mkdocs serve`. Files GitHub already renders:
[SKILL.md](https://github.com/Furox-Art/plan-auditor/blob/main/SKILL.md) ·
[CONTRIBUTING.md](https://github.com/Furox-Art/plan-auditor/blob/main/CONTRIBUTING.md) ·
[CHANGELOG.md](https://github.com/Furox-Art/plan-auditor/blob/main/CHANGELOG.md) ·
[SECURITY.md](https://github.com/Furox-Art/plan-auditor/blob/main/SECURITY.md)

## Honest limits

- **Not an OS sandbox.** In a normal install the agent and the verifier run as the
  same OS user.
- Evidence is **tamper-evident**, not tamper-proof; HMAC integrity is only as strong
  as the secrecy of the key.
- It verifies that *declared, checkable* requirements were met. Domain meaning that
  cannot be a deterministic check is reviewed by a human, not guessed.
- Progress output is Turkish-only; the JSON verdict is the stable interface.
- The npm package needs Python on `PATH` and carries **no** Sigstore build
  attestation: the npm attestations endpoint returns `404` for `2.4.3`. Its
  `dist.signatures` block is a registry transport signature and is **not** build
  provenance, so verify the npm tarball against `dist.integrity` instead.
  PyPI does carry a PEP 740 provenance attestation for every artifact.
- No comparison against other tools has been measured, no telemetry is collected,
  and no download or usage figure is printed anywhere in this repository.
- Maintained by one person, pre-1.0, with no external contributors yet. That means
  slow review, not unwanted contributions.