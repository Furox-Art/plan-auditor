# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)

**An independent, multi-layered verification supervisor for AI coding agents.**

AI coding agents routinely leave work half-done or claim "done" when it
isn't. Root cause: no explicit, machine-checkable plan, and nobody
verifying the claims. `plan-auditor` fixes both — and goes further: it
runs **independently** of the main AI, seals plan criteria against
weakening, watches execution in real time, and refuses to count
unverified work as done. It supports **parallel / concurrent agents**.

---

## Two modes

| Mode | What it is | How you use it |
|---|---|---|
| **Skill Mode** | The original Agent Skill (unchanged v1.1 behavior). Copy the folder; the agent follows `SKILL.md`. | Copy to your tool's skills directory. |
| **Supervisor Mode** | The new layered verification daemon. Independent process, 14 layers, parallel-agent aware. | `plan-auditor supervisor start --profile standard` then `plan-auditor audit <dir>`. |

---

## Architecture

```
User Task
   │
   ▼
Main AI Agent ──────────────► proposes plan
   │                              │
   │                              ▼
   │                 ┌──────────────────────────────┐
   └───────────────► │  Independent Supervisor       │
                     │  (separate process / daemon)  │
                     └──────────────┬───────────────┘
                                    │
              ┌─────────────────────┼──────────────────────────┐
              ▼                     ▼                          ▼
     L0 Event Layer        L1 Requirements           L5 STRIPS-like
     (pattern detect)      (structured reqs)         Plan Verifier
              │                     │                          │
              ▼                     ▼                          ▼
     L2 World Model        L3 Policy Engine          L9 Watchdog
     (workspace state)     (deterministic rules)     (runtime observe)
              │                     │                          │
              └─────────────────────┼──────────────────────────┘
                                    ▼
                     L10 Deterministic Core (audit_check.py)
                                    │
                                    ▼
                     L8 Sealing + Monotonic Verification
                                    │
                                    ▼
                     L13 Completion Gate ──► PASS / FAIL / UNKNOWN
                                    │
                                    ▼
                     L12 Adversarial AI (optional semantic review)
```

See [`docs/architecture.md`](docs/architecture.md) for the full data flow
and layer responsibilities.

---

## Layers

| Layer | Responsibility | LLM? |
|---|---|---|
| **L0** Event / pattern detection — ELIZA-like. Detects "done", config changes, repeated failures, security signals. Only triggers; never judges. | no |
| **L1** Requirement interpretation — structured requirements with acceptance criteria and ambiguity flags. | optional |
| **L2** Workspace / world model — SHRDLU-inspired structured repo state (git, files, tools, agents). | no |
| **L3** Policy engine — MYCIN/expert-system IF/THEN rules, fail-closed, testable. | no |
| **L4** BDI goal model — Beliefs/Desires/Intention state container driving audit order. | no |
| **L5** STRIPS-like plan verifier — preconditions/effects/coverage/contradiction analysis. | optional |
| **L6** Soar-like lifecycle — task state machine (NEW → … → PASSED/FAILED/UNKNOWN). | no |
| **L7** Subsumption priority — lower safety layers **override** higher AI judgment. | no |
| **L8** Plan sealing + monotonic verification — criteria can only tighten, never weaken. | no |
| **L9** Execution watchdog — fs/git/build/test monitoring, best-effort per platform. | no |
| **L10** Deterministic core — real checks via fresh subprocess (pytest, build, lint, exit codes). **Only** source of `verified`. | no |
| **L11** Evidence / integrity — cross-archive anchored, tamper-evident chain. | no |
| **L12** Adversarial AI — optional second-pass semantic review; proposes new deterministic checks only. | optional |
| **L13** Completion gate — **only** component that emits PASS/FAIL/UNKNOWN. | no |
| **L14** Multi-agent orchestrator — parallel agents, file ownership, conflict detection, locking. | no |

### Subsumption priority (authoritative)

```
LEVEL 0  process / system safety        (supervisor alive, no deadlocks)
LEVEL 1  plan integrity                 (seal unchanged, monotonic)
LEVEL 2  deterministic verification     (L10 core, real checks)
LEVEL 3  security policy               (L3 rules: secrets, injection)
LEVEL 4  requirement coverage           (all reqs checked)
LEVEL 5  AI semantic / adversarial judgment (L12)
```

A failure at level **N** cannot be overridden by a PASS from any level
**> N**.

---

## Why independent verification?

An LLM auditing its own work with prose can hallucinate a pass. The
evidence engine here is **deterministic code**: subprocess exit codes,
filesystem facts, regex matches, pytest results. The main AI's judgment
can only *tighten* the gate, never loosen it.

---

## Parallel / multi-agent support

The supervisor is **not** single-agent. Multiple agents can work on the
same workspace concurrently:

- Each plan step declares file ownership (`owns`, inferred from `verify`
  paths if absent).
- Overlap -> conflict warning (or block in STRICT profile).
- Heartbeats track liveness; stale ownership auto-releases.
- Lock files + append-only hashed registry coordinate agents.

Modes: `serial` | `parallel-warn` | `parallel-strict`.

---

## Local-first / hardware-adaptive

| Tier | What runs | Requirements |
|---|---|---|
| TIER 1 — NO LLM | L0-L11, L13, L14 fully | any modern box, no GPU |
| TIER 2 — SMALL LOCAL | + L12 adversarial (1B-4B quantized) | ~4-8 GB RAM |
| TIER 3 — STRONG LOCAL | + L1 + L5 (7B-14B+) | capable workstation |
| TIER 4 — REMOTE | user-provided API model | internet |

Core verification **never** requires an LLM. The supervisor is fully
useful in TIER 1.

## Profiles

| Profile | Use case |
|---|---|
| LIGHT | small tasks, low overhead |
| STANDARD | normal repo/coding work |
| STRICT | bounty / production / security-sensitive |

---

## Install

One package, every agent. Copy the `plan-auditor/` folder into the skills
directory of whichever tool you use. No config, no build — the folder is
the install.

| Tool | User-level path | Invoke |
|---|---|---|
| Command Code | `~/.commandcode/skills/plan-auditor/` | `/plan-auditor` |
| Claude Code | `~/.claude/skills/plan-auditor/` | `/plan-auditor` |
| Codex CLI | `~/.codex/skills/plan-auditor/` | `$plan-auditor` |
| OpenCode | `~/.config/opencode/skills/plan-auditor/` | `/plan-auditor` |
| Cursor | `~/.cursor/skills/plan-auditor/` | `/plan-auditor` |
| Grok Build | `~/.grok/skills/plan-auditor/` | auto-loads by description |

## How it auto-activates (no extra setup)

This works like **any other skill the agent already has**. Two activation paths:

### 1. Automatic via description matching (all tools)

Every tool reads `SKILL.md`'s `description` field. When the user's request
matches it, the skill loads automatically — the agent never needs to be
told to use it. The current description triggers on phrases like
"build X", "implement Y", "add a feature", "plan it",
"don't leave it half-done", "did you actually do it".

Example flow:

```
You: "Build the login form with tests"
   │
   ▼ (Claude Code / Codex / Cursor / Grok / OpenCode sees the request
     matches the skill's description → loads ~/.../skills/plan-auditor/SKILL.md)
   │
   ▼ (Agent follows SKILL.md)
   │  1. Writes .plan-auditor/plan.json with concrete verify checks
   │  2. Implements each step
   │  3. After each step runs: python .../audit_check.py run <dir>
   │  4. Only finishes when: python .../audit_check.py audit <dir> exits 0
   │
   ▼
Agent: "audit PASSED — all steps verified"   ← not just "done"
```

No `/plan-auditor` invocation needed — it self-loads. You can also call it
explicitly (`/plan-auditor "build the login"`) for a one-shot task.

### 2. Platform hook (Command Code — unskippable)

Command Code additionally wires `scripts/stop_gate.py` as a `Stop` hook.
At every turn-end, if any active plan has unverified steps, the turn is
**blocked** and the model is told to run the auditor. The agent cannot
finish, skip the audit, or relax a failed check. See
[`docs/integrations.md`](docs/integrations.md) for the one-block
`settings.json`.

---

## CLI (Supervisor Mode)

```
plan-auditor supervisor start  [--profile LIGHT|STANDARD|STRICT]
                               [--mode serial|parallel-warn|parallel-strict]
plan-auditor supervisor stop
plan-auditor supervisor status
plan-auditor task list | inspect <id>
plan-auditor plan verify <dir> | inspect <dir>
plan-auditor audit <dir>
plan-auditor evidence verify <dir>
plan-auditor doctor <dir>
plan-auditor agents list
```

The existing `audit_check.py` subcommands (`validate`, `run`, `audit`,
`status`, `snapshot`, `rollback`) remain for Skill Mode.

---

## Threat model

See [`docs/threat-model.md`](docs/threat-model.md). Key points:

- **Main AI is untrusted.** The supervisor verifies independently.
- **Same-user limitation.** The supervisor cannot kernel-isolate from a
  malicious same-user agent. This is a documented limitation, not a
  guarantee. Use OS-level isolation for high-assurance cases.
- **Fail-closed.** Anything unknown resolves to FAIL or UNKNOWN, never
  PASS.
- **Honest language.** The project uses "tamper-evident",
  "fail-closed where supported", and "best-effort isolation" — never
  "unbreakable" or "immutable".

---

## Guarantees

| Claim | Level |
|---|---|
| Deterministic check -> real pass/fail | guaranteed |
| Evidence tamper *detection* | tamper-evident (best-effort protection) |
| Plan criteria weakening blocked (same run) | guaranteed |
| Completion claim blocked (platform hook present) | guaranteed |
| Completion claim blocked (no platform hook) | supervisor state BLOCKED (best-effort) |
| Malicious same-user agent fully contained | **not guaranteed** |

---

## What's new in v2.0

- 14-layer supervisor architecture (L0-L14).
- Subsumption priority model.
- Plan sealing + monotonic verification.
- Multi-agent parallel support.
- Profiles (LIGHT/STANDARD/STRICT) and hardware tiers (TIER 1-4).
- Cross-archive evidence anchoring.
- 117 automated tests including 30 failure-injection / security scenarios.
- Full backward compatibility with Skill Mode.

---

## License

MIT
