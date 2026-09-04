# Architecture — Plan Auditor v2.0 Supervisor

Plan Auditor is now a **local-first, multi-layered AI Agent Verification
Supervisor**. It runs *independently* of the main AI, verifies work with
real evidence, seals plan criteria against weakening, and blocks unproven
"done" claims. It also supports **parallel / concurrent agents**.

Two modes:

- **Skill Mode** — unchanged v1.1 behavior (copy the folder, the agent
  follows `SKILL.md`). Backward compatible.
- **Supervisor Mode** — the new daemon + layered verification. Opt-in.

---

## Data flow

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
     L2 World Model       L3 Policy Engine           L9 Watchdog
     (workspace state)    (deterministic rules)      (runtime observe)
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

---

## Layers

| Layer | Module | LLM? | Single responsibility |
|-------|--------|------|-----------------------|
| L0 | `supervisor/events.py` | no | Detect patterns -> route & trigger |
| L1 | `supervisor/requirements.py` | optional | Task -> structured requirements |
| L2 | `supervisor/workspace.py` | no | Structured repo/workspace state |
| L3 | `supervisor/policies.py` | no | Deterministic IF/THEN rules (fail-closed) |
| L4 | `supervisor/goals.py` | no | Beliefs / Desires / Intention state |
| L5 | `supervisor/plan_verifier.py` | optional | Preconditions / effects / coverage / contradictions |
| L6 | `supervisor/lifecycle.py` | no | Task state machine + operators |
| L7 | `supervisor/priority.py` | no | Subsumption authority resolver |
| L8 | `supervisor/sealing.py` | no | Canonical plan + strong hash + monotonic diff |
| L9 | `supervisor/watchdog.py` | no | fs / git / build / test / agent heartbeat monitor |
| L10 | `scripts/audit_check.py` | no | Real checks via fresh subprocess (ONLY source of `verified`) |
| L11 | `supervisor/evidence.py` | no | Cross-archive anchored, tamper-evident chain |
| L12 | `supervisor/adversarial.py` | optional | Semantic review -> candidate deterministic checks |
| L13 | `supervisor/gate.py` | no | Aggregate all layers -> PASS / FAIL / UNKNOWN |
| L14 | `supervisor/agents.py` | no | Parallel agents, file ownership, conflict detection, locking |

### Layer interaction rules

- L0 **detects and triggers** only; never decides PASS/FAIL.
- L7 (subsumption) is the **authority resolver**: a lower-level safety
  failure overrides any higher-level AI "looks fine" verdict.
- L12 (adversarial AI) only **proposes new deterministic checks**; its
  own verdict is never final.
- L10 (deterministic core) is the **only** component that can set a step
  to `verified`.
- L13 (gate) is the **only** component that emits the final
  PASS / FAIL / UNKNOWN.

---

## Subsumption priority (authoritative)

```
LEVEL 0  process / system safety        (supervisor alive, no deadlocks)
LEVEL 1  plan integrity                 (seal unchanged, monotonic)
LEVEL 2  deterministic verification     (L10 core, real checks)
LEVEL 3  security policy               (L3 rules: secrets, injection)
LEVEL 4  requirement coverage           (all reqs checked)
LEVEL 5  AI semantic / adversarial judgment (L12)
```

A failure at level N **cannot** be overridden by a PASS from any level
greater than N. Example: if L2 reports a test FAIL, an L12 AI verdict of
"looks fine" cannot convert it to PASS.

---

## Parallel / multi-agent support (L14)

The supervisor is not single-agent. Multiple agents may work on the same
workspace concurrently.

### Agent model

```python
@dataclass
class Agent:
    agent_id: str
    task_id: str
    plan_id: str
    pid: Optional[int]
    workspace_root: str
    owned_files: Set[str]
    current_action: str
    retry_count: Dict[int, int]
    state: str
```

### Ownership & conflict detection

- Each plan step may declare `owns: ["src/foo.py", "tests/foo.py"]`. If
  absent it is inferred from the step's `verify` paths.
- Before any agent writes a file, L9 + L14 check the `owned_files` of
  every *other* active agent.
- Overlap -> `confale_warning`; in STRICT profile it blocks.
- Stale ownership: an agent with no heartbeat for `OWNER_TIMEOUT`
  releases its ownership.

### Coordination

- Lock file: `.plan-auditor/agents/<agent_id>.lock` (PID + timestamp) with
  stale-lock detection via PID liveness.
- Ownership registry: `.plan-auditor/agents/registry.jsonl`
  (append-only, hashed).

### Modes

```
SUPERVISOR_MODE = serial | parallel-warn | parallel-strict
```

- `serial` — one active plan at a time (current behavior).
- `parallel-warn` — many plans; file conflicts logged as warnings.
- `parallel-strict` — conflicts block the second writer.

---

## Profiles

| Profile | Use case | Layers active |
|---------|----------|---------------|
| LIGHT | small tasks, low overhead | L0, L2, L3, L10, L13 |
| STANDARD | normal repo/coding work | L0-L11, L13 |
| STRICT | bounty / production / security-sensitive | all layers + adversarial + parallel-strict |

---

## Local-first / hardware-adaptive tiers

| Tier | What runs | Requirements |
|------|-----------|--------------|
| TIER 1 — NO LLM | L0-L11, L13, L14 fully | any modern box, no GPU |
| TIER 2 — SMALL LOCAL | + L12 adversarial (1B-4B quantized) | ~4-8 GB RAM |
| TIER 3 — STRONG LOCAL | + L1 + L5 (7B-14B+) | capable workstation |
| TIER 4 — REMOTE | user-provided API model | internet |

Core verification **never** requires an LLM. The supervisor is fully
useful in TIER 1.

---

## Trust boundaries & threat model (summary)

**Trust boundary**: the main AI is **untrusted**. The supervisor is
trusted but runs as the same OS user, so it cannot kernel-isolate from a
malicious same-user agent. This is a documented limitation, not a hidden
one.

**Actors**: buggy main agent, malicious main agent, malicious repo,
malicious verification command, compromised tool, accidental user
misconfiguration.

**Key risks**: command injection via `run`/`exec` commands, shell
escaping, path traversal, symlink attacks, TOCTOU on evidence, secret
leakage into logs, policy bypass, evidence tampering, agent PID reuse.

**Mitigations**:
- `run`/`exec` commands are logged and never `eval`'d by the supervisor.
- All paths are resolved and confined to `workspace_root`.
- Evidence uses cross-archive anchoring; described as *tamper-evident*,
  not "immutable".
- Policy rules cannot be disabled by the AI, only by the user config file.
- Fail-closed: anything unknown resolves to FAIL or UNKNOWN (never PASS).

Full threat model: `docs/threat-model.md`.

---

## Guarantees

| Claim | Level |
|-------|-------|
| Deterministic check -> real pass/fail | guaranteed |
| Evidence tamper *detection* | tamper-evident (best-effort protection) |
| Plan criteria weakening blocked (same run) | guaranteed |
| Completion claim blocked (platform hook present) | guaranteed |
| Completion claim blocked (no platform hook) | supervisor state BLOCKED (best-effort) |
| Malicious same-user agent fully contained | **not guaranteed** (documented limitation) |
| Parallel conflict detection | guaranteed (registry); blocking depends on profile |

---

## Module layout

```
supervisor/
  __init__.py
  config.py
  events.py            L0
  requirements.py      L1
  workspace.py         L2
  policies.py          L3
  goals.py             L4
  plan_verifier.py     L5
  lifecycle.py         L6
  priority.py          L7
  sealing.py           L8
  watchdog.py          L9
  evidence.py          L11
  adversarial.py       L12
  gate.py              L13
  agents.py            L14
  daemon.py
  cli.py
policies/*.toml
```

Existing `scripts/audit_check.py`, `references/plan-format.md`,
`examples/`, and the self-audit CI are preserved and extended.

---

## CLI

```
plan-auditor supervisor start  [--profile LIGHT|STANDARD|STRICT]
                               [--mode serial|parallel-warn|parallel-strict]
plan-auditor supervisor stop
plan-auditor supervisor status
plan-auditor task list
plan-auditor task inspect <id>
plan-auditor plan verify <id>
plan-auditor audit <id>
plan-auditor evidence verify <id>
plan-auditor doctor
plan-auditor agents list
```

Existing `audit_check.py` subcommands remain for Skill Mode.
