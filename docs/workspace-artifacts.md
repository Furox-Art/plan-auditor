# What plan-auditor writes to your workspace

Everything the tool creates lives under `.plan-auditor/` **inside the project you
are auditing**. Nothing is written outside that directory, and nothing outside it
is required to audit.

This page exists because "what will this tool do to my repository?" is a fair
question to ask before running anything, and the answer should not require reading
the source.

## What you write, and what it writes

| File | Written by | What it is |
|---|---|---|
| `plan.json` | you | Your plan: requirements, steps, `covers`, dependency edges, `verify` checks. The tool rewrites step `status` and nothing else. |
| `request.json` | `request init` | The activated request contract, copied and frozen. |
| `activation.json` | `request init` | The digest and validity state of that activation. |
| `seal.json` | `plan verify` | The seal over the whole verification contract: requirements, coverage, the step DAG, output contracts, every check, and the supervisor profile/mode/policy fingerprint. |
| `evidence.jsonl` | `run`, `audit` | Append-only evidence. Every record carries the SHA-256 of the previous one. |
| `evidence.head.json` | `run`, `audit` | Pointer to the current chain head, so a truncated log is detectable. |
| `evidence.write.lock` | `run`, `audit` | Held while evidence is appended. |
| `agents/registry.jsonl` | `agents register` and friends | Multi-agent registry: who exists, what they own. |
| `agents/registry.head.json` | `agents *` | Registry chain head. |
| `agents/registry.write.lock` | `agents *` | Held while the registry is written. |
| `watchdog.jsonl` | `supervisor start` | Heartbeat and filesystem/build/test events. |
| `supervisor.json` | `supervisor start` | Resolved supervisor config: profile, mode, policies. |
| `supervisor.log` | `supervisor start` | Supervisor log. |
| `supervisor-runtime.json` | `supervisor start` | Daemon runtime state. |
| `supervisor-assessment.json` | `supervisor start` / `audit` | The persisted final assessment, so a verdict survives the process. |
| `supervisor.stop` | `supervisor stop` | Stop sentinel consumed by the daemon. |
| `integrity.json` | `integrity init` | External HMAC integrity marker for evidence, seals and the registry. |
| `facts.json` | `plan-auditor-formalize` | Generated STRIPS facts for the formal contract. |

Rotated history and scratch state also appear under `.plan-auditor/`:
`archive/` for rotated evidence chains, `snapshots/` for `snapshot`/`rollback`,
`seals/` for migrated seals, `audit.freeze.lock` while a full audit holds the
workspace frozen, and `*.tmp` during writes.

## Why this matters for trust

Three properties follow from the layout, and they are the reason the files are
separated rather than kept in one blob:

- **Append-only.** `evidence.jsonl` is never rewritten in place. Any edit or
  reorder breaks the chain, and `plan-auditor evidence verify .` detects it.
- **Host-owned input is separate from agent-owned state.** `request.json` and
  `activation.json` record what *you* asked for. `plan.json` step statuses are the
  only thing the agent can move, and only from `pending` to `verified`, and only
  when a behavioural check really passed.
- **A stale verdict is detectable.** `supervisor-assessment.json` records a verdict,
  but `audit` recomputes it from scratch under a workspace freeze, so a passing
  assessment file is never sufficient on its own.

## What is not written

- Nothing outside `.plan-auditor/` in the audited project.
- Nothing in the user's home directory or global config.
- No telemetry, no network calls, no usage counters.

## Cleaning up

`.gitignore` already excludes the generated state. To discard it entirely, stop
the supervisor first if it is running, then remove the directory:

```bash
plan-auditor supervisor stop .
rm -rf .plan-auditor
```

That deletes the evidence chain along with the verdict, so a later `audit` has
nothing to re-verify. Re-seal with `plan-auditor plan verify .` before trusting a
workspace again.