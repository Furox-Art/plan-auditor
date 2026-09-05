# Threat model

## Purpose and trust boundary

Plan Auditor's primary job is to answer:

> Did the AI actually complete the user's requirements and the sealed plan, with
> reproducible evidence, or did it merely claim completion?

The main AI agent is untrusted. The deterministic supervisor is trusted, but in a
normal installation both processes may run as the same OS user. Plan Auditor is
**not** an OS sandbox and does not claim kernel-level isolation.

For the normal “buggy/overconfident agent” threat model, deterministic evidence,
full-contract sealing, requirement coverage and fail-closed aggregation are the
main controls. Separate OS users/containers are optional defense-in-depth for a
deliberately malicious process with the same credentials.

## Trust model

| Actor/state | Trust level |
|---|---|
| Deterministic supervisor code | trusted implementation |
| Main AI agent | untrusted |
| Repository/product files | untrusted until checked |
| Plan requirements and verification contract | trusted only after full-contract seal |
| Verification commands/build scripts | executable code; results are evidence, not inherently trustworthy semantics |
| User configuration/policies | trusted intent, but syntax is validated fail-closed |
| External HMAC key | trusted only while inaccessible to an untrusted forger |

## Main failure/attack classes

1. AI forgets part of the user's request.
2. AI writes a shorter plan that omits a requirement.
3. AI skips a prerequisite or consumes an unverified intermediate result.
4. AI marks a step `verified` without real evidence.
5. AI weakens checks/dependencies/coverage after approval.
6. A named plan is left unfinished while a default plan passes.
7. Evidence is edited, truncated, reordered, or races under concurrent writers.
8. A verification command is unsafe or produces pathological output.
9. Configuration/policies are malformed or downgraded after sealing.
10. Multi-agent file ownership uses alternate path spellings to evade conflicts.
11. Package behavior differs across Linux/Windows/macOS.
12. A malicious same-user process directly interferes with supervisor state/key material.

## Controls

| Risk | Current mitigation |
|---|---|
| Omitted user requirement | Explicit `requirements` plus step `covers`; every `must`/`should` requirement must be covered for Supervisor PASS |
| Hidden named plan | Integrated gate enumerates default + every safe named plan; global PASS requires ALL active plans PASS |
| Skipped prerequisite | DAG validation, topological full audit, `depends_on`, concrete `outputs` and `requires_outputs` rechecks |
| Fake `status=verified` | Status alone is never fresh-audit proof; final gate matches current checks/graph/output evidence and workspace fingerprint |
| Criteria weakening | Format-v3 seal binds task, requirements, tools, step order/title, coverage, DAG, outputs and all verification checks |
| Config/policy downgrade | Seal binds profile/mode/tier/policy fingerprint; malformed config/policy files are blocking errors |
| Command injection | Structured `argv` preferred; shell disabled by default; `shell:true` is explicit opt-in and cannot combine with `argv` |
| Path traversal | Workspace paths are realpath-confined; named plan IDs and agent IDs are safe basenames |
| Agent path aliases | Ownership paths are canonical workspace-relative paths before conflict comparison |
| Evidence concurrent writes | Cross-process evidence write lock serializes append/rotation |
| Evidence history rewrite | SHA-256 `prev` chain spans rotations; active log links latest archive tail |
| Tail truncation / forged state | Optional external-key HMAC signs records, heads/checkpoints, registry state, integrity marker and plan seals |
| Retry-cap reset by rotation | Failed attempts are counted across archived and active evidence |
| Rollback leftovers | Full-workspace snapshots contain a manifest; rollback restores state and prunes introduced files within full scope |
| File-mode drift | Workspace fingerprint includes type and POSIX mode as well as content/symlink target |
| Output-memory exhaustion | Verification command output is bounded before it is retained/processed |
| Internal shell surface | Supervisor workspace/watchdog probes use structured argv with `shell=False` |
| Packaging/platform drift | Real wheel is installed in a clean venv and exercised on Ubuntu, Windows and macOS |

## Verification commands are still code

A deterministic verifier proves exactly what its checks measure. If a repository's
own test script is malicious and always exits zero, an exit code alone cannot prove
semantic correctness. This is why plans should use independent behavioral checks,
concrete output contracts, numerical/property tests where appropriate, and an
optional adversarial review that can propose stronger deterministic checks.

The adversarial/LLM layer cannot create PASS. It can only withhold PASS or suggest
additional deterministic checks.

## External-key authenticated integrity

Set exactly one:

- `PLAN_AUDITOR_HMAC_KEY`
- `PLAN_AUDITOR_HMAC_KEY_FILE`

Key files resolving inside the workspace are rejected and key material must meet
the minimum length. Recommended initialization order:

```bash
plan-auditor plan verify .
plan-auditor integrity init .
plan-auditor audit .
```

Initialization validates existing hash chains before authenticating them, signs
all active plan seals, evidence/archive records and checkpoints, and agent-registry
records/head. The signed integrity marker is written last.

Once initialized, missing/wrong key material, HMAC mismatch, seal tampering, tail
truncation or marker loss fails closed.

### Same-user limitation

HMAC protects against workspace-only rewriting **only while the attacker cannot
obtain the key**. A same-user process that can read the environment/key file can
compute valid HMACs. That limitation is explicit; use OS-level credential/process
separation only when the deployment threat model requires protection against a
deliberately malicious same-user process.

## Fail-closed terminology

The project does not claim “unbreakable”, “immutable”, or “perfectly secure”. It
uses these narrower guarantees:

- **deterministic evidence** — real reproducible checks rather than agent prose,
- **full-contract seal** — approved criteria cannot be weakened without detection,
- **tamper-evident/authenticated state** — modifications are detected within the
  stated key/trust boundary,
- **aggregate multi-plan gate** — all active plans participate in completion,
- **fail-closed** — invalid/unknown critical state resolves to FAIL/UNKNOWN rather
  than PASS.
