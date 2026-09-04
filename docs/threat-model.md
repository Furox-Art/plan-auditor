# Threat Model

## Trust boundary

The **main AI agent is untrusted**. The Plan Auditor supervisor is
trusted but runs as the **same OS user** as the main agent. It cannot
kernel-isolate from a determined malicious same-user agent. This is a
**documented limitation**, not a hidden caveat.

For high-assurance deployments, run the main agent under a separate OS
user, in a container, or in a sandbox. The supervisor remains valuable
even then, but defense-in-depth is recommended.

## Trust model

| Actor | Trust level |
|---|---|
| Supervisor code (deterministic layers) | trusted |
| Main AI agent | **untrusted** |
| Repository contents | untrusted until verified |
| Verification commands (`run`/`exec`) | execute with care; logged |
| User configuration | trusted |

## Threat actors

1. **Buggy main agent** — produces wrong code, forgets steps, skips
   tests. (Most common.)
2. **Malicious main agent** — deliberately weakens verification,
   fabricates evidence, claims false completion.
3. **Malicious repository** — contains trojaned build/test scripts that
   always exit 0.
4. **Malicious verification command** — a `verify.run` command that does
   something harmful.
5. **Compromised tool** — a hijacked `pytest` or `git`.
6. **Accidental user misconfiguration** — wrong paths, overly permissive
   policies.

## Attack vectors and mitigations

| Vector | Mitigation |
|---|---|
| Command injection via `verify.run`/`exec` | Commands are logged; supervisor never `eval`s model text. User controls the policy. |
| Shell escaping | Prefer explicit command arrays where possible; never concatenate model output into a shell string. |
| Path traversal | All paths resolved and confined to `workspace_root`. |
| Symlink attacks | `os.path.realpath` resolution before writes; refuse paths escaping root. |
| TOCTOU on evidence | Evidence records carry SHA-256 hashes verified on read. |
| Unsafe temp files | Use `tempfile` stdlib module; atomic `os.replace` for writes. |
| Privilege escalation | Supervisor does not escalate privileges; runs as the invoking user. |
| Evidence tampering | Append-only JSONL + cross-archive anchoring (tamper-**evident**, not immutable). |
| State corruption | Atomic writes via `.tmp` + `os.replace`; manifest hashing. |
| Secret leakage to logs | L3 policy rule `NO_SECRET_LEAK` scans logs for credential patterns. |
| Process kill | Lock files have stale-detection via PID liveness. |
| Policy bypass | Policy rules cannot be disabled by the AI; only by user config. |
| Malicious build/test scripts | Supervisor observes exit codes only; behavioral diversity in TIER 2+ can flag "too clean" results. |
| Fake evidence injection | Breaking the SHA-256 chain is detectable via `verify_anchor_chain`. |
| Mock abuse / hardcoded success | L12 adversarial layer flags `assert True` and `mock`/`monkeypatch` patterns. |
| Weakening criteria post-seal | L8 monotonic verification rejects check removal and strength reduction. |
| Concurrent agent file conflicts | L14 ownership registry warns or blocks overlapping writes. |
| Missing requirement coverage | L1 requirement model + L4 BDI track uncovered requirements. |

## Honest terminology

This project **never** claims:

- unbreakable
- impossible to bypass
- fully secure / perfectly secure
- immutable
- cannot be modified

Instead it uses:

- **tamper-evident** — modifications are detectable
- **fail-closed where supported** — unknown states resolve to FAIL/UNKNOWN
- **best-effort isolation** — same-user OS boundary only
- **independent verification** — supervisor runs separately from the main AI
- **deterministic checks** — real execution, not prose judgment
- **sealed state** — monotonic criteria once approved

## Residual risks

Even with all layers active:

- A **malicious same-user agent** can interfere with supervisor files on
  disk. This is inherent to the single-user deployment model.
- **Zero-day vulnerabilities** in Python's `subprocess` or the shell may
  allow escapes outside `workspace_root`.
- **Social engineering** of the user to disable policies is out of scope.

Mitigate with OS-level isolation, minimal policies, and regular audits
of the `.plan-auditor/` directory.
