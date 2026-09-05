# Changelog

## Unreleased

- **Command execution hardening:** behavioral checks now execute without a shell by default. Structured `argv` is supported and preferred; legacy `cmd` strings are parsed into argument vectors, while shell interpretation requires explicit `shell: true` opt-in. Internal `git ls-files` snapshot discovery also runs without a shell.
- **Agent registry chain hardening:** L14 registry records now use `format_version + seq + prev + hash`, with a persisted head checkpoint for tail-truncation detection. Middle deletion, reordering, record mutation, missing logs with a surviving head, and head mismatches are rejected. Legacy v1 per-record-hash registries are validated and atomically migrated before further writes.
- **Fail-closed registry gating:** integrated completion policy now blocks PASS when the multi-agent registry chain/head integrity check fails. Mutating registry operations refuse to proceed after an integrity failure.
- **Cross-process registry serialization:** registry migration and append operations use an exclusive write lock so independent agent processes cannot race sequence/previous-hash assignment.
- **Regression coverage:** tests verify structured argv execution, inert shell metacharacters by default, explicit shell opt-in, rejection of `shell=true` combined with `argv`, registry sequence/previous-hash continuity, mutation/deletion/reordering/tail-truncation detection, legacy migration, and integrated gate failure on registry tampering.

## v2.0.2 — 2026-09-05

- **Integrated supervisor pipeline:** new `supervisor/orchestrator.py` wires plan validation, requirements, workspace state, policies, sealing, deterministic evidence, adversarial review, completion gating, lifecycle state, and multi-agent state into one fail-closed assessment.
- **Real hook enforcement:** `hooks/gate_hook.py` no longer trusts `status=verified` or fabricated integrity flags; PASS requires a valid seal and matching fresh full-audit evidence.
- **Deterministic audit freshness:** full audits now record SHA-256 fingerprints of the verification contract and workspace contents. Any post-audit content change invalidates completion without relying on filesystem mtimes.
- **Cross-archive evidence anchoring:** rotations write archive anchors and L11 verifies both internal JSONL hash chains and links between archives.
- **Persistent multi-agent state:** ownership and heartbeat updates are written to the shared registry; separate processes see the same state, and `parallel-strict` rejects overlapping file claims.
- **Adversarial gate integration:** high/critical L12 findings with no deterministic follow-up prevent PASS and produce UNKNOWN instead of being ignored.
- **User policy loading:** deterministic JSON/TOML policies now load from configured policy directories.
- **Workspace safety:** file checks and rollback are path-confined; workspace observation is read-only and uses `shutil.which()` instead of shell redirections that could create files.
- **Daemon integration:** the background supervisor now persists an integrated assessment and final gate outcome on every observation cycle.
- **Regression coverage:** integration-hardening tests cover stale `verified` labels, fingerprints, archive anchors, cross-process ownership, strict conflicts, policy loading, and read-only workspace observation.

## v1.1.0 — 2026-09-03

- **Portable skill paths:** `SKILL.md` no longer hardcodes an install path; agents resolve `scripts/audit_check.py` relative to the skill directory. The package now drops into any Agent-Skills tool (Command Code, Claude Code, Codex CLI, Cursor, Grok Build, OpenCode).
- **Hard attempt cap:** `run` refuses to execute a step that already failed `MAX_ATTEMPTS` (3) times — evidence-based, agent can't grind past it. `--force` overrides explicitly.
- **Multi-plan support:** `--plan <name>` operates on `.plan-auditor/plans/<name>.json`; the default remains `plan.json`. Evidence records are scoped per plan; `stop_gate.py` checks all active plans.
- **Snapshot / rollback:** `snapshot` archives the files listed in the plan's optional `snapshot` field (falls back to `git ls-files`) into a zip; `rollback` restores the latest (`--to` to pick one). Both actions are recorded in the evidence chain.
- **Evidence rotation:** logs over 2 MB are moved to `.plan-auditor/archive/` automatically; the chain restarts cleanly.
- **Test suite:** 25 unit tests covering schema, checks, chain/tamper, caps, multi-plan, rotation, snapshot/rollback.

## v1.0.0 — 2026-09-03

- Initial release: strict plan + independent auditor Agent Skill.
- `plan.json` schema with machine-checkable `verify` checks (`run`, `exec`, `file_exists`, `regex`, `pytest`).
- Deterministic auditor: fresh-shell execution, append-only SHA-256 hash-chained evidence log, tamper detection (exit 2), full-audit final gate.
- Mandatory behavioral check per step; recovery-loop rules; self-audit CI gate (GitHub Actions); Command Code Stop-hook enforcement gate.
