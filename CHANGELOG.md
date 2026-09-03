# Changelog

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
