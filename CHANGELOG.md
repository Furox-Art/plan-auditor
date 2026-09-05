## Unreleased

- Introduce host-owned immutable request activation and deterministic acceptance-check binding.
- Reject active-workspace plan deletion as FAIL instead of NO_PLAN.
- Remove automatic reseal baseline reset; request generations are immutable.
- Require explicit dependency declarations and concrete output bindings for every multi-step edge.
- Upgrade seals to format v4 with canonical effective dependency graphs and full runtime-config/request fingerprints.
- Make authenticated-integrity initialization idempotent and refuse re-signing a broken initialized state.
- Pin GitHub Actions dependencies to immutable commit SHAs.

# Changelog

## v2.1.0 — 2026-09-05

- **Aggregate multi-plan completion:** the integrated supervisor now enumerates the default plan and every safe `.plan-auditor/plans/<name>.json` plan. Global PASS requires every active plan to PASS; a passing default plan cannot hide an unfinished named plan, and a named-only workspace is no longer misclassified as `NO_PLAN`.
- **Explicit requirement coverage:** Supervisor Mode requires explicit requirements and deterministic `covers` links from steps. Every `must`/`should` requirement must be covered; omitted user requirements, unknown coverage IDs and duplicate requirement contracts block plan approval/PASS.
- **Full-contract format-v3 seals:** seals now bind task, requirements, required tools, step identity/order/title, requirement coverage, dependencies, required outputs, output contracts/checks, step checks, and the supervisor profile/mode/tier/policy fingerprint. Existing criteria may only be strengthened.
- **Authenticated seals:** external-key HMAC integrity now authenticates plan seals in addition to evidence, checkpoints, registry state and the integrity marker. Seal tampering or missing/wrong key material fails closed after integrity initialization.
- **Configuration/policy downgrade prevention:** malformed supervisor configuration and configured policy files are explicit blocking errors. Profile/mode/tier and policy-file fingerprint are part of the sealed environment contract, so a post-seal downgrade is detected.
- **Evidence concurrency and rotation continuity:** evidence append/rotation uses a cross-process exclusive lock, active evidence links the latest archive tail, and failed-attempt limits are counted across archived plus active evidence instead of resetting after rotation.
- **Complete evidence verification:** `plan-auditor evidence verify` now checks both active evidence and anchored archives.
- **Safe plan addressing:** named plan IDs are validated as safe basenames and cannot traverse outside `.plan-auditor/plans`.
- **Canonical multi-agent ownership:** agent IDs are safe basenames and ownership paths are canonical workspace-relative paths before conflict comparison, preventing alternate spellings from evading `parallel-strict` overlap detection.
- **Transactional full-scope rollback:** default snapshots carry a manifest with file type, mode and hash; rollback restores that state and removes files introduced after the snapshot. Explicit snapshot lists remain intentionally scoped.
- **Stronger fresh-audit fingerprint:** workspace fingerprints include directories, file type and mode/executable bits in addition to contents and symlink targets.
- **Internal shell removal:** workspace/world-model and watchdog Git probes use structured argv with `shell=False`; behavioral plan checks still require explicit `shell: true` for shell interpretation.
- **Bounded verifier output:** command output is spooled/bounded instead of being captured without limit in memory; output-limit overflow fails the check.
- **Doctor fail-closed exit codes:** `doctor` recomputes a current assessment and returns nonzero on FAIL/UNKNOWN instead of hiding a failed assessment behind exit 0.
- **Authoritative hook unification:** `hooks/gate_hook.py` is the single integrated gate. `scripts/stop_gate.py` remains only as an exit-code-2 compatibility adapter and delegates to the same multi-plan full-contract assessment instead of trusting `status=verified`.
- **Three-platform packaging and release gates:** real wheels are built and installed in clean virtual environments on Ubuntu, Windows and macOS. Smoke tests exercise multi-plan discovery, DAG/output dependencies, requirement coverage, full-contract seals, external-key HMAC, integrated audit, doctor, and evidence/integrity CLI paths. PyPI publishing waits for the same three-platform wheel preflight.
- **Versioning:** development version advanced to `2.1.0` so the hardened source cannot be confused with the already-published `2.0.2` artifact.
- **Regression hardening:** dedicated failure-injection tests cover named-plan bypasses, seal-contract weakening, environment downgrade, HMAC seal tampering, invalid config/policies, path traversal, evidence races/rotation/retry history, active-log tampering, rollback cleanup, executable-bit fingerprint changes, canonical agent conflicts, missing tools and bounded verifier output.
- **Observational final audit:** a full audit now fails if a verifier mutates product workspace content, type, or mode. Verification must prove pre-existing implementation state rather than creating the claimed result during the audit itself.

## v2.0.2 — 2026-09-05

- **Integrated supervisor pipeline:** new `supervisor/orchestrator.py` wires plan validation, requirements, workspace state, policies, sealing, deterministic evidence, adversarial review, completion gating, lifecycle state, and multi-agent state into one fail-closed assessment.
- **Real hook enforcement:** `hooks/gate_hook.py` no longer trusts `status=verified` or fabricated integrity flags; PASS requires a valid seal and matching fresh full-audit evidence.
- **Deterministic audit freshness:** full audits record SHA-256 fingerprints of the verification contract and workspace contents instead of relying on filesystem mtimes.
- **Cross-archive evidence anchoring:** rotations write archive anchors and L11 verifies internal JSONL hash chains and links between archives.
- **Persistent multi-agent state:** ownership and heartbeat updates are written to the shared registry; separate processes see the same state, and `parallel-strict` rejects overlapping file claims.
- **Adversarial gate integration:** high/critical L12 findings with no deterministic follow-up prevent PASS and produce UNKNOWN instead of being ignored.
- **User policy loading:** deterministic JSON/TOML policies load from configured policy directories.
- **Workspace safety:** file checks and rollback are path-confined; workspace observation is read-only and uses `shutil.which()` instead of shell redirections that could create files.
- **Daemon integration:** the background supervisor persists an integrated assessment and final gate outcome on every observation cycle.

## v1.1.0 — 2026-09-03

- **Portable skill paths:** `SKILL.md` resolves auditor scripts relative to the skill directory.
- **Hard attempt cap:** `run` refuses a step after the configured failed-attempt cap unless explicitly forced.
- **Multi-plan core support:** `--plan <name>` operates on `.plan-auditor/plans/<name>.json`; evidence is scoped per plan.
- **Snapshot / rollback:** snapshot and rollback support were introduced and recorded in evidence.
- **Evidence rotation:** large evidence logs rotate into `.plan-auditor/archive/`.

## v1.0.0 — 2026-09-03

- Initial strict plan + independent auditor Agent Skill.
- Machine-checkable `verify` checks (`run`, `exec`, `file_exists`, `regex`, `pytest`).
- Deterministic fresh execution, append-only SHA-256 evidence, tamper detection, and full-audit final gate.
