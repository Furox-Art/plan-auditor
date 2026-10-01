## Unreleased

# Changelog

## Unreleased — documentation and packaging metadata

- **README rebuilt around a verified quick start:** explicit problem/solution framing, "who it is for", `pipx` and `pip` install paths, a five-minute walkthrough, Agent Skill invocation table, a `plan-auditor doctor` troubleshooting section, accurate CI/PyPI/npm/license badges, and a stated list of honest limits.
- **Removed an inaccurate Python API example.** The previous README showed `from plan_auditor import AuditContract`; no such module exists in the distribution, which ships `supervisor` and `scripts`. The README now documents the real CLI only.
- **Quick start transcript is now machine-verified.** `tests/test_readme_quickstart.py` parses the documented JSON files and commands out of `README.md`, executes them through the installed CLI in a temporary workspace, and asserts every documented output line is real. The old transcript contained a `plan verify` block with fields that were never emitted.
- **Documentation site is coherent and strict-build clean.** Added `docs/index.md` and `docs/cli.md`, rewrote `docs/quickstart.md` with a full troubleshooting guide, added a working `examples/fib/request-source.json` so the shipped example passes the supervisor gate, and repaired `mkdocs.yml` navigation, which referenced a non-existent `index.md` and omitted four existing pages. `mkdocs build --strict` now exits 0.
- **`docs/benchmark.md` no longer contains fabricated comparative numbers.** It previously claimed results from "100 coding tasks" and detection rates for unnamed alternatives that no harness in this repository ever produced. It is replaced with a reproducible in-repo demo, the commands that back each remaining claim, and an explicit table of what is not measured.
- **Deterministic documentation and packaging checks.** New `tests/test_docs_metadata.py` verifies mkdocs navigation targets exist and cover every page, relative links resolve, README badges reference real workflows, no unverified adoption or trust-badge claims are present, every documented `plan-auditor` invocation is in the parser surface, and `pyproject.toml`/`package.json`/`SKILL.md`/`CITATION.cff` versions, classifiers, keywords, URLs, and npm launcher wiring agree with what ships.
- **`pyproject.toml` metadata completed:** broader keyword set, audience/topic/platform/typing classifiers, and `project.urls` entries for Security, Contributing, and Citation. `Development Status` and license metadata left unchanged because the published version is unchanged.
- **`package.json` aligned with the real CLI.** `npm test` was `echo "Error: no test specified" && exit 1`; it now syntax-checks the launcher. Added an explicit `files` allowlist so the published tarball no longer ships the entire working tree (the previous package included local virtual environments and build output). Version bumped to `2.4.1` to match the Python distribution.
- **`index.js` launcher repaired.** It contained a syntax error (`(code) =;`), so the published npm launcher could not run at all. It now forwards arguments to the Python CLI and propagates the child exit code. `files` ships everything the launcher needs at runtime (`supervisor`, `scripts`, `hooks`, `references`).
- **Housekeeping:** `.gitignore` now excludes `.venv/`, `venv/`, `.tmp-site/`, `site/`, and `node_modules/`.

## Unreleased — npm launcher exit codes and transcript fidelity

- **`index.js` now propagates the child's exit code.** It previously spawned `python -m supervisor.cli` and returned without ever reading the result, so `npx plan-auditor audit .` exited `0` even when the audit printed `"outcome": "FAIL"`. A failing gate could pass through the npm entry point. The launcher now handles `close` with `process.exit(code === null ? FAILURE_EXIT_CODE : code)` and handles `error` by exiting nonzero, so an unstartable interpreter also fails closed.
- **New `tests/test_npm_launcher.py`:** asserts a failing `run` and a blocked `audit` both yield a nonzero launcher exit code, a passing `run` yields `0`, and an empty `PATH` (spawn failure) yields nonzero. The failing and blocked cases were confirmed to fail against the previous launcher.
- **Verbatim transcripts.** The README and `docs/quickstart.md`/`docs/cli.md` failure transcripts previously showed a single collapsed `çıktı:` line while the tool actually prints a `|`-joined multi-line traceback. Both blocks now reproduce the real output line for line and state that nothing is elided.
- **Removed a fabricated transcript line from `docs/benchmark.md`:** it showed `çıktı: AssertionError` where the tool emits a full `Traceback` block. Replaced with verbatim output, plus the equivalent launcher invocation and its exit code.
- **`.npmignore` added and `package.json` tightened:** `__pycache__` directories were still being packed despite the `files` allowlist, because the allowlist re-includes whole directories. Added `!**/__pycache__` and `!**/*.py[cod]` negation patterns and a minimal `.npmignore`. `npm pack --dry-run` now reports 59 entries / ~134 KB with zero `__pycache__`, `.venv`, or `site-packages` paths, down from 18502 entries / 29.1 MB.

## v2.4.1 — 2026-09-29

- Metadata-only patch release: improved PyPI discovery keywords, classifiers, description, documentation links, and synchronized package version metadata.

## v2.4.0 — 2026-09-06

- **Deterministic automatic formalization:** `plan-auditor-formalize compile` converts structured Plan Auditor requirements, coverage, dependencies, named outputs, `requires_outputs`, and deterministic checks into a conservative grounded STRIPS contract without asking an LLM to invent authoritative symbolic semantics.
- **Independent formalization proof:** generated contracts carry a `formalization-source:<SHA256>` marker and are independently recompiled from the current plan; stale, weakened, omitted, or manually edited generated contracts are rejected even if their embedded contract SHA is recomputed.
- **Dataflow-bound symbolic state:** generated actions prove step completion, named-output availability, and canonical `requirement-satisfied:<REQ-ID>` goals; downstream `requires_outputs` become symbolic preconditions while the existing dependency DAG remains independently enforced.
- **Safe generated/manual split:** automatic formalization refuses to overwrite reviewed manual formal contracts and refuses to mutate already sealed plans. Domain semantics that cannot be derived mechanically remain explicit/manual rather than guessed.
- **New installed CLI:** adds `plan-auditor-formalize compile|verify`; package and skill identity advance to stable `2.4.0`.
- **Regression coverage:** tests exercise exact recompilation, source-staleness detection, goal weakening, dropped output preconditions, fake initial requirement goals, idempotence, sealed-plan mutation refusal, and manual-contract preservation.

## v2.3.0 — 2026-09-06

- **Sealed classical planning:** non-trivial multi-step plans can embed one sealed `formal_planning` contract with explicit initial facts, final goals, one grounded STRIPS-style action per Plan Auditor step, symbolic preconditions, add effects and delete effects.
- **Native LLM-free reachability:** monotonic contracts use deterministic forward reasoning while delete-effect contracts use bounded state-space search. Exhausting the configured state budget returns UNKNOWN instead of manufacturing PASS.
- **PDDL / Fast Downward cross-check:** the same normalized contract can be exported as sanitized PDDL `:strips` and optionally cross-checked with Fast Downward without making an external planner or GPU a package dependency.
- **Requirement-to-formal-goal binding:** every `must`/`should` requirement in a formalized plan must map to the canonical `requirement-satisfied:<REQ-ID>` final goal, may not be pre-satisfied in `initial_facts`, and must be produced by an action whose Plan Auditor step covers that same requirement.
- **Semantic fail-closed hardening:** missing requirement goals, non-covering producers, pre-satisfied required goals, duplicate formal anchors and effect-free formal actions are rejected before formal reachability can contribute to PASS.
- **Direct skill-name invocation:** `SKILL.md` and README now make `plan-auditor` the user-facing invocation; users do not need to hand-author plan JSON, STRIPS/PDDL contracts, seal metadata or evidence files for the normal skill workflow.
- **Regression coverage:** dedicated formal-planning and semantic-binding tests cover reachable/unreachable contracts, delete-effect dead ends, alternate valid orderings, bounded search, PDDL sanitization, duplicate anchors, requirement omissions and formal-contract mutation.
- **Version identity:** source/package/skill version advances to `2.3.0`, so the post-v2.2.0 formal-planning and semantic-binding code is no longer distributed under the already-published `2.2.0` identity.

## v2.2.0 — 2026-09-05

- **Physical control-plane confinement:** existing `.plan-auditor`, plan, seal, request/activation and policy path components are inspected with `lstat`; symlinked parents/leaves cannot redefine the workspace trust root.
- **Policy read confinement:** `load_config` authorizes only symlink-free workspace policy directories before policy loading; a resolved external symlink target is rejected before its files are read.
- **Sealed scope freeze:** automatic monotonic strengthening remains available for extra deterministic checks/prerequisites, but new steps, requirements, tools, coverage assignments or declared outputs now require a new host-approved request generation.
- **Safe v3→v4 migration:** `plan-auditor-migrate-seal` provides a representation-only migration path for exact full-contract v3 seals. It requires authoritative request alignment and refuses any plan-scope change.
- **Seal self-consistency:** v3/v4 seals validate their contract hash and criteria count on load/save before being trusted or authenticated.
- **Streaming evidence verification:** JSONL verification, hashing and HMAC migration retain one record/chunk at a time instead of reading complete evidence/archive files into RAM.
- **PID-aware registry locking:** registry transaction locks carry PID + random token; live owners are never evicted because of age alone, and stale cleanup requires a provably dead PID plus unchanged lock identity.
- **Activation semantics:** a lone `.plan-auditor/supervisor.json`, log or cache no longer makes a plans-free workspace look like an activated failed task; request/seal/evidence/plan/integrity/registry state still prevents deletion from degrading to `NO_PLAN`.
- **Single audit freeze implementation:** the unused `workspace.audit.lock` implementation was removed; `audit.freeze.lock`/`final_audit_session` remains the sole workspace final-audit freeze path.
- **Version identity:** source/package version advances to `2.2.0`, preventing post-v2.1.0 hardening from producing a different wheel under the already-published `2.1.0` version.
- **Trust-boundary documentation:** deliberate same-OS-user interference is explicitly treated as an OS isolation problem; separate account/container/VM deployment is required when that attacker is in scope.
- **Regression coverage:** new tests cover plan/policy symlink escapes, scope expansion, config-only activation, PID-aware registry locks, streaming evidence verification and exact legacy-seal migration.

## v2.1.0 — 2026-09-05

- **Aggregate multi-plan completion:** the integrated supervisor now enumerates the default plan and every safe `.plan-auditor/plans/<name>.json` plan. Global PASS requires every active plan to PASS; a passing default plan cannot hide an unfinished named plan, and a named-only workspace is no longer misclassified as `NO_PLAN`.
- **Explicit requirement coverage:** Supervisor Mode requires explicit requirements and deterministic `covers` links from steps. Every `must`/`should` requirement must be covered; omitted user requirements, unknown coverage IDs and duplicate requirement contracts block plan approval/PASS.
- **Full-contract format-v3 seals:** seals bind task, requirements, required tools, step identity/order/title, requirement coverage, dependencies, required outputs, output contracts/checks, step checks, and the supervisor profile/mode/tier/policy fingerprint. Existing criteria may only be strengthened.
- **Authenticated seals:** external-key HMAC integrity authenticates plan seals in addition to evidence, checkpoints, registry state and the integrity marker. Seal tampering or missing/wrong key material fails closed after integrity initialization.
- **Configuration/policy downgrade prevention:** malformed supervisor configuration and configured policy files are explicit blocking errors. Profile/mode/tier and policy-file fingerprint are part of the sealed environment contract, so a post-seal downgrade is detected.
- **Evidence concurrency and rotation continuity:** evidence append/rotation uses a cross-process exclusive lock, active evidence links the latest archive tail, and failed-attempt limits are counted across archived plus active evidence instead of resetting after rotation.
- **Complete evidence verification:** `plan-auditor evidence verify` checks both active evidence and anchored archives.
- **Safe plan addressing:** named plan IDs are validated as safe basenames and cannot use lexical `..` traversal outside `.plan-auditor/plans`.
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
- **Observational final audit:** a full audit fails if a verifier mutates product workspace content, type, or mode. Verification must prove pre-existing implementation state rather than creating the claimed result during the audit itself.

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