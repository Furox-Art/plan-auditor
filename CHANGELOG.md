# Changelog

All notable changes to plan-auditor. Versions are published to PyPI and npm.

## Unreleased

## v2.4.3 - 2026-10-04

A documentation release. The README restructure and the three corrections below
land on PyPI's project page for the first time: `2.4.2`'s `long_description` is
the old 499-line README and still carries the "so it cannot drift from reality"
claim that this release removes. PyPI serves `description` per release, so only
a new release can change it.

**No behaviour change in `supervisor/`, in the deterministic core, or in the npm
launcher.** Verified against the published artifacts, not the working tree:
`supervisor/` has no commit since `311f4dc`, and the `index.js` and
`bin/plan-auditor.js` inside the PyPI `2.4.2` wheel are byte-identical to those
on `main`.

Two packaging changes do reach users. Both are already live on npm at `2.4.2`,
which was published at 16:16:46Z -- after #29 landed at 16:14:02Z -- so this is
the first release in which they reach PyPI:

- **The wheel's embedded `package.json` now declares `engines.node >=22.14.0`.**
  The `2.4.2` wheel says `>=18`, because it was uploaded 2026-10-02T23:06:40Z and
  therefore predates #27. Anyone copying the bundled launcher out of this wheel
  onto Node 18 or 20 now gets npm's engine warning.
- **The sdist and npm tarball carry `bin/prepublish_gate.js`** in place of the
  `bin/check_tarball_contents.js` and `bin/verify_installed_launcher.js` it
  replaces. Both old scripts only ran under `prepublishOnly`; so does the new
  one. Installed behaviour is unchanged -- what a publisher executes differs.


- **Three false claims in the README and quickstart are corrected.**
  - The quick-start transcript documented `request_sha256`
    `7b347f48...0db55f`. The CLI has never printed that value: `request_contract.py`
    stamps `plan_contract_sha256s` into the request before hashing, so the printed
    digest is not a hash of the source file. Running the documented walkthrough in
    a clean virtualenv yields `d7d47e409fc1c53b9830346740bac2a20e716aefc71e7396ad3db0ebbdd837f2`.
    Fixed in `README.md` and `docs/quickstart.md`. The value was unaffected by
    reformatting the JSON, because the digest is taken over the parsed contract
    rather than the file bytes.
  - The README claimed the transcript "cannot drift from reality" because
    `tests/test_readme_quickstart.py` executes it. It could. `_mask()` rewrites
    every 64-hex string to `<sha256>` and the transcript check is a subset test, so
    substituting `dead0000...` for the real digest left the suite green: measured
    at 389 passed, 0 failed. The claim is corrected and two new tests close the gap
    (see below).
  - The README and `CONTRIBUTING.md` both described `examples/fib` as shipping a
    "deliberately broken variant". It does not; the directory holds four files, none
    of them broken. `docs/benchmark.md` is where you break it yourself, and says so.

- **`tests/test_readme_quickstart.py` can now fail on the two ways it used to
  pass.** Proven by mutation against this commit.
  - `test_readme_quickstart_hashes_are_not_normalised_away` compares the documented
    digests against the *unmasked* real output, so a fabricated hash is rejected.
    Replacing `request_sha256` with `dead0000...`: **389 passed / 0 failed before,
    1 failed after**.
  - `test_readme_quickstart_json_keys_match_the_real_output` compares the JSON key
    sequence at each indentation level and only tolerates a shorter sequence where
    the document actually used a `...` marker. Dropping `deterministic_core` from
    the `audit` block, which had no elision, is now a failure. This check caught a
    real omission introduced while compressing this very README.
  - A third mutation, inserting a fabricated `plan_hash`, fails both the original
    subset test and the new hash test.

- **The README now explains the repository instead of only the happy path.**
  Measured against a 60-surface checklist drawn from the code, coverage goes from
  14/60 to 60/60. Added: the L0-L14 layer table with the two layers that can decide
  a verdict; all 11 command groups and their 17 nested actions; the other three
  console scripts including `plan-auditor-formal`'s `verify`/`export-pddl`/
  `make-check`; the core's `status`/`snapshot`/`rollback` modes; the `regex` check
  type and the rule that `regex` and `file_exists` are non-behavioural; profiles,
  run modes and the four LLM tiers; every file written under `.plan-auditor/`;
  `hooks/gate_hook.py` as the single authoritative gate with no per-host adapter
  files; exit codes including `3` for `UNKNOWN`; and
  `references/plan-format.md`.
  - Two checklist items from the audit were wrong and are documented as the code
    actually is: the tiers are `NO_LLM`/`SMALL_LOCAL`/`STRONG_LOCAL`/`REMOTE`
    (four, not "T1/T2/T3"), and there are no six hook adapters — `hooks/` contains
    `gate_hook.py` and its README, and the per-host wiring patterns are documented
    in `docs/integrations.md`.

- **The 53-line release-status block moved to `docs/release-status.md`** and is in
  the mkdocs navigation. Almost all of it describes one version number and would be
  wrong at the next release. The README keeps two lines, and keeps them honest
  rather than dropping the substance: `2.4.2` is current on both registries, npm
  has no provenance attestation and returns `404` for one, and PyPI publishes with a
  PEP 740 attestation. `test_readme_states_the_npm_attestation_gap` still passes
  against the shortened text, so the move did not cost the supply-chain disclosure.

- **Sections that GitHub or the docs already render are gone from the README:**
  the inline `Troubleshooting` block (a 158-line per-error guide lives in
  `docs/quickstart.md`), the standalone `npm` section, `Project links`, and
  `License`. README length falls from 499 to 356 lines.

- **Two doc tests were updated because they pinned text that moved, not because
  they were inconvenient.** `test_readme_adoption_region_covers_the_essentials`
  used `## Troubleshooting` as its region sentinel; the sentinel is now
  `## Documentation`, and the ordering assertions it exists to protect are
  unchanged. `test_doc_transcripts.py` no longer requires the README to carry a
  failing run, but now also requires the README to link the page that does, and
  that page to still document the most common failure.

- **A new test keeps the deleted troubleshooting reachable.**
  `test_readme_points_at_the_full_troubleshooting_page` fails if the README stops
  linking `docs/quickstart.md`, or if that page stops documenting
  `"request contract is not activated"`.

- **A successful npm publish is no longer reported as a failed one.** Run
  37136117550 published `plan-auditor@2.4.2` and then failed its own
  verification step one second later with `ERROR: npm reports 'nothing',
  expected 2.4.2`. `npm publish` returns when the registry's *write* path accepts
  the upload, while clients read from a CDN that converges asynchronously; the
  run's own timestamps show the window, with the probe at 16:15:10Z against a
  registry `time["2.4.2"]` of 16:16:46Z. The verification step now polls with a
  growing backoff over a bounded budget â€” 12 attempts, ~200s of waiting, first
  match wins â€” and a version that never appears still fails closed with a
  `::warning::` explaining what to check. Both directions are covered by
  `tests/test_npm_registry_visibility.py`.
- **The poll queries the registry over HTTP instead of `npm view`.** `npm view`'s
  stdout is not a stable contract, its on-disk HTTP cache can answer from state
  staler than the registry, and it inherits `npm_config_*` and `NODE_AUTH_TOKEN`
  from the environment. `GET /<package>/<version>` is exactly what an
  independent reader requests, with no cache in between.
- **Documentation now matches the registries.** `README.md`, `SECURITY.md` and
  `docs/index.md`, `docs/quickstart.md`, `docs/integrations.md` no longer say npm
  is unpublished or that the published builds are behind `main`. `2.4.2` is on
  both registries; `2.4.0` and `2.4.1` carried the defects and `2.4.2` is the
  fixed release.
- **The attestation story is stated per registry, from the registries themselves.**
  PyPI `2.4.2` carries a PEP 740 provenance attestation. npm `2.4.2` does **not**:
  the attestations endpoint returns `404` and the packument has no `provenance`
  field, because it was published in token mode, which cannot mint one. The npm
  `dist.signatures` block is npm's own signature over the packument and is not
  described as provenance.
- **The npm badge is retained** only after confirming the registry's `latest`
  (`2.4.2`) matches PyPI's version (`2.4.2`).

## v2.4.2 - 2026-10-03

- **npm publishing is restored, and `2.4.2` exists because the published `2.4.1`
  npm build is broken.** Verified against the registry tarball, not against the
  repository: `plan-auditor@2.4.1` ships an `index.js` that passes
  `cwd: __dirname` to `spawn`, so `npx plan-auditor validate .` from a
  workspace directory resolves `.` against the *installed package directory* and
  reports `plan yok: .../node_modules/plan-auditor/.plan-auditor/plan.json`. The
  launcher starts and an absolute workspace path works, so the failure is silent
  and looks authoritative â€” it audits the wrong tree. `2.4.1` cannot be
  republished because npm versions are immutable, hence the patch bump.
- **The launcher now runs the CLI in the caller's working directory.** `index.js`
  keeps `process.cwd()` and prepends the package directory to `PYTHONPATH`
  instead, so the bundled `supervisor` package stays importable without changing
  what a relative workspace path means.
- **`npm publish` runs again.** The previous commit replaced the publish step
  with `echo "npm publishing is disabled" && exit 0`, so the workflow reported
  success while publishing nothing. Publishing is back, gated on the version not
  already existing on the registry, and selectable between OIDC trusted
  publishing and an `NPM_TOKEN` fallback that must be requested explicitly.
  Correction: `2.4.2` itself was published in **token mode** â€” the run log
  records `selected publish mode: token` â€” so it carries **no** provenance
  attestation. The attestation endpoint for `plan-auditor@2.4.2` returns `404`
  and the packument has no `provenance` field. Only PyPI publishes with
  attestation, via trusted publishing.
- **The publish path proves the artifact works before uploading it.** The gate
  packs the tarball, installs it into a throwaway directory, and runs the
  *installed* `bin/plan-auditor.js` from an unrelated working directory against a
  throwaway workspace. The `2.4.0` syntax error and the `2.4.1` wrong-directory
  bug both fail that check.
- **npm and PyPI now share one release trigger.** Touching
  `.github/pypi-release-trigger` on `main` publishes the same version to both
  registries, so the two cannot drift apart.

### OSS visibility and onboarding (shipped in `2.4.2`)

Documentation and project-metadata work only. No behaviour in the supervisor, the
deterministic core or the npm launcher changed. This work was merged before the
`2.4.2` release commit, so it is part of `2.4.2` rather than still pending.

- **The README now states the real release status instead of implying parity.** The
  published PyPI `2.4.1` was built 2026-09-29 and npm `2.4.1` 2026-10-01, from
  different commits, and neither is byte-identical to `main`. The README carries a
  table of what each published build actually contains, and says plainly which
  surface to use for the verified quick start. A maintainer note marks the section
  for deletion in the commit that bumps the version.
- **The "ships with the package" claim in `docs/benchmark.md` was false and is now
  scoped.** The PyPI *wheel* contains only the `supervisor` and `scripts` packages;
  `examples/fib` ships in the repository and in the *sdist*. Verified against the
  published `plan_auditor-2.4.1-py3-none-any.whl`.
- **`docs/benchmark.md` gained a provenance table.** Every remaining quality claim
  is tied to the exact command that produces it, plus the tool, the commit the text
  describes and where the live value lives. The coverage figure for any commit is
  deliberately not copied into the page, because a transcribed number goes stale;
  the command and the workflow comment are the only places it appears. No
  adoption, download or usage figure is printed anywhere, and telemetry is not
  collected.
- **The skill path now says where the files come from.** The PyPI wheel ships no
  `SKILL.md`, `references/` or `hooks/`, so `pipx install plan-auditor` alone
  cannot use the Agent Skill path. The README and `docs/integrations.md` now give a
  concrete `git clone` plus copy command instead of saying "copy the repository".
- **`docs/quickstart.md` no longer overstates its own verification.** It claimed
  "everything on this page is executed by `tests/test_readme_quickstart.py`"; that
  test parses the README's quick-start section only. The page now names the three
  tests that actually check it and their separate responsibilities.
- **The `2.4.0` launcher troubleshooting entry was split by surface.** It conflated
  the npm launcher bug with the pip console script; npm `2.4.0` is named as the
  broken build and the fix is given per surface.
- **Interpreter requirement is documented where it bites.** The examples invoke
  `python`; the note explains what to do on a system that only ships `python3`,
  and that the npm launcher already picks `python3` off Windows.
- **README links are absolute and correct on every surface.** Repository-relative
  links are dead on the PyPI project page, which renders this same file as the
  package description. Every `docs/`, `SKILL.md`, `CHANGELOG.md`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CITATION.cff` and `LICENSE` link is now
  absolute, and each target was checked over HTTP.
- **A documentation URL is stated, and so is the reason there is no site yet.**
  `docs/index.md` is the canonical entry point. `mkdocs.yml` is configured but no
  GitHub Pages workflow exists, so the README no longer promises a rendered site
  and instead gives the two-command local build with the `mkdocs-material`
  dependency named. The old pointer to `CONTRIBUTING.md` for `mkdocs serve` was
  false, since that file did not mention mkdocs at all.
- **"15 supervision layers" is now sourced.** The README attributes the count to
  the L0-L14 table in `docs/architecture.md` instead of stating it bare.
- **A project-status section was added** without any download, star or user
  figure: pre-1.0, single maintainer, no external contributors yet, no measured
  comparison against other tools, and the note that human-readable output is
  Turkish with no locale switch yet.
- **Governance files rewritten.** `SECURITY.md` gained a supported-versions table,
  the private advisory route, a response target and an explicit statement that
  there is no PGP key. `CODE_OF_CONDUCT.md` moved enforcement off the public
  issue tracker, which would have exposed reporters, onto a private address, and
  its Contact section now matches what Contributor Covenant 2.1 requires.
- **`CONTRIBUTING.md` documents the workflow the code actually implements** â€” the
  real test and coverage commands, the seal and trust chain, exit codes, the
  `CHECK_TYPES` extension path, and the release procedure including the reason the
  two registries diverged.
- **Issue and pull-request templates added**, plus a documentation URL in
  `CITATION.cff` and repository `topics`/`description` corrected to match what the
  project is.
- **`mkdocs.yml`** gained `repo_name`, `edit_uri` so every page has an "edit on
  GitHub" link, and social links for the repository, PyPI, npm and the citation
  file. Navigation is unchanged and still covers every page.

#### Re-verified against `main` after #24

- **The README's release-status text was corrected against the merged code rather
  than the previous `main`.** The wheel now force-includes the Agent Skill assets
  under `plan_auditor_skill/`, so the earlier claim that a `pip` install cannot
  supply `SKILL.md`, `references/` or `hooks/` was true of the published `2.4.1`
  wheel and false of anything built from `main`. The README and
  `docs/integrations.md` now document both routes â€” a checkout, or the installed
  `plan_auditor_skill/` directory â€” with a command that prints its location, and
  the claim is scoped to the already-published build. `docs/` and `examples/` are
  still not in the wheel, which is stated as such.
- **The npm surface was re-checked against the merged launcher, not the old one.**
  `index.js` now spawns the CLI with the caller's working directory and puts the
  package directory on `PYTHONPATH`. The published npm `2.4.1` still resolves a
  bare `.` against the installed package and can audit the wrong tree while
  looking authoritative, so the README and `docs/quickstart.md` say so, give the
  absolute-path workaround, and stop implying `npx` is unconditionally CI-safe.
  Exit-code propagation, the `bin` field and the `python`/`python3` selection are
  unchanged.
- **The coverage command in the provenance table was stale and is fixed.** It named
  `--cov=supervisor --cov=scripts --cov-branch`, which measured the checkout. The
  merged `pyproject.toml` reads `branch`, `source_pkgs` and `fail_under` from
  `[tool.coverage.*]`, and `conftest.py` pins the suite to the installed
  distribution, so the documented command is now
  `python -m pytest tests/ -q --cov --cov-report=term-missing`.
- **"The mkdocs step is not part of CI" is no longer true** and was removed.
  `docs (mkdocs --strict)` is a required check, pinned to `mkdocs==1.6.1` and
  `mkdocs-material==9.6.14`; the page now names those pins and adds
  `.github/scripts/check_dist_assets.py` to the reproduce list.
- **`CONTRIBUTING.md` documents the gates that now exist**: `ruff` and `mypy`
  against ratchet baselines that refuse to record a higher count,
  `version-lockstep`, `workflow-syntax`, `build (wheel + sdist)` with a
  `twine check --strict`, `npm-launcher`, and `wheel-cli-smoke` on three
  platforms. The release section was rewritten: OIDC trusted publishing only, the
  GitHub release gated on the version-existence check, an npm `verify` job and an
  already-published gate, and `main` protected by a ruleset with no bypass actors.
  The local setup changed from `pip install -e .` to a non-editable install,
  because `conftest.py` resolves the runtime packages from site-packages and fails
  loudly if they are absent.

## The two published `2.4.1` builds are not the same artifact

Recorded here so nobody has to rediscover it: the same version number was
published to two registries from two different commits.

| Build | Published | Notes |
|---|---|---|
| PyPI `2.4.1` | 2026-09-29 | Built before the documentation and packaging rewrite. 14 keywords; its sdist omits `index.js`, `bin/`, `mkdocs.yml`, `SECURITY.md`, `CITATION.cff`, `CODE_OF_CONDUCT.md` and `package.json`; its project page serves the previous README. |
| npm `2.4.1` | 2026-10-01 | Built from the documentation rewrite; carries the `files` allowlist, the repaired launcher and the current README. |

`pyproject.toml` was left at `2.4.1` and the release workflow skips a version
that already exists on PyPI, so the metadata on `main` cannot be published without
a version bump. That part is unchanged by this entry.

The other half has been fixed since, by #24: the npm workflow now runs a `verify`
job â€” the launcher tests and the packed-tarball check â€” before publishing, and
refuses a version already on the registry, so the absence of any gate that let
`2.4.0` ship a syntax error is no longer the state of the tree. `main` is also
now protected by a ruleset with no bypass actors, so none of the required checks
can be skipped by pushing to `main`.

**Still outstanding:** the version bump itself. Until `2.4.2` is published to both
registries, a `pip` user keeps seeing the pre-rewrite README on the project page.

## v2.4.1 â€” PyPI 2026-09-29, npm 2026-10-01

### Published to both registries

- Metadata-only patch release: improved PyPI discovery keywords, classifiers, description, documentation links, and synchronized package version metadata.

### Published to npm only (built from the documentation rewrite)

#### README rebuilt around a verified quick start

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
- **Removed the broken PyPI downloads badge.** `img.shields.io/pypi/dm/plan-auditor`
  answers HTTP 200 while rendering `downloads: inaccessible`, because shields.io
  scrapes a third-party download API that is rate-limited or down. The README now
  links the PyPI and npm project pages instead, which always answer 200 and always
  carry the real numbers. No count is hardcoded. `tests/test_docs_metadata.py` now
  fails if a `img.shields.io/pypi/d...` badge or a hand-copied download count
  reappears anywhere in the docs.

#### npm launcher exit codes and transcript fidelity

- **Both npm entry points now propagate the verifier's exit code.** The fix was
  initially placed only in `index.js`, but `package.json` maps the `plan-auditor`
  bin to `bin/plan-auditor.js` â€” the file `npx plan-auditor` actually executes â€”
  and that file discarded the child's result entirely. Verified: `node
  bin/plan-auditor.js run <failing plan>` returned `0` while `index.js` returned
  `1`. `index.js` now exposes `runPythonAndPropagate()`, which attaches the
  `close` and `error` handlers and mirrors the code, and `bin/plan-auditor.js`
  calls it. Exit codes are `1` for a failed step, `2` for a blocked audit, `0` for
  a proven workspace, and nonzero if Python cannot be started.
- **`tests/test_npm_launcher.py` covers every entry point and the real package.**
  Every exit-code assertion is parameterised over `bin/plan-auditor.js` and
  `index.js`, the launcher's code is compared against the underlying CLI's, and the
  failing/passing/blocked checks are repeated against the packed npm tarball so a
  fix that works only in the working tree fails the suite. All of these were
  confirmed to fail against the pre-fix `bin` (6 failures) and pass after.
- `test_docs_metadata.py` and `test_doc_transcripts.py` now check that the `bin`
  field resolves to a launcher that propagates rather than a bare spawn, and that
  documented launcher commands reference a file that exists.
- **Verbatim transcripts.** The README and `docs/quickstart.md`/`docs/cli.md` failure transcripts previously showed a single collapsed `Ã§Ä±ktÄ±:` line while the tool actually prints a `|`-joined multi-line traceback. Both blocks now reproduce the real output line for line and state that nothing is elided.
- **Removed a fabricated transcript line from `docs/benchmark.md`:** it showed
  `Ã§Ä±ktÄ±: AssertionError` where the tool emits a full traceback. Replaced with
  verbatim output, plus the equivalent launcher invocation and its exit code.
- **Transcripts are now stable across the CI matrix.** Two platform differences
  had made the documented failure output wrong somewhere: the core joins a
  captured traceback into one physical line separated by `" | "` (a Windows
  carriage return before each separator makes a text-mode reader render it as
  several lines), and Python 3.11+ adds the offending source line and a caret to
  tracebacks. The attempt transcripts in the README, `docs/quickstart.md` and
  `docs/cli.md` now use a stderr-free sentinel check (`sys.exit(3)`) so the
  rendered output is byte-identical on every Python version and platform, with a
  note explaining what a stderr-bearing check adds.
- `tests/test_doc_transcripts.py` reads raw bytes and normalises `\r` itself
  instead of relying on text-mode universal newlines, and rejects any documented
  traceback that pins a version-specific frame.
- **`.npmignore` added and `package.json` tightened:** `__pycache__` directories were still being packed despite the `files` allowlist, because the allowlist re-includes whole directories. Added `!**/__pycache__` and `!**/*.py[cod]` negation patterns and a minimal `.npmignore`. `npm pack --dry-run` now reports 59 entries / ~134 KB with zero `__pycache__`, `.venv`, or `site-packages` paths, down from 18502 entries / 29.1 MB.

## v2.4.0 â€” 2026-09-06

- **Deterministic automatic formalization:** `plan-auditor-formalize compile` converts structured Plan Auditor requirements, coverage, dependencies, named outputs, `requires_outputs`, and deterministic checks into a conservative grounded STRIPS contract without asking an LLM to invent authoritative symbolic semantics.
- **Independent formalization proof:** generated contracts carry a `formalization-source:<SHA256>` marker and are independently recompiled from the current plan; stale, weakened, omitted, or manually edited generated contracts are rejected even if their embedded contract SHA is recomputed.
- **Dataflow-bound symbolic state:** generated actions prove step completion, named-output availability, and canonical `requirement-satisfied:<REQ-ID>` goals; downstream `requires_outputs` become symbolic preconditions while the existing dependency DAG remains independently enforced.
- **Safe generated/manual split:** automatic formalization refuses to overwrite reviewed manual formal contracts and refuses to mutate already sealed plans. Domain semantics that cannot be derived mechanically remain explicit/manual rather than guessed.
- **New installed CLI:** adds `plan-auditor-formalize compile|verify`; package and skill identity advance to stable `2.4.0`.
- **Regression coverage:** tests exercise exact recompilation, source-staleness detection, goal weakening, dropped output preconditions, fake initial requirement goals, idempotence, sealed-plan mutation refusal, and manual-contract preservation.

## v2.3.0 â€” 2026-09-06

- **Sealed classical planning:** non-trivial multi-step plans can embed one sealed `formal_planning` contract with explicit initial facts, final goals, one grounded STRIPS-style action per Plan Auditor step, symbolic preconditions, add effects and delete effects.
- **Native LLM-free reachability:** monotonic contracts use deterministic forward reasoning while delete-effect contracts use bounded state-space search. Exhausting the configured state budget returns UNKNOWN instead of manufacturing PASS.
- **PDDL / Fast Downward cross-check:** the same normalized contract can be exported as sanitized PDDL `:strips` and optionally cross-checked with Fast Downward without making an external planner or GPU a package dependency.
- **Requirement-to-formal-goal binding:** every `must`/`should` requirement in a formalized plan must map to the canonical `requirement-satisfied:<REQ-ID>` final goal, may not be pre-satisfied in `initial_facts`, and must be produced by an action whose Plan Auditor step covers that same requirement.
- **Semantic fail-closed hardening:** missing requirement goals, non-covering producers, pre-satisfied required goals, duplicate formal anchors and effect-free formal actions are rejected before formal reachability can contribute to PASS.
- **Direct skill-name invocation:** `SKILL.md` and README now make `plan-auditor` the user-facing invocation; users do not need to hand-author plan JSON, STRIPS/PDDL contracts, seal metadata or evidence files for the normal skill workflow.
- **Regression coverage:** dedicated formal-planning and semantic-binding tests cover reachable/unreachable contracts, delete-effect dead ends, alternate valid orderings, bounded search, PDDL sanitization, duplicate anchors, requirement omissions and formal-contract mutation.
- **Version identity:** source/package/skill version advances to `2.3.0`, so the post-v2.2.0 formal-planning and semantic-binding code is no longer distributed under the already-published `2.2.0` identity.

## v2.2.0 â€” 2026-09-05

- **Physical control-plane confinement:** existing `.plan-auditor`, plan, seal, request/activation and policy path components are inspected with `lstat`; symlinked parents/leaves cannot redefine the workspace trust root.
- **Policy read confinement:** `load_config` authorizes only symlink-free workspace policy directories before policy loading; a resolved external symlink target is rejected before its files are read.
- **Sealed scope freeze:** automatic monotonic strengthening remains available for extra deterministic checks/prerequisites, but new steps, requirements, tools, coverage assignments or declared outputs now require a new host-approved request generation.
- **Safe v3â†’v4 migration:** `plan-auditor-migrate-seal` provides a representation-only migration path for exact full-contract v3 seals. It requires authoritative request alignment and refuses any plan-scope change.
- **Seal self-consistency:** v3/v4 seals validate their contract hash and criteria count on load/save before being trusted or authenticated.
- **Streaming evidence verification:** JSONL verification, hashing and HMAC migration retain one record/chunk at a time instead of reading complete evidence/archive files into RAM.
- **PID-aware registry locking:** registry transaction locks carry PID + random token; live owners are never evicted because of age alone, and stale cleanup requires a provably dead PID plus unchanged lock identity.
- **Activation semantics:** a lone `.plan-auditor/supervisor.json`, log or cache no longer makes a plans-free workspace look like an activated failed task; request/seal/evidence/plan/integrity/registry state still prevents deletion from degrading to `NO_PLAN`.
- **Single audit freeze implementation:** the unused `workspace.audit.lock` implementation was removed; `audit.freeze.lock`/`final_audit_session` remains the sole workspace final-audit freeze path.
- **Version identity:** source/package version advances to `2.2.0`, preventing post-v2.1.0 hardening from producing a different wheel under the already-published `2.1.0` version.
- **Trust-boundary documentation:** deliberate same-OS-user interference is explicitly treated as an OS isolation problem; separate account/container/VM deployment is required when that attacker is in scope.
- **Regression coverage:** new tests cover plan/policy symlink escapes, scope expansion, config-only activation, PID-aware registry locks, streaming evidence verification and exact legacy-seal migration.

## v2.1.0 â€” 2026-09-05

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

## v2.0.2 â€” 2026-09-05

- **Integrated supervisor pipeline:** new `supervisor/orchestrator.py` wires plan validation, requirements, workspace state, policies, sealing, deterministic evidence, adversarial review, completion gating, lifecycle state, and multi-agent state into one fail-closed assessment.
- **Real hook enforcement:** `hooks/gate_hook.py` no longer trusts `status=verified` or fabricated integrity flags; PASS requires a valid seal and matching fresh full-audit evidence.
- **Deterministic audit freshness:** full audits record SHA-256 fingerprints of the verification contract and workspace contents instead of relying on filesystem mtimes.
- **Cross-archive evidence anchoring:** rotations write archive anchors and L11 verifies internal JSONL hash chains and links between archives.
- **Persistent multi-agent state:** ownership and heartbeat updates are written to the shared registry; separate processes see the same state, and `parallel-strict` rejects overlapping file claims.
- **Adversarial gate integration:** high/critical L12 findings with no deterministic follow-up prevent PASS and produce UNKNOWN instead of being ignored.
- **User policy loading:** deterministic JSON/TOML policies load from configured policy directories.
- **Workspace safety:** file checks and rollback are path-confined; workspace observation is read-only and uses `shutil.which()` instead of shell redirections that could create files.
- **Daemon integration:** the background supervisor persists an integrated assessment and final gate outcome on every observation cycle.

## v1.1.0 â€” 2026-09-03

- **Portable skill paths:** `SKILL.md` resolves auditor scripts relative to the skill directory.
- **Hard attempt cap:** `run` refuses a step after the configured failed-attempt cap unless explicitly forced.
- **Multi-plan core support:** `--plan <name>` operates on `.plan-auditor/plans/<name>.json`; evidence is scoped per plan.
- **Snapshot / rollback:** snapshot and rollback support were introduced and recorded in evidence.
- **Evidence rotation:** large evidence logs rotate into `.plan-auditor/archive/`.

## v1.0.0 â€” 2026-09-03

- Initial strict plan + independent auditor Agent Skill.
- Machine-checkable `verify` checks (`run`, `exec`, `file_exists`, `regex`, `pytest`).
- Deterministic fresh execution, append-only SHA-256 evidence, tamper detection, and full-audit final gate.