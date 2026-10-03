# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)
[![release](https://github.com/Furox-Art/plan-auditor/actions/workflows/release.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/release.yml)
[![PyPI](https://img.shields.io/pypi/v/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![Python](https://img.shields.io/pypi/pyversions/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![npm](https://img.shields.io/npm/v/plan-auditor)](https://www.npmjs.com/package/plan-auditor)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Download numbers live on the package pages themselves, where they are always current:
[PyPI](https://pypi.org/project/plan-auditor/) |
[npm](https://www.npmjs.com/package/plan-auditor)

**An AI agent says "done." This tool makes "done" mean "here is the command output that proves it."**

## The problem

Ask a coding agent to change something and it will report success with confident
prose. Sometimes it never ran the tests. Sometimes it ran them once, failed, and
edited the test until it went green. Either way the transcript you are left with is
narration, and narration is indistinguishable from a real result until you
re-run everything yourself.

## The solution

plan-auditor runs verification in a **separate process with its own check
implementation**. The implementing agent's claims carry no weight at all — only
sealed command output does.

- Every step is a machine-checkable requirement, not a prose bullet.
- Every step needs at least one **behavioral** check (`run`, `pytest`, `exec`). A
  file-existence check can never verify a step on its own.
- Verification output is appended to a SHA-256 hash-chained, tamper-evident log.
- The plan's verification contract is **sealed** on approval and can only be
  strengthened afterwards, never weakened.
- A failed check fails closed. `audit` exits non-zero until every check really passes.

There is no LLM in the verification path. Core verification works on tier 1 hardware
with no model and no network.

## Who it is for

- Anyone who ships AI-generated code and needs receipts before merge.
- Agent-skill authors who want a gate that an agent cannot talk its way past.
- Teams adding a required CI step for "the agent must prove it".
- Researchers who want LLM-free STRIPS/PDDL-style reachability checks over a plan.


## GitHub Action

Use the action from this repository when the check should run in CI. It installs this checkout and runs the fail-closed audit:

```yaml
- uses: Furox-Art/plan-auditor@main
  with:
    path: .
```

`SKILL.md` is the agent-skill install. Copy it into the host skill directory. The npm package is published again as of `2.4.2`; see [Release status](#release-status).

## Install

```bash
pipx install plan-auditor          # isolated CLI, recommended
pip install plan-auditor           # into the current environment / virtualenv
```

Requires Python 3.10 or newer. No third-party runtime dependencies.

The examples below invoke the interpreter as `python`. On a system that only
provides `python3` (common on Debian/Ubuntu without `python-is-python3`), either
activate a virtualenv where `python` exists, or change the `cmd` in the plan to
`python3`. The npm launcher picks `python` on Windows and `python3` everywhere
else, so that path is unaffected.

```bash
plan-auditor --help
plan-auditor-formalize --help
```

The commands and transcripts below are written for a checkout of `main`. Read the
next section before you assume the published packages match them.

## Release status: `2.4.2` is published on both registries

Checked directly against the live registries, not against this repository.

| Surface | Version | Published | Notes |
|---|---|---|---|
| npm (`latest`) | `2.4.2` | 2026-10-03 | Byte-identical to `npm pack` of the current `main` tip: `shasum` `0a284a48fb4fe18cf9de8e45134142b7425f7b47` and integrity `sha512-AMTy8LLGVz5ySoAJN80RhT+I0ku9hat2d2DUbj7pKHNSdmpwiiOLDtH7CDfNGwkU7LDUQ2NE3vMUKlAzwES2NQ==` both reproduce from a clean checkout. |
| PyPI | `2.4.2` | 2026-10-02 | Carries a [PEP 740](https://peps.python.org/pep-0740/) provenance attestation. Its wheel's Python runtime is identical to `main`; the only content difference is the bundled `plan_auditor_skill/package.json` (npm dev-script names and the `engines.node` floor), which is not used at runtime. |

Both registries therefore agree that `2.4.2` is current, so the
[quick start](#quick-start-verified-5-minutes) below describes the published
packages, not only a checkout.

### `2.4.0` and `2.4.1` were defective; `2.4.2` is the fixed release

| Version | Defect |
|---|---|
| `2.4.0` | A JavaScript syntax error in the `bin` launcher: the published entry point could not run at all. |
| `2.4.1` | The launcher passed `cwd: __dirname`, so a relative workspace path resolved against the *installed package directory*. `npx plan-auditor audit .` audited the wrong tree while looking authoritative. An absolute workspace path still worked, which made the failure silent. |
| `2.4.2` | Fixes both, and adds the pre-publish gate that would have caught them. |

npm versions are immutable, so `2.4.0` and `2.4.1` cannot be withdrawn. Pin
`plan-auditor>=2.4.2` if you consume the npm package.

### Supply chain: what is and is not attested

Be precise about this, because the two registries differ:

- **PyPI `2.4.2` has a real provenance attestation.** The endpoint
  `https://pypi.org/integrity/plan-auditor/2.4.2/plan_auditor-2.4.2-py3-none-any.whl/provenance`
  returns a signed in-toto v1 statement with predicate type
  `https://docs.pypi.org/attestations/publish/v1`, bound to the artifact's
  SHA-256. It exists because PyPI publishes through OIDC trusted publishing.
- **npm `2.4.2` has no Sigstore attestation.** There is no `provenance` field in
  the packument and
  `https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@2.4.2`
  returns `404`. The `dist.signatures` block that *is* present is npm's own
  ECDSA signature over the packument, not evidence of how the tarball was built.
  This is expected: npm `2.4.2` was published in **token mode** (the workflow log
  records `selected publish mode: token`), and token publishing runs
  `npm publish --access public` without `--provenance` because a registry token
  cannot mint an attestation. Registering a trusted publisher for this package on
  npmjs.com would enable OIDC and change this.

Until that happens, verify npm artifacts by the integrity hash the registry
serves, not by an attestation:

```bash
npm view plan-auditor@2.4.2 dist.integrity
```

`docs/` and `examples/` are in the repository and the sdist, but not in the wheel.

## Quick start (verified, 5 minutes)

The transcript below is **executed by `tests/test_readme_quickstart.py` on every CI
run**, so it cannot drift from reality.

This quick start uses a throwaway project directory so the walkthrough is
self-contained.

**1. Create the project and the plan.**

```bash
mkdir plan-auditor-demo && cd plan-auditor-demo
mkdir .plan-auditor
```

`.plan-auditor/plan.json`:

```json
{
  "task": "Prove that README.md exists in this scratch project",
  "created": "2026-07-24T00:00:00",
  "requirements": [
    {
      "id": "REQ-001",
      "description": "README.md must exist in the project root and print its first line.",
      "priority": "must"
    }
  ],
  "steps": [
    {
      "id": 1,
      "title": "README.md exists and is readable",
      "covers": ["REQ-001"],
      "verify": [
        { "type": "file_exists", "path": "README.md" },
        {
          "type": "run",
          "cmd": "python -c \"print(open('README.md', encoding='utf-8').read().strip())\"",
          "expect_exit": 0
        }
      ],
      "status": "pending"
    }
  ]
}
```

`request-source.json` — the host-owned statement of what you actually asked for.
It is sealed, so the agent cannot rewrite your requirements later:

```json
{
  "format_version": 1,
  "task": "Prove that README.md exists in this scratch project",
  "requirements": [
    {
      "id": "REQ-001",
      "description": "README.md must exist in the project root and print its first line.",
      "priority": "must",
      "acceptance_checks": [
        { "type": "file_exists", "path": "README.md" },
        {
          "type": "run",
          "cmd": "python -c \"print(open('README.md', encoding='utf-8').read().strip())\"",
          "expect_exit": 0
        }
      ]
    }
  ]
}
```

**2. Run the gate.**

```bash
plan-auditor request init . --file request-source.json
plan-auditor plan verify .
plan-auditor run . 1
plan-auditor audit .
```

Real output. A lone `...` marks fields omitted for length; every other line is
verbatim output from `tests/test_readme_quickstart.py`.

```console
$ plan-auditor request init . --file request-source.json
{
  "activated": true,
  "valid": true,
  "reason": "request contract active",
  "request_sha256": "7b347f48ca610db107039976990f3bbaa8be0c45bffd9b2158b5790ca40db55f",
  "authenticated": false
}
$ plan-auditor plan verify .
{
  "plans": {
    "default": {
      "verdict": "PASS",
      "schema_errors": [],
      ...
      "steps": [
        {
          "id": 1,
          "behavioral": true,
          "dependencies": [],
          "required_outputs": [],
          "declared_outputs": [],
          "risks": []
        }
      ],
      "seal": {
        "status": "sealed",
        "format_version": 4,
        "criteria_count": 2,
        "plan_hash": "27617f6233effbc0f15c77eed6951a5d656d606f48adee840fd04cf43deb02fa",
        ...
      }
    }
  },
  "outcome": "PASS"
}
$ plan-auditor run . 1
[OK ] adım 1: README.md exists and is readable (deneme 1/3)
       - geçti | README.md VAR
       - geçti | exit=0 (beklenen 0)
$ plan-auditor audit .
TAM DENETİM: tüm adımlar taze subprocess ile yeniden test ediliyor...

[OK ] adım 1: README.md exists and is readable
       - geçti | README.md VAR
       - geçti | exit=0 (beklenen 0)

ID   ADIM                                       DURUM     KONTROL
----------------------------------------------------------------------
1    README.md exists and is readable           VERIFIED  2 kontrol

SONUÇ: audit GEÇTİ — tüm adımlar kanıtlı.
{
  "outcome": "PASS",
  "plans": {
    "default": "PASS"
  },
  "deterministic_core": "fresh audit PASS for every active plan under workspace-wide freeze",
  "gate": {
    "outcome": "PASS",
    "deterministic_passed": true,
    "pending_steps": [],
    "seal_ok": true,
    "seal_violations": [],
    "adversarial_findings": [],
    "notes": []
  }
}
```

`audit` re-runs every check in a fresh subprocess. Only exit code `0` means the
work is proven. Note the progress lines are localized by the tool's own UI strings;
the JSON verdict is the stable machine interface.

## Use it as an Agent Skill

plan-auditor ships a skill definition ([SKILL.md](https://github.com/Furox-Art/plan-auditor/blob/main/SKILL.md))
for hosts that load skills by directory. It is four things: `SKILL.md`, `scripts/`,
`references/` and `hooks/`.

**From a checkout** — always works:

```bash
git clone https://github.com/Furox-Art/plan-auditor.git
cp -r plan-auditor/SKILL.md plan-auditor/scripts plan-auditor/references plan-auditor/hooks \
      ~/.config/opencode/skills/plan-auditor/   # or your host's path, from the table below
```

**From a `pip` install** — works from a build of `main` or later, because the
wheel now ships those assets under `plan_auditor_skill/`. Print the directory:

```bash
python -c "import supervisor,pathlib;print(pathlib.Path(supervisor.__file__).resolve().parent.parent/'plan_auditor_skill')"
```

then copy `SKILL.md`, `scripts/`, `references/` and `hooks/` out of it. The
published `2.4.2` wheel does contain them; see
[Release status](#release-status-242-is-published-on-both-registries).

Copy them into your host's skills directory:

| Host | User-level path | Project-level path | Invoke |
|---|---|---|---|
| Claude Code | `~/.claude/skills/plan-auditor/` | `.claude/skills/plan-auditor/` | `/plan-auditor` |
| Command Code | `~/.commandcode/skills/plan-auditor/` | `.commandcode/skills/plan-auditor/` | `/plan-auditor` |
| OpenCode | `~/.config/opencode/skills/plan-auditor/` | `.opencode/skills/plan-auditor/` | `/plan-auditor` |
| Codex CLI | `~/.codex/skills/plan-auditor/` | `.codex/skills/plan-auditor/` | `$plan-auditor` |

Restart the host if it only discovers skills at startup, then ask for the work you
want and let the skill build the plan, run the checks and refuse to stop until
`plan-auditor audit <project>` exits `0`.

Enforcement details, including the blocking `Stop` hook, are in
[docs/integrations.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md).

## npm

The npm package is a **thin Node launcher**. It ships the same Python sources and
forwards to `python -m supervisor.cli`, so it needs Python 3.10+ on `PATH`. Prefer
`pipx` or `pip` unless you already manage Node tooling.

```bash
npx plan-auditor --help
```

`npx plan-auditor` is what the package's `bin` field points at
(`bin/plan-auditor.js`), and it mirrors the verifier's exit code rather than
defaulting to success — so `npx plan-auditor audit .` is as CI-safe as the console
script. Verified exit codes: a failing `run` returns `1`, a blocked `audit` returns
`2`, a proven workspace returns `0`, and an unstartable Python fails closed with a
nonzero code.

The npm package is `2.4.2` on the registry and its launcher is fixed. The
`2.4.0` and `2.4.1` builds were defective — see
[Release status](#242-and-241-were-defective-242-is-the-fixed-release) — so pin
`plan-auditor@2.4.2` or newer if you use `npx`.

## Troubleshooting

`plan-auditor doctor <workspace>` prints a machine-readable capability and health
report. Run it first whenever something looks wrong:

```bash
plan-auditor doctor .
```

Two real failure modes you will hit, and what they actually mean:

**`audit` fails with `"request contract is not activated"`**

You skipped the host-side approval step. The agent must not be able to invent your
requirements. Activate them yourself, once:

```bash
plan-auditor request init . --file request-source.json
```

**A step fails three times and then refuses to run again**

The attempt cap is deliberate — it stops an agent from brute-forcing green. Here
is the complete stdout from a plan whose only check is
`python -c "import sys; sys.exit(3)"` with `expect_exit: 0`:

```console
$ plan-auditor run . 1
[FAIL] adım 1: the sentinel script exits nonzero (deneme 1/3)
       - KALDI | exit=3 (beklenen 0)
$ plan-auditor run . 1
[FAIL] adım 1: the sentinel script exits nonzero (deneme 2/3)
       - KALDI | exit=3 (beklenen 0)
$ plan-auditor run . 1
[FAIL] adım 1: the sentinel script exits nonzero (deneme 3/3)
       - KALDI | exit=3 (beklenen 0)
$ plan-auditor run . 1
[ATLADI] adım 1: the sentinel script exits nonzero önceki gerçek başarısız deneme — 3 sınırı aşıldı.
```

Nothing is elided and every invocation exits `1`. When a failing check prints to
stderr, the core joins the captured text onto one `çıktı:` line separated by
`" | "`; the exact frames depend on your Python version, so this example uses a
check that produces no stderr and stays byte-identical everywhere.

Fix the underlying problem, or re-arm deliberately with `plan-auditor run . 1 --force`.

Full troubleshooting guidance, including the observational-audit rule that fails a
run when the workspace changes mid-audit, is in
[docs/quickstart.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/quickstart.md).

## Documentation

Canonical entry point:
<https://github.com/Furox-Art/plan-auditor/blob/main/docs/index.md>

| Document | What it covers |
|---|---|
| [docs/index.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/index.md) | Documentation home and reading order |
| [docs/quickstart.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/quickstart.md) | Install, first verified task, `doctor` troubleshooting |
| [docs/cli.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/cli.md) | Every `plan-auditor` subcommand with real invocations |
| [docs/architecture.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/architecture.md) | The 15 supervision layers (L0-L14, counted from the table in that page) and subsumption order |
| [docs/dependency-graph.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/dependency-graph.md) | Step DAGs, output contracts, requirement coverage |
| [docs/formal-planning.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/formal-planning.md) | LLM-free STRIPS reachability and PDDL export |
| [docs/threat-model.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/threat-model.md) | Trust boundary and what is explicitly *not* guaranteed |
| [docs/deployment-isolation.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/deployment-isolation.md) | Running against a deliberately hostile agent |
| [docs/integrations.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/integrations.md) | Skill hosts, blocking hooks, CI |
| [docs/benchmark.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/benchmark.md) | What is measurable here, what is not, and where each number comes from |

Runnable example: [`examples/fib/`](https://github.com/Furox-Art/plan-auditor/tree/main/examples/fib)
is a complete two-step plan you can audit end to end, including a deliberately
broken variant.

**No rendered documentation site is published yet.** `mkdocs.yml` is set up, CI
enforces `mkdocs build --strict` as a required check, and the navigation covers
every page — but publishing needs a GitHub Pages workflow that does not exist in
this repository yet. Until then, read the Markdown on GitHub or build it yourself:

```bash
python -m pip install mkdocs-material
mkdocs serve
```

`mkdocs-material` is a documentation-only dependency and is deliberately not part
of the installable package, so `pip install plan-auditor` does not need it. CI
pins its own versions for the strict build. See
[CONTRIBUTING.md](https://github.com/Furox-Art/plan-auditor/blob/main/CONTRIBUTING.md)
for the full contributor workflow.

## Project status

- Pre-1.0, `Development Status :: 4 - Beta` on both registries.
- Maintained by a single person, with no external contributors yet. Review is slow
  for that reason, not because contributions are unwanted.
- No comparison against other tools has been measured. See
  [docs/benchmark.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/benchmark.md)
  for what is reproducible and what is explicitly not claimed.
- No telemetry is collected, and no download or usage figure is printed anywhere
  in this repository. Where a count would be useful, the link to the package page
  is given instead, because the package page is the only place the number is
  current.
- The human-readable progress output is in Turkish (for example the `adım`,
  `geçti` and `KALDI` lines in the transcripts above). There is no locale switch
  yet, so parse the JSON verdict (`"outcome"`) rather than the prose.

## Project links

- [Changelog](https://github.com/Furox-Art/plan-auditor/blob/main/CHANGELOG.md)
- [Security policy](https://github.com/Furox-Art/plan-auditor/blob/main/SECURITY.md)
- [Contributing guide](https://github.com/Furox-Art/plan-auditor/blob/main/CONTRIBUTING.md)
- [Code of conduct](https://github.com/Furox-Art/plan-auditor/blob/main/CODE_OF_CONDUCT.md)
- [Citation metadata](https://github.com/Furox-Art/plan-auditor/blob/main/CITATION.cff)
- [Issues](https://github.com/Furox-Art/plan-auditor/issues) — bug, feature and
  question templates are provided
- [Open a pull request](https://github.com/Furox-Art/plan-auditor/pulls)

## Honest limits

Read these before you rely on it:

- It is **not** an OS sandbox. In a normal install the agent and the verifier run as
  the same OS user. See [docs/deployment-isolation.md](https://github.com/Furox-Art/plan-auditor/blob/main/docs/deployment-isolation.md).
- Evidence is **tamper-evident**, not tamper-proof.
- External HMAC integrity detects tampering only for a key the agent cannot read.
- It verifies that *declared, checkable* requirements were met. Domain meaning that
  cannot be expressed as a deterministic check is reviewed by a human, not guessed.
- The npm package is a launcher: it needs Python 3.10 or newer already on `PATH`.
- Progress output is Turkish-only for now; the JSON verdict is the stable interface.
- The published PyPI and npm packages are both `2.4.2`. npm publishes without a
  provenance attestation; PyPI publishes with one. See
  [Release status](#supply-chain-what-is-and-is-not-attested).
- There is no rendered documentation site yet. The strict docs build *is* a
  required CI check, so the Markdown is known to build, but nothing serves it.
- The branch-coverage floor is enforced in CI and the measured value lives in the
  run, not in this file. Read the run rather than a number here.
- Releases are published on PyPI and npm; there are no third-party mirrors, forks,
  or packaged distributions listed here.

## License

MIT — see [LICENSE](https://github.com/Furox-Art/plan-auditor/blob/main/LICENSE).