# plan-auditor

[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)
[![release](https://github.com/Furox-Art/plan-auditor/actions/workflows/release.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/release.yml)
[![PyPI](https://img.shields.io/pypi/v/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![PyPI downloads](https://img.shields.io/pypi/dm/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![Python](https://img.shields.io/pypi/pyversions/plan-auditor)](https://pypi.org/project/plan-auditor/)
[![npm](https://img.shields.io/npm/v/plan-auditor)](https://www.npmjs.com/package/plan-auditor)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

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

## Install

```bash
pipx install plan-auditor          # isolated CLI, recommended
pip install plan-auditor           # into the current environment / virtualenv
```

Requires Python 3.10 or newer. No third-party runtime dependencies.

```bash
plan-auditor --help
plan-auditor-formalize --help
```

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

plan-auditor ships as a skill definition ([SKILL.md](SKILL.md)) for hosts that load
skills by directory. Copy the repository (or just `SKILL.md`, `scripts/`,
`references/`, `hooks/`) into your host's skills directory:

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
[docs/integrations.md](docs/integrations.md).

## npm

The npm package is a **thin Node launcher**. It ships the same Python sources and
forwards to `python -m supervisor.cli`, so it needs Python 3.10+ on `PATH`. Prefer
`pipx` or `pip` unless you already manage Node tooling.

```bash
npx plan-auditor --help
```

The launcher propagates the verifier's exit code rather than defaulting to
success, so `npx plan-auditor audit .` is as CI-safe as the console script. A
missing or unstartable Python fails closed with a nonzero code, never `0`.

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

The attempt cap is deliberate — it stops an agent from brute-forcing green. This
is the complete stdout, verbatim, from a workspace with no `README.md`. The core
prints a captured traceback as one physical line joined with `" | "`, so the third
line below is genuinely long:

```console
$ plan-auditor run . 1
[FAIL] adım 1: README.md exists in the project root (deneme 3/3)
       - KALDI | README.md YOK
       - KALDI | exit=1 (beklenen 0)
         çıktı: Traceback (most recent call last): |   File "<string>", line 1, in <module> | FileNotFoundError: [Errno 2] No such file or directory: 'README.md' | 
$ plan-auditor run . 1
[ATLADI] adım 1: README.md exists in the project root önceki gerçek başarısız deneme — 3 sınırı aşıldı.
```

Nothing is elided. Both invocations exit `1`.

Fix the underlying problem, or re-arm deliberately with `plan-auditor run . 1 --force`.

Full troubleshooting guidance, including the observational-audit rule that fails a
run when the workspace changes mid-audit, is in
[docs/quickstart.md](docs/quickstart.md).

## Documentation

| Document | What it covers |
|---|---|
| [docs/index.md](docs/index.md) | Documentation home and reading order |
| [docs/quickstart.md](docs/quickstart.md) | Install, first verified task, `doctor` troubleshooting |
| [docs/cli.md](docs/cli.md) | Every `plan-auditor` subcommand with real invocations |
| [docs/architecture.md](docs/architecture.md) | The 15 supervision layers and subsumption order |
| [docs/dependency-graph.md](docs/dependency-graph.md) | Step DAGs, output contracts, requirement coverage |
| [docs/formal-planning.md](docs/formal-planning.md) | LLM-free STRIPS reachability and PDDL export |
| [docs/threat-model.md](docs/threat-model.md) | Trust boundary and what is explicitly *not* guaranteed |
| [docs/deployment-isolation.md](docs/deployment-isolation.md) | Running against a deliberately hostile agent |
| [docs/integrations.md](docs/integrations.md) | Skill hosts, blocking hooks, CI |
| [docs/benchmark.md](docs/benchmark.md) | What is measurable here, and what is not |

Build the site locally with `mkdocs serve` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Project links

- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Citation metadata](CITATION.cff)
- [Issues](https://github.com/Furox-Art/plan-auditor/issues)

## Honest limits

Read these before you rely on it:

- It is **not** an OS sandbox. In a normal install the agent and the verifier run as
  the same OS user. See [docs/deployment-isolation.md](docs/deployment-isolation.md).
- Evidence is **tamper-evident**, not tamper-proof.
- External HMAC integrity detects tampering only for a key the agent cannot read.
- It verifies that *declared, checkable* requirements were met. Domain meaning that
  cannot be expressed as a deterministic check is reviewed by a human, not guessed.
- The most recent release is published on PyPI and npm; there are no third-party
  mirrors, forks, or packaged distributions listed here.

## License

MIT — see [LICENSE](LICENSE).