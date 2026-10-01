# Quick start

Get a task proven end to end. Everything on this page is executed by
`tests/test_readme_quickstart.py`, so the commands and their output are real.

## Install

```bash
pipx install plan-auditor
```

Prefer an isolated environment. If you must install into the current one:

```bash
pip install plan-auditor
```

Python 3.10 or newer. No third-party runtime dependencies.

```bash
plan-auditor --help
```

If you would rather not install anything, the deterministic core runs straight from
a checkout:

```bash
python scripts/audit_check.py --help
```

## Your first verified task

The walkthrough uses a throwaway directory so nothing else on your machine is
touched.

**1. Create the project and the plan.**

```bash
mkdir plan-auditor-demo && cd plan-auditor-demo
mkdir .plan-auditor
```

`README.md`:

```markdown
# Demo project
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

Two rules are already visible here and they are not optional:

- `requirements` must exist, and every `must`/`should` requirement must be named
  in at least one step's `covers`.
- Every step needs at least one **behavioral** check. `file_exists` and `regex`
  can supplement, but a step made only of those is rejected with
  *"at least one BEHAVIORAL control (run/pytest/exec) is required"*.

**2. Declare what you asked for.**

`request-source.json`:

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

This is the host-owned half of the contract. You write it; the agent does not.
Once activated it is immutable, and the supervisor rejects a plan whose
requirements no longer match it.

**3. Activate, seal, prove, gate.**

```bash
plan-auditor request init . --file request-source.json
plan-auditor plan verify .
plan-auditor run . 1
plan-auditor audit .
```

Real output:

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

A lone `...` marks fields omitted here for length. The progress lines above come
from the tool's own UI strings; the JSON verdict is the stable machine interface,
so scripts should read `"outcome"`, not scrape the prose.

Afterwards, `.plan-auditor/` holds `request.json`, `activation.json`, `seal.json`,
`evidence.jsonl` and the updated `plan.json`. Nothing else needs to be trusted,
because `plan-auditor audit .` re-derives the verdict from scratch.

## What "verified" actually means

| It does prove | It does not prove |
|---|---|
| The named command exited `0` in a fresh subprocess | That the command tested the right thing |
| The file or regex matched at audit time | That your product code is correct |
| The plan still matches the sealed contract | That your requirements were complete |
| The evidence chain is unbroken | That a same-user hostile process could not interfere |
| Every active plan passed | That natural-language meaning was formalized perfectly |

The right column is not a disclaimer to ignore; it is why the acceptance checks are
yours to write. See [Threat model](threat-model.md).

## Adding a real project

For a repository you already have:

1. Write `.plan-auditor/plan.json` with one requirement per thing you asked for,
   and a step per deliverable.
2. Write `request-source.json` with the same requirement IDs, descriptions and
   priorities, plus the deterministic acceptance checks.
3. Activate the contract **yourself**, before handing the task to the agent.
4. Seal with `plan-auditor plan verify .`.
5. Let the agent implement and run `plan-auditor run . <step-id>` after each step.
6. Require `plan-auditor audit .` to exit `0` before merge.

Useful conventions:

- Prefer `{"type": "pytest", "args": "tests/ -q"}` over a hand-written shell
  command; it is portable and its output is captured automatically.
- Set `"timeout"` on a `run` check that can hang. Output is bounded; overflow fails
  the check rather than truncating silently.
- Add a named `output` to a step when a later step must consume its artifact, and
  bind it with `requires_outputs`. See
  [Dependency graph](dependency-graph.md).
- For non-trivial multi-step plans, run `plan-auditor-formalize compile .` **before**
  sealing. The compiler refuses to mutate a sealed plan.

## Troubleshooting

Start here, always:

```bash
plan-auditor doctor .
```

It emits JSON with a top-level `assessment.outcome` and an `integrity` block. A
workspace with no plan reports `NO_PLAN`; that is healthy.

### `audit` reports `"request contract is not activated"`

You skipped the host-side approval. The agent must not be able to invent your
requirements, so this gate has no bypass:

```bash
plan-auditor request init . --file request-source.json
```

Check `plan-auditor request status .` for the current activation state.

### `request init` reports `"... is not a safe regular file"`

`--file` is resolved against your current working directory, not against the
workspace argument. From the workspace root use a bare filename, or pass an
absolute path:

```bash
plan-auditor request init . --file request-source.json
plan-auditor request init . --file "$PWD/request-source.json"
```

### `request init` reports `"invalid request contract: ... at least one BEHAVIORAL control"`

Your `acceptance_checks` are all `file_exists`/`regex`. Add at least one `run`,
`pytest`, or `exec` check per requirement.

### `request init` reports `"requirement REQ-001 is missing from every active plan"`

The request contract is authoritative. Every requirement in it must also appear
in a plan's `requirements` with the **same** description and priority, and must be
named by at least one step's `covers`. If the text drifts you get
`"was modified in plan requirements"` instead — keep the two strings identical.

### `plan verify` reports `"seal.json already exists"` / refuses to change

Once a plan is sealed, criteria may only be **strengthened**. To genuinely change
the scope you need a new host-approved request generation. See
[Threat model](threat-model.md) and the `plan-auditor-migrate-seal` command for
the representation-only migration path.

### A step fails three times and then refuses to run

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

Nothing is elided and every invocation exits `1`. The check here is
`python -c "import sys; sys.exit(3)"` against `expect_exit: 0`; a failing command
that writes to stderr additionally gets a `çıktı:` line, joined with `" | "`.

Fix the underlying problem. Re-arm deliberately with `plan-auditor run . 1 --force`
only when you are certain the check is correct and the implementation is wrong.

### `audit` fails with `"workspace content/type/mode changed during the full final-audit session"`

The final audit is **observational**: it fingerprints the workspace, runs the
checks, and fails if anything changed underneath it. The usual causes are yours,
not the agent's:

- A background process, formatter, watcher, or build writing into the workspace
  during the audit.
- Redirecting the audit's own output into a file inside the workspace.
- Another agent or terminal running a generator concurrently.

Quiesce those writers and re-run. If a *verification command itself* creates the
artifact it asserts, move creation into an earlier step and have the check only
read it.

### `audit` fails with `"no fresh deterministic full-audit proof for the current plan"`

The workspace fingerprint changed since the last successful audit. Re-run
`plan-auditor audit .` with nothing else touching the tree.

### `evidence verify` reports a broken chain

Records in `.plan-auditor/evidence.jsonl` (or an archive) were edited or reordered.
Every record carries the SHA-256 of the previous one, so tampering is detected.
`doctor` explains where the chain breaks; you will have to re-establish the plan
rather than repair the log by hand.

### The npm launcher always exits 0

It should not. `index.js` exits with the child verifier's code, so a nonzero
result reaches your shell:

```bash
npx plan-auditor audit .
echo $?
```

If that prints `0` while the JSON verdict says `FAIL`, you are running the
published `2.4.0`, which shipped a syntax error in the launcher. Upgrade to
`2.4.1` or use the console script:

```bash
pipx install --force plan-auditor
plan-auditor audit .
```

### The agent keeps "fixing" the test instead of the code

That is a policy problem, not a bug. Add a check that asserts the *product*
behavior independently — for example a `run` check that imports your package and
calls the API — so editing the test cannot produce a green result.

## Next steps

- [CLI reference](cli.md) for every command and exit code.
- [Integrations](integrations.md) for skill hosts, blocking hooks, and CI.
- [Architecture](architecture.md) for the layer model.
- [Formal planning](formal-planning.md) for LLM-free STRIPS reachability.
- [What is measurable](benchmark.md) for claims this project does and does not make.