# Integrations and enforcement

Plan Auditor can be used as an Agent Skill, a CLI supervisor, or both. The
**authoritative completion decision** is the integrated gate exposed by
`hooks/gate_hook.py` and `plan-auditor audit`.

The gate evaluates every active default/named plan and does not trust persisted
`status=verified` by itself.

## Skill install paths

The skill is four things: `SKILL.md`, `scripts/`, `references/` and `hooks/`.

**From a checkout** — always works:

```bash
git clone https://github.com/Furox-Art/plan-auditor.git
cp -r plan-auditor/SKILL.md plan-auditor/scripts plan-auditor/references plan-auditor/hooks \
      <your host's user-level path below>/
```

**From a `pip` install** — works from a build of `main` or later. The wheel
namespaces those assets under `plan_auditor_skill/` so they cannot collide with
anything else at the site-packages root. Print the directory and copy them out:

```bash
python -c "import supervisor,pathlib;print(pathlib.Path(supervisor.__file__).resolve().parent.parent/'plan_auditor_skill')"
```

The published PyPI `2.4.2` wheel contains them; CI asserts that
every wheel it builds does, via `.github/scripts/check_dist_assets.py`.

| Tool | User-level path | Project-level path | Typical invocation |
|---|---|---|---|
| Command Code | `~/.commandcode/skills/plan-auditor/` | `.commandcode/skills/plan-auditor/` | `/plan-auditor` |
| Claude Code | `~/.claude/skills/plan-auditor/` | `.claude/skills/plan-auditor/` | `/plan-auditor` |
| Codex CLI | `~/.codex/skills/plan-auditor/` | `.codex/skills/plan-auditor/` | `$plan-auditor` |
| OpenCode | `~/.config/opencode/skills/plan-auditor/` | `.opencode/skills/plan-auditor/` | `/plan-auditor` |

Start a new host-tool session after installing/changing skills if that host only
discovers skills at startup.

The npm package is a separate surface: `npx plan-auditor` runs the same CLI
through a Node launcher, but it is not a skill and does not need one.

## Authoritative generic gate

```bash
python /abs/path/to/plan-auditor/hooks/gate_hook.py <workspace>
```

Exit codes:

- `0` — PASS or no active plan
- `1` — deterministic/blocking FAIL
- `3` — UNKNOWN; completion is withheld

A PASS requires all active plans to satisfy requirement coverage, format-v3
full-contract seals, fresh full audits, evidence/registry integrity and policies.

## Command Code compatibility Stop hook

Some Command Code installations expect a Stop adapter that returns exit code `2`
to request another turn. `scripts/stop_gate.py` remains for that interface, but
it is **not a second verification implementation**. It delegates to the same
integrated supervisor decision as `gate_hook.py`.

Example:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python \"C:\\path\\to\\plan-auditor\\scripts\\stop_gate.py\"",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

Projects with no active plans pass through. Any active plan that is unsealed,
uncovered, stale, failed, or otherwise not PASS blocks completion.

## Claude Code / Cursor / other blocking hooks

When the host supports a blocking stop hook, call `hooks/gate_hook.py` and treat
any nonzero exit code as “do not finish.” For example:

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python \"/abs/path/to/plan-auditor/hooks/gate_hook.py\" \"$(pwd)\"",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

Exact host configuration syntax may differ by version; the invariant is that the
host executes the authoritative gate and does not treat non-PASS as completion.

## Advisory-only hosts

If a host exposes notifications/context injection but no blocking lifecycle hook,
use:

```bash
python hooks/gate_hook.py . --warn-file .plan-auditor/gate-warning.json
```

and instruct the agent to read the warning before claiming completion. This is
advisory enforcement: Plan Auditor can produce a deterministic non-PASS result,
but it cannot force an advisory-only host to keep a turn open.

## Recommended CLI sequence

```bash
plan-auditor plan verify .
plan-auditor audit .
```

With authenticated integrity:

```bash
plan-auditor plan verify .
plan-auditor integrity init .
plan-auditor audit .
```

`plan verify` and the final integrated gate cover **all active plans** when no
specific plan is selected.
