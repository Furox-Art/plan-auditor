# Platform hook adapters

`gate_hook.py` is the **single authoritative hook gate**. It calls the integrated
supervisor assessment and only returns PASS when every active plan has:

- explicit requirement coverage,
- an intact format-v3 full-contract seal,
- matching supervisor profile/mode/policy contract,
- a fresh deterministic full audit,
- valid active + archived evidence,
- valid agent-registry state,
- required tools and policies satisfied.

It never trusts `status=verified` by itself.

## Generic invocation

```bash
python hooks/gate_hook.py <workspace-dir>
```

Exit codes:

- `0` — PASS / no active plan
- `1` — FAIL / completion blocked
- `3` — UNKNOWN / completion withheld pending deterministic follow-up

JSON output:

```bash
python hooks/gate_hook.py . --format json
```

Advisory warning file:

```bash
python hooks/gate_hook.py . --warn-file .plan-auditor/gate-warning.json
```

## Command Code compatibility adapter

`scripts/stop_gate.py` exists only for hosts that use exit code `2` to retry a
Stop event. It delegates to the same integrated supervisor assessment as
`gate_hook.py`; it is not a weaker status-only gate.

## Claude Code / blocking Stop hooks

Point the host's Stop hook at `gate_hook.py` and treat any nonzero result as
“do not finish.” Example shape:

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

Host configuration syntax can change; the invariant is that the host executes the
integrated gate and does not accept a non-PASS completion.

## Cursor / Grok / similar hosts

Use the same `gate_hook.py` command from the host's blocking stop/lifecycle hook
when such a hook is available.

## Codex CLI and advisory-only hosts

When the host cannot block turn-end, use `--warn-file` or inject the gate output
into the next model turn. This makes the deterministic result visible but cannot
physically force an advisory-only host to continue.

## OpenCode plugin pattern

An OpenCode plugin can execute `gate_hook.py` after relevant tool events and
append non-PASS output to the agent context. This is advisory unless the host
itself exposes a blocking lifecycle API.

## Multi-plan behavior

The hook enumerates the default plan and every safe
`.plan-auditor/plans/<name>.json` plan. A passing default plan cannot hide an
unfinished named plan. If only named plans exist, the workspace is **not** treated
as `NO_PLAN`.

## Trust boundary

The gate verifies whether the planned/user-requested work is actually proven. It
is not an OS sandbox. See `docs/threat-model.md` for the same-user boundary and
external-key HMAC integrity mode.
