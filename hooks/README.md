# Platform hook adapters

Each AI tool exposes lifecycle hooks differently. This directory contains
the small glue that wires `gate_hook.py` into each platform so the audit
gate runs **automatically** — without the main AI having to remember to
call the skill.

## Generic hook (tool-agnostic)

`gate_hook.py` is the core. It reads the workspace, runs the completion
gate, and prints a verdict. Every adapter below calls it.

```bash
python hooks/gate_hook.py <workspace-dir>
# exit 0 = PASS, exit 1 = BLOCKED, exit 3 = UNKNOWN
```

---

## Per-platform wiring

### Claude Code — `.claude/settings.json`

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python \"/abs/path/to/plan-auditor/hooks/gate_hook.py\" \"$(pwd)\"",
            "timeout": 15
          }
        ]
      }
    ]
  }
}
```

The `Stop` event fires at every turn-end. If the gate returns BLOCKED,
Claude Code retries the turn (capped at 3) and feeds the hook output back
to the model — so the model sees "completion BLOCKED" and runs the
auditor.

### Cursor — `.cursor/hooks.json` (or hooks UI)

```json
{
  "hooks": {
    "stop": [
      {
        "command": "python /abs/path/to/plan-auditor/hooks/gate_hook.py \"$(pwd)\""
      }
    ]
  }
}
```

Cursor runs `stop` hooks after each agent turn and injects the output
into the conversation.

### Codex CLI — `config.toml`

Codex's `notify` hook is advisory (it cannot block a turn), so the hook
writes a **warning file** the model reads on the next turn:

```toml
notify = [
  "python",
  "/abs/path/to/plan-auditor/hooks/gate_hook.py",
  "--warn-file",
  ".plan-auditor/gate-warning.json",
  "$(pwd)"
]
```

Pair this with an AGENTS.md instruction: *"Before claiming done, read
`.plan-auditor/gate-warning.json`; if outcome is not PASS, run the
auditor."*

### OpenCode — `~/.config/opencode/plugins/plan-auditor.js`

```js
import { spawn } from "child_process";
export default async function (input) {
  return {
    "tool.execute.after": async (_toolInput, output) => {
      const base = input.directory || process.cwd();
      const hook = "/abs/path/to/plan-auditor/hooks/gate_hook.py";
      const proc = spawn("python", [hook, base], { windowsHide: true });
      let out = "";
      proc.stdout.on("data", (d) => (out += d.toString()));
      proc.on("close", (code) => {
        if (code !== 0 && output && typeof output === "object") {
          output.output = (output.output || "") + "\n\n" + out;
        }
      });
      return output;
    },
  };
}
```

The plugin appends the verdict to tool output after every tool call.

### Grok Build — `.grok/settings.json` (or hooks config)

```json
{
  "hooks": {
    "stop": [
      {
        "command": "python /abs/path/to/plan-auditor/hooks/gate_hook.py \"$(pwd)\""
      }
    ]
  }
}
```

Same pattern as Claude Code / Cursor.

---

## What the hook guarantees

- **Deterministic gate runs automatically** on every turn/tool event.
- The main AI **sees the verdict** (PASS / BLOCKED / UNKNOWN) without
  being asked.
- The main AI **cannot relax criteria** to force a PASS — the gate reads
  sealed plan state, not the AI's claim.
- Exit codes let platforms that support blocking (Claude Code, Cursor,
  Grok) physically prevent turn-end until PASS.

## What it cannot do

- On advisory-only platforms (Codex `notify`), the hook **nudges** but
  cannot block. Use `--warn-file` + AGENTS.md as the enforcement layer.
- The hook trusts the workspace filesystem. A same-user malicious agent
  can tamper with `.plan-auditor/` state — see `docs/threat-model.md`.
