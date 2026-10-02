#!/usr/bin/env python3
"""Quality ratchet: hold ruff/mypy findings at or below a recorded baseline.

This does not suppress anything. No rule is disabled, no ``ignore_errors`` is
set, and no file is excluded. Instead the current per-rule finding counts are
compared against ``.github/baselines/<tool>.json`` and the job fails when any
rule gets *worse*. That keeps the existing backlog visible and forces it
downward: fixing findings lowers a count, which the ratchet then records as the
new ceiling, so the next regression has less room than the last.

Baseline files are regenerated with ``--write-baseline`` and the regenerated
counts must never be *higher* than what is already recorded, so the ratchet
cannot be used to launder new debt in as "baseline".
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASELINE_DIR = ROOT / ".github" / "baselines"

# Recorded against these exact tool versions. A tool upgrade legitimately changes
# finding counts, so the workflow pins the version and this constant documents it.
EXPECTED_TOOL_VERSIONS = {"ruff": "0.16", "mypy": "2.4"}

# Tools that scan the same tree. Paths that are generated or vendored are not
# project source and must never be able to move a baseline number.
SKIP_DIRS = (
    ".git",
    ".venv",
    "venv",
    "build",
    "dist",
    "node_modules",
    ".tmp-site",
    "site",
    "htmlcov",
)


def _run(tool: str, *args: str) -> subprocess.CompletedProcess[str]:
    # Always run the tool through the current interpreter. Resolving a bare
    # ``ruff``/``mypy`` from PATH would silently pick up whatever happens to be
    # installed globally and record its counts in the baseline.
    cmd = [sys.executable, "-m", tool, *args]
    # Capture bytes and decode explicitly: this repo's sources contain non-ASCII
    # text and the console codepage (cp1254 on this machine) would otherwise
    # raise UnicodeDecodeError inside the reader thread.
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True)
    return subprocess.CompletedProcess(
        cmd,
        proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def ruff_counts() -> tuple[Counter, int]:
    """Per-rule ruff finding counts, plus the total."""
    proc = _run("ruff", "check", "--output-format", "json", ".")
    if proc.returncode not in (0, 1):
        raise SystemExit(f"ruff failed to run:\n{proc.stderr}")
    findings = json.loads(proc.stdout or "[]")
    counter: Counter = Counter()
    for item in findings:
        rel = Path(item["filename"])
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        counter[item["code"]] += 1
    return counter, sum(counter.values())


def mypy_counts() -> tuple[Counter, int]:
    """Per-error-code mypy finding counts, plus the total.

    ``--no-error-summary`` plus a machine-readable output format keeps this
    independent of mypy's human-readable layout. Errors are collected per code
    so a new error class cannot hide inside a large existing one.
    """
    proc = _run(
        "mypy",
        "--strict",
        "--no-error-summary",
        "--no-pretty",
        "--show-error-codes",
        "--no-color-output",
        "--no-incremental",
        "supervisor",
        "scripts",
    )
    counter: Counter = Counter()
    # Lines look like: path:line: severity: message  [error-code]
    pattern = re.compile(r"^(?P<path>[^:]+):\d+:\s+(?:error|note):.*\[(?P<code>[\w-]+)\]\s*$")
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        match = pattern.match(stripped)
        if match is None:
            continue
        rel = match.group("path")
        if any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        counter[match.group("code")] += 1
    return counter, sum(counter.values())


TOOLS = {"ruff": ruff_counts, "mypy": mypy_counts}


def load_baseline(tool: str) -> dict:
    path = BASELINE_DIR / f"{tool}.json"
    if not path.is_file():
        raise SystemExit(
            f"missing baseline {path.relative_to(ROOT)}. Create it with --write-baseline."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(tool: str, current: Counter, total: int, baseline: dict) -> int:
    """Print a ratchet report. Returns a process exit code."""
    recorded: dict[str, int] = baseline.get("counts", {})
    recorded_total = int(baseline.get("total", 0))
    tool_version = baseline.get("tool_version", "unknown")

    print(f"=== {tool} ratchet (baseline {baseline.get('recorded_at', 'unknown')}) ===")
    print(f"tool version:   {tool_version}")
    print(f"baseline total: {recorded_total}")
    print(f"current total:  {total}")

    regressions: list[str] = []
    for code in sorted(set(recorded) | set(current)):
        before = recorded.get(code, 0)
        after = current.get(code, 0)
        status = "OK"
        if after > before:
            status = "REGRESSION"
            regressions.append(f"  {code}: {before} -> {after}")
        elif after < before:
            status = "improved (baseline can be lowered)"
        print(f"  {code:<10} {before:>5} -> {after:<5} {status}")

    if regressions:
        print(f"\n{tool} ratchet FAILED. New findings introduced:")
        print("\n".join(regressions))
        print(
            "\nFix the findings above. Do not disable the rule. If a baseline entry is "
            "wrong, regenerate deliberately and explain it in the PR description."
        )
        return 1

    if total < recorded_total:
        print(
            f"\n{tool} improved by {recorded_total - total} finding(s). "
            "Run scripts/quality_ratchet.py --write-baseline and commit the lower baseline."
        )
    print(f"\n{tool} ratchet passed.")
    return 0


def write_baseline(tool: str, current: Counter, total: int) -> int:
    path = BASELINE_DIR / f"{tool}.json"
    existing = {}
    if path.is_file():
        existing = json.loads(path.read_text(encoding="utf-8"))
        recorded_total = int(existing.get("total", 0))
        if total > recorded_total:
            print(
                f"refusing to raise the {tool} baseline from {recorded_total} to {total}.\n"
                "A baseline may only move downward; otherwise new debt would be recorded "
                "as an accepted starting point. Fix the findings instead."
            )
            return 1

    version = _run(tool, "--version").stdout.strip()
    payload = {
        "tool": tool,
        "tool_version": version,
        "recorded_at": subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True
        ).stdout.strip(),
        "total": total,
        "counts": dict(sorted(current.items())),
        "note": (
            "Ratchet baseline. Findings are never suppressed; this file only records the "
            "current per-rule ceiling so regressions fail CI. Regenerate with "
            "scripts/quality_ratchet.py --write-baseline; it may only decrease."
        ),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} (total={total})")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", choices=sorted(TOOLS))
    parser.add_argument(
        "--write-baseline",
        action="store_true",
        help="record the current counts as the new ceiling (may only decrease)",
    )
    args = parser.parse_args()

    current, total = TOOLS[args.tool]()
    if args.write_baseline:
        return write_baseline(args.tool, current, total)
    return evaluate(args.tool, current, total, load_baseline(args.tool))


if __name__ == "__main__":
    raise SystemExit(main())
