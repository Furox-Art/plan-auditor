"""Validate the GitHub Actions workflows the way GitHub does, not just YAML.

`yaml.safe_load` accepting a file does not mean GitHub will run it. Two of the
mistakes found while building these workflows parse as valid YAML but are
rejected at runtime:

  * the `secrets` context is not available in a step-level `if`, so
    `if: ${{ secrets.X != '' }}` invalidates the whole workflow file;
  * a step list entry dedented out of its job makes the document a mapping
    rather than a list of steps.

Both are checked here so the mistake is caught locally instead of by a red run
that says only "this run likely failed because of a workflow file issue".
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

problems: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        problems.append(message)


for path in sorted(WORKFLOWS.glob("*.yml")):
    text = path.read_text(encoding="utf-8")
    name = path.name

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        problems.append(f"{name}: not valid YAML: {exc}")
        continue

    check(isinstance(data, dict), f"{name}: top level must be a mapping")
    check("jobs" in data, f"{name}: no jobs defined")

    # Every `if:` must not reference the secrets context.
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("if:") and "secrets." in stripped:
            problems.append(
                f"{name}:{line_no}: `secrets` is not available in a step-level `if`; "
                "resolve it in a step and pass it through `env`"
            )

    jobs = data.get("jobs") or {}
    check(bool(jobs), f"{name}: jobs mapping is empty")

    for job_name, job in jobs.items():
        check(isinstance(job, dict), f"{name}: job {job_name} is not a mapping")
        if not isinstance(job, dict):
            continue
        check("runs-on" in job, f"{name}: job {job_name} has no runs-on")
        check("permissions" in job, f"{name}: job {job_name} sets no permissions")

        steps = job.get("steps")
        check(
            isinstance(steps, list),
            f"{name}: job {job_name} `steps` is {type(steps).__name__}, expected a list "
            "(a mis-indented step collapses the list into the job mapping)",
        )
        if not isinstance(steps, list):
            continue

        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                problems.append(f"{name}: job {job_name} step {index} is not a mapping")
                continue
            check(
                "uses" in step or "run" in step,
                f"{name}: job {job_name} step {index} has neither `uses` nor `run`",
            )
            uses = step.get("uses")
            if isinstance(uses, str) and not uses.startswith("./"):
                ref = uses.split("@", 1)
                check(
                    len(ref) == 2 and bool(FULL_SHA.match(ref[1])),
                    f"{name}: job {job_name} step {step.get('name')!r} uses {uses!r}, "
                    "which is not pinned to a full 40-character commit SHA",
                )

    print(f"  checked {name}: {len(jobs)} job(s)")

print()
if problems:
    print(f"WORKFLOW VALIDATION FAILED ({len(problems)} problem(s)):")
    for problem in problems:
        print(f"  - {problem}")
    sys.exit(1)

print("all workflows are valid YAML, SHA-pinned, scoped, and secrets-safe")
sys.exit(0)
