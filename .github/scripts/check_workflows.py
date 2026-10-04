"""Validate the GitHub Actions workflows the way GitHub does, not just YAML.

`yaml.safe_load` accepting a file does not mean GitHub will run it. Three of the
mistakes found while building these workflows parse as valid YAML but are
rejected or misbehave at runtime:

  * the `secrets` context is not available in a step-level `if`, so
    `if: ${{ secrets.X != '' }}` invalidates the whole workflow file;
  * a step list entry dedented out of its job makes the document a mapping
    rather than a list of steps;
  * a job that writes to the repository without `contents: write` fails only
    when it runs. Release runs 37075003605 and 37165300933 uploaded to PyPI and
    then died on the GitHub-release step with "Resource not accessible by
    integration", because that step needs `contents: write` and the job granted
    only `id-token: write`. The upload had already succeeded, so the run reported
    failure for a release that was in fact published.

The permissions checks are two-sided on purpose. Asserting only that write steps
have the scope they need would be satisfied by granting `contents: write`
everywhere, so a job that needs nothing but an OIDC attestation is also required
*not* to carry write scope.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")

# Actions that create or update repository content -- tags, releases, comments,
# issues -- through the REST or GraphQL API. Each needs `contents: write`. The
# token a job receives is the intersection of the workflow-level and job-level
# `permissions` blocks, so a job can only widen what the workflow allows.
#
# `actions/upload-artifact` is deliberately absent: it writes to the Actions
# artifact store, not to the repository, and needs no `contents` scope at all.
REPO_WRITING_ACTIONS = (
    "softprops/action-gh-release",
    "actions/create-release",
    "ncipollo/release-action",
    "marvinpinto/action-automatic-releases",
)

# Actions that consume `id-token: write` to mint an OIDC identity. The
# attestation path must stay away from repository write scope: that token is
# what makes a published artifact verifiable, so the job holding it should not
# also be able to rewrite the repository.
OIDC_ACTIONS = ("pypa/gh-action-pypi-publish",)

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

        permissions = job.get("permissions")
        perms = permissions if isinstance(permissions, dict) else {}
        # `id-token: write` mints an OIDC identity and is not repository write
        # scope; only `contents` (and the other content scopes) can rewrite the
        # repository, so only those count here.
        content_scopes = ("contents", "issues", "pull-requests", "packages")
        declares_write = any(scope in perms and perms[scope] == "write" for scope in content_scopes)

        # Per GitHub's workflow-syntax reference, a job-level `permissions` block
        # *replaces* the workflow-level one for that job rather than intersecting
        # it, so the job's own block is the whole story. The workflow-level block
        # only decides what a job that sets no permissions of its own receives.
        workflow_perms = data.get("permissions")
        workflow_allows_write = (
            workflow_perms == "write-all"
            or workflow_perms == "write"
            or (
                isinstance(workflow_perms, dict)
                and any(value == "write" for value in workflow_perms.values())
            )
        )
        effective_write = declares_write

        steps = job.get("steps")
        check(
            isinstance(steps, list),
            f"{name}: job {job_name} `steps` is {type(steps).__name__}, expected a list "
            "(a mis-indented step collapses the list into the job mapping)",
        )
        if not isinstance(steps, list):
            continue

        writes_repo = False
        mints_oidc = False
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
                action = ref[0]
                if action in REPO_WRITING_ACTIONS:
                    writes_repo = True
                    check(
                        effective_write,
                        f"{name}: job {job_name} step {step.get('name')!r} uses {action!r}, "
                        "which creates or updates a tag or release, but the job is not "
                        f"granted `contents: write` (effective: {perms or 'unset'}; "
                        f"workflow level allows write: {workflow_allows_write}). This is "
                        "how runs 37075003605 and 37165300933 published to PyPI and then "
                        "failed with 'Resource not accessible by integration'.",
                    )
                if action in OIDC_ACTIONS:
                    mints_oidc = True

        # Least privilege, asserted rather than assumed: a job that only mints an
        # OIDC attestation must not also be able to write to the repository.
        if mints_oidc:
            check(
                not effective_write,
                f"{name}: job {job_name} mints an OIDC attestation but is also granted "
                f"write scope ({perms}). The attestation token must not sit in a job "
                "that can rewrite the repository; split the write work into its own "
                "job that needs it.",
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
