#!/usr/bin/env python3
"""Fail CI when a pinned action SHA does not exist upstream.

`check_workflows.py` proves a pin is a full 40-character string. That is not the
same as proving the commit exists: `npm-publish.yml` carried

    actions/setup-python@a26ef69be951a213d495a4c3e4e4022e16d87065 # v5.6.0

one character away from the real `a26af69b...`, so it was a well-formed SHA of
a commit that does not exist. GitHub could not resolve the action, so run
37199866973 failed at workflow setup -- before any job started, before any gate
ran, and before a version check could report anything. The npm publish was
blocked entirely and nothing in the repository noticed.

A SHA that cannot be resolved is treated as a hard failure, never as a skip. A
checker that quietly passes when the network is unavailable is worse than no
checker, because it reports "all pins verified" about pins it never looked at.
An offline run fails with an explicit message naming what it could not verify.

Usage:
    python .github/scripts/check_action_pins.py            # check every pin
    python .github/scripts/check_action_pins.py --report   # list, never fails

Network access is required unless every pin is already cached under
`.action-pin-cache/`. Pass `--offline` to use only the cache.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CACHE = ROOT / ".action-pin-cache"

API = "https://api.github.com"
PIN = re.compile(r"uses:\s+(?P<action>[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+)@(?P<sha>[0-9a-f]{40})\b")
# The `# v1.2.3` comment after a pin is the human claim about which release it is.
VERSION_COMMENT = re.compile(r"#\s*v?(\d+(?:\.\d+)+)\s*$")

# Refuse to guess at a rate limit. Seven distinct pins is the whole repository;
# this is generous headroom, not a throttle that will trip in practice.
CALLS_PER_HOST = 40
RATE_LIMIT = 403
# `GET /repos/{o}/{r}/commits/{ref}` answers 422 "No commit found for SHA" for a
# well-formed SHA that does not exist, and 404 only for some paths. Both mean
# the pin is bad, which is the whole point of this check.
NOT_FOUND = (404, 422)


class Unreachable(Exception):
    """The upstream could not be asked, as opposed to answering 'no such SHA'."""


def _get(url: str, token: str | None) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "check-action-pins"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # A rate limit is not evidence that a SHA is missing. Reporting it as a
        # bad pin would be a false positive that trains people to ignore this.
        if exc.code == RATE_LIMIT:
            raise Unreachable(
                f"GitHub API rate limit hit while asking for {url} "
                "(HTTP 403). Set GITHUB_TOKEN, or wait for the limit to reset."
            ) from exc
        return exc.code, exc.read().decode("utf-8", "replace")
    except urllib.error.URLError as exc:
        raise Unreachable(f"cannot reach {url}: {exc.reason}") from exc


def collect_pins() -> list[tuple[str, str, str, str]]:
    """Return (action, sha, version_comment, source) for every pin in the repo."""
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            match = PIN.search(line)
            if match is None:
                continue
            comment = VERSION_COMMENT.search(line)
            found.append(
                (
                    match.group("action"),
                    match.group("sha"),
                    comment.group(1) if comment else "",
                    f"{path.name}:{line_no}",
                )
            )
    return found


def cache_path(action: str, sha: str) -> Path:
    return CACHE / f"{action.replace('/', '__')}__{sha}.json"


def resolve(action: str, sha: str, token: str | None, offline: bool) -> tuple[bool, str]:
    """Return (resolves, detail). Never returns False for an unreachable network."""
    path = cache_path(action, sha)
    if path.exists():
        record = json.loads(path.read_text(encoding="utf-8"))
        return bool(record["resolves"]), str(record["detail"])

    if offline:
        raise Unreachable(
            f"{action}@{sha} is not in the cache and --offline was requested; "
            "run without --offline to verify it against GitHub"
        )

    status, body = _get(f"{API}/repos/{action}/commits/{sha}", token)
    if status == 200:
        record = json.loads(body)
        detail = f"{record.get('sha', sha)[:12]} {record.get('commit', {}).get('message', '').splitlines()[0]}"
        resolves = record.get("sha", "") == sha
        if not resolves:
            detail = f"upstream returned sha {record.get('sha')!r} for {sha}"
    elif status in NOT_FOUND:
        resolves, detail = False, f"HTTP {status}: no such commit upstream"
    else:
        raise Unreachable(f"unexpected HTTP {status} from {API}/repos/{action}/commits/{sha}")

    CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"resolves": resolves, "detail": detail}, indent=2),
        encoding="utf-8",
    )
    return resolves, detail


def tag_matches(action: str, sha: str, version: str, token: str | None) -> str:
    """Best-effort: is `version` the tag that resolves to `sha`? Empty = not asked."""
    if not version:
        return ""
    status, body = _get(f"{API}/repos/{action}/git/ref/tags/v{version}", token)
    if status != 200:
        return f"tag v{version} does not exist upstream"
    ref = json.loads(body)["object"]
    if ref["type"] == "tag":  # annotated: peel to the commit
        status, body = _get(f"{API}/repos/{action}/git/tags/{ref['sha']}", token)
        if status != 200:
            return f"annotated tag v{version} could not be dereferenced"
        ref = json.loads(body)["object"]
    if ref["sha"] != sha:
        return f"tag v{version} points at {ref['sha'][:12]}, not {sha[:12]}"
    return ""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        action="store_true",
        help="print every pin and its status; never exits non-zero",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="use only the local cache; a pin absent from the cache is an error",
    )
    args = parser.parse_args()

    token = None
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        token = os.environ.get(name) or None
        if token:
            break

    pins = collect_pins()
    distinct = sorted({(action, sha) for action, sha, _, _ in pins})
    if not distinct:
        print("no pinned actions found; nothing to verify")
        return 0

    print(f"=== action pins ({len(pins)} reference(s), {len(distinct)} distinct) ===")
    problems: list[str] = []
    unreachable: list[str] = []

    for index, (action, sha) in enumerate(distinct):
        if index >= CALLS_PER_HOST:
            unreachable.append(
                f"{action}@{sha} was not checked; more than {CALLS_PER_HOST} distinct pins"
            )
            continue
        try:
            resolves, detail = resolve(action, sha, token, args.offline)
        except Unreachable as exc:
            unreachable.append(str(exc))
            print(f"  UNVERIFIED  {action}@{sha[:12]}  {exc}")
            continue

        versions = sorted({v for a, s, v, _ in pins if (a, s) == (action, sha) and v})
        note = ""
        if resolves and versions:
            try:
                mismatch = tag_matches(action, sha, versions[0], token)
            except Unreachable as exc:
                # The commit itself resolved; only the comment cross-check is
                # unavailable. That is a gap in the report, not in the pin, so
                # record it and keep sweeping instead of aborting.
                unreachable.append(f"{action}@{sha} tag cross-check: {exc}")
                mismatch = ""
            if mismatch:
                note = f"  [{mismatch}]"
                if not args.report:
                    problems.append(f"{action}@{sha} is commented #{versions[0]} but {mismatch}")

        sites = sorted({src for a, s, _, src in pins if (a, s) == (action, sha)})
        status = "ok " if resolves else "BAD"
        print(f"  {status}        {action}@{sha[:12]}  {detail}{note}")
        print(f"                used at {', '.join(sites)}")
        if not resolves and not args.report:
            problems.append(
                f"{action}@{sha} does not exist upstream; GitHub cannot resolve the "
                f"action, so every workflow using it fails at setup ({', '.join(sites)})"
            )

    if args.report:
        return 0

    if unreachable:
        print()
        print(f"PIN VERIFICATION INCOMPLETE ({len(unreachable)} pin(s) unverified):")
        for item in unreachable:
            print(f"  - {item}")
        print(
            "This is a hard failure on purpose. Reporting success for pins that were "
            "never resolved is how a bad SHA reaches a release."
        )
        return 1

    print()
    if problems:
        print(f"ACTION PIN VALIDATION FAILED ({len(problems)} problem(s)):")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(f"all {len(distinct)} pinned action(s) resolve to real upstream commits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
