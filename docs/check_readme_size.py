#!/usr/bin/env python3
"""Keep ``README.md`` from silently re-inflating.

The README grew to nearly 500 lines because every fact someone added stayed there.
This guard makes the size budget explicit so the next addition has to be a trade,
not an append.

It measures three things, and fails if any regressed against the recorded baseline:

* total lines of ``README.md``
* total words of ``README.md``
* the line count of each ``## `` section, so one section cannot absorb the whole
  budget while the rest look fine

Usage::

    python docs/check_readme_size.py            # verify against the baseline
    python docs/check_readme_size.py --report   # print the table, do not fail
    python docs/check_readme_size.py --update   # record the current size as the budget

``--update`` is deliberately not free: it only lowers or raises the recorded
budget when the README is *smaller* than it, and it prints what it changed. A
budget that ratchets upward without anyone reading the diff is worse than no
guard, so run it deliberately and read the output.

Baseline lives next to this file in ``docs/readme_size_baseline.json``.

CI wiring: this script is not referenced by any workflow in this repository. To
enforce it, add a job to ``.github/workflows/lint.yml`` (or ``build.yml``) that
runs ``python docs/check_readme_size.py`` and then add the check name to the
``main-branch-protection`` ruleset, or the merge will not be blocked by it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
BASELINE = Path(__file__).resolve().parent / "readme_size_baseline.json"

#: A section whose name changes should not read as a budget reset, so section keys
#: are normalised to their heading text without the leading ``## ``.
SECTION = re.compile(r"^##\s+(?P<name>.+?)\s*$", re.M)


def measure() -> dict[str, object]:
    text = README.read_text(encoding="utf-8")
    lines = text.splitlines()
    sections: dict[str, int] = {}
    names = [(m.start(), m.group("name")) for m in SECTION.finditer(text)]
    for index, (offset, name) in enumerate(names):
        end = names[index + 1][0] if index + 1 < len(names) else len(text)
        sections[name] = len(text[offset:end].strip().splitlines())
    return {
        "lines": len(lines),
        "words": len(text.split()),
        "sections": sections,
    }


def load_baseline() -> dict[str, object]:
    if not BASELINE.is_file():
        raise SystemExit(
            f"missing {BASELINE.relative_to(ROOT)}; run with --update to create it"
        )
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def render(current: dict[str, object], baseline: dict[str, object] | None) -> str:
    lines = [
        f"README.md: {current['lines']} lines, {current['words']} words",
    ]
    if baseline:
        delta = current["lines"] - baseline["lines"]  # type: ignore[operator]
        direction = "over" if delta > 0 else "under"
        lines.append(
            f"  budget: {baseline['lines']} lines  "
            f"({abs(delta)} {direction} budget, {abs(delta) * 100 // max(baseline['lines'], 1)}%)"  # type: ignore[index]
        )
    lines.append("  sections:")
    for name, count in current["sections"].items():  # type: ignore[union-attr]
        allowed = (baseline or {}).get("sections", {}).get(name)  # type: ignore[union-attr]
        mark = "" if allowed is None else ("  ok" if count <= allowed else f"  OVER (budget {allowed})")
        lines.append(f"    {count:4d}  {name}{mark}")
    return "\n".join(lines)


def violations(current: dict[str, object], baseline: dict[str, object]) -> list[str]:
    problems: list[str] = []
    for field in ("lines", "words"):
        if current[field] > baseline[field]:  # type: ignore[operator]
            problems.append(
                f"{field}: {current[field]} exceeds the recorded budget of {baseline[field]}"  # type: ignore[index]
            )
    baseline_sections: dict[str, int] = baseline.get("sections", {})  # type: ignore[assignment]
    for name, count in current["sections"].items():  # type: ignore[union-attr]
        allowed = baseline_sections.get(name)
        if allowed is not None and count > allowed:
            problems.append(f"section {name!r}: {count} lines exceeds its budget of {allowed}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="record the current size as the budget")
    parser.add_argument("--report", action="store_true", help="print the table and exit 0")
    args = parser.parse_args(argv)

    current = measure()

    if args.update:
        previous = load_baseline() if BASELINE.is_file() else None
        BASELINE.write_text(
            json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(render(current, previous))
        if previous and current["lines"] > previous["lines"]:  # type: ignore[operator]
            print(
                f"\nWARNING: the budget was raised from {previous['lines']} to {current['lines']} lines."  # type: ignore[index]
                "\nThat should be a deliberate trade. Say why in the PR description."
            )
        else:
            print("\nbudget recorded")
        return 0

    baseline = load_baseline()
    print(render(current, baseline))
    if args.report:
        return 0

    problems = violations(current, baseline)
    if problems:
        print("\nREADME.md has grown past its recorded budget:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print(
            "\nDetail belongs on the docs site, not here. Move it, then run\n"
            "    python docs/check_readme_size.py --update\n"
            "if the budget really should change.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())