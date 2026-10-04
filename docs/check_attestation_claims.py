#!/usr/bin/env python3
"""Guard every supply-chain provenance/attestation claim against a channel-scoped rule.

Why this exists
---------------
Three different mechanisms get blurred into the single word "attested":

1. a **digest** (``dist.integrity`` / ``digests.sha256``) -- proves the bytes you
   received are the bytes that were published, and nothing about how they were built;
2. npm's ``dist.signatures`` -- a **registry transport signature** over the
   packument, signed by npm for every package whether or not it was ever built in CI;
3. a **build attestation** (Sigstore/in-toto on npm, PEP 740 on PyPI) -- the only one
   of the three that says a named workflow, repository and commit produced the
   artifact.

The measured state of this project, re-checkable with ``--online``:

============  ===============  ==========================================
Channel       Build attested? Endpoint
============  ===============  ==========================================
PyPI          yes             ``/integrity/<proj>/<ver>/<file>/provenance``
npm           no              ``/-/npm/v1/attestations/<pkg>@<ver>`` -> 404
============  ===============  ==========================================

Rules enforced, on prose in the documents that state *current* facts:

- a supply-chain provenance/attestation claim must name a channel (PyPI or npm),
  because a claim that names no channel cannot be checked against either;
- it must state a definite status, not a vague gesture;
- ``dist.signatures`` must never be presented as attestation or provenance, anywhere,
  including the changelog;
- a version called "current" must be the pinned current version.

Deliberate exclusions, because they are not the same claim:

- **"Provenance" meaning measurement lineage.** ``docs/benchmark.md`` uses it for
  where a number came from. That is unrelated and is not inspected.
- **"Provenance" meaning source-plan lineage.** ``docs/formal-planning.md`` uses it
  for the ``formalization-source:<SHA256>`` marker. Also unrelated.
  The trigger below requires a supply-chain token, so both are skipped.
- **Fenced code blocks and markdown table rows.** In a shell example the channel is
  in the URL on the same line but the status is on the next, and in the per-channel
  table the channel is the row's first cell. Exempting them is why the rule is stated
  about prose.
- **``CHANGELOG.md``** is scanned only for the ``dist.signatures`` blur. A changelog
  records what was written when; rewriting history is not the goal.

Runnable four ways::

    python docs/check_attestation_claims.py             # scan the repo docs
    python docs/check_attestation_claims.py --online    # also re-measure the registries
    python docs/check_attestation_claims.py --json     # machine-readable
    python docs/check_attestation_claims.py --self-test # negative control

``--self-test`` is the negative control: it feeds this guard deliberately false claim
texts and fails if any is accepted. A guard that cannot be shown to reject a known lie is
not a guard.
"""

from __future__ import annotations

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

#: Bumped together with the release.
CURRENT_VERSION = "2.4.3"

#: Documents that state current facts. Strict rules apply to their prose.
CURRENT_FACT_DOCS = ("README.md", "SECURITY.md")
CURRENT_FACT_GLOBS = ("docs/**/*.md", "SKILL.md", "CONTRIBUTING.md")

#: History. Only the dist.signatures blur rule applies, because that one is wrong
#: wherever it appears.
HISTORY_DOCS = ("CHANGELOG.md",)

#: A line is about supply-chain provenance only if it has one of these. This is what
#: keeps "provenance for every number" and "source SHA-256 provenance" out.
SUPPLY_CHAIN = re.compile(
    r"attestation|attested|sigstore|in-toto|\bslsa\b|pep[ -]?740|"
    r"\bnpm\b|\bpypi\b|registry|tarball|dist\.signatures|dist\.integrity|trusted publish",
    re.I,
)

#: The word that carries the claim, on top of the supply-chain context.
CLAIM = re.compile(r"provenance|attestation|attested|sigstore|in-toto|\bslsa\b|pep[ -]?740", re.I)

#: A claim must name a channel, or it cannot be checked against one.
CHANNEL = re.compile(r"\bpypi\b|\bnpm\b", re.I)

#: A claim must be definite. Copulas are deliberately NOT status words: "the npm
#: attestation status is complicated" is a sentence with a copula and no status, and
#: that is exactly what this rule exists to catch.
STATUS_NEGATIVE = re.compile(
    r"\b(?:no|not|none|never|without|absent|absence|404|pending|unattended|unattested|"
    r"cannot|can't|neither|nor|fails?)\b",
    re.I,
)
STATUS_AFFIRMATIVE = re.compile(
    r"\b(?:attested|yes|carries|carried|serves|attaches|publishes|provides|exists|"
    r"only|returns)\b",
    re.I,
)
STATUS = re.compile(
    STATUS_NEGATIVE.pattern.strip("r\\b") + r"|" + STATUS_AFFIRMATIVE.pattern.strip("r\\b"),
    re.I,
)

#: Negations that make a ``dist.signatures`` sentence honest rather than wrong.
NEGATION = re.compile(
    r"\b(?:not|no|never|rather than|instead|is not|does not|cannot|unrelated|transport|neither)\b",
    re.I,
)

#: How each channel is expected to answer, and where to ask.
ONLINE_EXPECTATIONS = {
    "pypi": (
        "https://pypi.org/integrity/plan-auditor/"
        f"{CURRENT_VERSION}/plan_auditor-{CURRENT_VERSION}-py3-none-any.whl/provenance",
        200,
    ),
    "npm": (
        f"https://registry.npmjs.org/-/npm/v1/attestations/plan-auditor@{CURRENT_VERSION}",
        404,
    ),
}


def _strip_code_fences(lines: list[str]) -> list[bool]:
    """Return, per line, whether it is inside a fenced code block."""
    inside = False
    flags: list[bool] = []
    for line in lines:
        if line.lstrip().startswith("```"):
            inside = not inside
            flags.append(True)
            continue
        flags.append(inside)
    return flags


def _is_table_row(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and stripped.endswith("|")


def current_fact_files() -> list[Path]:
    found: list[Path] = []
    for rel in CURRENT_FACT_DOCS:
        path = ROOT / rel
        if path.is_file():
            found.append(path)
    for pattern in CURRENT_FACT_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            if path.is_file() and path not in found:
                found.append(path)
    return found


def history_files() -> list[Path]:
    return [ROOT / rel for rel in HISTORY_DOCS if (ROOT / rel).is_file()]


def _logical_units(lines: list[str]) -> list[tuple[int, str, str]]:
    """Group wrapped prose into logical units.

    Returns ``(first_line_number, kind, text)`` where kind is ``prose``, ``other``,
    ``table`` or ``code``. Prose sentences are joined across soft wraps, because
    Markdown hard-wraps at ~80 columns and a rule that only looked at one physical
    line would demand the channel and the status word land on the same line -- which
    is a formatting rule, not a truth rule.
    """
    in_code = _strip_code_fences(lines)
    units: list[tuple[int, str, str]] = []
    buffer: list[str] = []
    start = 0

    def flush() -> None:
        nonlocal buffer, start
        if buffer:
            units.append((start, "prose", " ".join(buffer)))
            buffer = []

    for index, line in enumerate(lines, 1):
        if in_code[index - 1]:
            flush()
            units.append((index, "code", line))
            continue
        stripped = line.strip()
        if not stripped:
            flush()
            continue
        if _is_table_row(line) or stripped.startswith("#"):
            flush()
            units.append((index, "table" if _is_table_row(line) else "other", line))
            continue
        # A hard break (list item, blockquote) ends the current sentence group.
        if stripped.startswith(("-", "*", ">", "|")) and buffer:
            flush()
        if not buffer:
            start = index
        buffer.append(stripped)
    flush()
    return units


def _prose_problems(path: Path) -> list[str]:
    """Strict channel/status rules, applied to logical prose units."""
    rel = path.relative_to(ROOT).as_posix()
    units = _logical_units(path.read_text(encoding="utf-8").splitlines())
    problems: list[str] = []

    for number, kind, text in units:
        if kind != "prose":
            continue
        if not (SUPPLY_CHAIN.search(text) and CLAIM.search(text)):
            continue
        if not CHANNEL.search(text):
            problems.append(
                f"{rel}:{number}: supply-chain provenance/attestation claim names no "
                f"channel (PyPI or npm), so it cannot be checked against either: {text}"
            )
        elif not STATUS.search(text):
            problems.append(
                f"{rel}:{number}: supply-chain provenance/attestation claim states no "
                f"definite status: {text}"
            )
    return problems


def _signature_problems(path: Path) -> list[str]:
    """The dist.signatures blur rule. Applies everywhere, code blocks included.

    A shell line that *inspects* the field (``npm view ... dist.signatures``) is an
    instruction, not a claim, so command lines are exempt. A comment in a code block is
    prose and is still checked.
    """
    rel = path.relative_to(ROOT).as_posix()
    command = re.compile(r"^\s*(?:\$\s*)?(?:npm|curl|python|node|gh)\s")
    problems: list[str] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if "dist.signatures" not in line:
            continue
        if command.match(line):
            continue
        if not NEGATION.search(line):
            problems.append(
                f"{rel}:{number}: dist.signatures presented without a negation; it is a "
                f"registry transport signature and never build provenance: {line.strip()}"
            )
    return problems


def _version_problems(path: Path) -> list[str]:
    """Flag a *stale* version only where that version is the one called current.

    Deliberately sentence-scoped: one table row can call `2.4.3` current and name
    `2.4.0` and `2.4.1` as defective in the same breath, and the defective ones are
    not claims to be current.
    """
    rel = path.relative_to(ROOT).as_posix()
    problems: list[str] = []
    text = path.read_text(encoding="utf-8")
    for index, line in enumerate(text.splitlines(), 1):
        # In a table row each cell is its own claim. Without this, the support floor
        # in `>= 2.4.2` and the current version in the next cell look like one
        # sentence naming two "current" versions.
        segments = [c for c in line.split("|")] if _is_table_row(line) else [line]
        for segment in segments:
            for sentence in re.split(r"(?<=[.!?])\s+", segment):
                if "current" not in sentence.lower():
                    continue
                if re.search(r"\b(?:was|were|superseded|no longer|not the)\b", sentence, re.I):
                    continue
                for raw in re.findall(r"`(\d+\.\d+\.\d+)`|\b(\d+\.\d+\.\d+)\b", sentence):
                    found = raw[0] or raw[1]
                    if found and found != CURRENT_VERSION:
                        problems.append(
                            f"{rel}:{index}: calls {found} the current release; the current "
                            f"release is {CURRENT_VERSION}: {sentence.strip()}"
                        )
    return sorted(set(problems))


def _pypi_404_trap_problems(path: Path) -> list[str]:
    """A PyPI integrity 404 means 'no such URL', not 'no attestation'.

    If a non-``/provenance`` integrity shape is quoted at all, the docs must say the
    404 is a missing endpoint -- otherwise a reader repeats the inversion that produced
    the claim this guard was written to correct.
    """
    text = path.read_text(encoding="utf-8")
    if "pypi.org/integrity" not in text:
        return []
    quoted_non_endpoint = re.search(r"pypi\.org/integrity/[^\s)`\"']*/(?![^\s)`\"']*provenance)", text)
    if not quoted_non_endpoint:
        return []
    if re.search(r"not an endpoint|no such URL|means .{0,40}no such|absence of a collection|not evidence", text, re.I):
        return []
    return [
        f"{path.relative_to(ROOT).as_posix()}: quotes a PyPI integrity URL without "
        f"'/provenance'. That 404 means 'no such URL', not 'no attestation', and the "
        f"docs must say so."
    ]


def findings(strict_paths: list[Path] | None = None, all_paths: list[Path] | None = None) -> list[str]:
    problems: list[str] = []
    strict = strict_paths if strict_paths is not None else current_fact_files()
    everything = all_paths if all_paths is not None else (strict + history_files())

    for path in strict:
        problems += _prose_problems(path)
        problems += _version_problems(path)
        problems += _pypi_404_trap_problems(path)
    for path in everything:
        problems += _signature_problems(path)
    return problems


# --------------------------------------------------------------------------
# Online re-measurement
# --------------------------------------------------------------------------


def _status(url: str, timeout: float = 40.0) -> int | None:
    request = urllib.request.Request(url, headers={"User-Agent": "plan-auditor-attestation-guard"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(getattr(response, "status", 200) or 200)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def online_problems() -> list[str]:
    problems: list[str] = []
    for channel, (url, expected) in ONLINE_EXPECTATIONS.items():
        observed = _status(url)
        if observed is None:
            problems.append(f"{channel}: could not reach {url} (network error); verdict withheld")
        elif observed != expected:
            problems.append(
                f"{channel}: {url} returned HTTP {observed}, the docs state {expected}. "
                f"Either the registry changed or the docs are stale."
            )
        else:
            print(f"  {channel:5} HTTP {observed} as documented   {url}")
    return problems


# --------------------------------------------------------------------------
# Negative control
# --------------------------------------------------------------------------

#: (description, text) that MUST be rejected, with the positive control that must pass.
NEGATIVE_CONTROLS: tuple[tuple[str, str], ...] = (
    (
        "unscoped attestation claim",
        "The release is attested, so you can trust it.\n",
    ),
    (
        "dist.signatures presented as provenance",
        "npm `dist.signatures` is a provenance attestation for the tarball.\n",
    ),
    (
        "stale version called current",
        "`2.4.2` is the current release on both registries.\n",
    ),
    (
        "vague gesture, no definite status",
        "npm and PyPI attestation status is complicated.\n",
    ),
    (
        "attestation claimed with no channel",
        "Every artifact carries an attestation; verify before installing.\n",
    ),
)

POSITIVE_CONTROL = (
    "PyPI publishes every artifact with a PEP 740 provenance attestation; npm has no\n"
    "provenance attestation and its attestations endpoint returns `404` for one.\n"
)

#: Must be *skipped*, not flagged: same word, different meaning.
NON_SUPPLY_CHAIN: tuple[tuple[str, str], ...] = (
    ("measurement provenance", "## Provenance for every number on this page\n"),
    ("source-plan provenance", "+--> source SHA-256 provenance\n"),
)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def self_test() -> int:
    failures: list[str] = []
    scratch = ROOT / "docs" / ".attestation-guard-selftest.md"
    scratch_rel = scratch.relative_to(ROOT).as_posix()
    try:
        for description, text in NEGATIVE_CONTROLS:
            _write(scratch, text)
            if not findings(strict_paths=[scratch], all_paths=[scratch]):
                failures.append(f"  ACCEPTED a false claim ({description}): {text.strip()}")
            else:
                print(f"  rejected: {description}")
        _write(scratch, POSITIVE_CONTROL)
        accepted = not findings(strict_paths=[scratch], all_paths=[scratch])
        if accepted:
            print("  accepted: a correct channel-scoped claim")
        else:
            failures.append("  REJECTED a correct, channel-scoped claim: the guard is too strict")
        for description, text in NON_SUPPLY_CHAIN:
            _write(scratch, text)
            if findings(strict_paths=[scratch], all_paths=[scratch]):
                failures.append(f"  false positive: flagged '{description}': {text.strip()}")
            else:
                print(f"  correctly skipped: {description}")
    finally:
        scratch.unlink(missing_ok=True)
    if failures:
        print(f"FAIL negative control in {scratch_rel}:")
        print("\n".join(failures))
        return 1
    print(
        f"OK: {len(NEGATIVE_CONTROLS)} false claims rejected, "
        f"{len(NON_SUPPLY_CHAIN)} unrelated senses skipped, correct claim accepted"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guard supply-chain attestation claims.")
    parser.add_argument("--online", action="store_true", help="also re-measure both registries")
    parser.add_argument("--self-test", action="store_true", help="run the negative control only")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    strict = current_fact_files()
    everything = strict + history_files()
    problems = findings(strict_paths=strict, all_paths=everything)
    if args.online:
        print("re-measuring the registries:")
        problems += online_problems()

    if args.json:
        print(json.dumps({
            "current_version": CURRENT_VERSION,
            "strict": [p.relative_to(ROOT).as_posix() for p in strict],
            "history": [p.relative_to(ROOT).as_posix() for p in everything if p not in strict],
            "problems": problems,
        }, indent=2))
        return 1 if problems else 0

    print(f"current version pinned to {CURRENT_VERSION}")
    print(f"strict ({len(strict)}):")
    for path in strict:
        print(f"  {path.relative_to(ROOT).as_posix()}")
    print(f"blur-rule only ({len(everything) - len(strict)}):")
    for path in everything:
        if path not in strict:
            print(f"  {path.relative_to(ROOT).as_posix()}")
    if problems:
        print(f"\nFAIL: {len(problems)} attestation-claim problem(s):")
        for problem in problems:
            print(f"  {problem}")
        return 1
    print("\nPASS: every supply-chain provenance claim names a channel and a definite status")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())