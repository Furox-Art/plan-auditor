"""Deterministic docs and package-metadata consistency checks.

These checks are intentionally offline and standard-library only: every claim the
README and the docs site make about the CLI, the file tree, the package metadata
and the published artifacts must be mechanically true, or the suite fails.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from supervisor.cli import _build_parser

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
README = ROOT / "README.md"
MKDOCS = ROOT / "mkdocs.yml"
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_JSON = ROOT / "package.json"
SKILL = ROOT / "SKILL.md"
CITATION = ROOT / "CITATION.cff"
WORKFLOWS = ROOT / ".github" / "workflows"

# Supply-chain signals the project never configures, so the docs must never imply
# them. ``provenance`` is deliberately not here: it is handled separately by
# ``test_readme_has_no_unverifiable_trust_badges``, because the two registries
# differ and the README has to be able to say which one attests and which does not.
NEVER_CLAIMED_SIGNALS = [
    "scorecard",
    "openssf",
    "slsa",
]

UNVERIFIED_ADOPTION = [
    re.compile(r"\b\d[\d.,]*\s*\+?\s*(?:github\s+)?(?:stars?|forks?|dependents?|watchers?)\b", re.I),
    re.compile(r"\b\d[\d.,]*\s*\+?\s*(?:downloads?|installs?|weekly\s+downloads?)\b", re.I),
    re.compile(r"\b\d[\d.,]*\s*\+?\s*(?:users?|developers?|companies|teams|organi[sz]ations)\s+(?:trust|use|rely)", re.I),
    re.compile(r"\btrusted by\b", re.I),
    re.compile(r"\bused by\s+\d", re.I),
    re.compile(r"\b\d[\d.,]*\s*\+?\s*(?:daily|weekly|monthly)\s+(?:downloads?|installs?)\b", re.I),
]

# Fraction claims are the shape a fabricated comparison table takes. The CLI's own
# attempt counter prints `attempt 1/3`, so that specific spelling is exempt.
COMPARATIVE_FRACTION = re.compile(r"\b\d+\s*/\s*\d+\b")
ATTEMPT_COUNTER = re.compile(r"attempt\s*\d+\s*/\s*\d+", re.I)

UNVERIFIED_RESULTS = [
    re.compile(r"\bwe\s+(?:tested|ran|measured|benchmarked|surveyed)\b", re.I),
    COMPARATIVE_FRACTION,
    re.compile(r"\b\d+(?:\.\d+)?\s*%"),
    re.compile(r"\bothers?\b", re.I),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _toml_block(text: str, name: str) -> str:
    pattern = re.compile(r"^\[" + re.escape(name) + r"\]\s*$(.*?)(?=^\[|\Z)", re.M | re.S)
    match = pattern.search(text)
    assert match is not None, f"missing [{name}] table in pyproject.toml"
    return match.group(1)


def _toml_string(block: str, key: str) -> str:
    match = re.search(r'^' + re.escape(key) + r'\s*=\s*"([^"]+)"', block, re.M)
    assert match is not None, f"missing {key!r}"
    return match.group(1)


def _toml_list(block: str, key: str) -> list[str]:
    match = re.search(r"^" + re.escape(key) + r"\s*=\s*\[(.*?)\]", block, re.M | re.S)
    assert match is not None, f"missing {key!r} list"
    return re.findall(r'"([^"]+)"', match.group(1))


def _code_fences(text: str) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = []
    info = ""
    buf: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("```"):
            if info or buf:
                blocks.append((info, buf))
            info = stripped[3:].strip()
            buf = []
            continue
        if info:
            buf.append(line)
    if info or buf:
        blocks.append((info, buf))
    return blocks


def _markdown_files() -> list[Path]:
    return [README, *sorted(DOCS.glob("*.md")), SKILL, ROOT / "CONTRIBUTING.md", ROOT / "SECURITY.md"]


def _nav_targets(text: str) -> dict[str, str]:
    nav = re.search(r"^nav:\s*$(.*?)(?=^\S|\Z)", text, re.M | re.S)
    assert nav is not None, "mkdocs.yml has no nav section"
    return dict(re.findall(r"^\s*-\s*([^:\n]+):\s*(\S+)\s*$", nav.group(1), re.M))


def _package_version() -> str:
    return json.loads(_read(PACKAGE_JSON))["version"]


def _subcommands() -> dict[str, set[str] | None]:
    parser = _build_parser()
    top: dict[str, set[str] | None] = {}
    for action in parser._actions:
        if not hasattr(action, "choices") or not action.choices:
            continue
        for name, sub in action.choices.items():
            inner: set[str] | None = None
            for sub_action in sub._actions:
                if getattr(sub_action, "choices", None):
                    inner = set(sub_action.choices)
                    break
            top[name] = inner
    return top


def test_mkdocs_nav_targets_all_exist() -> None:
    targets = _nav_targets(_read(MKDOCS))
    assert targets, "mkdocs nav is empty"
    for label, target in targets.items():
        assert not target.startswith("http"), f"nav entry {label!r} must be a local doc"
        assert (DOCS / target).is_file(), f"nav entry {label!r} points at missing docs/{target}"


def test_every_docs_page_is_reachable_from_nav() -> None:
    targets = set(_nav_targets(_read(MKDOCS)).values())
    pages = {page.name for page in DOCS.glob("*.md")}
    assert pages - targets == set(), f"orphaned docs pages: {sorted(pages - targets)}"


def test_nav_exposes_core_documentation_coherently() -> None:
    targets = list(_nav_targets(_read(MKDOCS)).values())
    for required in ("index.md", "quickstart.md", "cli.md", "architecture.md", "threat-model.md", "integrations.md"):
        assert required in targets, f"mkdocs nav must expose {required}"


def test_relative_markdown_links_resolve() -> None:
    for source in _markdown_files():
        for target in re.findall(r"\]\(([^)\s]+)\)", _read(source)):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            resolved = (source.parent / target.split("#", 1)[0]).resolve()
            assert resolved.exists(), f"{source.relative_to(ROOT)} links to missing {target}"


def test_readme_badges_reference_real_workflows() -> None:
    readme = _read(README)
    for workflow in re.findall(r"/actions/workflows/([A-Za-z0-9._-]+)/badge\.svg", readme):
        assert (WORKFLOWS / workflow).is_file(), f"README badge references missing workflow {workflow}"


def test_no_dynamic_pypi_download_badges() -> None:
    """shields.io's pypi download endpoints answer 200 while rendering "downloads:
    inaccessible" or a rate-limit notice, so the badge looks broken in the README.
    A download claim must be a link to the package page, never a rendered image or
    a number copied by hand.
    """
    offenders: list[str] = []
    for source in _markdown_files():
        text = _read(source)
        for line_no, line in enumerate(text.splitlines(), 1):
            if re.search(r"img\.shields\.io/pypi/d", line):
                offenders.append(f"{source.relative_to(ROOT)}:{line_no}: {line.strip()}")
            for pattern in UNVERIFIED_ADOPTION:
                match = pattern.search(line)
                if match:
                    offenders.append(
                        f"{source.relative_to(ROOT)}:{line_no}: hand-copied count {match.group(0)!r}"
                    )
    assert not offenders, "dynamic or hand-copied download claims:\n  " + "\n  ".join(offenders)


def test_readme_points_at_the_pypi_project_page_for_downloads() -> None:
    readme = _read(README)
    assert "https://pypi.org/project/plan-auditor/" in readme, (
        "README must link the PyPI project page, which is where download numbers live"
    )
    assert "download numbers live on the package pages" in readme.lower(), (
        "README must say where download numbers come from instead of showing a badge"
    )


def test_readme_has_no_unverifiable_trust_badges() -> None:
    """No supply-chain signal may be claimed unless it is real.

    ``scorecard``, ``openssf`` and ``slsa`` stay banned outright: the project
    configures no such badge or level, so any mention would be a claim.

    ``provenance`` is different, and is now scoped rather than banned. The two
    registries genuinely differ -- PyPI publishes through trusted publishing and
    serves a PEP 740 attestation, while npm ``2.4.2`` has none -- so the README
    has to be able to say so. Every mention must therefore name a registry or
    state an absence. That keeps the original intent (never imply a signal you do
    not have) and makes it checkable per sentence instead of by word count.
    """
    text = _read(README)
    lowered = text.lower()

    for marker in NEVER_CLAIMED_SIGNALS:
        assert marker not in lowered, (
            f"README must not imply a {marker} signal that is not configured"
        )

    scoped = re.compile(
        r"pypi|npm|not\b|no\b|without|absent|absence|404|cannot|mint",
        re.I,
    )
    offenders = [
        f"  line {number}: {line.strip()}"
        for number, line in enumerate(text.splitlines(), 1)
        if "provenance" in line.lower() and not scoped.search(line)
    ]
    assert not offenders, (
        "every README mention of provenance must name a registry or state an "
        "absence; these do neither:\n" + "\n".join(offenders)
    )


def test_readme_states_the_npm_attestation_gap() -> None:
    """The npm attestation gap is a documented fact, not an omission.

    Guarding the negative claim in both directions: the README must say npm has
    no provenance attestation, so nobody reads the PyPI attestation as covering
    both registries.
    """
    lowered = _read(README).lower()
    assert "npm" in lowered
    assert re.search(
        r"npm[^.]*?provenance|npm[^.]*?attestation|attestation[^.]*?npm",
        lowered,
        re.S,
    ), "README must state npm's attestation status explicitly"
    assert re.search(r"\b404\b|no provenance|not attested|without.{0,40}attestation", lowered), (
        "README must state that npm 2.4.2 carries no provenance attestation"
    )


@pytest.mark.parametrize("source", _markdown_files(), ids=lambda p: p.name)
def test_docs_make_no_unverified_adoption_claims(source: Path) -> None:
    text = _read(source)
    for pattern in UNVERIFIED_ADOPTION:
        match = pattern.search(text)
        assert match is None, f"{source.name}: unverified adoption claim {match.group(0)!r}"


def test_benchmark_doc_makes_no_unverified_comparative_claims() -> None:
    text = ATTEMPT_COUNTER.sub("attempt", _read(DOCS / "benchmark.md"))
    for pattern in UNVERIFIED_RESULTS:
        match = pattern.search(text)
        assert match is None, f"benchmark.md: unverified claim {match.group(0)!r}"
    assert "examples/fib" in text, "benchmark.md must point at the runnable in-repo example"


def test_readme_adoption_region_covers_the_essentials() -> None:
    """Everything a visitor needs to try the tool appears before the doc index.

    The region used to end at ``## Troubleshooting``. Troubleshooting now lives
    only in ``docs/quickstart.md`` -- it is a page of per-error guidance and
    duplicated it here -- so the sentinel is the Documentation section instead.
    The orderings below are the point of the test and are unchanged.
    """
    readme = _read(README)
    assert readme.lstrip().startswith("# plan-auditor")
    adoption = readme.split("\n## Documentation", 1)
    assert len(adoption) == 2, "README must have a Documentation section"
    region = adoption[0]
    for needle in (
        "## The problem",
        "## The solution",
        "## Who it is for",
        "## Install",
        "## Quick start (verified, 5 minutes)",
        "pipx install plan-auditor",
        "pip install plan-auditor",
        "plan-auditor run . 1",
        "plan-auditor audit .",
    ):
        assert needle in region, f"README adoption region must show {needle!r}"
    assert region.index("## The problem") < region.index("## Install")
    assert region.index("## Install") < region.index("## Quick start (verified, 5 minutes)")


def test_readme_points_at_the_full_troubleshooting_page() -> None:
    """Deleting the inline Troubleshooting section must not lose the guidance.

    The README no longer carries the per-error walkthroughs, so it has to link the
    page that does, or a reader who hits ``request contract is not activated`` has
    nothing to click.
    """
    readme = _read(README)
    assert "docs/quickstart.md" in readme, "README must link docs/quickstart.md"
    quickstart = _read(DOCS / "quickstart.md")
    assert "## Troubleshooting" in quickstart, (
        "docs/quickstart.md must carry the troubleshooting section the README points at"
    )
    assert "request contract is not activated" in quickstart, (
        "the most common failure mode must still be documented somewhere reachable"
    )


def test_readme_links_project_signals() -> None:
    readme = _read(README)
    for needle in ("SECURITY.md", "CHANGELOG.md", "docs/threat-model.md", "docs/cli.md", "SKILL.md"):
        assert needle in readme, f"README must link {needle}"


def test_readme_does_not_advertise_a_nonexistent_python_api() -> None:
    readme = _read(README)
    assert "from plan_auditor import" not in readme
    assert "plan_auditor." not in readme


def test_documented_cli_invocations_exist() -> None:
    surface = _subcommands()
    assert surface, "CLI surface is empty"
    pattern = re.compile(
        r"^\s*(?:\$|#)?\s*(?:npx\s+|uvx\s+)?"
        r"(plan-auditor(?:-formal|-formalize|-migrate-seal)?)\b\s*([a-z][a-z-]*)?"
    )
    problems: list[str] = []
    for source in _markdown_files():
        for info, body in _code_fences(_read(source)):
            if info in {"json", "jsonc", "text", "python", "py"}:
                continue
            for line in body:
                match = pattern.match(line)
                if not match:
                    continue
                executable, first = match.group(1), match.group(2)
                if executable != "plan-auditor":
                    continue
                if first is None:
                    continue
                if first not in surface:
                    problems.append(f"{source.name}: `{executable} {first}` is not a command")
                elif surface[first] is not None and match.group(2):
                    rest = line[match.end(2) :].strip()
                    token = next((part for part in rest.split() if not part.startswith("-")), None)
                    if token and token not in surface[first]:
                        problems.append(
                            f"{source.name}: `{executable} {first} {token}` is not a command"
                        )
    assert not problems, "; ".join(problems)


def test_pyproject_metadata_is_complete_and_consistent() -> None:
    text = _read(PYPROJECT)
    project = _toml_block(text, "project")
    version = _toml_string(project, "version")
    assert _toml_string(project, "readme") == "README.md"
    assert (ROOT / "README.md").is_file()
    assert _toml_string(project, "license") == "MIT"
    assert "LICENSE" in _toml_list(project, "license-files")
    assert (ROOT / "LICENSE").is_file()

    classifiers = _toml_list(project, "classifiers")
    assert "License :: OSI Approved :: MIT License" in classifiers
    assert "Development Status :: 4 - Beta" in classifiers
    assert "Topic :: Software Development :: Quality Assurance" in classifiers
    for minor in ("3.10", "3.11", "3.12", "3.13"):
        assert f"Programming Language :: Python :: {minor}" in classifiers
    assert not any(c.startswith("License ::") and "MIT" not in c for c in classifiers)

    keywords = _toml_list(project, "keywords")
    assert len(keywords) >= 10
    assert len(keywords) == len(set(keywords))
    assert all(k == k.lower() and " " not in k for k in keywords)

    urls = dict(
        re.findall(r'^([A-Za-z]+)\s*=\s*"([^"]+)"', _toml_block(text, "project.urls"), re.M)
    )
    assert {"Homepage", "Repository", "Issues", "Documentation", "Changelog", "Security"} <= set(urls)
    slug = re.search(r"github\.com/([^/]+/[^/#?]+)", urls["Repository"]).group(1)
    for key in ("Homepage", "Issues"):
        assert slug in urls[key]
    assert urls["Changelog"].endswith("/CHANGELOG.md")
    assert urls["Security"].endswith("/SECURITY.md")
    assert urls["Documentation"].endswith("/tree/main/docs")
    assert re.fullmatch(r"\d+\.\d+\.\d+", version)
    assert version == _package_version(), "pyproject and package.json versions must match"


def test_project_urls_resolve_to_repository_paths() -> None:
    text = _read(PYPROJECT)
    urls = dict(
        re.findall(r'^([A-Za-z]+)\s*=\s*"([^"]+)"', _toml_block(text, "project.urls"), re.M)
    )
    assert urls, "project.urls is empty"
    # GitHub-managed destinations are not files in the tree.
    managed = {"issues", "releases", "tags", "pulls", "actions", "security", "graphs"}
    for key, url in urls.items():
        assert url.startswith("https://github.com/"), f"{key} must be a repository URL: {url}"
        path = url.split("https://github.com/", 1)[1].split("/", 2)
        repo_path = "/".join(path[2:])
        for prefix in ("tree/main/", "blob/main/"):
            if repo_path.startswith(prefix):
                repo_path = repo_path[len(prefix) :]
                assert (ROOT / repo_path).exists(), f"{key} points at missing path {repo_path}"
                break
        else:
            head = repo_path.split("/", 1)[0]
            assert not repo_path or head in managed, f"{key} points at non-file path {repo_path}"


def test_versions_agree_across_package_skill_and_citation() -> None:
    project = _toml_block(_read(PYPROJECT), "project")
    version = _toml_string(project, "version")
    skill = re.search(r'version:\s*"([^"]+)"', _read(SKILL)).group(1)
    citation = re.search(r"^version:\s*(\S+)", _read(CITATION), re.M).group(1)
    package = json.loads(_read(PACKAGE_JSON))["version"]
    assert version == skill == citation == package


def test_package_json_describes_a_working_npm_launcher() -> None:
    package = json.loads(_read(PACKAGE_JSON))
    assert package["main"] == "index.js"
    assert (ROOT / package["main"]).is_file()
    for name, target in package["bin"].items():
        assert name.startswith("plan-auditor")
        resolved = target.lstrip("./")
        path = ROOT / resolved
        assert path.is_file(), f"npm bin {target} is missing"
        # npx executes this file, so it must mirror the verifier's exit code.
        body = path.read_text(encoding="utf-8")
        assert "runPythonAndPropagate" in body, (
            f"{resolved} is what npx executes; it must propagate the child's exit code"
        )
        assert "runPython(process.argv" not in body, (
            f"{resolved} calls bare runPython, which discards the child's exit code"
        )
    scripts = package.get("scripts", {})
    assert scripts.get("test") == "node --check index.js && node --check bin/plan-auditor.js"
    assert "files" in package
    for required in ("index.js", "bin", "supervisor", "scripts", "LICENSE"):
        assert required in package["files"], f"npm files allowlist must ship {required}"
    assert package["license"] == "MIT"
    assert package["repository"]["url"].startswith("git+https://github.com/")


def test_npm_launcher_forwards_to_the_python_cli() -> None:
    index = _read(ROOT / "index.js")
    assert "supervisor.cli" in index
    assert "spawn(" in index
    assert not re.search(r"=>\s*;\s*\}", index), "index.js must not contain a broken arrow body"


def test_npm_tarball_ships_no_interpreter_or_build_artifacts() -> None:
    package = json.loads(_read(PACKAGE_JSON))
    for pattern in ("!**/__pycache__", "!**/*.py[cod]"):
        assert pattern in package["files"], f"npm files must exclude {pattern}"
    npmignore = ROOT / ".npmignore"
    assert npmignore.is_file(), "a .npmignore must keep local artifacts out of the tarball"
    rules = {
        line.strip()
        for line in _read(npmignore).splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    assert {"__pycache__/", ".venv/", "node_modules/"} <= rules
    assert len(rules) <= 20, f".npmignore should stay minimal, got {sorted(rules)}"
    # The launcher cannot work without the Python package at runtime, so no
    # ignore rule may exclude the directories it needs.
    for required in ("supervisor", "scripts", "hooks", "references"):
        assert required in package["files"], f"npm files must ship {required}"
        assert not any(rule.rstrip("/") == required for rule in rules), (
            f".npmignore must not exclude runtime directory {required!r}"
        )