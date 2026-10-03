"""The README quick start must be executable and its transcript must be real.

This test does not trust the README prose. It parses the documented files and
commands out of ``README.md``, runs them through the installed CLI entry point in
a throwaway workspace, and asserts every documented output line actually appears.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import pytest

from supervisor.cli import main

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / "README.md").read_text(encoding="utf-8")

HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


def _section(title: str) -> str:
    body = README.split(f"\n## {title}", 1)
    assert len(body) == 2, f"README must have a `## {title}` section"
    return body[1].split("\n## ", 1)[0]


def _fences(text: str) -> list[tuple[str, list[str]]]:
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


def _mask(text: str) -> str:
    return HEX64.sub("<sha256>", text.replace("\r\n", "\n"))


@pytest.fixture(scope="module")
def quickstart() -> dict[str, object]:
    section = _section("Quick start (verified, 5 minutes)")
    json_blocks = [body for info, body in _fences(section) if info == "json"]
    bash_blocks = [body for info, body in _fences(section) if info == "bash"]
    console_blocks = [body for info, body in _fences(section) if info == "console"]
    assert len(json_blocks) == 2, "quick start must document exactly two JSON files"
    assert bash_blocks, "quick start must document the commands to run"
    assert len(console_blocks) == 1, "quick start must have one transcript block"
    files = [json.loads("\n".join(body)) for body in json_blocks]
    commands = [
        line.strip()
        for body in bash_blocks
        for line in body
        if line.strip().startswith("plan-auditor ")
    ]
    transcript = ["\n".join(body) for body in console_blocks]
    return {"plan": files[0], "request": files[1], "commands": commands, "transcript": transcript}


def _workspace(tmp_path: Path, quickstart: dict) -> Path:
    workspace = tmp_path / "plan-auditor-demo"
    (workspace / ".plan-auditor").mkdir(parents=True)
    (workspace / ".plan-auditor" / "plan.json").write_text(
        json.dumps(quickstart["plan"], indent=2) + "\n", encoding="utf-8"
    )
    (workspace / "request-source.json").write_text(
        json.dumps(quickstart["request"], indent=2) + "\n", encoding="utf-8"
    )
    (workspace / "README.md").write_text("# Demo project\n", encoding="utf-8")
    return workspace


def _argv(command: str, workspace: Path) -> list[str]:
    tokens = shlex.split(command.replace("plan-auditor ", "", 1))
    resolved: list[str] = []
    for token in tokens:
        if token == ".":
            resolved.append(str(workspace))
        elif not token.startswith("-") and (workspace / token).exists():
            resolved.append(str(workspace / token))
        else:
            resolved.append(token)
    return resolved


def test_readme_quickstart_commands_really_run_and_pass(
    tmp_path: Path, quickstart: dict, capfd: pytest.CaptureFixture
) -> None:
    workspace = _workspace(tmp_path, quickstart)
    commands: list[str] = quickstart["commands"]
    assert commands == [
        "plan-auditor request init . --file request-source.json",
        "plan-auditor plan verify .",
        "plan-auditor run . 1",
        "plan-auditor audit .",
    ], "quick start command list changed; keep it in sync with the transcript"

    observed: list[str] = []
    for command in commands:
        code = main(_argv(command, workspace))
        observed.append(capfd.readouterr().out)
    captured = _mask("".join(observed))
    assert code == 0, (
        "the documented quick start must end with `plan-auditor audit` exiting 0\n"
        f"observed output:\n{captured[-3000:]}"
    )

    plan = json.loads((workspace / ".plan-auditor" / "plan.json").read_text(encoding="utf-8"))
    assert plan["steps"][0]["status"] == "verified"
    assert (workspace / ".plan-auditor" / "seal.json").is_file()
    assert (workspace / ".plan-auditor" / "evidence.jsonl").is_file()

    missing = [
        line
        for block in quickstart["transcript"]
        for line in block.splitlines()
        if line.strip()
        and line.strip() != "..."
        and not line.startswith("$ ")
        and _mask(line) not in captured
    ]
    assert not missing, f"README transcript lines are not real CLI output: {missing}"


def _key_lines(text: str) -> dict[int, list[str]]:
    """JSON object keys grouped by indentation, in document order."""
    grouped: dict[int, list[str]] = {}
    for line in text.splitlines():
        match = re.match(r'^(\s*)"([^"]+)":', line)
        if match:
            grouped.setdefault(len(match.group(1)), []).append(match.group(2))
    return grouped


def _elided_indents(text: str) -> set[int]:
    """Indentation levels where the document used a lone ``...`` elision marker."""
    return {
        len(line) - len(line.lstrip()) for line in text.splitlines() if line.strip() == "..."
    }


def _chunks_by_command(text: str) -> dict[str, str]:
    """Split a console block into ``{command: output shown for it}``."""
    chunks: dict[str, str] = {}
    command: str | None = None
    buf: list[str] = []
    for line in text.splitlines():
        if line.startswith("$ "):
            if command is not None:
                chunks[command] = "\n".join(buf)
            command = line[2:].strip()
            buf = []
            continue
        buf.append(line)
    if command is not None:
        chunks[command] = "\n".join(buf)
    return chunks


def test_readme_quickstart_hashes_are_not_normalised_away(
    tmp_path: Path, quickstart: dict, capfd: pytest.CaptureFixture
) -> None:
    """Every hash in the transcript must be the one the CLI actually printed.

    ``_mask`` exists so that the line-level comparison above is not defeated by a
    re-ordered evidence chain, but it also means that comparison alone cannot see a
    *wrong* hash: substituting any 64-hex string passes. That was verified by
    mutation -- replacing ``request_sha256`` with ``dead0...`` left the whole suite
    green, because the check is a subset test over masked text.

    So this test does the comparison without the mask. A hash in the README is
    only acceptable if the tool printed that exact digest.
    """
    workspace = _workspace(tmp_path, quickstart)
    observed: list[str] = []
    for command in quickstart["commands"]:
        main(_argv(command, workspace))
        observed.append(capfd.readouterr().out)
    verbatim = "".join(observed).replace("\r\n", "\n")

    documented = sorted(
        {match.group(0) for block in quickstart["transcript"] for match in HEX64.finditer(block)}
    )
    assert documented, "the quick start should document at least one digest"
    fabricated = [digest for digest in documented if digest not in verbatim]
    assert not fabricated, (
        "these digests appear in the README transcript but the CLI never printed "
        f"them: {fabricated}"
    )


def test_readme_quickstart_json_keys_match_the_real_output(
    tmp_path: Path, quickstart: dict, capfd: pytest.CaptureFixture
) -> None:
    """A JSON block that elides nothing must document every key the tool emits.

    The transcript comparison is a subset check, so a key the tool prints and the
    README omits -- ``policy_findings`` and ``verdict``, for instance -- is
    silently tolerated and the reader gets a shape that no longer exists. Here each
    indentation level is compared as a sequence, and only the levels where the
    document actually used a ``...`` marker are allowed to be shorter.
    """
    workspace = _workspace(tmp_path, quickstart)
    observed: list[str] = []
    for command in quickstart["commands"]:
        main(_argv(command, workspace))
        observed.append(capfd.readouterr().out)

    documented_chunks = _chunks_by_command("\n".join(quickstart["transcript"]))
    problems: list[str] = []
    for index, command in enumerate(quickstart["commands"]):
        shown = documented_chunks.get(command)
        if shown is None or not shown.strip():
            continue
        real = observed[index].replace("\r\n", "\n")
        shown_keys = _key_lines(shown)
        if not shown_keys:
            continue
        real_keys = _key_lines(real)
        elided = _elided_indents(shown)
        for indent, keys in sorted(shown_keys.items()):
            if indent in elided:
                extra = [key for key in keys if key not in real_keys.get(indent, [])]
                if extra:
                    problems.append(
                        f"{command}: keys the tool never emitted at indent {indent}: {extra}"
                    )
                continue
            if real_keys.get(indent, []) != keys:
                problems.append(
                    f"{command}: keys at indent {indent} are {keys} but the tool "
                    f"emitted {real_keys.get(indent, [])}; add a scoped '...' elision "
                    "or document the real shape"
                )
    assert not problems, "README JSON shape does not match real output:\n  " + "\n  ".join(
        problems
    )


def test_readme_quickstart_transcript_covers_every_documented_command(
    quickstart: dict,
) -> None:
    transcript = "\n".join(quickstart["transcript"])
    for command in quickstart["commands"]:
        assert f"$ {command}" in transcript, f"transcript does not show `{command}`"


def test_readme_quickstart_declares_a_behavioral_check(quickstart: dict) -> None:
    step = quickstart["plan"]["steps"][0]
    kinds = {check["type"] for check in step["verify"]}
    assert kinds & {"run", "pytest", "exec"}, "the documented step must prove behavior"
    for requirement in quickstart["request"]["requirements"]:
        assert any(
            check["type"] in {"run", "pytest", "exec"}
            for check in requirement["acceptance_checks"]
        ), "every authoritative requirement needs a behavioral acceptance check"