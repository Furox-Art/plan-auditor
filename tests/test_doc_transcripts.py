"""Documentation transcripts must reproduce real tool output verbatim.

The tool prints captured multi-line stderr as ``çıktı:`` followed by
``|``-joined continuation lines. A transcript that collapses that into one line
is not what a reader will see, so these tests compare the documented blocks
against output regenerated from a real failing run.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
BENCHMARK = ROOT / "docs" / "benchmark.md"
QUICKSTART = ROOT / "docs" / "quickstart.md"
CLI_DOC = ROOT / "docs" / "cli.md"

FALLING_TITLE = "README.md exists in the project root"
FAILING_CMD = (
    "python -c \"import sys; sys.exit(1 if 'EXPECTED' not in "
    "open('README.md', encoding='utf-8').read() else 0)\""
)


def _failing_plan(workspace: Path) -> Path:
    """A one-step plan whose check always fails because the file is missing."""
    plan = {
        "task": "Show what a failing check looks like",
        "created": "2026-10-01T00:00:00",
        "steps": [
            {
                "id": 1,
                "title": FALLING_TITLE,
                "verify": [
                    {"type": "file_exists", "path": "README.md"},
                    {"type": "run", "cmd": FAILING_CMD, "expect_exit": 0},
                ],
                "status": "pending",
            }
        ],
    }
    (workspace / ".plan-auditor").mkdir(parents=True)
    (workspace / ".plan-auditor" / "plan.json").write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8"
    )
    return workspace / ".plan-auditor" / "plan.json"


def _real_failing_run(tmp_path: Path) -> list[str]:
    """Run the deterministic core three times, then a fourth refused attempt."""
    workspace = tmp_path / "failing"
    _failing_plan(workspace)
    plan_path = workspace / ".plan-auditor" / "plan.json"
    lines: list[str] = []
    for _ in range(3):
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        plan["steps"][0]["status"] = "pending"
        plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "scripts/audit_check.py", "run", str(workspace), "1"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
        lines.extend((proc.stdout + proc.stderr).replace("\r\n", "\n").splitlines())
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["steps"][0]["status"] = "pending"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    # Consume the attempt budget with real runs rather than rewriting evidence.
    for _ in range(3):
        subprocess.run(
            [sys.executable, "scripts/audit_check.py", "run", str(workspace), "1"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
    proc = subprocess.run(
        [sys.executable, "scripts/audit_check.py", "run", str(workspace), "1"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    lines.extend((proc.stdout + proc.stderr).replace("\r\n", "\n").splitlines())
    return [line for line in lines if line.strip()]


def _console_blocks(text: str) -> list[list[str]]:
    blocks: list[list[str]] = []
    inside = False
    buf: list[str] = []
    for line in text.splitlines():
        if line.strip().startswith("```"):
            if inside:
                blocks.append(buf)
                buf = []
            inside = not inside
            continue
        if inside:
            buf.append(line)
    return blocks


def _output_lines(block: list[str]) -> list[str]:
    """Strip ``$ command`` prompt lines and lone elision markers."""
    return [
        line
        for line in block
        if line.strip() and not line.startswith("$ ") and line.strip() != "..."
    ]


def test_failing_transcript_check_fixtures_are_real(tmp_path: Path) -> None:
    """Guard the fixture itself: the transcript we compare against must be real."""
    observed = _real_failing_run(tmp_path)
    joined = "\n".join(observed)
    assert "Traceback (most recent call last):" in joined, observed[-800:]
    assert "FileNotFoundError: [Errno 2] No such file or directory" in joined, observed[-800:]
    assert any("deneme 3/3" in line for line in observed), observed[-800:]
    assert any("[ATLADI]" in line for line in observed), observed[-800:]


def _assert_verbatim(document: Path, tmp_path: Path) -> None:
    observed = _real_failing_run(tmp_path)
    documented: list[str] = []
    for block in _console_blocks(document.read_text(encoding="utf-8")):
        documented.extend(_output_lines(block))
    # Only compare the failure blocks, identified by their distinctive markers.
    failure_blocks = [
        block
        for block in _console_blocks(document.read_text(encoding="utf-8"))
        if any("[FAIL]" in line or "[ATLADI]" in line for line in block)
    ]
    assert failure_blocks, f"{document.name} must show a real failing run"
    for block in failure_blocks:
        for line in _output_lines(block):
            assert line in observed, (
                f"{document.name} shows a line the tool never emitted: {line!r}\n"
                f"real output was:\n" + "\n".join(observed[-40:])
            )
    assert documented, f"{document.name} has no documented output lines at all"


def test_readme_failure_transcript_is_verbatim(tmp_path: Path) -> None:
    _assert_verbatim(README, tmp_path)


def test_quickstart_failure_transcript_is_verbatim(tmp_path: Path) -> None:
    _assert_verbatim(QUICKSTART, tmp_path)


def test_cli_failure_transcript_is_verbatim(tmp_path: Path) -> None:
    _assert_verbatim(CLI_DOC, tmp_path)


@pytest.mark.parametrize("document", [README, BENCHMARK, QUICKSTART, CLI_DOC])
def test_no_collapsed_output_lines(document: Path) -> None:
    """A ``çıktı:`` line must never swallow the traceback that follows it."""
    offenders = [
        line
        for line in document.read_text(encoding="utf-8").splitlines()
        if line.lstrip().startswith("çıktı:")
        and ("Traceback" not in line)
        and not re.search(r"Error: \[Errno \d+\]", line)
    ]
    assert not offenders, f"{document.name} collapses tool output: {offenders}"


@pytest.mark.parametrize("document", [README, BENCHMARK, QUICKSTART, CLI_DOC])
def test_failure_blocks_state_that_nothing_is_elided(document: Path) -> None:
    """Where a failure transcript is abbreviated, say so explicitly."""
    text = document.read_text(encoding="utf-8")
    for block in _console_blocks(text):
        if not any("[FAIL]" in line or "[ATLADI]" in line for line in block):
            continue
        nearby = text[max(0, text.find("\n".join(block)) - 1200) :]
        assert re.search(r"nothing is elided|nothing above is elided|not elided", nearby, re.I), (
            f"{document.name} shows a failure transcript without stating its scope"
        )


def test_benchmark_transcript_matches_the_real_fib_failure(tmp_path: Path) -> None:
    """docs/benchmark.md quotes a fib example; compare it to a real broken fib."""
    if shutil.which("python") is None:
        pytest.skip("python is required to reproduce the fib example")
    workspace = tmp_path / "fib"
    shutil.copytree(ROOT / "examples" / "fib", workspace)
    (workspace / "fib.py").write_text("def fib(n):\n    return 0\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "supervisor.cli", "request", "init", str(workspace),
         "--file", str(workspace / "request-source.json")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout[-600:] + proc.stderr[-600:]
    proc = subprocess.run(
        [sys.executable, "-m", "supervisor.cli", "plan", "verify", str(workspace)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout[-600:] + proc.stderr[-600:]
    proc = subprocess.run(
        [sys.executable, "-m", "supervisor.cli", "run", str(workspace)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    observed = [
        line
        for line in (proc.stdout + proc.stderr).replace("\r\n", "\n").splitlines()
        if line.strip() and "RuntimeWarning" not in line
    ]
    joined = "\n".join(observed)
    assert proc.returncode == 1, f"broken fib must fail: {observed[-600:]}"
    assert "AssertionError" in joined, observed[-800:]
    text = BENCHMARK.read_text(encoding="utf-8")
    assert "çıktı: AssertionError\n" not in text, (
        "benchmark.md must not claim the tool prints a bare AssertionError line"
    )
    blocks = [
        block
        for block in _console_blocks(text)
        if any("[FAIL]" in line for line in block)
    ]
    assert blocks, "benchmark.md must show the broken-fib failure"
    for block in blocks:
        if any(line.startswith("$ node index.js") for line in block):
            continue  # launcher blocks carry an `echo $?` line; covered below
        for line in _output_lines(block):
            assert line in observed, (
                f"benchmark.md shows a line the tool never emitted: {line!r}\n"
                f"real output was:\n" + "\n".join(observed[-40:])
            )


def test_benchmark_launcher_block_matches_a_real_launcher_run(tmp_path: Path) -> None:
    """The `node index.js` block in benchmark.md must be reproducible too."""
    if shutil.which("node") is None:
        pytest.skip("node is required for the npm launcher")
    launcher_blocks = [
        block
        for block in _console_blocks(BENCHMARK.read_text(encoding="utf-8"))
        if any(line.startswith("$ node index.js") for line in block)
    ]
    assert launcher_blocks, "benchmark.md must show the launcher exit code"
    workspace = tmp_path / "fib-launcher"
    shutil.copytree(ROOT / "examples" / "fib", workspace)
    (workspace / "fib.py").write_text("def fib(n):\n    return 0\n", encoding="utf-8")
    for argv in (
        ["request", "init", str(workspace), "--file", str(workspace / "request-source.json")],
        ["plan", "verify", str(workspace)],
    ):
        proc = subprocess.run(
            [sys.executable, "-m", "supervisor.cli", *argv],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
        assert proc.returncode == 0, proc.stdout[-600:] + proc.stderr[-600:]

    observed: list[str] = []
    proc = subprocess.run(
        ["node", str(ROOT / "index.js"), "run", str(workspace)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=300,
    )
    observed.extend(
        line
        for line in (proc.stdout + proc.stderr).replace("\r\n", "\n").splitlines()
        if line.strip() and "RuntimeWarning" not in line
    )
    assert proc.returncode == 1, f"launcher must exit nonzero, got {proc.returncode}"

    block = launcher_blocks[0]
    documented_code = next(
        (line.strip() for line in block if line.strip() == str(proc.returncode)),
        None,
    )
    assert documented_code is not None, (
        f"benchmark.md must show the launcher's real exit code {proc.returncode}; block={block}"
    )
    for line in _output_lines(block):
        if line.strip().isdigit():
            assert line.strip() == documented_code, (
                f"benchmark.md shows exit code {line!r} but the launcher returned "
                f"{proc.returncode}"
            )
            continue
        assert line in observed, (
            f"benchmark.md launcher block shows a line never emitted: {line!r}\n"
            f"real output was:\n" + "\n".join(observed[-40:])
        )