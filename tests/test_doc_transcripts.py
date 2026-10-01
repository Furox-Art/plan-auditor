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

# A check that fails by exit code alone. Deliberately stderr-free so the rendered
# transcript is byte-identical across Python versions and platforms: a real
# traceback gains frames (e.g. 3.11+ adds the source line and caret), which would
# make a documented transcript correct on one CI matrix leg and wrong on another.
SENTINEL_TITLE = "the sentinel script exits nonzero"
SENTINEL_CMD = 'python -c "import sys; sys.exit(3)"'


def _failing_plan(workspace: Path) -> Path:
    """A one-step plan whose check always fails, with no version-specific output."""
    plan = {
        "task": "Show what a failing check looks like",
        "created": "2026-10-01T00:00:00",
        "steps": [
            {
                "id": 1,
                "title": SENTINEL_TITLE,
                "verify": [{"type": "run", "cmd": SENTINEL_CMD, "expect_exit": 0}],
                "status": "pending",
            }
        ],
    }
    (workspace / ".plan-auditor").mkdir(parents=True)
    (workspace / ".plan-auditor" / "plan.json").write_text(
        json.dumps(plan, indent=2) + "\n", encoding="utf-8"
    )
    return workspace / ".plan-auditor" / "plan.json"


def _tail(proc: subprocess.CompletedProcess, limit: int = 600) -> str:
    """Decoded tail of a raw-bytes result, for assertion messages only."""
    raw = (proc.stdout or b"") + (proc.stderr or b"")
    return raw.decode("utf-8", errors="replace")[-limit:]


def _lines(raw: bytes | str) -> list[str]:
    """Split raw tool output the way a POSIX reader sees it.

    The core joins a captured traceback into a single physical line separated by
    ``" | "``. On Windows the captured child output uses ``\\r\\n``, so the join
    leaves a bare ``\\r`` before each separator. Any text-mode reader applies
    universal-newline translation and turns that into a line break, making the
    same output look like one line per traceback frame. We always read bytes and
    normalise ``\\r`` ourselves, so the comparison is platform-independent and
    matches what the tool prints on POSIX.
    """
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    return text.replace("\r\n", "\n").replace("\r", "").split("\n")


def _reset_step_one(plan_path: Path) -> None:
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    plan["steps"][0]["status"] = "pending"
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")


def _core_run(workspace: Path) -> subprocess.CompletedProcess:
    """Run the core and return raw bytes so no newline translation is applied."""
    return subprocess.run(
        [sys.executable, "scripts/audit_check.py", "run", str(workspace), "1"],
        cwd=str(ROOT),
        capture_output=True,
        timeout=300,
    )


def _real_failing_run(tmp_path: Path) -> list[str]:
    """Run the deterministic core through the attempt cap and the refusal."""
    workspace = tmp_path / "failing"
    plan_path = _failing_plan(workspace)
    lines: list[str] = []
    for _ in range(3):
        _reset_step_one(plan_path)
        lines.extend(_lines(_core_run(workspace).stdout))
    # Consume the attempt budget for real rather than editing evidence.
    for _ in range(3):
        _core_run(workspace)
    lines.extend(_lines(_core_run(workspace).stdout))
    return [line.rstrip() for line in lines if line.strip()]


def _assert_attempt_transcript(observed: list[str]) -> None:
    """Every attempt and the refusal must be present, in order."""
    for attempt in (1, 2, 3):
        assert any(
            f"{SENTINEL_TITLE} (deneme {attempt}/3)" in line for line in observed
        ), f"attempt {attempt} missing from {observed[-800:]}"
    assert "       - KALDI | exit=3 (beklenen 0)" in observed, observed[-800:]
    assert any("[ATLADI]" in line for line in observed), observed[-800:]


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
        line.rstrip()
        for line in block
        if line.strip() and not line.startswith("$ ") and line.strip() != "..."
    ]


def test_failing_transcript_check_fixtures_are_real(tmp_path: Path) -> None:
    """Guard the fixture itself: the transcript we compare against must be real."""
    observed = _real_failing_run(tmp_path)
    _assert_attempt_transcript(observed)
    # The sentinel check writes no stderr, so nothing version-specific may leak in.
    joined = "\n".join(observed)
    assert "Traceback" not in joined, observed[-800:]
    assert "çıktı:" not in joined, observed[-800:]


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
def test_no_transcript_pins_version_specific_traceback_frames(document: Path) -> None:
    """Documented tracebacks must not name frames that vary by Python version.

    Python 3.11+ adds the offending source line and a caret to tracebacks, so a
    transcript that quotes frames verbatim is correct on some CI legs and wrong
    on others. The documented attempt transcripts use a stderr-free check
    precisely to avoid this; any traceback shown elsewhere must therefore be
    scoped rather than pinned.
    """
    text = document.read_text(encoding="utf-8")
    for line in text.splitlines():
        if "Traceback (most recent call last)" not in line:
            continue
        assert not re.search(r"\|\s*\^+", line), (
            f"{document.name} pins a caret frame that Python 3.11+ adds: {line!r}"
        )
        assert SENTINEL_TITLE not in line, (
            f"{document.name} mixes the sentinel transcript with a traceback"
        )


@pytest.mark.parametrize("document", [README, BENCHMARK, QUICKSTART, CLI_DOC])
def test_failure_blocks_state_their_scope(document: Path) -> None:
    """A failure transcript must either be complete or say exactly what it omits."""
    text = document.read_text(encoding="utf-8")
    for block in _console_blocks(text):
        if not any("[FAIL]" in line or "[ATLADI]" in line for line in block):
            continue
        elides = any(line.strip() == "..." for line in block)
        start = text.find("\n".join(block))
        preceding = text[max(0, start - 1400) :]
        following = text[start + len("\n".join(block)) :][:1400]
        nearby = preceding + following
        if elides:
            assert re.search(r"scoped omission|omitted|elided", nearby, re.I), (
                f"{document.name} elides output without saying so"
            )
        else:
            assert re.search(r"nothing is elided|nothing above is elided", nearby, re.I), (
                f"{document.name} shows a failure transcript without stating its scope"
            )


def test_benchmark_transcript_matches_the_real_fib_failure(tmp_path: Path) -> None:
    """docs/benchmark.md quotes a fib example; compare it to a real broken fib."""
    if shutil.which("python") is None:
        pytest.skip("python is required to reproduce the fib example")
    workspace = tmp_path / "fib"
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
            timeout=300,
        )
        assert proc.returncode == 0, _tail(proc)
    proc = subprocess.run(
        [sys.executable, "-m", "supervisor.cli", "run", str(workspace)],
        cwd=str(ROOT),
        capture_output=True,
        timeout=300,
    )
    observed = [
        line.rstrip()
        for line in _lines((proc.stdout or b"") + (proc.stderr or b""))
        if line.strip() and "RuntimeWarning" not in line
    ]
    joined = "\n".join(observed)
    assert proc.returncode == 1, f"broken fib must fail: {observed[-600:]}"
    assert "AssertionError" in joined, observed[-800:]
    assert "Traceback (most recent call last)" in joined, observed[-800:]
    text = BENCHMARK.read_text(encoding="utf-8")
    # The traceback interior is version-dependent, so the doc must scope the
    # omission rather than pin frames no single interpreter renders. Only a line
    # that actually starts the marker counts as a quoted transcript line.
    for block in _console_blocks(text):
        quoted = [
            line
            for line in block
            if line.lstrip().startswith("çıktı:") or line.strip().startswith("| ")
        ]
        assert not quoted, (
            "benchmark.md must not quote the traceback body inside a transcript; "
            f"scope the omission instead: {quoted}"
        )
    assert "Scoped omission" in text, "benchmark.md must scope its omission"
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
            timeout=300,
        )
        assert proc.returncode == 0, _tail(proc)

    proc = subprocess.run(
        ["node", str(ROOT / "index.js"), "run", str(workspace)],
        cwd=str(ROOT),
        capture_output=True,
        timeout=300,
    )
    observed = [
        line.rstrip()
        for line in _lines((proc.stdout or b"") + (proc.stderr or b""))
        if line.strip() and "RuntimeWarning" not in line
    ]
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