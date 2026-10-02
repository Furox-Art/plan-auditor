"""Regression coverage for the npm launchers.

``package.json`` maps the ``plan-auditor`` bin to ``bin/plan-auditor.js``, so that
file is what ``npx plan-auditor`` actually executes; ``index.js`` is the ``main``
module and is also runnable directly. Both must mirror the verifier's exit code,
otherwise a failing audit silently becomes a passing one in CI -- the exact
failure mode this project exists to prevent.

The parameterised tests cover every entry point, and the installed-tarball test
covers what npm would really publish.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

import pytest

from tests.trusted_workspace import establish_trust

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "index.js"
BIN = ROOT / "bin" / "plan-auditor.js"

# Every way a user can reach the CLI through Node. `bin` is what npx/npm publish
# resolves; `index` is `main` and is runnable directly.
LAUNCHERS = {"bin": BIN, "index": INDEX}

# Resolved once at import time: the module-level skip guard runs first, and every
# helper below must use this absolute path so a test cannot depend on PATH lookup
# (which is exactly what the fail-closed test deliberately removes).
NODE = shutil.which("node")
NPM = shutil.which("npm")

pytestmark = pytest.mark.skipif(
    NODE is None, reason="node is required for the npm launcher"
)


def _npm() -> list[str]:
    """Absolute npm command; resolved at import so PATH changes cannot break it."""
    assert NPM is not None, "npm is required for the packed-tarball tests"
    return [NPM]

FAILING_CMD = 'python -c "import sys; sys.exit(3)"'
PASSING_CMD = "python -c \"print('launcher ok')\""


def _write_plan(workspace: Path, *, command: str, title: str) -> Path:
    plan = {
        "task": "npm launcher must not mask the verifier's verdict",
        "created": "2026-10-01T00:00:00",
        "requirements": [
            {"id": "REQ-001", "description": "the declared check behaviour", "priority": "must"}
        ],
        "steps": [
            {
                "id": 1,
                "title": title,
                "covers": ["REQ-001"],
                "verify": [{"type": "run", "cmd": command, "expect_exit": 0}],
                "status": "pending",
            }
        ],
    }
    (workspace / ".plan-auditor").mkdir(parents=True)
    path = workspace / ".plan-auditor" / "plan.json"
    path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return path


def _failing_plan(workspace: Path) -> None:
    _write_plan(workspace, command=FAILING_CMD, title="the sentinel script exits nonzero")
    establish_trust(workspace)


def _passing_plan(workspace: Path) -> None:
    _write_plan(workspace, command=PASSING_CMD, title="the check really passes")
    establish_trust(workspace)


def _launcher(name: str) -> Path:
    path = LAUNCHERS[name]
    assert path.is_file(), f"missing launcher {path}"
    return path


def _run_launcher(
    entry: Path,
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    assert NODE is not None
    return subprocess.run(
        [NODE, str(entry), *args],
        cwd=str(cwd or ROOT),
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )


@pytest.fixture(params=sorted(LAUNCHERS), ids=sorted(LAUNCHERS))
def launcher(request: pytest.FixtureRequest) -> Path:
    """Each Node entry point, so no one can regress while the others hold."""
    return _launcher(request.param)


def test_launcher_propagates_failure_exit_code(launcher: Path, tmp_path: Path) -> None:
    """A failing step must not leave the launcher reporting success."""
    workspace = tmp_path / "failing"
    _failing_plan(workspace)
    result = _run_launcher(launcher, ["run", str(workspace), "1"])
    assert result.returncode != 0, (
        f"{launcher.name} reported success for a failing step; "
        f"stdout={result.stdout[-800:]!r} stderr={result.stderr[-800:]!r}"
    )


def test_launcher_propagates_blocked_audit_exit_code(launcher: Path, tmp_path: Path) -> None:
    """A failing audit must surface the supervisor's blocking code (1 or 2)."""
    workspace = tmp_path / "blocked"
    _failing_plan(workspace)
    audit = _run_launcher(launcher, ["audit", str(workspace)])
    assert audit.returncode in (1, 2), (
        f"{launcher.name} must return the supervisor's FAIL/UNBLOCKED code, got "
        f"{audit.returncode}; stdout={audit.stdout[-800:]!r}"
    )


def test_launcher_reports_success_exit_code(launcher: Path, tmp_path: Path) -> None:
    """The success path must stay 0, so the fix cannot simply always fail."""
    workspace = tmp_path / "passing"
    _passing_plan(workspace)
    result = _run_launcher(launcher, ["run", str(workspace), "1"])
    assert result.returncode == 0, (
        f"{launcher.name} must exit 0 on a verified step; "
        f"stdout={result.stdout[-800:]!r} stderr={result.stderr[-800:]!r}"
    )


def test_launcher_exit_code_matches_the_underlying_cli(launcher: Path, tmp_path: Path) -> None:
    """The launcher must not invent a code: it has to equal the real CLI's."""
    import sys

    workspace = tmp_path / "parity"
    _failing_plan(workspace)
    direct = subprocess.run(
        [sys.executable, "-m", "supervisor.cli", "run", str(workspace), "1"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    through = _run_launcher(launcher, ["run", str(workspace), "1"])
    assert through.returncode == direct.returncode, (
        f"{launcher.name} returned {through.returncode} but the CLI returned "
        f"{direct.returncode}"
    )


def test_launcher_fails_closed_when_python_is_unavailable(launcher: Path, tmp_path: Path) -> None:
    """Point PATH at an empty directory so the interpreter cannot be found.

    The spawn must fail and the launcher must exit nonzero rather than reporting
    success, since no verdict was ever produced.
    """
    empty = tmp_path / "empty-bin"
    empty.mkdir()
    env = {"PATH": str(empty), "SystemRoot": str(Path.home())}
    result = _run_launcher(launcher, ["--help"], env=env, timeout=120)
    assert result.returncode != 0, (
        f"{launcher.name} must fail closed when it cannot start Python; "
        f"stdout={result.stdout[-400:]!r}"
    )


def test_launcher_help_succeeds(launcher: Path) -> None:
    result = _run_launcher(launcher, ["--help"])
    assert result.returncode == 0, result.stderr[-800:]


@pytest.mark.parametrize("source", [INDEX, BIN], ids=["index.js", "bin/plan-auditor.js"])
def test_launcher_source_propagates_exit_code(source: Path) -> None:
    text = source.read_text(encoding="utf-8")
    if source is BIN:
        # The bin file must reach the propagating helper, not bare runPython.
        assert "runPythonAndPropagate" in text, (
            "bin/plan-auditor.js is what npx executes; it must use "
            "runPythonAndPropagate so the exit code is not discarded"
        )
        assert "runPython(process.argv" not in text, (
            "bin/plan-auditor.js calls bare runPython, which drops the child's code"
        )
    if source is INDEX:
        assert "process.exit(code === null ? FAILURE_EXIT_CODE : code)" in text
        assert "child.on('close'" in text
        assert "child.on('error'" in text


def _pack_tarball() -> Path:
    """Build the exact tarball `npm publish` would upload."""
    proc = subprocess.run(
        [*_npm(), "pack", "--pack-destination", tempfile.gettempdir()],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-800:]
    produced = [line.strip() for line in proc.stdout.splitlines() if line.strip().endswith(".tgz")]
    assert produced, proc.stdout
    return Path(tempfile.gettempdir()) / produced[-1]


requires_npm = pytest.mark.skipif(NPM is None, reason="npm is required to pack the tarball")


def test_package_json_bin_field_points_at_the_propagating_launcher() -> None:
    """`npx plan-auditor` resolves the `bin` field, so it must not point at a bare spawn."""
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    target = package["bin"]["plan-auditor"].lstrip("./")
    assert target == "bin/plan-auditor.js", f"unexpected bin target: {target}"
    body = (ROOT / target).read_text(encoding="utf-8")
    assert "runPythonAndPropagate" in body
    assert "runPython(process.argv" not in body


@requires_npm
def test_installed_tarball_propagates_exit_codes(tmp_path: Path) -> None:
    """Exercise what npm really installs, not just the working tree.

    This is the entry point a user gets from ``npx plan-auditor``: the packed
    tarball, unpacked and run from its own directory. A failure here means the
    published package swallows the verifier's verdict even if the repo looks right.
    """
    tarball = _pack_tarball()
    unpacked = tmp_path / "unpacked"
    unpacked.mkdir()
    with tarfile.open(tarball) as archive:
        members = [m for m in archive.getmembers() if not m.name.startswith("/")]
        for member in members:
            if ".." in Path(member.name).parts:
                raise AssertionError(f"unsafe path in tarball: {member.name}")
        archive.extractall(unpacked, filter="data")
    package_root = unpacked / "package"
    entry = package_root / "bin" / "plan-auditor.js"
    assert entry.is_file(), f"packed tarball has no {entry}"

    workspace = tmp_path / "packed-failing"
    _failing_plan(workspace)

    failing = _run_launcher(entry, ["run", str(workspace), "1"], cwd=package_root)
    assert failing.returncode != 0, (
        "the packed tarball's launcher reported success for a failing step; "
        f"stdout={failing.stdout[-800:]!r}"
    )
    blocked = _run_launcher(entry, ["audit", str(workspace)], cwd=package_root)
    assert blocked.returncode in (1, 2), (
        f"packed launcher returned {blocked.returncode} for a blocked audit"
    )

    passing_workspace = tmp_path / "packed-passing"
    _passing_plan(passing_workspace)
    passing = _run_launcher(entry, ["run", str(passing_workspace), "1"], cwd=package_root)
    assert passing.returncode == 0, (
        f"packed launcher must exit 0 on success; stdout={passing.stdout[-800:]!r} "
        f"stderr={passing.stderr[-800:]!r}"
    )
    try:
        tarball.unlink()
    except OSError:
        pass


@requires_npm
def test_packed_tarball_ships_every_runtime_dependency() -> None:
    """The launcher imports `../index.js`, which imports `supervisor.cli`."""
    tarball = _pack_tarball()
    with tarfile.open(tarball) as archive:
        names = {name.split("/", 1)[-1] for name in archive.getnames()}
    for required in (
        "index.js",
        "bin/plan-auditor.js",
        "supervisor/cli.py",
        "supervisor/__init__.py",
        "scripts/audit_check.py",
    ):
        assert required in names, f"packed tarball is missing {required}"
    try:
        tarball.unlink()
    except OSError:
        pass