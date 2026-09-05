"""Cross-platform smoke test for the built wheel and installed console script.

This intentionally runs the installed ``plan-auditor`` entry point from a
fresh virtual environment whose working directory is outside the repository.
That prevents the source checkout from masking missing wheel files or broken
console-script installation.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], capture: bool = False) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(str(item) for item in argv))
    return subprocess.run(
        argv,
        cwd=str(cwd),
        env=env,
        check=True,
        text=True,
        capture_output=capture,
    )


def _venv_python(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def _console_script(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "plan-auditor.exe"
    return venv / "bin" / "plan-auditor"


def _single_wheel(directory: Path) -> Path:
    wheels = sorted(directory.resolve().glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {directory}, found {len(wheels)}: {wheels}")
    return wheels[0]


def _verify_wheel_contents(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        required = {
            "supervisor/cli.py",
            "supervisor/orchestrator.py",
            "scripts/audit_check.py",
            "scripts/plan_graph.py",
        }
        missing = sorted(required - names)
        if missing:
            raise SystemExit(f"wheel is missing runtime files: {missing}")
        entry_points = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        if len(entry_points) != 1:
            raise SystemExit(f"wheel must contain one entry_points.txt, found: {entry_points}")
        text = archive.read(entry_points[0]).decode("utf-8")
        if "plan-auditor" not in text or "supervisor.cli:entrypoint" not in text:
            raise SystemExit("wheel entry point does not expose plan-auditor -> supervisor.cli:entrypoint")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel-dir", default="dist")
    parser.add_argument("--work-dir")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    wheel = _single_wheel(Path(args.wheel_dir))
    _verify_wheel_contents(wheel)

    if args.work_dir:
        root = Path(args.work_dir).resolve()
    else:
        runner_temp = os.environ.get("RUNNER_TEMP")
        root = Path(runner_temp).resolve() / "plan-auditor-wheel-cli-smoke" if runner_temp else Path(tempfile.mkdtemp(prefix="plan-auditor-wheel-cli-smoke-"))
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    venv = root / "venv"
    workspace = root / "workspace"
    workspace.mkdir()

    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
    vpy = _venv_python(venv)
    cli = _console_script(venv)
    if not vpy.is_file():
        raise SystemExit(f"virtualenv python missing: {vpy}")

    clean_env = os.environ.copy()
    clean_env.pop("PYTHONPATH", None)
    clean_env.pop("PYTHONHOME", None)
    clean_env.pop("PLAN_AUDITOR_HMAC_KEY", None)
    clean_env.pop("PLAN_AUDITOR_HMAC_KEY_FILE", None)
    clean_env["PYTHONNOUSERSITE"] = "1"

    _run([str(vpy), "-m", "pip", "install", "--no-deps", str(wheel)], cwd=root, env=clean_env)
    if not cli.is_file():
        raise SystemExit(f"installed console script missing: {cli}")

    origin = _run(
        [str(vpy), "-c", "import pathlib, supervisor; print(pathlib.Path(supervisor.__file__).resolve())"],
        cwd=root,
        env=clean_env,
        capture=True,
    ).stdout.strip()
    print("installed supervisor origin:", origin)
    origin_path = Path(origin).resolve()
    try:
        origin_path.relative_to(venv.resolve())
    except ValueError as exc:
        raise SystemExit(f"supervisor was not imported from fresh venv: {origin_path}") from exc
    try:
        origin_path.relative_to(repo_root)
    except ValueError:
        pass
    else:
        raise SystemExit(f"source checkout leaked into installed-wheel smoke: {origin_path}")

    pg = workspace / ".plan-auditor"
    pg.mkdir()
    output = workspace / "wheel-smoke-output.txt"
    plan = {
        "task": "Verify installed wheel and console CLI",
        "created": datetime.now(timezone.utc).isoformat(),
        "steps": [
            {
                "id": 1,
                "title": "execute behavioral check from installed wheel",
                "verify": [
                    {
                        "type": "run",
                        "argv": [
                            str(vpy),
                            "-c",
                            "from pathlib import Path; Path('wheel-smoke-output.txt').write_text('wheel-ok', encoding='utf-8')",
                        ],
                        "expect_exit": 0,
                    }
                ],
                "outputs": [
                    {
                        "name": "wheel-smoke-output",
                        "verify": [{"type": "file_exists", "path": "wheel-smoke-output.txt"}],
                    }
                ],
            }
        ],
    }
    (pg / "plan.json").write_text(json.dumps(plan, indent=2), encoding="utf-8")

    help_result = _run([str(cli), "--help"], cwd=root, env=clean_env, capture=True)
    if "Plan Auditor" not in help_result.stdout or "plan-auditor" not in help_result.stdout:
        raise SystemExit("installed console script help output is incomplete")

    _run([str(cli), "validate", str(workspace)], cwd=root, env=clean_env)
    _run([str(cli), "plan", "verify", str(workspace)], cwd=root, env=clean_env)
    _run([str(cli), "audit", str(workspace)], cwd=root, env=clean_env)

    doctor = _run([str(cli), "doctor", str(workspace)], cwd=root, env=clean_env, capture=True)
    doctor_data = json.loads(doctor.stdout)
    outcome = (doctor_data.get("assessment") or {}).get("outcome")
    if outcome != "PASS":
        raise SystemExit(f"installed-wheel doctor assessment is {outcome!r}, expected PASS")

    _run([str(cli), "task", "list", str(workspace)], cwd=root, env=clean_env)
    _run([str(cli), "agents", "list", str(workspace)], cwd=root, env=clean_env)
    _run([str(cli), "evidence", "verify", str(workspace)], cwd=root, env=clean_env)

    if output.read_text(encoding="utf-8") != "wheel-ok":
        raise SystemExit("behavioral smoke output was not produced by the audited command")

    print(f"wheel/CLI smoke PASS: platform={sys.platform} wheel={wheel.name} cli={cli}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
