"""Cross-platform smoke test for the built wheel and installed console script.

Runs the installed CLI from a clean virtual environment outside the source
checkout and exercises multi-plan aggregation, explicit DAG/output contracts,
requirement coverage, full-contract seals and external-key HMAC integrity.
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
    return subprocess.run(argv, cwd=str(cwd), env=env, check=True, text=True, capture_output=capture)


def _venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _console_script(venv: Path) -> Path:
    return venv / ("Scripts/plan-auditor.exe" if os.name == "nt" else "bin/plan-auditor")


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
            "supervisor/plans.py",
            "supervisor/coverage.py",
            "supervisor/contracts.py",
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
        cwd=root, env=clean_env, capture=True,
    ).stdout.strip()
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
    (pg / "plans").mkdir(parents=True)
    now = datetime.now(timezone.utc).isoformat()
    default_plan = {
        "task": "Verify installed wheel, dependency graph and CLI",
        "created": now,
        "requirements": [
            {"id": "REQ-001", "description": "Produce an upstream artifact", "priority": "must"},
            {"id": "REQ-002", "description": "Consume the verified upstream artifact", "priority": "must"},
        ],
        "required_tools": ["python"],
        "steps": [
            {
                "id": 1,
                "title": "produce upstream artifact",
                "depends_on": [],
                "covers": ["REQ-001"],
                "verify": [{
                    "type": "run",
                    "argv": [str(vpy), "-c", "from pathlib import Path; assert Path('wheel-upstream.txt').read_text(encoding='utf-8') == 'upstream-ok'"],
                    "expect_exit": 0,
                }],
                "outputs": [{
                    "name": "upstream",
                    "verify": [{"type": "file_exists", "path": "wheel-upstream.txt"}],
                }],
            },
            {
                "id": 2,
                "title": "consume upstream artifact",
                "depends_on": [1],
                "requires_outputs": [{"step": 1, "name": "upstream"}],
                "covers": ["REQ-002"],
                "verify": [{
                    "type": "run",
                    "argv": [str(vpy), "-c", "from pathlib import Path; assert Path('wheel-upstream.txt').read_text(encoding='utf-8') == 'upstream-ok'; assert Path('wheel-final.txt').read_text(encoding='utf-8') == 'final-ok'"],
                    "expect_exit": 0,
                }],
                "outputs": [{
                    "name": "final",
                    "verify": [{"type": "file_exists", "path": "wheel-final.txt"}],
                }],
            },
        ],
    }
    named_plan = {
        "task": "Verify named plan aggregation",
        "created": now,
        "requirements": [
            {"id": "REQ-N1", "description": "Execute a named-plan behavioral check", "priority": "must"}
        ],
        "required_tools": ["python"],
        "steps": [{
            "id": 1,
            "title": "named plan check",
            "covers": ["REQ-N1"],
            "verify": [{
                "type": "run",
                "argv": [str(vpy), "-c", "from pathlib import Path; assert Path('wheel-named.txt').read_text(encoding='utf-8') == 'named-ok'"],
                "expect_exit": 0,
            }],
        }],
    }
    (pg / "plan.json").write_text(json.dumps(default_plan, indent=2), encoding="utf-8")
    (pg / "plans" / "named.json").write_text(json.dumps(named_plan, indent=2), encoding="utf-8")

    request_source = {
        "format_version": 1,
        "task": "Verify the installed wheel and both active plans",
        "requirements": [
            {
                "id": "REQ-001",
                "description": "Produce an upstream artifact",
                "priority": "must",
                "acceptance_checks": default_plan["steps"][0]["verify"],
            },
            {
                "id": "REQ-002",
                "description": "Consume the verified upstream artifact",
                "priority": "must",
                "acceptance_checks": default_plan["steps"][1]["verify"],
            },
            {
                "id": "REQ-N1",
                "description": "Execute a named-plan behavioral check",
                "priority": "must",
                "acceptance_checks": named_plan["steps"][0]["verify"],
            },
        ],
    }
    request_source_path = pg / "request-source.json"
    request_source_path.write_text(json.dumps(request_source, indent=2), encoding="utf-8")

    # Product state exists before verification. Audit commands are evidence, not implementation.
    (workspace / "wheel-upstream.txt").write_text("upstream-ok", encoding="utf-8")
    (workspace / "wheel-final.txt").write_text("final-ok", encoding="utf-8")
    (workspace / "wheel-named.txt").write_text("named-ok", encoding="utf-8")

    help_result = _run([str(cli), "--help"], cwd=root, env=clean_env, capture=True)
    if "Plan Auditor" not in help_result.stdout or "plan-auditor" not in help_result.stdout:
        raise SystemExit("installed console script help output is incomplete")

    _run([str(cli), "request", "init", str(workspace), "--file", str(request_source_path)], cwd=root, env=clean_env)
    _run([str(cli), "validate", str(workspace)], cwd=root, env=clean_env)
    _run([str(cli), "validate", str(workspace), "--plan", "named"], cwd=root, env=clean_env)
    _run([str(cli), "plan", "verify", str(workspace)], cwd=root, env=clean_env)

    auth_env = clean_env.copy()
    auth_env["PLAN_AUDITOR_HMAC_KEY"] = "wheel-smoke-external-hmac-key-material-0123456789"
    _run([str(cli), "integrity", "init", str(workspace)], cwd=root, env=auth_env)
    _run([str(cli), "audit", str(workspace)], cwd=root, env=auth_env)

    doctor = _run([str(cli), "doctor", str(workspace)], cwd=root, env=auth_env, capture=True)
    doctor_data = json.loads(doctor.stdout)
    assessment = doctor_data.get("assessment") or {}
    if assessment.get("outcome") != "PASS" or assessment.get("active_plan_count") != 2:
        raise SystemExit(f"installed-wheel doctor assessment unexpected: {assessment}")
    if set(assessment.get("plans", {})) != {"default", "named"}:
        raise SystemExit("multi-plan aggregation did not expose default and named plans")

    _run([str(cli), "supervisor", "start", "--profile", "standard", "--mode", "serial", str(workspace)], cwd=root, env=auth_env)
    try:
        status_data = None
        for _ in range(40):
            proc = subprocess.run(
                [str(cli), "supervisor", "status", str(workspace)],
                cwd=str(root), env=auth_env, text=True, capture_output=True,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                try:
                    status_data = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    status_data = None
            if (
                isinstance(status_data, dict)
                and status_data.get("running") is True
                and (status_data.get("assessment") or {}).get("outcome") == "PASS"
            ):
                break
            import time
            time.sleep(0.2)
        else:
            raise SystemExit(f"installed-wheel supervisor did not reach running+PASS: {status_data}")
    finally:
        _run([str(cli), "supervisor", "stop", str(workspace)], cwd=root, env=auth_env)
    stopped = subprocess.run(
        [str(cli), "supervisor", "status", str(workspace)],
        cwd=str(root), env=auth_env, text=True, capture_output=True,
    )
    if stopped.returncode == 0:
        raise SystemExit("installed-wheel supervisor still reports running after stop")

    _run([str(cli), "task", "list", str(workspace)], cwd=root, env=auth_env)
    _run([str(cli), "agents", "list", str(workspace)], cwd=root, env=auth_env)
    _run([str(cli), "evidence", "verify", str(workspace)], cwd=root, env=auth_env)
    _run([str(cli), "integrity", "status", str(workspace)], cwd=root, env=auth_env)

    expected = {
        "wheel-upstream.txt": "upstream-ok",
        "wheel-final.txt": "final-ok",
        "wheel-named.txt": "named-ok",
    }
    for name, value in expected.items():
        if (workspace / name).read_text(encoding="utf-8") != value:
            raise SystemExit(f"behavioral smoke output mismatch: {name}")

    print(f"wheel/CLI smoke PASS: platform={sys.platform} wheel={wheel.name} cli={cli}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
