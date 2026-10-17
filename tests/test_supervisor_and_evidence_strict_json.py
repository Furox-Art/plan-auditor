"""No ambiguous JSON fields may alter runtime policy or authenticated evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts import audit_check as core


def _config(tmp_path: Path, raw: str) -> Path:
    directory = tmp_path / ".plan-auditor"
    directory.mkdir(exist_ok=True)
    path = directory / "supervisor.json"
    path.write_text(raw, encoding="utf-8")
    return path


def _evidence(tmp_path: Path) -> Path:
    core.append_evidence(
        str(tmp_path),
        {"mode": "run", "plan": "default", "step": 1,
         "status": "failed", "results": [{"passed": False}]},
    )
    return Path(core.evidence_path(str(tmp_path)))


@pytest.mark.parametrize(
    "config",
    [
        '{"profile":"strict","profile":"light","max_attempts":3}',
        '{"max_attempts":1,"max_attempts":100}',
        '{"extra":{"mode":"strict","mode":"light"}}',
        '{"max_attempts":3,"value":NaN}',
        '{"max_attempts":3,"value":1e9999}',
        r'{"max_attempts":3,"value":"\ud800"}',
    ],
)
def test_runtime_config_rejects_ambiguous_and_nonfinite_json(
    tmp_path: Path, config: str
) -> None:
    _config(tmp_path, config)
    with pytest.raises(ValueError, match="invalid supervisor config"):
        core._validated_runtime_config(str(tmp_path))


def test_runtime_config_rejects_unbounded_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _config(tmp_path, '{"profile":"standard","padding":"' + "x" * 600 + '"}')
    monkeypatch.setattr(core, "MAX_SUPERVISOR_CONFIG_CHARS", 64)
    with pytest.raises(ValueError, match="exceeds input size limit"):
        core._validated_runtime_config(str(tmp_path))


@pytest.mark.skipif(os.name == "nt", reason="symlink privileges differ on Windows")
def test_runtime_config_does_not_follow_symlinks(tmp_path: Path) -> None:
    external = tmp_path / "external.json"
    external.write_text('{"profile":"strict"}')
    directory = tmp_path / ".plan-auditor"
    directory.mkdir()
    (directory / "supervisor.json").symlink_to(external)
    with pytest.raises(ValueError, match="symlink"):
        core._validated_runtime_config(str(tmp_path))


@pytest.mark.parametrize(
    "replacement",
    [
        '"status":"verified","status": "failed"',
        '"status":NaN,"status": "failed"',
        '"status":1e9999,"status": "failed"',
        r'"status":"\ud800","status": "failed"',
    ],
)
def test_evidence_chain_cannot_verify_ambiguous_or_invalid_json(
    tmp_path: Path, replacement: str
) -> None:
    evidence = _evidence(tmp_path)
    source = evidence.read_text(encoding="utf-8")
    mutated = source.replace('"status": "failed"', replacement, 1)
    assert mutated != source
    evidence.write_text(mutated, encoding="utf-8")
    ok, count, problem = core.verify_chain(str(tmp_path))
    assert not ok
    assert count == 0
    assert "strict JSON" in problem


def test_nested_duplicate_record_field_is_not_tolerated(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    source = evidence.read_text(encoding="utf-8")
    mutated = source.replace('"passed": false', '"passed": true, "passed": false', 1)
    assert mutated != source
    evidence.write_text(mutated, encoding="utf-8")
    assert core.verify_chain(str(tmp_path))[0] is False


def test_failed_attempt_count_cannot_skip_ambiguous_record(tmp_path: Path) -> None:
    evidence = _evidence(tmp_path)
    source = evidence.read_text(encoding="utf-8")
    mutated = source.replace('"status": "failed"', '"status":"verified","status": "failed"', 1)
    evidence.write_text(mutated, encoding="utf-8")
    with pytest.raises(ValueError, match="ambiguous or corrupt evidence record"):
        core.failed_attempt_counts(str(tmp_path))


def test_clean_config_and_evidence_remain_compatible(tmp_path: Path) -> None:
    original = {"profile": "standard", "max_attempts": 2}
    _config(tmp_path, json.dumps(original))
    assert core._validated_runtime_config(str(tmp_path)) == original
    _evidence(tmp_path)
    valid, count, message = core.verify_chain(str(tmp_path))
    assert valid and count == 1 and not message
    assert core.failed_attempt_counts(str(tmp_path))[("default", 1)] == 1
