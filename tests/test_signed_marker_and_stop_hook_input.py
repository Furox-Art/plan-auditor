"""Signed marker and Stop-hook must refuse parser-dependent JSON."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from scripts import integrity, stop_gate


def _marker(tmp_path: Path) -> tuple[Path, integrity.KeyMaterial]:
    key = integrity.KeyMaterial(key=b"z" * 32, source="test fixture", key_id="z" * 16)
    return integrity.write_marker(tmp_path, key), key


def test_original_signed_integrity_marker_remains_valid(tmp_path: Path) -> None:
    _, key = _marker(tmp_path)
    assert integrity.verify_marker(tmp_path, key)


@pytest.mark.parametrize(
    "injection",
    [
        '"mode":"bad","mode":"external-hmac"',
        '"bad":NaN,"mode":"external-hmac"',
        '"bad":1e9999,"mode":"external-hmac"',
        r'"bad":"\ud800","mode":"external-hmac"',
    ],
)
def test_signed_marker_rejects_ambiguous_or_invalid_json(
    tmp_path: Path, injection: str
) -> None:
    path, key = _marker(tmp_path)
    source = path.read_text(encoding="utf-8")
    path.write_text(
        source.replace('"mode":"external-hmac"', injection, 1),
        encoding="utf-8",
    )
    assert not integrity.verify_marker(tmp_path, key)


def test_duplicate_nested_authentication_field_is_invalid(tmp_path: Path) -> None:
    path, key = _marker(tmp_path)
    text = path.read_text(encoding="utf-8")
    text = text.replace('"alg":"hmac-sha256"', '"alg":"none","alg":"hmac-sha256"', 1)
    assert text != path.read_text(encoding="utf-8")
    path.write_text(text, encoding="utf-8")
    assert not integrity.verify_marker(tmp_path, key)


@pytest.mark.parametrize(
    "input_json",
    [
        '{"cwd":"/tmp/first","cwd":"/tmp/second"}',
        '{"cwd":{"x":1,"x":2}}',
        '{"cwd":NaN}',
        '{"cwd":1e9999}',
        r'{"cwd":"\ud800"}',
        '{"cwd":["/tmp"]}',
        '{"cwd":null,"malformed":Infinity}',
        '{"cwd":',
    ],
)
def test_stop_hook_rejects_ambiguous_or_invalid_payload(
    monkeypatch: pytest.MonkeyPatch, input_json: str
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(input_json))
    with pytest.raises((ValueError, UnicodeError)):
        stop_gate._workspace()


def test_stop_hook_input_is_bounded_before_json_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(stop_gate, "MAX_HOOK_JSON_CHARS", 32)

    class GuardedReader(io.StringIO):
        def read(self, size: int = -1) -> str:
            assert 0 < size <= 33
            return super().read(size)

    monkeypatch.setattr(sys, "stdin", GuardedReader(json.dumps({"cwd": "/tmp/" + "x" * 80})))
    with pytest.raises(ValueError, match="exceeds bounded JSON size"):
        stop_gate._workspace()


def test_stop_hook_valid_workspace_selection_is_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("COMMANDCODE_PROJECT_DIR", raising=False)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"cwd": str(tmp_path)})))
    assert stop_gate._workspace() == str(tmp_path.resolve())


def test_stop_hook_ambiguous_request_blocks_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import supervisor.orchestrator as orchestrator

    def refuse_to_evaluate(_workspace: str) -> object:
        raise AssertionError("invalid request must not reach the gate")

    monkeypatch.setattr(orchestrator, "evaluate_workspace", refuse_to_evaluate)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"cwd":"/first","cwd":"/second"}'))
    assert stop_gate.main() == 2
    assert "failed closed" in capsys.readouterr().err
