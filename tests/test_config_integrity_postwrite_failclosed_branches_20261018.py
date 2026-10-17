"""A trusted supervisor cannot accept redirected config or sign failing state."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts.integrity import IntegrityKeyError
from supervisor import config, integrity, plans, sealing


def test_symlinked_supervisor_config_is_not_loaded_even_if_target_contains_valid_json(tmp_path):
    # A per-test unique outside source; do not modify any existing user file.
    outside=tmp_path.parent/(tmp_path.name+"-external-config.json")
    outside.write_text('{"profile":"strict"}',encoding="utf-8")
    pg=tmp_path/".plan-auditor"
    pg.mkdir()
    (pg/"supervisor.json").symlink_to(outside)
    parsed=config.load_config(str(tmp_path))
    assert not parsed.valid
    assert parsed.profile==config.Profile.STANDARD
    assert any("symlink" in error for error in parsed.errors)
    outside.unlink()


def test_symlinked_custom_policy_directory_never_becomes_execution_path(tmp_path):
    pg=tmp_path/".plan-auditor"
    pg.mkdir()
    (pg/"supervisor.json").write_text(json.dumps({"policies_dir":"policies"}))
    (tmp_path/"policies").symlink_to(
        tmp_path.parent/(tmp_path.name+"-outside-policy"),target_is_directory=True
    )
    parsed=config.load_config(str(tmp_path))
    assert not parsed.valid
    assert parsed.policies_dir==".plan-auditor/__invalid_policies__"
    assert any("policy directory" in err for err in parsed.errors)


def test_repeated_config_policy_error_is_not_doubled(monkeypatch,tmp_path):
    from supervisor import policies
    monkeypatch.setattr(
        policies,"register_policy_workspace",
        lambda *_args:["unsafe configured policy","unsafe configured policy"],
    )
    problems=[]
    config._register_policy_roots(tmp_path,"policies",problems)
    assert problems==["unsafe configured policy"]


def test_unsafe_path_probe_attaches_explicit_config_error(tmp_path):
    problems=[]
    out=config._safe_path(tmp_path,"../outside",problems,"supervisor path")
    assert out is None
    assert len(problems)==1
    assert "supervisor path" in problems[0]


def prepare_key(tmp_path,monkeypatch):
    workspace=tmp_path/"workspace"
    workspace.mkdir()
    key=tmp_path/"outside.key"
    key.write_bytes(b"plan-auditor-ci-test-only-key-material-123" * 2)
    key.chmod(0o600)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE",str(key))
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY",raising=False)
    return workspace


def test_integrity_init_fails_after_written_marker_if_full_authentication_does_not_verify(
    tmp_path,monkeypatch
):
    workspace=prepare_key(tmp_path,monkeypatch)
    monkeypatch.setattr(
        integrity,"integrity_status",
        lambda *_args:{"authenticated":False,"problem":"independent HMAC verification failed"},
    )
    with pytest.raises(IntegrityKeyError,match="post-write verification"):
        integrity.initialize_integrity(workspace)


@pytest.mark.parametrize("failure",["missing","corrupt"])
def test_auth_status_reports_missing_or_tampered_plan_seal(failure,tmp_path,monkeypatch):
    workspace=prepare_key(tmp_path,monkeypatch)
    initial=integrity.initialize_integrity(workspace)
    assert initial["authenticated"] is True
    fake=SimpleNamespace(name="case-1")
    monkeypatch.setattr(plans,"all_plan_refs",lambda *_args:[fake])
    if failure=="missing":
        monkeypatch.setattr(sealing,"load_seal",lambda *_args:None)
    else:
        def corrupted(*args,**kwargs):
            raise sealing.SealIntegrityError("corrupt signed seal")
        monkeypatch.setattr(sealing,"load_seal",corrupted)
    current=integrity.integrity_status(workspace)
    assert current["authenticated"] is False
    assert current["seals"]["valid"] is False
    assert current["seals"]["count"]==0
    assert len(current["seals"]["errors"])==1
