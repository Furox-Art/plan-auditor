"""Policy engine refuses malformed rules and keeps deterministic evidence provenance."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from supervisor import policies as p


def spec(kind, identifier="policy-1", **extra):
    result = {"id": identifier, "kind": kind, "field": "audit.trust", "level": 2}
    result.update(extra)
    return result


def test_policy_engine_collects_real_triggered_failures_in_registration_order():
    first = p._compile_policy(spec("require_truthy", identifier="ready"))
    second = p._compile_policy(spec("require_empty", identifier="clean", field="audit.errors"))
    engine = p.PolicyEngine()
    engine.add(first)
    engine.extend([second])
    result = engine.evaluate({"audit": {"trust": False, "errors": ["unsigned evidence"]}})
    assert [r.rule_id for r in result] == ["ready", "clean"]
    assert all(r.triggered for r in result)
    assert [
        r.rule_id
        for r in engine.failures({"audit": {"trust": False, "errors": ["unsigned evidence"]}})
    ] == ["ready", "clean"]


@pytest.mark.parametrize(
    ("bad", "message"),
    [
        ({"kind": "require_truthy", "field": "audit.trust"}, "missing id"),
        ({"id": "missing-kind", "field": "audit.trust"}, "missing kind"),
        ({"id": "missing-field", "kind": "require_empty"}, "missing field"),
        (spec("other"), "unknown"),
        (spec("forbid_regex", pattern=""), "no pattern"),
        (spec("forbid_regex", pattern="("), "malformed regex"),
        (spec("require_truthy", level="not-an-int"), "noninteger level"),
        (spec("require_truthy", level=99), "out-of-range level"),
    ],
)
def test_invalid_policy_specs_do_not_create_executable_rules(bad, message):
    assert p._compile_policy(bad) is None, message


def test_regex_policy_reads_only_declared_nested_field_not_unrelated_environment():
    rule = p._compile_policy(spec("forbid_regex", pattern="secret"))
    assert rule is not None
    report = rule.fn({"audit": {"trust": "safe"}, "unrelated": "secret"})
    assert not report.triggered
    observed = rule.fn({"audit": {"trust": "Secret=here"}})
    assert observed.triggered
    assert observed.evidence == "Secret"


def test_truthy_policy_fails_closed_on_missing_nested_value_and_accepts_real_explicit_true():
    rule = p._compile_policy(spec("require_truthy"))
    assert rule.fn({}).triggered
    assert not rule.fn({"audit": {"trust": True}}).triggered


def test_empty_policy_preserves_exact_reported_error_evidence():
    rule = p._compile_policy(spec("require_empty", field="audit.errors"))
    assert rule.fn({"audit": {"errors": []}}).triggered is False
    triggered = rule.fn({"audit": {"errors": ["failed real SHA", "unverified witness"]}})
    assert triggered.triggered
    assert "failed real SHA" in triggered.evidence


def test_nested_policy_value_converts_explicit_structured_data_without_using_eval():
    assert p._ctx_get({"outer": {"inner": {"foo": "bar"}}}, "outer.inner.foo") == "bar"
    assert p._ctx_get({"outer": 12}, "outer.inner") is None
    assert p._as_text(["A", "B"]) == "A\nB"
    assert p._as_text(None) == ""
    assert p._as_text({"x": 1}) == '{"x": 1}'


@pytest.mark.parametrize(
    ("literal", "expected"),
    [
        ("true", True),
        ("FALSE", False),
        ("4", 4),
        ("'explicit'", "explicit"),
        ("unquoted-identifier", "unquoted-identifier"),
    ],
)
def test_literal_policy_parser_is_bounded_to_actual_scalar_text(literal, expected):
    assert p._parse_scalar(literal) == expected


def test_simple_toml_parser_records_structural_errors_without_guessing_rules():
    source = """
unexpected = "outside"
[[rules]]
id = "policy-1"
kind = "require_truthy"
field = "audit.ready"
bad_without_equal_sign
= "missing key"
"""
    rules, errors = p._parse_simple_toml_rules(source)
    assert len(rules) == 1
    assert len(errors) == 3
    assert any("outside" in err for err in errors)
    assert any("expected key = value" in err for err in errors)
    assert any("empty key" in err for err in errors)


def test_policy_loader_reads_approved_json_and_toml_without_inventing_severity(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    (root / "one.json").write_text(
        json.dumps({"rules": [spec("require_truthy", identifier="signed")]})
    )
    (root / "two.toml").write_text(
        '[[rules]]\nid = "not-clean"\nkind = "require_empty"\nfield = "audit.errors"\nlevel = 1\n'
    )
    errors = []
    rules = p.load_policy_rules_from_dir(str(root), errors=errors)
    assert errors == []
    assert [r.rule_id for r in rules] == ["signed", "not-clean"]
    assert rules[0].fn({"audit": {"trust": True}}).triggered is False
    assert rules[1].fn({"audit": {"errors": ["bad"]}}).triggered is True


def test_policy_file_symlink_is_rejected_without_following_secret_target(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    external = tmp_path / "external.json"
    external.write_text(json.dumps({"rules": [spec("require_truthy")]}))
    (root / "linked.json").symlink_to(external)
    errors = []
    assert p.load_policy_rules_from_dir(str(root), errors) == []
    assert any("policy file cannot be a symlink" in err for err in errors)


def test_policy_root_symlink_is_rejected_without_loading_external_policies(tmp_path):
    real = tmp_path / "outside"
    real.mkdir()
    (real / "policy.json").write_text(json.dumps({"rules": [spec("require_truthy")]}))
    linked = tmp_path / "unsafe"
    linked.symlink_to(real, target_is_directory=True)
    errors = []
    assert p.load_policy_rules_from_dir(str(linked), errors) == []
    assert "policy directory cannot be a symlink" in errors[0]


def test_non_directory_policy_root_cannot_act_as_an_authoritative_rule_set(tmp_path):
    root = tmp_path / "single.json"
    root.write_text(json.dumps({"rules": [spec("require_truthy")]}))
    errors = []
    assert p.load_policy_rules_from_dir(str(root), errors) == []
    assert "not a directory" in errors[0]


def test_malformed_json_rule_and_duplicate_ids_are_diagnosed_without_silent_merge(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    (root / "bad.json").write_text("{invalid")
    (root / "duplicate.json").write_text(
        json.dumps(
            [
                spec("require_truthy", identifier="dup"),
                spec("require_empty", identifier="dup"),
                "not a structured rule",
            ]
        )
    )
    errors = []
    result = p.load_policy_rules_from_dir(str(root), errors)
    assert [r.rule_id for r in result] == ["dup"]
    assert any("invalid JSON" in err for err in errors)
    assert any("duplicate policy id" in err for err in errors)
    assert any("must be an object" in err for err in errors)


def test_invalid_rule_level_cannot_become_an_authorized_policy(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    (root / "invalid.json").write_text(json.dumps([spec("require_truthy", level=999)]))
    errors = []
    assert p.load_policy_rules_from_dir(str(root), errors) == []
    assert any("invalid policy rule" in err for err in errors)


def test_unreadable_policy_file_reports_distinct_denied_read(monkeypatch, tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    target = root / "rule.json"
    target.write_text(json.dumps([spec("require_truthy")]))
    read = Path.read_text

    def inaccessible(self, *args, **kwargs):
        if self == target:
            raise OSError("simulated denied read")
        return read(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", inaccessible)
    errors = []
    assert p.load_policy_rules_from_dir(str(root), errors) == []
    assert any("unreadable policy file" in err for err in errors)


def test_default_policy_engine_evaluates_actual_reported_state_not_fabricated_pass():
    ctx = {
        "plan_steps": [{"status": "verified", "results": [{"passed": False}]}],
        "seal_ok": False,
        "logs": ["password=exposed"],
        "evidence_valid": False,
        "agent_registry_valid": False,
        "missing_required_tools": ["git"],
        "configuration_errors": ["bad schema"],
        "policy_errors": ["invalid rule"],
    }
    triggered = p.default_engine().failures(ctx)
    ids = {x.rule_id for x in triggered}
    assert {
        "REQ_TESTS_PASS",
        "SEAL_INTACT",
        "NO_SECRET_LEAK",
        "EVIDENCE_VALID",
        "AGENT_REGISTRY_VALID",
        "TOOLS_PRESENT",
        "CONFIG_VALID",
        "POLICY_CONFIG_VALID",
    } <= ids
    assert "NO_PENDING" not in ids


def test_policy_loader_without_error_sink_still_refuses_malformed_files(tmp_path):
    root = tmp_path / "policy"
    root.mkdir()
    (root / "malformed.json").write_text("{truncated")
    (root / "wrong.json").write_text(json.dumps({"rules": {"not": "a list"}}))
    (root / "duplicate.json").write_text(
        json.dumps(
            [
                spec("require_truthy", identifier="A"),
                spec("require_empty", identifier="A"),
                spec("unknown", identifier="bad"),
                False,
            ]
        )
    )
    (root / "invalid.toml").write_text(
        'invalid = "outside"\n[[rules]]\nnot-a-valid-toml-assignment\n'
    )
    result = p.load_policy_rules_from_dir(str(root), errors=None)
    assert [rule.rule_id for rule in result] == ["A"]


def test_non_policy_extension_and_policy_named_directories_are_never_interpreted_as_rules(tmp_path):
    root = tmp_path / "policy"
    root.mkdir()
    (root / "readme.txt").write_text(json.dumps([spec("require_truthy")]))
    (root / "nested.json").mkdir()
    assert p.load_policy_rules_from_dir(str(root), errors=[]) == []


def test_malformed_json_rule_collection_is_explicitly_reported(tmp_path):
    root = tmp_path / "policy"
    root.mkdir()
    (root / "not-a-list.json").write_text(json.dumps({"rules": "not-a-list"}))
    errors = []
    assert p.load_policy_rules_from_dir(str(root), errors=errors) == []
    assert len(errors) == 1
    assert "JSON policy must be a list" in errors[0]


def test_registered_denied_symlink_target_cannot_be_reintroduced_as_trusted_policy(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    actual = tmp_path / "outside-policies"
    actual.mkdir()
    (actual / "policy.json").write_text(json.dumps([spec("require_truthy")]))
    (workspace / "policies").symlink_to(actual, target_is_directory=True)
    errors = p.register_policy_workspace(workspace, "policies")
    assert any("configured policy directory" in e for e in errors)
    issues = []
    assert p.load_policy_rules_from_dir(str(actual), issues) == []
    assert any("unsafe workspace symlink" in e for e in issues)


def test_registered_workspace_safe_policy_directory_remains_usable(tmp_path):
    workspace = tmp_path / "workspace"
    policy = workspace / "policies"
    policy.mkdir(parents=True)
    (policy / "rule.json").write_text(json.dumps([spec("require_truthy")]))
    assert p.register_policy_workspace(workspace, "policies") == []
    assert [r.rule_id for r in p.load_policy_rules_from_dir(str(policy), errors=[])] == ["policy-1"]


def test_symlinked_policy_folder_does_not_need_an_error_accumulator_to_be_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "linked"
    alias.symlink_to(actual, target_is_directory=True)
    assert p.load_policy_rules_from_dir(str(alias), errors=None) == []


def test_existing_nondirectory_policy_with_no_error_sink_is_not_accidentally_evaluated(tmp_path):
    file = tmp_path / "policy.json"
    file.write_text(json.dumps([spec("require_truthy")]))
    assert p.load_policy_rules_from_dir(str(file), errors=None) == []


def test_denied_policy_file_read_is_not_promoted_by_missing_report_sink(monkeypatch, tmp_path):
    root = tmp_path / "policy"
    root.mkdir()
    bad = root / "blocked.json"
    bad.write_text(json.dumps([spec("require_truthy")]))
    original = Path.read_text

    def deny(self, *args, **kwargs):
        if self == bad:
            raise OSError("simulated read refusal")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", deny)
    assert p.load_policy_rules_from_dir(str(root), errors=None) == []


def test_policy_root_resolution_error_is_explicit_and_cannot_fall_through(monkeypatch, tmp_path):
    root = tmp_path / "policy"
    root.mkdir()
    original = Path.resolve

    def fail(self, *args, **kwargs):
        if self == root and kwargs.get("strict") is True:
            raise OSError("unstable metadata")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail)
    errors = []
    assert p.load_policy_rules_from_dir(str(root), errors) == []
    assert any("cannot resolve policy directory" in e for e in errors)


def test_existing_policy_registration_reports_unresolvable_directory(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    policy = workspace / "policies"
    policy.mkdir(parents=True)
    orig = Path.resolve

    def deny(self, *args, **kwargs):
        if self == policy and kwargs.get("strict") is True:
            raise OSError("simulated realpath failure")
        return orig(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", deny)
    errors = p.register_policy_workspace(workspace, "policies")
    assert any("cannot resolve directory" in e for e in errors)


def test_configured_policy_lexical_resolution_error_preserves_denial(monkeypatch, tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    alias = workspace / "policies"
    alias.symlink_to(tmp_path.parent / "outside", target_is_directory=True)
    orig = Path.resolve

    def deny(self, *args, **kwargs):
        if self == alias:
            raise OSError("simulated unreadable symlink inode")
        return orig(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", deny)
    errors = p.register_policy_workspace(workspace, "policies")
    assert any("configured policy directory" in e for e in errors)


def test_policy_root_resolution_error_without_error_sink_still_returns_no_authorized_rules(
    monkeypatch, tmp_path
):
    root = tmp_path / "policies"
    root.mkdir()
    original = Path.resolve

    def fail_root(self, *args, **kwargs):
        if self == root:
            raise OSError("simulated invalid inode")
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", fail_root)
    assert p.load_policy_rules_from_dir(str(root), errors=None) == []


def test_previously_denied_policy_directory_cannot_be_reauthorized_by_omitting_error_sink(
    monkeypatch, tmp_path
):
    root = tmp_path / "policies"
    root.mkdir()
    monkeypatch.setattr(p, "_DENIED_POLICY_DIRS", {root.resolve()})
    assert p.load_policy_rules_from_dir(str(root), errors=None) == []


def test_symlinked_policy_file_is_ignored_even_without_error_sink(tmp_path):
    root = tmp_path / "policies"
    root.mkdir()
    target = tmp_path / "external.json"
    target.write_text(json.dumps([spec("require_truthy")]))
    (root / "untrusted.json").symlink_to(target)
    assert p.load_policy_rules_from_dir(str(root), errors=None) == []
