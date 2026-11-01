"""Contract, ledger records, report outcomes, and seal binding for traffic."""
from __future__ import annotations

import datetime
import json
from pathlib import Path

import pytest

import scripts.traffic as traffic_core
from scripts import audit_check as core
from scripts.contract import contract_plan
from scripts.traffic import (
    MAX_ALLOWED_HOSTS,
    TRAFFIC_CLASS_PROMPT,
    TRAFFIC_CLASS_TRANSCRIPT_UPLOAD,
    TRAFFIC_CLASS_UNKNOWN,
    TrafficRequest,
    audit_records,
    build_session_id,
    classify_request,
    load_state,
    load_trust_marker,
    log_path,
    pid_is_alive,
    pki_dir,
    plan_dir,
    request_record,
    session_record,
    state_path,
    stop_path,
    traffic_contract,
    traffic_root,
    trust_path,
    validate_traffic_contract,
    write_state,
    write_trust_marker,
)
from supervisor.gate import TrafficCheck
from supervisor.integrity import initialize_integrity
from supervisor.sealing import (
    _traffic_scope,
    check_monotonic,
    load_seal,
    save_seal,
    seal_plan,
)
from supervisor.traffic import (
    _reason,
    build_traffic_report,
    evaluate_traffic,
    report_exit_code,
    selected_plan,
    traffic_records,
)

# --------------------------------------------------------------------- helpers


def _key_env(tmp_path: Path, monkeypatch) -> Path:
    key_file = tmp_path / "outside-hmac.key"
    key_file.write_bytes(b"plan-auditor-test-key-material-" * 2)
    monkeypatch.delenv("PLAN_AUDITOR_HMAC_KEY", raising=False)
    monkeypatch.setenv("PLAN_AUDITOR_HMAC_KEY_FILE", str(key_file))
    return key_file


def _workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


def _write_plan(workspace: Path, plan: dict) -> None:
    target = workspace / ".plan-auditor" / "plan.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(plan), encoding="utf-8")


def _request_record(
    *, host: str = "api.test", path: str = "/v1/messages", body: bytes = b'{"messages": []}',
    seq: int = 1, session_id: str = "s-1", plan: str = "default",
) -> dict:
    req = TrafficRequest("POST", host, 443, path, {"content-type": "application/json"}, body)
    return request_record(
        req, classify_request(req), plan=plan, session_id=session_id, seq=seq
    )


def _append_traffic(
    workspace: Path,
    *,
    plan: str = "default",
    requests: list[dict] | None = None,
    sessions: list[dict] | None = None,
) -> None:
    for record in requests or []:
        core.append_evidence(str(workspace), record)
    for record in sessions or []:
        core.append_evidence(str(workspace), record)


def _closed_session(
    requests: list[dict], *, session_id: str = "s-1", plan: str = "default"
) -> dict:
    return session_record(
        plan=plan,
        session_id=session_id,
        started_at="2026-01-01T00:00:00+00:00",
        stopped_at="2026-01-01T00:00:01+00:00",
        captures=requests,
    )


# -------------------------------------------------------------------- contract


class TestContract:
    def test_non_object_is_rejected(self):
        assert validate_traffic_contract([]) == ["must be an object"]

    def test_unknown_keys_and_missing_hosts(self):
        errors = validate_traffic_contract({"extra": 1})
        assert "unknown key(s): extra" in errors
        assert "allowed_hosts must be a non-empty list of host names" in errors

    def test_hosts_must_be_a_non_empty_list(self):
        assert validate_traffic_contract({"allowed_hosts": "api.test"}) == [
            "allowed_hosts must be a non-empty list of host names"
        ]
        assert validate_traffic_contract({"allowed_hosts": []}) == [
            "allowed_hosts must be a non-empty list of host names"
        ]

    def test_host_count_is_bounded(self):
        hosts = [f"h{index}.test" for index in range(MAX_ALLOWED_HOSTS + 1)]
        errors = validate_traffic_contract({"allowed_hosts": hosts})
        assert errors == [f"allowed_hosts cannot exceed {MAX_ALLOWED_HOSTS} entries"]

    def test_each_entry_must_be_a_bare_host_name(self):
        errors = validate_traffic_contract(
            {"allowed_hosts": [1, "", "  ", "https://api.test", "host:443", "a/b"]}
        )
        assert errors == [
            "allowed_hosts[0] must be a non-empty string",
            "allowed_hosts[1] must be a non-empty string",
            "allowed_hosts[2] must be a non-empty string",
            "allowed_hosts[3] must be a host name without a scheme, port, or path",
            "allowed_hosts[4] must be a host name without a scheme, port, or path",
            "allowed_hosts[5] must be a host name without a scheme, port, or path",
        ]

    def test_valid_contract_passes(self):
        assert validate_traffic_contract({"allowed_hosts": ["API.test", "api.openai.com"]}) == []

    def test_absent_contract_is_none(self):
        assert traffic_contract({"task": "t"}) is None

    def test_non_object_plan_value_is_refused(self):
        with pytest.raises(ValueError, match="traffic contract must be an object"):
            traffic_contract({"traffic": []})

    def test_invalid_contract_is_refused(self):
        with pytest.raises(ValueError, match="invalid traffic contract"):
            traffic_contract({"traffic": {"allowed_hosts": []}})

    def test_contract_is_sorted_and_lowercased(self):
        contract = traffic_contract({"traffic": {"allowed_hosts": ["B.test", "a.test", "A.test"]}})
        assert contract == {"allowed_hosts": ["a.test", "b.test"]}


class TestContractBinding:
    def _plan(self) -> dict:
        return {
            "task": "t",
            "requirements": [],
            "required_tools": [],
            "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}],
        }

    def test_legacy_contract_has_no_traffic_key(self):
        contracted = contract_plan(self._plan())
        assert set(contracted) == {"task", "requirements", "required_tools", "steps"}

    def test_declared_contract_is_sealed_verbatim(self):
        plan = {**self._plan(), "traffic": {"allowed_hosts": ["B.test", "a.test"]}}
        assert contract_plan(plan)["traffic"] == {"allowed_hosts": ["B.test", "a.test"]}

    def test_seal_round_trip_preserves_traffic(self, tmp_path):
        plan = {**self._plan(), "traffic": {"allowed_hosts": ["api.test"]}}
        seal = seal_plan(plan, "p1", "2026-01-01T00:00:00")
        assert seal.payload()["traffic"] == {"allowed_hosts": ["api.test"]}
        path = tmp_path / ".plan-auditor" / "seal.json"
        save_seal(seal, str(path))
        loaded = load_seal(str(path))
        assert loaded is not None
        assert loaded.traffic == {"allowed_hosts": ["api.test"]}
        assert loaded.as_plan()["traffic"] == {"allowed_hosts": ["api.test"]}

    def test_legacy_seal_payload_is_byte_identical(self, tmp_path):
        seal = seal_plan(self._plan(), "p1", "2026-01-01T00:00:00")
        assert "traffic" not in seal.payload()
        assert "traffic" not in seal.as_plan()
        path = tmp_path / ".plan-auditor" / "seal.json"
        save_seal(seal, str(path))
        loaded = load_seal(str(path))
        assert loaded is not None and "traffic" not in loaded.payload()

    def test_monotonic_allows_host_reordering_and_case(self):
        before = {**self._plan(), "traffic": {"allowed_hosts": ["api.test", "b.test"]}}
        after = {**self._plan(), "traffic": {"allowed_hosts": ["B.TEST", "api.test"]}}
        assert check_monotonic(before, after).ok

    def test_monotonic_rejects_a_scope_change(self):
        before = {**self._plan(), "traffic": {"allowed_hosts": ["api.test"]}}
        after = {**self._plan(), "traffic": {"allowed_hosts": ["api.test", "evil.test"]}}
        check = check_monotonic(before, after)
        assert not check.ok
        assert any("outbound-traffic scope changed" in item for item in check.violations)

    def test_monotonic_rejects_removing_the_contract(self):
        before = {**self._plan(), "traffic": {"allowed_hosts": ["api.test"]}}
        check = check_monotonic(before, self._plan())
        assert not check.ok

    def test_traffic_scope_normalizes_only_dict_host_lists(self):
        assert _traffic_scope("raw") == "raw"
        assert _traffic_scope({"allowed_hosts": "api.test"}) == {"allowed_hosts": "api.test"}
        assert _traffic_scope(
            {"allowed_hosts": [" A.test ", 5, "b.test"], "extra": 1}
        ) == {"allowed_hosts": ["a.test", "b.test"], "extra": 1}

    def test_plan_validation_reports_traffic_problems(self):
        plan = {
            "task": "t",
            "created": "2026-01-01T00:00:00",
            "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}],
            "traffic": {"allowed_hosts": ["https://api.test"]},
        }
        errors = core.validate_plan(plan)
        assert any(error.startswith("traffic: allowed_hosts[0]") for error in errors)

    def test_plan_validation_accepts_a_valid_contract(self):
        plan = {
            "task": "t",
            "created": "2026-01-01T00:00:00",
            "steps": [{"id": 1, "verify": [{"type": "run", "cmd": "x"}]}],
            "traffic": {"allowed_hosts": ["api.test"]},
        }
        assert not [error for error in core.validate_plan(plan) if error.startswith("traffic:")]

    def test_contract_fingerprint_binds_traffic(self):
        plan = self._plan()
        with_traffic = {**plan, "traffic": {"allowed_hosts": ["api.test"]}}
        assert core.plan_contract_fingerprint(plan) != core.plan_contract_fingerprint(with_traffic)
        assert core.plan_contract_fingerprint(with_traffic) == (
            core.plan_contract_fingerprint({**with_traffic})
        )


# ----------------------------------------------------------------- paths/state


class TestPathsAndState:
    def test_paths_are_workspace_local(self, tmp_path):
        assert traffic_root(tmp_path) == tmp_path.resolve() / ".plan-auditor" / "traffic"
        assert plan_dir(tmp_path) == traffic_root(tmp_path) / "default"
        assert plan_dir(tmp_path, "work") == traffic_root(tmp_path) / "work"
        assert pki_dir(tmp_path) == traffic_root(tmp_path) / "pki"
        assert state_path(tmp_path).name == "state.json"
        assert stop_path(tmp_path).name == "stop.flag"
        assert log_path(tmp_path).name == "daemon.log"
        assert trust_path(tmp_path) == traffic_root(tmp_path) / "trust.json"

    def test_plan_name_rejects_traversal(self, tmp_path):
        for name in (".", "..", "../escape", "bad/name"):
            with pytest.raises(ValueError, match="invalid plan name"):
                plan_dir(tmp_path, name)

    def test_state_round_trip_and_tolerates_corruption(self, tmp_path):
        assert load_state(tmp_path) is None
        write_state(tmp_path, None, {"running": True, "pid": 1})
        assert load_state(tmp_path) == {"running": True, "pid": 1}
        path = state_path(tmp_path)
        path.write_text("not-json", encoding="utf-8")
        assert load_state(tmp_path) is None
        path.write_text("[]", encoding="utf-8")
        assert load_state(tmp_path) is None

    def test_trust_marker_round_trip_and_tolerates_corruption(self, tmp_path):
        assert load_trust_marker(tmp_path) is None
        write_trust_marker(tmp_path, {"fingerprint": "ABC"})
        assert load_trust_marker(tmp_path) == {"fingerprint": "ABC"}
        path = trust_path(tmp_path)
        path.write_text("{", encoding="utf-8")
        assert load_trust_marker(tmp_path) is None
        path.write_text("null", encoding="utf-8")
        assert load_trust_marker(tmp_path) is None

    def test_pid_liveness_proves_death_only(self, monkeypatch):
        assert pid_is_alive(True) is False
        assert pid_is_alive("1") is False
        assert pid_is_alive(0) is False
        assert pid_is_alive(-1) is False
        assert pid_is_alive(__import__("os").getpid()) is True

        def missing(_pid, _signal):
            raise ProcessLookupError

        monkeypatch.setattr(traffic_core.os, "kill", missing)
        assert pid_is_alive(1234) is False

        class InvalidPid(OSError):
            winerror = 87

        def invalid(_pid, _signal):
            raise InvalidPid()

        monkeypatch.setattr(traffic_core.os, "kill", invalid)
        assert pid_is_alive(1234) is False

        def unknown(_pid, _signal):
            raise OSError("cannot prove")

        monkeypatch.setattr(traffic_core.os, "kill", unknown)
        assert pid_is_alive(1234) is True

    def test_session_id_is_deterministic(self):
        moment = datetime.datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc)
        assert build_session_id(moment, 7) == "traffic-20260102T030405000006Z-7"
        generated = build_session_id()
        assert generated.startswith("traffic-")
        assert generated.endswith(f"-{__import__('os').getpid()}")


# -------------------------------------------------------------------- records


class TestAuditRecords:
    def test_unexpected_mode_is_a_violation(self):
        summary = audit_records([{"mode": "run"}], allowed_hosts=["api.test"])
        assert summary["outcome"] == "INCOMPLETE"
        assert summary["violations"] == [{"kind": "unexpected-record-mode", "mode": "run"}]

    def test_request_defects_and_secret_aggregation(self):
        records = [
            {
                "mode": "traffic_request",
                "ts": "short",
                "host": 5,
                "traffic_seq": True,
                "class": "custom-class",
                "session_id": "s-1",
                "secret_hits": [
                    {"name": "github-token", "masked": "ghp_…1234"},
                    5,
                    {"name": "", "masked": "x"},
                    {"name": "github-token", "masked": ""},
                ],
            },
            {
                "mode": "traffic_request",
                "ts": "2026-01-02T00:00:00+00:00",
                "host": "EVIL.test",
                "traffic_seq": "7",
                "class": "transcript-upload",
                "session_id": "s-1",
            },
            {
                "mode": "traffic_request",
                "ts": "2026-01-02T00:00:00+00:00",
                "host": "api.test",
                "traffic_seq": 3,
                "class": 9,
                "session_id": "orphan",
                "secret_hits": None,
            },
            {"mode": "traffic_request", "host": "api.test", "class": "", "traffic_seq": 4},
        ]
        summary = audit_records(records, allowed_hosts=["api.test"])
        kinds = [item["kind"] for item in summary["violations"]]
        assert "invalid-record" in kinds
        assert "out-of-scope-host" in kinds
        assert "transcript-upload" in kinds
        assert summary["unrecognized_classes"] == ["custom-class"]
        assert summary["secret_hits"] == [{"name": "github-token", "masked": "ghp_…1234", "count": 1}]
        assert summary["by_day"]["unknown"]["requests"] == 2
        assert summary["by_day"]["2026-01-02"]["requests"] == 2
        assert summary["classes"][TRAFFIC_CLASS_UNKNOWN] == 3
        assert summary["classes"][TRAFFIC_CLASS_TRANSCRIPT_UPLOAD] == 1
        assert summary["hosts"] == {"api.test": 2, "evil.test": 1}
        assert summary["outcome"] == "INCOMPLETE"
        assert any(
            problem["kind"] == "requests-without-closing-session" for problem in summary["session_problems"]
        )

    def test_session_defects_are_incomplete(self):
        records = [
            {"mode": "traffic_session", "session_id": "", "requests": 0},
            {"mode": "traffic_session", "session_id": "s-1", "requests": 3},
            {"mode": "traffic_session", "session_id": "s-2", "requests": True},
            {"mode": "traffic_session", "session_id": "s-3", "requests": -2},
            {
                "mode": "traffic_session",
                "session_id": "s-4",
                "requests": "two",
                "started_at": "a",
                "stopped_at": "b",
            },
            {
                "mode": "traffic_request",
                "host": "api.test",
                "class": "prompt",
                "traffic_seq": 1,
                "session_id": "s-1",
            },
        ]
        summary = audit_records(records, allowed_hosts=["api.test"])
        kinds = [item["kind"] for item in summary["session_problems"]]
        assert kinds.count("session-count-mismatch") == 4
        assert "invalid-session" in kinds
        assert summary["outcome"] == "INCOMPLETE"
        assert summary["sessions"][1]["declared_requests"] == -1
        assert summary["sessions"][3]["declared_requests"] == -1

    def test_silent_is_not_success(self):
        summary = audit_records(
            [_closed_session([], session_id="s-1")], allowed_hosts=["api.test"]
        )
        assert summary["outcome"] == "SILENT"
        assert summary["ok"] is False
        assert summary["requests"] == 0

    def test_violation_outranks_silence_truthfully(self):
        request = _request_record(host="evil.test")
        summary = audit_records(
            [request, _closed_session([request])], allowed_hosts=["api.test"]
        )
        assert summary["outcome"] == "VIOLATION"

    def test_clean_run_is_ok(self):
        request = _request_record()
        summary = audit_records(
            [request, _closed_session([request])], allowed_hosts=["api.test"]
        )
        assert summary["outcome"] == "OK"
        assert summary["ok"] is True
        assert summary["sessions"][0]["observed_requests"] == 1
        assert summary["classes"][TRAFFIC_CLASS_PROMPT] == 1


# --------------------------------------------------------------------- report


class TestReport:
    def test_selected_plan_loads_default_and_named(self, tmp_path):
        workspace = _workspace(tmp_path)
        _write_plan(workspace, {"task": "default"})
        key, plan = selected_plan(workspace, None)
        assert key == "default" and plan["task"] == "default"
        named = workspace / ".plan-auditor" / "plans" / "work.json"
        named.parent.mkdir(parents=True)
        named.write_text(json.dumps({"task": "named"}), encoding="utf-8")
        key, plan = selected_plan(workspace, "work")
        assert key == "work" and plan["task"] == "named"

    def test_selected_plan_refuses_missing_invalid_and_unsafe(self, tmp_path):
        workspace = _workspace(tmp_path)
        with pytest.raises(FileNotFoundError, match="plan not found"):
            selected_plan(workspace, None)
        _write_plan(workspace, {})
        (workspace / ".plan-auditor" / "plan.json").write_text("{", encoding="utf-8")
        with pytest.raises(ValueError, match="cannot load plan"):
            selected_plan(workspace, None)
        with pytest.raises(ValueError):
            selected_plan(workspace, "../escape")

    def test_traffic_records_filter_mode_and_plan_and_skip_bad_lines(self, tmp_path):
        workspace = _workspace(tmp_path)
        pg = workspace / ".plan-auditor"
        pg.mkdir()
        archive = pg / "archive"
        archive.mkdir()
        (archive / "evidence-00000001-x.jsonl").write_text(
            json.dumps({"mode": "traffic_request", "plan": "default", "host": "a"}) + "\n",
            encoding="utf-8",
        )
        (pg / "evidence.jsonl").write_text(
            "\n"
            + "not json\n"
            + json.dumps([1, 2]) + "\n"
            + json.dumps({"mode": "traffic_session", "plan": "default"}) + "\n"
            + json.dumps({"mode": "traffic_request", "plan": "other"}) + "\n"
            + json.dumps({"mode": "run", "plan": "default"}) + "\n",
            encoding="utf-8",
        )
        records = traffic_records(workspace, "default")
        assert [record["mode"] for record in records] == ["traffic_request", "traffic_session"]

    def test_unreadable_evidence_file_is_skipped(self, tmp_path):
        workspace = _workspace(tmp_path)
        pg = workspace / ".plan-auditor"
        pg.mkdir()
        (pg / "evidence.jsonl").mkdir()
        assert traffic_records(workspace, "default") == []

    def test_not_configured(self, tmp_path):
        workspace = _workspace(tmp_path)
        report = build_traffic_report(workspace, "default", plan={"task": "t"})
        assert report["outcome"] == "NOT_CONFIGURED"
        assert report["ok"] is False
        assert report["reason"] == "plan does not declare a traffic contract"

    def test_invalid_contract(self, tmp_path):
        workspace = _workspace(tmp_path)
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["bad:port"]}}
        )
        assert report["outcome"] == "INVALID"
        assert report["violations"] == []
        assert report["chain"] == {}

    def test_unverified_without_a_key(self, tmp_path):
        workspace = _workspace(tmp_path)
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "UNVERIFIED"
        assert "not authenticated" in report["reason"]

    def test_tampered_active_chain_wins(self, tmp_path):
        workspace = _workspace(tmp_path)
        request = _request_record()
        _append_traffic(
            workspace, requests=[request], sessions=[_closed_session([request])]
        )
        path = workspace / ".plan-auditor" / "evidence.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["class"] = "telemetry"
        lines[0] = json.dumps(tampered)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "TAMPERED"
        assert "not verifiable" in report["reason"]
        assert report["chain"]["active_valid"] is False

    def test_broken_archive_alone_is_tampered(self, tmp_path):
        workspace = _workspace(tmp_path)
        archive = workspace / ".plan-auditor" / "archive"
        archive.mkdir(parents=True)
        (archive / "evidence-00000001-x.jsonl").write_text(
            json.dumps({"prev": "CORRUPT", "hash": "00"}) + "\n", encoding="utf-8"
        )
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "TAMPERED"
        assert report["chain"]["archive_anchored"] is False
        assert report["reason"].endswith("archive is not anchored")

    def test_incomplete_without_a_closing_session(self, tmp_path, monkeypatch):
        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        _append_traffic(workspace, requests=[_request_record()])
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "INCOMPLETE"
        assert "requests-without-closing-session" in report["reason"]

    def test_incomplete_reports_the_problem_kinds(self, tmp_path, monkeypatch):
        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        _append_traffic(
            workspace,
            sessions=[{"mode": "traffic_session", "plan": "default", "session_id": "", "requests": 0}],
        )
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "INCOMPLETE"
        assert "invalid-session" in report["reason"]

    def test_silent_run_refuses_success(self, tmp_path, monkeypatch):
        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        _append_traffic(workspace, sessions=[_closed_session([])])
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "SILENT"
        assert "silence is not proof" in report["reason"]

    def test_violation_names_the_rule(self, tmp_path, monkeypatch):
        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        request = _request_record(host="evil.test")
        _append_traffic(workspace, requests=[request], sessions=[_closed_session([request])])
        report = build_traffic_report(
            workspace, "default", plan={"traffic": {"allowed_hosts": ["api.test"]}}
        )
        assert report["outcome"] == "VIOLATION"
        assert report["reason"] == "outbound traffic violations: out-of-scope-host"

    def test_clean_run_is_ok_and_loads_the_plan_from_disk(self, tmp_path, monkeypatch):
        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        request = _request_record()
        _append_traffic(workspace, requests=[request], sessions=[_closed_session([request])])
        _write_plan(workspace, {"traffic": {"allowed_hosts": ["api.test"]}})
        report = build_traffic_report(workspace)
        assert report["outcome"] == "OK"
        assert report["ok"] is True
        assert report["allowed_hosts"] == ["api.test"]
        assert report["requests"] == 1
        assert report["chain"]["authenticated"] is True
        assert report["reason"] == (
            "1 outbound request(s) observed, all in plan scope, every session closed exactly"
        )

    def test_unknown_outcome_has_a_truthful_fallback(self):
        assert _reason({"outcome": "OTHER"}) == "traffic audit outcome is OTHER"

    def test_evaluate_requires_and_reports(self, tmp_path, monkeypatch):
        not_required = evaluate_traffic(tmp_path, {"task": "t"}, "default")
        assert not_required.required is False
        assert not_required.ok is True
        assert not_required.outcome == "NOT_REQUIRED"

        invalid = evaluate_traffic(tmp_path, {"traffic": {"allowed_hosts": []}}, "default")
        assert invalid.required is True and invalid.ok is False
        assert invalid.outcome == "INVALID"

        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        request = _request_record()
        _append_traffic(workspace, requests=[request], sessions=[_closed_session([request])])
        check = evaluate_traffic(
            workspace, {"traffic": {"allowed_hosts": ["api.test"]}}, "default"
        )
        assert check.required is True and check.ok is True
        assert check.requests == 1
        assert check.authenticated is True
        assert check.classes[TRAFFIC_CLASS_PROMPT] == 1
        assert check.sessions[0]["session_id"] == "s-1"

    def test_evaluate_fails_closed_on_a_violation(self, tmp_path, monkeypatch):
        workspace = _workspace(tmp_path)
        _key_env(tmp_path, monkeypatch)
        initialize_integrity(workspace)
        request = _request_record(host="evil.test")
        _append_traffic(workspace, requests=[request], sessions=[_closed_session([request])])
        check = evaluate_traffic(
            workspace, {"traffic": {"allowed_hosts": ["api.test"]}}, "default"
        )
        assert check.ok is False
        assert check.outcome == "VIOLATION"
        assert check.violations[0]["kind"] == "out-of-scope-host"

    @pytest.mark.parametrize(
        ("outcome", "code"),
        [("OK", 0), ("VIOLATION", 1), ("SILENT", 1), ("TAMPERED", 2), ("UNVERIFIED", 2),
         ("NOT_CONFIGURED", 2), ("INCOMPLETE", 2), ("INVALID", 1)],
    )
    def test_report_exit_codes(self, outcome, code):
        assert report_exit_code(outcome) == code


def test_gate_fails_when_traffic_check_is_required_and_not_ok():
    from supervisor.gate import CompletionGate
    from supervisor.policies import PolicyEngine

    gate = CompletionGate(PolicyEngine([]))
    report = gate.evaluate(
        deterministic_passed=True,
        pending_steps=[],
        workspace_context={},
        traffic_check=TrafficCheck(
            required=True, ok=False, outcome="VIOLATION", reason="out-of-scope-host"
        ),
    )
    assert report.outcome == "FAIL"
    assert "outbound traffic gate: out-of-scope-host" in report.notes
    assert report.as_dict()["traffic"]["outcome"] == "VIOLATION"


def test_gate_passes_without_a_traffic_contract():
    from supervisor.gate import CompletionGate
    from supervisor.policies import PolicyEngine

    gate = CompletionGate(PolicyEngine([]))
    report = gate.evaluate(
        deterministic_passed=True,
        pending_steps=[],
        workspace_context={},
        traffic_check=TrafficCheck(required=False, ok=True, outcome="NOT_REQUIRED", reason=""),
    )
    assert report.outcome == "PASS"
