"""Deterministic outbound-traffic observation for sealed-plan evidence.

A loopback HTTPS proxy records what an agent CLI sends while a plan runs. The
module never calls a model: classification is a fixed priority over literal
method/path/host/body markers, secret detection is a fixed regular-expression
list, and scope violations are recomputed from the sealed plan. Captures are
written through the existing hash-chained evidence writer, so every traffic
record carries ``prev``/``hash``/``auth`` exactly like the audit records and the
report can verify the chain rather than trusting a separate log.

The proxy is monitor-only. Local capture never decides by itself whether a task
is complete; it records facts that the deterministic completion gate re-checks
against the plan's ``traffic`` contract.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as _dt
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any, BinaryIO, cast
from urllib.parse import urlsplit

TRAFFIC_CLASS_PROMPT = "prompt"
TRAFFIC_CLASS_TOOL_RESULT = "tool-result"
TRAFFIC_CLASS_TELEMETRY = "telemetry"
TRAFFIC_CLASS_TRANSCRIPT_UPLOAD = "transcript-upload"
TRAFFIC_CLASS_UNKNOWN = "unknown"
TRAFFIC_CLASSES = (
    TRAFFIC_CLASS_PROMPT,
    TRAFFIC_CLASS_TOOL_RESULT,
    TRAFFIC_CLASS_TELEMETRY,
    TRAFFIC_CLASS_TRANSCRIPT_UPLOAD,
    TRAFFIC_CLASS_UNKNOWN,
)

MAX_SCAN_BYTES = 1_048_576
MAX_DETECTIONS = 100
MAX_DETECTION_LENGTH = 512
MAX_ALLOWED_HOSTS = 256
MAX_BODY_BYTES = 16 * 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
REPORT_SCHEMA = "plan-auditor-traffic-report/v1"

_PROMPT_PATH_MARKERS = (
    "/chat/completions",
    "/v1/messages",
    "/v1/responses",
    "/v1/complete",
    "/v1/completions",
    "/generatecontent",
    "/v1/embeddings",
)
_PROMPT_HOSTS = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "api.deepseek.com",
    "api.mistral.ai",
    "api.groq.com",
    "api.together.xyz",
)
_TELEMETRY_HOST_MARKERS = (
    "telemetry",
    "sentry",
    "statsig",
    "posthog",
    "segment.io",
    "datadoghq",
    "datadog",
    "newrelic",
    "amplitude",
    "mixpanel",
    "google-analytics",
    "analytics",
)
_TELEMETRY_PATH_MARKERS = (
    "/telemetry",
    "/metrics",
    "/stats",
    "/events",
    "/analytics",
    "/logs",
)
_TOOL_RESULT_MARKERS = (
    '"tool_result"',
    '"tool_use_id"',
    '"function_call_output"',
    '"tool_call_id"',
    '"role":"tool"',
    '"role": "tool"',
)
_TRANSCRIPT_MARKERS = ("transcript", "conversation_dump", "dump.jsonl")
_UPLOAD_MARKERS = ("upload", "/files", "transcript", "dump")

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_WINDOWS_PATH_RE = re.compile(r"(?<![\w])(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+")
_POSIX_PATH_RE = re.compile(
    r"(?<![\w:])(?:/(?:home|Users|root|etc|var|tmp|opt|usr|mnt|workspace|data)/[^\s\"'<>|]+)"
)
_ENV_PATTERNS = (
    re.compile(r"\$(?:\{([A-Z][A-Z0-9_]{2,})\}|([A-Z][A-Z0-9_]{2,}))"),
    re.compile(r"%([A-Z][A-Z0-9_]{2,})%"),
    re.compile(
        r"(?:os\.environ|process\.env)(?:\[[\"']([A-Z][A-Z0-9_]+)[\"']\]|\.([A-Z][A-Z0-9_]+))"
    ),
    re.compile(r"\b(?:env|environment)\.([A-Z][A-Z0-9_]{2,})\b"),
)
_ALLOWED_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]*$")
_PLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TLS_HOST_RE = re.compile(r"^[A-Za-z0-9.:-]+$")

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], int, str], ...] = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        0,
        "[REDACTED PRIVATE KEY]",
    ),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"), 0, ""),
    ("openai-key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{20,}\b"), 0, ""),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), 0, ""),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), 0, ""),
    (
        "bearer-token",
        re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})"),
        1,
        "",
    ),
    (
        "password-assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*[\"']?([^\s\"',}]{8,})"
        ),
        1,
        "",
    ),
)
_SENSITIVE_HEADERS = frozenset(
    {"authorization", "x-api-key", "api-key", "cookie", "x-auth-token"}
)
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
    }
)

TRAFFIC_ROOT = ".plan-auditor/traffic"
PKI_DIR = "pki"
STATE_FILE = "state.json"
STOP_FILE = "stop.flag"
LOG_FILE = "daemon.log"
TRUST_FILE = "trust.json"


# ------------------------------------------------------------------ contract


def validate_traffic_contract(value: Any) -> list[str]:
    """Schema errors for a plan's ``traffic`` block, in deterministic order."""
    if not isinstance(value, dict):
        return ["must be an object"]
    errors: list[str] = []
    unknown = sorted(set(value) - {"allowed_hosts"})
    if unknown:
        errors.append(f"unknown key(s): {', '.join(unknown)}")
    hosts = value.get("allowed_hosts")
    if not isinstance(hosts, list) or not hosts:
        errors.append("allowed_hosts must be a non-empty list of host names")
        return errors
    if len(hosts) > MAX_ALLOWED_HOSTS:
        errors.append(f"allowed_hosts cannot exceed {MAX_ALLOWED_HOSTS} entries")
    for index, host in enumerate(hosts):
        if not isinstance(host, str) or not host.strip():
            errors.append(f"allowed_hosts[{index}] must be a non-empty string")
        elif not _ALLOWED_HOST_RE.fullmatch(host.strip()):
            errors.append(
                f"allowed_hosts[{index}] must be a host name without a scheme, port, or path"
            )
    return errors


def traffic_contract(plan: Mapping[str, Any]) -> dict[str, Any] | None:
    """Normalized contract, or ``None`` when the plan does not opt in."""
    if "traffic" not in plan:
        return None
    value = plan.get("traffic")
    if not isinstance(value, dict):
        raise ValueError("traffic contract must be an object")
    errors = validate_traffic_contract(value)
    if errors:
        raise ValueError(f"invalid traffic contract: {'; '.join(errors)}")
    hosts = cast(list[Any], value.get("allowed_hosts"))
    return {"allowed_hosts": sorted({str(host).strip().lower() for host in hosts})}


def _safe_plan_name(name: str | None) -> str:
    if not name or name == "default":
        return "default"
    if name in {".", ".."} or not _PLAN_NAME_RE.fullmatch(name):
        raise ValueError("invalid plan name")
    return name


# ------------------------------------------------------------------ paths


def traffic_root(workspace: str | Path) -> Path:
    return Path(workspace).expanduser().resolve() / TRAFFIC_ROOT


def plan_dir(workspace: str | Path, plan: str | None = None) -> Path:
    return traffic_root(workspace) / _safe_plan_name(plan)


def pki_dir(workspace: str | Path) -> Path:
    """CA material shares one subtree per workspace, outside every plan dir."""
    return traffic_root(workspace) / PKI_DIR


def state_path(workspace: str | Path, plan: str | None = None) -> Path:
    return plan_dir(workspace, plan) / STATE_FILE


def stop_path(workspace: str | Path, plan: str | None = None) -> Path:
    return plan_dir(workspace, plan) / STOP_FILE


def log_path(workspace: str | Path, plan: str | None = None) -> Path:
    return plan_dir(workspace, plan) / LOG_FILE


def trust_path(workspace: str | Path) -> Path:
    return traffic_root(workspace) / TRUST_FILE


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def write_state(workspace: str | Path, plan: str | None, state: Mapping[str, Any]) -> Path:
    path = state_path(workspace, plan)
    _atomic_json(path, state)
    return path


def load_state(workspace: str | Path, plan: str | None = None) -> dict[str, Any] | None:
    try:
        value = json.loads(state_path(workspace, plan).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def write_trust_marker(workspace: str | Path, detail: Mapping[str, Any]) -> Path:
    path = trust_path(workspace)
    _atomic_json(path, detail)
    return path


def load_trust_marker(workspace: str | Path) -> dict[str, Any] | None:
    try:
        value = json.loads(trust_path(workspace).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def pid_is_alive(pid: object) -> bool:
    """Only a provably dead PID reports dead (same discipline as the core)."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError as exc:
        return getattr(exc, "winerror", None) != 87
    return True


def build_session_id(now: _dt.datetime | None = None, pid: int | None = None) -> str:
    moment = now or _dt.datetime.now(_dt.UTC)
    return f"traffic-{moment.strftime('%Y%m%dT%H%M%S%fZ')}-{pid or os.getpid()}"


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()


# ------------------------------------------------------------- classification


@dataclass(frozen=True)
class SecretHit:
    name: str
    masked: str
    fingerprint: str
    location: str

    def to_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "masked": self.masked,
            "fingerprint": self.fingerprint,
            "location": self.location,
        }


@dataclass(frozen=True)
class TrafficClassification:
    classification: str
    reasons: tuple[str, ...]
    secret_hits: tuple[SecretHit, ...]
    detected_paths: tuple[str, ...]
    detected_urls: tuple[str, ...]
    env_vars: tuple[str, ...]
    payload_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "class": self.classification,
            "reasons": list(self.reasons),
            "secret_hits": [hit.to_dict() for hit in self.secret_hits],
            "detected_paths": list(self.detected_paths),
            "detected_urls": list(self.detected_urls),
            "env_vars": list(self.env_vars),
            "payload_sha256": self.payload_sha256,
        }


@dataclass(frozen=True)
class TrafficRequest:
    method: str
    host: str
    port: int
    path: str
    headers: Mapping[str, str]
    body: bytes

    def header(self, name: str) -> str:
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return ""


def mask_secret(value: str) -> str:
    if not value:
        return "***"
    if len(value) < 12:
        return "***"
    return f"{value[:4]}…{value[-4:]}"


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _iter_secret_hits(sources: Iterable[tuple[str, str]]) -> tuple[SecretHit, ...]:
    hits: dict[tuple[str, str, str], SecretHit] = {}
    for location, text in sources:
        if not text:
            continue
        for name, pattern, group, replacement in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                raw = match.group(group)
                masked = replacement or mask_secret(raw)
                hit = SecretHit(
                    name=name,
                    masked=masked,
                    fingerprint=_fingerprint(raw),
                    location=location,
                )
                hits.setdefault((name, hit.fingerprint, location), hit)
    return tuple(
        hits[key] for key in sorted(hits, key=lambda item: (item[0], item[2], item[1]))
    )


def _secret_sources(request: TrafficRequest, body_text: str) -> list[tuple[str, str]]:
    sources = [("body", body_text), ("url", request.path)]
    for key, value in request.headers.items():
        if key.lower() in _SENSITIVE_HEADERS:
            sources.append((f"header:{key.lower()}", value))
    return sources


def _bounded_unique(values: Iterable[str]) -> tuple[str, ...]:
    unique = sorted({value[:MAX_DETECTION_LENGTH] for value in values if value})
    return tuple(unique[:MAX_DETECTIONS])


def _detect_paths(text: str) -> tuple[str, ...]:
    matches: list[str] = []
    for pattern in (_WINDOWS_PATH_RE, _POSIX_PATH_RE):
        matches.extend(match.group(0).rstrip(".,;:)]}") for match in pattern.finditer(text))
    return _bounded_unique(matches)


def _detect_urls(text: str) -> tuple[str, ...]:
    urls: list[str] = []
    for match in _URL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;:)]}")
        try:
            parts = urlsplit(raw)
        except ValueError:
            continue
        if not parts.scheme or not parts.netloc:
            continue
        urls.append(f"{parts.scheme}://{parts.netloc}{parts.path}")
    return _bounded_unique(urls)


def _detect_env_vars(text: str) -> tuple[str, ...]:
    names: list[str] = []
    for pattern in _ENV_PATTERNS:
        for match in pattern.finditer(text):
            for group in match.groups():
                if group:
                    names.append(group)
    return _bounded_unique(names)


def _path_text(request: TrafficRequest) -> str:
    try:
        parts = urlsplit(request.path)
    except ValueError:
        return request.path
    return parts.path or request.path


def classify_request(request: TrafficRequest) -> TrafficClassification:
    """Classify one request with a fixed priority and literal markers."""
    body_bytes = request.body[:MAX_SCAN_BYTES]
    body_text = body_bytes.decode("utf-8", errors="replace")
    body_lower = body_text.lower()
    path_lower = _path_text(request).lower()
    host_lower = request.host.lower()

    reasons: list[str] = []
    classification = TRAFFIC_CLASS_UNKNOWN

    transcript_in_body = any(marker in body_lower for marker in _TRANSCRIPT_MARKERS)
    upload_in_path = any(marker in path_lower for marker in _UPLOAD_MARKERS)
    transcript_in_path = any(marker in path_lower for marker in _TRANSCRIPT_MARKERS)
    if (transcript_in_body and upload_in_path) or transcript_in_path:
        classification = TRAFFIC_CLASS_TRANSCRIPT_UPLOAD
        if transcript_in_body:
            reasons.append("body:transcript-marker")
        if upload_in_path:
            reasons.append("path:upload")
        if transcript_in_path:
            reasons.append("path:transcript-marker")
    elif any(marker in host_lower for marker in _TELEMETRY_HOST_MARKERS):
        classification = TRAFFIC_CLASS_TELEMETRY
        reasons.append("host:telemetry")
    elif any(marker in path_lower for marker in _TELEMETRY_PATH_MARKERS):
        classification = TRAFFIC_CLASS_TELEMETRY
        reasons.append("path:telemetry")
    elif any(marker in body_lower for marker in _TOOL_RESULT_MARKERS):
        classification = TRAFFIC_CLASS_TOOL_RESULT
        reasons.append("body:tool-result")
    elif host_lower in _PROMPT_HOSTS:
        classification = TRAFFIC_CLASS_PROMPT
        reasons.append("host:model-api")
    elif any(marker in path_lower for marker in _PROMPT_PATH_MARKERS):
        classification = TRAFFIC_CLASS_PROMPT
        reasons.append("path:model-api")
    elif (
        "json" in request.header("content-type").lower()
        and any(marker in body_lower for marker in ('"messages"', '"prompt"'))
    ):
        classification = TRAFFIC_CLASS_PROMPT
        reasons.append("body:prompt-shape")

    full_text = "\n".join([_path_text(request), body_text])
    return TrafficClassification(
        classification=classification,
        reasons=tuple(reasons),
        secret_hits=_iter_secret_hits(_secret_sources(request, body_text)),
        detected_paths=_detect_paths(full_text),
        detected_urls=_detect_urls(full_text),
        env_vars=_detect_env_vars(full_text),
        payload_sha256=hashlib.sha256(request.body).hexdigest(),
    )


def request_record(
    request: TrafficRequest,
    classification: TrafficClassification,
    *,
    plan: str,
    session_id: str,
    seq: int,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build the ledger record; raw body and sensitive headers never enter it."""
    return {
        "ts": timestamp or _now(),
        "mode": "traffic_request",
        "plan": _safe_plan_name(plan),
        "session_id": session_id,
        "traffic_seq": seq,
        "method": request.method,
        "host": request.host.lower(),
        "port": request.port,
        "path": _path_text(request),
        "class": classification.classification,
        "reasons": list(classification.reasons),
        "payload_sha256": classification.payload_sha256,
        "payload_bytes": len(request.body),
        "secret_hits": [hit.to_dict() for hit in classification.secret_hits],
        "detected_paths": list(classification.detected_paths),
        "detected_urls": list(classification.detected_urls),
        "env_vars": list(classification.env_vars),
        "content_type": request.header("content-type")[:MAX_DETECTION_LENGTH],
    }


def session_record(
    *,
    plan: str,
    session_id: str,
    started_at: str,
    stopped_at: str,
    captures: Sequence[Mapping[str, Any]],
    timestamp: str | None = None,
) -> dict[str, Any]:
    classes = {name: 0 for name in TRAFFIC_CLASSES}
    hosts: dict[str, int] = {}
    for payload in captures:
        classification = str(payload.get("class", TRAFFIC_CLASS_UNKNOWN))
        if classification not in classes:
            classification = TRAFFIC_CLASS_UNKNOWN
        classes[classification] += 1
        host = str(payload.get("host", ""))
        if host:
            hosts[host] = hosts.get(host, 0) + 1
    return {
        "ts": timestamp or _now(),
        "mode": "traffic_session",
        "plan": _safe_plan_name(plan),
        "session_id": session_id,
        "requests": len(captures),
        "classes": classes,
        "hosts": dict(sorted(hosts.items())),
        "started_at": started_at,
        "stopped_at": stopped_at,
        "silent": not captures,
    }


# -------------------------------------------------------------------- audit


def _record_class(value: Any) -> str:
    if isinstance(value, str) and value in TRAFFIC_CLASSES:
        return value
    return TRAFFIC_CLASS_UNKNOWN


def audit_records(
    records: Iterable[Mapping[str, Any]],
    *,
    allowed_hosts: Sequence[str],
) -> dict[str, Any]:
    """Deterministically aggregate request/session records against plan scope."""
    allowed = {str(host).lower() for host in allowed_hosts}
    requests: list[Mapping[str, Any]] = []
    sessions: list[Mapping[str, Any]] = []
    violations: list[dict[str, Any]] = []
    classes = {name: 0 for name in TRAFFIC_CLASSES}
    hosts: dict[str, int] = {}
    by_day: dict[str, dict[str, Any]] = {}
    secret_hits: dict[tuple[str, str], int] = {}
    unrecognized: set[str] = set()
    per_session: dict[str, int] = {}

    for record in records:
        mode = record.get("mode")
        if mode == "traffic_request":
            requests.append(record)
        elif mode == "traffic_session":
            sessions.append(record)
        else:
            violations.append({"kind": "unexpected-record-mode", "mode": str(mode)})
            continue
        if mode != "traffic_request":
            continue
        raw_class = record.get("class")
        classification = _record_class(raw_class)
        if isinstance(raw_class, str) and raw_class and raw_class not in TRAFFIC_CLASSES:
            unrecognized.add(raw_class)
        host = record.get("host")
        if not isinstance(host, str) or not host:
            violations.append({"kind": "invalid-record", "detail": "request has no host"})
            host = ""
        seq = record.get("traffic_seq")
        if isinstance(seq, bool) or not isinstance(seq, int):
            seq = None
        if host and host.lower() not in allowed:
            violations.append({
                "kind": "out-of-scope-host",
                "host": host.lower(),
                "traffic_seq": seq,
            })
        if classification == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD:
            violations.append({
                "kind": "transcript-upload",
                "host": host.lower(),
                "traffic_seq": seq,
            })
        timestamp = record.get("ts")
        day = timestamp[:10] if isinstance(timestamp, str) and len(timestamp) >= 10 else "unknown"
        bucket = by_day.setdefault(
            day, {"requests": 0, "classes": {name: 0 for name in TRAFFIC_CLASSES}}
        )
        bucket["requests"] += 1
        bucket["classes"][classification] += 1
        classes[classification] += 1
        if host:
            hosts[host.lower()] = hosts.get(host.lower(), 0) + 1
        session_id = record.get("session_id")
        if isinstance(session_id, str):
            per_session[session_id] = per_session.get(session_id, 0) + 1
        for hit in record.get("secret_hits", []) or []:
            if not isinstance(hit, dict):
                continue
            name = hit.get("name")
            masked = hit.get("masked")
            if isinstance(name, str) and name and isinstance(masked, str) and masked:
                secret_hits[(name, masked)] = secret_hits.get((name, masked), 0) + 1

    declared_sessions: set[str] = set()
    session_items: list[dict[str, Any]] = []
    session_problems: list[dict[str, Any]] = []
    for record in sessions:
        session_id = record.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            session_problems.append({"kind": "invalid-session", "detail": "missing session_id"})
            continue
        declared_sessions.add(session_id)
        declared = record.get("requests")
        if isinstance(declared, bool) or not isinstance(declared, int) or declared < 0:
            declared = -1
        observed = per_session.get(session_id, 0)
        item = {
            "session_id": session_id,
            "declared_requests": declared,
            "observed_requests": observed,
            "started_at": record.get("started_at"),
            "stopped_at": record.get("stopped_at"),
        }
        session_items.append(item)
        if declared != observed:
            session_problems.append({
                "kind": "session-count-mismatch",
                "session_id": session_id,
                "declared": declared,
                "observed": observed,
            })
    orphan_sessions = sorted(set(per_session) - declared_sessions)
    if orphan_sessions:
        session_problems.append({
            "kind": "requests-without-closing-session",
            "sessions": orphan_sessions,
        })

    violations.sort(key=lambda item: (item.get("kind", ""), str(item.get("traffic_seq"))))
    if not sessions or session_problems:
        outcome = "INCOMPLETE"
    elif violations:
        outcome = "VIOLATION"
    elif not requests:
        outcome = "SILENT"
    else:
        outcome = "OK"
    return {
        "outcome": outcome,
        "ok": outcome == "OK",
        "requests": len(requests),
        "classes": classes,
        "hosts": dict(sorted(hosts.items())),
        "by_day": {
            day: {"requests": item["requests"], "classes": dict(item["classes"])}
            for day, item in sorted(by_day.items())
        },
        "secret_hits": [
            {"name": name, "masked": masked, "count": count}
            for (name, masked), count in sorted(secret_hits.items())
        ],
        "unrecognized_classes": sorted(unrecognized),
        "sessions": session_items,
        "session_problems": session_problems,
        "violations": violations,
    }


# ------------------------------------------------------------------- certs

CA_CN = "Plan Auditor Traffic Local CA"
CA_DAYS = 3650
LEAF_DAYS = 825
Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


class CertificateError(RuntimeError):
    """Certificate or trust-store operation could not be completed."""


@dataclass(frozen=True)
class IssuedCertificate:
    host: str
    cert_path: Path
    key_path: Path


def _default_runner(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv), capture_output=True, text=True, timeout=60, check=False
    )


def _detail(completed: subprocess.CompletedProcess[str]) -> str:
    text = (completed.stderr or completed.stdout or "").strip()
    return text.splitlines()[-1] if text else f"exit {completed.returncode}"


def _openssl() -> str:
    executable = shutil.which("openssl")
    if not executable:
        raise CertificateError(
            "openssl executable not found; install openssl to use outbound traffic capture"
        )
    return executable


def _run(argv: Sequence[str], *, runner: Runner | None = None, what: str) -> str:
    try:
        completed = (runner or _default_runner)(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CertificateError(f"{what}: {exc}") from exc
    if completed.returncode != 0:
        raise CertificateError(f"{what} failed: {_detail(completed)}")
    return completed.stdout or ""


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows has no POSIX mode bits; the file still lives under the
        # user's control-plane directory.
        pass


def _pem_der(path: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
        return ssl.PEM_cert_to_DER_cert(text)
    except (OSError, ValueError) as exc:
        raise CertificateError(f"cannot read certificate {path}: {exc}") from exc


def certificate_fingerprint(cert_path: str | Path) -> str:
    return hashlib.sha256(_pem_der(Path(cert_path))).hexdigest().upper()


class CertificateAuthority:
    """A local CA plus a per-host leaf cache under one control-plane directory."""

    def __init__(self, root: str | Path, *, runner: Runner | None = None) -> None:
        self.root = Path(root)
        self.ca_dir = self.root / "ca"
        self.leaf_dir = self.root / "leafs"
        self.cert_path = self.ca_dir / "ca.crt.pem"
        self.key_path = self.ca_dir / "ca.key.pem"
        self._runner = runner
        self._lock = threading.Lock()

    def ensure(self) -> None:
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        has_cert = self.cert_path.is_file()
        has_key = self.key_path.is_file()
        if has_cert != has_key:
            raise CertificateError(
                f"incomplete CA state under {self.ca_dir}: certificate and key must "
                "both exist or both be absent"
            )
        if not has_cert:
            self._generate_ca()
        self._verify(self.cert_path, what="CA self-verification")

    def _generate_ca(self) -> None:
        openssl = _openssl()
        self.leaf_dir.mkdir(parents=True, exist_ok=True)
        ca_conf = self.ca_dir / "ca.cnf"
        _write_private(
            ca_conf,
            "[req]\n"
            "prompt = no\n"
            "distinguished_name = dn\n"
            "[dn]\n"
            f"CN = {CA_CN}\n"
            "[v3_ca]\n"
            "basicConstraints = critical,CA:TRUE,pathlen:0\n"
            "keyUsage = critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid:always\n",
        )
        _run(
            [openssl, "genpkey", "-algorithm", "EC", "-pkeyopt",
             "ec_paramgen_curve:prime256v1", "-out", str(self.key_path)],
            runner=self._runner,
            what="CA key generation",
        )
        _run(
            [openssl, "req", "-x509", "-new", "-key", str(self.key_path),
             "-days", str(CA_DAYS), "-subj", f"/CN={CA_CN}",
             "-config", str(ca_conf), "-extensions", "v3_ca",
             "-out", str(self.cert_path)],
            runner=self._runner,
            what="CA certificate generation",
        )
        try:
            os.chmod(self.key_path, 0o600)
        except OSError:
            # Windows has no POSIX mode bits; see _write_private.
            pass

    def _verify(self, cert_path: Path, *, what: str) -> None:
        _run(
            [_openssl(), "verify", "-CAfile", str(self.cert_path), str(cert_path)],
            runner=self._runner,
            what=what,
        )

    def fingerprint(self) -> str:
        return certificate_fingerprint(self.cert_path)

    def issue(self, host: str) -> IssuedCertificate:
        host = host.strip().strip("[]")
        if not host or not _TLS_HOST_RE.fullmatch(host):
            raise CertificateError(f"refusing unsafe TLS host name: {host!r}")
        self.ensure()
        with self._lock:
            cache_key = hashlib.sha256(host.lower().encode("utf-8")).hexdigest()[:24]
            cert_path = self.leaf_dir / f"{cache_key}.crt.pem"
            key_path = self.leaf_dir / "leaf.key.pem"
            if cert_path.is_file() and key_path.is_file():
                self._verify(cert_path, what=f"leaf verification for {host}")
                return IssuedCertificate(host, cert_path, key_path)

            self.leaf_dir.mkdir(parents=True, exist_ok=True)
            if not key_path.is_file():
                _run(
                    [_openssl(), "genpkey", "-algorithm", "EC", "-pkeyopt",
                     "ec_paramgen_curve:prime256v1", "-out", str(key_path)],
                    runner=self._runner,
                    what="leaf key generation",
                )
                try:
                    os.chmod(key_path, 0o600)
                except OSError:
                    # Windows has no POSIX mode bits; see _write_private.
                    pass

            san = self._san(host)
            leaf_conf = self.leaf_dir / f"{cache_key}.cnf"
            _write_private(
                leaf_conf,
                "[req]\n"
                "prompt = no\n"
                "distinguished_name = dn\n"
                "[dn]\n"
                f"CN = {host[:64]}\n"
                "[v3_leaf]\n"
                "basicConstraints = critical,CA:FALSE\n"
                "keyUsage = critical,digitalSignature\n"
                "extendedKeyUsage = serverAuth\n"
                f"subjectAltName = {san}\n"
                "subjectKeyIdentifier = hash\n"
                "authorityKeyIdentifier = keyid:always\n",
            )
            csr_path = self.leaf_dir / f"{cache_key}.csr.pem"
            with tempfile.TemporaryDirectory(dir=self.leaf_dir) as tmp:
                serial_path = Path(tmp) / "ca.srl"
                _run(
                    [_openssl(), "req", "-new", "-key", str(key_path),
                     "-subj", f"/CN={host[:64]}", "-config", str(leaf_conf),
                     "-out", str(csr_path)],
                    runner=self._runner,
                    what=f"CSR generation for {host}",
                )
                _run(
                    [_openssl(), "x509", "-req", "-in", str(csr_path),
                     "-CA", str(self.cert_path), "-CAkey", str(self.key_path),
                     "-CAserial", str(serial_path), "-CAcreateserial",
                     "-days", str(LEAF_DAYS), "-extfile", str(leaf_conf),
                     "-extensions", "v3_leaf", "-out", str(cert_path)],
                    runner=self._runner,
                    what=f"leaf signing for {host}",
                )
            self._verify(cert_path, what=f"leaf verification for {host}")
            return IssuedCertificate(host, cert_path, key_path)

    @staticmethod
    def _san(host: str) -> str:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
                raise CertificateError(f"refusing unsafe TLS host name: {host!r}") from None
            return f"DNS:{host}"
        return f"IP:{address.compressed}"

    def remove(self) -> None:
        """Delete CA and leaf material. Trust removal is a separate act."""
        for path in sorted(self.root.rglob("*"), reverse=True):
            if path.is_dir() and not path.is_symlink():
                path.rmdir()
            else:
                path.unlink()
        if self.root.exists():
            try:
                self.root.rmdir()
            except OSError:
                # Another writer may still hold a file open; removal is
                # best-effort and the caller re-checks existence.
                pass


# -- trust-store installation -------------------------------------------------


def _login_keychain() -> str:
    return str(Path.home() / "Library" / "Keychains" / "login.keychain-db")


_LINUX_SYSTEM_CERT = Path("/usr/local/share/ca-certificates/plan-auditor-traffic.crt")
_LINUX_CA_BUNDLE = Path("/etc/ssl/certs/ca-certificates.crt")


def install_trust(
    cert_path: str | Path,
    *,
    runner: Runner | None = None,
    platform: str | None = None,
    ca: CertificateAuthority | None = None,
) -> tuple[bool, str]:
    cert = Path(cert_path)
    platform = platform or sys.platform
    run = runner or _default_runner
    if platform.startswith("win"):
        thumb = ca.fingerprint() if ca is not None else certificate_fingerprint(cert)
        added = run(["certutil", "-addstore", "-user", "Root", str(cert)])
        if added.returncode != 0:
            return False, f"certutil addstore failed: {_detail(added)}"
        checked = run(["certutil", "-user", "-store", "Root", thumb])
        return (
            checked.returncode == 0,
            "trusted in the current-user Root store"
            if checked.returncode == 0
            else f"certutil verification failed: {_detail(checked)}",
        )
    if platform.startswith("linux"):
        copied = run(["cp", str(cert), str(_LINUX_SYSTEM_CERT)])
        if copied.returncode != 0:
            return False, f"cannot copy CA into the system store: {_detail(copied)}"
        updated = run(["update-ca-certificates"])
        if updated.returncode != 0:
            return False, f"update-ca-certificates failed: {_detail(updated)}"
        verified = run(["openssl", "verify", "-CAfile", str(_LINUX_CA_BUNDLE), str(cert)])
        return (
            verified.returncode == 0,
            "trusted by the system CA bundle"
            if verified.returncode == 0
            else f"system bundle verification failed: {_detail(verified)}",
        )
    if platform == "darwin":
        added = run([
            "security", "add-trusted-cert", "-d", "-r", "trustRoot",
            "-k", _login_keychain(), str(cert),
        ])
        if added.returncode != 0:
            return False, f"security add-trusted-cert failed: {_detail(added)}"
        checked = run(["security", "verify-cert", "-c", str(cert), "-p", "ssl"])
        return (
            checked.returncode == 0,
            "trusted in the login keychain"
            if checked.returncode == 0
            else f"security verification failed: {_detail(checked)}",
        )
    return False, f"unsupported platform for trust installation: {platform}"


def uninstall_trust(
    cert_path: str | Path,
    *,
    runner: Runner | None = None,
    platform: str | None = None,
    ca: CertificateAuthority | None = None,
) -> tuple[bool, str]:
    cert = Path(cert_path)
    platform = platform or sys.platform
    run = runner or _default_runner
    if platform.startswith("win"):
        thumb = ca.fingerprint() if ca is not None else certificate_fingerprint(cert)
        deleted = run(["certutil", "-delstore", "-user", "Root", thumb])
        if deleted.returncode != 0:
            return False, f"certutil delstore failed: {_detail(deleted)}"
        checked = run(["certutil", "-user", "-store", "Root", thumb])
        return (
            checked.returncode != 0,
            "removed from the current-user Root store"
            if checked.returncode != 0
            else "certificate still present in the Root store",
        )
    if platform.startswith("linux"):
        removed = run(["rm", "-f", str(_LINUX_SYSTEM_CERT)])
        if removed.returncode != 0:
            return False, f"cannot remove CA from the system store: {_detail(removed)}"
        updated = run(["update-ca-certificates", "--fresh"])
        if updated.returncode != 0:
            return False, f"update-ca-certificates failed: {_detail(updated)}"
        checked = run(["openssl", "verify", "-CAfile", str(_LINUX_CA_BUNDLE), str(cert)])
        return (
            checked.returncode != 0,
            "removed from the system CA bundle"
            if checked.returncode != 0
            else "certificate still trusted by the system bundle",
        )
    if platform == "darwin":
        removed = run(["security", "remove-trusted-cert", "-d", str(cert)])
        if removed.returncode != 0:
            return False, f"security remove-trusted-cert failed: {_detail(removed)}"
        checked = run(["security", "verify-cert", "-c", str(cert), "-p", "ssl"])
        return (
            checked.returncode != 0,
            "removed from the login keychain"
            if checked.returncode != 0
            else "certificate still trusted by the login keychain",
        )
    return False, f"unsupported platform for trust removal: {platform}"


# ------------------------------------------------------------------ proxy


class ProxyError(RuntimeError):
    """A captured request could not be parsed or forwarded safely."""


@dataclass
class Capture:
    request: TrafficRequest
    classification: TrafficClassification
    record: dict[str, Any]
    seq: int
    entry_hash: str
    reasons: tuple[str, ...] = field(default_factory=tuple)


def _read_until(rfile: BinaryIO, marker: bytes, limit: int, *, what: str) -> bytes:
    data = b""
    while marker not in data:
        chunk = rfile.read(1)
        if not chunk:
            return data
        data += chunk
        if len(data) > limit:
            raise ProxyError(f"{what} exceeds {limit} bytes")
    return data


def _read_exact(rfile: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = rfile.read(remaining)
        if not chunk:
            raise ProxyError("request body ended before Content-Length")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_chunked(rfile: BinaryIO) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        line = rfile.readline(1024)
        if not line:
            raise ProxyError("chunked body ended before the final chunk")
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as exc:
            raise ProxyError("invalid chunk size") from exc
        if size == 0:
            while True:
                trailer = rfile.readline(MAX_HEADER_BYTES)
                if not trailer or trailer in (b"\r\n", b"\n"):
                    return b"".join(chunks)
        total += size
        if total > MAX_BODY_BYTES:
            raise ProxyError(f"request body exceeds {MAX_BODY_BYTES} bytes")
        chunks.append(_read_exact(rfile, size))
        terminator = rfile.read(2)
        if terminator != b"\r\n":
            raise ProxyError("invalid chunk terminator")


def _parse_http_request(rfile: BinaryIO) -> tuple[str, str, dict[str, str], bytes] | None:
    head = _read_until(rfile, b"\r\n\r\n", MAX_HEADER_BYTES, what="request headers")
    if not head:
        return None
    lines = head[:-4].decode("latin-1").split("\r\n")
    if not lines or not lines[0]:
        raise ProxyError("empty request line")
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise ProxyError("malformed request line")
    method, path, _version = parts
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise ProxyError("malformed request header")
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = _read_chunked(rfile)
    elif "content-length" in headers:
        try:
            length = int(headers["content-length"])
        except ValueError as exc:
            raise ProxyError("invalid Content-Length") from exc
        if length < 0:
            raise ProxyError("negative Content-Length")
        if length > MAX_BODY_BYTES:
            raise ProxyError(f"request body exceeds {MAX_BODY_BYTES} bytes")
        body = _read_exact(rfile, length)
    else:
        body = b""
    return method, path, headers, body


def _split_authority(authority: str) -> tuple[str, int]:
    value = authority.strip()
    if not value:
        raise ProxyError("empty CONNECT authority")
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            raise ProxyError("malformed IPv6 authority")
        host = value[1:end]
        rest = value[end + 1:]
        try:
            port = int(rest[1:]) if rest.startswith(":") and rest[1:] else 443
        except ValueError as exc:
            raise ProxyError("invalid CONNECT port") from exc
    elif ":" in value:
        host, port_text = value.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ProxyError("invalid CONNECT port") from exc
    else:
        host, port = value, 443
    if not host:
        raise ProxyError("empty CONNECT host")
    if not 0 < port < 65536:
        raise ProxyError("CONNECT port out of range")
    return host, port


def _host_header(host: str, port: int) -> str:
    rendered = f"[{host}]" if ":" in host else host
    return rendered if port == 443 else f"{rendered}:{port}"


class _ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[socketserver.BaseRequestHandler],
        owner: TrafficProxy,
    ) -> None:
        self.owner = owner
        super().__init__(address, handler)


class _ProxyHandler(socketserver.BaseRequestHandler):
    server: _ProxyServer

    def handle(self) -> None:
        owner = self.server.owner
        try:
            rfile = self.request.makefile("rb")
            try:
                raw = _read_until(
                    rfile, b"\r\n\r\n", MAX_HEADER_BYTES, what="CONNECT headers"
                )
            finally:
                rfile.close()
            if not raw:
                return
            first = raw.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first.split(" ")
            if len(parts) != 3 or parts[0].upper() != "CONNECT":
                self.request.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
                return
            host, port = _split_authority(parts[1])
            issued = owner.ca.issue(host)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(issued.cert_path), str(issued.key_path))
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            with context.wrap_socket(self.request, server_side=True) as tls:
                owner.serve_tunnel(tls, host, port)
        except (ProxyError, CertificateError, ssl.SSLError, OSError, ValueError):
            # A malformed tunnel gets a closed connection, never a guessed
            # success. The proxy remains available for the next request.
            return
        finally:
            with contextlib.suppress(OSError):
                self.request.close()


class TrafficProxy:
    """A loopback HTTPS proxy that appends one chained record per request."""

    def __init__(
        self,
        ca: CertificateAuthority,
        *,
        append_record: Callable[[dict[str, Any]], str],
        plan: str,
        session_id: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        upstream_map: Mapping[str, tuple[str, int]] | None = None,
        upstream_ca: str | Path | None = None,
    ) -> None:
        self.ca = ca
        self.append_record = append_record
        self.plan = plan
        self.session_id = session_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_map = dict(upstream_map or {})
        self.upstream_ca = Path(upstream_ca) if upstream_ca is not None else None
        self.lock = threading.Lock()
        self._server: _ProxyServer | None = None
        self._thread: threading.Thread | None = None
        self.captures: list[Capture] = []
        self.last_upstream_error = ""
        self.last_evidence_error = ""

    @property
    def port(self) -> int:
        if self._server is None:
            return 0
        return int(self._server.server_address[1])

    def start(self) -> int:
        if self._server is not None:
            raise ProxyError("proxy is already running")
        self.ca.ensure()
        self._server = _ProxyServer((self.listen_host, self.listen_port), _ProxyHandler, self)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="plan-auditor-traffic-proxy", daemon=True
        )
        self._thread.start()
        return self.port

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        server.shutdown()
        server.server_close()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> TrafficProxy:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def serve_tunnel(self, tls: ssl.SSLSocket, host: str, port: int) -> None:
        rfile = tls.makefile("rb")
        try:
            parsed = _parse_http_request(rfile)
            if parsed is None:
                return
            method, path, headers, body = parsed
            request = TrafficRequest(
                method=method,
                host=host,
                port=port,
                path=path,
                headers=headers,
                body=body,
            )
            classification = classify_request(request)
            try:
                self.record(request, classification)
            except (OSError, RuntimeError, ValueError) as exc:
                self.last_evidence_error = str(exc)
                tls.sendall(self._json_response(502, {"error": "traffic evidence write failed"}))
                return
            try:
                response = self.forward(request, headers, body)
            except (OSError, http.client.HTTPException, ssl.SSLError, ProxyError) as exc:
                self.last_upstream_error = str(exc)
                response = self._json_response(502, {"error": "upstream request failed"})
            tls.sendall(response)
        finally:
            with contextlib.suppress(OSError):
                rfile.close()

    def record(
        self, request: TrafficRequest, classification: TrafficClassification
    ) -> Capture:
        with self.lock:
            seq = len(self.captures) + 1
            record = request_record(
                request,
                classification,
                plan=self.plan,
                session_id=self.session_id,
                seq=seq,
            )
            entry_hash = self.append_record(record)
            capture = Capture(
                request=request,
                classification=classification,
                record=record,
                seq=seq,
                entry_hash=entry_hash,
                reasons=classification.reasons,
            )
            self.captures.append(capture)
        return capture

    def forward(
        self, request: TrafficRequest, headers: dict[str, str], body: bytes
    ) -> bytes:
        connect_host, connect_port = self.upstream_map.get(
            request.host.lower(), (request.host, request.port)
        )
        context = ssl.create_default_context(
            cafile=str(self.upstream_ca) if self.upstream_ca is not None else None
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        raw_socket = socket.create_connection((connect_host, connect_port), timeout=20)
        upstream = context.wrap_socket(raw_socket, server_hostname=request.host)
        connection = http.client.HTTPConnection(request.host, request.port, timeout=20)
        connection.sock = upstream
        try:
            connection.putrequest(
                request.method,
                request.path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            for name, value in headers.items():
                if name in _HOP_BY_HOP or name in {"host", "content-length"}:
                    continue
                connection.putheader(name, value)
            connection.putheader("Host", _host_header(request.host, request.port))
            if body or "content-length" in headers:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body if body else None)
            response = connection.getresponse()
            data = response.read()
            lines = [f"HTTP/1.1 {response.status} {response.reason}\r\n"]
            for name, value in response.getheaders():
                if name.lower() in _HOP_BY_HOP or name.lower() == "content-length":
                    continue
                lines.append(f"{name}: {value}\r\n")
            lines.append(f"Content-Length: {len(data)}\r\n")
            lines.append("Connection: close\r\n\r\n")
            return "".join(lines).encode("latin-1") + data
        finally:
            with contextlib.suppress(OSError):
                connection.close()
            upstream.close()

    @staticmethod
    def _json_response(status: int, payload: dict[str, Any]) -> bytes:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        head = (
            f"HTTP/1.1 {status} Error\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n"
        )
        return head.encode("latin-1") + body


# ---------------------------------------------------------------- daemon


def run_daemon(
    workspace: str | Path,
    *,
    plan: str,
    port: int,
    session_id: str,
    started_at: str,
) -> int:
    """Own one proxy session and append its closing record exactly once."""
    from scripts import audit_check as core

    root = Path(workspace).resolve()
    safe_plan = _safe_plan_name(plan)
    ca = CertificateAuthority(pki_dir(root))
    parent = load_state(root, safe_plan) or {}
    preserved: dict[str, Any] = {
        key: parent[key]
        for key in ("allowed_hosts", "trust_installed", "trust_detail")
        if key in parent
    }
    state_base = {
        "version": 1,
        "workspace": str(root),
        "plan": safe_plan,
        "session_id": session_id,
        "started_at": started_at,
        "pid": os.getpid(),
        **preserved,
    }

    def append(record: dict[str, Any]) -> str:
        writer = cast(Callable[[str, Mapping[str, Any]], str], core.append_evidence)
        return writer(str(root), record)

    try:
        ca.ensure()
        proxy = TrafficProxy(
            ca,
            append_record=append,
            plan=safe_plan,
            session_id=session_id,
            listen_host="127.0.0.1",
            listen_port=port,
        )
        actual_port = proxy.start()
    except (OSError, RuntimeError) as exc:
        write_state(
            root,
            safe_plan,
            {**state_base, "running": False, "starting": False,
             "error": str(exc), "stopped_at": _now()},
        )
        return 3

    write_state(
        root,
        safe_plan,
        {**state_base, "running": True, "starting": False, "port": actual_port,
         "ca_cert": str(ca.cert_path), "ca_fingerprint": ca.fingerprint(),
         "proxy_url": f"http://127.0.0.1:{actual_port}"},
    )
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except (ValueError, OSError):
            # A platform without this signal still has the stop file.
            pass
    _set_workspace(root, safe_plan)
    try:
        while not _stop_requested():
            time.sleep(0.1)
    finally:
        proxy.stop()
        stopped_at = _now()
        record = session_record(
            plan=safe_plan,
            session_id=session_id,
            started_at=started_at,
            stopped_at=stopped_at,
            captures=[capture.record for capture in proxy.captures],
        )
        try:
            append(record)
            error = ""
        except (OSError, RuntimeError, ValueError) as exc:
            error = f"could not persist the closing session record: {exc}"
        write_state(
            root,
            safe_plan,
            {**state_base, "running": False, "starting": False, "port": actual_port,
             "ca_cert": str(ca.cert_path), "ca_fingerprint": ca.fingerprint(),
             "proxy_url": f"http://127.0.0.1:{actual_port}",
             "stopped_at": stopped_at, "requests": record["requests"],
             "classes": record["classes"], "silent": record["silent"],
             **({"error": error} if error else {})},
        )
        with contextlib.suppress(OSError):
            stop_path(root, safe_plan).unlink()
    return 0


_STOP_EVENT = False
_WORKSPACE = Path(".")
_PLAN = "default"


def _set_workspace(root: Path, plan: str) -> None:
    global _WORKSPACE, _PLAN
    _WORKSPACE = root
    _PLAN = plan


def _handle_signal(_signum: int, _frame: FrameType | None) -> None:
    global _STOP_EVENT
    _STOP_EVENT = True


def _stop_requested() -> bool:
    return stop_path(_WORKSPACE, _PLAN).exists() or _STOP_EVENT


def _build_daemon_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plan-auditor-traffic-daemon")
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--plan", default="default")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--started-at", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_daemon_parser().parse_args(argv)
    return run_daemon(
        args.workspace,
        plan=args.plan,
        port=args.port,
        session_id=args.session_id,
        started_at=args.started_at,
    )


if __name__ == "__main__":
    raise SystemExit(main())
