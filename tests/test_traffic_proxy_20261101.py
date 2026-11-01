"""End-to-end loopback proxy: fixed requests become chained ledger records."""
from __future__ import annotations

import hashlib
import io
import json
import socket
import socketserver
import ssl
import threading
import types
from pathlib import Path

import pytest

from scripts.traffic import (
    MAX_BODY_BYTES,
    TRAFFIC_CLASS_PROMPT,
    TRAFFIC_CLASS_TELEMETRY,
    TRAFFIC_CLASS_TRANSCRIPT_UPLOAD,
    CertificateAuthority,
    CertificateError,
    ProxyError,
    TrafficProxy,
    TrafficRequest,
    _host_header,
    _parse_http_request,
    _read_chunked,
    _read_exact,
    _read_until,
    _split_authority,
    classify_request,
)


class _UpstreamServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, ca: CertificateAuthority) -> None:
        self.ca = ca
        self.requests: list[dict] = []
        default = ca.issue("default.test")
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(default.cert_path), str(default.key_path))
        self.context.set_servername_callback(self._select_context)
        super().__init__(("127.0.0.1", 0), _UpstreamHandler)

    def _select_context(self, ssl_socket, server_name, _context) -> None:
        if not server_name:
            return
        issued = self.ca.issue(server_name)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(issued.cert_path), str(issued.key_path))
        ssl_socket.context = context

    @property
    def port(self) -> int:
        return self.server_address[1]


class _UpstreamHandler(socketserver.BaseRequestHandler):
    server: _UpstreamServer

    def handle(self) -> None:
        try:
            tls = self.server.context.wrap_socket(self.request, server_side=True)
        except (ssl.SSLError, OSError):
            return
        with tls:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, path, _ = lines[0].split(" ")
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
            length = int(headers.get("content-length", "0"))
            while len(body) < length:
                chunk = tls.recv(length - len(body))
                if not chunk:
                    break
                body += chunk
            self.server.requests.append(
                {"method": method, "path": path, "headers": headers, "body": body}
            )
            payload = b'{"ok": true}'
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + payload
            )


@pytest.fixture(scope="module")
def upstream_ca(tmp_path_factory) -> CertificateAuthority:
    ca = CertificateAuthority(tmp_path_factory.mktemp("upstream-ca"))
    ca.ensure()
    return ca


@pytest.fixture(scope="module")
def upstream(upstream_ca):
    server = _UpstreamServer(upstream_ca)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture(scope="module")
def watch_ca(tmp_path_factory) -> CertificateAuthority:
    ca = CertificateAuthority(tmp_path_factory.mktemp("watch-ca"))
    ca.ensure()
    return ca


def start_proxy(
    watch_ca,
    upstream,
    *,
    records: list[dict] | None = None,
    append=None,
    upstream_map=None,
    upstream_ca: Path | None = None,
):
    captured = records if records is not None else []

    def default_append(record):
        captured.append(record)
        return f"hash-{len(captured)}"

    proxy = TrafficProxy(
        watch_ca,
        append_record=append or default_append,
        plan="default",
        session_id="session-test",
        upstream_map=upstream_map
        or {
            "api.test": ("127.0.0.1", upstream.port),
            "telemetry.test": ("127.0.0.1", upstream.port),
        },
        upstream_ca=upstream_ca or upstream.ca.cert_path,
    )
    proxy.start()
    return proxy, captured


def _read_until_socket(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def send_through_proxy(
    port: int,
    ca_cert: Path,
    *,
    host: str = "api.test",
    method: str = "POST",
    path: str = "/v1/messages",
    headers: dict[str, str] | None = None,
    body: bytes = b"",
    payload: bytes | None = None,
    raw_request: bytes | None = None,
) -> bytes:
    raw = socket.create_connection(("127.0.0.1", port), timeout=15)
    raw.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
    head = _read_until_socket(raw, b"\r\n\r\n")
    assert b" 200 " in head, head
    context = ssl.create_default_context(cafile=str(ca_cert))
    tls = context.wrap_socket(raw, server_hostname=host)
    try:
        all_headers = {"Host": host, "Connection": "close"}
        all_headers.update(headers or {})
        lines = [f"{method} {path} HTTP/1.1"]
        lines.extend(f"{name}: {value}" for name, value in all_headers.items())
        if raw_request is not None:
            tls.sendall(raw_request)
        elif payload is not None:
            request_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + payload
            tls.sendall(request_bytes)
        else:
            lines.append(f"Content-Length: {len(body)}")
            request_bytes = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
            tls.sendall(request_bytes)
        response = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            response += chunk
        return response
    finally:
        tls.close()


class TestEndToEnd:
    def test_fixed_prompt_request_is_recorded_and_forwarded(self, watch_ca, upstream):
        proxy, records = start_proxy(watch_ca, upstream)
        body = b'{"messages": [{"role": "user", "content": "hello"}]}'
        try:
            response = send_through_proxy(
                proxy.port,
                watch_ca.cert_path,
                headers={"Content-Type": "application/json"},
                body=body,
            )
        finally:
            proxy.stop()

        assert b"200 OK" in response and b'{"ok": true}' in response
        assert upstream.requests[-1]["body"] == body
        assert upstream.requests[-1]["path"] == "/v1/messages"
        assert len(proxy.captures) == 1
        capture = proxy.captures[0]
        assert capture.classification.classification == TRAFFIC_CLASS_PROMPT
        assert capture.seq == 1
        assert capture.entry_hash == "hash-1"
        assert capture.reasons == ("path:model-api",)
        assert records[0]["payload_sha256"] == hashlib.sha256(body).hexdigest()
        assert records[0]["session_id"] == "session-test"
        assert records[0]["mode"] == "traffic_request"

    def test_transcript_upload_is_recorded_and_forwarded_in_monitor_mode(
        self, watch_ca, upstream
    ):
        proxy, records = start_proxy(watch_ca, upstream)
        try:
            response = send_through_proxy(
                proxy.port, watch_ca.cert_path, path="/upload", body=b'{"dump": "transcript"}'
            )
        finally:
            proxy.stop()
        assert b"200 OK" in response
        assert proxy.captures[0].classification.classification == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD
        assert records[0]["class"] == TRAFFIC_CLASS_TRANSCRIPT_UPLOAD

    def test_telemetry_is_recorded(self, watch_ca, upstream):
        proxy, _records = start_proxy(watch_ca, upstream)
        try:
            response = send_through_proxy(
                proxy.port,
                watch_ca.cert_path,
                host="telemetry.test",
                path="/v1/events",
                body=b'{"event": "start"}',
            )
        finally:
            proxy.stop()
        assert b"200 OK" in response
        assert proxy.captures[0].classification.classification == TRAFFIC_CLASS_TELEMETRY

    def test_upstream_failure_returns_502_but_keeps_evidence(self, watch_ca, upstream):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        proxy, records = start_proxy(
            watch_ca, upstream, upstream_map={"api.test": ("127.0.0.1", closed_port)}
        )
        try:
            response = send_through_proxy(proxy.port, watch_ca.cert_path, body=b'{"messages": []}')
        finally:
            proxy.stop()
        assert b"502" in response
        assert proxy.last_upstream_error
        assert len(proxy.captures) == 1
        assert len(records) == 1

    def test_missing_upstream_ca_still_fails_and_records(self, watch_ca, upstream):
        proxy, records = start_proxy(watch_ca, upstream, upstream_ca=Path("missing-ca.pem"))
        try:
            response = send_through_proxy(proxy.port, watch_ca.cert_path, body=b'{"messages": []}')
        finally:
            proxy.stop()
        assert b"502" in response
        assert proxy.last_upstream_error
        assert len(records) == 1

    def test_evidence_write_failure_blocks_forwarding(self, watch_ca, upstream):
        upstream.requests.clear()

        def append(_record):
            raise OSError("disk full")

        proxy, _records = start_proxy(watch_ca, upstream, append=append)
        try:
            response = send_through_proxy(proxy.port, watch_ca.cert_path, body=b'{"messages": []}')
        finally:
            proxy.stop()
        assert b"502" in response
        assert json.loads(response.split(b"\r\n\r\n", 1)[1])["error"] == (
            "traffic evidence write failed"
        )
        assert upstream.requests == []
        assert proxy.last_evidence_error == "disk full"

    def test_chunked_request_is_decoded_and_forwarded(self, watch_ca, upstream):
        proxy, records = start_proxy(watch_ca, upstream)
        payload = b'7\r\n{"messa\r\n9\r\nges": []}\r\n0\r\n\r\n'
        try:
            response = send_through_proxy(
                proxy.port,
                watch_ca.cert_path,
                headers={"Transfer-Encoding": "chunked"},
                payload=payload,
            )
        finally:
            proxy.stop()
        assert b"200 OK" in response
        assert upstream.requests[-1]["body"] == b'{"messages": []}'
        assert records[0]["payload_bytes"] == len(b'{"messages": []}')

    def test_malformed_inner_request_closes_without_a_capture(self, watch_ca, upstream):
        proxy, _records = start_proxy(watch_ca, upstream)
        try:
            response = send_through_proxy(
                proxy.port,
                watch_ca.cert_path,
                raw_request=b"POST / HTTP/1.1\r\nHost: api.test\r\nBroken\r\n\r\n",
            )
        finally:
            proxy.stop()
        assert response == b""
        assert proxy.captures == []

    def test_empty_tunnel_request_is_ignored(self, watch_ca, upstream):
        proxy, _records = start_proxy(watch_ca, upstream)
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            raw.sendall(b"CONNECT api.test:443 HTTP/1.1\r\n\r\n")
            _read_until_socket(raw, b"\r\n\r\n")
            context = ssl.create_default_context(cafile=str(watch_ca.cert_path))
            tls = context.wrap_socket(raw, server_hostname="api.test")
            tls.close()
        finally:
            proxy.stop()
        assert proxy.captures == []

    def test_get_without_body_or_content_length_is_forwarded(self, watch_ca, upstream):
        proxy, _records = start_proxy(watch_ca, upstream)
        try:
            response = send_through_proxy(
                proxy.port, watch_ca.cert_path, method="GET", path="/health", payload=b""
            )
        finally:
            proxy.stop()
        assert b"200 OK" in response
        assert proxy.captures[0].record["payload_bytes"] == 0
        assert "content-length" not in upstream.requests[-1]["headers"]

    def test_forward_strips_hop_by_hop_headers_and_sets_host(self, watch_ca, upstream):
        proxy, _records = start_proxy(watch_ca, upstream)
        try:
            response = send_through_proxy(
                proxy.port,
                watch_ca.cert_path,
                headers={
                    "Proxy-Connection": "keep-alive",
                    "Keep-Alive": "timeout=5",
                    "X-Trace": "yes",
                },
                body=b"",
            )
        finally:
            proxy.stop()
        assert b"200 OK" in response
        forwarded = upstream.requests[-1]["headers"]
        assert "proxy-connection" not in forwarded
        assert "keep-alive" not in forwarded
        assert forwarded["x-trace"] == "yes"
        assert forwarded["host"] == "api.test"
        assert forwarded["content-length"] == "0"


class TestHandlerProtocol:
    def test_non_connect_is_rejected(self, watch_ca):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            response = _read_until_socket(raw, b"\r\n\r\n")
            raw.close()
        finally:
            proxy.stop()
        assert b"405" in response
        assert proxy.captures == []

    def test_malformed_connect_is_closed(self, watch_ca):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            raw.sendall(b"CONNECT api.test:notaport HTTP/1.1\r\n\r\n")
            try:
                assert raw.recv(4096) == b""
            except (ConnectionResetError, ConnectionAbortedError):
                pass
            raw.close()
        finally:
            proxy.stop()
        assert proxy.captures == []

    def test_certificate_failure_is_closed(self, watch_ca, monkeypatch):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )

        def fail(_host):
            raise CertificateError("cannot issue")

        monkeypatch.setattr(proxy.ca, "issue", fail)
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            raw.sendall(b"CONNECT api.test:443 HTTP/1.1\r\n\r\n")
            try:
                assert raw.recv(4096) == b""
            except (ConnectionResetError, ConnectionAbortedError):
                pass
            raw.close()
        finally:
            proxy.stop()
        assert proxy.captures == []

    def test_empty_connection_is_closed(self, watch_ca):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        proxy.start()
        try:
            raw = socket.create_connection(("127.0.0.1", proxy.port), timeout=15)
            try:
                raw.shutdown(socket.SHUT_WR)
                assert raw.recv(1) == b""
            finally:
                raw.close()
        finally:
            proxy.stop()
        assert proxy.captures == []

    def test_start_stop_lifecycle(self, watch_ca):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        assert proxy.port == 0
        proxy.stop()
        with proxy:
            port = proxy.port
            assert port > 0
            with pytest.raises(ProxyError, match="already running"):
                proxy.start()
        assert proxy.port == 0

    def test_stop_without_a_thread_closes_the_server(self, watch_ca):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        calls = []
        proxy._server = types.SimpleNamespace(
            shutdown=lambda: calls.append("shutdown"),
            server_close=lambda: calls.append("server_close"),
        )
        proxy.stop()
        assert calls == ["shutdown", "server_close"]
        assert proxy._server is None


class TestDirectPaths:
    def test_serve_tunnel_ignores_an_empty_request(self, watch_ca):
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        tls = types.SimpleNamespace(makefile=lambda mode: io.BytesIO(b""))
        proxy.serve_tunnel(tls, "api.test", 443)
        assert proxy.captures == []

    def test_serve_tunnel_survives_a_failing_stream_close(self, watch_ca):
        class Boom(io.BytesIO):
            def close(self):
                raise OSError("close failed")

        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: "h",
            plan="default",
            session_id="s",
        )
        tls = types.SimpleNamespace(makefile=lambda mode: Boom(b""))
        proxy.serve_tunnel(tls, "api.test", 443)
        assert proxy.captures == []

    def test_record_increments_sequence_and_calls_the_writer(self, watch_ca):
        records = []
        proxy = TrafficProxy(
            watch_ca,
            append_record=lambda record: records.append(record) or f"h{len(records)}",
            plan="default",
            session_id="s",
        )
        first = TrafficRequest("POST", "api.test", 443, "/v1/messages", {}, b'{"messages": []}')
        second = TrafficRequest("GET", "api.test", 443, "/health", {}, b"")
        capture_one = proxy.record(first, classify_request(first))
        capture_two = proxy.record(second, classify_request(second))
        assert capture_one.seq == 1 and capture_two.seq == 2
        assert capture_two.entry_hash == "h2"
        assert [record["traffic_seq"] for record in records] == [1, 2]


class TestParsing:
    def test_read_until_limit(self):
        with pytest.raises(ProxyError, match="request headers exceeds 5 bytes"):
            _read_until(io.BytesIO(b"abcdefgh"), b"\r\n\r\n", 5, what="request headers")

    def test_read_until_returns_partial_data_on_eof(self):
        assert _read_until(io.BytesIO(b"abc"), b"\r\n\r\n", 5, what="w") == b"abc"

    def test_read_exact_short_body(self):
        with pytest.raises(ProxyError, match="ended before Content-Length"):
            _read_exact(io.BytesIO(b"abc"), 5)

    def test_parse_empty(self):
        assert _parse_http_request(io.BytesIO(b"")) is None

    def test_parse_malformed_request_line(self):
        with pytest.raises(ProxyError, match="malformed request line"):
            _parse_http_request(io.BytesIO(b"GET /\r\n\r\n"))
        with pytest.raises(ProxyError, match="empty request line"):
            _parse_http_request(io.BytesIO(b"\r\n\r\n"))

    def test_parse_malformed_header(self):
        with pytest.raises(ProxyError, match="malformed request header"):
            _parse_http_request(io.BytesIO(b"GET / HTTP/1.1\r\nBroken\r\n\r\n"))

    def test_parse_content_length_errors(self):
        with pytest.raises(ProxyError, match="invalid Content-Length"):
            _parse_http_request(io.BytesIO(b"POST / HTTP/1.1\r\nContent-Length: x\r\n\r\n"))
        with pytest.raises(ProxyError, match="negative Content-Length"):
            _parse_http_request(io.BytesIO(b"POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"))
        with pytest.raises(ProxyError, match="exceeds"):
            _parse_http_request(
                io.BytesIO(
                    f"POST / HTTP/1.1\r\nContent-Length: {MAX_BODY_BYTES + 1}\r\n\r\n".encode()
                )
            )

    def test_parse_valid_body(self):
        parsed = _parse_http_request(
            io.BytesIO(b"POST /x HTTP/1.1\r\nContent-Length: 3\r\nA: b\r\n\r\nabc")
        )
        assert parsed == ("POST", "/x", {"content-length": "3", "a": "b"}, b"abc")

    def test_parse_no_body(self):
        parsed = _parse_http_request(io.BytesIO(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        assert parsed is not None and parsed[3] == b""

    def test_chunked_errors(self):
        with pytest.raises(ProxyError, match="ended before the final chunk"):
            _read_chunked(io.BytesIO(b""))
        with pytest.raises(ProxyError, match="invalid chunk size"):
            _read_chunked(io.BytesIO(b"zz\r\n"))
        with pytest.raises(ProxyError, match="invalid chunk terminator"):
            _read_chunked(io.BytesIO(b"1\r\naXX"))
        with pytest.raises(ProxyError, match="exceeds"):
            oversized = f"{MAX_BODY_BYTES + 1:x}".encode() + b"\r\n"
            _read_chunked(io.BytesIO(oversized))

    def test_chunked_with_trailers(self):
        assert _read_chunked(io.BytesIO(b"3\r\nabc\r\n0\r\nX-T: y\r\n\r\n")) == b"abc"
        assert _read_chunked(io.BytesIO(b"3\r\nabc\r\n0\r\n\r\n")) == b"abc"
        assert _read_chunked(io.BytesIO(b"3\r\nabc\r\n0\r\n")) == b"abc"

    def test_split_authority(self):
        assert _split_authority("api.test:8443") == ("api.test", 8443)
        assert _split_authority("api.test") == ("api.test", 443)
        assert _split_authority("[::1]:8443") == ("::1", 8443)
        assert _split_authority("[::1]") == ("::1", 443)
        assert _split_authority("[::1]:") == ("::1", 443)

    @pytest.mark.parametrize(
        ("authority", "message"),
        [
            ("", "empty CONNECT authority"),
            ("[::1", "malformed IPv6 authority"),
            ("[::1]:x", "invalid CONNECT port"),
            ("api.test:x", "invalid CONNECT port"),
            (":443", "empty CONNECT host"),
            ("api.test:0", "CONNECT port out of range"),
            ("api.test:70000", "CONNECT port out of range"),
        ],
    )
    def test_split_authority_errors(self, authority, message):
        with pytest.raises(ProxyError, match=message):
            _split_authority(authority)

    def test_host_header(self):
        assert _host_header("api.test", 443) == "api.test"
        assert _host_header("api.test", 8443) == "api.test:8443"
        assert _host_header("::1", 443) == "[::1]"
        assert _host_header("::1", 8443) == "[::1]:8443"

    def test_json_response(self):
        rendered = TrafficProxy._json_response(502, {"error": "x"})
        assert rendered.startswith(b"HTTP/1.1 502 Error\r\n")
        assert rendered.endswith(b'{"error": "x"}')
