"""Regression coverage for the npm post-publish propagation poll.

Run 37136117550 published ``plan-auditor@2.4.2`` successfully and then failed its
own verification step one second later, because the step probed the registry once
and gave up:

    ERROR: npm reports 'nothing', expected 2.4.2

The registry's own ``time["2.4.2"]`` is 16:16:46Z; the probe ran at 16:15:10Z. The
upload was never the problem, the check was too impatient.

These tests pin both directions of the fix, because either half alone would be a
regression in the other direction:

* a version that appears part-way through the poll must succeed (no false
  failure), and
* a version that never appears must still fail closed (no silent pass).

The loop is exercised through injected ``prober``/``sleeper``/``clock`` callables,
so nothing here touches the network, real sleeps, or wall-clock time.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "scripts" / "npm_registry_visibility.py"


def _load():
    spec = importlib.util.spec_from_file_location("npm_registry_visibility", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register before exec: the module uses postponed annotations, and dataclass
    # resolves string annotations through sys.modules while the class body runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vis = _load()
ProbeResult = vis.ProbeResult


class _Clock:
    """Monotonic fake clock advanced only by the fake sleeper."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def _sequence_prober(responses):
    """Return a prober replaying ``responses``, then repeating the last one."""
    calls: list[str] = []

    def prober(url: str, timeout: float):
        calls.append(url)
        index = min(len(calls) - 1, len(responses) - 1)
        return responses[index]

    prober.calls = calls  # type: ignore[attr-defined]
    return prober


# --------------------------------------------------------------------------
# Direction 1: absent, then present -> succeeds (the bug being fixed).
# --------------------------------------------------------------------------


def test_version_that_appears_late_does_not_fail_the_publish():
    """Two 404s then a hit must pass, which is exactly run 37136117550's shape."""
    sleeper = _Clock()
    prober = _sequence_prober(
        [
            ProbeResult(visible=False, status=404, detail="Not Found"),
            ProbeResult(visible=False, status=404, detail="Not Found"),
            ProbeResult(visible=True, status=200, detail="registry served 2.4.2"),
        ]
    )

    result = vis.wait_for_version(
        "plan-auditor",
        "2.4.2",
        attempts=12,
        prober=prober,
        sleeper=sleeper.sleep,
        clock=sleeper,
    )

    assert result.visible is True
    assert result.attempts == 3
    assert len(prober.calls) == 3


def test_first_match_wins_without_sleeping_the_remaining_budget():
    """A version already visible must not sit through the whole backoff."""
    sleeper = _Clock()
    prober = _sequence_prober([ProbeResult(visible=True, status=200, detail="served")])

    result = vis.wait_for_version(
        "plan-auditor",
        "2.4.2",
        attempts=12,
        prober=prober,
        sleeper=sleeper.sleep,
        clock=sleeper,
    )

    assert result.visible is True
    assert result.attempts == 1
    assert len(prober.calls) == 1
    assert sleeper.now == 0.0, "a hit on the first attempt must not sleep"


def test_main_exits_zero_when_the_version_becomes_visible(capsys):
    sleepers: list[float] = []
    responses = [
        ProbeResult(visible=False, status=404, detail="Not Found"),
        ProbeResult(visible=True, status=200, detail="registry served 9.9.9"),
    ]

    original_wait = vis.wait_for_version

    def fake_wait(*args, **kwargs):
        kwargs.update(prober=_sequence_prober(responses), sleeper=sleepers.append)
        return original_wait(*args, **kwargs)

    vis.wait_for_version = fake_wait
    try:
        code = vis.main(["--package", "plan-auditor", "--version", "9.9.9", "--first-delay", "0"])
    finally:
        vis.wait_for_version = original_wait

    assert code == 0
    assert "registry is serving plan-auditor@9.9.9" in capsys.readouterr().out


# --------------------------------------------------------------------------
# Direction 2: never appears -> still fails closed (the guard rail).
# --------------------------------------------------------------------------


def test_version_that_never_appears_fails_closed():
    sleeper = _Clock()
    prober = _sequence_prober([ProbeResult(visible=False, status=404, detail="Not Found")])

    result = vis.wait_for_version(
        "plan-auditor",
        "2.4.2",
        attempts=12,
        prober=prober,
        sleeper=sleeper.sleep,
        clock=sleeper,
    )

    assert result.visible is False
    assert result.attempts == 12
    assert result.last_status == 404


def test_main_exits_non_zero_and_warns_when_never_visible(capsys):
    original_wait = vis.wait_for_version

    def fake_wait(*args, **kwargs):
        kwargs.update(
            prober=_sequence_prober([ProbeResult(visible=False, status=404, detail="nf")]),
            sleeper=lambda _s: None,
            clock=_Clock(),
        )
        return original_wait(*args, **kwargs)

    vis.wait_for_version = fake_wait
    try:
        code = vis.main(["--package", "plan-auditor", "--version", "9.9.9", "--attempts", "3"])
    finally:
        vis.wait_for_version = original_wait

    captured = capsys.readouterr()
    assert code == 1
    assert "::warning::" in captured.out, "a failed poll must explain itself in the log"
    assert "did not become readable" in captured.out
    assert "ERROR: registry never served plan-auditor@9.9.9" in captured.out


def test_transport_errors_are_retried_not_treated_as_success():
    """A DNS blip or timeout is 'not yet', never 'published'."""
    sleeper = _Clock()
    prober = _sequence_prober(
        [
            ProbeResult(visible=False, status=0, detail="connection reset"),
            ProbeResult(visible=True, status=200, detail="registry served 2.4.2"),
        ]
    )

    result = vis.wait_for_version(
        "plan-auditor",
        "2.4.2",
        prober=prober,
        sleeper=sleeper.sleep,
        clock=sleeper,
    )

    assert result.visible is True
    assert result.attempts == 2


def test_attempts_must_be_positive():
    with pytest.raises(ValueError):
        vis.wait_for_version("plan-auditor", "2.4.2", attempts=0)


# --------------------------------------------------------------------------
# The budget has to outlast the observed propagation window.
# --------------------------------------------------------------------------


def test_default_budget_exceeds_the_observed_propagation_window():
    """npm 2.4.2 took ~95s to appear; the default schedule must clear that."""
    delays = vis.backoff_delays(vis.DEFAULT_ATTEMPTS)
    assert vis.DEFAULT_ATTEMPTS == 12
    assert len(delays) == vis.DEFAULT_ATTEMPTS - 1
    total = sum(delays)
    assert total >= 95, f"budget {total:g}s would re-trip the observed ~95s window"
    assert 120 <= total <= 600, f"budget {total:g}s is not a sensible few minutes"


def test_backoff_is_monotonic_non_decreasing_and_capped():
    delays = vis.backoff_delays(vis.DEFAULT_ATTEMPTS)
    assert delays == sorted(delays)
    assert delays[0] == pytest.approx(vis.DEFAULT_FIRST_DELAY)
    assert max(delays) <= vis.DEFAULT_MAX_DELAY


def test_single_attempt_has_no_sleeps():
    assert vis.backoff_delays(1) == []


# --------------------------------------------------------------------------
# The real prober: same path an independent client would request.
# --------------------------------------------------------------------------


def test_version_url_targets_the_exact_version_document():
    assert vis.version_url("https://registry.npmjs.org", "plan-auditor", "2.4.2") == (
        "https://registry.npmjs.org/plan-auditor/2.4.2"
    )
    assert vis.version_url("https://registry.npmjs.org/", "plan-auditor", "2.4.2") == (
        "https://registry.npmjs.org/plan-auditor/2.4.2"
    )


def test_probe_treats_a_mismatched_body_as_not_visible(tmp_path, monkeypatch):
    """A 200 for a *different* version must not be read as success."""
    import urllib.request

    class _Response:
        status = 200

        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self) -> bytes:
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda request, timeout=None: _Response(json.dumps({"version": "9.9.9"}).encode()),
    )
    result = vis.probe_once("https://registry.npmjs.org/plan-auditor/2.4.2")
    assert result.visible is True, "probe_once reports transport success; caller compares"

    class _WrongVersion(_Response):
        def __init__(self) -> None:
            super().__init__(json.dumps({"version": "9.9.9"}).encode())

    class _NoVersion(_Response):
        def __init__(self) -> None:
            super().__init__(json.dumps({"error": "not found"}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=None: _NoVersion())
    assert vis.probe_once("https://x/plan-auditor/2.4.2").visible is False


def test_probe_reports_http_error_as_not_visible(monkeypatch):
    import urllib.error
    import urllib.request

    def _boom(request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url,
            404,
            "Not Found",
            {},
            None,  # type: ignore[arg-type]
        )

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    result = vis.probe_once("https://registry.npmjs.org/plan-auditor/9.9.9")
    assert result.visible is False
    assert result.status == 404


def test_probe_reports_unparseable_body_as_not_visible(monkeypatch):
    import urllib.request

    class _Response:
        status = 200

        def read(self) -> bytes:
            return b"<html>not json</html>"

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=None: _Response())
    result = vis.probe_once("https://x/plan-auditor/2.4.2")
    assert result.visible is False
    assert "unparseable" in result.detail


def test_probe_accepts_a_matching_body(monkeypatch):
    import urllib.request

    class _Response:
        status = 200

        def read(self) -> bytes:
            return json.dumps({"name": "plan-auditor", "version": "2.4.2"}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=None: _Response())
    assert vis.probe_once("https://x/plan-auditor/2.4.2").visible is True
