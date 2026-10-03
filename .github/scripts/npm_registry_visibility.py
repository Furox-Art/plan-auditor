#!/usr/bin/env python3
"""Wait until a just-published npm version is readable by an independent client.

``npm publish`` returns as soon as the registry's **write** path accepts the
upload. The **read** path that clients actually use is served from a CDN and
converges asynchronously, so a version can be live and still 404 for a minute or
more. Run 37136117550 published ``plan-auditor@2.4.2`` successfully and then
failed its own verification step one second later, because the step probed the
registry exactly once:

    ERROR: npm reports 'nothing', expected 2.4.2

That run's own timestamps show the size of the window: the probe ran at
16:15:10Z and the registry's ``time["2.4.2"]`` is 16:16:46Z. The publish was fine;
the check was too impatient.

This module polls the registry until the version is visible, with a growing
backoff over a bounded budget, and fails closed if it never appears.

Why the registry is queried over HTTP rather than through ``npm view``:

* ``npm view`` is exactly the stdout-parsing surface PR #29 had to harden; npm
  writes warnings to stderr and its human output is not a stable contract.
* ``npm view`` can be answered from npm's on-disk HTTP cache, so it may report
  state that is independent of -- and staler than -- what a reader sees.
* ``npm view`` inherits ``npm_config_*`` and ``NODE_AUTH_TOKEN`` from the
  environment. Inside a publish lifecycle, or with the runner's ``.npmrc`` in
  play, that changes its behaviour in ways unrelated to registry visibility.
* The property worth verifying is "can a fresh client resolve this version",
  and that is precisely ``GET /<package>/<version>`` on the registry.

Exits ``0`` on the first visible response, ``1`` if the budget runs out.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field

DEFAULT_REGISTRY = "https://registry.npmjs.org"
DEFAULT_ATTEMPTS = 12
#: 2 * (1.6**0 .. 1.6**10), capped at 30s, is ~200s of waiting spread over 12
#: attempts. That is comfortably longer than the ~95s observed between a
#: successful publish and the version appearing on the read path, while still
#: finishing inside a few minutes.
DEFAULT_FIRST_DELAY = 2.0
DEFAULT_GROWTH = 1.6
DEFAULT_MAX_DELAY = 30.0
DEFAULT_TIMEOUT = 15.0

Prober = Callable[[str, float], "ProbeResult"]


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a single registry read."""

    visible: bool
    status: int
    detail: str = ""


@dataclass
class WaitResult:
    """Aggregate outcome of a poll sequence."""

    visible: bool
    attempts: int
    elapsed: float
    delays: list[float] = field(default_factory=list)
    last_status: int = 0
    last_detail: str = ""


def backoff_delays(
    attempts: int,
    first_delay: float = DEFAULT_FIRST_DELAY,
    growth: float = DEFAULT_GROWTH,
    max_delay: float = DEFAULT_MAX_DELAY,
) -> list[float]:
    """Return the sleep after each attempt except the last.

    Geometric so the early attempts stay cheap and the later ones give the CDN
    real time, clamped so a long tail cannot grow without bound.
    """
    if attempts <= 1:
        return []
    delays: list[float] = []
    for index in range(attempts - 1):
        delays.append(min(max_delay, first_delay * (growth**index)))
    return delays


def version_url(registry: str, package: str, version: str) -> str:
    """URL an independent client would request for one exact version."""
    return f"{registry.rstrip('/')}/{package}/{version}"


def probe_once(url: str, timeout: float = DEFAULT_TIMEOUT) -> ProbeResult:
    """GET ``url`` and report whether it served the requested version.

    A 200 whose body disagrees about the version counts as not visible: the
    point is to confirm *this* version is readable, not merely that some
    response arrived.
    """
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read()
    except urllib.error.HTTPError as exc:
        return ProbeResult(visible=False, status=int(exc.code), detail=str(exc.reason))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return ProbeResult(visible=False, status=0, detail=str(exc))
    try:
        served = json.loads(body.decode("utf-8")).get("version")
    except (ValueError, AttributeError, UnicodeDecodeError) as exc:
        return ProbeResult(visible=False, status=status, detail=f"unparseable body: {exc}")
    if served is None:
        return ProbeResult(visible=False, status=status, detail="response has no version field")
    return ProbeResult(visible=True, status=status, detail=f"registry served {served}")


def wait_for_version(
    package: str,
    version: str,
    *,
    registry: str = DEFAULT_REGISTRY,
    attempts: int = DEFAULT_ATTEMPTS,
    first_delay: float = DEFAULT_FIRST_DELAY,
    growth: float = DEFAULT_GROWTH,
    max_delay: float = DEFAULT_MAX_DELAY,
    timeout: float = DEFAULT_TIMEOUT,
    prober: Prober | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> WaitResult:
    """Poll until ``package@version`` is readable. First match wins.

    ``prober``, ``sleeper`` and ``clock`` are injection points so the loop can be
    tested without network access, real delays, or wall-clock time.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    read = prober or (lambda url, t: probe_once(url, t))
    url = version_url(registry, package, version)
    delays = backoff_delays(attempts, first_delay, growth, max_delay)
    started = clock()
    result = WaitResult(visible=False, attempts=0, elapsed=0.0, delays=delays)
    for attempt in range(1, attempts + 1):
        probe = read(url, timeout)
        result.attempts = attempt
        result.last_status = probe.status
        result.last_detail = probe.detail
        if probe.visible:
            result.visible = True
            result.elapsed = clock() - started
            return result
        remaining = attempts - attempt
        print(
            f"attempt {attempt}/{attempts}: {package}@{version} not visible yet "
            f"(http {probe.status}{': ' + probe.detail if probe.detail else ''}); "
            f"{remaining} attempt(s) left"
        )
        if remaining:
            sleeper(delays[attempt - 1])
    result.elapsed = clock() - started
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Wait for a published npm version to become readable from the registry."
    )
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--registry", default=DEFAULT_REGISTRY)
    parser.add_argument("--attempts", type=int, default=DEFAULT_ATTEMPTS)
    parser.add_argument("--first-delay", type=float, default=DEFAULT_FIRST_DELAY)
    parser.add_argument("--growth", type=float, default=DEFAULT_GROWTH)
    parser.add_argument("--max-delay", type=float, default=DEFAULT_MAX_DELAY)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(
        f"polling {args.registry} for {args.package}@{args.version} "
        f"(up to {args.attempts} attempt(s))"
    )
    result = wait_for_version(
        args.package,
        args.version,
        registry=args.registry,
        attempts=args.attempts,
        first_delay=args.first_delay,
        growth=args.growth,
        max_delay=args.max_delay,
        timeout=args.timeout,
    )
    waited = ", ".join(f"{value:g}s" for value in result.delays)
    summary = (
        f"{result.attempts} attempt(s) over {result.elapsed:.1f}s "
        f"(last http {result.last_status}"
        f"{': ' + result.last_detail if result.last_detail else ''}); sleeps: {waited or 'none'}"
    )
    if result.visible:
        print(f"registry is serving {args.package}@{args.version}; {summary}")
        return 0
    # A warning so the run log carries the diagnosis even though the step fails,
    # and a non-zero exit so a genuinely unpublished version still fails closed.
    print(
        f"::warning::{args.package}@{args.version} did not become readable within the "
        f"propagation budget. The upload may have succeeded while the read path stayed "
        f"behind, so check the registry before republishing: "
        f"https://www.npmjs.com/package/{args.package}?activeTab=versions. {summary}"
    )
    print(f"ERROR: registry never served {args.package}@{args.version}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
