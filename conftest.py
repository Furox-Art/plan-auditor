"""Test-suite import contract.

The suite must exercise the *installed* ``plan-auditor`` distribution, not a
copy of the source tree that happens to sit next to it. Several test modules
still insert the repository root (or ``scripts/``) onto ``sys.path`` at import
time, which silently shadows an installed wheel: the tests then pass against
local files that may never ship.

This module resolves the two runtime packages *before* any test module is
imported, while the repository root is temporarily removed from ``sys.path``,
and pins the results in ``sys.modules``. Because ``sys.modules`` wins over
``sys.path``, those later ``sys.path.insert`` calls can no longer redirect the
import. The legacy top-level ``import audit_check`` alias used by
``tests/test_audit_check.py`` is mapped onto the installed
``scripts.audit_check`` so both spellings resolve to a single module object
instead of two independent copies with separate global state.

If the distribution is not installed, collection fails loudly instead of
quietly falling back to the source tree.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RUNTIME_PACKAGES = ("supervisor", "scripts")

_INSTALLED: dict[str, object] = {}


def _import_from_installed(name: str):
    """Import ``name`` with the repository root hidden from ``sys.path``.

    ``sys.path`` is restored afterwards so the repository root stays importable:
    ``tests.request_fixture`` and ``examples/fib/fib.py`` are still reached by
    name from the checkout.
    """
    saved = list(sys.path)
    try:
        sys.path[:] = [
            entry
            for entry in sys.path
            if _normalise(entry) != _normalise(ROOT)
            and _normalise(entry) != _normalise(ROOT / "scripts")
        ]
        try:
            return importlib.import_module(name)
        except ImportError as exc:
            raise RuntimeError(
                f"cannot import {name!r} from an installed plan-auditor distribution: {exc}. "
                "Install the package (pip install .) before running the suite."
            ) from exc
    finally:
        sys.path[:] = saved


def _normalise(entry: str | None) -> Path | None:
    if not entry:
        return None
    try:
        return Path(entry).resolve()
    except OSError:  # pragma: no cover - defensive
        return None


def _assert_installed(name: str, module) -> None:
    origin = getattr(module, "__file__", None)
    if origin is None:  # pragma: no cover - namespace package guard
        raise RuntimeError(f"{name} resolved to a namespace package with no file")
    resolved = _normalise(origin)
    if resolved is None:  # pragma: no cover - defensive
        raise RuntimeError(f"{name} origin is not resolvable: {origin!r}")
    if _is_inside(resolved, ROOT / name):
        raise RuntimeError(
            f"{name} was imported from the source checkout ({resolved}) instead of the "
            "installed distribution. Install the package (pip install .) before running "
            "the suite, otherwise the tests validate files that never ship."
        )


def _is_inside(path: Path, parent: Path) -> bool:
    """True when ``path`` is ``parent`` or lives underneath it.

    Compared path-by-path rather than with ``Path.is_relative_to`` on the
    resolved strings alone, because a virtualenv can sit inside the checkout
    (``<repo>/.venv/lib/site-packages/supervisor``). That layout is a perfectly
    good install and must not be mistaken for the source tree.
    """
    resolved_parent = _normalise(parent)
    return resolved_parent is not None and resolved_parent in path.parents


for _name in RUNTIME_PACKAGES:
    _module = _import_from_installed(_name)
    _assert_installed(_name, _module)
    sys.modules[_name] = _module
    _INSTALLED[_name] = _module

# ``tests/test_audit_check.py`` does ``import audit_check`` after inserting the
# source ``scripts/`` directory. Bind that name to the installed module so the
# suite has exactly one ``audit_check`` module object.
try:
    import scripts.audit_check as _audit_check
except ImportError as _exc:  # pragma: no cover - surfaced by the assert above
    raise RuntimeError(f"installed distribution is missing scripts.audit_check: {_exc}") from _exc

sys.modules.setdefault("audit_check", _audit_check)

del _name, _module
