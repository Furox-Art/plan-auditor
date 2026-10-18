"""The shipped installed script remains executable when package-style imports fail."""

from __future__ import annotations

import builtins
import runpy
from pathlib import Path

from scripts import audit_check as ac


def test_direct_file_execution_uses_validated_unprefixed_fallbacks(monkeypatch):
    root = Path(ac.__file__).resolve().parent
    monkeypatch.syspath_prepend(str(root))
    actual = builtins.__import__
    suppressed = {
        "scripts.check_isolation",
        "scripts.contract",
        "scripts.exec_trust",
        "scripts.integrity",
        "scripts.plan_graph",
    }
    observed = []

    def fail_package_only(name, *args, **kwargs):
        if name in suppressed:
            observed.append(name)
            raise ImportError("standalone integration requires fallback")
        return actual(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_package_only)
    result = runpy.run_path(str(root / "audit_check.py"), run_name="standalone_audit_check_test")
    assert "scripts.check_isolation" in observed
    assert "scripts.integrity" in observed
    assert "scripts.plan_graph" in observed
    assert callable(result["verify_chain"])
    assert callable(result["validate_plan"])
