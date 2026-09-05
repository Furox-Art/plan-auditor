from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from supervisor.agents import MultiAgentRegistry


def test_transient_partial_registry_lock_is_retried_without_eviction(tmp_path: Path) -> None:
    """A contender must not fail when it sees an O_EXCL lock before JSON is complete."""
    registry = MultiAgentRegistry(str(tmp_path))
    registry._ensure_dirs()
    registry.REGISTRY_LOCK_TIMEOUT = 0.5

    # Model the visibility window of the real lock acquisition primitive:
    # directory entry exists first, payload becomes valid shortly afterwards,
    # and the live owner eventually releases it.
    registry.lock_path.write_bytes(b"")

    def finish_owner() -> None:
        time.sleep(0.03)
        registry.lock_path.write_text(
            json.dumps({"pid": os.getpid(), "token": "owner", "created": time.time()}),
            encoding="utf-8",
        )
        time.sleep(0.05)
        try:
            registry.lock_path.unlink()
        except FileNotFoundError:
            pass

    owner = threading.Thread(target=finish_owner)
    owner.start()
    with registry._write_lock():
        assert registry.lock_path.exists()
    owner.join(timeout=1)
    assert not registry.lock_path.exists()
