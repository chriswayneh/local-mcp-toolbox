"""Windows: a folder swapped for a junction after the pre-open checks is refused.

The swap happens after the resolve, policy, and stat checks and is undone before the
re-resolve, so only the opened-handle real-path check can catch it.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_toolbox.config.settings import (
    AuditSettings,
    IntegrationSettings,
    PermissionProfile,
    SecuritySettings,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime
from mcp_toolbox.tools.security import handlers, safe_reader

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions")

_FALLBACK_FUNCTIONS = frozenset({"_read_resolved", "read_resolved_fallback"})


def _junction(link: Path, target: Path) -> None:
    subprocess.run(  # noqa: S603
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],  # noqa: S607
        check=True,
        capture_output=True,
    )


def _swap_for_junction_during_open(
    monkeypatch: pytest.MonkeyPatch, root: Path, other: Path, name: str
) -> dict[str, bool]:
    real_stat = os.stat
    real_fstat = os.fstat
    state = {"swapped": False, "restored": False}

    def swapping_stat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        # Swap only on the pre-open stat inside the fallback itself, after its checks.
        caller = sys._getframe(1).f_code.co_name
        if (
            not state["swapped"]
            and caller in _FALLBACK_FUNCTIONS
            and Path(path) == root / "pkg" / name
        ):
            state["swapped"] = True
            os.rename(root / "pkg", root / "pkg_real")
            _junction(root / "pkg", other / "pkg")
        return real_stat(path, *args, **kwargs)

    def restoring_fstat(fd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        result = real_fstat(fd, *args, **kwargs)
        if state["swapped"] and not state["restored"]:
            state["restored"] = True
            os.rmdir(root / "pkg")  # removes the junction, not its target
            os.rename(root / "pkg_real", root / "pkg")
        return result

    monkeypatch.setattr(os, "stat", swapping_stat)
    monkeypatch.setattr(os, "fstat", restoring_fstat)
    return state


def _layout(tmp_path: Path, name: str) -> tuple[Path, Path]:
    root = (tmp_path / "approved").resolve()
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / name).write_bytes(b"SAFE = 1\n")
    other = (tmp_path / "other").resolve()
    (other / "pkg").mkdir(parents=True)
    (other / "pkg" / name).write_bytes(b"LEAKED = 1\n")
    return root, other


def test_bandit_fallback_refuses_folder_swapped_for_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert handlers._USE_DIR_FD is False
    root, other = _layout(tmp_path, "a.py")
    snapshot = (tmp_path / "snap").resolve()
    snapshot.mkdir()
    runtime = build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            integrations=IntegrationSettings(security_scanners=True),
            security=SecuritySettings(approved_roots=[root, other]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )
    state = _swap_for_junction_during_open(monkeypatch, root, other, "a.py")
    copied = handlers._snapshot_authorized_sources(runtime, root, snapshot)
    monkeypatch.undo()
    assert state == {"swapped": True, "restored": True}
    assert "pkg/a.py" not in copied
    assert not (snapshot / "pkg" / "a.py").exists()


def test_safe_reader_fallback_refuses_folder_swapped_for_junction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, other = _layout(tmp_path, "AGENTS.md")
    state = _swap_for_junction_during_open(monkeypatch, root, other, "AGENTS.md")
    result = safe_reader.read_resolved_fallback(
        root, ("pkg", "AGENTS.md"), 10_000, 10_000, (), None
    )
    monkeypatch.undo()
    assert state == {"swapped": True, "restored": True}
    assert result == (None, False)


def test_without_the_path_check_the_junction_swap_would_leak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Proves the swap reaches the open: with the real-path check disabled, it reads LEAKED."""

    root, other = _layout(tmp_path, "AGENTS.md")
    monkeypatch.setattr(safe_reader, "same_path", lambda _left, _right: True)
    monkeypatch.setattr(safe_reader, "is_under", lambda _path, _root: True)
    _swap_for_junction_during_open(monkeypatch, root, other, "AGENTS.md")
    result = safe_reader.read_resolved_fallback(
        root, ("pkg", "AGENTS.md"), 10_000, 10_000, (), None
    )
    monkeypatch.undo()
    assert result == (b"LEAKED = 1\n", False)
