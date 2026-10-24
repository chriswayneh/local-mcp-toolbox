"""Exercise the real Windows Bandit snapshot fallback (issue #43)."""

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

_WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="Windows handle API")


@_WINDOWS_ONLY
def test_windows_final_path_matches_the_resolved_file(tmp_path: Path) -> None:
    target = (tmp_path / "a.py").resolve()
    target.write_text("x = 1\n")
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = handlers._opened_file_path(descriptor)
    finally:
        os.close(descriptor)
    assert opened is not None
    assert os.path.normcase(str(opened)) == os.path.normcase(str(target))


@_WINDOWS_ONLY
def test_windows_snapshot_copies_files_under_the_root(tmp_path: Path) -> None:
    assert handlers._USE_DIR_FD is False
    root = (tmp_path / "approved").resolve()
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "a.py").write_text("x = 1\n")
    snapshot = (tmp_path / "snap").resolve()
    snapshot.mkdir()
    runtime = build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            integrations=IntegrationSettings(security_scanners=True),
            security=SecuritySettings(approved_roots=[root]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )
    assert handlers._snapshot_authorized_sources(runtime, root, snapshot) == {"pkg/a.py"}
    assert (snapshot / "pkg" / "a.py").read_text() == "x = 1\n"


@_WINDOWS_ONLY
def test_windows_junction_to_folder_outside_root_is_refused(tmp_path: Path) -> None:
    root = (tmp_path / "approved").resolve()
    root.mkdir()
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    (outside / "leak.py").write_text("LEAKED = 1\n")
    subprocess.run(  # noqa: S603
        ["cmd", "/c", "mklink", "/J", str(root / "j"), str(outside)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    snapshot = (tmp_path / "snap").resolve()
    snapshot.mkdir()
    runtime = build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            integrations=IntegrationSettings(security_scanners=True),
            security=SecuritySettings(approved_roots=[root, outside]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )
    assert handlers._snapshot_authorized_sources(runtime, root, snapshot) == set()
    assert not (snapshot / "j" / "leak.py").exists()


def test_final_path_prefixes_are_stripped() -> None:
    """Runs on every platform: pure string handling."""

    assert safe_reader.strip_final_path_prefix("\\\\?\\C:\\repo\\a.py") == "C:\\repo\\a.py"
    assert safe_reader.strip_final_path_prefix("\\\\?\\UNC\\srv\\share\\a.py") == (
        "\\\\srv\\share\\a.py"
    )
    assert safe_reader.strip_final_path_prefix("C:\\repo\\a.py") == "C:\\repo\\a.py"
