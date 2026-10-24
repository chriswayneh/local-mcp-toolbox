"""The agent-config auditor's Windows fallback verifies the opened file's real path."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_toolbox.models import ToolboxError
from mcp_toolbox.tools.security import safe_reader


def _swap_parent_during_open(monkeypatch: pytest.MonkeyPatch, root: Path, other: Path) -> None:
    """Swap root/pkg for a link to other/pkg after the checks, and undo it before re-resolve."""

    real_stat = os.stat
    real_fstat = os.fstat
    state = {"swapped": False}

    def swapping_stat(path, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        if not state["swapped"] and Path(path) == root / "pkg" / "AGENTS.md":
            state["swapped"] = True
            os.rename(root / "pkg", root / "pkg_real")
            os.symlink(other / "pkg", root / "pkg", target_is_directory=True)
        return real_stat(path, *args, **kwargs)

    def restoring_fstat(fd, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
        result = real_fstat(fd, *args, **kwargs)
        if state["swapped"] and (root / "pkg").is_symlink():
            os.unlink(root / "pkg")
            os.rename(root / "pkg_real", root / "pkg")
        return result

    monkeypatch.setattr(os, "stat", swapping_stat)
    monkeypatch.setattr(os, "fstat", restoring_fstat)


def _layout(tmp_path: Path) -> tuple[Path, Path]:
    root = (tmp_path / "approved").resolve()
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "AGENTS.md").write_bytes(b"# Safe\n")
    other = (tmp_path / "other").resolve()
    (other / "pkg").mkdir(parents=True)
    (other / "pkg" / "AGENTS.md").write_text("# LEAKED\n", encoding="utf-8")
    return root, other


def _read(root: Path) -> tuple[bytes | None, bool]:
    return safe_reader.read_resolved_fallback(root, ("pkg", "AGENTS.md"), 10_000, 10_000, (), None)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")
def test_fallback_refuses_parent_swapped_between_check_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, other = _layout(tmp_path)
    _swap_parent_during_open(monkeypatch, root, other)
    result = _read(root)
    monkeypatch.undo()
    assert result == (None, False)


def test_fallback_refuses_when_opened_path_is_outside_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, other = _layout(tmp_path)
    monkeypatch.setattr(safe_reader, "opened_file_path", lambda _fd: other / "pkg" / "AGENTS.md")
    assert _read(root) == (None, False)


def test_fallback_fails_closed_when_opened_path_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _ = _layout(tmp_path)
    monkeypatch.setattr(safe_reader, "opened_file_path", lambda _fd: None)
    assert _read(root) == (None, False)


def test_fallback_still_reads_ordinary_files(tmp_path: Path) -> None:
    root, _ = _layout(tmp_path)
    assert _read(root) == (b"# Safe\n", False)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle API")
def test_windows_opened_file_path_matches_the_resolved_file(tmp_path: Path) -> None:
    target = (tmp_path / "AGENTS.md").resolve()
    target.write_text("# x\n", encoding="utf-8")
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    try:
        opened = safe_reader.opened_file_path(descriptor)
    finally:
        os.close(descriptor)
    assert opened is not None
    assert safe_reader.same_path(opened, target)
    assert safe_reader.is_under(opened, tmp_path.resolve())


def test_fallback_needs_same_path_even_inside_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same-path check alone refuses a different file inside the root."""

    root, _ = _layout(tmp_path)
    (root / "OTHER.md").write_bytes(b"# Other\n")
    monkeypatch.setattr(safe_reader, "opened_file_path", lambda _fd: root / "OTHER.md")
    monkeypatch.setattr(safe_reader, "is_under", lambda _path, _root: True)
    assert _read(root) == (None, False)


def test_fallback_needs_path_under_root_even_when_same(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The under-root check alone refuses a path outside the root."""

    root, other = _layout(tmp_path)
    monkeypatch.setattr(safe_reader, "opened_file_path", lambda _fd: other / "pkg" / "AGENTS.md")
    monkeypatch.setattr(safe_reader, "same_path", lambda _left, _right: True)
    assert _read(root) == (None, False)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows junctions")
def test_windows_junction_to_folder_outside_root_is_refused(tmp_path: Path) -> None:
    root = (tmp_path / "approved").resolve()
    root.mkdir()
    outside = (tmp_path / "outside").resolve()
    outside.mkdir()
    (outside / "AGENTS.md").write_bytes(b"# LEAKED\n")
    subprocess.run(  # noqa: S603
        ["cmd", "/c", "mklink", "/J", str(root / "j"), str(outside)],  # noqa: S607
        check=True,
        capture_output=True,
    )
    try:
        result = safe_reader.read_resolved_fallback(
            root, ("j", "AGENTS.md"), 10_000, 10_000, (), None
        )
    except ToolboxError:
        return
    assert result == (None, False)
