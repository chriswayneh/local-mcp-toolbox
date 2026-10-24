"""Pin every check in the Bandit snapshot copy gate (QE mutation review of #36)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import types
from pathlib import Path

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IntegrationSettings,
    PermissionProfile,
    SecuritySettings,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.security import handlers, safe_reader
from mcp_toolbox.tools.security.handlers import ScannerResult, ScannerRunner

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlink semantics")


def _settings(tmp_path: Path, *extra_roots: Path) -> ToolboxSettings:
    return ToolboxSettings(
        profile=PermissionProfile.STANDARD,
        integrations=IntegrationSettings(security_scanners=True),
        security=SecuritySettings(
            approved_roots=[tmp_path / "approved", *extra_roots],
            blocked_patterns=("secret_*",),
        ),
        audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
    )


@pytest.fixture
def env(tmp_path: Path):
    root = (tmp_path / "approved").resolve()
    root.mkdir()
    other = (tmp_path / "other").resolve()
    other.mkdir()
    snapshot = (tmp_path / "snap").resolve()
    snapshot.mkdir()
    runtime = build_runtime(_settings(tmp_path, other))
    return runtime, root, other, snapshot


@pytest.fixture
def fallback(monkeypatch):
    """Exercise the Windows resolve-then-verify path on this platform."""

    monkeypatch.setattr(handlers, "_USE_DIR_FD", False)


def _snap(runtime, root: Path, snapshot: Path) -> set[str]:
    return handlers._snapshot_authorized_sources(runtime, root, snapshot)


def test_walk_filters_match_bandit(env) -> None:
    runtime, root, _, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    (root / "b.PYW").write_text("x = 1\n")
    (root / "notes.txt").write_text("x\n")
    for skipped in (".git", "__pycache__", "lib.egg"):
        (root / skipped).mkdir()
        (root / skipped / "c.py").write_text("x = 1\n")
    (root / "pkg").mkdir()
    (root / "pkg" / "d.py").write_text("x = 1\n")
    assert _snap(runtime, root, snapshot) == {"a.py", "b.PYW", "pkg/d.py"}
    assert (snapshot / "pkg" / "d.py").read_text() == "x = 1\n"
    assert not (snapshot / "notes.txt").exists()


def test_directory_symlinks_are_not_followed(env) -> None:
    runtime, root, _, snapshot = env
    (root / "real").mkdir()
    (root / "real" / "a.py").write_text("x = 1\n")
    (root / "dirlink").symlink_to(root / "real", target_is_directory=True)
    assert _snap(runtime, root, snapshot) == {"real/a.py"}


def test_symlink_into_another_approved_root_is_refused(env, fallback) -> None:
    runtime, root, other, snapshot = env
    (other / "x.py").write_text("SECRET = 1\n")
    (root / "l.py").symlink_to(other / "x.py")
    assert _snap(runtime, root, snapshot) == set()


def test_blocked_link_name_to_allowed_file_is_refused(env, fallback) -> None:
    runtime, root, _, snapshot = env
    (root / "plain.py").write_text("x = 1\n")
    (root / "secret_link.py").symlink_to(root / "plain.py")
    assert _snap(runtime, root, snapshot) == {"plain.py"}


def test_allowed_link_name_to_blocked_file_is_refused(env, fallback) -> None:
    runtime, root, _, snapshot = env
    (root / "secret_real.py").write_text("x = 1\n")
    (root / "ok.py").symlink_to(root / "secret_real.py")
    assert _snap(runtime, root, snapshot) == set()


def test_dangling_link_is_skipped_and_resolve_is_strict(env, fallback, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    (root / "dangle.py").symlink_to(root / "missing.py")
    calls: list[bool] = []
    original = Path.resolve

    def spy(self: Path, strict: bool = False) -> Path:
        calls.append(strict)
        return original(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", spy)
    assert _snap(runtime, root, snapshot) == set()
    assert calls and all(calls)


class _OsProxy(types.SimpleNamespace):
    def __getattr__(self, name: str):
        return getattr(os, name)


def test_file_swapped_between_check_and_open_is_refused(env, fallback, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    real = os.stat(root / "a.py")
    fake = types.SimpleNamespace(st_mode=real.st_mode, st_dev=real.st_dev, st_ino=real.st_ino + 1)
    monkeypatch.setattr(handlers, "os", _OsProxy(stat=lambda path: fake))
    assert handlers._copy_if_authorized(runtime, root, root / "a.py", snapshot) is None
    assert not (snapshot / "a.py").exists()


def test_link_retargeted_after_open_is_refused(env, fallback, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    (root / "b.py").write_text("x = 2\n")
    link = root / "link.py"
    link.symlink_to(root / "a.py")

    def fstat_then_retarget(fd: int):
        result = os.fstat(fd)
        link.unlink()
        link.symlink_to(root / "b.py")
        return result

    monkeypatch.setattr(handlers, "os", _OsProxy(fstat=fstat_then_retarget))
    assert handlers._copy_if_authorized(runtime, root, link, snapshot) is None
    assert not (snapshot / "link.py").exists()


def test_existing_snapshot_file_is_never_overwritten(env) -> None:
    runtime, root, _, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    (snapshot / "a.py").write_text("planted\n")
    assert handlers._copy_if_authorized(runtime, root, root / "a.py", snapshot) is None
    assert (snapshot / "a.py").read_text() == "planted\n"


def test_entry_outside_root_returns_none_instead_of_raising(env) -> None:
    runtime, root, other, snapshot = env
    (other / "x.py").write_text("x = 1\n")
    assert handlers._copy_if_authorized(runtime, root, other / "x.py", snapshot) is None


def test_finding_paths_map_only_to_authorized_snapshot_files(tmp_path: Path) -> None:
    snapshot = tmp_path.resolve()
    authorized = {"a.py"}
    assert handlers._authorized_relative_path({"filename": "a.py"}, snapshot, authorized) == "a.py"
    assert (
        handlers._authorized_relative_path(
            {"filename": str(snapshot / "a.py")}, snapshot, authorized
        )
        == "a.py"
    )
    assert handlers._authorized_relative_path({"filename": "b.py"}, snapshot, authorized) is None
    assert (
        handlers._authorized_relative_path({"filename": "/elsewhere/a.py"}, snapshot, authorized)
        is None
    )
    assert handlers._authorized_relative_path({"filename": ""}, snapshot, authorized) is None


def test_fake_scanner_sees_only_the_snapshot(tmp_path: Path, monkeypatch) -> None:
    """The fake scanner walks the directory it is given, as Bandit would."""

    root = tmp_path / "approved"
    root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (root / "app.py").write_text("x = 1\n")
    (root / "secret_keys.py").write_text("K = 1\n")
    (other / "leak.py").write_text("LEAK = 1\n")
    (root / "linked.py").symlink_to(other / "leak.py")
    server = create_server(build_runtime(_settings(tmp_path, other)))
    seen: dict[str, str] = {}

    def fake_bandit(self: ScannerRunner, repository: Path) -> ScannerResult:
        assert repository != root.resolve()
        results = []
        for path in sorted(repository.rglob("*.py")):
            seen[path.relative_to(repository).as_posix()] = path.read_text()
            results.append({"test_id": "B105", "filename": str(path), "line_number": 1})
        results.append({"test_id": "B105", "filename": str(other / "leak.py"), "line_number": 1})
        return ScannerResult(stdout=json.dumps({"results": results}))

    monkeypatch.setattr(ScannerRunner, "run_bandit", fake_bandit)

    async def scenario() -> dict:
        async with Client(server) as client:
            result = await client.call_tool(
                "security_scan_repository", {"repository": str(root), "limit": 10}
            )
            assert result.is_error is False
            return result.structured_content["data"]

    data = asyncio.run(scenario())
    assert seen == {"app.py": "x = 1\n"}
    assert [f["file"] for f in data["findings"]] == ["app.py"]
    assert data["total_findings"] == 1
    assert data["withheld_findings"] == 1


# --- POSIX descriptor walk (Red Team round 3) ---------------------------------------------


def test_posix_walk_is_used_here() -> None:
    assert handlers._USE_DIR_FD is True


def test_symlinked_files_are_never_followed(env) -> None:
    runtime, root, other, snapshot = env
    (root / "real.py").write_text("x = 1\n")
    (root / "inside.py").symlink_to(root / "real.py")
    (other / "x.py").write_text("SECRET = 1\n")
    (root / "outside.py").symlink_to(other / "x.py")
    assert _snap(runtime, root, snapshot) == {"real.py"}


def test_parent_directory_swapped_to_symlink_is_refused(env, monkeypatch) -> None:
    """Red Team PoC: pkg is swapped for a symlink to outside right after the policy check."""

    runtime, root, _, snapshot = env
    outside = root.parent / "outside"
    outside.mkdir()
    (outside / "m.py").write_text("OUTSIDE_SECRET = 'leaked'\n")
    (root / "pkg").mkdir()
    (root / "pkg" / "m.py").write_text("x = 1\n")
    policy = runtime.permissions.security
    original = type(policy).check_path
    state = {"swapped": False}

    def check_then_swap(self, requested_path: Path):  # type: ignore[no-untyped-def]
        decision = original(self, requested_path)
        if not state["swapped"] and str(requested_path).endswith("pkg/m.py"):
            state["swapped"] = True
            os.rename(root / "pkg", root / "pkg.bak")
            os.symlink(outside, root / "pkg")
        return decision

    monkeypatch.setattr(type(policy), "check_path", check_then_swap)
    handlers._copy_if_authorized(runtime, root, root / "pkg" / "m.py", snapshot)
    assert state["swapped"]
    copied = snapshot / "pkg" / "m.py"
    assert not copied.exists() or "OUTSIDE_SECRET" not in copied.read_text()


def test_fifo_is_skipped_without_hanging(env) -> None:
    runtime, root, _, snapshot = env
    os.mkfifo(root / "evil.py")
    (root / "ok.py").write_text("x = 1\n")
    stats = handlers._SnapshotStats()
    started = time.monotonic()
    assert handlers._snapshot_authorized_sources(runtime, root, snapshot, stats) == {"ok.py"}
    assert time.monotonic() - started < 5
    assert stats.withheld_files == 1


def test_fifo_is_skipped_on_fallback_path_too(env, fallback) -> None:
    runtime, root, _, snapshot = env
    os.mkfifo(root / "evil.py")
    assert _snap(runtime, root, snapshot) == set()


def test_hard_linked_files_are_withheld(env) -> None:
    runtime, root, _, snapshot = env
    outside = root.parent / "outside2"
    outside.mkdir()
    (outside / "h.py").write_text("OUTSIDE_HL = 1\n")
    os.link(outside / "h.py", root / "h.py")
    assert _snap(runtime, root, snapshot) == set()


def test_per_file_cap_withholds_large_files(env, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    monkeypatch.setattr(handlers, "_MAX_FILE_BYTES", 10)
    (root / "big.py").write_text("x = 1234567890\n")
    (root / "small.py").write_text("x = 1\n")
    stats = handlers._SnapshotStats()
    assert handlers._snapshot_authorized_sources(runtime, root, snapshot, stats) == {"small.py"}
    assert stats.withheld_files == 1
    assert stats.truncated is False


def test_exactly_at_file_cap_is_copied(env, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    monkeypatch.setattr(handlers, "_MAX_FILE_BYTES", 6)
    (root / "a.py").write_text("x = 1\n")
    assert _snap(runtime, root, snapshot) == {"a.py"}


def test_file_growing_past_cap_after_fstat_is_withheld(env, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    monkeypatch.setattr(handlers, "_MAX_FILE_BYTES", 6)
    (root / "a.py").write_text("x = 1\n")
    real_fstat = os.fstat

    def small_fstat(fd: int):
        info = real_fstat(fd)
        (root / "a.py").write_text("x = 1234567\n")
        return info

    monkeypatch.setattr(handlers, "os", _OsProxy(fstat=small_fstat))
    assert handlers._copy_if_authorized(runtime, root, root / "a.py", snapshot) is None


def test_total_cap_stops_copying_and_is_reported(env, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    monkeypatch.setattr(handlers, "_MAX_SNAPSHOT_BYTES", 10)
    for name in ("a.py", "b.py", "c.py"):
        (root / name).write_text("x = 1\n")
    stats = handlers._SnapshotStats()
    assert handlers._snapshot_authorized_sources(runtime, root, snapshot, stats) == {"a.py"}
    assert stats.withheld_files == 2
    assert stats.truncated is True
    assert stats.copied_bytes == 6


def test_odd_names_stay_inside_snapshot(env) -> None:
    runtime, root, _, snapshot = env
    for name in ["a\nb.py", "..py", "x\x1b[2J.py", " .py"]:
        (root / name).write_text("x = 1\n")
    got = _snap(runtime, root, snapshot)
    # "..py" has no Path.suffix on Python 3.14+, but Bandit's "*.py" glob still matches it.
    assert got == {"a\nb.py", "..py", "x\x1b[2J.py", " .py"}
    for item in got:
        assert not item.startswith("/") and ".." not in Path(item).parts
    for path in snapshot.rglob("*"):
        assert path.resolve().is_relative_to(snapshot)


def test_relative_parts_are_validated(env) -> None:
    runtime, root, _, snapshot = env
    assert handlers._copy_if_authorized(runtime, root, root, snapshot) is None
    (root.parent / "e.py").write_text("x = 1\n")
    assert handlers._copy_if_authorized(runtime, root, root / ".." / "e.py", snapshot) is None


def test_response_reports_withheld_files(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    os.mkfifo(root / "pipe.py")
    server = create_server(build_runtime(_settings(tmp_path)))
    monkeypatch.setattr(
        ScannerRunner, "run_bandit", lambda self, repo: ScannerResult(stdout='{"results": []}')
    )

    async def scenario() -> dict:
        async with Client(server) as client:
            result = await client.call_tool("security_scan_repository", {"repository": str(root)})
            return result.structured_content["data"]

    data = asyncio.run(scenario())
    assert data["withheld_files"] == 1
    assert data["snapshot_truncated"] is False


def test_directory_symlinks_are_not_followed_on_fallback_path(env, fallback) -> None:
    runtime, root, _, snapshot = env
    (root / "real").mkdir()
    (root / "real" / "a.py").write_text("x = 1\n")
    (root / "dirlink").symlink_to(root / "real", target_is_directory=True)
    assert _snap(runtime, root, snapshot) == {"real/a.py"}


def test_descriptor_walk_requires_root_to_be_a_directory(tmp_path: Path) -> None:
    not_a_directory = tmp_path / "file"
    not_a_directory.write_text("x\n")
    with pytest.raises(NotADirectoryError):
        handlers._read_without_following(not_a_directory, ("a.py",), 100, handlers._SnapshotStats())


def _swap_parent_during_open(monkeypatch, root: Path, other: Path) -> None:
    """Swap root/pkg for a link to other/pkg after the checks, and undo it before re-resolve.

    This is the window the inode and re-resolve checks alone cannot close (issue #43).
    """

    real_stat = os.stat
    real_fstat = os.fstat
    state = {"swapped": False}

    def swapping_stat(path, *args, **kwargs):
        if not state["swapped"] and Path(path) == root / "pkg" / "a.py":
            state["swapped"] = True
            os.rename(root / "pkg", root / "pkg_real")
            os.symlink(other / "pkg", root / "pkg", target_is_directory=True)
        return real_stat(path, *args, **kwargs)

    def restoring_fstat(fd, *args, **kwargs):
        result = real_fstat(fd, *args, **kwargs)
        if state["swapped"] and (root / "pkg").is_symlink():
            os.unlink(root / "pkg")
            os.rename(root / "pkg_real", root / "pkg")
        return result

    monkeypatch.setattr(os, "stat", swapping_stat)
    monkeypatch.setattr(os, "fstat", restoring_fstat)


def test_fallback_refuses_parent_swapped_between_check_and_open(env, fallback, monkeypatch) -> None:
    runtime, root, other, snapshot = env
    (root / "pkg").mkdir()
    (root / "pkg" / "a.py").write_text("x = 1\n")
    (other / "pkg").mkdir()
    (other / "pkg" / "a.py").write_text("LEAKED = 1\n")
    _swap_parent_during_open(monkeypatch, root, other)
    copied = _snap(runtime, root, snapshot)
    monkeypatch.undo()
    assert "pkg/a.py" not in copied
    assert not (snapshot / "pkg" / "a.py").exists()


def test_fallback_refuses_when_opened_path_is_outside_root(env, fallback, monkeypatch) -> None:
    runtime, root, other, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(handlers, "_opened_file_path", lambda _fd: other / "a.py")
    assert _snap(runtime, root, snapshot) == set()


def test_fallback_fails_closed_when_opened_path_is_unknown(env, fallback, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    monkeypatch.setattr(handlers, "_opened_file_path", lambda _fd: None)
    assert _snap(runtime, root, snapshot) == set()


def test_fallback_still_copies_ordinary_files(env, fallback) -> None:
    runtime, root, _, snapshot = env
    (root / "pkg").mkdir()
    (root / "pkg" / "a.py").write_text("x = 1\n")
    assert _snap(runtime, root, snapshot) == {"pkg/a.py"}


def test_windows_final_path_prefixes_are_stripped() -> None:
    assert safe_reader.strip_final_path_prefix("\\\\?\\C:\\repo\\a.py") == "C:\\repo\\a.py"
    assert safe_reader.strip_final_path_prefix("\\\\?\\UNC\\srv\\share\\a.py") == (
        "\\\\srv\\share\\a.py"
    )
    assert safe_reader.strip_final_path_prefix("C:\\repo\\a.py") == "C:\\repo\\a.py"
