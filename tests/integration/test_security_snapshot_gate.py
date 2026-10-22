"""Pin every check in the Bandit snapshot copy gate (QE mutation review of #36)."""

from __future__ import annotations

import asyncio
import json
import os
import sys
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
from mcp_toolbox.tools.security import handlers
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


def test_symlink_into_another_approved_root_is_refused(env) -> None:
    runtime, root, other, snapshot = env
    (other / "x.py").write_text("SECRET = 1\n")
    (root / "l.py").symlink_to(other / "x.py")
    assert _snap(runtime, root, snapshot) == set()


def test_blocked_link_name_to_allowed_file_is_refused(env) -> None:
    runtime, root, _, snapshot = env
    (root / "plain.py").write_text("x = 1\n")
    (root / "secret_link.py").symlink_to(root / "plain.py")
    assert _snap(runtime, root, snapshot) == {"plain.py"}


def test_allowed_link_name_to_blocked_file_is_refused(env) -> None:
    runtime, root, _, snapshot = env
    (root / "secret_real.py").write_text("x = 1\n")
    (root / "ok.py").symlink_to(root / "secret_real.py")
    assert _snap(runtime, root, snapshot) == set()


def test_dangling_link_is_skipped_and_resolve_is_strict(env, monkeypatch) -> None:
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


def test_file_swapped_between_check_and_open_is_refused(env, monkeypatch) -> None:
    runtime, root, _, snapshot = env
    (root / "a.py").write_text("x = 1\n")
    real = os.stat(root / "a.py")
    fake = types.SimpleNamespace(st_dev=real.st_dev, st_ino=real.st_ino + 1)
    monkeypatch.setattr(handlers, "os", _OsProxy(stat=lambda path: fake))
    assert handlers._copy_if_authorized(runtime, root, root / "a.py", snapshot) is None
    assert not (snapshot / "a.py").exists()


def test_link_retargeted_after_open_is_refused(env, monkeypatch) -> None:
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
