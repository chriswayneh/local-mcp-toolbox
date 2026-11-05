from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from mcp_toolbox.config.settings import AuditSettings, ToolboxSettings
from mcp_toolbox.models import ToolboxError
from mcp_toolbox.server import build_runtime
from mcp_toolbox.tools.git import handlers, snapshot


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def repository(root: Path, subject: str = "APPROVED_COMMIT") -> Path:
    root.mkdir()
    git(root, "init", "-q")
    git(root, "config", "user.name", "Test")
    git(root, "config", "user.email", "test@example.test")
    git(root, "config", "core.autocrlf", "false")
    (root / "file.txt").write_text("original\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", subject)
    return root


@pytest.fixture
def runner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> handlers.GitRunner:
    monkeypatch.setattr(handlers, "_FD_PATHS", False)
    monkeypatch.setattr(handlers, "_SNAPSHOT_PATHS", True)
    return handlers.GitRunner(
        build_runtime(ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit.jsonl")))
    )


@pytest.mark.parametrize("packed", [False, True])
def test_snapshot_keeps_status_diff_history_and_source_unchanged(
    tmp_path: Path, runner: handlers.GitRunner, packed: bool
) -> None:
    root = repository(tmp_path / "repo")
    if packed:
        git(root, "gc", "--prune=now", "-q")
    before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert not runner.run(root, ["status", "--porcelain"]).stdout.strip()
    assert "APPROVED_COMMIT" in runner.run(root, ["log", "-1", "--format=%s"]).stdout
    assert {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()} == before
    (root / "file.txt").write_text("original\nchanged\n", encoding="utf-8")
    assert "file.txt" in runner.run(root, ["status", "--porcelain"]).stdout
    assert (
        "1\t0\tfile.txt"
        in runner.run(root, ["diff", "--numstat", "--no-ext-diff", "--no-textconv"]).stdout
    )


@pytest.mark.parametrize(
    "key", ["include.path", "includeIf.gitdir:/.path", "core.attributesFile", "core.excludesFile"]
)
def test_snapshot_rejects_config_redirects(
    tmp_path: Path, runner: handlers.GitRunner, key: str
) -> None:
    root = repository(tmp_path / "repo")
    outside = tmp_path / "outside"
    outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
    git(root, "config", key, str(outside))
    with pytest.raises(ToolboxError, match="unsupported settings"):
        runner.run(root, ["log", "-1"])


def test_snapshot_limits_are_fail_closed(
    tmp_path: Path, runner: handlers.GitRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository(tmp_path / "repo")
    monkeypatch.setattr(snapshot, "MAX_SNAPSHOT_BYTES", 1)
    with pytest.raises(ToolboxError):
        runner.run(root, ["status", "--porcelain"])


def test_snapshot_subprocesses_never_use_source(
    tmp_path: Path, runner: handlers.GitRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = repository(tmp_path / "repo")
    original = subprocess.run
    calls = []

    def check(command, **kwargs):
        assert str(root) not in " ".join(command)
        calls.append(command)
        # Mutation of the source after copying cannot affect any subprocess.
        (root / "file.txt").write_text("changed after copying", encoding="utf-8")
        return original(command, **kwargs)

    monkeypatch.setattr(subprocess, "run", check)
    assert not runner.run(root, ["status", "--porcelain"]).stdout.strip()
    assert len(calls) == 3


def test_snapshot_rejects_hardlinked_files(tmp_path: Path, runner: handlers.GitRunner) -> None:
    root = repository(tmp_path / "repo")
    outside = tmp_path / "secret.txt"
    outside.write_text("OUTSIDE_SECRET", encoding="utf-8")
    os.link(outside, root / "linked.txt")
    with pytest.raises(ToolboxError):
        runner.run(root, ["status", "--porcelain"])


@pytest.mark.parametrize("packed", [True, False])
def test_snapshot_pack_and_loose_flip_never_leak(
    tmp_path: Path, runner: handlers.GitRunner, packed: bool
) -> None:
    root = repository(tmp_path / "repo")
    outside = repository(tmp_path / "outside", "OUTSIDE_SECRET_COMMIT")
    if packed:
        git(root, "gc", "--prune=now", "-q")
        git(outside, "gc", "--prune=now", "-q")
    foreign_head = git(outside, "rev-parse", "HEAD")
    branch = git(root, "symbolic-ref", "--short", "HEAD")
    (root / ".git" / "refs" / "heads" / branch).write_text(foreign_head + "\n", encoding="utf-8")
    store = root / ".git" / "objects"
    name = "pack" if packed else foreign_head[:2]
    live = store / name
    live.mkdir(exist_ok=True)
    parked = tmp_path / "parked"
    link = tmp_path / "swap-link"
    foreign = outside / ".git" / "objects" / name
    if sys.platform == "win32":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(foreign)], check=True, capture_output=True
        )
    else:
        link.symlink_to(foreign, target_is_directory=True)
    stop = threading.Event()
    flips = []

    def flip() -> None:
        while not stop.is_set():
            try:
                live.rename(parked)
                link.rename(live)
                flips.append(1)
                time.sleep(0.0005)
                live.rename(link)
                parked.rename(live)
            except OSError:
                pass

    thread = threading.Thread(target=flip)
    thread.start()
    try:
        for _ in range(200):
            try:
                result = runner.run(root, ["log", "-1", "--format=%s"])
            except ToolboxError:
                continue
            assert "OUTSIDE_SECRET" not in result.stdout
    finally:
        stop.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert flips, "The swapper must actually run for this regression to be meaningful"


def test_snapshot_missing_final_handle_path_denies(
    tmp_path: Path, runner: handlers.GitRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.security import safe_reader

    root = repository(tmp_path / "repo")
    monkeypatch.setattr(safe_reader, "USE_DIR_FD", False)
    monkeypatch.setattr(safe_reader, "opened_file_path", lambda _fd: None)
    with pytest.raises(ToolboxError):
        runner.run(root, ["status", "--porcelain"])


@pytest.mark.parametrize("name", [".git", ".GIT", ".gitmodules", ".GITMODULES"])
def test_snapshot_rejects_nested_git_redirects(
    tmp_path: Path, runner: handlers.GitRunner, name: str
) -> None:
    root = repository(tmp_path / "repo")
    child = root / "nested"
    child.mkdir()
    (child / name).write_text("gitdir: /outside/private\n", encoding="utf-8")
    with pytest.raises(ToolboxError, match="Nested repositories"):
        runner.run(root, ["status", "--porcelain"])
