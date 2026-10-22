from __future__ import annotations

import asyncio
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    FilesystemSettings,
    GitSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server

# Git tools refuse to run outside Linux (see test_git_platform.py), so these tests need Linux.
pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="Git tools are supported on Linux only"
)


@pytest.fixture()
def git_repository(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    repository = tmp_path / "approved-repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Toolbox Test")
    _git(repository, "config", "user.email", "toolbox@example.test")
    readme = repository / "README.md"
    readme.write_text("Initial content\n", encoding="utf-8")
    _git(repository, "add", "README.md")
    _git(repository, "commit", "-m", "Initial commit")
    _git(repository, "commit", "--allow-empty", "-m", "token ghp_123456789012345678901234567890")
    readme.write_text("Initial content\nChanged\n", encoding="utf-8")
    return repository


def test_git_tools_require_approved_repository_and_redact_commit_content(
    tmp_path: Path, git_repository: Path
) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(
                    approved_roots=[tmp_path],
                    allowed_extensions=[".md", ".txt"],
                    blocked_patterns=[".env", "*.pem"],
                ),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            status = await client.call_tool(
                "git_repository_status", {"repository": str(git_repository)}
            )
            branch = await client.call_tool(
                "git_current_branch", {"repository": str(git_repository)}
            )
            commits = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository), "limit": 5}
            )
            diff = await client.call_tool("git_diff_summary", {"repository": str(git_repository)})
            denied = await client.call_tool("git_current_branch", {"repository": str(tmp_path)})

            assert status.is_error is False
            assert status.structured_content["data"]["changed_file_count"] == 1
            assert branch.is_error is False
            assert branch.structured_content["data"]["reference"]
            assert commits.is_error is False
            subjects = str(commits.structured_content["data"]["commits"])
            assert "ghp_123456789012345678901234567890" not in subjects
            assert "[REDACTED_GITHUB_TOKEN]" in subjects
            assert diff.is_error is False
            assert diff.structured_content["data"]["files"][0]["path"] == "README.md"
            assert denied.is_error is True

    asyncio.run(scenario())


def test_git_tools_are_not_registered_when_integration_is_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(
                filesystem=FilesystemSettings(
                    approved_roots=[tmp_path],
                    allowed_extensions=[".md"],
                ),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "git_repository_status",
                "git_current_branch",
                "git_recent_commits",
                "git_diff_summary",
            }

    asyncio.run(scenario())


def _git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
    )


def _status_server(tmp_path: Path, repository: Path):  # type: ignore[no-untyped-def]
    return create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )


def test_repo_local_core_worktree_cannot_point_git_outside_the_repository(
    tmp_path: Path, git_repository: Path
) -> None:
    outside = tmp_path / "outside-worktree"
    outside.mkdir()
    (outside / "outside-only-file.txt").write_text("not approved\n", encoding="utf-8")
    _git(git_repository, "config", "core.worktree", str(outside))
    server = _status_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "git_repository_status", {"repository": str(git_repository)}
            )
            assert result.is_error is False
            assert "outside-only-file" not in str(result.structured_content)
            paths = [c["path"] for c in result.structured_content["data"]["changes"]]
            assert paths == ["README.md"]

    asyncio.run(scenario())


def test_dot_git_file_redirecting_to_another_repository_is_refused(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    other = tmp_path / "unapproved-repository"
    other.mkdir()
    _git(other, "init")
    (other / "unapproved-only.txt").write_text("x\n", encoding="utf-8")
    approved = tmp_path / "approved-repository"
    approved.mkdir()
    (approved / ".git").write_text(f"gitdir: {other / '.git'}\n", encoding="utf-8")
    server = _status_server(tmp_path, approved)

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in ("git_repository_status", "git_recent_commits", "git_current_branch"):
                result = await client.call_tool(tool, {"repository": str(approved)})
                assert result.is_error is True
                assert "unapproved" not in str(result.content)

    asyncio.run(scenario())


def _outside_repository(tmp_path: Path) -> Path:
    outside = tmp_path / "outside"
    outside.mkdir()
    _git(outside, "init", "-b", "master")
    _git(outside, "config", "user.name", "Outside")
    _git(outside, "config", "user.email", "outside@example.test")
    (outside / "outside-only.txt").write_text("outside data\n", encoding="utf-8")
    _git(outside, "add", ".")
    _git(outside, "commit", "-m", "outside-only commit subject")
    return outside


def _assert_every_git_tool_refused(tmp_path: Path, repository: Path) -> None:
    server = _status_server(tmp_path, repository)

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in (
                "git_repository_status",
                "git_recent_commits",
                "git_current_branch",
                "git_diff_summary",
            ):
                result = await client.call_tool(tool, {"repository": str(repository)})
                assert result.is_error is True, tool
                text = str(result.content) + str(result.structured_content)
                assert "outside-only" not in text, tool
                assert "outside data" not in text, tool
                assert "Outside" not in text, tool

    asyncio.run(scenario())


def _make_writable_and_retry(function, path, _error):  # type: ignore[no-untyped-def]
    # Git marks object files read-only; Windows refuses to delete them until that is cleared.
    os.chmod(path, stat.S_IWRITE)
    function(path)


def test_commondir_pointing_outside_is_refused(tmp_path: Path, git_repository: Path) -> None:
    outside = _outside_repository(tmp_path)
    git_dir = git_repository / ".git"
    shutil.rmtree(git_dir / "refs", onexc=_make_writable_and_retry)
    shutil.rmtree(git_dir / "objects", onexc=_make_writable_and_retry)
    (git_dir / "commondir").write_text(f"{outside / '.git'}\n", encoding="utf-8")
    (git_dir / "HEAD").write_text("ref: refs/heads/master\n", encoding="utf-8")
    # Sanity check: plain Git really follows commondir to the outside repository.
    log = subprocess.run(
        ["git", "-C", str(git_repository), "log", "-1", "--format=%s"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    assert "outside-only commit subject" in log

    _assert_every_git_tool_refused(tmp_path, git_repository)


def test_alternates_pointing_outside_are_refused(tmp_path: Path, git_repository: Path) -> None:
    outside = _outside_repository(tmp_path)
    info = git_repository / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text(f"{outside / '.git' / 'objects'}\n", encoding="utf-8")

    _assert_every_git_tool_refused(tmp_path, git_repository)


def test_alternates_inside_the_repository_are_allowed(tmp_path: Path, git_repository: Path) -> None:
    store = git_repository / "local-store"
    store.mkdir()
    info = git_repository / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text("../../local-store\n", encoding="utf-8")
    server = _status_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository)}
            )
            assert result.is_error is False

    asyncio.run(scenario())


def _refusal_text(tmp_path: Path, repository: Path, tool: str = "git_recent_commits") -> str:
    server = _status_server(tmp_path, repository)
    texts: list[str] = []

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(tool, {"repository": str(repository)})
            assert result.is_error is True
            texts.append(str(result.content) + str(result.structured_content))

    asyncio.run(scenario())
    return texts[0]


def test_nested_alternates_chain_leaving_the_repository_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    outside = _outside_repository(tmp_path)
    store = git_repository / "store"
    (store / "info").mkdir(parents=True)
    info = git_repository / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "alternates").write_text("../../store\n", encoding="utf-8")
    (store / "info" / "alternates").write_text(
        f"{outside / '.git' / 'objects'}\n", encoding="utf-8"
    )

    _assert_every_git_tool_refused(tmp_path, git_repository)
    assert "alternates" in _refusal_text(tmp_path, git_repository)


def test_real_linked_worktree_is_refused_with_its_reason(
    tmp_path: Path, git_repository: Path
) -> None:
    linked = tmp_path / "linked-worktree"
    _git(git_repository, "worktree", "add", "-q", str(linked), "-b", "linked")

    text = _refusal_text(tmp_path, linked)
    assert "gitdir file" in text and "linked worktree" in text


def test_real_submodule_checkout_is_refused_with_its_reason(
    tmp_path: Path, git_repository: Path
) -> None:
    child = _outside_repository(tmp_path)
    _git(git_repository, "-c", "protocol.file.allow=always", "submodule", "add", str(child), "sub")
    submodule = git_repository / "sub"
    assert (submodule / ".git").is_file()

    text = _refusal_text(tmp_path, submodule)
    assert "gitdir file" in text and "submodule checkout" in text


def test_real_shared_clone_is_refused_with_its_reason(tmp_path: Path, git_repository: Path) -> None:
    shared = tmp_path / "shared-clone"
    _git(tmp_path, "clone", "-q", "--shared", str(git_repository), str(shared))

    assert "alternates" in _refusal_text(tmp_path, shared)


def test_symlinked_dot_git_directory_is_refused(tmp_path: Path) -> None:
    outside = _outside_repository(tmp_path)
    approved = tmp_path / "approved-repository"
    approved.mkdir()
    try:
        (approved / ".git").symlink_to(outside / ".git", target_is_directory=True)
    except OSError:
        pytest.skip("Symlinks are not available")
    # Without the symlink check, .git passes is_dir() and Git reads the outside repository.
    assert (approved / ".git").is_dir()

    _assert_every_git_tool_refused(tmp_path, approved)
    assert "symlink" in _refusal_text(tmp_path, approved)


def test_commondir_refusal_names_its_reason(tmp_path: Path, git_repository: Path) -> None:
    (git_repository / ".git" / "commondir").write_text("../elsewhere\n", encoding="utf-8")

    assert "commondir" in _refusal_text(tmp_path, git_repository)


def _git_output(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks cannot be created on this system")


def test_symlinked_objects_store_pointing_outside_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    outside = _outside_repository(tmp_path)
    git_dir = git_repository / ".git"
    shutil.rmtree(git_dir / "objects", onexc=_make_writable_and_retry)
    _symlink_or_skip(git_dir / "objects", outside / ".git" / "objects")
    outside_head = _git_output(outside, "rev-parse", "HEAD")
    branch = _git_output(git_repository, "symbolic-ref", "--short", "HEAD")
    (git_dir / "refs" / "heads" / branch).write_text(outside_head + "\n", encoding="utf-8")
    # Sanity check: plain Git now reads the outside repository's commit.
    assert "outside-only commit subject" in _git_output(git_repository, "log", "-1", "--format=%s")

    _assert_every_git_tool_refused(tmp_path, git_repository)
    assert "symlink" in _refusal_text(tmp_path, git_repository)


@pytest.mark.parametrize(
    "name", ["refs", "HEAD", "config", "packed-refs", "logs", "info", "worktrees"]
)
def test_symlinked_git_metadata_is_refused(tmp_path: Path, git_repository: Path, name: str) -> None:
    outside = _outside_repository(tmp_path)
    git_dir = git_repository / ".git"
    entry = git_dir / name
    target = outside / ".git" / name
    if not target.exists():
        target = tmp_path / f"outside-{name}"
        target.mkdir()
    if entry.is_dir():
        shutil.rmtree(entry, onexc=_make_writable_and_retry)
    elif entry.exists():
        entry.unlink()
    _symlink_or_skip(entry, target)

    _assert_every_git_tool_refused(tmp_path, git_repository)


def test_containment_is_rechecked_after_git_runs(
    tmp_path: Path, git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    real_run = handlers.subprocess.run

    def plant_commondir_then_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        # Simulates an attacker winning the race between the check and the Git process.
        commondir = git_repository / ".git" / "commondir"
        if not commondir.exists():
            commondir.write_text("../elsewhere\n", encoding="utf-8")
        return real_run(*args, **kwargs)

    monkeypatch.setattr(handlers.subprocess, "run", plant_commondir_then_run)

    text = _refusal_text(tmp_path, git_repository)
    assert "commondir" in text or "changed" in text


def test_git_dir_swapped_during_run_is_refused(
    tmp_path: Path, git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    outside = _outside_repository(tmp_path)
    real_run = handlers.subprocess.run
    git_dir = git_repository / ".git"

    def swap_git_dir_then_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        # Replace .git with a different (outside-cloned) directory between check and exec.
        if not (tmp_path / "moved-git").exists():
            git_dir.rename(tmp_path / "moved-git")
            shutil.copytree(outside / ".git", git_dir)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(handlers.subprocess, "run", swap_git_dir_then_run)

    text = _refusal_text(tmp_path, git_repository)
    assert "outside-only" not in text
    assert "changed" in text


def _successful_call(tmp_path: Path, repository: Path) -> None:
    server = _status_server(tmp_path, repository)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool("git_recent_commits", {"repository": str(repository)})
            assert result.is_error is False, result.content

    asyncio.run(scenario())


def _write_alternates(objects: Path, text: str) -> None:
    (objects / "info").mkdir(parents=True, exist_ok=True)
    (objects / "info" / "alternates").write_text(text, encoding="utf-8")


@pytest.mark.parametrize("kind", ["loose", "pack"])
def test_symlink_nested_inside_objects_is_refused(
    tmp_path: Path, git_repository: Path, kind: str
) -> None:
    outside = _outside_repository(tmp_path)
    objects = git_repository / ".git" / "objects"
    if kind == "pack":
        _git(outside, "gc", "-q")
        shutil.rmtree(objects / "pack", onexc=_make_writable_and_retry)
        _symlink_or_skip(objects / "pack", outside / ".git" / "objects" / "pack")
    else:
        head = _git_output(outside, "rev-parse", "HEAD")
        fanout = objects / head[:2]
        if fanout.exists():
            shutil.rmtree(fanout, onexc=_make_writable_and_retry)
        _symlink_or_skip(fanout, outside / ".git" / "objects" / head[:2])

    _assert_every_git_tool_refused(tmp_path, git_repository)
    assert "contains a symlink" in _refusal_text(tmp_path, git_repository)


def test_symlink_nested_inside_refs_is_refused(tmp_path: Path, git_repository: Path) -> None:
    outside = _outside_repository(tmp_path)
    heads = git_repository / ".git" / "refs" / "heads"
    _symlink_or_skip(heads / "borrowed", outside / ".git" / "refs" / "heads" / "master")

    assert "contains a symlink" in _refusal_text(tmp_path, git_repository)


def test_dangling_commondir_symlink_is_refused(tmp_path: Path, git_repository: Path) -> None:
    _symlink_or_skip(git_repository / ".git" / "commondir", tmp_path / "does-not-exist")
    assert not (git_repository / ".git" / "commondir").exists()

    assert "commondir" in _refusal_text(tmp_path, git_repository)


def test_alternates_cycle_inside_the_repository_is_allowed(
    tmp_path: Path, git_repository: Path
) -> None:
    store_a = git_repository / "store-a"
    store_b = git_repository / "store-b"
    store_a.mkdir()
    store_b.mkdir()
    _write_alternates(git_repository / ".git" / "objects", "../../store-a\n")
    _write_alternates(store_a, "../store-b\n")
    _write_alternates(store_b, "../store-a\n")

    _successful_call(tmp_path, git_repository)


def test_overlong_alternates_chain_is_refused(tmp_path: Path, git_repository: Path) -> None:
    from mcp_toolbox.tools.git.handlers import _MAX_ALTERNATE_STORES

    stores = [git_repository / f"store-{index}" for index in range(_MAX_ALTERNATE_STORES + 2)]
    for store in stores:
        store.mkdir()
    _write_alternates(git_repository / ".git" / "objects", f"{stores[0]}\n")
    for current, following in zip(stores, stores[1:], strict=False):
        _write_alternates(current, f"{following}\n")

    assert "alternates" in _refusal_text(tmp_path, git_repository)


def test_alternates_chain_at_the_cap_is_allowed(tmp_path: Path, git_repository: Path) -> None:
    from mcp_toolbox.tools.git.handlers import _MAX_ALTERNATE_STORES

    stores = [git_repository / f"store-{index}" for index in range(_MAX_ALTERNATE_STORES - 1)]
    for store in stores:
        store.mkdir()
    _write_alternates(git_repository / ".git" / "objects", f"{stores[0]}\n")
    for current, following in zip(stores, stores[1:], strict=False):
        _write_alternates(current, f"{following}\n")

    _successful_call(tmp_path, git_repository)


def test_symlinked_alternates_file_is_refused(tmp_path: Path, git_repository: Path) -> None:
    # .git/objects itself is covered by the nested-symlink walk, so the alternates file
    # sits in a chained store elsewhere in the repository.
    harmless = git_repository / "harmless-alternates"
    harmless.write_text("", encoding="utf-8")
    store = git_repository / "store"
    (store / "info").mkdir(parents=True)
    _write_alternates(git_repository / ".git" / "objects", "../../store\n")
    _symlink_or_skip(store / "info" / "alternates", harmless)

    assert "alternates" in _refusal_text(tmp_path, git_repository)


def test_quoted_alternates_line_is_refused(tmp_path: Path, git_repository: Path) -> None:
    (git_repository / "store").mkdir()
    _write_alternates(git_repository / ".git" / "objects", '"../../store"\n')

    assert "alternates" in _refusal_text(tmp_path, git_repository)


def test_commented_alternates_line_is_ignored(tmp_path: Path, git_repository: Path) -> None:
    # Treated as a path, this comment would escape the repository and be refused.
    _write_alternates(git_repository / ".git" / "objects", "#/../../../../../../outside\n")

    _successful_call(tmp_path, git_repository)


def test_http_alternates_has_its_own_refusal(tmp_path: Path, git_repository: Path) -> None:
    info = git_repository / ".git" / "objects" / "info"
    info.mkdir(parents=True, exist_ok=True)
    (info / "http-alternates").write_text("https://example.test/objects\n", encoding="utf-8")

    assert "http-alternates" in _refusal_text(tmp_path, git_repository)


def test_alternate_object_directories_env_has_its_own_refusal(
    tmp_path: Path, git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(tmp_path / "elsewhere"))

    assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" in _refusal_text(tmp_path, git_repository)


def test_git_is_pinned_with_git_dir_work_tree_and_ceiling(
    tmp_path: Path, git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    real_run = handlers.subprocess.run
    seen: list[tuple[list[str], dict[str, str]]] = []

    def recording_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
        seen.append((list(command), dict(kwargs["env"])))
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(handlers.subprocess, "run", recording_run)
    _successful_call(tmp_path, git_repository)

    repository = git_repository.resolve()
    assert seen
    for command, env in seen:
        assert f"--git-dir={repository / '.git'}" in command
        assert f"--work-tree={repository}" in command
        assert env["GIT_CEILING_DIRECTORIES"] == str(repository.parent)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Descriptor-pinned object view is Linux-only; elsewhere the race is documented",
)
def test_pack_directory_flip_race_never_leaks_outside_commits(
    tmp_path: Path, git_repository: Path
) -> None:
    import threading

    outside = _outside_repository(tmp_path)
    _git(outside, "commit", "--allow-empty", "-q", "-m", "OTHER_SECRET_COMMIT")
    _git(outside, "gc", "-q")
    objects = git_repository / ".git" / "objects"
    pack = objects / "pack"
    parked = objects / "pack_parked"
    evil = outside / ".git" / "objects" / "pack"
    probe = tmp_path / "probe-link"
    _symlink_or_skip(probe, evil)
    probe.unlink()
    branch = _git_output(git_repository, "symbolic-ref", "--short", "HEAD")
    (git_repository / ".git" / "refs" / "heads" / branch).write_text(
        _git_output(outside, "rev-parse", "HEAD") + "\n", encoding="utf-8"
    )
    stop = threading.Event()

    def flip() -> None:
        while not stop.is_set():
            try:
                os.rename(pack, parked)
                os.symlink(evil, pack)
                time.sleep(0.0005)
                os.unlink(pack)
                os.rename(parked, pack)
                time.sleep(0.0005)
            except OSError:
                pass

    server = _status_server(tmp_path, git_repository)
    leaks: list[str] = []

    async def scenario() -> None:
        async with Client(server) as client:
            for _ in range(200):
                result = await client.call_tool(
                    "git_recent_commits", {"repository": str(git_repository)}
                )
                if not result.is_error and "OTHER_SECRET" in str(result.structured_content):
                    leaks.append("leak")

    flipper = threading.Thread(target=flip)
    flipper.start()
    try:
        asyncio.run(scenario())
    finally:
        stop.set()
        flipper.join()
    assert not leaks, f"{len(leaks)} of 200 calls leaked an outside commit"


def test_check_cost_does_not_grow_with_loose_objects(tmp_path: Path, git_repository: Path) -> None:
    objects = git_repository / ".git" / "objects"
    for index in range(60_000):
        fanout = objects / f"{index % 256:02x}"
        fanout.mkdir(exist_ok=True)
        (fanout / f"{index:038x}").write_bytes(b"x")
    server = _status_server(tmp_path, git_repository)

    async def scenario() -> float:
        async with Client(server) as client:
            started = time.perf_counter()
            result = await client.call_tool(
                "git_current_branch", {"repository": str(git_repository)}
            )
            assert result.is_error is False
            return time.perf_counter() - started

    assert asyncio.run(scenario()) < 2.0


def test_alternates_cap_is_sixty_four_stores() -> None:
    from mcp_toolbox.tools.git.handlers import _MAX_ALTERNATE_STORES

    assert _MAX_ALTERNATE_STORES == 64


def test_alternates_chain_one_over_the_cap_is_refused(tmp_path: Path, git_repository: Path) -> None:
    # The repository's own store plus 64 chained stores is 65, one over the cap.
    stores = [git_repository / f"store-{index}" for index in range(64)]
    for store in stores:
        store.mkdir()
    _write_alternates(git_repository / ".git" / "objects", f"{stores[0]}\n")
    for current, following in zip(stores, stores[1:], strict=False):
        _write_alternates(current, f"{following}\n")

    assert "alternates" in _refusal_text(tmp_path, git_repository)


def test_alternates_file_with_hundreds_of_duplicate_entries_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    # Few distinct stores, but the walk would visit far more than the cap allows.
    store = git_repository / "store"
    store.mkdir()
    _write_alternates(git_repository / ".git" / "objects", "../../store\n" * 300)

    assert "alternates" in _refusal_text(tmp_path, git_repository)


def test_dangling_http_alternates_symlink_is_refused(tmp_path: Path, git_repository: Path) -> None:
    store = git_repository / "store"
    (store / "info").mkdir(parents=True)
    _write_alternates(git_repository / ".git" / "objects", "../../store\n")
    _symlink_or_skip(store / "info" / "http-alternates", tmp_path / "missing")
    assert not (store / "info" / "http-alternates").exists()

    assert "http-alternates" in _refusal_text(tmp_path, git_repository)


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="Needs POSIX permissions and a non-root user",
)
def test_unreadable_refs_directory_is_refused(tmp_path: Path, git_repository: Path) -> None:
    locked = git_repository / ".git" / "refs" / "locked"
    locked.mkdir()
    locked.chmod(0)
    try:
        assert "could not be inspected" in _refusal_text(tmp_path, git_repository)
    finally:
        locked.chmod(0o755)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="Descriptor-pinned object view is Linux-only; elsewhere the race is documented",
)
def test_pack_swapped_after_checks_is_not_read(
    tmp_path: Path, git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    outside = _outside_repository(tmp_path)
    _git(outside, "commit", "--allow-empty", "-q", "-m", "OTHER_SECRET_COMMIT")
    _git(outside, "gc", "-q")
    branch = _git_output(git_repository, "symbolic-ref", "--short", "HEAD")
    (git_repository / ".git" / "refs" / "heads" / branch).write_text(
        _git_output(outside, "rev-parse", "HEAD") + "\n", encoding="utf-8"
    )
    pack = git_repository / ".git" / "objects" / "pack"
    real_run = handlers.subprocess.run

    objects = pack.parent

    def swap_then_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        # Deterministically lose the race: every check has passed, pack is swapped for a link
        # while Git runs, then swapped back and the directory times restored so the checks
        # after exec cannot see it happened.
        times = os.stat(objects)
        pack.rename(tmp_path / "parked-pack")
        pack.symlink_to(outside / ".git" / "objects" / "pack", target_is_directory=True)
        try:
            return real_run(*args, **kwargs)
        finally:
            pack.unlink()
            (tmp_path / "parked-pack").rename(pack)
            os.utime(objects, ns=(times.st_atime_ns, times.st_mtime_ns))

    monkeypatch.setattr(handlers.subprocess, "run", swap_then_run)
    server = _status_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository)}
            )
            assert "OTHER_SECRET" not in str(result.content) + str(result.structured_content)

    asyncio.run(scenario())
