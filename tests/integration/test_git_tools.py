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
    for index in range(40_000):
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
    real_lstat = handlers.os.lstat
    saved_stat = real_lstat(objects)

    def freeze_objects_stat(path: Path):  # type: ignore[no-untyped-def]
        st = real_lstat(path)
        if Path(path) == objects and not pack.is_symlink():
            return saved_stat
        return st

    def swap_then_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        # Deterministically lose the race: every check has passed, pack is swapped for a link
        # while Git runs, then swapped back and the directory stat frozen so the post-exec
        # fingerprint check cannot see it happened; only the pinned object view stops the leak.
        pack.rename(tmp_path / "parked-pack")
        pack.symlink_to(outside / ".git" / "objects" / "pack", target_is_directory=True)
        try:
            return real_run(*args, **kwargs)
        finally:
            pack.unlink()
            (tmp_path / "parked-pack").rename(pack)

    monkeypatch.setattr(handlers.os, "lstat", freeze_objects_stat)
    monkeypatch.setattr(handlers.subprocess, "run", swap_then_run)
    server = _status_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository)}
            )
            assert "OTHER_SECRET" not in str(result.content) + str(result.structured_content)

    asyncio.run(scenario())


def test_symlinked_loose_object_reachable_from_a_ref_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    outside = _outside_repository(tmp_path)
    _git(outside, "commit", "--allow-empty", "-q", "-m", "OTHER_SECRET_COMMIT")
    secret = _git_output(outside, "rev-parse", "HEAD")
    tree = _git_output(outside, "rev-parse", "HEAD^{tree}")
    objects = git_repository / ".git" / "objects"
    # Link the outside commit, its tree, and its parent chain in as loose objects.
    for sha in {secret, tree, *_git_output(outside, "rev-list", "--objects", "--all").split()}:
        if len(sha) != 40:
            continue
        source = outside / ".git" / "objects" / sha[:2] / sha[2:]
        if not source.exists():
            continue
        (objects / sha[:2]).mkdir(exist_ok=True)
        target = objects / sha[:2] / sha[2:]
        if not target.exists():
            _symlink_or_skip(target, source)
    (git_repository / ".git" / "refs" / "heads" / "evil").write_text(secret + "\n", "utf-8")
    assert "OTHER_SECRET_COMMIT" in _git_output(git_repository, "log", "-1", "--format=%s", "evil")

    _assert_every_git_tool_refused(tmp_path, git_repository)
    text = _refusal_text(tmp_path, git_repository)
    assert "symlinked loose object" in text and "OTHER_SECRET" not in text


def test_too_many_loose_objects_asks_for_git_gc(tmp_path: Path, git_repository: Path) -> None:
    from mcp_toolbox.tools.git.handlers import _MAX_LOOSE_OBJECTS

    objects = git_repository / ".git" / "objects"
    for index in range(_MAX_LOOSE_OBJECTS + 1):
        fanout = objects / f"{index % 256:02x}"
        fanout.mkdir(exist_ok=True)
        (fanout / f"{index:038x}").write_bytes(b"x")

    assert "git gc" in _refusal_text(tmp_path, git_repository)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_fifo_in_pack_directory_is_refused_without_hanging(
    tmp_path: Path, git_repository: Path
) -> None:
    import tempfile

    pack = git_repository / ".git" / "objects" / "pack"
    pack.mkdir(exist_ok=True)
    os.mkfifo(pack / "pack-trap.pack")
    before = set(Path(tempfile.gettempdir()).glob("local-mcp-toolbox-git-objects-*"))

    started = time.perf_counter()
    text = _refusal_text(tmp_path, git_repository)
    assert time.perf_counter() - started < 5
    assert "not a regular file" in text
    after = set(Path(tempfile.gettempdir()).glob("local-mcp-toolbox-git-objects-*"))
    assert after <= before, "private object view was left behind"


def test_in_repo_alternate_store_with_symlinked_fanout_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    outside = _outside_repository(tmp_path)
    _git(outside, "commit", "--allow-empty", "-q", "-m", "OUTSIDE_ALT_SECRET_999")
    secret = _git_output(outside, "rev-parse", "HEAD")
    alt_store = git_repository / "alt_store"
    alt_store.mkdir()
    _write_alternates(git_repository / ".git" / "objects", "../../alt_store\n")
    for sha in {secret, *_git_output(outside, "rev-list", "--objects", "--all").split()}:
        if len(sha) == 40 and not (alt_store / sha[:2]).exists():
            _symlink_or_skip(alt_store / sha[:2], outside / ".git" / "objects" / sha[:2])
    branch = _git_output(git_repository, "symbolic-ref", "--short", "HEAD")
    (git_repository / ".git" / "refs" / "heads" / branch).write_text(secret + "\n", "utf-8")
    assert "OUTSIDE_ALT_SECRET_999" in _git_output(git_repository, "log", "-1", "--format=%s")

    _assert_every_git_tool_refused(tmp_path, git_repository)
    text = _refusal_text(tmp_path, git_repository)
    assert "contains a symlink" in text and "OUTSIDE_ALT_SECRET_999" not in text


def test_in_repo_alternate_store_with_symlinked_loose_object_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    outside = _outside_repository(tmp_path)
    _git(outside, "commit", "--allow-empty", "-q", "-m", "OUTSIDE_ALT_SECRET_999")
    secret = _git_output(outside, "rev-parse", "HEAD")
    alt_store = git_repository / "alt_store"
    alt_store.mkdir()
    _write_alternates(git_repository / ".git" / "objects", "../../alt_store\n")
    for sha in {secret, *_git_output(outside, "rev-list", "--objects", "--all").split()}:
        if len(sha) != 40:
            continue
        source = outside / ".git" / "objects" / sha[:2] / sha[2:]
        if not source.exists():
            continue
        (alt_store / sha[:2]).mkdir(exist_ok=True)
        target = alt_store / sha[:2] / sha[2:]
        if not target.exists():
            _symlink_or_skip(target, source)
    (git_repository / ".git" / "refs" / "heads" / "evil").write_text(secret + "\n", "utf-8")
    assert "OUTSIDE_ALT_SECRET_999" in _git_output(
        git_repository, "log", "-1", "--format=%s", "evil"
    )

    _assert_every_git_tool_refused(tmp_path, git_repository)
    text = _refusal_text(tmp_path, git_repository)
    assert "symlinked loose object" in text and "OUTSIDE_ALT_SECRET_999" not in text


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_in_repo_alternate_store_with_fifo_in_pack_is_refused(
    tmp_path: Path, git_repository: Path
) -> None:
    import tempfile

    alt_store = git_repository / "alt_store"
    (alt_store / "pack").mkdir(parents=True)
    os.mkfifo(alt_store / "pack" / "pack-trap.pack")
    _write_alternates(git_repository / ".git" / "objects", "../../alt_store\n")
    before = set(Path(tempfile.gettempdir()).glob("local-mcp-toolbox-git-objects-*"))

    started = time.perf_counter()
    _assert_every_git_tool_refused(tmp_path, git_repository)
    text = _refusal_text(tmp_path, git_repository)
    assert time.perf_counter() - started < 2.0
    assert "not a regular file" in text
    after = set(Path(tempfile.gettempdir()).glob("local-mcp-toolbox-git-objects-*"))
    assert after <= before, "private object view was left behind"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
@pytest.mark.parametrize(
    "relative_fifo",
    [
        "HEAD",
        "packed-refs",
        "config",
        "objects/info/alternates",
        "objects/ab/0123456789abcdef0123456789abcdef012345",
        "refs/heads/fifo-ref",
    ],
)
def test_fifo_in_git_metadata_or_loose_objects_is_refused_without_hanging(
    tmp_path: Path, git_repository: Path, relative_fifo: str
) -> None:
    import signal
    import tempfile

    target = git_repository / ".git" / relative_fifo
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    os.mkfifo(target)
    before = set(Path(tempfile.gettempdir()).glob("local-mcp-toolbox-git-objects-*"))

    def on_alarm(_signum: int, _frame: object) -> None:
        raise TimeoutError(f"Blocked opening FIFO at {relative_fifo}")

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(2)
    try:
        started = time.perf_counter()
        text = _refusal_text(tmp_path, git_repository)
        assert time.perf_counter() - started < 2.0
        assert "not a regular file" in text
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
    after = set(Path(tempfile.gettempdir()).glob("local-mcp-toolbox-git-objects-*"))
    assert after <= before, "private object view was left behind"


def test_git_dir_fingerprint_includes_ctime_ns(
    git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    git_dir = git_repository / ".git"
    baseline = handlers._git_dir_fingerprint(git_dir)
    real_lstat = handlers.os.lstat
    objects_path = git_dir / "objects"

    def bumped_ctime_lstat(path: Path):  # type: ignore[no-untyped-def]
        st = real_lstat(path)
        if Path(path) == objects_path:
            # Same st_dev, st_ino, st_mode, and st_mtime_ns (as after os.utime), but newer ctime.
            values = list(st)
            return os.stat_result(
                values,
                {
                    "st_atime_ns": st.st_atime_ns,
                    "st_mtime_ns": st.st_mtime_ns,
                    "st_ctime_ns": st.st_ctime_ns + 1_000_000,
                },
            )
        return st

    monkeypatch.setattr(handlers.os, "lstat", bumped_ctime_lstat)
    assert handlers._git_dir_fingerprint(git_dir) != baseline


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are POSIX-only")
def test_packed_refs_fifo_with_one_second_timeout_refuses_immediately(
    tmp_path: Path, git_repository: Path
) -> None:
    from mcp_toolbox.config.settings import LimitSettings

    packed_refs = git_repository / ".git" / "packed-refs"
    if packed_refs.exists():
        packed_refs.unlink()
    os.mkfifo(packed_refs)
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                limits=LimitSettings(timeout_seconds=1),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            started = time.perf_counter()
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository)}
            )
            assert time.perf_counter() - started < 1.0
            assert result.is_error is True
            assert "not a regular file" in str(result.content) + str(result.structured_content)

    asyncio.run(scenario())


def test_in_repo_alternate_store_objects_are_served_through_verified_private_view(
    tmp_path: Path, git_repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    alt_repo = tmp_path / "alt-work"
    alt_repo.mkdir()
    _git(alt_repo, "init", "-b", "main")
    _git(alt_repo, "config", "user.name", "Alt Author")
    _git(alt_repo, "config", "user.email", "alt@example.test")
    (alt_repo / "note.txt").write_text("alt content\n", encoding="utf-8")
    _git(alt_repo, "add", "note.txt")
    _git(alt_repo, "commit", "-q", "-m", "ALT_IN_REPO_COMMIT")
    alt_head = _git_output(alt_repo, "rev-parse", "HEAD")

    alt_store = git_repository / "alt_store"
    shutil.copytree(alt_repo / ".git" / "objects", alt_store)
    _write_alternates(git_repository / ".git" / "objects", "../../alt_store\n")
    branch = _git_output(git_repository, "symbolic-ref", "--short", "HEAD")
    (git_repository / ".git" / "refs" / "heads" / branch).write_text(alt_head + "\n", "utf-8")

    real_run = handlers.subprocess.run
    seen_alternates: list[str] = []

    def inspect_view_then_run(command, *args, **kwargs):  # type: ignore[no-untyped-def]
        obj_dir = Path(kwargs["env"]["GIT_OBJECT_DIRECTORY"])
        seen_alternates.extend(
            (obj_dir / "info" / "alternates").read_text(encoding="utf-8").splitlines()
        )
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr(handlers.subprocess, "run", inspect_view_then_run)
    server = _status_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository)}
            )
            assert result.is_error is False
            assert "ALT_IN_REPO_COMMIT" in str(result.structured_content)

    asyncio.run(scenario())
    assert seen_alternates and all("alt-0" in line for line in seen_alternates)


@pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX shell required for the probe")
def test_git_tools_ignore_repository_config_that_runs_programs(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "repo-config-ran"
    probe = tmp_path / "probe.sh"
    probe.write_text(f"#!/bin/sh\necho ran >> '{marker}'\n", encoding="utf-8")
    probe.chmod(0o755)
    hooks = git_repository / ".git" / "hooks"
    for hook in ("post-index-change", "pre-commit"):
        (hooks / hook).write_text(probe.read_text(encoding="utf-8"), encoding="utf-8")
        (hooks / hook).chmod(0o755)
    (git_repository / ".gitattributes").write_text("*.md diff=probe\n", encoding="utf-8")
    _git(git_repository, "config", "core.fsmonitor", str(probe))
    _git(git_repository, "config", "diff.external", str(probe))
    _git(git_repository, "config", "diff.probe.textconv", str(probe))
    _git(git_repository, "config", "diff.probe.command", str(probe))
    (git_repository / ".gitattributes").write_text(
        "*.md diff=probe filter=probe\n*.txt filter=probe\n", encoding="utf-8"
    )
    _git(git_repository, "config", "filter.probe.clean", str(probe))
    _git(git_repository, "config", "filter.probe.process", str(probe))
    for tracked in git_repository.iterdir():
        if tracked.is_file():
            tracked.write_text(tracked.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
    index = git_repository / ".git" / "index"
    index_before = index.read_bytes()

    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in ("git_repository_status", "git_diff_summary", "git_current_branch"):
                result = await client.call_tool(tool, {"repository": str(git_repository)})
                assert result.is_error is False

    asyncio.run(scenario())

    assert not marker.exists(), "repository config made Git run a program"
    assert index.read_bytes() == index_before, "read-only Git inspection rewrote the index"


def _git_output(repository: Path, *arguments: str, stdin: str | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        shell=False,
        capture_output=True,
        text=True,
        input=stdin,
    ).stdout.strip()


def _write_probe(tmp_path: Path, marker: Path) -> Path:
    probe = tmp_path / "probe.sh"
    probe.write_text(f"#!/bin/sh\necho ran >> '{marker}'\ncat >/dev/null\n", encoding="utf-8")
    probe.chmod(0o755)
    return probe


def _git_server(tmp_path: Path, repository: Path) -> object:
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


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter or verifier",
)
def test_recent_commits_never_runs_a_repository_signature_verifier(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "verifier-ran"
    probe = _write_probe(tmp_path, marker)
    # Write a commit object carrying a gpgsig header so `git log` has a signature to verify.
    tree = _git_output(git_repository, "rev-parse", "HEAD^{tree}")
    parent = _git_output(git_repository, "rev-parse", "HEAD")
    signature = "\n ".join(
        ["-----BEGIN PGP SIGNATURE-----", "", "iQEzBAABCAAdFiEEfake", "-----END PGP SIGNATURE-----"]
    )
    commit = (
        f"tree {tree}\nparent {parent}\n"
        "author Toolbox Test <toolbox@example.test> 1700000000 +0000\n"
        "committer Toolbox Test <toolbox@example.test> 1700000000 +0000\n"
        f"gpgsig {signature}\n\nSigned commit\n"
    )
    signed = _git_output(
        git_repository, "hash-object", "-t", "commit", "-w", "--stdin", stdin=commit
    )
    _git(git_repository, "update-ref", "HEAD", signed)
    _git(git_repository, "config", "log.showSignature", "true")
    _git(git_repository, "config", "gpg.program", str(probe))
    _git(git_repository, "config", "gpg.format", "openpgp")
    # Sanity check: a plain `git log` in this repository does run the verifier.
    _git(git_repository, "log", "-1")
    assert marker.exists(), "fixture did not make git log run the verifier"
    marker.unlink()

    server = _git_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:  # type: ignore[arg-type]
            result = await client.call_tool(
                "git_recent_commits", {"repository": str(git_repository), "limit": 5}
            )
            assert result.is_error is False
            subjects = [c["subject"] for c in result.structured_content["data"]["commits"]]
            assert subjects[0] == "Signed commit"

    asyncio.run(scenario())

    assert not marker.exists(), "git_recent_commits ran a repository-chosen signature verifier"


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter or verifier",
)
def test_status_and_diff_never_run_filters_defined_only_in_a_submodule(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "submodule-filter-ran"
    probe = _write_probe(tmp_path, marker)
    child = tmp_path / "child-source"
    child.mkdir()
    _git(child, "init")
    _git(child, "config", "user.name", "Toolbox Test")
    _git(child, "config", "user.email", "toolbox@example.test")
    (child / ".gitattributes").write_text("*.txt filter=childonly\n", encoding="utf-8")
    (child / "data.txt").write_text("one\n", encoding="utf-8")
    _git(child, "add", ".")
    _git(child, "commit", "-m", "child")
    _git(git_repository, "-c", "protocol.file.allow=always", "submodule", "add", str(child), "sub")
    _git(git_repository, "commit", "-m", "add submodule")
    submodule = git_repository / "sub"
    _git(submodule, "config", "filter.childonly.clean", str(probe))
    # Same size, newer mtime: Git must run the clean filter to tell whether it changed.
    data = submodule / "data.txt"
    data.write_text("uno\n", encoding="utf-8")
    stat = data.stat()
    os.utime(data, (stat.st_atime + 5, stat.st_mtime + 5))
    # Sanity check: a plain `git status` in the parent does run the submodule's filter.
    _git(git_repository, "status")
    assert marker.exists(), "fixture did not make git status run the submodule filter"
    marker.unlink()

    server = _git_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:  # type: ignore[arg-type]
            for tool in ("git_repository_status", "git_diff_summary"):
                result = await client.call_tool(tool, {"repository": str(git_repository)})
                assert result.is_error is False

    asyncio.run(scenario())

    assert not marker.exists(), "Git tools ran a filter defined only in a submodule"


def test_git_diff_summary_never_rewrites_the_index(tmp_path: Path, git_repository: Path) -> None:
    import os

    other = git_repository / "other.txt"
    other.write_bytes(b"tracked\n")
    _git(git_repository, "add", "other.txt")
    _git(git_repository, "commit", "-m", "Add other")
    index = git_repository / ".git" / "index"
    past = 1_600_000_000
    os.utime(index, (past, past))
    # Make a tracked file stat-dirty but content-identical so a refreshing diff rewrites the index.
    os.utime(other, (past + 3600, past + 3600))
    before_bytes = index.read_bytes()
    before_mtime = index.stat().st_mtime_ns

    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                filesystem=FilesystemSettings(approved_roots=[tmp_path]),
                integrations=IntegrationSettings(git=True),
                git=GitSettings(approved_repositories=[git_repository]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            diff = await client.call_tool("git_diff_summary", {"repository": str(git_repository)})
            assert diff.is_error is False
            data = diff.structured_content["data"]
            assert [item["path"] for item in data["files"]] == ["README.md"], data
            assert data["changed_file_count"] == 1

    asyncio.run(scenario())

    assert index.read_bytes() == before_bytes
    assert index.stat().st_mtime_ns == before_mtime


def _diff_paths(tmp_path: Path, repository: Path) -> list[str]:
    server = create_server(
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
    result: list[str] = []

    async def scenario() -> None:
        async with Client(server) as client:
            diff = await client.call_tool("git_diff_summary", {"repository": str(repository)})
            assert diff.is_error is False
            data = diff.structured_content["data"]
            assert data["changed_file_count"] == len(data["files"])
            result.extend(item["path"] for item in data["files"])

    asyncio.run(scenario())
    return sorted(result)


def _commit_files(repository: Path, files: dict[str, bytes]) -> None:
    for name, content in files.items():
        (repository / name).write_bytes(content)
    _git(repository, "add", *files)
    _git(repository, "commit", "-m", "Add fixtures")


def _touch(path: Path) -> None:
    import os

    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 7_000_000_000))


_POSIX_ONLY = pytest.mark.skipif(
    __import__("sys").platform == "win32", reason="POSIX file modes and file names"
)


def test_git_diff_summary_reports_deleted_empty_tracked_file(
    tmp_path: Path, git_repository: Path
) -> None:
    _commit_files(git_repository, {"empty.txt": b""})
    (git_repository / "empty.txt").unlink()

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "empty.txt"]


def test_git_diff_summary_drops_touched_only_file_next_to_real_changes(
    tmp_path: Path, git_repository: Path
) -> None:
    _commit_files(git_repository, {"touched.txt": b"same\n", "edited.txt": b"one\n"})
    _touch(git_repository / "touched.txt")
    (git_repository / "edited.txt").write_bytes(b"one\ntwo\n")

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "edited.txt"]


@_POSIX_ONLY
def test_git_diff_summary_qe_touch_delete_chmod_repro(tmp_path: Path, git_repository: Path) -> None:
    _commit_files(git_repository, {"a.txt": b"a\n", "b_empty.txt": b"", "c.sh": b"c\n"})
    _touch(git_repository / "a.txt")
    (git_repository / "b_empty.txt").unlink()
    (git_repository / "c.sh").chmod(0o755)

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "b_empty.txt", "c.sh"]


@_POSIX_ONLY
def test_git_diff_summary_red_team_touch_and_chmod(tmp_path: Path, git_repository: Path) -> None:
    _commit_files(git_repository, {"b": b"b\n", "c": b"c\n"})
    _touch(git_repository / "b")
    (git_repository / "c").chmod(0o755)

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "c"]


def test_git_diff_summary_reports_merge_conflict_once(tmp_path: Path, git_repository: Path) -> None:
    _commit_files(git_repository, {"m.txt": b"base\n"})
    _git(git_repository, "checkout", "-b", "other")
    _commit_files(git_repository, {"m.txt": b"other\n"})
    _git(git_repository, "checkout", "-")
    _commit_files(git_repository, {"m.txt": b"mine\n"})
    subprocess.run(
        ["git", "-C", str(git_repository), "merge", "other"], check=False, capture_output=True
    )

    assert _diff_paths(tmp_path, git_repository) == ["README.md", "m.txt"]


@_POSIX_ONLY
def test_git_diff_summary_handles_tab_newline_and_unicode_paths(
    tmp_path: Path, git_repository: Path
) -> None:
    names = ["tab\tname.txt", "new\nline.txt", "\u00fcnic\u00f8de \u6587.txt"]
    _commit_files(git_repository, {name: b"x\n" for name in names})
    for name in names:
        (git_repository / name).write_bytes(b"x\ny\n")

    # Paths come back intact but with control characters escaped (issue #42).
    expected = ["tab\\x09name.txt", "new\\x0aline.txt", "\u00fcnic\u00f8de \u6587.txt"]
    assert sorted(_diff_paths(tmp_path, git_repository)) == sorted(["README.md", *expected])


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter",
)
def test_filter_driver_with_equals_in_name_never_runs_probe(
    tmp_path: Path, git_repository: Path
) -> None:
    from mcp_toolbox.models import ErrorCategory, ToolboxError
    from mcp_toolbox.tools.git.handlers import GitRunner, _safe_git_environment

    marker = tmp_path / "eq-filter-ran"
    probe = _write_probe(tmp_path, marker)
    config_path = git_repository / ".git" / "config"
    config_path.write_text(
        config_path.read_text(encoding="utf-8") + f'\n[filter "a=b"]\n\tclean = {probe}\n',
        encoding="utf-8",
    )
    (git_repository / ".gitattributes").write_text(
        "*.md filter=a=b\n*.txt filter=a=b\n", encoding="utf-8"
    )
    readme = git_repository / "README.md"
    # Same byte length as the committed "Initial content\n" so git status must run clean filter.
    readme.write_text("Initial CONTENX\n", encoding="utf-8")
    stat = readme.stat()
    os.utime(readme, (stat.st_atime + 10, stat.st_mtime + 10))

    # Sanity check: plain `git -c filter.a=b.clean= status` splits on the first '=' and runs probe.
    _git(git_repository, "-c", "filter.a=b.clean=", "status", "--porcelain=v1")
    assert marker.exists(), 'fixture did not make git status run the [filter "a=b"] clean command'
    marker.unlink()

    # Defense 1: GIT_CONFIG_KEY_<n> in _safe_git_environment does not split on '=' in key names.
    os.utime(readme, (stat.st_atime + 20, stat.st_mtime + 20))
    subprocess.run(
        ["git", "-C", str(git_repository), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
        env=_safe_git_environment(["-c", "filter.a=b.clean=", "-c", "filter.a=b.required=false"]),
    )
    assert not marker.exists(), "GIT_CONFIG_KEY_<n> failed to blank filter.a=b.clean"

    # Defense 2: GitRunner and MCP tools refuse the repository before running git status/diff.
    runtime = build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            filesystem=FilesystemSettings(approved_roots=[tmp_path]),
            integrations=IntegrationSettings(git=True),
            git=GitSettings(approved_repositories=[git_repository]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )
    with pytest.raises(ToolboxError) as caught:
        GitRunner(runtime).run(git_repository, ["status", "--porcelain=v1"])
    assert caught.value.category is ErrorCategory.PERMISSION_DENIED
    assert not marker.exists()

    server = create_server(runtime)

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in ("git_repository_status", "git_diff_summary"):
                result = await client.call_tool(tool, {"repository": str(git_repository)})
                assert result.is_error is True

    asyncio.run(scenario())
    assert not marker.exists(), '[filter "a=b"] executed probe through MCP tool'


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as a filter",
)
@pytest.mark.parametrize("bad_driver", ["foo\x1ebar", "foo\u2028bar", "a.clean\x1efilter.b"])
def test_filter_driver_with_line_separator_in_name_is_refused_and_never_runs_probe(
    bad_driver: str, tmp_path: Path, git_repository: Path
) -> None:
    from mcp_toolbox.models import ErrorCategory, ToolboxError
    from mcp_toolbox.tools.git.handlers import GitRunner

    marker = tmp_path / "sep-filter-ran"
    probe = _write_probe(tmp_path, marker)
    config_path = git_repository / ".git" / "config"
    config_path.write_bytes(
        config_path.read_bytes() + f'\n[filter "{bad_driver}"]\n\tclean = {probe}\n'.encode()
    )
    (git_repository / ".gitattributes").write_bytes(f"*.md filter={bad_driver}\n".encode())
    readme = git_repository / "README.md"
    readme.write_text("Initial CONTENX\n", encoding="utf-8")
    stat = readme.stat()
    os.utime(readme, (stat.st_atime + 10, stat.st_mtime + 10))

    runtime = build_runtime(
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            filesystem=FilesystemSettings(approved_roots=[tmp_path]),
            integrations=IntegrationSettings(git=True),
            git=GitSettings(approved_repositories=[git_repository]),
            audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
        )
    )
    with pytest.raises(ToolboxError) as caught:
        GitRunner(runtime).run(git_repository, ["status", "--porcelain=v1"])
    assert caught.value.category is ErrorCategory.PERMISSION_DENIED
    assert not marker.exists(), f"filter driver {bad_driver!r} executed probe"


@pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("sh") is None,
    reason="POSIX shell probe; Git for Windows cannot run it as an uploadpack/ssh helper",
)
def test_promisor_partial_clone_never_runs_lazy_fetch_helpers(
    tmp_path: Path, git_repository: Path
) -> None:
    marker = tmp_path / "promisor-ran"
    probe = tmp_path / "promisor-probe.sh"
    probe.write_text(f"#!/bin/sh\necho ran >> '{marker}'\nexit 1\n", encoding="utf-8")
    probe.chmod(0o755)
    pack_dir = git_repository / ".git" / "objects" / "pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / f"pack-{'1' * 40}.promisor").write_bytes(b"")
    (git_repository / ".git" / "refs" / "heads" / "main").write_text(
        f"{'2' * 40}\n", encoding="utf-8"
    )
    (git_repository / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    _git(git_repository, "config", "core.repositoryformatversion", "1")
    _git(git_repository, "config", "extensions.partialclone", "origin")
    _git(git_repository, "config", "remote.origin.url", str(tmp_path))
    _git(git_repository, "config", "remote.origin.promisor", "true")
    _git(git_repository, "config", "remote.origin.uploadpack", str(probe))
    _git(git_repository, "config", "core.sshCommand", str(probe))

    # Sanity check: plain `git log` in this repo triggers a promisor lazy fetch and runs probe.
    subprocess.run(
        ["git", "-C", str(git_repository), "log", "-1"],
        check=False,
        capture_output=True,
    )
    assert marker.exists(), "fixture did not make plain git log run the promisor helper"
    marker.unlink()

    server = _git_server(tmp_path, git_repository)

    async def scenario() -> None:
        async with Client(server) as client:  # type: ignore[arg-type]
            for tool in (
                "git_recent_commits",
                "git_repository_status",
                "git_diff_summary",
                "git_current_branch",
            ):
                await client.call_tool(tool, {"repository": str(git_repository)})

    asyncio.run(scenario())
    assert not marker.exists(), "Git tool triggered a partial-clone promisor lazy fetch"


def test_git_tools_escape_control_and_bidi_characters(tmp_path: Path) -> None:
    """Raw terminal and bidi controls in paths and subjects never reach the client."""

    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    repository = tmp_path / "control-repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Toolbox Test")
    _git(repository, "config", "user.email", "toolbox@example.test")
    tricky = "evil\u202etxt.md"
    (repository / tricky).write_text("one\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-m", "subject \x1b[31mred\x1b[0m \u2066x\u2069")
    (repository / tricky).write_text("one\ntwo\n", encoding="utf-8")
    (repository / "new\x07file.md").write_text("x\n", encoding="utf-8")
    server = create_server(
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

    async def scenario() -> None:
        async with Client(server) as client:
            results = [
                await client.call_tool("git_repository_status", {"repository": str(repository)}),
                await client.call_tool("git_recent_commits", {"repository": str(repository)}),
                await client.call_tool("git_diff_summary", {"repository": str(repository)}),
            ]
            for result in results:
                assert result.is_error is False
                text = "".join(_all_strings(result.structured_content))
                for raw in ("\x1b", "\x07", "\u202e", "\u2066", "\u2069"):
                    assert raw not in text
            status, commits, diff = (r.structured_content["data"] for r in results)
            # Every tool returns the same escaped form of a path (issue #42).
            paths = {change["path"] for change in status["changes"]}
            assert paths == {"evil\\u202etxt.md", "new\\x07file.md"}
            assert commits["commits"][0]["subject"] == (
                "subject \\x1b[31mred\\x1b[0m \\u2066x\\u2069"
            )
            assert diff["files"][0]["path"] == "evil\\u202etxt.md"

    asyncio.run(scenario())


def _all_strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for item in value.values() for text in _all_strings(item)]
    if isinstance(value, list):
        return [text for item in value for text in _all_strings(item)]
    return []


def test_git_branch_names_with_bidi_characters_come_back_escaped(tmp_path: Path) -> None:
    """Both tools that report the branch name escape it (issue #42)."""

    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    repository = tmp_path / "branch-repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Toolbox Test")
    _git(repository, "config", "user.email", "toolbox@example.test")
    _git(repository, "commit", "--allow-empty", "-m", "base")
    _git(repository, "checkout", "-b", "feat\u202eabc")
    server = create_server(
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

    async def scenario() -> None:
        async with Client(server) as client:
            status = await client.call_tool(
                "git_repository_status", {"repository": str(repository)}
            )
            branch = await client.call_tool("git_current_branch", {"repository": str(repository)})
            assert status.structured_content["data"]["branch"]["head"] == "feat\\u202eabc"
            assert branch.structured_content["data"]["reference"] == "feat\\u202eabc"

    asyncio.run(scenario())


def test_git_status_handles_renames_and_spaces_without_quoting(tmp_path: Path) -> None:
    """With -z, status paths are raw (then escaped), and a rename reports the new path."""

    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    repository = tmp_path / "rename-repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.name", "Toolbox Test")
    _git(repository, "config", "user.email", "toolbox@example.test")
    (repository / "old name.md").write_text("x\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-m", "base")
    _git(repository, "mv", "old name.md", "new name.md")
    (repository / "tab\tfile.md").write_text("x\n", encoding="utf-8")
    server = create_server(
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

    async def scenario() -> None:
        async with Client(server) as client:
            status = await client.call_tool(
                "git_repository_status", {"repository": str(repository)}
            )
            changes = status.structured_content["data"]["changes"]
            assert status.structured_content["data"]["changed_file_count"] == 2
            assert {(c["index_status"], c["path"]) for c in changes} == {
                ("R", "new name.md"),
                ("?", "tab\\x09file.md"),
            }

    asyncio.run(scenario())
