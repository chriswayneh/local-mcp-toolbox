from __future__ import annotations

import asyncio
import shutil
import subprocess
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


def test_commondir_pointing_outside_is_refused(tmp_path: Path, git_repository: Path) -> None:
    outside = _outside_repository(tmp_path)
    git_dir = git_repository / ".git"
    shutil.rmtree(git_dir / "refs")
    shutil.rmtree(git_dir / "objects")
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
