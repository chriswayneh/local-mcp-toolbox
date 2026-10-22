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
