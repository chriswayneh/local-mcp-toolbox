from __future__ import annotations

import asyncio
import shutil
import subprocess
import sys
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

_TOOLS = ("git_repository_status", "git_current_branch", "git_recent_commits", "git_diff_summary")


def _repository(tmp_path: Path) -> Path:
    if shutil.which("git") is None:
        pytest.skip("Git is not installed")
    repository = tmp_path / "approved-repository"
    repository.mkdir()
    for arguments in (
        ["init", "-q"],
        ["config", "user.name", "Toolbox Test"],
        ["config", "user.email", "toolbox@example.test"],
        ["commit", "-q", "--allow-empty", "-m", "PLATFORM_TEST_COMMIT"],
    ):
        subprocess.run(["git", "-C", str(repository), *arguments], check=True)
    return repository


def _call_all(tmp_path: Path, repository: Path) -> list[tuple[bool, str]]:
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
    results: list[tuple[bool, str]] = []

    async def scenario() -> None:
        async with Client(server) as client:
            for tool in _TOOLS:
                result = await client.call_tool(tool, {"repository": str(repository)})
                results.append(
                    (result.is_error, str(result.content) + str(result.structured_content))
                )

    asyncio.run(scenario())
    return results


def _assert_refused(results: list[tuple[bool, str]]) -> None:
    for is_error, text in results:
        assert is_error is True
        assert "not supported on this operating system" in text
        assert "PLATFORM_TEST_COMMIT" not in text


def test_git_tools_refuse_where_descriptor_pinning_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_toolbox.tools.git import handlers

    repository = _repository(tmp_path)
    monkeypatch.setattr(handlers, "_FD_PATHS", False)
    calls: list[object] = []
    monkeypatch.setattr(handlers.subprocess, "run", lambda *a, **k: calls.append(a))

    _assert_refused(_call_all(tmp_path, repository))
    assert calls == [], "Git must not be started on an unsupported platform"


@pytest.mark.skipif(
    sys.platform not in {"darwin", "win32"}, reason="Checks the real macOS/Windows refusal"
)
def test_git_tools_refuse_on_macos_and_windows(tmp_path: Path) -> None:
    _assert_refused(_call_all(tmp_path, _repository(tmp_path)))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux is the supported platform")
def test_git_tools_run_on_linux(tmp_path: Path) -> None:
    results = _call_all(tmp_path, _repository(tmp_path))
    assert all(is_error is False for is_error, _ in results)
