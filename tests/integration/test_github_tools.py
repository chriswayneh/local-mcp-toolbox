from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    GitHubSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.github.handlers import GitHubGateway


def _github_settings(audit_path: Path) -> ToolboxSettings:
    return ToolboxSettings(
        profile=PermissionProfile.STANDARD,
        integrations=IntegrationSettings(github=True, external_network=True),
        github=GitHubSettings(approved_repositories=["Example/Project"]),
        audit=AuditSettings(path=audit_path),
    )


def test_github_tools_return_allowlisted_bounded_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, dict[str, str | int] | None]] = []

    def request_json(
        _gateway: GitHubGateway,
        path: str,
        query: dict[str, str | int] | None = None,
    ) -> Any:
        calls.append((path, query))
        if path.endswith("/issues"):
            return [
                {
                    "number": 7,
                    "title": "token=ghp_123456789012345678901234567890",
                    "state": "open",
                    "user": {"login": "octocat"},
                    "labels": [{"name": "bug"}],
                    "created_at": "2026-09-12T00:00:00Z",
                    "updated_at": "2026-09-12T01:00:00Z",
                    "html_url": "https://github.com/Example/Project/issues/7",
                },
                {"number": 8, "pull_request": {}},
            ]
        if path.endswith("/pulls"):
            return [
                {
                    "number": 9,
                    "title": "Add safe adapter",
                    "state": "open",
                    "draft": False,
                    "user": {"login": "octocat"},
                    "head": {"ref": "feature"},
                    "base": {"ref": "main"},
                    "created_at": "2026-09-12T00:00:00Z",
                    "updated_at": "2026-09-12T01:00:00Z",
                    "merged_at": None,
                    "html_url": "https://github.com/Example/Project/pull/9",
                }
            ]
        return {
            "full_name": "Example/Project",
            "description": "A safe repository",
            "visibility": "public",
            "private": False,
            "archived": False,
            "default_branch": "main",
            "open_issues_count": 2,
            "pushed_at": "2026-09-12T01:00:00Z",
            "html_url": "https://github.com/Example/Project",
            "license": {"spdx_id": "MIT"},
            "topics": ["mcp"],
        }

    monkeypatch.setattr(GitHubGateway, "request_json", request_json)
    server = create_server(build_runtime(_github_settings(tmp_path / "audit.jsonl")))

    async def scenario() -> None:
        async with Client(server) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            repository = await client.call_tool(
                "github_repository_summary", {"repository": "example/project"}
            )
            issues = await client.call_tool(
                "github_recent_issues",
                {"repository": "Example/Project", "limit": 10, "state": "all"},
            )
            pulls = await client.call_tool(
                "github_recent_pull_requests",
                {"repository": "Example/Project", "limit": 10},
            )
            denied = await client.call_tool(
                "github_repository_summary", {"repository": "other/repository"}
            )

            assert tools["github_repository_summary"].annotations.open_world_hint is True
            assert repository.is_error is False
            assert repository.structured_content["data"]["full_name"] == "Example/Project"
            assert issues.is_error is False
            assert len(issues.structured_content["data"]["issues"]) == 1
            assert "ghp_123456789012345678901234567890" not in str(issues.structured_content)
            assert pulls.is_error is False
            assert pulls.structured_content["data"]["pull_requests"][0]["head"] == "feature"
            assert denied.is_error is True
            assert denied.structured_content["category"] == "PERMISSION_DENIED"

    asyncio.run(scenario())
    assert calls == [
        ("/repos/Example/Project", None),
        ("/repos/Example/Project/issues", {"state": "all", "per_page": 10}),
        ("/repos/Example/Project/pulls", {"state": "open", "per_page": 10}),
    ]


def test_github_tools_are_not_registered_without_opt_in(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit.jsonl")))
    )

    async def scenario() -> None:
        async with Client(server) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert not {name for name in names if name.startswith("github_")}

    asyncio.run(scenario())
