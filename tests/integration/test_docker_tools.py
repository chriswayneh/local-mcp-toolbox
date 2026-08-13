from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.docker.handlers import DockerGateway


@dataclass
class FakeImage:
    tags: list[str]


class FakeContainer:
    def __init__(self, name: str, *, health: str | None, logs: bytes) -> None:
        self.name = name
        self.short_id = "abc123def456"
        self.status = "running"
        self.image = FakeImage(tags=["example/api:1.0"])
        self._logs = logs
        self.attrs: dict[str, Any] = {
            "Created": "2026-08-13T00:00:00Z",
            "Image": "sha256:example",
            "Config": {"Entrypoint": ["python"], "Cmd": ["app.py"]},
            "State": {
                "RestartCount": 2,
                "StartedAt": "2026-08-13T00:01:00Z",
                "FinishedAt": "",
                "ExitCode": 0,
                "OOMKilled": False,
                "Health": {"Status": health} if health else None,
            },
        }

    def logs(self, **_: Any) -> bytes:
        return self._logs


class FakeContainers:
    def __init__(self, containers: list[FakeContainer]) -> None:
        self._containers = containers

    def list(self, *, all: bool) -> list[FakeContainer]:
        del all
        return self._containers

    def get(self, identifier: str) -> FakeContainer:
        for container in self._containers:
            if identifier in {container.name, container.short_id}:
                return container
        raise LookupError(identifier)


class FakeDockerClient:
    def __init__(self, containers: list[FakeContainer]) -> None:
        self.containers = FakeContainers(containers)


def test_docker_tools_return_safe_bounded_redacted_responses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api = FakeContainer(
        "api",
        health="unhealthy",
        logs=b"2026-08-13 error token=ghp_123456789012345678901234567890\n",
    )
    worker = FakeContainer("worker", health="healthy", logs=b"worker ready\n")
    client = FakeDockerClient([api, worker])
    monkeypatch.setattr(DockerGateway, "_client", lambda self: client)
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                integrations=IntegrationSettings(docker=True),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as mcp_client:
            listed = await mcp_client.call_tool("docker_list_containers", {"limit": 10})
            details = await mcp_client.call_tool("docker_container_details", {"container": "api"})
            logs = await mcp_client.call_tool(
                "docker_container_logs", {"container": "api", "tail": 10}
            )
            unhealthy = await mcp_client.call_tool("docker_unhealthy_containers", {"limit": 10})
            invalid = await mcp_client.call_tool(
                "docker_container_details", {"container": "api;rm -rf"}
            )

            assert listed.is_error is False
            assert listed.structured_content["data"]["total_containers"] == 2
            assert details.is_error is False
            assert details.structured_content["data"]["restart_count"] == 2
            assert details.structured_content["data"]["health"] == "unhealthy"
            assert logs.is_error is False
            assert (
                "ghp_123456789012345678901234567890" not in logs.structured_content["data"]["logs"]
            )
            assert "[REDACTED_GITHUB_TOKEN]" in logs.structured_content["data"]["logs"]
            assert unhealthy.is_error is False
            assert unhealthy.structured_content["data"]["total_unhealthy"] == 1
            assert invalid.is_error is True

    asyncio.run(scenario())


def test_docker_tools_are_not_registered_when_integration_is_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"))
        )
    )

    async def scenario() -> None:
        async with Client(server) as mcp_client:
            tools = await mcp_client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "docker_list_containers",
                "docker_container_details",
                "docker_container_logs",
                "docker_unhealthy_containers",
            }

    asyncio.run(scenario())
