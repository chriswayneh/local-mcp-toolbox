from __future__ import annotations

import asyncio
from pathlib import Path

from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    InfrastructureSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server


def _server(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                integrations=IntegrationSettings(infrastructure=True),
                infrastructure=InfrastructureSettings(approved_roots=[root]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )
    return root, server


def test_infrastructure_tools_return_top_level_metadata_only(tmp_path: Path) -> None:
    root, server = _server(tmp_path)
    for name in ("Dockerfile", "compose.yml", "package.json", "pyproject.toml", "main.tf"):
        (root / name).write_text("not read by this tool", encoding="utf-8")
    (root / ".github").mkdir()

    async def scenario() -> None:
        async with Client(server) as client:
            detected = await client.call_tool("infra_detect_project_types", {"project": str(root)})
            inventory = await client.call_tool(
                "infra_configuration_inventory", {"project": str(root), "limit": 10}
            )
            denied = await client.call_tool(
                "infra_detect_project_types", {"project": str(tmp_path)}
            )

            assert detected.is_error is False
            assert set(detected.structured_content["data"]["project_types"]) == {
                "docker",
                "github_actions",
                "node",
                "python",
                "terraform",
            }
            assert inventory.is_error is False
            assert inventory.structured_content["data"]["scope"] == "top_level_only"
            assert {item["name"] for item in inventory.structured_content["data"]["items"]} == {
                "Dockerfile",
                "compose.yml",
                "main.tf",
                "package.json",
                "pyproject.toml",
            }
            assert denied.is_error is True

    asyncio.run(scenario())


def test_infrastructure_tools_are_not_registered_when_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"))
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "infra_detect_project_types",
                "infra_configuration_inventory",
            }

    asyncio.run(scenario())
