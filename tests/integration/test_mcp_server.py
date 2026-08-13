from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

import pytest
from mcp import Client, ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_toolbox.audit import AuditEvent
from mcp_toolbox.config.settings import AuditSettings, FilesystemSettings, ToolboxSettings
from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server import build_runtime, create_server


def _settings(audit_path: Path, root: Path | None = None) -> ToolboxSettings:
    filesystem = (
        FilesystemSettings(
            approved_roots=[root],
            allowed_extensions=[".md", ".txt", ".json"],
            blocked_patterns=[".env", "*.pem", "*.key"],
        )
        if root
        else FilesystemSettings()
    )
    return ToolboxSettings(filesystem=filesystem, audit=AuditSettings(path=audit_path))


def test_in_memory_mcp_server_lists_safe_capabilities_and_audits_requests(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "events.jsonl"
    root = tmp_path / "approved"
    root.mkdir()
    runtime = build_runtime(_settings(audit_path, root))
    server = create_server(runtime)

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            resources = await client.list_resources()
            prompts = await client.list_prompts()
            status_resource = await client.read_resource("toolbox://server/status")
            configuration_resource = await client.read_resource("toolbox://configuration/summary")
            prompt = await client.get_prompt("analyze_repository")
            tool_result = await client.call_tool("toolbox_server_status")

            assert {tool.name for tool in tools.tools} == {
                "toolbox_server_status",
                "system_info",
                "disk_usage",
                "installed_developer_tools",
                "filesystem_list_directory",
                "filesystem_file_metadata",
                "filesystem_read_text_file",
            }
            assert {resource.uri for resource in resources.resources} == {
                "toolbox://server/status",
                "toolbox://configuration/summary",
                "toolbox://security/policy",
                "toolbox://modules",
            }
            assert {item.name for item in prompts.prompts} == {
                "analyze_repository",
                "summarize_recent_errors",
                "troubleshoot_container",
                "perform_security_review",
            }
            assert "Local MCP Toolbox" in status_resource.contents[0].text
            assert str(root) not in configuration_resource.contents[0].text
            assert "untrusted" in prompt.messages[0].content.text
            assert tool_result.is_error is False
            assert tool_result.structured_content["data"]["transport"] == "stdio"

    asyncio.run(scenario())

    events = [
        AuditEvent.model_validate(json.loads(line)) for line in audit_path.read_text().splitlines()
    ]
    event_names = {event.tool_name for event in events}
    assert {
        "tools_list",
        "resources_list",
        "prompts_list",
        "resources_read",
        "prompts_get",
    } <= event_names
    status_event = next(event for event in events if event.tool_name == "toolbox_server_status")
    assert status_event.tool_module == "server"
    assert status_event.result_status == "success"


def test_startup_rejects_missing_approved_root(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "audit.jsonl", tmp_path / "does-not-exist")

    with pytest.raises(ToolboxError) as raised:
        build_runtime(settings)

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_stdio_transport_serves_the_registered_status_tool(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit" / "events.jsonl"
    config_path = tmp_path / "restricted.yml"
    config_path.write_text(
        "\n".join(
            [
                "profile: restricted",
                "audit:",
                f"  path: {audit_path.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "mcp_toolbox", "serve", "--config", str(config_path)],
            cwd=Path.cwd(),
        )
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errlog:
            async with stdio_client(parameters, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    assert "toolbox_server_status" in {tool.name for tool in tools.tools}

    asyncio.run(scenario())
    assert audit_path.exists()
