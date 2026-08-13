from __future__ import annotations

import asyncio
from pathlib import Path

from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IncidentSettings,
    IntegrationSettings,
    LogSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server


def _server(tmp_path: Path):
    log_root = tmp_path / "logs"
    log_root.mkdir()
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                integrations=IntegrationSettings(logs=True),
                logs=LogSettings(approved_roots=[log_root], max_file_bytes=1_000),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )
    return log_root, server


def test_log_tools_bound_search_and_redact_untrusted_content(tmp_path: Path) -> None:
    log_root, server = _server(tmp_path)
    log_file = log_root / "application.log"
    log_file.write_text(
        "INFO service started\n"
        "ERROR database unavailable token=ghp_123456789012345678901234567890\n"
        "ERROR database unavailable token=ghp_123456789012345678901234567890\n"
        "WARNING retrying connection\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tail = await client.call_tool("logs_tail_file", {"path": str(log_file), "lines": 2})
            search = await client.call_tool(
                "logs_search", {"path": str(log_file), "query": "database", "limit": 10}
            )
            summary = await client.call_tool(
                "logs_error_summary", {"path": str(log_file), "lines": 10, "limit": 10}
            )
            outside = await client.call_tool(
                "logs_tail_file", {"path": str(tmp_path / "outside.log"), "lines": 1}
            )
            regex_like = await client.call_tool(
                "logs_search", {"path": str(log_file), "query": "(database|retry)", "limit": 10}
            )

            assert tail.is_error is False
            assert len(tail.structured_content["data"]["lines"]) == 2
            assert search.is_error is False
            assert search.structured_content["data"]["total_matches"] == 2
            assert "ghp_123456789012345678901234567890" not in str(search.structured_content)
            assert "[REDACTED_GITHUB_TOKEN]" in str(search.structured_content)
            assert summary.is_error is False
            assert summary.structured_content["data"]["severity_counts"]["ERROR"] == 2
            assert summary.structured_content["data"]["total_error_groups"] == 1
            assert outside.is_error is True
            assert regex_like.is_error is False
            assert regex_like.structured_content["data"]["total_matches"] == 0

    asyncio.run(scenario())


def test_log_tools_are_not_registered_when_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"))
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "logs_tail_file",
                "logs_search",
                "logs_error_summary",
            }

    asyncio.run(scenario())


def test_log_and_incident_tools_redact_multiline_private_keys_in_line_outputs(
    tmp_path: Path,
) -> None:
    log_root = tmp_path / "logs"
    log_root.mkdir()
    log_file = log_root / "incident.log"
    key_material = "private-key-material-that-must-not-reach-the-client"
    log_file.write_text(
        "INFO before key\n"
        "ERROR -----BEGIN PRIVATE KEY-----\n"
        f"{key_material}\n"
        "-----END PRIVATE KEY-----\n"
        "ERROR key was present\n",
        encoding="utf-8",
    )
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                integrations=IntegrationSettings(logs=True, incident=True),
                logs=LogSettings(approved_roots=[log_root], max_file_bytes=1_000),
                incident=IncidentSettings(approved_roots=[log_root], max_file_bytes=1_000),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            results = [
                await client.call_tool("logs_tail_file", {"path": str(log_file), "lines": 10}),
                await client.call_tool(
                    "logs_search", {"path": str(log_file), "query": "PRIVATE", "limit": 10}
                ),
                await client.call_tool(
                    "logs_error_summary", {"path": str(log_file), "lines": 10, "limit": 10}
                ),
                await client.call_tool(
                    "incident_extract_timeline", {"path": str(log_file), "lines": 10}
                ),
                await client.call_tool(
                    "incident_summarize_evidence",
                    {"path": str(log_file), "lines": 10, "limit": 10},
                ),
            ]

            for result in results:
                assert result.is_error is False
                assert key_material not in str(result.structured_content)
                assert "[REDACTED_PRIVATE_KEY]" in str(result.structured_content)
            assert results[0].structured_content["metadata"]["redaction_count"] >= 1
            assert results[3].structured_content["metadata"]["redaction_count"] >= 1

    asyncio.run(scenario())
