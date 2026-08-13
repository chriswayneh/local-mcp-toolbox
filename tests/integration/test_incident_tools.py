from __future__ import annotations

import asyncio
from pathlib import Path

from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IncidentSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server


def _server(tmp_path: Path):
    log_root = tmp_path / "incident-logs"
    log_root.mkdir()
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                integrations=IntegrationSettings(incident=True),
                incident=IncidentSettings(approved_roots=[log_root], max_file_bytes=1_000),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )
    return log_root, server


def test_incident_tools_extract_redacted_evidence_without_causal_claims(tmp_path: Path) -> None:
    log_root, server = _server(tmp_path)
    log_file = log_root / "api.log"
    log_file.write_text(
        "2026-08-13T10:00:00Z INFO service started\n"
        "2026-08-13T10:01:00Z ERROR database unavailable token=ghp_123456789012345678901234567890\n"
        "2026-08-13T10:02:00Z ERROR database unavailable "
        "token=ghp_123456789012345678901234567890\n",
        encoding="utf-8",
    )

    async def scenario() -> None:
        async with Client(server) as client:
            timeline = await client.call_tool(
                "incident_extract_timeline", {"path": str(log_file), "lines": 10}
            )
            evidence = await client.call_tool(
                "incident_summarize_evidence", {"path": str(log_file), "lines": 10, "limit": 10}
            )
            denied = await client.call_tool(
                "incident_extract_timeline", {"path": str(tmp_path / "outside.log"), "lines": 1}
            )

            assert timeline.is_error is False
            assert timeline.structured_content["data"]["events"][0]["source_timestamp"] == (
                "2026-08-13T10:00:00Z"
            )
            assert "ghp_123456789012345678901234567890" not in str(timeline.structured_content)
            assert "[REDACTED_GITHUB_TOKEN]" in str(timeline.structured_content)
            assert evidence.is_error is False
            assert evidence.structured_content["data"]["total_observation_groups"] == 1
            assert evidence.structured_content["data"]["likely_hypotheses"] == []
            assert evidence.structured_content["data"]["confidence"] == "observed_log_evidence_only"
            assert denied.is_error is True

    asyncio.run(scenario())


def test_incident_tools_are_not_registered_when_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"))
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "incident_extract_timeline",
                "incident_summarize_evidence",
            }

    asyncio.run(scenario())
