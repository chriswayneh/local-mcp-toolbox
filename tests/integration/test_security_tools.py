from __future__ import annotations

import asyncio
import json
from pathlib import Path

from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IntegrationSettings,
    PermissionProfile,
    SecuritySettings,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.security.handlers import ScannerResult, ScannerRunner


def _server(tmp_path: Path):
    root = tmp_path / "approved"
    root.mkdir()
    server = create_server(
        build_runtime(
            ToolboxSettings(
                profile=PermissionProfile.STANDARD,
                integrations=IntegrationSettings(security_scanners=True),
                security=SecuritySettings(approved_roots=[root]),
                audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
            )
        )
    )
    return root, server


def test_security_scan_returns_normalized_redacted_findings(tmp_path: Path, monkeypatch) -> None:
    root, server = _server(tmp_path)
    report = {
        "results": [
            {
                "test_id": "B105",
                "test_name": "hardcoded_password_string",
                "issue_severity": "LOW",
                "issue_confidence": "MEDIUM",
                "filename": str(root / "src" / "settings.py"),
                "line_number": 12,
                "issue_text": "Possible password=ghp_123456789012345678901234567890",
                "more_info": "https://bandit.readthedocs.io/en/latest/plugins/b105_hardcoded_password_string.html",
            }
        ]
    }
    monkeypatch.setattr(
        ScannerRunner,
        "run_bandit",
        lambda self, repository: ScannerResult(stdout=json.dumps(report)),
    )

    async def scenario() -> None:
        async with Client(server) as client:
            inventory = await client.call_tool("security_scanner_inventory")
            result = await client.call_tool(
                "security_scan_repository", {"repository": str(root), "limit": 10}
            )
            unsupported = await client.call_tool(
                "security_scan_repository", {"repository": str(root), "scanner": "trivy"}
            )
            denied = await client.call_tool(
                "security_scan_repository", {"repository": str(tmp_path), "limit": 10}
            )

            assert inventory.is_error is False
            assert result.is_error is False
            finding = result.structured_content["data"]["findings"][0]
            assert finding["file"] == "src/settings.py"
            assert finding["finding_id"] == "B105"
            assert "ghp_123456789012345678901234567890" not in str(result.structured_content)
            assert "[REDACTED_PASSWORD]" in str(result.structured_content)
            assert unsupported.is_error is True
            assert denied.is_error is True

    asyncio.run(scenario())


def test_security_tools_are_not_registered_when_disabled(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(
            ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"))
        )
    )

    async def scenario() -> None:
        async with Client(server) as client:
            tools = await client.list_tools()
            assert not {tool.name for tool in tools.tools} & {
                "security_scanner_inventory",
                "security_scan_repository",
            }

    asyncio.run(scenario())


def test_bandit_adapter_runs_a_fixed_local_report(tmp_path: Path) -> None:
    root, server = _server(tmp_path)
    (root / "safe.py").write_text("value = 1\n", encoding="utf-8")

    async def scenario() -> None:
        async with Client(server) as client:
            result = await client.call_tool(
                "security_scan_repository", {"repository": str(root), "limit": 10}
            )

            assert result.is_error is False
            assert result.structured_content["data"]["scanner"] == "bandit"
            assert result.structured_content["data"]["total_findings"] == 0

    asyncio.run(scenario())
