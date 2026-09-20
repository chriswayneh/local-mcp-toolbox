"""Release acceptance through real transports, using only synthetic local data."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import socket
import subprocess
import sys
import sysconfig
import tempfile
import time
from http.client import HTTPConnection
from pathlib import Path

import yaml
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from mcp_toolbox.audit import AuditEvent

ROOT = Path(__file__).resolve().parents[2]


def test_documented_demo_over_stdio_from_outside_checkout(tmp_path: Path) -> None:
    """Absolute client paths work; the demo is redacted and denials are audited."""
    audit = tmp_path / "events.jsonl"
    config = tmp_path / "demo.yml"
    config.write_text(
        yaml.safe_dump(
            {
                "profile": "standard",
                "integrations": {"logs": True, "infrastructure": True, "incident": True},
                "logs": {"approved_roots": [str(ROOT / "demo/logs")]},
                "incident": {"approved_roots": [str(ROOT / "demo/logs")]},
                "infrastructure": {"approved_roots": [str(ROOT / "demo/project")]},
                "audit": {"path": str(audit)},
            }
        ),
        encoding="utf-8",
    )
    executable = Path(sysconfig.get_path("scripts")) / (
        "local-mcp-toolbox.exe" if os.name == "nt" else "local-mcp-toolbox"
    )

    async def scenario() -> None:
        parameters = StdioServerParameters(
            command=str(executable), args=["serve", "--config", str(config)], cwd=tmp_path
        )
        with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errlog:
            async with stdio_client(parameters, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    status = await client.call_tool("toolbox_server_status")
                    assert not status.is_error
                    for name, arguments in (
                        ("logs_tail_file", {"path": str(ROOT / "demo/logs/api.log"), "lines": 10}),
                        ("logs_error_summary", {"path": str(ROOT / "demo/logs/api.log")}),
                        ("incident_extract_timeline", {"path": str(ROOT / "demo/logs/api.log")}),
                        ("incident_summarize_evidence", {"path": str(ROOT / "demo/logs/api.log")}),
                        ("infra_detect_project_types", {"project": str(ROOT / "demo/project")}),
                        ("infra_configuration_inventory", {"project": str(ROOT / "demo/project")}),
                    ):
                        result = await client.call_tool(name, arguments)
                        assert not result.is_error, result
                        serialized = json.dumps(result.structured_content)
                        assert "sk-demo-1234567890abcdefghijklmnop" not in serialized
                        if name == "logs_tail_file":
                            assert "REDACTED" in serialized
                    denied = await client.call_tool("logs_tail_file", {"path": str(config)})
                    assert denied.is_error
                    assert denied.structured_content["category"] == "PERMISSION_DENIED"
                    disabled = await client.call_tool("docker_unhealthy_containers")
                    assert disabled.is_error
                    assert disabled.structured_content["category"] == "UNSUPPORTED_OPERATION"

    asyncio.run(scenario())
    raw = audit.read_text(encoding="utf-8")
    assert "sk-demo-" not in raw
    events = [AuditEvent.model_validate_json(line) for line in raw.splitlines()]
    assert any(e.tool_name == "logs_tail_file" and e.result_status == "denied" for e in events)
    assert any(e.tool_name == "logs_tail_file" and e.result_status == "success" for e in events)


def test_http_socket_authentication_and_request_boundaries(tmp_path: Path) -> None:
    """Exercise the installed HTTP server, not just the authentication middleware."""
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    token = secrets.token_urlsafe(48)
    audit = tmp_path / "http-events.jsonl"
    config = tmp_path / "http.yml"
    config.write_text(
        yaml.safe_dump(
            {
                "profile": "restricted",
                "http": {"enabled": True, "port": port, "max_request_body_bytes": 1024},
                "audit": {"path": str(audit)},
            }
        ),
        encoding="utf-8",
    )

    def request(body: bytes, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("POST", "/mcp", body=body, headers=headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    initialize = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "release-acceptance", "version": "1"},
            },
        }
    ).encode()
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as output:
        process = subprocess.Popen(
            [sys.executable, "-m", "mcp_toolbox", "serve-http", "--config", str(config)],
            cwd=tmp_path,
            env={**os.environ, "LOCAL_MCP_TOOLBOX_HTTP_TOKEN": token},
            stdout=output,
            stderr=output,
            shell=False,
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                try:
                    assert request(b"{}", {})[0] == 401
                    break
                except (ConnectionError, OSError):
                    assert process.poll() is None, "HTTP server exited before readiness"
                    assert time.monotonic() < deadline, "HTTP server readiness timed out"
                    time.sleep(0.1)
            assert request(initialize, {**headers, "Authorization": "Bearer wrong"})[0] == 401
            assert request(initialize, {**headers, "Host": "untrusted.invalid"})[0] == 421
            assert request(initialize, {**headers, "Origin": "https://untrusted.invalid"})[0] == 403
            assert request(b"x" * 1025, headers)[0] == 413
            status, response_headers, body = request(initialize, headers)
            assert status == 200, body
            session = next(v for k, v in response_headers.items() if k.lower() == "mcp-session-id")
            protocol = json.loads(body)["result"]["protocolVersion"]
            headers.update({"Mcp-Session-Id": session, "MCP-Protocol-Version": protocol})
            assert (
                request(b'{"jsonrpc":"2.0","method":"notifications/initialized"}', headers)[0]
                == 202
            )
            status, _, body = request(
                b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
                b'"params":{"name":"toolbox_server_status","arguments":{}}}',
                headers,
            )
            assert status == 200, body
            result = json.loads(body)["result"]
            assert not result.get("isError", False)
            assert result["structuredContent"]["data"]["transport"] == "streamable-http"
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        output.seek(0)
        assert token not in output.read()
    raw = audit.read_text(encoding="utf-8")
    assert token not in raw
    events = [AuditEvent.model_validate_json(line) for line in raw.splitlines()]
    assert any(
        e.tool_name == "toolbox_server_status" and e.result_status == "success" for e in events
    )
