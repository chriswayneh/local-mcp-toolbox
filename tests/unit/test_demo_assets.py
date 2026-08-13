from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_client_configuration_examples_parse() -> None:
    codex_config = REPOSITORY_ROOT / "examples" / "codex" / "config.toml"
    claude_desktop_config = (
        REPOSITORY_ROOT / "examples" / "claude-desktop" / "claude_desktop_config.json"
    )
    claude_code_config = REPOSITORY_ROOT / "examples" / "claude-code" / ".mcp.json"
    vscode_config = REPOSITORY_ROOT / "examples" / "vscode" / "mcp.json"

    codex = tomllib.loads(codex_config.read_text(encoding="utf-8"))
    claude_desktop = json.loads(claude_desktop_config.read_text(encoding="utf-8"))
    claude_code = json.loads(claude_code_config.read_text(encoding="utf-8"))
    vscode = json.loads(vscode_config.read_text(encoding="utf-8"))

    assert codex["mcp_servers"]["local-mcp-toolbox"]["command"] == "<TOOLBOX_EXE>"
    assert claude_desktop["mcpServers"]["local-mcp-toolbox"]["args"] == [
        "serve",
        "--config",
        "<CONFIG_FILE>",
    ]
    assert "${LOCAL_MCP_TOOLBOX_EXE}" == claude_code["mcpServers"]["local-mcp-toolbox"]["command"]
    assert vscode["servers"]["local-mcp-toolbox"]["type"] == "stdio"


def test_demo_compose_defines_isolated_healthy_and_unhealthy_services() -> None:
    compose_path = REPOSITORY_ROOT / "demo" / "compose.yaml"
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))

    healthy = compose["services"]["healthy"]
    unhealthy = compose["services"]["unhealthy"]

    assert healthy["read_only"] is True
    assert unhealthy["read_only"] is True
    assert healthy["healthcheck"]["test"] == ["CMD", "true"]
    assert unhealthy["healthcheck"]["test"][-1].endswith("exit 1")
    assert "ports" not in healthy
    assert "ports" not in unhealthy
    assert "volumes" not in healthy
    assert "volumes" not in unhealthy
