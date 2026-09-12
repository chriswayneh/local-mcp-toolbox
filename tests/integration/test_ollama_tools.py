from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IntegrationSettings,
    OllamaSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.ollama.handlers import OllamaGateway


def _settings(audit_path: Path) -> ToolboxSettings:
    return ToolboxSettings(
        profile=PermissionProfile.STANDARD,
        integrations=IntegrationSettings(ollama=True, external_network=True, external_ai=True),
        ollama=OllamaSettings(approved_models=["llama3.2:latest"]),
        audit=AuditSettings(path=audit_path),
    )


def test_ollama_tools_filter_models_and_redact_prompts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[tuple[str, str]] = []
    monkeypatch.setattr(
        OllamaGateway,
        "list_models",
        lambda _self: {
            "models": [
                {
                    "name": "llama3.2:latest",
                    "modified_at": "2026-09-12T00:00:00Z",
                    "size": 2_000,
                    "details": {"parameter_size": "3B", "quantization_level": "Q4_K_M"},
                },
                {"name": "unapproved:latest", "size": 4_000},
            ]
        },
    )

    def generate(_self: OllamaGateway, model: str, prompt: str) -> dict[str, object]:
        prompts.append((model, prompt))
        return {
            "model": model,
            "response": "Generated output token=ghp_123456789012345678901234567890",
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": 12,
            "eval_count": 8,
            "total_duration": 100,
        }

    monkeypatch.setattr(OllamaGateway, "generate", generate)
    server = create_server(build_runtime(_settings(tmp_path / "audit.jsonl")))

    async def scenario() -> None:
        async with Client(server) as client:
            models = await client.call_tool("ollama_list_models")
            generated = await client.call_tool(
                "ollama_generate",
                {
                    "model": "llama3.2:latest",
                    "prompt": "Inspect token=ghp_123456789012345678901234567890 safely",
                },
            )
            denied = await client.call_tool(
                "ollama_generate", {"model": "unapproved:latest", "prompt": "hello"}
            )

            assert [item["name"] for item in models.structured_content["data"]["models"]] == [
                "llama3.2:latest"
            ]
            assert generated.is_error is False
            assert "ghp_123456789012345678901234567890" not in str(generated.structured_content)
            assert generated.structured_content["metadata"]["redaction_count"] == 2
            assert denied.is_error is True
            assert denied.structured_content["category"] == "PERMISSION_DENIED"

    asyncio.run(scenario())
    assert prompts == [
        (
            "llama3.2:latest",
            "Inspect token=[REDACTED_GITHUB_TOKEN] safely",
        )
    ]


def test_ollama_tools_are_not_registered_without_opt_in(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit.jsonl")))
    )

    async def scenario() -> None:
        async with Client(server) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert not {name for name in names if name.startswith("ollama_")}

    asyncio.run(scenario())
