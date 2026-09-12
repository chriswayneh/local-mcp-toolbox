"""Local Ollama generation through a fixed loopback connection."""

from __future__ import annotations

import json
from http.client import HTTPConnection, HTTPException
from typing import Any, cast

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response

_LOCAL_AI = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=True,
)


class OllamaGateway:
    """Bounded loopback-only Ollama adapter with fixed API paths."""

    def __init__(self, runtime: ServerRuntime) -> None:
        settings = runtime.settings.ollama
        self._host = settings.host
        self._port = settings.port
        self._timeout = runtime.settings.limits.timeout_seconds
        self._output_limit = runtime.settings.limits.max_output_bytes

    def list_models(self) -> dict[str, Any]:
        return self._request("GET", "/api/tags")

    def generate(self, model: str, prompt: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/api/generate",
            {"model": model, "prompt": prompt, "stream": False},
        )

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8") if body else None
        headers = {"Accept": "application/json"}
        if encoded_body is not None:
            headers["Content-Type"] = "application/json"
        connection = HTTPConnection(self._host, self._port, timeout=self._timeout)
        try:
            connection.request(method, path, body=encoded_body, headers=headers)
            response = connection.getresponse()
            payload = response.read(self._output_limit + 1)
        except (OSError, TimeoutError, HTTPException) as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "The local Ollama service could not be reached.",
                remediation="Start Ollama on the configured loopback port or disable it.",
            ) from error
        finally:
            connection.close()
        if len(payload) > self._output_limit:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "The Ollama response exceeded the configured output limit.",
                remediation="Use a smaller prompt or model response.",
            )
        if response.status == 404:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The approved Ollama model or API resource was not found.",
                remediation="Check the approved model name and installed Ollama models.",
            )
        if response.status == 429:
            raise ToolboxError(
                ErrorCategory.RATE_LIMITED,
                "The local Ollama service is currently rate limited.",
                remediation="Retry after the current local model workload completes.",
            )
        if not 200 <= response.status < 300:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "The local Ollama service returned an unexpected HTTP error.",
                remediation="Check the Ollama service and selected model.",
            )
        try:
            value = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "The local Ollama service returned an unreadable response.",
                remediation="Check Ollama compatibility and retry.",
            ) from error
        if not isinstance(value, dict):
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "The local Ollama service returned an unexpected response shape.",
                remediation="Check Ollama compatibility and retry.",
            )
        return cast(dict[str, Any], value)


def register_ollama_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register local AI tools only after all three explicit opt-ins."""

    if not runtime.permissions.check_integration("ollama").allowed:
        return ()
    gateway = OllamaGateway(runtime)

    @server.tool(
        name="ollama_list_models",
        title="List approved local Ollama models",
        description="Return installed metadata only for explicitly approved local models.",
        annotations=_LOCAL_AI,
    )
    def ollama_list_models() -> dict[str, Any]:
        payload = gateway.list_models()
        raw_models = payload.get("models")
        models = (
            [
                _model_summary(item)
                for item in raw_models
                if isinstance(item, dict)
                and isinstance(item.get("name"), str)
                and item["name"] in runtime.settings.ollama.approved_models
            ]
            if isinstance(raw_models, list)
            else []
        )
        return bounded_response(
            runtime,
            f"Found {len(models)} approved local Ollama models.",
            {"models": models},
        )

    @server.tool(
        name="ollama_generate",
        title="Generate with an approved local Ollama model",
        description="Send a redacted bounded prompt to an approved loopback Ollama model.",
        annotations=_LOCAL_AI,
    )
    def ollama_generate(model: str, prompt: str) -> dict[str, Any]:
        approved_model = runtime.permissions.require_ollama_model(model)
        if not prompt or len(prompt) > runtime.settings.ollama.max_prompt_chars:
            raise ToolboxError(
                ErrorCategory.INVALID_INPUT,
                "The Ollama prompt is empty or exceeds the configured character limit.",
                remediation=(
                    f"Use 1 to {runtime.settings.ollama.max_prompt_chars} prompt characters."
                ),
            )
        redacted_prompt = runtime.redactor.redact(prompt)
        payload = gateway.generate(approved_model, redacted_prompt.text)
        return bounded_response(
            runtime,
            "Generated a response with an approved local Ollama model.",
            {
                "model": approved_model,
                "response": payload.get("response"),
                "done": payload.get("done"),
                "done_reason": payload.get("done_reason"),
                "prompt_eval_count": payload.get("prompt_eval_count"),
                "eval_count": payload.get("eval_count"),
                "total_duration": payload.get("total_duration"),
            },
            prior_redactions=redacted_prompt.redaction_count,
        )

    return ("ollama_list_models", "ollama_generate")


def _model_summary(payload: dict[str, Any]) -> dict[str, Any]:
    details = payload.get("details")
    return {
        "name": payload.get("name"),
        "modified_at": payload.get("modified_at"),
        "size": payload.get("size"),
        "parameter_size": details.get("parameter_size") if isinstance(details, dict) else None,
        "quantization_level": (
            details.get("quantization_level") if isinstance(details, dict) else None
        ),
    }
