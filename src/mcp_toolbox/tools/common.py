"""Shared result controls for read-only tool modules."""

from __future__ import annotations

from typing import Any

from mcp_toolbox.models import ErrorCategory, ResponseMetadata, ToolboxError, ToolResponse
from mcp_toolbox.server.runtime import ServerRuntime


def bounded_response(
    runtime: ServerRuntime,
    summary: str,
    data: dict[str, Any],
    *,
    untrusted_content: bool = True,
    prior_redactions: int = 0,
) -> dict[str, Any]:
    """Redact and bound structured tool data before it reaches the MCP transport."""

    redacted_data, redaction_count = runtime.redactor.redact_value(data)
    response = ToolResponse(
        summary=summary,
        data=redacted_data,
        metadata=ResponseMetadata(
            redaction_count=prior_redactions + redaction_count,
            untrusted_content=untrusted_content,
        ),
    )
    payload = response.model_dump_json()
    encoded = payload.encode("utf-8")
    if len(encoded) > runtime.settings.limits.max_output_bytes:
        raise ToolboxError(
            ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
            "The requested result exceeds the configured output limit.",
            remediation="Use a narrower path, lower limit, or more specific query.",
        )
    return response.model_dump(mode="json")


def require_bounded_limit(runtime: ServerRuntime, limit: int) -> int:
    """Validate an operator-configured result limit at a tool boundary."""

    if not 1 <= limit <= runtime.settings.limits.max_records:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            "The requested result limit is outside the configured bounds.",
            remediation=f"Use a limit between 1 and {runtime.settings.limits.max_records}.",
        )
    return limit
