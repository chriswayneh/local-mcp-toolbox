"""Shared, transport-neutral response and error contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ErrorCategory(StrEnum):
    """Safe error categories exposed to MCP clients."""

    INVALID_INPUT = "INVALID_INPUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    INTEGRATION_UNAVAILABLE = "INTEGRATION_UNAVAILABLE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ResponseMetadata(BaseModel):
    """Metadata included with successful bounded tool responses."""

    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    redaction_count: int = Field(default=0, ge=0)
    truncated: bool = False
    untrusted_content: bool = True


class ToolResponse(BaseModel):
    """A consistent envelope for structured read-only tool data."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=1_000)
    data: dict[str, Any] = Field(default_factory=dict)
    metadata: ResponseMetadata = Field(default_factory=ResponseMetadata)


class ErrorResponse(BaseModel):
    """A client-safe error envelope that never contains tracebacks or secrets."""

    model_config = ConfigDict(extra="forbid")

    category: ErrorCategory
    message: str = Field(min_length=1, max_length=1_000)
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    remediation: str | None = Field(default=None, max_length=1_000)


class ToolboxError(Exception):
    """Expected failure with a client-safe, structured representation."""

    def __init__(
        self,
        category: ErrorCategory,
        message: str,
        *,
        request_id: str | None = None,
        remediation: str | None = None,
    ) -> None:
        super().__init__(message)
        self.category = category
        self.message = message
        self.request_id = request_id or str(uuid4())
        self.remediation = remediation

    def to_response(self) -> ErrorResponse:
        return ErrorResponse(
            category=self.category,
            message=self.message,
            request_id=self.request_id,
            remediation=self.remediation,
        )
