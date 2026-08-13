"""Append-only JSONL audit events with mandatory redaction."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from mcp_toolbox.models import ErrorCategory
from mcp_toolbox.redaction import Redactor


class AuditEvent(BaseModel):
    """Sanitized metadata for one MCP tool invocation."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    request_id: str = Field(default_factory=lambda: str(uuid4()))
    client_identifier: str | None = Field(default=None, max_length=200)
    tool_name: str = Field(min_length=1, max_length=200)
    tool_module: str = Field(min_length=1, max_length=100)
    input_summary: dict[str, Any] = Field(default_factory=dict)
    result_status: str = Field(pattern="^(success|error|denied)$")
    duration_ms: int = Field(ge=0)
    records_returned: int = Field(default=0, ge=0)
    redaction_count: int = Field(default=0, ge=0)
    error_category: ErrorCategory | None = None
    permission_decision: str = Field(min_length=1, max_length=100)


class JsonlAuditLogger:
    """Serialize sanitized audit metadata as one JSON object per line."""

    def __init__(self, path: Path, redactor: Redactor) -> None:
        self._path = path
        self._redactor = redactor
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event: AuditEvent) -> AuditEvent:
        """Redact an event and append it atomically within this process."""

        safe_payload, new_redactions = self._redactor.redact_value(event.model_dump(mode="json"))
        safe_event = AuditEvent.model_validate(safe_payload)
        safe_event.redaction_count += new_redactions
        serialized = json.dumps(
            safe_event.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
        )

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._path.open("a", encoding="utf-8", newline="\n") as audit_file:
            audit_file.write(serialized)
            audit_file.write("\n")
        return safe_event


class AuditTimer:
    """Capture bounded request duration without recording raw request contents."""

    def __init__(self) -> None:
        self._started_at = perf_counter()

    def elapsed_ms(self) -> int:
        return int((perf_counter() - self._started_at) * 1_000)
