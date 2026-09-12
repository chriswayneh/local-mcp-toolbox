"""Append-only JSONL audit events with mandatory redaction."""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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
    request_id: str = Field(default_factory=lambda: str(uuid4()), max_length=200)
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
    """Write sanitized JSONL to a bounded active file and immutable segments."""

    _MAX_EVENT_BYTES = 8_192
    _DEFAULT_MAX_SEGMENT_BYTES = 8 * 1_048_576
    _SEGMENT_TIMESTAMP_FORMAT = "%Y%m%dT%H%M%S%fZ"

    def __init__(
        self,
        path: Path,
        redactor: Redactor,
        retention_days: int = 30,
        *,
        segment_max_bytes: int = _DEFAULT_MAX_SEGMENT_BYTES,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if retention_days < 1:
            raise ValueError("retention_days must be at least one")
        if segment_max_bytes < self._MAX_EVENT_BYTES + 1:
            raise ValueError("segment_max_bytes must fit one maximum-size JSONL event")
        self._path = path
        self._redactor = redactor
        self._retention_days = retention_days
        self._segment_max_bytes = segment_max_bytes
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._active_started_at: datetime | None = None
        self._active_newest_at: datetime | None = None
        self._active_size = 0

    @property
    def path(self) -> Path:
        return self._path

    def record(self, event: AuditEvent) -> AuditEvent:
        """Redact and durably append one event within this process."""

        safe_payload, new_redactions = self._redactor.redact_value(event.model_dump(mode="json"))
        safe_event = AuditEvent.model_validate(safe_payload)
        safe_event.redaction_count += new_redactions
        serialized = self._serialize_bounded(safe_event)

        encoded = f"{serialized}\n".encode()
        with self._lock:
            now = self._now()
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._prepare_active(now, len(encoded))
            self._append_durable(encoded)
            self._active_size += len(encoded)
            self._active_newest_at = max(self._active_newest_at or now, now)
            self._prune_expired_segments(now)
        return safe_event

    def _serialize_bounded(self, event: AuditEvent) -> str:
        serialized = json.dumps(
            event.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
        )
        if len(serialized.encode()) <= self._MAX_EVENT_BYTES:
            return serialized

        event.input_summary = {"truncated": True, "reason": "audit_event_size_limit"}
        serialized = json.dumps(
            event.model_dump(mode="json"), separators=(",", ":"), sort_keys=True
        )
        if len(serialized.encode()) > self._MAX_EVENT_BYTES:
            raise ValueError("Audit event cannot be represented within the event size limit")
        return serialized

    def _prepare_active(self, now: datetime, additional_bytes: int) -> None:
        if self._active_started_at is None:
            self._load_or_create_active(now)
        if self._active_started_at is None:
            raise RuntimeError("Active audit segment was not initialized")
        should_rotate = self._active_size > 0 and (
            self._active_started_at.date() != now.date()
            or self._active_size + additional_bytes > self._segment_max_bytes
        )
        if should_rotate:
            self._rotate_active(now)

    def _load_or_create_active(self, now: datetime) -> None:
        if not self._path.exists():
            self._create_active()
            self._active_started_at = now
            self._active_newest_at = now
            self._active_size = 0
            return

        size = self._path.stat().st_size
        if size > self._segment_max_bytes:
            raise ValueError("Existing active audit segment exceeds the configured size bound")
        first, newest = self._validate_jsonl(self._path)
        self._active_started_at = first or now
        self._active_newest_at = newest or now
        self._active_size = size

    def _create_active(self) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self._path, flags, 0o600)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_parent()

    def _append_durable(self, payload: bytes) -> None:
        flags = os.O_WRONLY | os.O_APPEND
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self._path, flags)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("Audit append made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _rotate_active(self, now: datetime) -> None:
        newest = self._active_newest_at or now
        timestamp = newest.astimezone(UTC).strftime(self._SEGMENT_TIMESTAMP_FORMAT)
        segment = self._path.with_name(
            f"{self._path.stem}.{timestamp}.{uuid4().hex}{self._path.suffix}"
        )
        os.rename(self._path, segment)
        self._fsync_parent()
        self._create_active()
        self._active_started_at = now
        self._active_newest_at = now
        self._active_size = 0

    def _prune_expired_segments(self, now: datetime) -> None:
        cutoff = now - timedelta(days=self._retention_days)
        deleted = False
        for segment in self._segments():
            newest = self._segment_timestamp(segment)
            if newest is not None and newest < cutoff:
                segment.unlink()
                deleted = True
        if deleted:
            self._fsync_parent()

    def _segments(self) -> list[Path]:
        pattern = f"{self._path.stem}.*{self._path.suffix}"
        return sorted(path for path in self._path.parent.glob(pattern) if path != self._path)

    def _segment_timestamp(self, segment: Path) -> datetime | None:
        pattern = re.compile(
            rf"^{re.escape(self._path.stem)}\."
            rf"(?P<timestamp>\d{{8}}T\d{{12}}Z)\."
            rf"[0-9a-f]{{32}}{re.escape(self._path.suffix)}$"
        )
        match = pattern.fullmatch(segment.name)
        if match is None:
            return None
        return datetime.strptime(match.group("timestamp"), self._SEGMENT_TIMESTAMP_FORMAT).replace(
            tzinfo=UTC
        )

    def _validate_jsonl(self, path: Path) -> tuple[datetime | None, datetime | None]:
        first: datetime | None = None
        newest: datetime | None = None
        with path.open("rb") as audit_file:
            for line in audit_file:
                if not line.endswith(b"\n") or len(line) > self._MAX_EVENT_BYTES + 1:
                    raise ValueError("Active audit file is not bounded strict JSONL")
                try:
                    value = json.loads(line)
                    timestamp_value = value["timestamp"]
                    if not isinstance(value, dict) or not isinstance(timestamp_value, str):
                        raise ValueError
                    timestamp = datetime.fromisoformat(timestamp_value)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                    raise ValueError("Active audit file is not bounded strict JSONL") from error
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                timestamp = timestamp.astimezone(UTC)
                first = first or timestamp
                newest = max(newest or timestamp, timestamp)
        return first, newest

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("Audit clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _fsync_parent(self) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(self._path.parent, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


class AuditTimer:
    """Capture bounded request duration without recording raw request contents."""

    def __init__(self) -> None:
        self._started_at = perf_counter()

    def elapsed_ms(self) -> int:
        return int((perf_counter() - self._started_at) * 1_000)
