from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from mcp_toolbox.audit import AuditEvent, JsonlAuditLogger
from mcp_toolbox.redaction import Redactor


def test_audit_log_redacts_summaries_before_writing(tmp_path: Path) -> None:
    token = "ghp_123456789012345678901234567890"
    path = tmp_path / "audit" / "events.jsonl"
    logger = JsonlAuditLogger(path, Redactor())
    event = AuditEvent(
        tool_name="filesystem_read_text_file",
        tool_module="filesystem",
        input_summary={"authorization": f"Bearer {token}"},
        result_status="success",
        duration_ms=12,
        permission_decision="allowed",
    )

    recorded = logger.record(event)
    payload = path.read_text(encoding="utf-8")
    stored = json.loads(payload)

    assert token not in payload
    assert recorded.redaction_count == 1
    assert stored["input_summary"]["authorization"] == "Bearer [REDACTED_GITHUB_TOKEN]"


def test_audit_event_size_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    logger = JsonlAuditLogger(path, Redactor(), retention_days=1)
    event = AuditEvent(
        tool_name="oversized_argument_tool",
        tool_module="test",
        input_summary={"payload": "x" * 10_000},
        result_status="success",
        duration_ms=1,
        permission_decision="allowed",
    )

    logger.record(event)

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert len(lines[0].encode("utf-8")) <= 8_192
    assert json.loads(lines[0])["input_summary"] == {
        "truncated": True,
        "reason": "audit_event_size_limit",
    }


def test_rotation_keeps_closed_segment_immutable(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    first_day = datetime(2026, 9, 10, 12, tzinfo=UTC)
    current = [first_day]
    logger = JsonlAuditLogger(path, Redactor(), clock=lambda: current[0])

    logger.record(_event("first"))
    current[0] += timedelta(days=1)
    logger.record(_event("second"))

    segments = list(path.parent.glob("events.*.jsonl"))
    assert len(segments) == 1
    closed_content = segments[0].read_bytes()
    assert json.loads(closed_content)["tool_name"] == "first"

    logger.record(_event("third"))
    assert segments[0].read_bytes() == closed_content
    assert [json.loads(line)["tool_name"] for line in path.read_text().splitlines()] == [
        "second",
        "third",
    ]


def test_retention_deletes_only_expired_closed_segments(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    current = [datetime(2026, 9, 10, 12, tzinfo=UTC)]
    logger = JsonlAuditLogger(path, Redactor(), retention_days=1, clock=lambda: current[0])

    logger.record(_event("old"))
    current[0] += timedelta(days=2)
    logger.record(_event("current"))

    assert list(path.parent.glob("events.*.jsonl")) == []
    assert json.loads(path.read_text())["tool_name"] == "current"


def test_malformed_active_jsonl_fails_closed_without_rewrite(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    path.parent.mkdir(parents=True)
    original = b'{"incomplete":true}'
    path.write_bytes(original)
    logger = JsonlAuditLogger(path, Redactor())

    with pytest.raises(ValueError, match="strict JSONL"):
        logger.record(_event("must_not_append"))

    assert path.read_bytes() == original


def test_concurrent_clients_produce_complete_jsonl_records(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    logger = JsonlAuditLogger(path, Redactor())

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(lambda index: logger.record(_event(f"tool_{index}")), range(16)))

    lines = path.read_bytes().splitlines(keepends=True)
    assert len(lines) == 16
    assert all(line.endswith(b"\n") for line in lines)
    assert {json.loads(line)["tool_name"] for line in lines} == {
        f"tool_{index}" for index in range(16)
    }


def _event(tool_name: str) -> AuditEvent:
    return AuditEvent(
        tool_name=tool_name,
        tool_module="test",
        result_status="success",
        duration_ms=1,
        permission_decision="allowed",
    )
