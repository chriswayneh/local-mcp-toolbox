from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

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


def test_audit_event_size_is_bounded_and_expired_events_are_pruned(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    expired = AuditEvent(
        timestamp=datetime.now(UTC) - timedelta(days=2),
        tool_name="expired_tool",
        tool_module="test",
        result_status="success",
        duration_ms=1,
        permission_decision="allowed",
    )
    path.parent.mkdir(parents=True)
    path.write_text(f"{expired.model_dump_json()}\n", encoding="utf-8")
    logger = JsonlAuditLogger(path, Redactor(), retention_days=1)
    event = AuditEvent(
        tool_name="oversized_argument_tool",
        tool_module="test",
        input_summary={"payload": "x" * 100_000},
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
