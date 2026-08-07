from __future__ import annotations

import json
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
