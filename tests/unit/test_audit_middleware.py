from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from mcp_toolbox.audit import JsonlAuditLogger
from mcp_toolbox.metrics import MetricsRegistry
from mcp_toolbox.redaction import Redactor
from mcp_toolbox.server.audit_middleware import AuditMiddleware


def _context(request_id: Any, tool_name: str) -> Any:
    return SimpleNamespace(
        request_id=request_id,
        method="tools/call",
        params={"name": tool_name, "arguments": {}},
        session=SimpleNamespace(client_params=None),
    )


def test_long_request_id_and_tool_name_do_not_mask_result_or_drop_audit(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    middleware = AuditMiddleware(JsonlAuditLogger(path, Redactor()), MetricsRegistry())
    long_id = "r" * 5_000
    long_name = "filesystem_" + "n" * 500
    expected = {"ok": True}

    async def call_next(_: Any) -> Any:
        return expected

    result = asyncio.run(middleware(_context(long_id, long_name), call_next))
    again = asyncio.run(middleware(_context(long_id, "filesystem_read"), call_next))

    assert result is expected
    assert again is expected
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 2
    assert events[0]["request_id"].startswith("sha256:")
    assert events[0]["request_id"] == events[1]["request_id"]
    assert long_id not in path.read_text(encoding="utf-8")
    assert len(events[0]["tool_name"]) <= 200
    assert events[0]["result_status"] == "success"


def test_short_request_id_is_recorded_unchanged(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "events.jsonl"
    middleware = AuditMiddleware(JsonlAuditLogger(path, Redactor()), MetricsRegistry())

    async def call_next(_: Any) -> Any:
        return {}

    asyncio.run(middleware(_context(42, "filesystem_read"), call_next))

    assert json.loads(path.read_text(encoding="utf-8"))["request_id"] == "42"
