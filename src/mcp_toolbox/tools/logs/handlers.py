"""Deterministic read-only log inspection within dedicated approved roots."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
_SEVERITY_PATTERN = re.compile(r"\b(fatal|critical|error|warning|warn|info|debug)\b", re.IGNORECASE)
_WHITESPACE = re.compile(r"\s+")


def register_log_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register local log tools only after explicit integration enablement."""

    if not runtime.permissions.check_integration("logs").allowed:
        return ()

    @server.tool(
        name="logs_tail_file",
        title="Tail approved log file",
        description="Return a bounded, redacted tail of one approved local log file.",
        annotations=_READ_ONLY,
    )
    def logs_tail_file(path: str, lines: int = 100) -> dict[str, Any]:
        """Read only the requested trailing lines from a small, approved text log."""

        line_limit = require_bounded_limit(runtime, lines)
        log_file = _require_log_file(runtime, path)
        redacted_content = runtime.redactor.redact(_read_log_file(runtime, log_file))
        content = redacted_content.text
        tail = content.splitlines()[-line_limit:]
        return bounded_response(
            runtime,
            f"Read {len(tail)} trailing lines from an approved log file.",
            {"file_name": log_file.name, "lines": tail, "total_lines": len(content.splitlines())},
            prior_redactions=redacted_content.redaction_count,
        )

    @server.tool(
        name="logs_search",
        title="Search approved log file",
        description=(
            "Search an approved log file using a bounded literal query, not regular expressions."
        ),
        annotations=_READ_ONLY,
    )
    def logs_search(
        path: str, query: str, limit: int = 50, case_sensitive: bool = False
    ) -> dict[str, Any]:
        """Find bounded literal matches, avoiding user-controlled regular-expression execution."""

        result_limit = require_bounded_limit(runtime, limit)
        needle = _validate_query(query)
        log_file = _require_log_file(runtime, path)
        redacted_content = runtime.redactor.redact(_read_log_file(runtime, log_file))
        source_lines = redacted_content.text.splitlines()
        comparable_needle = needle if case_sensitive else needle.casefold()
        matches = [
            {"line_number": line_number, "text": line}
            for line_number, line in enumerate(source_lines, start=1)
            if comparable_needle in (line if case_sensitive else line.casefold())
        ]
        page = matches[:result_limit]
        return bounded_response(
            runtime,
            f"Found {len(matches)} literal matches in an approved log file.",
            {
                "file_name": log_file.name,
                "matches": page,
                "total_matches": len(matches),
                "truncated_matches": len(matches) > result_limit,
            },
            prior_redactions=redacted_content.redaction_count,
        )

    @server.tool(
        name="logs_error_summary",
        title="Summarize approved log errors",
        description=(
            "Deterministically group recent severity-bearing log lines without "
            "inferring root cause."
        ),
        annotations=_READ_ONLY,
    )
    def logs_error_summary(path: str, lines: int = 500, limit: int = 20) -> dict[str, Any]:
        """Return severity counts and redacted evidence groups from a bounded trailing window."""

        line_limit = require_bounded_limit(runtime, lines)
        group_limit = require_bounded_limit(runtime, limit)
        log_file = _require_log_file(runtime, path)
        redacted_content = runtime.redactor.redact(_read_log_file(runtime, log_file))
        source_lines = redacted_content.text.splitlines()[-line_limit:]
        grouped, severity_counts = _group_severity_lines(runtime, source_lines)
        groups = sorted(
            grouped.values(), key=lambda group: (-group["occurrences"], group["fingerprint"])
        )
        return bounded_response(
            runtime,
            "Summarized observed severity-bearing log lines; this does not establish root cause.",
            {
                "file_name": log_file.name,
                "analyzed_lines": len(source_lines),
                "severity_counts": dict(sorted(severity_counts.items())),
                "error_groups": groups[:group_limit],
                "total_error_groups": len(groups),
                "truncated_groups": len(groups) > group_limit,
                "confidence": "observed_log_evidence_only",
            },
            prior_redactions=redacted_content.redaction_count,
        )

    return ("logs_tail_file", "logs_search", "logs_error_summary")


def _require_log_file(runtime: ServerRuntime, requested_path: str) -> Path:
    log_file = runtime.permissions.logs.require_file(Path(requested_path))
    if not log_file.is_file():
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved log file was not found.",
            remediation="Pass an existing approved log file path.",
        )
    return log_file


def _read_log_file(runtime: ServerRuntime, log_file: Path) -> str:
    size = log_file.stat().st_size
    if size > runtime.settings.logs.max_file_bytes:
        raise ToolboxError(
            ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
            "The log file exceeds the configured maximum readable size.",
            remediation="Configure a smaller log file or collect a narrower log slice.",
        )
    try:
        return log_file.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved log file could not be read.",
            remediation="Check that the file still exists and is readable.",
        ) from error


def _validate_query(query: str) -> str:
    candidate = query.strip()
    if not candidate or len(candidate) > 200 or "\n" in candidate or "\r" in candidate:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            "Log search requires a non-empty single-line literal query of at most 200 characters.",
            remediation=(
                "Use a concise plain-text search term; regular expressions are not supported."
            ),
        )
    return candidate


def _group_severity_lines(
    runtime: ServerRuntime, source_lines: list[str]
) -> tuple[dict[str, dict[str, Any]], Counter[str]]:
    groups: dict[str, dict[str, Any]] = {}
    severity_counts: Counter[str] = Counter()
    for line_number, line in enumerate(source_lines, start=1):
        severity = _severity(line)
        if severity is None:
            continue
        severity_counts[severity] += 1
        if severity not in {"CRITICAL", "ERROR", "FATAL"}:
            continue
        safe_line = runtime.redactor.redact(line).text
        fingerprint = _fingerprint(safe_line)
        group = groups.setdefault(
            fingerprint,
            {
                "fingerprint": fingerprint,
                "severity": severity,
                "occurrences": 0,
                "first_line_number": line_number,
                "sample": safe_line,
            },
        )
        group["occurrences"] += 1
    return groups, severity_counts


def _severity(line: str) -> str | None:
    match = _SEVERITY_PATTERN.search(line)
    return match.group(1).upper() if match else None


def _fingerprint(line: str) -> str:
    normalized = _WHITESPACE.sub(" ", line).strip()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"
