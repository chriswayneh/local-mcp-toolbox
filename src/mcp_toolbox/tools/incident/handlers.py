"""Bounded incident evidence collection from approved local log files."""

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
_TIMESTAMP_PATTERN = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}"
    r"(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))"
)
_WHITESPACE = re.compile(r"\s+")
_TIMESTAMP_REPLACEMENT = re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?Z?\b")


def register_incident_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register incident evidence tools only after explicit integration enablement."""

    if not runtime.permissions.check_integration("incident").allowed:
        return ()

    @server.tool(
        name="incident_extract_timeline",
        title="Extract incident timeline",
        description=(
            "Extract a bounded timestamp and severity timeline from one approved incident log."
        ),
        annotations=_READ_ONLY,
    )
    def incident_extract_timeline(path: str, lines: int = 200) -> dict[str, Any]:
        """Return observed trailing log events; source timestamps are not inferred or reordered."""

        line_limit = require_bounded_limit(runtime, lines)
        log_file = _require_incident_log(runtime, path)
        source_lines, start_line = _trailing_lines(runtime, log_file, line_limit)
        events = [
            {
                "line_number": line_number,
                "source_timestamp": _timestamp(line),
                "severity": _severity(line),
                "text": line,
            }
            for line_number, line in enumerate(source_lines, start=start_line)
        ]
        return bounded_response(
            runtime,
            "Extracted observed incident timeline events; log content is untrusted evidence.",
            {"file_name": log_file.name, "events": events, "total_events": len(events)},
        )

    @server.tool(
        name="incident_summarize_evidence",
        title="Summarize incident evidence",
        description="Group observed high-severity log evidence without asserting a root cause.",
        annotations=_READ_ONLY,
    )
    def incident_summarize_evidence(path: str, lines: int = 500, limit: int = 20) -> dict[str, Any]:
        """Return deterministic observations, unknowns, and safe next checks from one log window."""

        line_limit = require_bounded_limit(runtime, lines)
        group_limit = require_bounded_limit(runtime, limit)
        log_file = _require_incident_log(runtime, path)
        source_lines, start_line = _trailing_lines(runtime, log_file, line_limit)
        groups, severity_counts = _evidence_groups(runtime, source_lines, start_line)
        ordered_groups = sorted(
            groups.values(), key=lambda group: (-group["occurrences"], group["first_line_number"])
        )
        high_severity_count = sum(group["occurrences"] for group in ordered_groups)
        return bounded_response(
            runtime,
            "Summarized observed incident evidence; no root-cause conclusion was generated.",
            {
                "file_name": log_file.name,
                "analyzed_lines": len(source_lines),
                "severity_counts": dict(sorted(severity_counts.items())),
                "observations": ordered_groups[:group_limit],
                "total_observation_groups": len(ordered_groups),
                "truncated_observations": len(ordered_groups) > group_limit,
                "likely_hypotheses": [],
                "unknowns": [
                    "Log evidence alone does not establish causality or identify affected services."
                ],
                "recommended_next_checks": _recommended_next_checks(high_severity_count),
                "confidence": "observed_log_evidence_only",
            },
        )

    return ("incident_extract_timeline", "incident_summarize_evidence")


def _require_incident_log(runtime: ServerRuntime, requested_path: str) -> Path:
    runtime.permissions.require_integration("incident")
    log_file = runtime.permissions.incident.require_file(Path(requested_path))
    if not log_file.is_file():
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved incident log file was not found.",
            remediation="Pass an existing approved incident log file path.",
        )
    return log_file


def _trailing_lines(
    runtime: ServerRuntime, log_file: Path, line_limit: int
) -> tuple[list[str], int]:
    size = log_file.stat().st_size
    if size > runtime.settings.incident.max_file_bytes:
        raise ToolboxError(
            ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
            "The incident log exceeds the configured maximum readable size.",
            remediation="Configure a smaller log file or collect a narrower log slice.",
        )
    try:
        all_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved incident log could not be read.",
            remediation="Check that the file still exists and is readable.",
        ) from error
    source_lines = all_lines[-line_limit:]
    return source_lines, len(all_lines) - len(source_lines) + 1


def _evidence_groups(
    runtime: ServerRuntime, source_lines: list[str], start_line: int
) -> tuple[dict[str, dict[str, Any]], Counter[str]]:
    groups: dict[str, dict[str, Any]] = {}
    severity_counts: Counter[str] = Counter()
    for line_number, line in enumerate(source_lines, start=start_line):
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
                "last_line_number": line_number,
                "sample": safe_line,
            },
        )
        group["occurrences"] += 1
        group["last_line_number"] = line_number
    return groups, severity_counts


def _timestamp(line: str) -> str | None:
    match = _TIMESTAMP_PATTERN.match(line)
    return match.group("timestamp") if match else None


def _severity(line: str) -> str | None:
    match = _SEVERITY_PATTERN.search(line)
    return match.group(1).upper() if match else None


def _fingerprint(line: str) -> str:
    normalized = _TIMESTAMP_REPLACEMENT.sub("<timestamp>", line)
    normalized = _WHITESPACE.sub(" ", normalized).strip()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def _recommended_next_checks(high_severity_count: int) -> list[str]:
    if high_severity_count:
        return [
            "Inspect the earliest observed high-severity event in a bounded wider window.",
            "Compare timing with read-only Docker or service-health metadata if enabled.",
        ]
    return ["Collect a bounded wider log window before drawing conclusions."]
