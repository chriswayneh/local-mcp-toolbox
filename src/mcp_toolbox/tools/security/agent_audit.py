"""Orchestrator and MCP tool registration for agent instruction and MCP config auditing."""

from __future__ import annotations

import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.redaction import Redactor
from mcp_toolbox.tools.security.mcp_config_detector import (
    AuditContext,
    bound_escaped_text,
    scan_mcp_config_json,
)
from mcp_toolbox.tools.security.models import (
    DEFAULT_BLOCKED_PATTERNS,
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    MAX_FILE_BYTES_CEILING,
    MAX_FILES_CEILING,
    MAX_TOTAL_SCAN_BYTES,
    SEVERITY_RANK,
    SKIPPED_DIRECTORIES,
    AgentConfigAuditReport,
    AuditCategory,
    AuditSeverity,
    is_default_agent_file,
    is_mcp_config_path,
    matches_any_glob,
    matches_blocked_parts,
    validate_include_globs,
)
from mcp_toolbox.tools.security.safe_reader import (
    read_safe_candidate,
    reject_cli_target_links,
    reject_link_or_junction_chain,
    walk_safe_directory,
)
from mcp_toolbox.tools.security.text_detectors import (
    scan_text_rules,
    scan_unicode_smuggling,
)

if TYPE_CHECKING:
    from mcp.server import MCPServer

    from mcp_toolbox.permissions.service import FilesystemAuthorizer
    from mcp_toolbox.server.runtime import ServerRuntime

_MAX_SAFE_REL_PATH_CHARS = 960


def _matches_target_filter(
    rel_posix: str,
    filename: str,
    validated_globs: tuple[str, ...] | None,
) -> bool:
    if validated_globs is not None:
        return matches_any_glob(rel_posix, filename, validated_globs)
    return is_default_agent_file(rel_posix)


def _audit_single_file_content(
    rel_posix: str,
    payload: bytes,
    is_explicit_target: bool,
    context: AuditContext,
) -> None:
    raw_starts_with_bom = payload.startswith(b"\xef\xbb\xbf")
    text = payload.decode("utf-8", errors="replace")
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines = raw_lines[:-1]
    lines = [line[:-1] if line.endswith("\r") else line for line in raw_lines]
    safe_rel_posix = bound_escaped_text(rel_posix, _MAX_SAFE_REL_PATH_CHARS)

    scan_unicode_smuggling(safe_rel_posix, lines, raw_starts_with_bom, context)
    scan_text_rules(safe_rel_posix, text, lines, context)

    lower_rel = rel_posix.lower()
    dedicated_mcp = is_mcp_config_path(rel_posix)
    if dedicated_mcp or (is_explicit_target and lower_rel.endswith(".json")):
        scan_mcp_config_json(safe_rel_posix, text, lines, True, context)
    elif lower_rel.endswith(".json"):
        scan_mcp_config_json(safe_rel_posix, text, lines, False, context)


def audit_agent_configs(
    target_path: Path,
    *,
    include_globs: Sequence[str] | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    limit: int = 100,
    redactor: Redactor | None = None,
    authorizer: FilesystemAuthorizer | None = None,
    blocked_patterns: Sequence[str] = DEFAULT_BLOCKED_PATTERNS,
) -> tuple[AgentConfigAuditReport, int]:
    """Audit a file or directory for risky agent instructions, skills, prompts, and MCP configs.

    Returns the structured report and the total number of secret redactions performed.
    """

    if not 1 <= max_files <= MAX_FILES_CEILING:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            f"max_files must be between 1 and {MAX_FILES_CEILING}.",
            remediation=f"Use a max_files value between 1 and {MAX_FILES_CEILING}.",
        )
    if not 1 <= max_file_bytes <= MAX_FILE_BYTES_CEILING:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            f"max_file_bytes must be between 1 and {MAX_FILE_BYTES_CEILING}.",
            remediation=f"Use a max_file_bytes value between 1 and {MAX_FILE_BYTES_CEILING}.",
        )
    if not 1 <= limit <= MAX_FILES_CEILING:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            f"limit must be between 1 and {MAX_FILES_CEILING}.",
            remediation=f"Use a limit between 1 and {MAX_FILES_CEILING}.",
        )

    validated_globs = validate_include_globs(include_globs)
    effective_blocked = tuple(dict.fromkeys([*DEFAULT_BLOCKED_PATTERNS, *blocked_patterns]))

    if authorizer is not None:
        if not target_path.is_absolute() or ".." in target_path.parts:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an approved absolute path without parent-directory traversal.",
            )
        lexical = Path(os.path.abspath(target_path))
        matching_root: Path | None = None
        for root_candidate in authorizer.roots:
            if lexical == root_candidate or lexical.is_relative_to(root_candidate):
                matching_root = root_candidate
                break
        if matching_root is None:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use a path inside an approved security root.",
            )
        rel_to_root = lexical.relative_to(matching_root)
        if matches_blocked_parts(rel_to_root.parts, effective_blocked):
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="The requested path matches a blocked sensitive-file pattern.",
            )
        try:
            allowed = authorizer.check_path(lexical).allowed
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an accessible regular directory or file path.",
            ) from error
        if not allowed:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an approved path that does not match a blocked pattern.",
            )
        reject_link_or_junction_chain(matching_root, lexical)
        try:
            target_lstat = lexical.lstat()
            is_link = stat.S_ISLNK(target_lstat.st_mode)
            is_junction = lexical.is_junction() if hasattr(lexical, "is_junction") else False
        except FileNotFoundError as error:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The requested agent configuration path was not found.",
                remediation="Pass an existing directory or regular file path.",
            ) from error
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an accessible regular directory or file path.",
            ) from error
        if is_link or is_junction:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Symbolic links and junctions are not permitted for the target path.",
                remediation="Pass a canonical regular directory or file path.",
            )
        anchor_root = matching_root
        prefix_parts = rel_to_root.parts
    else:
        if ".." in target_path.parts:
            raise ToolboxError(
                ErrorCategory.INVALID_INPUT,
                "Target path must not contain '..' traversal segments.",
                remediation="Pass a direct path to the target file or directory.",
            )
        lexical = Path(os.path.abspath(target_path))
        target_lstat = reject_cli_target_links(target_path, lexical)
        anchor_root = lexical.parent if stat.S_ISREG(target_lstat.st_mode) else lexical
        prefix_parts = (lexical.name,) if stat.S_ISREG(target_lstat.st_mode) else ()

    context = AuditContext(redactor=redactor or Redactor())
    scanned_files: list[str] = []
    files_discovered = 0
    withheld_files = 0
    files_truncated = False
    total_bytes_read = 0

    if stat.S_ISREG(target_lstat.st_mode):
        target_type: Literal["directory", "file"] = "file"
        if matches_blocked_parts((lexical.name,), effective_blocked):
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "The target file matches a blocked sensitive-file pattern.",
                remediation="Pass an agent instruction, skill, prompt, or MCP configuration file.",
            )
        files_discovered = 1
        budget = min(max_file_bytes, MAX_TOTAL_SCAN_BYTES)
        payload, over_budget = read_safe_candidate(
            anchor_root,
            prefix_parts,
            budget,
            max_file_bytes,
            effective_blocked,
            authorizer,
        )
        if payload is None:
            if over_budget or target_lstat.st_size > max_file_bytes:
                raise ToolboxError(
                    ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                    "The target file exceeds the configured maximum readable size.",
                    remediation="Increase max_file_bytes or audit a smaller configuration file.",
                )
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "The target file could not be safely read.",
                remediation="Confirm the target is a readable single-link regular file.",
            )
        rel_posix = lexical.name
        scanned_files.append(bound_escaped_text(rel_posix, _MAX_SAFE_REL_PATH_CHARS))
        _audit_single_file_content(rel_posix, payload, True, context)

    elif stat.S_ISDIR(target_lstat.st_mode):
        target_type = "directory"
        candidate_rel_parts: list[tuple[str, ...]] = []
        walked_entries, walk_withheld = walk_safe_directory(
            anchor_root,
            prefix_parts,
            SKIPPED_DIRECTORIES,
        )
        withheld_files += walk_withheld

        for rel_dir_parts, regular_names, symlink_names in walked_entries:
            matched_symlink_names: list[str] = []
            for sym_name in symlink_names:
                sym_parts = (*rel_dir_parts, sym_name) if rel_dir_parts else (sym_name,)
                sym_posix = "/".join(sym_parts)
                if _matches_target_filter(sym_posix, sym_name, validated_globs):
                    matched_symlink_names.append(sym_name)
                elif sym_name not in SKIPPED_DIRECTORIES and not sym_name.endswith(".egg"):
                    withheld_files += 1

            for filename in sorted([*regular_names, *matched_symlink_names]):
                rel_parts = (*rel_dir_parts, filename) if rel_dir_parts else (filename,)
                rel_posix = "/".join(rel_parts)
                if not _matches_target_filter(rel_posix, filename, validated_globs):
                    continue
                files_discovered += 1
                if len(candidate_rel_parts) >= max_files:
                    files_truncated = True
                    withheld_files += 1
                    continue
                candidate_rel_parts.append(rel_parts)

        for rel_parts in candidate_rel_parts:
            remaining_total = MAX_TOTAL_SCAN_BYTES - total_bytes_read
            if remaining_total <= 0:
                files_truncated = True
                withheld_files += 1
                continue
            budget = min(max_file_bytes, remaining_total)
            payload, over_budget = read_safe_candidate(
                anchor_root,
                (*prefix_parts, *rel_parts),
                budget,
                max_file_bytes,
                effective_blocked,
                authorizer,
            )
            if payload is None:
                withheld_files += 1
                if over_budget:
                    files_truncated = True
                continue
            total_bytes_read += len(payload)
            rel_posix = "/".join(rel_parts)
            scanned_files.append(bound_escaped_text(rel_posix, _MAX_SAFE_REL_PATH_CHARS))
            _audit_single_file_content(
                rel_posix,
                payload,
                validated_globs is not None,
                context,
            )
    else:
        raise ToolboxError(
            ErrorCategory.PERMISSION_DENIED,
            "Target path must be a regular file or directory.",
            remediation="Pass a regular directory or file path.",
        )

    all_findings = sorted(
        context.findings,
        key=lambda item: (
            item.file_path,
            item.line_number,
            -SEVERITY_RANK[item.severity.value],
            item.rule_id,
        ),
    )

    severity_counts = {
        AuditSeverity.HIGH.value: 0,
        AuditSeverity.MEDIUM.value: 0,
        AuditSeverity.LOW.value: 0,
    }
    category_counts = {category.value: 0 for category in AuditCategory}
    for item in all_findings:
        severity_counts[item.severity.value] += 1
        category_counts[item.category.value] += 1

    bounded_findings = all_findings[:limit]
    report = AgentConfigAuditReport(
        status="findings_detected" if all_findings else "clean",
        target_type=target_type,
        files_discovered=files_discovered,
        files_scanned=len(scanned_files),
        withheld_files=withheld_files,
        files_truncated=files_truncated,
        total_findings=len(all_findings),
        truncated_findings=len(all_findings) > limit,
        severity_counts=severity_counts,
        category_counts=category_counts,
        findings=bounded_findings,
        scanned_files=scanned_files[:max_files],
    )
    return report, context.redaction_count


def format_text_report(report: AgentConfigAuditReport) -> str:
    """Format an AgentConfigAuditReport as concise, human-readable plain text."""

    lines = [
        (
            f"status: {report.status} "
            f"(files_scanned={report.files_scanned}, "
            f"withheld_files={report.withheld_files}, "
            f"total_findings={report.total_findings}, "
            f"high={report.severity_counts['high']}, "
            f"medium={report.severity_counts['medium']}, "
            f"low={report.severity_counts['low']})"
        )
    ]
    for finding in report.findings:
        lines.append(
            f"[{finding.severity.value.upper()}] {finding.rule_id} ({finding.category.value}) "
            f"{finding.file_path}:{finding.line_number} - {finding.title}"
        )
        lines.append(f"  snippet: {finding.snippet}")
        lines.append(f"  remediation: {finding.remediation}")
    return "\n".join(lines)


def register_agent_config_audit_tool(
    server: MCPServer,
    runtime: ServerRuntime,
) -> tuple[str, ...]:
    """Register the read-only MCP tool for auditing agent instructions and MCP config files."""

    from mcp_types import ToolAnnotations

    from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

    read_only = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )

    @server.tool(
        name="security_audit_agent_configs",
        title="Audit agent instructions, skills, prompts, and MCP configs",
        description=(
            "Inspect agent instruction files, skill definitions, prompt templates, and MCP "
            "configuration files in an approved root for hidden Unicode controls, prompt "
            "overrides, dangerous execution snippets, credential/exfiltration patterns, and "
            "unpinned or remote MCP servers."
        ),
        annotations=read_only,
    )
    def security_audit_agent_configs(
        path: str,
        include_globs: list[str] | None = None,
        limit: int = 50,
        max_files: int = DEFAULT_MAX_FILES,
    ) -> dict[str, Any]:
        """Return deterministic, redacted findings for agent instruction and MCP config files."""

        runtime.permissions.require_integration("security_scanners")
        result_limit = require_bounded_limit(runtime, limit)
        max_entries = runtime.settings.security.max_directory_entries
        if not 1 <= max_files <= max_entries:
            raise ToolboxError(
                ErrorCategory.INVALID_INPUT,
                "The requested max_files limit is outside the configured bounds.",
                remediation=f"Use max_files between 1 and {max_entries}.",
            )
        report, prior_redactions = audit_agent_configs(
            Path(path),
            include_globs=include_globs,
            max_files=max_files,
            max_file_bytes=runtime.settings.security.max_file_bytes,
            limit=result_limit,
            redactor=runtime.redactor,
            authorizer=runtime.permissions.security,
            blocked_patterns=runtime.settings.security.blocked_patterns,
        )
        return bounded_response(
            runtime,
            (
                "Audited agent instruction, skill, prompt, and MCP configuration files; "
                "findings are untrusted evidence."
            ),
            report.model_dump(mode="json"),
            prior_redactions=prior_redactions,
        )

    return ("security_audit_agent_configs",)
