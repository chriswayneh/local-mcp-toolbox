"""Typed models and file-discovery rules for agent configuration auditing."""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from fnmatch import fnmatchcase
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from mcp_toolbox.models import ErrorCategory, ToolboxError

DEFAULT_MAX_FILES = 200
MAX_FILES_CEILING = 10_000
DEFAULT_MAX_FILE_BYTES = 240_000
MAX_FILE_BYTES_CEILING = 100 * 1_048_576
MAX_TOTAL_SCAN_BYTES = 20 * 1_048_576
MAX_INCLUDE_GLOBS = 50
MAX_GLOB_LENGTH = 256
MAX_SNIPPET_CHARS = 220

SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "CVS",
        "__pycache__",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        ".eggs",
    }
)

DEFAULT_BLOCKED_PATTERNS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "id_rsa",
    "id_ed25519",
    "*.pem",
    "*.key",
    "credentials*",
)

INSTRUCTION_EXACT_NAMES = frozenset(
    {
        "skill.md",
        "agents.md",
        "agents.override.md",
        "claude.md",
        "claude.local.md",
        "gemini.md",
        "prompt.md",
        "copilot-instructions.md",
        ".cursorrules",
        ".windsurfrules",
        ".clinerules",
        ".goosehints",
        "conventions.md",
    }
)

MCP_CONFIG_EXACT_NAMES = frozenset(
    {
        ".mcp.json",
        "mcp.json",
        "claude_desktop_config.json",
    }
)

INSTRUCTION_PATH_GLOBS: tuple[str, ...] = (
    ".github/copilot-instructions.md",
    ".github/instructions/*.md",
    ".github/instructions/**/*.md",
    ".github/prompts/*.md",
    ".github/prompts/**/*.md",
    ".cursor/rules/*.md",
    ".cursor/rules/*.mdc",
    ".cursor/rules/**/*.md",
    ".cursor/rules/**/*.mdc",
    ".windsurf/rules/*.md",
    ".windsurf/rules/**/*.md",
    ".clinerules/*.md",
    ".clinerules/**/*.md",
    ".claude/*.md",
    ".claude/**/*.md",
    "skills/*.md",
    "skills/**/*.md",
    "prompts/*.md",
    "prompts/**/*.md",
    "prompts/*.txt",
    "prompts/**/*.txt",
    "instructions/*.md",
    "instructions/**/*.md",
    "*.instructions.md",
    "**/*.instructions.md",
    "*.prompt.md",
    "**/*.prompt.md",
    "*.mdc",
    "**/*.mdc",
)

MCP_CONFIG_PATH_GLOBS: tuple[str, ...] = (
    ".mcp.json",
    "**/.mcp.json",
    "mcp.json",
    "**/mcp.json",
    ".cursor/mcp.json",
    "**/.cursor/mcp.json",
    ".vscode/mcp.json",
    "**/.vscode/mcp.json",
    "claude_desktop_config.json",
    "**/claude_desktop_config.json",
)


class AuditSeverity(StrEnum):
    """Deterministic severity levels for agent configuration findings."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_RANK: dict[str, int] = {
    AuditSeverity.LOW.value: 1,
    AuditSeverity.MEDIUM.value: 2,
    AuditSeverity.HIGH.value: 3,
}


class AuditCategory(StrEnum):
    """Five deterministic detection categories for agent configuration auditing."""

    HIDDEN_UNICODE = "hidden_unicode"
    PROMPT_OVERRIDE = "prompt_override"
    DANGEROUS_EXECUTION = "dangerous_execution"
    CREDENTIAL_OR_EXFIL = "credential_or_exfil"
    MCP_CONFIG_RISK = "mcp_config_risk"


class AgentConfigFinding(BaseModel):
    """One normalized finding from an agent instruction, skill, prompt, or MCP config file."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=64)
    severity: AuditSeverity
    category: AuditCategory
    file_path: str = Field(min_length=1, max_length=1_024)
    line_number: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=240)
    description: str = Field(min_length=1, max_length=1_000)
    remediation: str = Field(min_length=1, max_length=1_000)
    snippet: str = Field(max_length=1_000)


class AgentConfigAuditReport(BaseModel):
    """Structured report returned by the CLI and MCP agent-configuration auditor."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["clean", "findings_detected"]
    target_type: Literal["directory", "file"]
    files_discovered: int = Field(ge=0)
    files_scanned: int = Field(ge=0)
    withheld_files: int = Field(ge=0)
    files_truncated: bool
    total_findings: int = Field(ge=0)
    truncated_findings: bool
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    findings: list[AgentConfigFinding]
    scanned_files: list[str]


def normalized_part(part: str) -> str:
    candidate = part.lower().rstrip(" .")
    if ":" in candidate and not candidate.endswith(":"):
        candidate = candidate.split(":", maxsplit=1)[0].rstrip(" .")
    return candidate


def matches_short_alias(name: str, pattern: str) -> bool:
    stem = name.split(".", maxsplit=1)[0]
    if "~" not in stem:
        return False
    prefix, suffix = stem.rsplit("~", maxsplit=1)
    blocked_stem = pattern.split("*", maxsplit=1)[0].split(".", maxsplit=1)[0]
    return bool(prefix and suffix.isdigit() and blocked_stem.startswith(prefix))


def matches_blocked_parts(parts: Sequence[str], blocked_patterns: Sequence[str]) -> bool:
    normalized_parts = tuple(normalized_part(part) for part in parts if part)
    lowered_patterns = tuple(pattern.lower() for pattern in blocked_patterns)
    return any(
        fnmatchcase(name, pattern) or matches_short_alias(name, pattern)
        for name in normalized_parts
        for pattern in lowered_patterns
    )


def matches_any_glob(rel_posix: str, name: str, globs: Sequence[str]) -> bool:
    rel_lower = rel_posix.lower()
    name_lower = name.lower()
    pure_rel = PurePosixPath(rel_lower)
    for raw_glob in globs:
        pattern = raw_glob.strip().lower()
        if not pattern:
            continue
        if (
            fnmatchcase(rel_lower, pattern)
            or fnmatchcase(name_lower, pattern)
            or pure_rel.match(pattern)
        ):
            return True
        if pattern.startswith("**/"):
            suffix = pattern[3:]
            if fnmatchcase(rel_lower, suffix) or fnmatchcase(name_lower, suffix):
                return True
    return False


def is_default_agent_file(rel_posix: str) -> bool:
    """Return True when a relative POSIX path matches default agent config patterns."""

    name = PurePosixPath(rel_posix).name.lower()
    if name in INSTRUCTION_EXACT_NAMES or name in MCP_CONFIG_EXACT_NAMES:
        return True
    return matches_any_glob(rel_posix, name, INSTRUCTION_PATH_GLOBS) or matches_any_glob(
        rel_posix, name, MCP_CONFIG_PATH_GLOBS
    )


def is_mcp_config_path(rel_posix: str) -> bool:
    """Return True when a root-relative POSIX path is a recognized MCP configuration filename."""

    name = PurePosixPath(rel_posix).name.lower()
    if name in MCP_CONFIG_EXACT_NAMES or name.endswith(".mcp.json"):
        return True
    return matches_any_glob(rel_posix, name, MCP_CONFIG_PATH_GLOBS)


def validate_include_globs(include_globs: Sequence[str] | None) -> tuple[str, ...] | None:
    if include_globs is None:
        return None
    if len(include_globs) > MAX_INCLUDE_GLOBS:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            f"At most {MAX_INCLUDE_GLOBS} include glob patterns may be specified.",
            remediation="Pass fewer include glob patterns.",
        )
    validated: list[str] = []
    for raw in include_globs:
        if not isinstance(raw, str):
            raise ToolboxError(
                ErrorCategory.INVALID_INPUT,
                "Include glob patterns must be strings.",
                remediation="Pass valid relative glob strings.",
            )
        cleaned = "/".join(raw.strip().split("\\"))
        if (
            not cleaned
            or len(cleaned) > MAX_GLOB_LENGTH
            or cleaned.startswith("/")
            or ".." in cleaned.split("/")
        ):
            raise ToolboxError(
                ErrorCategory.INVALID_INPUT,
                "Include glob patterns must be non-empty relative patterns without '..'.",
                remediation="Use relative glob patterns such as 'prompts/**/*.md' or '*.mcp.json'.",
            )
        validated.append(cleaned)
    return tuple(validated) if validated else None
