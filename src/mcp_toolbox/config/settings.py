"""Typed, fail-closed configuration loading."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mcp_toolbox.models import ErrorCategory, ToolboxError


class PermissionProfile(StrEnum):
    RESTRICTED = "restricted"
    STANDARD = "standard"
    ADVANCED = "advanced"


class FilesystemSettings(BaseModel):
    """Approved content boundaries for all filesystem-backed tools."""

    model_config = ConfigDict(extra="forbid")

    approved_roots: list[Path] = Field(default_factory=list)
    allowed_extensions: frozenset[str] = Field(default_factory=frozenset)
    blocked_patterns: tuple[str, ...] = ()
    max_file_bytes: int = Field(default=1_048_576, ge=1, le=100 * 1_048_576)
    max_directory_entries: int = Field(default=500, ge=1, le=10_000)

    @field_validator("allowed_extensions", mode="before")
    @classmethod
    def normalize_extensions(cls, value: list[str]) -> frozenset[str]:
        normalized: set[str] = set()
        for extension in value:
            candidate = extension.strip().lower()
            if not candidate.startswith(".") or candidate == ".":
                raise ValueError("allowed_extensions entries must start with a file extension dot")
            normalized.add(candidate)
        return frozenset(normalized)

    @field_validator("blocked_patterns")
    @classmethod
    def reject_empty_patterns(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not pattern.strip() for pattern in value):
            raise ValueError("blocked_patterns cannot contain an empty pattern")
        return value


class IntegrationSettings(BaseModel):
    """Explicit opt-in switches for external/local integrations."""

    model_config = ConfigDict(extra="forbid")

    docker: bool = False
    git: bool = False
    logs: bool = False
    github: bool = False
    kubernetes: bool = False
    external_network: bool = False
    external_ai: bool = False

    def enabled_names(self) -> frozenset[str]:
        return frozenset(name for name, enabled in self.model_dump().items() if enabled)


class GitSettings(BaseModel):
    """Explicit repository allowlist for the read-only Git module."""

    model_config = ConfigDict(extra="forbid")

    approved_repositories: list[Path] = Field(default_factory=list)


class LogSettings(FilesystemSettings):
    """Explicit approved roots and limits for the local log-inspection module."""

    allowed_extensions: frozenset[str] = Field(
        default_factory=lambda: frozenset({".jsonl", ".log", ".out", ".txt"})
    )
    max_file_bytes: int = Field(default=5_242_880, ge=1, le=100 * 1_048_576)


class LimitSettings(BaseModel):
    """Global resource limits applied before results reach the MCP client."""

    model_config = ConfigDict(extra="forbid")

    max_records: int = Field(default=100, ge=1, le=10_000)
    max_output_bytes: int = Field(default=262_144, ge=1_024, le=10 * 1_048_576)
    timeout_seconds: int = Field(default=10, ge=1, le=300)


class AuditSettings(BaseModel):
    """Audit storage settings. Events always contain sanitized summaries only."""

    model_config = ConfigDict(extra="forbid")

    path: Path = Path("./audit/events.jsonl")
    retention_days: int = Field(default=30, ge=1, le=3_650)


class RedactionSettings(BaseModel):
    """Privacy controls for additional non-secret identifiers."""

    model_config = ConfigDict(extra="forbid")

    redact_home_paths: bool = True
    redact_emails: bool = False
    redact_ip_addresses: bool = False


class ToolboxSettings(BaseModel):
    """Top-level configuration, deliberately strict about unknown fields."""

    model_config = ConfigDict(extra="forbid")

    profile: PermissionProfile = PermissionProfile.RESTRICTED
    filesystem: FilesystemSettings = Field(default_factory=FilesystemSettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)
    git: GitSettings = Field(default_factory=GitSettings)
    logs: LogSettings = Field(default_factory=LogSettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)

    @model_validator(mode="after")
    def enforce_profile_invariants(self) -> ToolboxSettings:
        if self.profile is PermissionProfile.RESTRICTED and self.integrations.enabled_names():
            enabled = ", ".join(sorted(self.integrations.enabled_names()))
            raise ValueError(f"restricted profile cannot enable integrations: {enabled}")
        if self.integrations.external_ai and not self.integrations.external_network:
            raise ValueError("external_ai requires explicit external_network enablement")
        return self


def load_settings(config_path: Path) -> ToolboxSettings:
    """Load one YAML configuration file and safely rebase its audit path."""

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "Configuration file was not found.",
            remediation="Pass an existing configuration file path.",
        ) from error
    except OSError as error:
        raise ToolboxError(
            ErrorCategory.CONFIGURATION_ERROR,
            "Configuration file could not be read.",
            remediation="Check the configuration file permissions.",
        ) from error
    except yaml.YAMLError as error:
        raise ToolboxError(
            ErrorCategory.CONFIGURATION_ERROR,
            "Configuration file is not valid YAML.",
            remediation="Fix the YAML syntax and try again.",
        ) from error

    if not isinstance(raw, dict):
        raise ToolboxError(
            ErrorCategory.CONFIGURATION_ERROR,
            "Configuration must be a YAML mapping.",
            remediation="Use a top-level mapping that matches the documented schema.",
        )

    try:
        settings = ToolboxSettings.model_validate(cast_mapping(raw))
    except ValidationError as error:
        raise ToolboxError(
            ErrorCategory.CONFIGURATION_ERROR,
            "Configuration failed validation.",
            remediation="Review the configuration against config/example.yml.",
        ) from error

    if not settings.audit.path.is_absolute():
        settings.audit.path = (config_path.parent / settings.audit.path).resolve()
    return settings


def cast_mapping(value: dict[Any, Any]) -> dict[str, Any]:
    """Validate YAML mapping keys before handing them to Pydantic."""

    if any(not isinstance(key, str) for key in value):
        raise ToolboxError(
            ErrorCategory.CONFIGURATION_ERROR,
            "Configuration keys must be strings.",
            remediation="Use string YAML keys only.",
        )
    return value
