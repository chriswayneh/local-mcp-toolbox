"""Typed, fail-closed configuration loading."""

from __future__ import annotations

import re
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
    max_file_bytes: int = Field(default=240_000, ge=1, le=100 * 1_048_576)
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
    security_scanners: bool = False
    infrastructure: bool = False
    incident: bool = False
    github: bool = False
    kubernetes: bool = False
    ollama: bool = False
    external_network: bool = False
    external_ai: bool = False

    def enabled_names(self) -> frozenset[str]:
        return frozenset(name for name, enabled in self.model_dump().items() if enabled)


class GitSettings(BaseModel):
    """Explicit repository allowlist for the read-only Git module."""

    model_config = ConfigDict(extra="forbid")

    approved_repositories: list[Path] = Field(default_factory=list)


_GITHUB_REPOSITORY = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9_.-]{1,100}$")
_KUBERNETES_CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,252}$")
_KUBERNETES_NAMESPACE = re.compile(
    r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$"
)
_OLLAMA_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")


class GitHubSettings(BaseModel):
    """Exact repository allowlist for the read-only GitHub integration."""

    model_config = ConfigDict(extra="forbid")

    approved_repositories: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("approved_repositories", mode="before")
    @classmethod
    def validate_repositories(cls, value: list[str]) -> frozenset[str]:
        repositories: set[str] = set()
        for repository in value:
            candidate = repository.strip()
            if not _GITHUB_REPOSITORY.fullmatch(candidate):
                raise ValueError("GitHub repositories must use the owner/repository format")
            repositories.add(candidate)
        return frozenset(repositories)


class KubernetesSettings(BaseModel):
    """Exact context and namespace allowlists for Kubernetes inspection."""

    model_config = ConfigDict(extra="forbid")

    approved_contexts: frozenset[str] = Field(default_factory=frozenset)
    approved_namespaces: frozenset[str] = Field(default_factory=frozenset)

    @field_validator("approved_contexts", mode="before")
    @classmethod
    def validate_contexts(cls, value: list[str]) -> frozenset[str]:
        contexts = {context.strip() for context in value}
        if any(not _KUBERNETES_CONTEXT.fullmatch(context) for context in contexts):
            raise ValueError("Kubernetes contexts contain unsupported characters")
        return frozenset(contexts)

    @field_validator("approved_namespaces", mode="before")
    @classmethod
    def validate_namespaces(cls, value: list[str]) -> frozenset[str]:
        namespaces = {namespace.strip() for namespace in value}
        if any(
            len(namespace) > 253 or not _KUBERNETES_NAMESPACE.fullmatch(namespace)
            for namespace in namespaces
        ):
            raise ValueError("Kubernetes namespaces must be valid DNS names")
        return frozenset(namespaces)


class OllamaSettings(BaseModel):
    """Fixed-loopback Ollama endpoint and exact model allowlist."""

    model_config = ConfigDict(extra="forbid")

    host: str = Field(default="127.0.0.1", pattern=r"^127\.0\.0\.1$")
    port: int = Field(default=11_434, ge=1, le=65_535)
    approved_models: frozenset[str] = Field(default_factory=frozenset)
    max_prompt_chars: int = Field(default=8_000, ge=1, le=100_000)

    @field_validator("approved_models", mode="before")
    @classmethod
    def validate_models(cls, value: list[str]) -> frozenset[str]:
        models = {model.strip() for model in value}
        if any(not _OLLAMA_MODEL.fullmatch(model) for model in models):
            raise ValueError("Ollama model names contain unsupported characters")
        return frozenset(models)


class LogSettings(FilesystemSettings):
    """Explicit approved roots and limits for the local log-inspection module."""

    allowed_extensions: frozenset[str] = Field(
        default_factory=lambda: frozenset({".jsonl", ".log", ".out", ".txt"})
    )
    max_file_bytes: int = Field(default=5_242_880, ge=1, le=100 * 1_048_576)


class SecuritySettings(FilesystemSettings):
    """Explicit approved roots for external read-only scanner invocation."""


class InfrastructureSettings(FilesystemSettings):
    """Explicit approved roots for top-level infrastructure metadata inventory."""


class IncidentSettings(LogSettings):
    """Explicit approved roots and limits for deterministic incident evidence tools."""


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
    github: GitHubSettings = Field(default_factory=GitHubSettings)
    kubernetes: KubernetesSettings = Field(default_factory=KubernetesSettings)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    logs: LogSettings = Field(default_factory=LogSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    infrastructure: InfrastructureSettings = Field(default_factory=InfrastructureSettings)
    incident: IncidentSettings = Field(default_factory=IncidentSettings)
    limits: LimitSettings = Field(default_factory=LimitSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    redaction: RedactionSettings = Field(default_factory=RedactionSettings)

    @model_validator(mode="after")
    def enforce_profile_invariants(self) -> ToolboxSettings:
        if self.profile is PermissionProfile.RESTRICTED and self.integrations.enabled_names():
            enabled = ", ".join(sorted(self.integrations.enabled_names()))
            raise ValueError(f"restricted profile cannot enable integrations: {enabled}")
        network_integrations = {
            name
            for name in ("github", "kubernetes", "ollama", "external_ai")
            if getattr(self.integrations, name)
        }
        if network_integrations and not self.integrations.external_network:
            enabled = ", ".join(sorted(network_integrations))
            raise ValueError(f"network integrations require external_network: {enabled}")
        if self.integrations.github and not self.github.approved_repositories:
            raise ValueError("github requires at least one approved repository")
        if self.integrations.kubernetes and (
            not self.kubernetes.approved_contexts or not self.kubernetes.approved_namespaces
        ):
            raise ValueError("kubernetes requires approved contexts and namespaces")
        if self.integrations.ollama and not self.integrations.external_ai:
            raise ValueError("ollama requires explicit external_ai enablement")
        if self.integrations.ollama and not self.ollama.approved_models:
            raise ValueError("ollama requires at least one approved model")
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
