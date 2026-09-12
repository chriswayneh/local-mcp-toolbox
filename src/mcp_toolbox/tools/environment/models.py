"""Typed, bounded contracts for inert Python-environment metadata auditing."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Reject accidental schema widening at every boundary."""

    model_config = ConfigDict(extra="forbid")


class EnvironmentAssessment(StrEnum):
    """Conservative result states; none imply runtime health or safety."""

    NO_DETECTED_ISSUES = "no_detected_issues"
    ISSUES_DETECTED = "issues_detected"
    PARTIAL = "partial"
    INVALID = "invalid"


class EnvironmentLayout(StrEnum):
    WINDOWS = "windows"
    POSIX = "posix"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class DependencyStatus(StrEnum):
    SATISFIED = "satisfied"
    MISSING = "missing"
    INCOMPATIBLE = "incompatible"
    UNVERIFIABLE = "unverifiable"


class EnvironmentAuditRequest(StrictModel):
    """Only the approved environment and presentation limit are caller-controlled."""

    environment_path: str = Field(min_length=1, max_length=4_096)
    limit: int = Field(default=100, ge=1, le=10_000)


class PythonEnvironmentFacts(StrictModel):
    pyvenv_cfg_present: bool
    layout: EnvironmentLayout
    python_version: str | None = Field(default=None, max_length=100)
    include_system_site_packages: bool | None
    site_packages_directories_found: int = Field(ge=0)


class PackageRecord(StrictModel):
    normalized_name: str = Field(min_length=1, max_length=512)
    version: str = Field(min_length=1, max_length=200)
    declared_dependency_count: int = Field(ge=0)


class DependencyFinding(StrictModel):
    required_by: str | None = Field(default=None, max_length=512)
    dependency: str | None = Field(default=None, max_length=512)
    specifier: str | None = Field(default=None, max_length=1_000)
    installed_version: str | None = Field(default=None, max_length=200)
    status: DependencyStatus
    reason_code: str = Field(min_length=1, max_length=100)


class AuditWarning(StrictModel):
    code: str = Field(min_length=1, max_length=100)
    count: int = Field(default=1, ge=1)


class EnvironmentAuditCounts(StrictModel):
    directory_entries_scanned: int = Field(ge=0)
    metadata_files_observed: int = Field(ge=0)
    metadata_files_parsed: int = Field(ge=0)
    metadata_files_skipped: int = Field(ge=0)
    packages_observed: int = Field(ge=0)
    dependencies_observed: int = Field(ge=0)
    satisfied: int = Field(ge=0)
    missing: int = Field(ge=0)
    incompatible: int = Field(ge=0)
    unverifiable: int = Field(ge=0)
    legacy_egg_info_observed: int = Field(ge=0)


class PythonEnvironmentAuditData(StrictModel):
    """Structured evidence returned inside the project's standard response envelope."""

    assessment: EnvironmentAssessment
    analysis_complete: bool
    environment: PythonEnvironmentFacts
    packages: list[PackageRecord]
    findings: list[DependencyFinding]
    counts: EnvironmentAuditCounts
    warnings: list[AuditWarning]
    packages_truncated: bool
    findings_truncated: bool
    inventory_truncated: bool
