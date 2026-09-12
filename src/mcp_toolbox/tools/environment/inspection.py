"""Bounded, race-aware inspection of inert Python virtual-environment metadata."""

from __future__ import annotations

import os
import re
import stat
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from email.parser import BytesParser
from email.policy import compat32
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import InvalidName, canonicalize_name
from packaging.version import InvalidVersion, Version

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.tools.environment.models import (
    AuditWarning,
    DependencyFinding,
    DependencyStatus,
    EnvironmentAssessment,
    EnvironmentAuditCounts,
    EnvironmentLayout,
    PackageRecord,
    PythonEnvironmentAuditData,
    PythonEnvironmentFacts,
)

if TYPE_CHECKING:
    from mcp_toolbox.server.runtime import ServerRuntime

PathAuthorizer = Callable[[Path], Path]
_VIRTUALENV_VERSION_INFO = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?:\.(?:alpha|beta|candidate|final)\.[0-9]+)?$"
)
_MAX_REQUIREMENT_CHARS = 2_000
_MAX_NAME_CHARS = 512
_MAX_VERSION_CHARS = 200


@dataclass(frozen=True, slots=True)
class ParsedDistribution:
    """Selected, normalized headers from one bounded METADATA file."""

    name: str
    version: Version
    requirements: tuple[Requirement | None, ...]
    declared_dependency_count: int
    requirements_truncated: bool


@dataclass(slots=True)
class _ScanState:
    directory_entries_scanned: int = 0
    metadata_files_observed: int = 0
    metadata_files_parsed: int = 0
    metadata_files_skipped: int = 0
    legacy_egg_info_observed: int = 0
    inventory_complete: bool = True
    analysis_complete: bool = True
    inventory_truncated: bool = False
    warnings: Counter[str] = field(default_factory=Counter)

    def warn(
        self,
        code: str,
        *,
        affects_inventory: bool = True,
        truncated: bool = False,
    ) -> None:
        self.warnings[code] += 1
        self.analysis_complete = False
        if affects_inventory:
            self.inventory_complete = False
        self.inventory_truncated |= truncated


def _identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _changed_error() -> ToolboxError:
    return ToolboxError(
        ErrorCategory.PERMISSION_DENIED,
        "Python environment metadata changed during authorization.",
        remediation="Retry after the environment is no longer changing.",
    )


def read_bounded_regular_file(
    requested: Path,
    *,
    authorize: PathAuthorizer,
    max_bytes: int,
) -> bytes:
    """Read one reauthorized regular file without following a final link."""

    canonical_before = authorize(requested)
    try:
        stat_before = canonical_before.stat()
    except OSError as error:
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "An approved environment metadata file could not be inspected.",
        ) from error
    if not stat.S_ISREG(stat_before.st_mode):
        raise ToolboxError(
            ErrorCategory.PERMISSION_DENIED,
            "Python environment metadata access was denied by the active policy.",
        )
    if stat_before.st_size > max_bytes:
        raise ToolboxError(
            ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
            "An environment metadata file exceeds its configured size limit.",
            remediation="Inspect an environment with bounded package metadata.",
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(canonical_before, flags)
    except OSError as error:
        raise _changed_error() from error

    try:
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Python environment metadata access was denied by the active policy.",
            )
        if _identity(stat_before) != _identity(opened_stat):
            raise _changed_error()
        if opened_stat.st_size > max_bytes:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "An environment metadata file exceeds its configured size limit.",
                remediation="Inspect an environment with bounded package metadata.",
            )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "An environment metadata file exceeds its configured size limit.",
                remediation="Inspect an environment with bounded package metadata.",
            )
    finally:
        os.close(descriptor)

    canonical_after = authorize(requested)
    try:
        stat_after = canonical_after.stat()
    except OSError as error:
        raise _changed_error() from error
    if canonical_after != canonical_before or _identity(stat_after) != _identity(stat_before):
        raise _changed_error()
    return payload


def bounded_sorted_entries(
    directory: Path,
    cap: int,
    *,
    authorize: PathAuthorizer | None = None,
) -> tuple[list[Path], bool]:
    """Return a stable immediate listing, discarding over-cap OS-order prefixes."""

    authorize_path = authorize or (lambda path: path.resolve(strict=True))
    canonical_before = authorize_path(directory)
    try:
        stat_before = canonical_before.stat()
        if not stat.S_ISDIR(stat_before.st_mode):
            raise _changed_error()
        entries: list[Path] = []
        truncated = False
        with os.scandir(canonical_before) as iterator:
            for entry in iterator:
                entries.append(canonical_before / entry.name)
                if len(entries) > cap:
                    entries = []
                    truncated = True
                    break
    except ToolboxError:
        raise
    except OSError as error:
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "An approved environment directory could not be inspected.",
        ) from error

    canonical_after = authorize_path(directory)
    try:
        stat_after = canonical_after.stat()
    except OSError as error:
        raise _changed_error() from error
    if canonical_after != canonical_before or _identity(stat_after) != _identity(stat_before):
        raise _changed_error()
    if not truncated:
        entries.sort(key=lambda item: (item.name.casefold(), item.name))
    return entries, truncated


def parse_distribution_metadata(
    payload: bytes,
    max_dependencies: int = 500,
) -> ParsedDistribution | None:
    """Parse only one Name, one Version, and bounded Requires-Dist headers."""

    message = BytesParser(policy=compat32).parsebytes(payload, headersonly=True)
    if message.defects:
        return None

    names: list[str] = []
    versions: list[str] = []
    requirements: list[Requirement | None] = []
    declared_dependency_count = 0
    requirements_truncated = False
    for key, value in message.raw_items():
        normalized_key = key.casefold()
        if normalized_key == "name":
            if len(names) < 2:
                names.append(value)
        elif normalized_key == "version":
            if len(versions) < 2:
                versions.append(value)
        elif normalized_key == "requires-dist":
            declared_dependency_count += 1
            if len(requirements) >= max_dependencies:
                requirements_truncated = True
                continue
            if not isinstance(value, str) or len(value) > _MAX_REQUIREMENT_CHARS:
                requirements.append(None)
                continue
            try:
                requirements.append(Requirement(value))
            except InvalidRequirement:
                requirements.append(None)

    if len(names) != 1 or len(versions) != 1:
        return None
    raw_name, raw_version = names[0].strip(), versions[0].strip()
    if (
        not raw_name
        or not raw_version
        or len(raw_name) > _MAX_NAME_CHARS
        or len(raw_version) > _MAX_VERSION_CHARS
    ):
        return None
    try:
        name = str(canonicalize_name(raw_name, validate=True))
        version = Version(raw_version)
    except (InvalidName, InvalidVersion):
        return None
    return ParsedDistribution(
        name,
        version,
        tuple(requirements),
        declared_dependency_count,
        requirements_truncated,
    )


def evaluate_requirement(
    *,
    required_by: str,
    requirement: Requirement | None,
    installed: dict[str, ParsedDistribution],
    ambiguous_names: set[str],
    inventory_complete: bool,
) -> DependencyFinding | None:
    """Evaluate one static edge without host-marker evaluation or URL access."""

    if requirement is None:
        return DependencyFinding(
            required_by=required_by,
            status=DependencyStatus.UNVERIFIABLE,
            reason_code="invalid_requirement",
        )

    dependency = str(canonicalize_name(requirement.name))
    specifier = str(requirement.specifier) or None
    if len(dependency) > _MAX_NAME_CHARS or (specifier is not None and len(specifier) > 1_000):
        return DependencyFinding(
            required_by=required_by,
            status=DependencyStatus.UNVERIFIABLE,
            reason_code="invalid_requirement",
        )
    if requirement.url is not None:
        return DependencyFinding(
            required_by=required_by,
            dependency=dependency,
            status=DependencyStatus.UNVERIFIABLE,
            reason_code="direct_reference_not_evaluated",
        )
    if requirement.marker is not None:
        return DependencyFinding(
            required_by=required_by,
            dependency=dependency,
            specifier=specifier,
            status=DependencyStatus.UNVERIFIABLE,
            reason_code="environment_marker_not_evaluated",
        )
    if requirement.extras:
        return DependencyFinding(
            required_by=required_by,
            dependency=dependency,
            specifier=specifier,
            status=DependencyStatus.UNVERIFIABLE,
            reason_code="extras_not_evaluated",
        )
    if dependency in ambiguous_names:
        return DependencyFinding(
            required_by=required_by,
            dependency=dependency,
            specifier=specifier,
            status=DependencyStatus.UNVERIFIABLE,
            reason_code="ambiguous_installed_distribution",
        )

    target = installed.get(dependency)
    if target is None:
        return DependencyFinding(
            required_by=required_by,
            dependency=dependency,
            specifier=specifier,
            status=(
                DependencyStatus.MISSING if inventory_complete else DependencyStatus.UNVERIFIABLE
            ),
            reason_code=(
                "dependency_not_installed" if inventory_complete else "incomplete_inventory"
            ),
        )
    if requirement.specifier and not requirement.specifier.contains(
        target.version, prereleases=None
    ):
        return DependencyFinding(
            required_by=required_by,
            dependency=dependency,
            specifier=specifier,
            installed_version=str(target.version),
            status=DependencyStatus.INCOMPATIBLE,
            reason_code="installed_version_outside_specifier",
        )
    return None


class PythonEnvironmentInspector:
    """Inspect fixed environment metadata paths without executing target content."""

    def __init__(self, runtime: ServerRuntime) -> None:
        self._runtime = runtime
        self._settings = runtime.settings.environment
        self._authorizer = runtime.permissions.environment

    def inspect(self, environment: Path, limit: int) -> PythonEnvironmentAuditData:
        state = _ScanState()
        environment_identity = self._environment_identity(environment)
        config_path = environment / "pyvenv.cfg"
        try:
            config_payload = read_bounded_regular_file(
                config_path,
                authorize=lambda path: self._authorizer.require_config(environment, path),
                max_bytes=self._settings.max_config_file_bytes,
            )
        except ToolboxError as error:
            if error.category is ErrorCategory.PERMISSION_DENIED:
                raise
            self._require_environment_identity(environment, environment_identity)
            return self._invalid_report(
                present=self._lexically_present(config_path),
                warning="invalid_pyvenv_config",
            )

        config = self._parse_config(config_payload)
        if config is None:
            self._require_environment_identity(environment, environment_identity)
            return self._invalid_report(present=True, warning="invalid_pyvenv_config")
        self._require_environment_identity(environment, environment_identity)
        python_version, include_system = config
        if include_system is not False:
            state.warn("system_site_packages_not_inspected")

        site_packages, layout = self._discover_site_packages(environment, python_version, state)
        if layout is EnvironmentLayout.MIXED:
            state.warn("mixed_environment_layout")
        if not site_packages:
            state.warn("site_packages_not_found")

        metadata_directories = self._discover_metadata_directories(
            environment, site_packages, state
        )
        self._require_environment_identity(environment, environment_identity)
        parsed: list[ParsedDistribution] = []
        dependency_capacity = self._settings.max_dependency_records
        for distribution_directory in metadata_directories:
            metadata_path = distribution_directory / "METADATA"
            authorize_metadata = partial(
                self._authorizer.require_metadata,
                environment,
                distribution_directory.parent,
            )

            try:
                payload = read_bounded_regular_file(
                    metadata_path,
                    authorize=authorize_metadata,
                    max_bytes=self._settings.max_metadata_file_bytes,
                )
            except ToolboxError as error:
                if error.category is ErrorCategory.PERMISSION_DENIED:
                    raise
                state.metadata_files_skipped += 1
                state.warn("metadata_unreadable")
                continue
            effective_cap = min(
                self._settings.max_dependencies_per_distribution,
                dependency_capacity,
            )
            package = parse_distribution_metadata(payload, effective_cap)
            if package is None:
                state.metadata_files_skipped += 1
                state.warn("metadata_invalid")
                continue
            state.metadata_files_parsed += 1
            parsed.append(package)
            dependency_capacity -= len(package.requirements)
            if package.requirements_truncated:
                state.warn("dependency_limit_reached", truncated=True)

        groups: dict[str, list[ParsedDistribution]] = {}
        for package in parsed:
            groups.setdefault(package.name, []).append(package)
        ambiguous_names = {name for name, values in groups.items() if len(values) > 1}
        if ambiguous_names:
            state.warn("duplicate_distribution_name")
        installed = {name: values[0] for name, values in groups.items() if len(values) == 1}

        requirements = [
            (package.name, requirement)
            for package in parsed
            for requirement in package.requirements
        ]
        if any(self._intrinsically_unverifiable(requirement) for _, requirement in requirements):
            state.warn("unverifiable_requirement", affects_inventory=False)

        package_records = sorted(
            (
                PackageRecord(
                    normalized_name=package.name,
                    version=str(package.version),
                    declared_dependency_count=package.declared_dependency_count,
                )
                for package in parsed
            ),
            key=lambda item: (item.normalized_name, item.version),
        )
        findings: list[DependencyFinding] = []
        satisfied = 0
        missing = 0
        incompatible = 0
        unverifiable = 0
        for required_by, requirement in requirements:
            finding = evaluate_requirement(
                required_by=required_by,
                requirement=requirement,
                installed=installed,
                ambiguous_names=ambiguous_names,
                inventory_complete=state.inventory_complete,
            )
            if finding is None:
                satisfied += 1
                continue
            findings.append(finding)
            if finding.status is DependencyStatus.MISSING:
                missing += 1
            elif finding.status is DependencyStatus.INCOMPATIBLE:
                incompatible += 1
            else:
                unverifiable += 1
        findings.sort(
            key=lambda item: (
                item.required_by or "",
                item.dependency or "",
                item.status.value,
                item.reason_code,
            )
        )

        if not state.analysis_complete:
            assessment = EnvironmentAssessment.PARTIAL
        elif missing or incompatible:
            assessment = EnvironmentAssessment.ISSUES_DETECTED
        else:
            assessment = EnvironmentAssessment.NO_DETECTED_ISSUES
        counts = EnvironmentAuditCounts(
            directory_entries_scanned=state.directory_entries_scanned,
            metadata_files_observed=state.metadata_files_observed,
            metadata_files_parsed=state.metadata_files_parsed,
            metadata_files_skipped=state.metadata_files_skipped,
            packages_observed=len(parsed),
            dependencies_observed=len(requirements),
            satisfied=satisfied,
            missing=missing,
            incompatible=incompatible,
            unverifiable=unverifiable,
            legacy_egg_info_observed=state.legacy_egg_info_observed,
        )
        warnings = [
            AuditWarning(code=code, count=count) for code, count in sorted(state.warnings.items())
        ]
        self._require_environment_identity(environment, environment_identity)
        return PythonEnvironmentAuditData(
            assessment=assessment,
            analysis_complete=state.analysis_complete,
            environment=PythonEnvironmentFacts(
                pyvenv_cfg_present=True,
                layout=layout,
                python_version=python_version,
                include_system_site_packages=include_system,
                site_packages_directories_found=len(site_packages),
            ),
            packages=package_records[:limit],
            findings=findings[:limit],
            counts=counts,
            warnings=warnings,
            packages_truncated=len(package_records) > limit,
            findings_truncated=len(findings) > limit,
            inventory_truncated=state.inventory_truncated,
        )

    def _discover_site_packages(
        self,
        environment: Path,
        python_version: str,
        state: _ScanState,
    ) -> tuple[list[Path], EnvironmentLayout]:
        windows: list[Path] = []
        posix: list[Path] = []
        windows_site = self._optional_directory(
            environment, environment / "Lib" / "site-packages", state
        )
        if windows_site is not None:
            windows.append(windows_site)

        python_directory = environment / "lib" / self._python_directory_name(python_version)
        posix_site = self._optional_directory(
            environment, python_directory / "site-packages", state
        )
        if posix_site is not None:
            posix.append(posix_site)

        if windows and posix:
            layout = EnvironmentLayout.MIXED
        elif windows:
            layout = EnvironmentLayout.WINDOWS
        elif posix:
            layout = EnvironmentLayout.POSIX
        else:
            layout = EnvironmentLayout.UNKNOWN
        return windows + posix, layout

    def _discover_metadata_directories(
        self,
        environment: Path,
        site_packages: list[Path],
        state: _ScanState,
    ) -> list[Path]:
        metadata_directories: list[Path] = []
        over_metadata_cap = False
        for site in site_packages:
            try:
                entries, truncated = bounded_sorted_entries(
                    site,
                    self._settings.max_directory_entries,
                    authorize=lambda path: self._authorizer.reauthorize_directory(
                        environment, path
                    ),
                )
            except ToolboxError as error:
                if error.category is ErrorCategory.PERMISSION_DENIED:
                    raise
                state.warn("directory_unreadable")
                continue
            state.directory_entries_scanned += (
                self._settings.max_directory_entries + 1 if truncated else len(entries)
            )
            if truncated:
                state.warn("directory_entry_limit_reached", truncated=True)
                continue
            for entry in entries:
                folded = entry.name.casefold()
                if folded.endswith(".egg-info"):
                    state.legacy_egg_info_observed += 1
                    state.warn("legacy_egg_info_not_inspected")
                    continue
                if not folded.endswith(".dist-info"):
                    continue
                state.metadata_files_observed += 1
                if len(metadata_directories) >= self._settings.max_metadata_files:
                    over_metadata_cap = True
                    state.metadata_files_skipped += 1
                    continue
                try:
                    metadata_directories.append(
                        self._authorizer.require_directory(environment, entry)
                    )
                except ToolboxError as error:
                    if error.category is ErrorCategory.PERMISSION_DENIED:
                        raise
                    state.metadata_files_skipped += 1
                    state.warn("metadata_directory_rejected")
        if over_metadata_cap:
            state.warn("metadata_file_limit_reached", truncated=True)
        return metadata_directories

    def _optional_directory(
        self,
        environment: Path,
        candidate: Path,
        state: _ScanState,
    ) -> Path | None:
        try:
            return self._authorizer.require_directory(environment, candidate)
        except ToolboxError as error:
            if error.category is ErrorCategory.PERMISSION_DENIED:
                raise
            if error.category is not ErrorCategory.RESOURCE_NOT_FOUND:
                state.warn("directory_unreadable")
            return None

    def _environment_identity(self, environment: Path) -> tuple[int, int, int, int]:
        canonical = self._authorizer.require_environment(environment)
        try:
            value = canonical.stat()
        except OSError as error:
            raise _changed_error() from error
        if not stat.S_ISDIR(value.st_mode):
            raise _changed_error()
        return _identity(value)

    def _require_environment_identity(
        self,
        environment: Path,
        expected: tuple[int, int, int, int],
    ) -> None:
        if self._environment_identity(environment) != expected:
            raise _changed_error()

    @staticmethod
    def _parse_config(payload: bytes) -> tuple[str, bool | None] | None:
        try:
            text = payload.decode("utf-8-sig")
        except UnicodeDecodeError:
            return None
        selected: dict[str, list[str]] = {
            "version": [],
            "version_info": [],
            "include-system-site-packages": [],
        }
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            if not separator:
                return None
            normalized_key = key.strip().casefold()
            if normalized_key in selected:
                selected[normalized_key].append(value.strip())
        version_values = selected["version"]
        version_info_values = selected["version_info"]
        includes = selected["include-system-site-packages"]
        if (
            len(version_values) > 1
            or len(version_info_values) > 1
            or (not version_values and not version_info_values)
            or len(includes) > 1
        ):
            return None
        version = PythonEnvironmentInspector._parse_config_version(
            version_values[0] if version_values else None,
            version_info_values[0] if version_info_values else None,
        )
        if version is None:
            return None
        include_system: bool | None = None
        if includes:
            normalized_include = includes[0].casefold()
            if normalized_include == "true":
                include_system = True
            elif normalized_include == "false":
                include_system = False
        return str(version), include_system

    @staticmethod
    def _parse_config_version(
        raw_version: str | None,
        raw_version_info: str | None,
    ) -> Version | None:
        versions: list[Version] = []
        if raw_version is not None:
            if not raw_version or len(raw_version) > 100:
                return None
            try:
                version = Version(raw_version)
            except InvalidVersion:
                return None
            if len(version.release) < 2:
                return None
            versions.append(version)
        if raw_version_info is not None:
            if not raw_version_info or len(raw_version_info) > 100:
                return None
            match = _VIRTUALENV_VERSION_INFO.fullmatch(raw_version_info)
            if match is None:
                return None
            versions.append(
                Version(f"{match.group('major')}.{match.group('minor')}.{match.group('patch')}")
            )
        if len(versions) == 2:
            releases = [version.release + (0,) * (3 - len(version.release)) for version in versions]
            if releases[0][:3] != releases[1][:3]:
                return None
        return versions[0]

    @staticmethod
    def _python_directory_name(python_version: str) -> str:
        version = Version(python_version)
        return f"python{version.release[0]}.{version.release[1]}"

    @staticmethod
    def _intrinsically_unverifiable(requirement: Requirement | None) -> bool:
        if requirement is None:
            return True
        dependency = str(canonicalize_name(requirement.name))
        specifier = str(requirement.specifier)
        return bool(
            len(dependency) > _MAX_NAME_CHARS
            or len(specifier) > 1_000
            or requirement.url is not None
            or requirement.marker is not None
            or requirement.extras
        )

    @staticmethod
    def _lexically_present(path: Path) -> bool:
        try:
            path.lstat()
        except OSError:
            return False
        return True

    @staticmethod
    def _invalid_report(*, present: bool, warning: str) -> PythonEnvironmentAuditData:
        return PythonEnvironmentAuditData(
            assessment=EnvironmentAssessment.INVALID,
            analysis_complete=False,
            environment=PythonEnvironmentFacts(
                pyvenv_cfg_present=present,
                layout=EnvironmentLayout.UNKNOWN,
                python_version=None,
                include_system_site_packages=None,
                site_packages_directories_found=0,
            ),
            packages=[],
            findings=[],
            counts=EnvironmentAuditCounts(
                directory_entries_scanned=0,
                metadata_files_observed=0,
                metadata_files_parsed=0,
                metadata_files_skipped=0,
                packages_observed=0,
                dependencies_observed=0,
                satisfied=0,
                missing=0,
                incompatible=0,
                unverifiable=0,
                legacy_egg_info_observed=0,
            ),
            warnings=[AuditWarning(code=warning)],
            packages_truncated=False,
            findings_truncated=False,
            inventory_truncated=False,
        )
