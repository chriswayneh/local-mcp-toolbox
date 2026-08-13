"""Fail-closed authorization for integrations and approved filesystem roots."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from mcp_toolbox.config.settings import FilesystemSettings, GitSettings, ToolboxSettings
from mcp_toolbox.models import ErrorCategory, ToolboxError


@dataclass(frozen=True, slots=True)
class PermissionDecision:
    """A sanitized authorization result suitable for audit metadata."""

    allowed: bool
    reason: str
    policy: str


class FilesystemAuthorizer:
    """Authorize only paths canonically contained by configured existing roots."""

    def __init__(self, settings: FilesystemSettings) -> None:
        self._settings = settings
        self._roots = tuple(self._resolve_root(root) for root in settings.approved_roots)

    @staticmethod
    def _resolve_root(root: Path) -> Path:
        if not root.is_absolute():
            raise ToolboxError(
                ErrorCategory.CONFIGURATION_ERROR,
                "Approved filesystem roots must be absolute paths.",
                remediation="Use an absolute existing directory path in approved_roots.",
            )
        try:
            resolved = root.resolve(strict=True)
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.CONFIGURATION_ERROR,
                "An approved filesystem root does not exist or cannot be resolved.",
                remediation="Configure an existing directory that the server can read.",
            ) from error
        if not resolved.is_dir():
            raise ToolboxError(
                ErrorCategory.CONFIGURATION_ERROR,
                "Approved filesystem roots must be directories.",
                remediation="Configure a directory, not a file.",
            )
        return resolved

    def check_directory(self, requested_path: Path) -> PermissionDecision:
        """Check a directory path without applying file extension restrictions."""

        return self._check_containment(requested_path)

    def check_file(self, requested_path: Path) -> PermissionDecision:
        """Check containment, blocked names, and allowlisted file extensions."""

        containment = self._check_containment(requested_path)
        if not containment.allowed:
            return containment

        canonical = requested_path.resolve(strict=False)
        if self._matches_blocked_pattern(canonical):
            return PermissionDecision(
                False, "The path matches a blocked sensitive-file pattern.", "blocked_pattern"
            )
        if canonical.suffix.lower() not in self._settings.allowed_extensions:
            return PermissionDecision(
                False, "The file extension is not approved for reading.", "extension"
            )
        return PermissionDecision(True, "Path is within an approved root.", "approved_root")

    def require_file(self, requested_path: Path) -> Path:
        """Return a canonical permitted file path or raise a safe denial."""

        decision = self.check_file(requested_path)
        if not decision.allowed:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an approved root and readable file type.",
            )
        return requested_path.resolve(strict=False)

    def require_directory(self, requested_path: Path) -> Path:
        """Return a canonical permitted directory path or raise a safe denial."""

        decision = self.check_directory(requested_path)
        if not decision.allowed:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Filesystem access was denied by the active policy.",
                remediation="Use an approved absolute directory path.",
            )
        return requested_path.resolve(strict=False)

    def _check_containment(self, requested_path: Path) -> PermissionDecision:
        if not requested_path.is_absolute():
            return PermissionDecision(
                False, "Only absolute filesystem paths are accepted.", "absolute_path"
            )
        try:
            canonical = requested_path.resolve(strict=False)
        except OSError:
            return PermissionDecision(
                False, "The filesystem path could not be resolved.", "path_resolution"
            )

        for root in self._roots:
            if canonical.is_relative_to(root):
                return PermissionDecision(True, "Path is within an approved root.", "approved_root")
        return PermissionDecision(
            False, "Path is outside approved filesystem roots.", "approved_root"
        )

    def _matches_blocked_pattern(self, canonical: Path) -> bool:
        names = (part.lower() for part in canonical.parts)
        patterns = tuple(pattern.lower() for pattern in self._settings.blocked_patterns)
        return any(fnmatchcase(name, pattern) for name in names for pattern in patterns)


class PermissionService:
    """Central authorization service used by all future tool modules."""

    def __init__(self, settings: ToolboxSettings) -> None:
        self.settings = settings
        self.filesystem = FilesystemAuthorizer(settings.filesystem)
        self.logs = FilesystemAuthorizer(settings.logs)
        self.security = FilesystemAuthorizer(settings.security)
        self.infrastructure = FilesystemAuthorizer(settings.infrastructure)
        self.incident = FilesystemAuthorizer(settings.incident)
        self.git = GitRepositoryAuthorizer(settings.git)

    def check_integration(self, integration: str) -> PermissionDecision:
        enabled = self.settings.integrations.model_dump().get(integration)
        if enabled is None:
            return PermissionDecision(False, "The integration is not recognized.", "integration")
        if not enabled:
            return PermissionDecision(
                False, "The integration is disabled by the active profile.", "integration"
            )
        return PermissionDecision(True, "The integration is explicitly enabled.", "integration")

    def require_integration(self, integration: str) -> None:
        decision = self.check_integration(integration)
        if not decision.allowed:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Integration access was denied by the active policy.",
                remediation=(
                    "Enable only the required integration in an explicit configuration profile."
                ),
            )

    def require_git_repository(self, requested_path: Path) -> Path:
        """Require Git integration plus both filesystem and repository allowlists."""

        self.require_integration("git")
        repository = self.filesystem.require_directory(requested_path)
        return self.git.require_repository(repository)


class GitRepositoryAuthorizer:
    """Authorize only exact canonical repositories explicitly approved by the operator."""

    def __init__(self, settings: GitSettings) -> None:
        self._repositories = tuple(
            self._resolve_repository(path) for path in settings.approved_repositories
        )

    @staticmethod
    def _resolve_repository(path: Path) -> Path:
        if not path.is_absolute():
            raise ToolboxError(
                ErrorCategory.CONFIGURATION_ERROR,
                "Approved Git repositories must be absolute paths.",
                remediation=(
                    "Use an absolute existing repository path in git.approved_repositories."
                ),
            )
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise ToolboxError(
                ErrorCategory.CONFIGURATION_ERROR,
                "An approved Git repository does not exist or cannot be resolved.",
                remediation="Configure an existing repository directory.",
            ) from error
        if not resolved.is_dir():
            raise ToolboxError(
                ErrorCategory.CONFIGURATION_ERROR,
                "Approved Git repositories must be directories.",
                remediation="Configure a repository directory, not a file.",
            )
        return resolved

    def require_repository(self, requested_path: Path) -> Path:
        """Return a canonical allowlisted repository or raise a safe denial."""

        canonical = requested_path.resolve(strict=False)
        if canonical not in self._repositories:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Git repository access was denied by the active policy.",
                remediation="Add the exact repository path to git.approved_repositories.",
            )
        return canonical
