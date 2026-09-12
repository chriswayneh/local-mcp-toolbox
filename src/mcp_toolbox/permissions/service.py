"""Fail-closed authorization for integrations and approved filesystem roots."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

from mcp_toolbox.config.settings import (
    FilesystemSettings,
    GitHubSettings,
    GitSettings,
    KubernetesSettings,
    OllamaSettings,
    ToolboxSettings,
)
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
        """Check containment and sensitive-name restrictions for a directory path."""

        containment = self._check_containment(requested_path)
        if not containment.allowed:
            return containment

        canonical = requested_path.resolve(strict=False)
        if self._matches_blocked_pattern(canonical):
            return PermissionDecision(
                False, "The path matches a blocked sensitive-file pattern.", "blocked_pattern"
            )
        return containment

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
        names = tuple(self._normalized_name(part) for part in canonical.parts)
        patterns = tuple(pattern.lower() for pattern in self._settings.blocked_patterns)
        return any(
            fnmatchcase(name, pattern) or self._matches_short_name_alias(name, pattern)
            for name in names
            for pattern in patterns
        )

    @staticmethod
    def _normalized_name(part: str) -> str:
        """Normalize Windows aliases that can disguise a blocked filename."""

        candidate = part.lower().rstrip(" .")
        if ":" in candidate and not candidate.endswith(":"):
            candidate = candidate.split(":", maxsplit=1)[0]
        return candidate

    @staticmethod
    def _matches_short_name_alias(name: str, pattern: str) -> bool:
        """Fail closed for a Windows 8.3 name that abbreviates a blocked basename."""

        stem = name.split(".", maxsplit=1)[0]
        if "~" not in stem:
            return False
        prefix, suffix = stem.rsplit("~", maxsplit=1)
        blocked_stem = pattern.split("*", maxsplit=1)[0].split(".", maxsplit=1)[0]
        return bool(prefix and suffix.isdigit() and blocked_stem.startswith(prefix))


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
        self.github = GitHubRepositoryAuthorizer(settings.github)
        self.kubernetes = KubernetesAuthorizer(settings.kubernetes)
        self.ollama = OllamaModelAuthorizer(settings.ollama)

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

    def require_github_repository(self, requested_repository: str) -> str:
        """Require network and GitHub opt-ins plus an exact repository allowlist match."""

        self.require_integration("external_network")
        self.require_integration("github")
        return self.github.require_repository(requested_repository)

    def require_kubernetes_scope(self, context: str, namespace: str) -> tuple[str, str]:
        """Require network and Kubernetes opt-ins plus exact scope allowlists."""

        self.require_integration("external_network")
        self.require_integration("kubernetes")
        return self.kubernetes.require_scope(context, namespace)

    def require_ollama_model(self, model: str) -> str:
        """Require network, AI, and Ollama opt-ins plus an exact model allowlist."""

        self.require_integration("external_network")
        self.require_integration("external_ai")
        self.require_integration("ollama")
        return self.ollama.require_model(model)


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


class GitHubRepositoryAuthorizer:
    """Authorize only exact case-insensitive GitHub owner/repository identifiers."""

    def __init__(self, settings: GitHubSettings) -> None:
        self._repositories = {
            repository.casefold(): repository for repository in settings.approved_repositories
        }

    def require_repository(self, requested_repository: str) -> str:
        candidate = requested_repository.strip().casefold()
        if candidate not in self._repositories:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "GitHub repository access was denied by the active policy.",
                remediation="Add the exact owner/repository name to github.approved_repositories.",
            )
        return self._repositories[candidate]


class KubernetesAuthorizer:
    """Authorize exact case-sensitive Kubernetes contexts and namespaces."""

    def __init__(self, settings: KubernetesSettings) -> None:
        self._contexts = settings.approved_contexts
        self._namespaces = settings.approved_namespaces

    def require_scope(self, context: str, namespace: str) -> tuple[str, str]:
        if context not in self._contexts or namespace not in self._namespaces:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Kubernetes scope access was denied by the active policy.",
                remediation=("Add the exact context and namespace to the Kubernetes allowlists."),
            )
        return context, namespace


class OllamaModelAuthorizer:
    """Authorize only exact case-sensitive local model names."""

    def __init__(self, settings: OllamaSettings) -> None:
        self._models = settings.approved_models

    def require_model(self, model: str) -> str:
        if model not in self._models:
            raise ToolboxError(
                ErrorCategory.PERMISSION_DENIED,
                "Ollama model access was denied by the active policy.",
                remediation="Add the exact model name to ollama.approved_models.",
            )
        return model
