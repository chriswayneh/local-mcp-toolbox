from __future__ import annotations

from pathlib import Path

import pytest

from mcp_toolbox.config import PermissionProfile, load_settings
from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server import build_runtime


def test_load_restricted_config_rebases_relative_audit_path() -> None:
    settings = load_settings(Path("config/restricted.yml"))

    assert settings.profile is PermissionProfile.RESTRICTED
    assert settings.integrations.enabled_names() == frozenset()
    assert settings.audit.path.is_absolute()


def test_restricted_profile_rejects_enabled_integration(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yml"
    config.write_text("profile: restricted\nintegrations:\n  docker: true\n", encoding="utf-8")

    with pytest.raises(ToolboxError) as raised:
        build_runtime(load_settings(config))

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_unknown_configuration_key_is_rejected(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yml"
    config.write_text("profile: restricted\nunsafe_override: true\n", encoding="utf-8")

    with pytest.raises(ToolboxError) as raised:
        load_settings(config)

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_git_repository_allowlist_requires_absolute_paths(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yml"
    config.write_text(
        "profile: standard\nintegrations:\n  git: true\ngit:\n"
        "  approved_repositories: [relative]\n",
        encoding="utf-8",
    )

    with pytest.raises(ToolboxError) as raised:
        build_runtime(load_settings(config))

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_github_requires_external_network_and_repository_allowlist(tmp_path: Path) -> None:
    missing_network = tmp_path / "missing-network.yml"
    missing_network.write_text(
        "profile: standard\nintegrations:\n  github: true\n"
        "github:\n  approved_repositories: [owner/repository]\n",
        encoding="utf-8",
    )

    with pytest.raises(ToolboxError) as raised:
        build_runtime(load_settings(missing_network))

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR

    missing_allowlist = tmp_path / "missing-allowlist.yml"
    missing_allowlist.write_text(
        "profile: standard\nintegrations:\n  github: true\n  external_network: true\n",
        encoding="utf-8",
    )

    with pytest.raises(ToolboxError) as raised:
        build_runtime(load_settings(missing_allowlist))

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR


def test_github_repository_allowlist_rejects_invalid_names(tmp_path: Path) -> None:
    config = tmp_path / "invalid.yml"
    config.write_text(
        "profile: standard\nintegrations:\n  github: true\n  external_network: true\n"
        "github:\n  approved_repositories: ['https://github.com/owner/repository']\n",
        encoding="utf-8",
    )

    with pytest.raises(ToolboxError) as raised:
        build_runtime(load_settings(config))

    assert raised.value.category is ErrorCategory.CONFIGURATION_ERROR
