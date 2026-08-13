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
