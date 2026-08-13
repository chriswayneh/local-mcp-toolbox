from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mcp_toolbox.config.settings import FilesystemSettings, ToolboxSettings
from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.permissions import FilesystemAuthorizer, PermissionService


def make_authorizer(root: Path) -> FilesystemAuthorizer:
    return FilesystemAuthorizer(
        FilesystemSettings(
            approved_roots=[root],
            allowed_extensions=[".txt", ".md"],
            blocked_patterns=[".env", "*.pem", "id_rsa", "credentials*"],
        )
    )


def test_path_traversal_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")

    decision = make_authorizer(root).check_file(root / ".." / "outside.txt")

    assert not decision.allowed
    assert decision.policy == "approved_root"


def test_blocked_sensitive_file_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    sensitive = root / ".env"
    sensitive.write_text("PASSWORD=not-real", encoding="utf-8")

    decision = make_authorizer(root).check_file(sensitive)

    assert not decision.allowed
    assert decision.policy == "blocked_pattern"


def test_blocked_sensitive_directory_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    sensitive_directory = root / ".env"
    sensitive_directory.mkdir()

    decision = make_authorizer(root).check_directory(sensitive_directory)

    assert not decision.allowed
    assert decision.policy == "blocked_pattern"


def test_unapproved_extension_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    binary = root / "tool.exe"
    binary.write_bytes(b"MZ")

    decision = make_authorizer(root).check_file(binary)

    assert not decision.allowed
    assert decision.policy == "extension"


def test_symlink_escape_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("private", encoding="utf-8")
    link = root / "linked.txt"
    try:
        os.symlink(outside, link)
    except OSError as error:
        pytest.skip(f"symlinks are not available in this environment: {error}")

    decision = make_authorizer(root).check_file(link)

    assert not decision.allowed
    assert decision.policy == "approved_root"


@pytest.mark.skipif(os.name != "nt", reason="Windows path aliases are platform-specific")
@pytest.mark.parametrize("alias", [".env::$DATA", ".env. ", "credentials~1.txt"])
def test_windows_sensitive_path_aliases_are_denied(tmp_path: Path, alias: str) -> None:
    root = tmp_path / "approved"
    root.mkdir()

    decision = make_authorizer(root).check_file(root / alias)

    assert not decision.allowed
    assert decision.policy == "blocked_pattern"


@pytest.mark.skipif(os.name != "nt", reason="Windows junctions are platform-specific")
def test_windows_junction_escape_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "private.txt").write_text("private", encoding="utf-8")
    junction = root / "linked-directory"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("Windows junction creation is not available in this environment")

    decision = make_authorizer(root).check_file(junction / "private.txt")

    assert not decision.allowed
    assert decision.policy == "approved_root"


def test_require_file_raises_safe_permission_error(tmp_path: Path) -> None:
    root = tmp_path / "approved"
    root.mkdir()

    with pytest.raises(ToolboxError) as raised:
        make_authorizer(root).require_file(tmp_path / "not-approved.txt")

    assert raised.value.category is ErrorCategory.PERMISSION_DENIED


def test_disabled_integration_is_denied() -> None:
    service = PermissionService(ToolboxSettings())

    assert not service.check_integration("docker").allowed
    with pytest.raises(ToolboxError) as raised:
        service.require_integration("docker")

    assert raised.value.category is ErrorCategory.PERMISSION_DENIED
