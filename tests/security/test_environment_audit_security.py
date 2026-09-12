from __future__ import annotations

import ast
import asyncio
import hashlib
import inspect
import json
import os
import subprocess
from pathlib import Path

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    EnvironmentSettings,
    IntegrationSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.environment import register_environment_tools
from mcp_toolbox.tools.environment.inspection import PythonEnvironmentInspector


def snapshot_tree(root: Path) -> dict[str, tuple[int, int, int, str]]:
    snapshot: dict[str, tuple[int, int, int, str]] = {}
    for path in sorted(root.rglob("*")):
        value = path.lstat()
        digest = (
            hashlib.sha256(path.read_bytes()).hexdigest()
            if path.is_file() and not path.is_symlink()
            else ""
        )
        snapshot[str(path.relative_to(root))] = (
            value.st_mode,
            value.st_size,
            value.st_mtime_ns,
            digest,
        )
    return snapshot


def environment_settings(tmp_path: Path, approved: Path) -> ToolboxSettings:
    return ToolboxSettings(
        profile=PermissionProfile.STANDARD,
        integrations=IntegrationSettings(environment=True),
        environment=EnvironmentSettings(approved_roots=[approved]),
        audit=AuditSettings(path=tmp_path / "audit.jsonl"),
    )


def call(server: object, environment: Path):
    async def scenario():
        async with Client(server) as client:  # type: ignore[arg-type]
            return await client.call_tool(
                "environment_audit_python_venv", {"environment_path": str(environment)}
            )

    return asyncio.run(scenario())


def test_environment_module_has_no_execution_network_or_mutation_primitives() -> None:
    module_root = Path(inspect.getfile(register_environment_tools)).parent
    forbidden_imports = {
        "subprocess",
        "socket",
        "urllib",
        "requests",
        "httpx",
        "runpy",
        "pkg_resources",
    }
    forbidden_calls = {
        "Popen",
        "run",
        "check_call",
        "check_output",
        "system",
        "popen",
        "exec",
        "eval",
        "compile",
        "import_module",
        "write_text",
        "write_bytes",
        "unlink",
        "remove",
        "rename",
        "replace",
        "mkdir",
        "makedirs",
        "rmdir",
    }

    for source_path in module_root.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots = {alias.name.split(".", 1)[0] for alias in node.names}
                assert roots.isdisjoint(forbidden_imports)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".", 1)[0] not in forbidden_imports
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in forbidden_calls
                elif isinstance(node.func, ast.Attribute):
                    if (
                        node.func.attr == "compile"
                        and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "re"
                    ):
                        continue
                    assert node.func.attr not in forbidden_calls


def test_audit_opens_only_fixed_metadata_and_does_not_modify_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    environment = approved / ".venv"
    site = environment / "Lib" / "site-packages"
    distribution = site / "demo-1.0.dist-info"
    distribution.mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(
        "version = 3.12.4\ninclude-system-site-packages = false\n"
        "home = /private/base\nprompt = ghp_123456789012345678901234567890\n",
        encoding="utf-8",
    )
    (distribution / "METADATA").write_text(
        "Metadata-Version: 2.3\nName: glpat-abcdefghijklmnopqrst\nVersion: 1.0\n"
        "Requires-Dist: dependency @ https://user:password@example.test/private.whl\n",
        encoding="utf-8",
    )
    (distribution / "direct_url.json").write_text(
        '{"url":"https://user:password@example.test/private.whl"}', encoding="utf-8"
    )
    (distribution / "RECORD").write_text("must-not-be-read", encoding="utf-8")
    (site / "sitecustomize.py").write_text(
        "raise RuntimeError('must not execute')", encoding="utf-8"
    )
    (site / "execute-me.pth").write_text("raise RuntimeError('must not execute')", encoding="utf-8")
    before = snapshot_tree(environment)
    opened_inside_environment: list[Path] = []
    real_open = os.open

    def tracked_open(
        path: os.PathLike[str] | str, flags: int, *args: object, **kwargs: object
    ) -> int:
        candidate = Path(path)
        try:
            candidate.resolve(strict=False).relative_to(environment.resolve(strict=True))
        except ValueError:
            pass
        else:
            opened_inside_environment.append(candidate)
        return real_open(path, flags, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "open", tracked_open)
    server = create_server(build_runtime(environment_settings(tmp_path, approved)))

    result = call(server, environment)
    after = snapshot_tree(environment)
    payload = json.dumps(result.structured_content)

    assert result.is_error is False
    assert before == after
    assert "password" not in payload
    assert "ghp_123456789012345678901234567890" not in payload
    assert "glpat-abcdefghijklmnopqrst" not in payload
    assert result.structured_content["metadata"]["redaction_count"] >= 1
    assert {path.name for path in opened_inside_environment} == {"pyvenv.cfg", "METADATA"}


def test_outside_and_relative_environment_paths_are_denied(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "pyvenv.cfg").write_text("version = 3.12\n", encoding="utf-8")
    server = create_server(build_runtime(environment_settings(tmp_path, approved)))

    outside_result = call(server, outside)
    missing_outside_result = call(server, tmp_path / "missing-outside")
    relative_result = call(server, Path("relative-venv"))

    assert outside_result.is_error is True
    assert outside_result.structured_content["category"] == "PERMISSION_DENIED"
    assert missing_outside_result.is_error is True
    assert missing_outside_result.structured_content["category"] == "PERMISSION_DENIED"
    assert relative_result.is_error is True
    assert relative_result.structured_content["category"] == "PERMISSION_DENIED"


def test_explicit_dot_dot_environment_path_is_denied(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    environment = approved / ".venv"
    environment.mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text("version = 3.12\n", encoding="utf-8")
    server = create_server(build_runtime(environment_settings(tmp_path, approved)))
    traversing = approved / "child" / ".." / ".venv"

    result = call(server, traversing)

    assert result.is_error is True
    assert result.structured_content["category"] == "PERMISSION_DENIED"


def test_environment_root_symlink_is_denied(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    target = approved / "target"
    target.mkdir()
    (target / "pyvenv.cfg").write_text("version = 3.12\n", encoding="utf-8")
    link = approved / "linked"
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable: {error}")
    server = create_server(build_runtime(environment_settings(tmp_path, approved)))

    result = call(server, link)

    assert result.is_error is True
    assert result.structured_content["category"] == "PERMISSION_DENIED"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction-specific")
def test_environment_root_junction_is_denied(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    target = approved / "target"
    target.mkdir()
    (target / "pyvenv.cfg").write_text("version = 3.12\n", encoding="utf-8")
    junction = approved / "junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("Windows junction creation is unavailable")
    server = create_server(build_runtime(environment_settings(tmp_path, approved)))

    result = call(server, junction)

    assert result.is_error is True
    assert result.structured_content["category"] == "PERMISSION_DENIED"


@pytest.mark.skipif(os.name != "nt", reason="Windows junction-specific")
def test_site_packages_junction_escape_is_denied_without_canary_leak(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    environment = approved / ".venv"
    (environment / "Lib").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(
        "version = 3.12.4\ninclude-system-site-packages = false\n", encoding="utf-8"
    )
    outside_site = tmp_path / "outside-site-packages"
    outside_distribution = outside_site / "canary-1.0.dist-info"
    outside_distribution.mkdir(parents=True)
    canary = "credential-canary-must-not-escape"
    (outside_distribution / "METADATA").write_text(
        f"Name: {canary}\nVersion: 1.0\n", encoding="utf-8"
    )
    junction = environment / "Lib" / "site-packages"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside_site)],
        capture_output=True,
        check=False,
        text=True,
    )
    if created.returncode != 0:
        pytest.skip("Windows junction creation is unavailable")
    settings = environment_settings(tmp_path, approved)
    server = create_server(build_runtime(settings))

    result = call(server, environment)
    audit_text = settings.audit.path.read_text(encoding="utf-8")

    assert result.is_error is True
    assert result.structured_content["category"] == "PERMISSION_DENIED"
    assert canary not in json.dumps(result.structured_content)
    assert canary not in audit_text


def test_metadata_symlink_escape_is_denied(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    environment = approved / ".venv"
    distribution = environment / "Lib" / "site-packages" / "demo-1.0.dist-info"
    distribution.mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(
        "version = 3.12.4\ninclude-system-site-packages = false\n", encoding="utf-8"
    )
    outside = tmp_path / "outside-metadata"
    outside.write_text("Name: canary-private-package\nVersion: 1.0\n", encoding="utf-8")
    metadata_link = distribution / "METADATA"
    try:
        os.symlink(outside, metadata_link)
    except OSError as error:
        pytest.skip(f"symlinks are unavailable: {error}")
    settings = environment_settings(tmp_path, approved)
    server = create_server(build_runtime(settings))

    result = call(server, environment)

    assert result.is_error is True
    assert result.structured_content["category"] == "PERMISSION_DENIED"
    assert "canary-private-package" not in json.dumps(result.structured_content)
    assert "canary-private-package" not in settings.audit.path.read_text(encoding="utf-8")


def test_environment_replacement_between_phases_is_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    environment = approved / ".venv"
    site = environment / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text(
        "version = 3.12.4\ninclude-system-site-packages = false\n", encoding="utf-8"
    )
    original_discovery = PythonEnvironmentInspector._discover_site_packages

    def replace_after_discovery(
        self: PythonEnvironmentInspector,
        selected: Path,
        python_version: str,
        state: object,
    ):
        result = original_discovery(self, selected, python_version, state)  # type: ignore[arg-type]
        moved = approved / "original-venv"
        selected.rename(moved)
        (selected / "Lib" / "site-packages").mkdir(parents=True)
        (selected / "pyvenv.cfg").write_text(
            "version = 3.12.4\ninclude-system-site-packages = false\n", encoding="utf-8"
        )
        return result

    monkeypatch.setattr(
        PythonEnvironmentInspector, "_discover_site_packages", replace_after_discovery
    )
    server = create_server(build_runtime(environment_settings(tmp_path, approved)))

    result = call(server, environment)

    assert result.is_error is True
    assert result.structured_content["category"] == "PERMISSION_DENIED"
