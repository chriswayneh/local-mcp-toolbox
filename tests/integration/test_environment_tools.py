from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path

import pytest
from mcp import Client
from pydantic import ValidationError

from mcp_toolbox.audit import AuditEvent
from mcp_toolbox.config.settings import (
    AuditSettings,
    EnvironmentSettings,
    IntegrationSettings,
    LimitSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.environment.inspection import PythonEnvironmentInspector


def write_environment(
    approved_root: Path,
    *,
    layout: str = "windows",
    include_system: bool = False,
    version: str = "3.12.4",
) -> tuple[Path, Path]:
    environment = approved_root / ".venv"
    environment.mkdir()
    (environment / "pyvenv.cfg").write_text(
        "\n".join(
            [
                f"version = {version}",
                f"include-system-site-packages = {str(include_system).lower()}",
                "home = /private/base-python",
                "command = /private/python -m venv .venv",
                "prompt = ignored-secret-value",
            ]
        ),
        encoding="utf-8",
    )
    if layout == "windows":
        site_packages = environment / "Lib" / "site-packages"
    else:
        release = VersionParts(version)
        site_packages = (
            environment / "lib" / f"python{release.major}.{release.minor}" / "site-packages"
        )
    site_packages.mkdir(parents=True)
    return environment, site_packages


class VersionParts:
    def __init__(self, version: str) -> None:
        parts = version.split(".")
        self.major = parts[0]
        self.minor = parts[1]


def write_distribution(
    site_packages: Path,
    *,
    name: str,
    version: str,
    requirements: tuple[str, ...] = (),
    directory_name: str | None = None,
) -> Path:
    directory = site_packages / (directory_name or f"{name.replace('-', '_')}-{version}.dist-info")
    directory.mkdir()
    (directory / "METADATA").write_text(
        "\n".join(
            [
                "Metadata-Version: 2.3",
                f"Name: {name}",
                f"Version: {version}",
                *(f"Requires-Dist: {item}" for item in requirements),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return directory


def settings_for(
    tmp_path: Path,
    approved_root: Path,
    **environment_overrides: int,
) -> ToolboxSettings:
    return ToolboxSettings(
        profile=PermissionProfile.STANDARD,
        integrations=IntegrationSettings(environment=True),
        environment=EnvironmentSettings(
            approved_roots=[approved_root],
            **environment_overrides,
        ),
        limits=LimitSettings(max_records=100, max_output_bytes=262_144),
        audit=AuditSettings(path=tmp_path / "audit" / "events.jsonl"),
    )


def call(server: object, arguments: dict[str, object]):
    async def scenario():
        async with Client(server) as client:  # type: ignore[arg-type]
            return await client.call_tool("environment_audit_python_venv", arguments)

    return asyncio.run(scenario())


def listed_tools(server: object):
    async def scenario():
        async with Client(server) as client:  # type: ignore[arg-type]
            return await client.list_tools()

    return asyncio.run(scenario()).tools


def test_tool_is_absent_without_explicit_opt_in(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit.jsonl")))
    )

    assert "environment_audit_python_venv" not in {item.name for item in listed_tools(server)}


def test_tool_has_strict_read_only_annotations(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    tool = next(
        item for item in listed_tools(server) if item.name == "environment_audit_python_venv"
    )

    assert tool.annotations is not None
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False
    assert tool.annotations.idempotent_hint is True
    assert tool.annotations.open_world_hint is False


def test_restricted_profile_rejects_environment_opt_in(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()

    with pytest.raises(ValidationError):
        ToolboxSettings(
            profile=PermissionProfile.RESTRICTED,
            integrations=IntegrationSettings(environment=True),
            environment=EnvironmentSettings(approved_roots=[approved]),
        )


def test_enabled_environment_requires_an_approved_root() -> None:
    with pytest.raises(ValidationError):
        ToolboxSettings(
            profile=PermissionProfile.STANDARD,
            integrations=IntegrationSettings(environment=True),
        )


def test_complete_environment_reports_only_abnormal_findings(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    write_distribution(site, name="caller", version="1.0", requirements=("dependency>=1,<3",))
    write_distribution(site, name="dependency", version="2.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    result = call(server, {"environment_path": str(environment), "limit": 100})
    data = result.structured_content["data"]

    assert result.is_error is False
    assert data["assessment"] == "no_detected_issues"
    assert data["analysis_complete"] is True
    assert data["findings"] == []
    assert data["counts"]["satisfied"] == 1
    assert [package["normalized_name"] for package in data["packages"]] == [
        "caller",
        "dependency",
    ]
    assert str(environment) not in json.dumps(result.structured_content)


def test_complete_inventory_confirms_missing_and_incompatible(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    write_distribution(site, name="caller", version="1.0", requirements=("absent>=1", "present>=3"))
    write_distribution(site, name="present", version="2.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["assessment"] == "issues_detected"
    assert data["analysis_complete"] is True
    assert {item["status"] for item in data["findings"]} == {"missing", "incompatible"}


def test_partial_precedes_confirmed_issues(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved, include_system=True)
    write_distribution(
        site,
        name="caller",
        version="1.0",
        requirements=("present>=3", "possibly-in-base>=1"),
    )
    write_distribution(site, name="present", version="2.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["assessment"] == "partial"
    assert data["analysis_complete"] is False
    assert data["counts"]["incompatible"] == 1
    assert data["counts"]["missing"] == 0
    unresolved = next(
        finding for finding in data["findings"] if finding["dependency"] == "possibly-in-base"
    )
    assert unresolved["reason_code"] == "incomplete_inventory"


@pytest.mark.parametrize("layout", ["windows", "posix"])
def test_supported_cross_platform_layouts(tmp_path: Path, layout: str) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved, layout=layout)
    write_distribution(site, name="demo", version="1.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["environment"]["layout"] == layout
    assert data["environment"]["site_packages_directories_found"] == 1


def test_virtualenv_version_and_version_info_are_accepted(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    with (environment / "pyvenv.cfg").open("a", encoding="utf-8") as stream:
        stream.write("\nversion_info = 3.12.4.final.0\n")
    write_distribution(site, name="demo", version="1.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["assessment"] == "no_detected_issues"
    assert data["environment"]["python_version"] == "3.12.4"


def test_stale_posix_python_directory_is_not_mixed_into_inventory(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved, layout="posix", version="3.12.4")
    write_distribution(site, name="caller", version="1.0", requirements=("dependency>=1",))
    stale = environment / "lib" / "python3.11" / "site-packages"
    stale.mkdir(parents=True)
    write_distribution(stale, name="dependency", version="2.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["environment"]["site_packages_directories_found"] == 1
    assert data["counts"]["missing"] == 1
    assert data["findings"][0]["dependency"] == "dependency"


def test_unverifiable_marker_does_not_hide_unrelated_missing_dependency(
    tmp_path: Path,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    write_distribution(
        site,
        name="caller",
        version="1.0",
        requirements=('conditional>=1; python_version >= "3.12"', "absent>=1"),
    )
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["assessment"] == "partial"
    assert data["counts"]["missing"] == 1
    assert data["counts"]["unverifiable"] == 1


def test_metadata_cap_counts_uninspected_files_as_skipped(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    write_distribution(site, name="first", version="1.0")
    write_distribution(site, name="second", version="1.0")
    server = create_server(build_runtime(settings_for(tmp_path, approved, max_metadata_files=1)))

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["counts"]["metadata_files_observed"] == 2
    assert data["counts"]["metadata_files_parsed"] == 1
    assert data["counts"]["metadata_files_skipped"] == 1
    assert data["assessment"] == "partial"


def test_missing_pyvenv_cfg_is_invalid(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment = approved / ".venv"
    environment.mkdir()
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    result = call(server, {"environment_path": str(environment)})

    assert result.is_error is False
    assert result.structured_content["data"]["assessment"] == "invalid"


def test_config_and_metadata_byte_caps_fail_safely(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    config_base = b"version = 3.12.4\ninclude-system-site-packages = false\n#"
    exact_config = config_base + b"x" * (1_024 - len(config_base))
    (environment / "pyvenv.cfg").write_bytes(exact_config)
    config_server = create_server(
        build_runtime(settings_for(tmp_path, approved, max_config_file_bytes=1_024))
    )

    exact_config_result = call(config_server, {"environment_path": str(environment)})
    assert exact_config_result.structured_content["data"]["assessment"] == "no_detected_issues"

    (environment / "pyvenv.cfg").write_bytes(exact_config + b"x")
    invalid = call(config_server, {"environment_path": str(environment)})

    assert invalid.is_error is False
    assert invalid.structured_content["data"]["assessment"] == "invalid"

    (environment / "pyvenv.cfg").write_text(
        "version = 3.12.4\ninclude-system-site-packages = false\n", encoding="utf-8"
    )
    distribution = write_distribution(site, name="demo", version="1.0")
    metadata_base = b"Metadata-Version: 2.3\nName: demo\nVersion: 1.0\n\n"
    exact_metadata = metadata_base + b"x" * (1_024 - len(metadata_base))
    (distribution / "METADATA").write_bytes(exact_metadata)
    metadata_server = create_server(
        build_runtime(settings_for(tmp_path, approved, max_metadata_file_bytes=1_024))
    )

    exact_metadata_result = call(metadata_server, {"environment_path": str(environment)})
    assert exact_metadata_result.structured_content["data"]["counts"]["metadata_files_parsed"] == 1

    (distribution / "METADATA").write_bytes(exact_metadata + b"x")
    partial = call(metadata_server, {"environment_path": str(environment)})
    data = partial.structured_content["data"]

    assert partial.is_error is False
    assert data["assessment"] == "partial"
    assert data["counts"]["metadata_files_skipped"] == 1


def test_final_output_limit_counts_multibyte_utf8(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, _ = write_environment(approved)
    settings = settings_for(tmp_path, approved)
    settings.limits.max_output_bytes = 1_024

    class OversizedReport:
        def model_dump(self, *, mode: str) -> dict[str, str]:
            assert mode == "json"
            return {"bounded_text": "é" * 600}

    def oversized_inspection(
        self: PythonEnvironmentInspector, selected: Path, limit: int
    ) -> OversizedReport:
        return OversizedReport()

    monkeypatch.setattr(PythonEnvironmentInspector, "inspect", oversized_inspection)
    server = create_server(build_runtime(settings))

    result = call(server, {"environment_path": str(environment)})

    assert result.is_error is True
    assert result.structured_content["category"] == "OUTPUT_LIMIT_EXCEEDED"


def test_dependency_caps_never_create_false_missing_findings(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    write_distribution(
        site,
        name="first",
        version="1.0",
        requirements=tuple(f"first-dependency-{index}>=1" for index in range(5)),
    )
    write_distribution(
        site,
        name="second",
        version="1.0",
        requirements=tuple(f"second-dependency-{index}>=1" for index in range(5)),
    )
    server = create_server(
        build_runtime(
            settings_for(
                tmp_path,
                approved,
                max_dependencies_per_distribution=2,
                max_dependency_records=3,
            )
        )
    )

    data = call(server, {"environment_path": str(environment)}).structured_content["data"]

    assert data["assessment"] == "partial"
    assert data["inventory_truncated"] is True
    assert data["counts"]["dependencies_observed"] <= 3
    assert data["counts"]["missing"] == 0


def test_result_limit_preserves_full_aggregate_analysis(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    for index in range(3):
        write_distribution(
            site,
            name=f"caller-{index}",
            version="1.0",
            requirements=(f"absent-{index}>=1",),
        )
    server = create_server(build_runtime(settings_for(tmp_path, approved)))

    data = call(server, {"environment_path": str(environment), "limit": 1}).structured_content[
        "data"
    ]

    assert len(data["packages"]) == 1
    assert len(data["findings"]) == 1
    assert data["packages_truncated"] is True
    assert data["findings_truncated"] is True
    assert data["counts"]["packages_observed"] == 3
    assert data["counts"]["missing"] == 3


def test_audit_records_only_path_shape_and_package_count(tmp_path: Path) -> None:
    approved = tmp_path / "approved"
    approved.mkdir()
    environment, site = write_environment(approved)
    write_distribution(site, name="private-package-name", version="1.0")
    settings = settings_for(tmp_path, approved)
    server = create_server(build_runtime(settings))

    result = call(server, {"environment_path": str(environment), "limit": 10})
    raw_audit = settings.audit.path.read_text(encoding="utf-8")
    events = [AuditEvent.model_validate(json.loads(line)) for line in raw_audit.splitlines()]
    event = next(item for item in events if item.tool_name == "environment_audit_python_venv")

    assert str(environment) not in raw_audit
    assert "private-package-name" not in raw_audit
    assert event.tool_module == "environment"
    assert event.records_returned == len(result.structured_content["data"]["packages"])
    assert event.input_summary["arguments"]["environment_path"] == {
        "type": "str",
        "length": len(str(environment)),
        "fingerprint": hashlib.sha256(str(environment).encode()).hexdigest()[:16],
    }
