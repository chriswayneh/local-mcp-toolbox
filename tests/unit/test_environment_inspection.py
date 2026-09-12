from __future__ import annotations

import os
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.tools.environment.inspection import (
    ParsedDistribution,
    bounded_sorted_entries,
    evaluate_requirement,
    parse_distribution_metadata,
    read_bounded_regular_file,
)
from mcp_toolbox.tools.environment.models import DependencyStatus


def metadata(
    *,
    name: str = "example",
    version: str = "1.0",
    requirements: tuple[str, ...] = (),
) -> bytes:
    lines = [
        "Metadata-Version: 2.3",
        f"Name: {name}",
        f"Version: {version}",
        *(f"Requires-Dist: {item}" for item in requirements),
        "",
        "Untrusted body content is deliberately ignored.",
    ]
    return "\n".join(lines).encode()


def installed(name: str, version: str) -> dict[str, ParsedDistribution]:
    return {
        name: ParsedDistribution(
            name=name,
            version=Version(version),
            requirements=(),
            declared_dependency_count=0,
            requirements_truncated=False,
        )
    }


def test_parser_reads_only_selected_headers() -> None:
    payload = (
        metadata(name="Demo_Package", version="1.2.3", requirements=("dependency>=2",))
        + b"\nAuthorization: Bearer secret-value-that-must-not-be-used\n"
    )

    result = parse_distribution_metadata(payload)

    assert result is not None
    assert result.name == "demo-package"
    assert str(result.version) == "1.2.3"
    assert len(result.requirements) == 1
    assert "Authorization" not in repr(result)


@pytest.mark.parametrize(
    "payload",
    [
        b"Metadata-Version: 2.3\nVersion: 1.0\n",
        b"Metadata-Version: 2.3\nName: demo\n",
        b"Name: demo\nName: shadow\nVersion: 1.0\n",
        b"Name: demo\nVersion: 1.0\nVersion: 2.0\n",
        b"Name: ../escape\nVersion: 1.0\n",
        b"Name: demo\nVersion: definitely-not-a-version\n",
    ],
)
def test_parser_rejects_missing_repeated_or_invalid_identity_headers(payload: bytes) -> None:
    assert parse_distribution_metadata(payload) is None


def test_per_distribution_dependency_cap_is_enforced_during_parsing() -> None:
    payload = metadata(requirements=tuple(f"dependency-{index}>=1" for index in range(101)))

    result = parse_distribution_metadata(payload, max_dependencies=10)

    assert result is not None
    assert len(result.requirements) == 10
    assert result.declared_dependency_count == 101
    assert result.requirements_truncated is True


def test_invalid_requirement_becomes_only_a_sentinel() -> None:
    result = parse_distribution_metadata(
        metadata(requirements=("valid>=1", "not a valid requirement ???"))
    )

    assert result is not None
    assert isinstance(result.requirements[0], Requirement)
    assert result.requirements[1] is None
    assert "not a valid requirement" not in repr(result.requirements[1])


def test_oversized_valid_specifier_becomes_content_free_unverifiable_finding() -> None:
    specifier = ",".join(f"!={index}.0" for index in range(250))

    finding = evaluate_requirement(
        required_by="caller",
        requirement=Requirement(f"dependency{specifier}"),
        installed=installed("dependency", "2.0"),
        ambiguous_names=set(),
        inventory_complete=True,
    )

    assert finding is not None
    assert finding.status is DependencyStatus.UNVERIFIABLE
    assert finding.reason_code == "invalid_requirement"
    assert finding.specifier is None


def test_oversized_valid_dependency_name_becomes_content_free_finding() -> None:
    finding = evaluate_requirement(
        required_by="caller",
        requirement=Requirement("a" * 600),
        installed={},
        ambiguous_names=set(),
        inventory_complete=True,
    )

    assert finding is not None
    assert finding.status is DependencyStatus.UNVERIFIABLE
    assert finding.reason_code == "invalid_requirement"
    assert finding.dependency is None


def test_satisfied_requirement_is_omitted_from_findings() -> None:
    finding = evaluate_requirement(
        required_by="caller",
        requirement=Requirement("dependency>=1,<3"),
        installed=installed("dependency", "2.0"),
        ambiguous_names=set(),
        inventory_complete=True,
    )

    assert finding is None


def test_incompatible_requirement_is_confirmed() -> None:
    finding = evaluate_requirement(
        required_by="caller",
        requirement=Requirement("dependency>=3"),
        installed=installed("dependency", "2.0"),
        ambiguous_names=set(),
        inventory_complete=True,
    )

    assert finding is not None
    assert finding.status is DependencyStatus.INCOMPATIBLE
    assert finding.installed_version == "2.0"
    assert finding.reason_code == "installed_version_outside_specifier"


def test_absent_requirement_is_missing_only_with_complete_inventory() -> None:
    confirmed = evaluate_requirement(
        required_by="caller",
        requirement=Requirement("dependency>=1"),
        installed={},
        ambiguous_names=set(),
        inventory_complete=True,
    )
    incomplete = evaluate_requirement(
        required_by="caller",
        requirement=Requirement("dependency>=1"),
        installed={},
        ambiguous_names=set(),
        inventory_complete=False,
    )

    assert confirmed is not None
    assert confirmed.status is DependencyStatus.MISSING
    assert confirmed.reason_code == "dependency_not_installed"
    assert incomplete is not None
    assert incomplete.status is DependencyStatus.UNVERIFIABLE
    assert incomplete.reason_code == "incomplete_inventory"


@pytest.mark.parametrize(
    ("raw_requirement", "reason"),
    [
        ('dependency>=1; python_version >= "3.12"', "environment_marker_not_evaluated"),
        ("dependency[feature]>=1", "extras_not_evaluated"),
        (
            "dependency @ https://user:password@example.test/archive.whl",
            "direct_reference_not_evaluated",
        ),
    ],
)
def test_host_dependent_or_secret_requirements_are_not_echoed(
    raw_requirement: str, reason: str
) -> None:
    finding = evaluate_requirement(
        required_by="caller",
        requirement=Requirement(raw_requirement),
        installed=installed("dependency", "2.0"),
        ambiguous_names=set(),
        inventory_complete=True,
    )

    assert finding is not None
    assert finding.status is DependencyStatus.UNVERIFIABLE
    assert finding.reason_code == reason
    serialized = finding.model_dump_json()
    assert "password" not in serialized
    assert "python_version" not in serialized
    assert "feature" not in serialized


def test_bounded_directory_scan_sorts_only_complete_inventory(tmp_path: Path) -> None:
    for name in ("Zulu", "alpha", "Beta"):
        (tmp_path / name).mkdir()

    entries, truncated = bounded_sorted_entries(tmp_path, 3)

    assert truncated is False
    assert [entry.name for entry in entries] == ["alpha", "Beta", "Zulu"]


def test_over_cap_directory_discards_nondeterministic_prefix(tmp_path: Path) -> None:
    for name in ("third", "first", "second"):
        (tmp_path / name).mkdir()

    entries, truncated = bounded_sorted_entries(tmp_path, 2)

    assert entries == []
    assert truncated is True


def test_bounded_directory_scan_rejects_identity_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "entry").mkdir()
    original_scandir = os.scandir

    class SwappingScandir:
        def __init__(self, path: Path) -> None:
            self._inner = original_scandir(path)

        def __enter__(self):
            return self._inner

        def __exit__(self, *args: object) -> None:
            self._inner.close()
            target.rename(tmp_path / "original-target")
            target.mkdir()

    monkeypatch.setattr(os, "scandir", SwappingScandir)

    with pytest.raises(ToolboxError) as raised:
        bounded_sorted_entries(target, 10)

    assert raised.value.category is ErrorCategory.PERMISSION_DENIED


def test_bounded_reader_accepts_exact_limit(tmp_path: Path) -> None:
    target = tmp_path / "METADATA"
    target.write_bytes(b"x" * 32)

    result = read_bounded_regular_file(
        target, authorize=lambda path: path.resolve(strict=True), max_bytes=32
    )

    assert result == b"x" * 32


def test_bounded_reader_rejects_limit_plus_one(tmp_path: Path) -> None:
    target = tmp_path / "METADATA"
    target.write_bytes(b"x" * 33)

    with pytest.raises(ToolboxError) as raised:
        read_bounded_regular_file(
            target, authorize=lambda path: path.resolve(strict=True), max_bytes=32
        )

    assert raised.value.category is ErrorCategory.OUTPUT_LIMIT_EXCEEDED


def test_bounded_reader_rejects_post_read_identity_change(tmp_path: Path) -> None:
    target = tmp_path / "METADATA"
    target.write_bytes(b"original")
    calls = 0

    def authorize(path: Path) -> Path:
        nonlocal calls
        calls += 1
        resolved = path.resolve(strict=True)
        if calls == 2:
            path.write_bytes(b"changed-size")
        return resolved

    with pytest.raises(ToolboxError) as raised:
        read_bounded_regular_file(target, authorize=authorize, max_bytes=100)

    assert raised.value.category is ErrorCategory.PERMISSION_DENIED
    assert "changed during authorization" in raised.value.message
