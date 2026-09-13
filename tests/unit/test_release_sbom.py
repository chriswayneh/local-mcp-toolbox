from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.validate_release_sbom import ReleaseSbomError, main, validate_release_sbom


def write_sbom(path: Path, **overrides: object) -> Path:
    document: dict[str, object] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:0cd50fb9-5e71-4b35-b346-262740e0d802",
        "version": 1,
        "components": [],
    }
    document.update(overrides)
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_validate_release_sbom_accepts_attestable_cyclonedx(tmp_path: Path) -> None:
    validate_release_sbom(write_sbom(tmp_path / "sbom.cdx.json"))


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"bomFormat": "SPDX"}, "CycloneDX format"),
        ({"specVersion": ""}, "specVersion"),
        ({"serialNumber": None}, "UUID serialNumber"),
        ({"serialNumber": "urn:uuid:not-a-uuid"}, "not a valid UUID"),
    ],
)
def test_validate_release_sbom_rejects_unsupported_identity_fields(
    tmp_path: Path,
    overrides: dict[str, object],
    message: str,
) -> None:
    path = write_sbom(tmp_path / "sbom.cdx.json", **overrides)

    with pytest.raises(ReleaseSbomError, match=message):
        validate_release_sbom(path)


def test_validate_release_sbom_rejects_non_object_json(tmp_path: Path) -> None:
    path = tmp_path / "sbom.cdx.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(ReleaseSbomError, match="JSON object"):
        validate_release_sbom(path)


def test_main_fails_closed_when_serial_number_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_sbom(tmp_path / "sbom.cdx.json", serialNumber=None)

    assert main([str(path)]) == 1
    assert "UUID serialNumber" in capsys.readouterr().err
