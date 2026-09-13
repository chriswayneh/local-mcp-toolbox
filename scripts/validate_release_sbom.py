"""Validate the fields required for a GitHub CycloneDX SBOM attestation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from uuid import UUID

MAX_SBOM_SIZE_BYTES = 16 * 1024 * 1024


class ReleaseSbomError(ValueError):
    """Raised when a release SBOM cannot be safely attested."""


def validate_release_sbom(path: Path) -> None:
    """Validate the bounded CycloneDX identity fields consumed by GitHub."""
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ReleaseSbomError("Release SBOM cannot be read.") from error
    if size > MAX_SBOM_SIZE_BYTES:
        raise ReleaseSbomError("Release SBOM exceeds GitHub's 16 MiB attestation limit.")

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseSbomError("Release SBOM must be readable UTF-8 JSON.") from error
    if not isinstance(document, dict):
        raise ReleaseSbomError("Release SBOM must be a JSON object.")
    if document.get("bomFormat") != "CycloneDX":
        raise ReleaseSbomError("Release SBOM must declare CycloneDX format.")
    if not isinstance(document.get("specVersion"), str) or not document["specVersion"]:
        raise ReleaseSbomError("Release SBOM must declare a CycloneDX specVersion.")

    serial_number = document.get("serialNumber")
    if not isinstance(serial_number, str) or not serial_number.startswith("urn:uuid:"):
        raise ReleaseSbomError("Release SBOM must contain a CycloneDX UUID serialNumber.")
    uuid_text = serial_number.removeprefix("urn:uuid:")
    try:
        parsed_uuid = UUID(uuid_text)
    except ValueError as error:
        raise ReleaseSbomError("Release SBOM serialNumber is not a valid UUID.") from error
    if str(parsed_uuid) != uuid_text.lower():
        raise ReleaseSbomError("Release SBOM serialNumber must use canonical UUID syntax.")


def main(argv: list[str] | None = None) -> int:
    """Validate one release SBOM path and return a process exit code."""
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("Usage: validate_release_sbom.py PATH", file=sys.stderr)
        return 2
    try:
        validate_release_sbom(Path(arguments[0]))
    except ReleaseSbomError as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Validated release CycloneDX SBOM attestation fields.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
