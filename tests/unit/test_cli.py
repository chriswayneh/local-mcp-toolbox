from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_toolbox.cli.app import app


def test_serve_fails_closed_for_invalid_configuration(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("profile: restricted\nintegrations:\n  docker: true\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["serve", "--config", str(invalid)])

    assert result.exit_code == 2
    assert "CONFIGURATION_ERROR" in result.stderr


def test_doctor_reports_validated_restricted_configuration() -> None:
    result = CliRunner().invoke(app, ["doctor", "--config", "config/restricted.yml"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["status"] == "ready"
    assert report["profile"] == "restricted"
    assert report["enabled_integrations"] == []
