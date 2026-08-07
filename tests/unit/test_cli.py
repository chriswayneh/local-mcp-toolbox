from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from mcp_toolbox.cli.app import app


def test_serve_fails_closed_for_invalid_configuration(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yml"
    invalid.write_text("profile: restricted\nintegrations:\n  docker: true\n", encoding="utf-8")

    result = CliRunner().invoke(app, ["serve", "--config", str(invalid)])

    assert result.exit_code == 2
    assert "CONFIGURATION_ERROR" in result.stderr
