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
    warning = any(check["status"] == "warning" for check in report["checks"])
    assert report["status"] == ("attention" if warning else "ready")
    assert report["profile"] == "restricted"
    assert report["enabled_integrations"] == []


def test_doctor_status_is_attention_when_audit_parent_is_missing(tmp_path: Path) -> None:
    config = tmp_path / "restricted.yml"
    config.write_text(
        "profile: restricted\naudit:\n  path: ./missing-audit/events.jsonl\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    audit = next(check for check in report["checks"] if check["name"] == "audit_parent")
    assert audit["status"] == "warning"
    assert report["status"] == "attention"


def test_doctor_status_is_ready_when_audit_parent_exists(tmp_path: Path) -> None:
    (tmp_path / "audit").mkdir()
    config = tmp_path / "restricted.yml"
    config.write_text(
        "profile: restricted\naudit:\n  path: ./audit/events.jsonl\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["doctor", "--config", str(config)])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    audit = next(check for check in report["checks"] if check["name"] == "audit_parent")
    assert audit["status"] == "pass"
    assert report["status"] == "ready"
