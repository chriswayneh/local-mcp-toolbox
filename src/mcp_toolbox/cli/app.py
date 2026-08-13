"""Operator-facing commands for the MCP server."""

import json
from importlib.util import find_spec
from pathlib import Path
from shutil import which
from typing import Annotated

import typer

from mcp_toolbox.models import ToolboxError
from mcp_toolbox.server import load_runtime, run_stdio

app = typer.Typer(
    name="local-mcp-toolbox",
    help="Secure, local-first MCP environment inspection.",
    no_args_is_help=True,
)


@app.callback()
def root() -> None:
    """Secure, local-first MCP environment inspection."""


@app.command()
def serve(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            help="Path to the explicit permission configuration file.",
        ),
    ] = Path("config/default.yml"),
) -> None:
    """Start the MCP server over stdio after validating policy configuration."""

    try:
        runtime = load_runtime(config)
    except ToolboxError as error:
        typer.echo(f"{error.category}: {error.message}", err=True)
        raise typer.Exit(code=2) from error
    run_stdio(runtime)


@app.command()
def doctor(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            help="Path to the explicit permission configuration file.",
        ),
    ] = Path("config/default.yml"),
) -> None:
    """Validate configuration and report non-mutating local prerequisite checks."""

    try:
        runtime = load_runtime(config)
    except ToolboxError as error:
        typer.echo(f"{error.category}: {error.message}", err=True)
        raise typer.Exit(code=2) from error

    integrations = runtime.settings.integrations.enabled_names()
    checks = [
        {"name": "configuration", "status": "pass", "detail": "validated"},
        {
            "name": "audit_parent",
            "status": "pass" if _audit_parent_exists(runtime.audit.path) else "warning",
            "detail": "exists"
            if _audit_parent_exists(runtime.audit.path)
            else "created_on_first_audit",
        },
        {
            "name": "git",
            "status": _availability_status("git" in integrations, which("git") is not None),
            "detail": "not_enabled" if "git" not in integrations else "path_check_only",
        },
        {
            "name": "docker",
            "status": _availability_status(
                "docker" in integrations, find_spec("docker") is not None
            ),
            "detail": "not_enabled" if "docker" not in integrations else "sdk_check_only",
        },
        {
            "name": "bandit",
            "status": _availability_status(
                "security_scanners" in integrations, find_spec("bandit") is not None
            ),
            "detail": "not_enabled"
            if "security_scanners" not in integrations
            else "module_check_only",
        },
    ]
    typer.echo(
        json.dumps(
            {
                "status": "ready",
                "profile": runtime.settings.profile.value,
                "enabled_integrations": sorted(integrations),
                "checks": checks,
            },
            sort_keys=True,
        )
    )


def _audit_parent_exists(audit_path: Path) -> bool:
    return audit_path.parent.exists()


def _availability_status(enabled: bool, available: bool) -> str:
    if not enabled:
        return "skipped"
    return "pass" if available else "warning"
