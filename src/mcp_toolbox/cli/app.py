"""Operator-facing commands for the MCP server and static security auditors."""

import json
from importlib.util import find_spec
from pathlib import Path
from shutil import which
from typing import Annotated

import typer

from mcp_toolbox.models import ToolboxError
from mcp_toolbox.server import load_runtime, run_http, run_stdio
from mcp_toolbox.tools.security.agent_audit import audit_agent_configs, format_text_report
from mcp_toolbox.tools.security.models import (
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_FILES,
    SEVERITY_RANK,
)

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


@app.command("serve-http")
def serve_http(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            help="Path to the explicit permission configuration file.",
        ),
    ] = Path("config/default.yml"),
) -> None:
    """Start authenticated Streamable HTTP on the configured loopback address."""

    try:
        runtime = load_runtime(config)
        run_http(runtime)
    except ToolboxError as error:
        typer.echo(f"{error.category}: {error.message}", err=True)
        raise typer.Exit(code=2) from error


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
        {
            "name": "environment",
            "status": "pass" if "environment" in integrations else "skipped",
            "detail": (
                "filesystem_metadata_only" if "environment" in integrations else "not_enabled"
            ),
        },
    ]
    warning = any(check["status"] == "warning" for check in checks)
    typer.echo(
        json.dumps(
            {
                "status": "attention" if warning else "ready",
                "profile": runtime.settings.profile.value,
                "enabled_integrations": sorted(integrations),
                "checks": checks,
            },
            sort_keys=True,
        )
    )


@app.command("audit-agent-configs")
def audit_agent_configs_cmd(
    target: Annotated[
        Path,
        typer.Argument(
            help="Directory or file path to audit for risky agent instructions and MCP configs.",
        ),
    ] = Path("."),
    include: Annotated[
        list[str] | None,
        typer.Option(
            "--include",
            "-i",
            help="Optional relative glob pattern(s) to scan instead of default discovery patterns.",
        ),
    ] = None,
    output_format: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: text or json.",
        ),
    ] = "text",
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit machine-readable JSON output.",
        ),
    ] = False,
    fail_on: Annotated[
        str,
        typer.Option(
            "--fail-on",
            help="Minimum finding severity that exits with code 1: low, medium, high, or none.",
        ),
    ] = "low",
    max_files: Annotated[
        int,
        typer.Option(
            "--max-files",
            help="Maximum number of candidate files to scan.",
        ),
    ] = DEFAULT_MAX_FILES,
    max_file_bytes: Annotated[
        int,
        typer.Option(
            "--max-file-bytes",
            help="Maximum readable size in bytes per file.",
        ),
    ] = DEFAULT_MAX_FILE_BYTES,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            help="Maximum number of findings returned in the report.",
        ),
    ] = 100,
) -> None:
    """Audit agent instruction, skill, prompt, and MCP config files without starting the server."""

    normalized_format = output_format.strip().lower()
    if normalized_format not in {"text", "json"}:
        typer.echo(
            "INVALID_INPUT: --format must be 'text' or 'json'.",
            err=True,
        )
        raise typer.Exit(code=2)
    if json_output:
        normalized_format = "json"

    normalized_fail_on = fail_on.strip().lower()
    if normalized_fail_on not in {"low", "medium", "high", "none"}:
        typer.echo(
            "INVALID_INPUT: --fail-on must be 'low', 'medium', 'high', or 'none'.",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        report, _ = audit_agent_configs(
            target,
            include_globs=include,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            limit=limit,
        )
    except ToolboxError as error:
        typer.echo(f"{error.category}: {error.message}", err=True)
        raise typer.Exit(code=2) from error

    if normalized_format == "json":
        typer.echo(json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True))
    else:
        typer.echo(format_text_report(report))

    if normalized_fail_on != "none":
        threshold_rank = SEVERITY_RANK[normalized_fail_on]
        should_fail = any(
            count > 0 and SEVERITY_RANK[sev] >= threshold_rank
            for sev, count in report.severity_counts.items()
        )
        if should_fail:
            raise typer.Exit(code=1)


def _audit_parent_exists(audit_path: Path) -> bool:
    return audit_path.parent.exists()


def _availability_status(enabled: bool, available: bool) -> str:
    if not enabled:
        return "skipped"
    return "pass" if available else "warning"
