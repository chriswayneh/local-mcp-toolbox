"""Operator-facing commands for the MCP server."""

from pathlib import Path
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
