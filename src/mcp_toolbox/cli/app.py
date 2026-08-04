"""CLI commands are added with the secure core foundation."""

import typer

app = typer.Typer(
    name="local-mcp-toolbox",
    help="Secure, local-first MCP environment inspection.",
    no_args_is_help=True,
)
