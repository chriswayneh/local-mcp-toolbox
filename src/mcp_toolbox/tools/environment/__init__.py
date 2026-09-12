"""Read-only Python virtual-environment metadata auditing."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp.server import MCPServer

if TYPE_CHECKING:
    from mcp_toolbox.server.runtime import ServerRuntime


def register_environment_tools(
    server: MCPServer,
    runtime: ServerRuntime,
) -> tuple[str, ...]:
    """Load registration lazily to keep parser imports independent of server startup."""

    from mcp_toolbox.tools.environment.handlers import register_environment_tools as register

    return register(server, runtime)


__all__ = ["register_environment_tools"]
