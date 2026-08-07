"""MCP server lifecycle and modular registration."""

from mcp_toolbox.server.app import create_server, run_stdio
from mcp_toolbox.server.runtime import ServerRuntime, build_runtime, load_runtime

__all__ = ["ServerRuntime", "build_runtime", "create_server", "load_runtime", "run_stdio"]
