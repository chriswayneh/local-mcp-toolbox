"""Read-only, dependency-free system inspection handlers."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from datetime import UTC, datetime
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response

_DEVELOPER_TOOLS = ("git", "docker", "kubectl", "python", "node", "npm", "terraform")


def register_system_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register non-invasive host metadata tools without shell execution."""

    @server.tool(
        name="system_info",
        title="System information",
        description=(
            "Return sanitized OS and runtime metadata without reading environment variables."
        ),
        annotations=_READ_ONLY,
    )
    def system_info() -> dict[str, Any]:
        """Return stable metadata from the Python standard library."""

        return bounded_response(
            runtime,
            "Collected local system metadata.",
            {
                "operating_system": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "python_version": sys.version.split()[0],
                "cpu_count": os.cpu_count(),
                "captured_at": datetime.now(UTC).isoformat(),
            },
            untrusted_content=False,
        )

    @server.tool(
        name="disk_usage",
        title="Disk usage",
        description="Return disk capacity for the server's current working volume.",
        annotations=_READ_ONLY,
    )
    def disk_usage() -> dict[str, Any]:
        """Return aggregate capacity without exposing directory contents."""

        usage = shutil.disk_usage(os.getcwd())
        return bounded_response(
            runtime,
            "Collected disk capacity for the current working volume.",
            {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
            },
            untrusted_content=False,
        )

    @server.tool(
        name="installed_developer_tools",
        title="Installed developer tools",
        description="Report availability of an allowlisted set of common developer tools.",
        annotations=_READ_ONLY,
    )
    def installed_developer_tools() -> dict[str, Any]:
        """Use executable resolution only; do not invoke or disclose executable paths."""

        return bounded_response(
            runtime,
            "Checked the availability of allowlisted developer tools.",
            {
                "tools": [
                    {"name": name, "available": shutil.which(name) is not None}
                    for name in _DEVELOPER_TOOLS
                ]
            },
            untrusted_content=False,
        )

    return ("system_info", "disk_usage", "installed_developer_tools")


_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
