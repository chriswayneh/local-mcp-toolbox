"""MCP registration for read-only Python virtual-environment auditing."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.tools.common import bounded_response, require_bounded_limit
from mcp_toolbox.tools.environment.inspection import PythonEnvironmentInspector
from mcp_toolbox.tools.environment.models import EnvironmentAuditRequest

if TYPE_CHECKING:
    from mcp_toolbox.server.runtime import ServerRuntime

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


def register_environment_tools(
    server: MCPServer,
    runtime: ServerRuntime,
) -> tuple[str, ...]:
    """Register the auditor only after explicit environment-integration opt-in."""

    if not runtime.permissions.check_integration("environment").allowed:
        return ()
    inspector = PythonEnvironmentInspector(runtime)

    @server.tool(
        name="environment_audit_python_venv",
        title="Audit approved Python virtual environment",
        description=(
            "Inspect bounded configuration and installed-package metadata from an approved "
            "Python virtual environment without executing or importing it."
        ),
        annotations=_READ_ONLY,
    )
    def environment_audit_python_venv(
        environment_path: str,
        limit: int = 100,
    ) -> dict[str, Any]:
        request = EnvironmentAuditRequest(environment_path=environment_path, limit=limit)
        result_limit = require_bounded_limit(runtime, request.limit)
        environment = runtime.permissions.require_python_environment(Path(request.environment_path))
        report = inspector.inspect(environment, result_limit)
        return bounded_response(
            runtime,
            (
                "Audited bounded Python environment metadata. No interpreter or installed "
                "package was executed or imported."
            ),
            report.model_dump(mode="json"),
        )

    return ("environment_audit_python_venv",)
