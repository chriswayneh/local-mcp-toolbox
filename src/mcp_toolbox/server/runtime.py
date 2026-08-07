"""Server runtime composition and startup validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mcp_toolbox.audit import JsonlAuditLogger
from mcp_toolbox.config import ToolboxSettings, load_settings
from mcp_toolbox.permissions import PermissionService
from mcp_toolbox.redaction import Redactor


@dataclass(frozen=True, slots=True)
class ServerRuntime:
    """Validated services shared by the MCP transport and registered modules."""

    settings: ToolboxSettings
    permissions: PermissionService
    redactor: Redactor
    audit: JsonlAuditLogger


def build_runtime(settings: ToolboxSettings) -> ServerRuntime:
    """Validate startup dependencies before accepting any MCP request."""

    permissions = PermissionService(settings)
    redactor = Redactor(settings.redaction)
    audit = JsonlAuditLogger(settings.audit.path, redactor)
    return ServerRuntime(settings, permissions, redactor, audit)


def load_runtime(config_path: Path) -> ServerRuntime:
    """Load validated settings from one explicit configuration file."""

    return build_runtime(load_settings(config_path))
