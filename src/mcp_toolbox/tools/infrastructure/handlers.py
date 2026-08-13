"""Bounded detection of well-known top-level project infrastructure files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
_PROJECT_MARKERS = {
    "ansible": {"ansible.cfg"},
    "docker": {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    },
    "github_actions": {".github"},
    "go": {"go.mod"},
    "helm": {"chart.yaml"},
    "kubernetes": {"kustomization.yaml", "kustomization.yml"},
    "node": {"package.json"},
    "python": {"pyproject.toml", "requirements.txt", "setup.py"},
    "terraform": {"main.tf", "terraform.tf"},
}
_CONFIGURATION_FILES = {
    "ansible": {"ansible.cfg"},
    "container": {
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    },
    "deployment": {"chart.yaml", "kustomization.yaml", "kustomization.yml"},
    "infrastructure": {"main.tf", "terraform.tf"},
    "project": {"go.mod", "package.json", "pyproject.toml", "requirements.txt", "setup.py"},
}


def register_infrastructure_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register metadata-only infrastructure tools after explicit enablement."""

    if not runtime.permissions.check_integration("infrastructure").allowed:
        return ()

    @server.tool(
        name="infra_detect_project_types",
        title="Detect project types",
        description=(
            "Detect known project and infrastructure markers at an approved project's top level."
        ),
        annotations=_READ_ONLY,
    )
    def infra_detect_project_types(project: str) -> dict[str, Any]:
        """Return deterministic marker matches without reading any configuration content."""

        root = _require_project_root(runtime, project)
        names = {entry.name.lower() for entry in root.iterdir()}
        detected = sorted(
            project_type
            for project_type, markers in _PROJECT_MARKERS.items()
            if names.intersection(markers)
        )
        return bounded_response(
            runtime,
            "Detected project types from top-level marker names only.",
            {"project_types": detected, "top_level_marker_count": len(names)},
        )

    @server.tool(
        name="infra_configuration_inventory",
        title="Inventory infrastructure configuration",
        description=(
            "List bounded recognized infrastructure configuration names at an approved "
            "project's top level."
        ),
        annotations=_READ_ONLY,
    )
    def infra_configuration_inventory(project: str, limit: int = 50) -> dict[str, Any]:
        """Return file names and categories only; configuration contents are not read."""

        result_limit = require_bounded_limit(runtime, limit)
        root = _require_project_root(runtime, project)
        categorized = [
            {"name": entry.name, "category": _configuration_category(entry.name)}
            for entry in root.iterdir()
            if _configuration_category(entry.name) is not None
        ]
        inventory = sorted(categorized, key=lambda item: (str(item["category"]), str(item["name"])))
        page = inventory[:result_limit]
        return bounded_response(
            runtime,
            "Collected a top-level infrastructure configuration inventory without reading files.",
            {
                "items": page,
                "total_items": len(inventory),
                "truncated_items": len(inventory) > result_limit,
                "scope": "top_level_only",
            },
        )

    return ("infra_detect_project_types", "infra_configuration_inventory")


def _require_project_root(runtime: ServerRuntime, requested_path: str) -> Path:
    runtime.permissions.require_integration("infrastructure")
    root = runtime.permissions.infrastructure.require_directory(Path(requested_path))
    if not root.is_dir():
        raise ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved infrastructure project root was not found.",
            remediation="Pass an existing approved project directory path.",
        )
    return root


def _configuration_category(name: str) -> str | None:
    lowered = name.lower()
    for category, markers in _CONFIGURATION_FILES.items():
        if lowered in markers:
            return category
    return None
