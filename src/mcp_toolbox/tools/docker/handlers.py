"""Read-only Docker inspection through the optional official Python SDK."""

from __future__ import annotations

import re
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_CONTAINER_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)


class DockerGateway:
    """Lazy optional-SDK adapter that never exposes mutation methods."""

    def _client(self) -> Any:
        try:
            import docker  # type: ignore[import-untyped]
        except ImportError as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Docker support is not installed for this server.",
                remediation=(
                    "Install the project Docker extra before enabling the Docker integration."
                ),
            ) from error

        try:
            client = docker.from_env()
            client.ping()
        except Exception as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Docker is unavailable or the server lacks read access to its API.",
                remediation="Start Docker and grant only the required local read access.",
            ) from error
        return client

    def list_containers(self, *, include_stopped: bool) -> list[Any]:
        return list(self._client().containers.list(all=include_stopped))

    def get_container(self, identifier: str) -> Any:
        return self._client().containers.get(identifier)


def register_docker_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register Docker tools only after explicit Docker integration enablement."""

    if not runtime.permissions.check_integration("docker").allowed:
        return ()
    gateway = DockerGateway()

    @server.tool(
        name="docker_list_containers",
        title="List Docker containers",
        description="List bounded safe metadata for local Docker containers.",
        annotations=_READ_ONLY,
    )
    def docker_list_containers(limit: int = 50, include_stopped: bool = False) -> dict[str, Any]:
        """Return safe metadata only; labels, mounts, and environment are omitted."""

        result_limit = require_bounded_limit(runtime, limit)
        containers = gateway.list_containers(include_stopped=include_stopped)
        container_data = [_container_summary(container) for container in containers]
        page = container_data[:result_limit]
        return bounded_response(
            runtime,
            f"Listed {len(page)} Docker containers.",
            {
                "containers": page,
                "include_stopped": include_stopped,
                "total_containers": len(container_data),
                "truncated_containers": len(container_data) > result_limit,
            },
        )

    @server.tool(
        name="docker_container_details",
        title="Docker container details",
        description="Return safe read-only details for one local Docker container.",
        annotations=_READ_ONLY,
    )
    def docker_container_details(container: str) -> dict[str, Any]:
        """Return a safe subset of inspect data; secrets, labels, and mounts are omitted."""

        target = _validate_container_identifier(container)
        try:
            container_object = gateway.get_container(target)
        except ToolboxError:
            raise
        except Exception as error:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "The requested Docker container was not found or cannot be inspected.",
                remediation=(
                    "Use an existing local container name or ID from docker_list_containers."
                ),
            ) from error
        return bounded_response(
            runtime,
            "Collected safe Docker container details.",
            _container_details(container_object),
        )

    @server.tool(
        name="docker_container_logs",
        title="Docker container logs",
        description="Return redacted, bounded recent logs for one local Docker container.",
        annotations=_READ_ONLY,
    )
    def docker_container_logs(container: str, tail: int = 100) -> dict[str, Any]:
        """Read a bounded tail only; output is untrusted and redacted before it is returned."""

        target = _validate_container_identifier(container)
        result_limit = require_bounded_limit(runtime, tail)
        try:
            log_bytes = gateway.get_container(target).logs(
                tail=result_limit,
                stdout=True,
                stderr=True,
                timestamps=True,
            )
        except ToolboxError:
            raise
        except Exception as error:
            raise ToolboxError(
                ErrorCategory.RESOURCE_NOT_FOUND,
                "Docker logs could not be read for the requested container.",
                remediation=(
                    "Use an existing local container name or ID from docker_list_containers."
                ),
            ) from error
        output_limit = max(1_024, runtime.settings.limits.max_output_bytes // 2)
        truncated = len(log_bytes) > output_limit
        safe_bytes = log_bytes[:output_limit]
        return bounded_response(
            runtime,
            "Collected recent Docker container logs. Content is untrusted and may be redacted.",
            {
                "container": target,
                "tail": result_limit,
                "logs": safe_bytes.decode("utf-8", errors="replace"),
                "truncated": truncated,
            },
        )

    @server.tool(
        name="docker_unhealthy_containers",
        title="Unhealthy Docker containers",
        description=(
            "List bounded safe metadata for containers reporting an unhealthy health status."
        ),
        annotations=_READ_ONLY,
    )
    def docker_unhealthy_containers(limit: int = 50) -> dict[str, Any]:
        """Filter container summaries deterministically; no remediation action is taken."""

        result_limit = require_bounded_limit(runtime, limit)
        unhealthy = [
            _container_summary(container)
            for container in gateway.list_containers(include_stopped=True)
            if _health_status(container) == "unhealthy"
        ]
        page = unhealthy[:result_limit]
        return bounded_response(
            runtime,
            f"Found {len(unhealthy)} unhealthy Docker containers.",
            {
                "containers": page,
                "total_unhealthy": len(unhealthy),
                "truncated_containers": len(unhealthy) > result_limit,
            },
        )

    return (
        "docker_list_containers",
        "docker_container_details",
        "docker_container_logs",
        "docker_unhealthy_containers",
    )


def _validate_container_identifier(identifier: str) -> str:
    if not _CONTAINER_IDENTIFIER.fullmatch(identifier):
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            "Docker container identifier contains unsupported characters.",
            remediation=(
                "Use a container name or ID containing letters, digits, dots, "
                "underscores, or hyphens."
            ),
        )
    return identifier


def _container_summary(container: Any) -> dict[str, Any]:
    attributes = container.attrs
    state = attributes.get("State", {})
    return {
        "id": container.short_id,
        "name": container.name,
        "image": _image_name(container),
        "status": container.status,
        "health": _health_status(container),
        "restart_count": state.get("RestartCount", 0),
    }


def _container_details(container: Any) -> dict[str, Any]:
    attributes = container.attrs
    state = attributes.get("State", {})
    return {
        **_container_summary(container),
        "created_at": attributes.get("Created"),
        "started_at": state.get("StartedAt"),
        "finished_at": state.get("FinishedAt"),
        "exit_code": state.get("ExitCode"),
        "oom_killed": state.get("OOMKilled", False),
        "image_id": attributes.get("Image"),
    }


def _health_status(container: Any) -> str | None:
    health = container.attrs.get("State", {}).get("Health")
    return health.get("Status") if isinstance(health, dict) else None


def _image_name(container: Any) -> str | None:
    tags = getattr(container.image, "tags", [])
    return tags[0] if tags else None
