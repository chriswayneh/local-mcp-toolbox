"""Read-only Kubernetes metadata inspection through the official SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_READ_ONLY_EXTERNAL = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)


@dataclass(frozen=True, slots=True)
class KubernetesClients:
    core: Any
    apps: Any
    version: Any


class KubernetesGateway:
    """Lazy official-SDK adapter that exposes no mutation operations."""

    def __init__(self, runtime: ServerRuntime) -> None:
        self._timeout = runtime.settings.limits.timeout_seconds

    def clients(self, context: str) -> KubernetesClients:
        try:
            from kubernetes import client, config  # type: ignore[import-not-found]
        except ImportError as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "Kubernetes support is not installed for this server.",
                remediation="Install the project kubernetes extra before enabling it.",
            ) from error
        try:
            api_client = config.new_client_from_config(context=context)
            return KubernetesClients(
                core=client.CoreV1Api(api_client),
                apps=client.AppsV1Api(api_client),
                version=client.VersionApi(api_client),
            )
        except Exception as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "The approved Kubernetes context could not be loaded.",
                remediation="Check kubeconfig access and the configured context name.",
            ) from error

    def cluster_version(self, context: str) -> Any:
        return self._call(
            lambda: self.clients(context).version.get_code(_request_timeout=self._timeout)
        )

    def namespace(self, context: str, namespace: str) -> Any:
        return self._call(
            lambda: self.clients(context).core.read_namespace(
                namespace, _request_timeout=self._timeout
            )
        )

    def pods(self, context: str, namespace: str, limit: int) -> list[Any]:
        response = self._call(
            lambda: self.clients(context).core.list_namespaced_pod(
                namespace, limit=limit, watch=False, _request_timeout=self._timeout
            )
        )
        return list(getattr(response, "items", []))

    def deployments(self, context: str, namespace: str, limit: int) -> list[Any]:
        response = self._call(
            lambda: self.clients(context).apps.list_namespaced_deployment(
                namespace, limit=limit, watch=False, _request_timeout=self._timeout
            )
        )
        return list(getattr(response, "items", []))

    @staticmethod
    def _call(operation: Any) -> Any:
        try:
            return operation()
        except ToolboxError:
            raise
        except Exception as error:
            status = getattr(error, "status", None)
            if status in {401, 403}:
                raise ToolboxError(
                    ErrorCategory.AUTHENTICATION_FAILED,
                    "Kubernetes rejected access to the approved scope.",
                    remediation="Check kubeconfig credentials and RBAC read permissions.",
                ) from error
            if status == 404:
                raise ToolboxError(
                    ErrorCategory.RESOURCE_NOT_FOUND,
                    "The approved Kubernetes resource was not found.",
                    remediation="Check the configured context and namespace.",
                ) from error
            if status == 429:
                raise ToolboxError(
                    ErrorCategory.RATE_LIMITED,
                    "The Kubernetes API rate limit was reached.",
                    remediation="Retry later or lower the requested result limit.",
                ) from error
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "The Kubernetes API request could not be completed.",
                remediation="Check cluster availability and kubeconfig connectivity.",
            ) from error


def register_kubernetes_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register metadata-only Kubernetes tools after explicit opt-in."""

    if not runtime.permissions.check_integration("kubernetes").allowed:
        return ()
    gateway = KubernetesGateway(runtime)

    @server.tool(
        name="kubernetes_cluster_version",
        title="Kubernetes cluster version",
        description="Return version metadata for an approved Kubernetes context and namespace.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def kubernetes_cluster_version(context: str, namespace: str) -> dict[str, Any]:
        approved_context, _ = runtime.permissions.require_kubernetes_scope(context, namespace)
        version = gateway.cluster_version(approved_context)
        return bounded_response(
            runtime,
            "Collected Kubernetes cluster version metadata.",
            {
                "context": approved_context,
                "git_version": getattr(version, "git_version", None),
                "platform": getattr(version, "platform", None),
                "major": getattr(version, "major", None),
                "minor": getattr(version, "minor", None),
            },
        )

    @server.tool(
        name="kubernetes_namespace_summary",
        title="Kubernetes namespace summary",
        description="Return lifecycle metadata for one approved context and namespace.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def kubernetes_namespace_summary(context: str, namespace: str) -> dict[str, Any]:
        approved_context, approved_namespace = runtime.permissions.require_kubernetes_scope(
            context, namespace
        )
        item = gateway.namespace(approved_context, approved_namespace)
        metadata = getattr(item, "metadata", None)
        status = getattr(item, "status", None)
        return bounded_response(
            runtime,
            "Collected Kubernetes namespace metadata.",
            {
                "context": approved_context,
                "namespace": approved_namespace,
                "phase": getattr(status, "phase", None),
                "created_at": _timestamp(getattr(metadata, "creation_timestamp", None)),
                "deletion_requested_at": _timestamp(getattr(metadata, "deletion_timestamp", None)),
            },
        )

    @server.tool(
        name="kubernetes_list_pods",
        title="List Kubernetes pods",
        description="Return bounded safe pod metadata from an approved namespace.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def kubernetes_list_pods(context: str, namespace: str, limit: int = 50) -> dict[str, Any]:
        approved_context, approved_namespace = runtime.permissions.require_kubernetes_scope(
            context, namespace
        )
        result_limit = require_bounded_limit(runtime, limit)
        pods = [
            _pod_summary(item)
            for item in gateway.pods(approved_context, approved_namespace, result_limit)
        ]
        return bounded_response(
            runtime,
            f"Collected {len(pods)} Kubernetes pods.",
            {
                "context": approved_context,
                "namespace": approved_namespace,
                "pods": pods,
            },
        )

    @server.tool(
        name="kubernetes_list_deployments",
        title="List Kubernetes deployments",
        description="Return bounded safe deployment metadata from an approved namespace.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def kubernetes_list_deployments(
        context: str, namespace: str, limit: int = 50
    ) -> dict[str, Any]:
        approved_context, approved_namespace = runtime.permissions.require_kubernetes_scope(
            context, namespace
        )
        result_limit = require_bounded_limit(runtime, limit)
        deployments = [
            _deployment_summary(item)
            for item in gateway.deployments(approved_context, approved_namespace, result_limit)
        ]
        return bounded_response(
            runtime,
            f"Collected {len(deployments)} Kubernetes deployments.",
            {
                "context": approved_context,
                "namespace": approved_namespace,
                "deployments": deployments,
            },
        )

    return (
        "kubernetes_cluster_version",
        "kubernetes_namespace_summary",
        "kubernetes_list_pods",
        "kubernetes_list_deployments",
    )


def _pod_summary(item: Any) -> dict[str, Any]:
    metadata = getattr(item, "metadata", None)
    spec = getattr(item, "spec", None)
    status = getattr(item, "status", None)
    container_statuses = getattr(status, "container_statuses", None) or []
    containers = getattr(spec, "containers", None) or []
    ready = sum(bool(getattr(container, "ready", False)) for container in container_statuses)
    restarts = sum(int(getattr(container, "restart_count", 0)) for container in container_statuses)
    return {
        "name": getattr(metadata, "name", None),
        "phase": getattr(status, "phase", None),
        "node": getattr(spec, "node_name", None),
        "ready_containers": ready,
        "total_containers": len(containers),
        "restart_count": restarts,
        "created_at": _timestamp(getattr(metadata, "creation_timestamp", None)),
    }


def _deployment_summary(item: Any) -> dict[str, Any]:
    metadata = getattr(item, "metadata", None)
    spec = getattr(item, "spec", None)
    status = getattr(item, "status", None)
    return {
        "name": getattr(metadata, "name", None),
        "desired_replicas": getattr(spec, "replicas", None),
        "ready_replicas": getattr(status, "ready_replicas", None) or 0,
        "available_replicas": getattr(status, "available_replicas", None) or 0,
        "updated_replicas": getattr(status, "updated_replicas", None) or 0,
        "unavailable_replicas": getattr(status, "unavailable_replicas", None) or 0,
        "created_at": _timestamp(getattr(metadata, "creation_timestamp", None)),
    }


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    return str(isoformat()) if callable(isoformat) else str(value)
