"""Read-only, allowlisted Kubernetes metadata tools."""

from mcp_toolbox.tools.kubernetes.handlers import register_kubernetes_tools

__all__ = ["register_kubernetes_tools"]
