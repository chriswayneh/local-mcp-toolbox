from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from mcp import Client

from mcp_toolbox.config.settings import (
    AuditSettings,
    IntegrationSettings,
    KubernetesSettings,
    PermissionProfile,
    ToolboxSettings,
)
from mcp_toolbox.server import build_runtime, create_server
from mcp_toolbox.tools.kubernetes.handlers import KubernetesGateway


def _settings(audit_path: Path) -> ToolboxSettings:
    return ToolboxSettings(
        profile=PermissionProfile.STANDARD,
        integrations=IntegrationSettings(kubernetes=True, external_network=True),
        kubernetes=KubernetesSettings(
            approved_contexts=["production"], approved_namespaces=["toolbox"]
        ),
        audit=AuditSettings(path=audit_path),
    )


def test_kubernetes_tools_return_allowlisted_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = SimpleNamespace(
        name="api-123", creation_timestamp="2026-09-12T00:00:00Z", deletion_timestamp=None
    )
    monkeypatch.setattr(
        KubernetesGateway,
        "cluster_version",
        lambda _self, _context: SimpleNamespace(
            git_version="v1.35.0", platform="linux/amd64", major="1", minor="35"
        ),
    )
    monkeypatch.setattr(
        KubernetesGateway,
        "namespace",
        lambda _self, _context, _namespace: SimpleNamespace(
            metadata=metadata, status=SimpleNamespace(phase="Active")
        ),
    )
    monkeypatch.setattr(
        KubernetesGateway,
        "pods",
        lambda _self, _context, _namespace, _limit: [
            SimpleNamespace(
                metadata=metadata,
                spec=SimpleNamespace(
                    node_name="node-1",
                    containers=[SimpleNamespace(name="api"), SimpleNamespace(name="sidecar")],
                ),
                status=SimpleNamespace(
                    phase="Running",
                    container_statuses=[
                        SimpleNamespace(ready=True, restart_count=1),
                        SimpleNamespace(ready=False, restart_count=0),
                    ],
                ),
            )
        ],
    )
    monkeypatch.setattr(
        KubernetesGateway,
        "deployments",
        lambda _self, _context, _namespace, _limit: [
            SimpleNamespace(
                metadata=SimpleNamespace(name="api", creation_timestamp="2026-09-12T00:00:00Z"),
                spec=SimpleNamespace(replicas=3),
                status=SimpleNamespace(
                    ready_replicas=2,
                    available_replicas=2,
                    updated_replicas=3,
                    unavailable_replicas=1,
                ),
            )
        ],
    )
    server = create_server(build_runtime(_settings(tmp_path / "audit.jsonl")))

    async def scenario() -> None:
        async with Client(server) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            version = await client.call_tool(
                "kubernetes_cluster_version",
                {"context": "production", "namespace": "toolbox"},
            )
            namespace = await client.call_tool(
                "kubernetes_namespace_summary",
                {"context": "production", "namespace": "toolbox"},
            )
            pods = await client.call_tool(
                "kubernetes_list_pods",
                {"context": "production", "namespace": "toolbox", "limit": 10},
            )
            deployments = await client.call_tool(
                "kubernetes_list_deployments",
                {"context": "production", "namespace": "toolbox", "limit": 10},
            )
            denied = await client.call_tool(
                "kubernetes_list_pods",
                {"context": "production", "namespace": "default", "limit": 10},
            )

            assert tools["kubernetes_list_pods"].annotations.open_world_hint is True
            assert version.structured_content["data"]["git_version"] == "v1.35.0"
            assert namespace.structured_content["data"]["phase"] == "Active"
            assert pods.structured_content["data"]["pods"][0]["ready_containers"] == 1
            assert pods.structured_content["data"]["pods"][0]["restart_count"] == 1
            assert (
                deployments.structured_content["data"]["deployments"][0]["unavailable_replicas"]
                == 1
            )
            assert denied.is_error is True
            assert denied.structured_content["category"] == "PERMISSION_DENIED"

    asyncio.run(scenario())


def test_kubernetes_tools_are_not_registered_without_opt_in(tmp_path: Path) -> None:
    server = create_server(
        build_runtime(ToolboxSettings(audit=AuditSettings(path=tmp_path / "audit.jsonl")))
    )

    async def scenario() -> None:
        async with Client(server) as client:
            names = {tool.name for tool in (await client.list_tools()).tools}
            assert not {name for name in names if name.startswith("kubernetes_")}

    asyncio.run(scenario())
