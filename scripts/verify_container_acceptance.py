"""Read-only acceptance against explicitly named synthetic demo containers.

Build the toolbox image and start the documented demo and socket proxy first.
This script creates only an ephemeral toolbox process with a temporary audit
filesystem. It does not start, stop, or modify the inspected containers.
"""

from __future__ import annotations

import argparse
import asyncio
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def verify(image: str, network: str, healthy: str, unhealthy: str) -> None:
    parameters = StdioServerParameters(
        command="docker",
        args=[
            "run",
            "--rm",
            "-i",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--network",
            network,
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",  # noqa: S108
            "--tmpfs",
            "/var/lib/local-mcp-toolbox/audit:uid=10001,gid=10001,size=16m",
            "--env",
            "DOCKER_HOST=tcp://docker-socket-proxy:2375",
            image,
            "serve",
            "--config",
            "/app/config/container-docker.yml",
        ],
    )
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as errlog:
        async with stdio_client(parameters, errlog=errlog) as (read, write):
            async with ClientSession(read, write) as client:
                await client.initialize()
                tools = {tool.name for tool in (await client.list_tools()).tools}
                if "docker_container_details" not in tools:
                    raise RuntimeError("Docker tools are not registered")
                for container, expected_health in ((healthy, "healthy"), (unhealthy, "unhealthy")):
                    result = await client.call_tool(
                        "docker_container_details", {"container": container}
                    )
                    if result.is_error:
                        raise RuntimeError(f"Container detail failed: {result.structured_content}")
                    data = result.structured_content["data"]
                    if data["health"] != expected_health:
                        raise RuntimeError(f"Expected {expected_health}, received {data['health']}")
                    print(f"PASS: {container}: {expected_health}")
                logs = await client.call_tool(
                    "docker_container_logs", {"container": unhealthy, "tail": 5}
                )
                if logs.is_error:
                    raise RuntimeError("Bounded synthetic container logs failed")
                denied = await client.call_tool(
                    "docker_container_logs", {"container": unhealthy, "tail": 101}
                )
                if not denied.is_error or denied.structured_content["category"] != "INVALID_INPUT":
                    raise RuntimeError("Oversized Docker log request was not denied")
                print("PASS: bounded logs and oversized-request denial over container stdio")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--network", required=True)
    parser.add_argument("--healthy", required=True)
    parser.add_argument("--unhealthy", required=True)
    args = parser.parse_args()
    asyncio.run(
        asyncio.wait_for(verify(args.image, args.network, args.healthy, args.unhealthy), 60)
    )


if __name__ == "__main__":
    main()
