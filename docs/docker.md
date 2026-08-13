# Container deployment

The MCP server uses stdio, so the primary container workflow is for controlled local integration rather than a network service. The production image runs as UID/GID `10001`, uses a read-only root filesystem in Compose, drops Linux capabilities, sets `no-new-privileges`, limits writable storage to `/tmp` and the audit volume, and provides a non-mutating `doctor` health check.

## Build and validate

```powershell
docker compose -f compose.yaml config
docker build --tag local-mcp-toolbox:local .
docker run --rm --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m local-mcp-toolbox:local doctor --config /app/config/container.yml
```

Use the core profile only when a client will attach to the container's standard input and output:

```powershell
docker compose --profile core run --rm -i toolbox
```

The container's standard output is reserved for the MCP protocol. Do not wrap it in an AI-exposed shell command.

## Docker inspection through a socket proxy

The recommended Docker-enabled profile uses `tecnativa/docker-socket-proxy:0.5.0` and grants only the container-listing API needed by the current read-only tools:

```powershell
docker compose --profile docker run --rm -i toolbox-docker
```

The proxy owns the host socket mount; the MCP container receives only the internal TCP endpoint. The profile disables `POST`, image, network, and volume access. Review and further restrict the proxy environment flags for your Docker API and threat model.

## Direct socket mount: advanced only

`compose.direct-socket.yaml` is provided only for environments where a socket proxy cannot be used:

```powershell
docker compose -f compose.yaml -f compose.direct-socket.yaml --profile direct-docker run --rm -i toolbox-direct-docker
```

Mounting `/var/run/docker.sock` can effectively grant control of the host even when a client application exposes only read-only Docker methods. Never use it with untrusted images, untrusted users, or an internet-exposed MCP transport. Prefer native host execution or the socket-proxy profile.

## Development container

```powershell
docker compose -f compose.yaml -f compose.dev.yaml --profile development run --rm toolbox-dev
```

The development profile bind-mounts the checkout and is intended for an interactive maintainer shell. It is not a production deployment.
