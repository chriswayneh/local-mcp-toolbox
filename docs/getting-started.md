# Getting Started

## Run locally

Create a local virtual environment, install the project, and start the default restrictive profile:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev,docker]"
.\.venv\Scripts\local-mcp-toolbox serve --config config\restricted.yml
```

The stdio process must reserve standard output for MCP protocol messages. Operator errors are written to standard error; do not wrap the command in a shell tool exposed to an AI client.

## Generic MCP client configuration

Use the executable and arguments appropriate to the local checkout. This is a generic representation; clients name the enclosing MCP-server object differently.

```json
{
  "command": "C:\\path\\to\\Local MCP Toolbox\\.venv\\Scripts\\local-mcp-toolbox.exe",
  "args": [
    "serve",
    "--config",
    "C:\\path\\to\\Local MCP Toolbox\\config\\restricted.yml"
  ]
}
```

Start with `restricted.yml`. To inspect an approved project later, copy `config/example.yml`, declare the smallest possible set of absolute roots, and explicitly enable only the required local integrations.

## Current capabilities

The server exposes server metadata plus read-only system, approved-root filesystem, exact-allowlist Git, opt-in Docker inspection, and opt-in dedicated log-file inspection. Kubernetes, GitHub, and all mutating capabilities are not registered.

## Enable Docker inspection deliberately

Install the Docker extra and configure a standard profile with the integration enabled:

```yaml
profile: standard
integrations:
  docker: true
```

Docker tools use the local Docker API only for container listing, selected metadata, health status, and bounded log reads. They do not register lifecycle, exec, image, network, volume, label, mount, environment, or command-inspection operations. A Docker socket is a high-privilege host boundary; do not mount or expose one to an untrusted process, and use the smallest local Docker access necessary.

## Enable log-file inspection deliberately

Logs use independent approved roots, so observing an application log does not broaden the general filesystem module:

```yaml
profile: standard
integrations:
  logs: true
logs:
  approved_roots:
    - C:\\absolute\\path\\to\\application-logs
```

Log searches are literal strings only—user-provided regular expressions are never executed. Responses are bounded and redacted, and error summaries report observed lines and groups rather than asserting a root cause.
