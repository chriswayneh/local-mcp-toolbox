# Getting Started

## Run locally

Create a local virtual environment, install the project, and start the default restrictive profile:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
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

Phase 3 registers server-generated metadata resources, safety prompts, and the read-only `toolbox_server_status` tool. It does not yet inspect the local filesystem, Git, Docker, logs, or Kubernetes. Those collection modules are the next implementation phase.
