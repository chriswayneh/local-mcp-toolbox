# Client configuration

Local MCP Toolbox is a local **stdio** server.  A client starts it, writes MCP
messages to its standard input, and reads protocol responses from its standard
output.  There is no HTTP listener in Version 1.

## Prepare the server

Install the project and validate the restrictive profile before adding it to a
client:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev,docker]"
.\.venv\Scripts\local-mcp-toolbox doctor --config config\restricted.yml
```

Use absolute paths in the client configuration.  On Windows, the executable is
normally `.venv\\Scripts\\local-mcp-toolbox.exe`; on macOS and Linux it is
normally `.venv/bin/local-mcp-toolbox`.

Do not add a shell wrapper that prints banners or diagnostics to stdout.  It
would corrupt the stdio protocol.  Server diagnostics belong on stderr.

## Copy-ready templates

The repository maintains templates with intentionally unresolved paths:

| Client | File | Installation notes |
| --- | --- | --- |
| Codex | [`examples/codex/config.toml`](../examples/codex/config.toml) | Add the table to `~/.codex/config.toml`, replace both paths, then restart Codex. |
| Claude Desktop | [`examples/claude-desktop/claude_desktop_config.json`](../examples/claude-desktop/claude_desktop_config.json) | Merge the `mcpServers.local-mcp-toolbox` entry into the client configuration. |
| Claude Code | [`examples/claude-code/.mcp.json`](../examples/claude-code/.mcp.json) | Set the two environment variables and place or merge the file at the project scope. |
| VS Code | [`examples/vscode/mcp.json`](../examples/vscode/mcp.json) | Save as `.vscode/mcp.json`, replacing both paths. |

Claude Code supports environment expansion in project `.mcp.json` files, so its
template avoids committing machine-specific paths.  VS Code's current stdio
schema uses a `servers` object and a `type` of `stdio`; its workspace
configuration lives in `.vscode/mcp.json`.  Consult the respective client docs
when upgrading: [Claude Code MCP](https://docs.anthropic.com/en/docs/claude-code/mcp),
[VS Code MCP configuration](https://code.visualstudio.com/docs/agents/reference/mcp-configuration),
and [Codex configuration](https://help.openai.com/en/articles/20001253-configure-codex-with-amazon-bedrock).

## Configure access separately from the client

Adding a client entry only permits that client to start the process.  It does
not expand the server's own permissions.

1. Copy `config/restricted.yml` to a local, untracked path.
2. Add only the exact approved roots and explicit integration allowlists needed
   for the task.
3. Run `doctor` against that profile.
4. Start the client and verify `toolbox_server_status` before enabling further
   modules.

Never configure an AI client with `config/default.yml` merely to avoid setup
work.  Profiles are part of the authorization boundary, not presentation
preferences.

## Container clients

The standard recommendation for a desktop client is a native virtual
environment.  A container is appropriate only when the client is explicitly
configured to keep the container attached in the foreground with stdin and
stdout connected.  Do not use Docker detach mode for an stdio server.  See
[container deployment](docker.md) for the least-privilege container profiles.
