# Client configuration examples

These examples start the server over standard input/output.  Use the installed
`local-mcp-toolbox` executable from a virtual environment and pass an explicit
profile.  Do not put secrets in a client configuration file.

Before copying an example, replace these placeholders with absolute paths for
your machine:

| Placeholder | Windows example | macOS/Linux example |
| --- | --- | --- |
| `<TOOLBOX_EXE>` | `C:\\dev\\AI\\MCP Toolbox\\.venv\\Scripts\\local-mcp-toolbox.exe` | `/home/alex/local-mcp-toolbox/.venv/bin/local-mcp-toolbox` |
| `<CONFIG_FILE>` | `C:\\dev\\AI\\MCP Toolbox\\config\\restricted.yml` | `/home/alex/local-mcp-toolbox/config/restricted.yml` |

Start with `restricted.yml`.  It does not authorize project, Git, Docker, log,
scanner, or infrastructure access.  To enable an inspection module, copy a
profile, add only the needed canonical roots or integration allowlists, run
`local-mcp-toolbox doctor --config <CONFIG_FILE>`, and review
[the permission guide](../docs/permissions.md).

The client owns process startup; the server's stdout is MCP protocol traffic.
Keep shell output, wrappers, and diagnostic logging off stdout.  Server startup
errors are written to stderr.

| Client | Example | Scope |
| --- | --- | --- |
| Codex | [codex/config.toml](codex/config.toml) | User configuration block |
| Claude Desktop | [claude-desktop/claude_desktop_config.json](claude-desktop/claude_desktop_config.json) | User configuration entry |
| Claude Code | [claude-code/.mcp.json](claude-code/.mcp.json) | Project configuration entry |
| Visual Studio Code | [vscode/mcp.json](vscode/mcp.json) | `.vscode/mcp.json` entry |

The files contain placeholders deliberately, so they are safe to commit and
share.  Refer to each client's current configuration documentation before
changing transport or permission behavior.
