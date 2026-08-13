# Operator troubleshooting

Use non-mutating checks first.  The server is intentionally narrow: a denied
request is usually evidence that an authorization boundary is working.

## First checks

```powershell
.\.venv\Scripts\local-mcp-toolbox doctor --config config\restricted.yml
.\.venv\Scripts\local-mcp-toolbox serve --config config\restricted.yml
```

`doctor` validates YAML, profile invariants, approved roots, audit-log
parent access, Git availability, optional Docker SDK availability, and Bandit
availability.  `serve` reserves stdout for MCP traffic; inspect stderr for
startup errors.

| Symptom | Likely cause | Safe response |
| --- | --- | --- |
| Client cannot start the server | Incorrect executable or configuration path | Use an absolute path and run `doctor` with that exact profile. |
| Client reports malformed MCP messages | A wrapper, banner, or debug output wrote to stdout | Remove the wrapper/output; keep diagnostics on stderr only. |
| A tool is missing | Its module is disabled in the profile | Enable only the required module, then restart the client so it rediscovers tools. |
| A path is denied | It is outside an approved root, traverses through a symlink, or matches a sensitive-file blocklist | Add the smallest canonical parent root that is genuinely in scope; do not weaken the blocklist. |
| Git inspection is denied | Repository is not on the exact allowlist | Add that repository's resolved path to the Git allowlist. |
| Docker tools are unavailable | Docker is disabled, the SDK is absent, or a socket endpoint is unreachable | Use native execution or the socket-proxy profile; avoid a direct socket mount where possible. |
| Container has no expected tools | Client is using a container profile that does not authorize the module | Select the intended Compose profile and restart the attached stdio process. |
| Logs look incomplete | File, line, byte, or result limits were reached | Narrow the search or request a bounded time/file range; do not raise limits indiscriminately. |
| Sensitive text is replaced | Redaction detected credential-like material | Treat the result as expected; use the fingerprint in the audit trail for correlation. |
| Audit file is missing | Parent directory is absent or unwritable | Create a dedicated local audit directory with appropriate OS permissions and rerun `doctor`. |

## Client-specific checks

- **Codex:** after editing `~/.codex/config.toml`, restart the desktop app or
  extension. Confirm the executable and YAML paths are absolute.
- **Claude Code:** ensure `LOCAL_MCP_TOOLBOX_EXE` and
  `LOCAL_MCP_TOOLBOX_CONFIG` are set in the process environment before it
  reads `.mcp.json`. Reset project approvals if the configuration changed.
- **Claude Desktop:** validate the JSON after merging the server entry; a
  trailing comma prevents startup.
- **VS Code:** open `.vscode/mcp.json`, use the MCP server list to start or
  restart the server, and view its output for client-side diagnostics.

## Docker checks

```powershell
docker compose -f compose.yaml config
docker compose --profile core run --rm -i toolbox doctor --config /app/config/container.yml
docker compose --profile docker run --rm -i toolbox-docker doctor --config /app/config/container-docker.yml
```

Do not run an stdio container with `-d`.  If Docker inspection is needed,
prefer the socket-proxy profile.  A direct `/var/run/docker.sock` mount is an
advanced, host-control-risk configuration and should not be used as a quick
fix.

## Escalation data

When filing a local issue, provide the profile name, operating system, client
and version, the safe command that failed, sanitized stderr, and the `doctor`
result.  Never include audit content containing real secrets, configuration
files with credentials, or a Docker socket.
