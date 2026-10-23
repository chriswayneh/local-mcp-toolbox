# Synthetic agent configuration audit fixtures

These local-only fixtures exercise `local-mcp-toolbox audit-agent-configs` and the
`security_audit_agent_configs` MCP tool without real credentials or runnable payloads.

- `benign/` contains clean `AGENTS.md`, `skills/code-review/SKILL.md`, and `.mcp.json`
  files that pass the audit with exit code 0.
- `risky/` contains intentionally unsafe synthetic instruction and MCP configuration
  files covering all five detection categories (`hidden_unicode`, `prompt_override`,
  `dangerous_execution`, `credential_or_exfil`, and `mcp_config_risk`). Do not copy
  or use `risky/` in an agent workspace.
