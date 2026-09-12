# Authenticated Loopback HTTP

Version 1.5 provides an optional Streamable HTTP transport for local clients that
cannot use stdio. It is disabled by default and binds only to the literal loopback
addresses `127.0.0.1` or `::1`.

## Security contract

- The transport cannot bind to `localhost`, wildcard addresses, LAN addresses, or
  public interfaces.
- Every HTTP request requires exactly one strict bearer header.
- The raw token is loaded from a named environment variable at startup, hashed
  immediately, and never stored in settings, logs, audit events, responses, or
  verifier state.
- Token comparison uses fixed-length SHA-256 digests and constant-time comparison.
- Host and Origin values use exact allowlists to resist DNS rebinding.
- Request bodies, active sessions, and idle session duration are bounded before
  work reaches a tool.
- The server runs one process. Audit appends and segment rotation are synchronized
  inside that process.

The bearer token protects local access. It is not a substitute for TLS on a remote
network, and this release intentionally provides no remote bind option.

## Configuration

Copy an explicit standard policy and enable its `http` section:

```yaml
http:
  enabled: true
  host: 127.0.0.1
  port: 8765
  token_environment: LOCAL_MCP_TOOLBOX_HTTP_TOKEN
  max_request_body_bytes: 262144
  session_idle_seconds: 300
  max_sessions: 16
```

Generate and export a high-entropy token outside the repository. One PowerShell
example is:

```powershell
$env:LOCAL_MCP_TOOLBOX_HTTP_TOKEN = [Convert]::ToBase64String(
  [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
)
local-mcp-toolbox serve-http --config C:\absolute\path\to\policy.yml
```

Connect the client to `http://127.0.0.1:8765/mcp` and configure it to send the
token as `Authorization: Bearer <token>`. Do not place the token in YAML, command
arguments, repository files, issue reports, or screenshots.

Startup fails before socket binding when HTTP is disabled, the named environment
variable is absent, or the token does not meet the strict format and length rules.
