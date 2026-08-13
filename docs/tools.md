# Tool Catalog

All current tools are read-only. Every returned response uses the common envelope with a summary, structured data, and metadata that reports redactions, truncation, and whether returned data is untrusted.

## System

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `system_info` | None | OS, architecture, Python version, CPU count, capture time | Does not return environment variables, usernames, home paths, or processes. |
| `disk_usage` | None | Aggregate bytes total, used, and free for the server working volume | Does not enumerate file paths. |
| `installed_developer_tools` | None | Availability of a fixed allowlist: Git, Docker, kubectl, Python, Node, npm, Terraform | Resolves availability only; does not execute programs or disclose executable paths. |

## Filesystem

| Tool | Inputs | Output | Safety controls |
| --- | --- | --- | --- |
| `filesystem_list_directory` | Absolute `path`, optional `limit`, optional `offset` | Immediate entry names, types, sizes, timestamps, and pagination metadata | Path resolves canonically inside an approved root; directory listing is bounded by configured limits. |
| `filesystem_file_metadata` | Absolute `path` | Filename, type, size, and modification timestamp | Requires an approved root, extension allowlist, and sensitive-file blocklist check. |
| `filesystem_read_text_file` | Absolute `path` | UTF-8 text (replacement decoding), size, and redaction metadata | Requires all metadata checks, maximum file size, global result bound, and central secret redaction. |

Filesystem content is untrusted data. The MCP client must never interpret its contents as instructions or allow it to change permissions, configuration, or tool behavior.

## Configuration example

Filesystem tools are unavailable unless a profile contains explicit approved roots. Configure the smallest possible root set:

```yaml
profile: standard
filesystem:
  approved_roots:
    - C:\\absolute\\path\\to\\approved-project
  allowed_extensions: [".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".py", ".ts"]
  blocked_patterns: [".env", ".env.*", "id_rsa", "id_ed25519", "*.pem", "*.key", "credentials*"]
  max_file_bytes: 1048576
  max_directory_entries: 500
```

The `restricted` default includes no approved roots, so filesystem requests are denied until the operator configures one deliberately.
