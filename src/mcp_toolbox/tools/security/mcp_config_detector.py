"""Category 5 detector: inspect MCP JSON configuration files for risky server definitions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from mcp_toolbox.redaction import Redactor
from mcp_toolbox.tools.security.models import (
    MAX_SNIPPET_CHARS,
    AgentConfigFinding,
    AuditCategory,
    AuditSeverity,
)

BIDI_CODEPOINTS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        *range(0x202A, 0x202F),
        *range(0x2066, 0x206A),
    }
)
TAG_CODEPOINTS = frozenset({*range(0xE0000, 0xE0080), *range(0xE0100, 0xE01F0)})
ZERO_WIDTH_CODEPOINTS = frozenset(
    {
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0xFEFF,
    }
)

_URL_SCHEME_HOST_RE = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#\s]+)")
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
_PACKAGE_RUNNERS = frozenset({"npx", "uvx", "pipx", "bunx", "pnpx"})
_SHELL_EXECUTABLES = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "ash", "cmd", "powershell", "pwsh"}
)
_SHELL_FLAGS = frozenset(
    {
        "-c",
        "-lc",
        "/c",
        "/C",
        "-Command",
        "-command",
        "-EncodedCommand",
        "-encodedcommand",
        "-enc",
    }
)
_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?i)(?:token|secret|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"auth|credential|bearer|client[_-]?key|pat\b)"
)
_ENV_PLACEHOLDER_RE = re.compile(
    r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|\{\{[^}]+\}\}|%[A-Za-z_][A-Za-z0-9_]*%|"
    r"\[REDACTED_[A-Z_]+\])$"
)


@dataclass(slots=True)
class AuditContext:
    redactor: Redactor
    redaction_count: int = 0
    findings: list[AgentConfigFinding] = field(default_factory=list)


def escape_control_and_invisible(text: str) -> str:
    """Replace invisible, bidirectional, tag, and C0/C1 control characters with safe escapes."""

    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if (
            cp in BIDI_CODEPOINTS
            or cp in ZERO_WIDTH_CODEPOINTS
            or (0x2000 <= cp <= 0x200F)
            or (0x2028 <= cp <= 0x202F)
            or (0x2060 <= cp <= 0x206F)
        ):
            out.append(f"\\u{cp:04x}")
        elif cp in TAG_CODEPOINTS:
            out.append(f"\\U{cp:08x}")
        elif cp < 0x20 or cp == 0x7F or (0x80 <= cp <= 0x9F):
            if ch == "\t":
                out.append(" ")
            else:
                out.append(f"\\x{cp:02x}")
        else:
            out.append(ch)
    return "".join(out)


def strip_invisible_for_matching(text: str) -> str:
    """Strip zero-width, bidi, and tag codepoints so split keywords cannot evade regexes."""

    return "".join(
        ch
        for ch in text
        if ord(ch) not in BIDI_CODEPOINTS
        and ord(ch) not in ZERO_WIDTH_CODEPOINTS
        and ord(ch) not in TAG_CODEPOINTS
    )


_QUOTED_KV_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>['\"]?[A-Za-z0-9_.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|client[_-]?key|credential)[A-Za-z0-9_.-]*['\"]?\s*[:=]\s*['\"])"
    r"(?P<val>[^'\"\r\n]{4,})(?P<suffix>['\"])"
)


def _scrub_quoted_kv_secrets(text: str, context: AuditContext) -> str:
    def _replace(match: re.Match[str]) -> str:
        raw_val = match.group("val")
        clean_val = strip_invisible_for_matching(raw_val).strip()
        if is_env_placeholder(clean_val) or clean_val.startswith("[REDACTED_"):
            return match.group(0)
        context.redaction_count += 1
        return f"{match.group('prefix')}[REDACTED_SECRET]{match.group('suffix')}"

    return _QUOTED_KV_SECRET_RE.sub(_replace, text)


def format_safe_snippet(raw_line: str, context: AuditContext) -> str:
    """Redact secrets and escape invisible/control characters in a bounded line snippet."""

    trimmed = raw_line.strip("\r\n")
    if len(trimmed) > MAX_SNIPPET_CHARS:
        trimmed = trimmed[:MAX_SNIPPET_CHARS] + "..."
    stripped_for_redaction = strip_invisible_for_matching(trimmed)
    redacted_result = context.redactor.redact(trimmed)
    if redacted_result.redaction_count == 0:
        fallback_redacted = context.redactor.redact(stripped_for_redaction)
        if fallback_redacted.redaction_count > 0:
            redacted_result = fallback_redacted
    context.redaction_count += redacted_result.redaction_count
    scrubbed = _scrub_quoted_kv_secrets(redacted_result.text, context)
    return escape_control_and_invisible(scrubbed)


def _find_line_number_for_token(lines: Sequence[str], key_name: str, start_line: int = 1) -> int:
    needle = f'"{key_name}"'
    for idx in range(max(0, start_line - 1), len(lines)):
        if needle in lines[idx]:
            return idx + 1
    for idx, line in enumerate(lines):
        if needle in line:
            return idx + 1
    return start_line


def _normalize_command_basename(command: str) -> str:
    normalized_slashes = "/".join(command.strip().split("\\"))
    base = PurePosixPath(normalized_slashes).name.lower()
    for suffix in (".cmd", ".exe", ".bat"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def extract_runner_and_package(
    command: str, args: Sequence[str]
) -> tuple[str | None, str | None, bool]:
    """Identify package runner (npx, uvx, pipx, bunx, pnpx) and its target package specifier."""

    base = _normalize_command_basename(command)
    str_args = [str(item).strip() for item in args]
    runner: str | None = None
    scan_args = list(str_args)
    if base in _PACKAGE_RUNNERS:
        runner = base
        if base == "pipx" and scan_args and scan_args[0] == "run":
            scan_args = scan_args[1:]
    elif base == "npm" and scan_args and scan_args[0] in {"exec", "x"}:
        runner = "npx"
        scan_args = scan_args[1:]
    elif base in {"pnpm", "yarn"} and scan_args and scan_args[0] == "dlx":
        runner = base
        scan_args = scan_args[1:]

    if runner is None:
        return None, None, False

    has_auto_yes = any(arg in {"-y", "--yes"} or arg.startswith("--yes=") for arg in scan_args)
    package_spec: str | None = None
    idx = 0
    while idx < len(scan_args):
        arg_item = scan_args[idx]
        if arg_item == "--":
            if idx + 1 < len(scan_args):
                package_spec = scan_args[idx + 1]
            break
        if arg_item in {"-y", "--yes", "-q", "--quiet", "--no-install"}:
            idx += 1
            continue
        if arg_item in {"-p", "--package", "--from"}:
            if idx + 1 < len(scan_args):
                package_spec = scan_args[idx + 1]
                break
            idx += 1
            continue
        if arg_item.startswith(("--package=", "--from=")):
            package_spec = arg_item.split("=", maxsplit=1)[1]
            break
        if arg_item.startswith("-"):
            idx += 1
            continue
        package_spec = arg_item
        break

    return runner, package_spec, has_auto_yes


def is_pinned_package_spec(runner: str, spec: str | None) -> bool:
    """Return True only when the package specifier pins an exact release version."""

    if not spec:
        return False
    cleaned = spec.strip()
    if not cleaned:
        return False
    if runner in {"uvx", "pipx"}:
        if "==" in cleaned:
            _, version = cleaned.split("==", maxsplit=1)
            return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))
        if "@" in cleaned and not cleaned.startswith("@"):
            _, version = cleaned.rsplit("@", maxsplit=1)
            return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))
        return False

    if cleaned.startswith("@"):
        rest = cleaned[1:]
        if "@" not in rest:
            return False
        _, version = rest.rsplit("@", maxsplit=1)
        return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))
    if "@" not in cleaned:
        return False
    _, version = cleaned.rsplit("@", maxsplit=1)
    return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))


def is_env_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    return bool(_ENV_PLACEHOLDER_RE.fullmatch(stripped))


def scan_mcp_config_json(
    rel_posix: str,
    text: str,
    lines: Sequence[str],
    is_dedicated_mcp_file: bool,
    context: AuditContext,
) -> None:
    """Category 5: Inspect JSON MCP configuration files for risky server definitions."""

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as error:
        if is_dedicated_mcp_file:
            line_no = max(1, min(error.lineno, max(1, len(lines))))
            raw_line = lines[line_no - 1] if lines else text[:MAX_SNIPPET_CHARS]
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-MCP-001",
                    severity=AuditSeverity.MEDIUM,
                    category=AuditCategory.MCP_CONFIG_RISK,
                    file_path=rel_posix,
                    line_number=line_no,
                    title="Invalid JSON in MCP configuration file",
                    description=(
                        f"MCP configuration file could not be parsed as valid JSON ({error.msg})."
                    ),
                    remediation="Fix the JSON syntax before loading the MCP configuration.",
                    snippet=format_safe_snippet(raw_line, context),
                )
            )
        return

    if not isinstance(parsed, Mapping):
        if is_dedicated_mcp_file:
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-MCP-001",
                    severity=AuditSeverity.MEDIUM,
                    category=AuditCategory.MCP_CONFIG_RISK,
                    file_path=rel_posix,
                    line_number=1,
                    title="Invalid top-level structure in MCP configuration file",
                    description="MCP configuration root must be a JSON object mapping.",
                    remediation=(
                        "Use a top-level JSON object with an 'mcpServers' or 'servers' mapping."
                    ),
                    snippet=format_safe_snippet(lines[0] if lines else text, context),
                )
            )
        return

    for container_key in ("mcpServers", "servers"):
        if container_key not in parsed:
            continue
        servers_block = parsed.get(container_key)
        if not isinstance(servers_block, Mapping):
            line_no = _find_line_number_for_token(lines, container_key)
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-MCP-001",
                    severity=AuditSeverity.MEDIUM,
                    category=AuditCategory.MCP_CONFIG_RISK,
                    file_path=rel_posix,
                    line_number=line_no,
                    title="Invalid servers mapping in MCP configuration file",
                    description=(
                        f"The '{container_key}' field must be a JSON object mapping server names "
                        "to configurations."
                    ),
                    remediation=f"Format '{container_key}' as a JSON object.",
                    snippet=format_safe_snippet(
                        lines[line_no - 1] if lines else container_key, context
                    ),
                )
            )
            continue

        for raw_server_name, server_cfg in servers_block.items():
            server_name = str(raw_server_name)
            safe_server = escape_control_and_invisible(server_name)
            server_line = _find_line_number_for_token(lines, server_name)
            if not isinstance(server_cfg, Mapping):
                context.findings.append(
                    AgentConfigFinding(
                        rule_id="AGENT-MCP-001",
                        severity=AuditSeverity.MEDIUM,
                        category=AuditCategory.MCP_CONFIG_RISK,
                        file_path=rel_posix,
                        line_number=server_line,
                        title="Invalid MCP server entry structure",
                        description=(f"Server entry '{safe_server}' is not a JSON object."),
                        remediation="Define each MCP server entry as a JSON object.",
                        snippet=format_safe_snippet(
                            lines[server_line - 1] if lines else server_name, context
                        ),
                    )
                )
                continue

            for url_key in ("url", "serverUrl", "endpoint", "uri"):
                raw_url = server_cfg.get(url_key)
                if not isinstance(raw_url, str) or not raw_url.strip():
                    continue
                url_value = raw_url.strip()
                if is_env_placeholder(url_value):
                    continue
                url_line = _find_line_number_for_token(lines, url_key, server_line)
                match = _URL_SCHEME_HOST_RE.match(url_value)
                if match is not None:
                    scheme = match.group("scheme").lower()
                    authority = match.group("authority")
                    host_part = authority.rsplit("@", maxsplit=1)[-1]
                    if host_part.startswith("["):
                        host = host_part.split("]", maxsplit=1)[0] + "]"
                    else:
                        host = host_part.split(":", maxsplit=1)[0].lower()
                    is_loopback = host.lower() in _LOOPBACK_HOSTS
                    if not is_loopback:
                        is_cleartext = scheme in {"http", "ws"}
                        context.findings.append(
                            AgentConfigFinding(
                                rule_id="AGENT-MCP-002",
                                severity=AuditSeverity.HIGH
                                if is_cleartext
                                else AuditSeverity.MEDIUM,
                                category=AuditCategory.MCP_CONFIG_RISK,
                                file_path=rel_posix,
                                line_number=url_line,
                                title=(
                                    "Cleartext remote MCP server URL"
                                    if is_cleartext
                                    else "Remote MCP server endpoint"
                                ),
                                description=(
                                    f"MCP server '{safe_server}' connects to "
                                    f"a non-loopback {scheme.upper()} endpoint "
                                    f"({escape_control_and_invisible(host)})."
                                ),
                                remediation=(
                                    "Prefer local stdio or loopback MCP servers, or verify and pin "
                                    "trusted HTTPS endpoints before enabling."
                                ),
                                snippet=format_safe_snippet(
                                    lines[url_line - 1] if lines else url_value, context
                                ),
                            )
                        )

            command_val = server_cfg.get("command")
            args_val = server_cfg.get("args")
            str_args = (
                [str(item) for item in args_val]
                if isinstance(args_val, Sequence) and not isinstance(args_val, (str, bytes))
                else []
            )
            if isinstance(command_val, str) and command_val.strip():
                cmd_line = _find_line_number_for_token(lines, "command", server_line)
                cmd_str = command_val.strip()
                base_cmd = _normalize_command_basename(cmd_str)

                if base_cmd in _SHELL_EXECUTABLES or any(flag in _SHELL_FLAGS for flag in str_args):
                    context.findings.append(
                        AgentConfigFinding(
                            rule_id="AGENT-MCP-004",
                            severity=AuditSeverity.HIGH,
                            category=AuditCategory.MCP_CONFIG_RISK,
                            file_path=rel_posix,
                            line_number=cmd_line,
                            title="Shell wrapper in MCP server command",
                            description=(
                                f"MCP server '{safe_server}' launches a shell "
                                "wrapper, which expands attack surface and command-injection risk."
                            ),
                            remediation=(
                                "Invoke the MCP server binary directly with fixed arguments "
                                "instead of wrapping it in sh, bash, cmd, or PowerShell."
                            ),
                            snippet=format_safe_snippet(
                                lines[cmd_line - 1] if lines else cmd_str, context
                            ),
                        )
                    )

                runner, pkg_spec, has_auto_yes = extract_runner_and_package(cmd_str, str_args)
                if runner is not None and not is_pinned_package_spec(runner, pkg_spec):
                    spec_display = escape_control_and_invisible(pkg_spec or "<unspecified>")
                    is_high = has_auto_yes or (
                        pkg_spec is not None and "@latest" in pkg_spec.lower()
                    )
                    context.findings.append(
                        AgentConfigFinding(
                            rule_id="AGENT-MCP-003",
                            severity=AuditSeverity.HIGH if is_high else AuditSeverity.MEDIUM,
                            category=AuditCategory.MCP_CONFIG_RISK,
                            file_path=rel_posix,
                            line_number=cmd_line,
                            title="Unpinned package execution in MCP server configuration",
                            description=(
                                f"MCP server '{safe_server}' runs '{runner}' "
                                f"with unpinned package '{spec_display}'"
                                + (" and auto-install enabled." if has_auto_yes else ".")
                            ),
                            remediation=(
                                "Pin the MCP server package to an exact reviewed version "
                                "(such as 'pkg@1.2.3' or 'pkg==1.2.3') or run a local binary."
                            ),
                            snippet=format_safe_snippet(
                                lines[cmd_line - 1] if lines else cmd_str, context
                            ),
                        )
                    )

            env_block = server_cfg.get("env")
            if isinstance(env_block, Mapping):
                for raw_env_key, raw_env_val in env_block.items():
                    if raw_env_val is None or isinstance(raw_env_val, bool):
                        continue
                    env_key = str(raw_env_key)
                    env_val = str(raw_env_val)
                    if is_env_placeholder(env_val):
                        continue
                    val_redaction = context.redactor.redact(env_val)
                    is_sensitive_key = bool(_SENSITIVE_ENV_KEY_RE.search(env_key))
                    if is_sensitive_key or val_redaction.redaction_count > 0:
                        env_line = _find_line_number_for_token(lines, env_key, server_line)
                        context.redaction_count += max(1, val_redaction.redaction_count)
                        safe_key = escape_control_and_invisible(env_key)
                        context.findings.append(
                            AgentConfigFinding(
                                rule_id="AGENT-MCP-005",
                                severity=AuditSeverity.HIGH,
                                category=AuditCategory.MCP_CONFIG_RISK,
                                file_path=rel_posix,
                                line_number=env_line,
                                title="Inline plaintext credential in MCP server environment",
                                description=(
                                    f"MCP server '{safe_server}' "
                                    f"sets inline credential variable '{safe_key}' in its "
                                    "'env' configuration."
                                ),
                                remediation=(
                                    "Replace inline credentials in MCP configuration files with "
                                    "environment variable placeholders such as '${API_TOKEN}'."
                                ),
                                snippet=f'"{safe_key}": "[REDACTED_SECRET]"',
                            )
                        )
