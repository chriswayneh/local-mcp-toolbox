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
TAG_CODEPOINTS = frozenset(
    {
        *range(0xFE00, 0xFE10),
        *range(0xE0000, 0xE0080),
        *range(0xE0100, 0xE01F0),
    }
)
ZERO_WIDTH_CODEPOINTS = frozenset(
    {
        0x00AD,
        0x034F,
        *range(0x180B, 0x180F),
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        *range(0x206A, 0x2070),
        0xFEFF,
    }
)

_URL_SCHEME_HOST_RE = re.compile(
    r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#\\\s]+)"
)
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})
_PACKAGE_RUNNERS = frozenset({"npx", "uvx", "pipx", "bunx", "pnpx"})
_RUNNER_BOOL_FLAGS = frozenset(
    {
        "-y",
        "--yes",
        "-q",
        "--quiet",
        "--no-install",
        "--isolated",
        "--no-cache",
        "--refresh",
        "--offline",
        "--prerelease",
        "--system-site-packages",
    }
)
_RUNNER_VALUE_FLAGS = frozenset(
    {
        "--python",
        "-P",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--registry",
        "--userconfig",
        "--cache-dir",
        "--cache",
        "--prefix",
        "--shell",
        "-c",
        "--call",
    }
)
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
_DANGEROUS_EXEC_ENV_KEYS = frozenset(
    {
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "NODE_OPTIONS",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
        "PROMPT_COMMAND",
        "RUBYOPT",
        "PERL5OPT",
    }
)
_EXACT_SEMVER_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_PKG_ATOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PYTHON_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9,._-]+\])?$")
_SENSITIVE_ENV_KEY_RE = re.compile(
    r"(?i)(?:token|secret|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"auth|credential|bearer|cookie|session|client[_-]?key|pat\b)"
)
_ENV_PLACEHOLDER_RE = re.compile(
    r"^(?:\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|<[^>]+>|\{\{[^}]+\}\}|%[A-Za-z_][A-Za-z0-9_]*%|"
    r"\[REDACTED_[A-Z0-9_]+\])$"
)
_REDACTED_MARKER_RE = re.compile(r"\[REDACTED_[A-Z0-9_]+\]")
_PRE_REDACTION_WINDOW = 4_096
_MAX_IDENTIFIER_DISPLAY = 120


@dataclass(slots=True)
class AuditContext:
    redactor: Redactor
    redaction_count: int = 0
    findings: list[AgentConfigFinding] = field(default_factory=list)


def _is_non_whitespace_control(cp: int) -> bool:
    return (cp < 0x20 and cp not in (0x09, 0x0A, 0x0D)) or cp == 0x7F or (0x80 <= cp <= 0x9F)


def escape_control_and_invisible(text: str) -> str:
    """Convert invisible, bidirectional, tag, and C0/C1 control characters into safe escapes."""

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
            if cp <= 0xFFFF:
                out.append(f"\\u{cp:04x}")
            else:
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
    """Strip zero-width, bidi, tag, and C0/C1 control codepoints so split keywords cannot evade."""

    return "".join(
        ch
        for ch in text
        if (cp := ord(ch)) not in BIDI_CODEPOINTS
        and cp not in ZERO_WIDTH_CODEPOINTS
        and cp not in TAG_CODEPOINTS
        and not _is_non_whitespace_control(cp)
    )


_QUOTED_KV_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>['\"]?(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]{0,64}"
    r"(?:token|secret|password|passwd|pwd|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?key|credential)[A-Za-z0-9_.-]{0,64}"
    r"['\"]?\s*[:=]\s*['\"])"
    r"(?P<val>[^'\"\r\n]{4,512})(?P<suffix>['\"])"
)
_URL_USERINFO_SECRET_RE = re.compile(
    r"(?i)(?P<prefix>[A-Za-z][A-Za-z0-9+.-]*://)"
    r"(?P<userinfo>[^/?#\\\s@:]{1,128}:[^/?#\\\s@]{1,256})(?P<suffix>@)"
)


def _scrub_extra_secrets(text: str) -> tuple[str, int]:
    count = 0

    def _sub_kv(match: re.Match[str]) -> str:
        nonlocal count
        raw_val = match.group("val")
        clean_val = strip_invisible_for_matching(raw_val).strip()
        if is_env_placeholder(clean_val) or clean_val.startswith("[REDACTED_"):
            return match.group(0)
        count += 1
        return f"{match.group('prefix')}[REDACTED_SECRET]{match.group('suffix')}"

    def _sub_userinfo(match: re.Match[str]) -> str:
        nonlocal count
        userinfo = match.group("userinfo")
        secret_part = userinfo.split(":", maxsplit=1)[1]
        if is_env_placeholder(secret_part) or secret_part.startswith("[REDACTED_"):
            return match.group(0)
        count += 1
        return f"{match.group('prefix')}[REDACTED_SECRET]{match.group('suffix')}"

    scrubbed = _QUOTED_KV_SECRET_RE.sub(_sub_kv, text)
    scrubbed = _URL_USERINFO_SECRET_RE.sub(_sub_userinfo, scrubbed)
    return scrubbed, count


def _redact_and_scrub(candidate: str, redactor: Redactor) -> tuple[str, int]:
    redacted_res = redactor.redact(candidate)
    scrubbed_text, extra_count = _scrub_extra_secrets(redacted_res.text)
    return scrubbed_text, redacted_res.redaction_count + extra_count


def _truncate_escaped_snippet(
    escaped: str,
    max_chars: int,
    *,
    force_ellipsis: bool = False,
    preserve_redacted_marker: bool = True,
) -> str:
    if len(escaped) <= max_chars and not force_ellipsis:
        return escaped
    cut = min(len(escaped), max(0, max_chars - 3))
    for match in _REDACTED_MARKER_RE.finditer(escaped):
        if match.start() < cut < match.end():
            if preserve_redacted_marker and match.end() + 3 <= 990:
                cut = match.end()
            else:
                cut = match.start()
            break
    # Do not slice through an escape sequence (\xHH, \uHHHH, \UHHHHHHHH).
    search_start = max(0, cut - 9)
    slash_idx = escaped.rfind("\\", search_start, cut)
    if slash_idx != -1:
        tail = escaped[slash_idx:]
        seq_len = 0
        if tail.startswith("\\x"):
            seq_len = 4
        elif tail.startswith("\\u"):
            seq_len = 6
        elif tail.startswith("\\U"):
            seq_len = 10
        if seq_len and slash_idx + seq_len > cut:
            cut = slash_idx
    return escaped[:cut] + "..."


def bound_escaped_text(text: str, max_chars: int = _MAX_IDENTIFIER_DISPLAY) -> str:
    """Escape control/invisible characters and bound the result to max_chars."""

    escaped = escape_control_and_invisible(text)
    if len(escaped) <= max_chars:
        return escaped
    return _truncate_escaped_snippet(
        escaped,
        max_chars,
        force_ellipsis=True,
        preserve_redacted_marker=False,
    )


def format_safe_snippet(raw_line: str, context: AuditContext) -> str:
    """Redact secrets and escape invisible/control characters in a bounded line snippet."""

    trimmed = raw_line.strip("\r\n")
    was_long = len(trimmed) > MAX_SNIPPET_CHARS
    window = trimmed[:_PRE_REDACTION_WINDOW]
    stripped_window = strip_invisible_for_matching(window)

    chosen_text, chosen_count = _redact_and_scrub(window, context.redactor)
    if stripped_window != window:
        stripped_text, stripped_count = _redact_and_scrub(stripped_window, context.redactor)
        if stripped_count > 0:
            chosen_text, chosen_count = stripped_text, stripped_count

    context.redaction_count += chosen_count
    escaped = escape_control_and_invisible(chosen_text)
    return _truncate_escaped_snippet(
        escaped,
        MAX_SNIPPET_CHARS,
        force_ellipsis=was_long,
        preserve_redacted_marker=True,
    )


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
    explicit_pkg_specs: list[str] = []
    with_pkg_specs: list[str] = []
    positional_pkg_specs: list[str] = []
    idx = 0
    while idx < len(scan_args):
        arg_item = scan_args[idx]
        if arg_item == "--":
            if idx + 1 < len(scan_args):
                positional_pkg_specs.append(scan_args[idx + 1])
            break
        if arg_item in _RUNNER_BOOL_FLAGS or arg_item.startswith("--yes="):
            idx += 1
            continue
        if arg_item in {"-p", "--package", "--from"}:
            if idx + 1 < len(scan_args):
                explicit_pkg_specs.append(scan_args[idx + 1])
                idx += 2
            else:
                explicit_pkg_specs.append("")
                idx += 1
            continue
        if arg_item.startswith(("--package=", "--from=")):
            explicit_pkg_specs.append(arg_item.split("=", maxsplit=1)[1])
            idx += 1
            continue
        if arg_item in {"--with", "-w"}:
            if idx + 1 < len(scan_args):
                for part in scan_args[idx + 1].split(","):
                    with_pkg_specs.append(part.strip())
                idx += 2
            else:
                with_pkg_specs.append("")
                idx += 1
            continue
        if arg_item.startswith("--with="):
            for part in arg_item.split("=", maxsplit=1)[1].split(","):
                with_pkg_specs.append(part.strip())
            idx += 1
            continue
        if arg_item in {"--with-editable", "--with-requirements", "-r"} or arg_item.startswith(
            ("--with-editable=", "--with-requirements=")
        ):
            with_pkg_specs.append(arg_item)
            idx += 2 if "=" not in arg_item else 1
            continue
        if arg_item in _RUNNER_VALUE_FLAGS:
            idx += 2
            continue
        if arg_item.startswith("-"):
            idx += 1
            continue
        positional_pkg_specs.append(arg_item)
        idx += 1

    primary_specs = explicit_pkg_specs if explicit_pkg_specs else positional_pkg_specs[:1]
    if not primary_specs:
        return runner, None, has_auto_yes

    all_checked_specs = [*primary_specs, *with_pkg_specs]
    for candidate_spec in all_checked_specs:
        if not is_pinned_package_spec(runner, candidate_spec):
            return runner, candidate_spec or None, has_auto_yes

    return runner, primary_specs[0], has_auto_yes


def is_pinned_package_spec(runner: str, spec: str | None) -> bool:
    """Return True only when the package specifier pins an exact release version."""

    if not spec:
        return False
    cleaned = spec.strip()
    if not cleaned:
        return False
    lowered = cleaned.lower()
    if (
        "://" in cleaned
        or "\\" in cleaned
        or cleaned.startswith((".", "/", "~"))
        or lowered.startswith(
            ("git+", "github:", "gitlab:", "bitbucket:", "file:", "http:", "https:", "ssh:", "ftp:")
        )
    ):
        return False

    if runner in {"uvx", "pipx"}:
        if "==" in cleaned:
            pkg_name, version = cleaned.split("==", maxsplit=1)
        elif "@" in cleaned and not cleaned.startswith("@"):
            pkg_name, version = cleaned.rsplit("@", maxsplit=1)
        else:
            return False
        if not _PYTHON_PKG_NAME_RE.fullmatch(pkg_name.strip()):
            return False
        return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))

    if cleaned.startswith("@"):
        rest = cleaned[1:]
        if "@" not in rest:
            return False
        pkg_name, version = rest.rsplit("@", maxsplit=1)
        if pkg_name.count("/") != 1:
            return False
        scope, name = pkg_name.split("/", maxsplit=1)
        if not (_PKG_ATOM_RE.fullmatch(scope) and _PKG_ATOM_RE.fullmatch(name)):
            return False
        return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))

    if "@" not in cleaned:
        return False
    pkg_name, version = cleaned.rsplit("@", maxsplit=1)
    if not _PKG_ATOM_RE.fullmatch(pkg_name.strip()):
        return False
    return bool(_EXACT_SEMVER_RE.fullmatch(version.strip()))


def is_env_placeholder(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return True
    if _ENV_PLACEHOLDER_RE.fullmatch(stripped):
        return True
    parts = stripped.split(None, 1)
    if len(parts) == 2 and parts[0].lower() in {"bearer", "basic", "token"}:
        return bool(_ENV_PLACEHOLDER_RE.fullmatch(parts[1].strip()))
    return False


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
    except (json.JSONDecodeError, RecursionError) as error:
        if is_dedicated_mcp_file:
            raw_lineno = getattr(error, "lineno", 1)
            line_no = max(1, min(raw_lineno, max(1, len(lines))))
            raw_line = lines[line_no - 1] if lines else text[:MAX_SNIPPET_CHARS]
            reason = getattr(error, "msg", "excessive nesting depth")
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-MCP-001",
                    severity=AuditSeverity.MEDIUM,
                    category=AuditCategory.MCP_CONFIG_RISK,
                    file_path=rel_posix,
                    line_number=line_no,
                    title="Invalid JSON in MCP configuration file",
                    description=(
                        f"MCP configuration file could not be parsed as valid JSON ({reason})."
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
            safe_server = bound_escaped_text(server_name)
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
                        description=f"Server entry '{safe_server}' is not a JSON object.",
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
                    has_userinfo = "@" in authority
                    has_backslash = "\\" in url_value
                    userinfo, host_part = (
                        authority.rsplit("@", maxsplit=1) if has_userinfo else ("", authority)
                    )
                    if host_part.startswith("["):
                        host = host_part.split("]", maxsplit=1)[0] + "]"
                    else:
                        host = host_part.split(":", maxsplit=1)[0].lower()
                    is_loopback = (
                        host.lower() in _LOOPBACK_HOSTS and not has_userinfo and not has_backslash
                    )
                    if not is_loopback:
                        is_cleartext = scheme in {"http", "ws"} or has_backslash
                        safe_host = bound_escaped_text(host or authority)
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
                                    f"({safe_host})."
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
                    if has_userinfo and userinfo:
                        secret_part = (
                            userinfo.split(":", maxsplit=1)[1] if ":" in userinfo else userinfo
                        )
                        if secret_part and not is_env_placeholder(secret_part):
                            ui_redact = context.redactor.redact(userinfo)
                            if (
                                ":" in userinfo
                                or _SENSITIVE_ENV_KEY_RE.search(userinfo)
                                or ui_redact.redaction_count > 0
                            ):
                                context.redaction_count += max(1, ui_redact.redaction_count)
                                safe_url_key = bound_escaped_text(url_key)
                                context.findings.append(
                                    AgentConfigFinding(
                                        rule_id="AGENT-MCP-005",
                                        severity=AuditSeverity.HIGH,
                                        category=AuditCategory.MCP_CONFIG_RISK,
                                        file_path=rel_posix,
                                        line_number=url_line,
                                        title="Inline plaintext credential in MCP server URL",
                                        description=(
                                            f"MCP server '{safe_server}' embeds inline userinfo "
                                            f"credentials in its '{safe_url_key}' endpoint URL."
                                        ),
                                        remediation=(
                                            "Remove embedded credentials from MCP URLs and pass "
                                            "secrets via environment variable placeholders."
                                        ),
                                        snippet=f'"{safe_url_key}": "[REDACTED_SECRET]"',
                                    )
                                )
                elif "\\" in url_value:
                    context.findings.append(
                        AgentConfigFinding(
                            rule_id="AGENT-MCP-002",
                            severity=AuditSeverity.HIGH,
                            category=AuditCategory.MCP_CONFIG_RISK,
                            file_path=rel_posix,
                            line_number=url_line,
                            title="Cleartext remote MCP server URL",
                            description=(
                                f"MCP server '{safe_server}' specifies an ambiguous backslash "
                                "URL authority."
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
                    spec_display = bound_escaped_text(pkg_spec or "<unspecified>")
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
                    env_line = _find_line_number_for_token(lines, env_key, server_line)
                    safe_key = bound_escaped_text(env_key)
                    if env_key.strip().upper() in _DANGEROUS_EXEC_ENV_KEYS and env_val.strip():
                        context.findings.append(
                            AgentConfigFinding(
                                rule_id="AGENT-MCP-004",
                                severity=AuditSeverity.HIGH,
                                category=AuditCategory.MCP_CONFIG_RISK,
                                file_path=rel_posix,
                                line_number=env_line,
                                title=(
                                    "Code-injection environment variable in MCP server "
                                    "configuration"
                                ),
                                description=(
                                    f"MCP server '{safe_server}' sets dangerous execution "
                                    f"environment variable '{safe_key}' in its 'env' configuration."
                                ),
                                remediation=(
                                    "Remove dynamic linker, interpreter startup, and shell-hook "
                                    "environment variables from MCP server configurations."
                                ),
                                snippet=format_safe_snippet(
                                    lines[env_line - 1] if lines else f'"{env_key}": "{env_val}"',
                                    context,
                                ),
                            )
                        )
                    if is_env_placeholder(env_val):
                        continue
                    val_redaction = context.redactor.redact(env_val)
                    is_sensitive_key = bool(_SENSITIVE_ENV_KEY_RE.search(env_key))
                    if is_sensitive_key or val_redaction.redaction_count > 0:
                        context.redaction_count += max(1, val_redaction.redaction_count)
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

            headers_block = server_cfg.get("headers")
            if isinstance(headers_block, Mapping):
                for raw_hdr_key, raw_hdr_val in headers_block.items():
                    if raw_hdr_val is None or isinstance(raw_hdr_val, bool):
                        continue
                    hdr_key = str(raw_hdr_key)
                    hdr_val = str(raw_hdr_val)
                    if is_env_placeholder(hdr_val):
                        continue
                    val_redaction = context.redactor.redact(hdr_val)
                    is_sensitive_key = bool(_SENSITIVE_ENV_KEY_RE.search(hdr_key))
                    if is_sensitive_key or val_redaction.redaction_count > 0:
                        hdr_line = _find_line_number_for_token(lines, hdr_key, server_line)
                        context.redaction_count += max(1, val_redaction.redaction_count)
                        safe_hdr_key = bound_escaped_text(hdr_key)
                        context.findings.append(
                            AgentConfigFinding(
                                rule_id="AGENT-MCP-005",
                                severity=AuditSeverity.HIGH,
                                category=AuditCategory.MCP_CONFIG_RISK,
                                file_path=rel_posix,
                                line_number=hdr_line,
                                title="Inline plaintext credential in MCP server headers",
                                description=(
                                    f"MCP server '{safe_server}' "
                                    f"sets inline credential header '{safe_hdr_key}' in its "
                                    "'headers' configuration."
                                ),
                                remediation=(
                                    "Replace inline credentials in MCP headers with "
                                    "environment variable placeholders such as '${API_TOKEN}'."
                                ),
                                snippet=f'"{safe_hdr_key}": "[REDACTED_SECRET]"',
                            )
                        )
