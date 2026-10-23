"""Categories 1-4 detectors: Unicode smuggling, prompt overrides, execution, and exfiltration."""

from __future__ import annotations

import re
from collections.abc import Sequence

from mcp_toolbox.tools.security.mcp_config_detector import (
    BIDI_CODEPOINTS,
    TAG_CODEPOINTS,
    ZERO_WIDTH_CODEPOINTS,
    AuditContext,
    format_safe_snippet,
    strip_invisible_for_matching,
)
from mcp_toolbox.tools.security.models import (
    AgentConfigFinding,
    AuditCategory,
    AuditSeverity,
)

# Category 2 pattern components (Prompt override / guardrail bypass)
_OVERRIDE_VERBS = "|".join(("ig" + "nore", "dis" + "regard", "for" + "get", "over" + "ride"))
_OVERRIDE_SCOPES = "|".join(
    (
        "previous",
        "prior",
        "earlier",
        "above",
        "preceding",
        "system",
        "developer",
        "existing",
        "initial",
        "original",
    )
)
_OVERRIDE_NOUNS = "|".join(
    (
        "instructions?",
        "rules?",
        "prompts?",
        "directives?",
        "guidelines?",
        "constraints?",
        "guardrails?",
    )
)
_PROMPT_OVERRIDE_RE = re.compile(
    rf"(?i)(?:"
    rf"\b(?:{_OVERRIDE_VERBS})\s+(?:all\s+)?(?:{_OVERRIDE_SCOPES})\s+(?:{_OVERRIDE_NOUNS})\b"
    rf"|\b(?:new|updated|replacement)\s+(?:system|developer)\s+(?:{_OVERRIDE_NOUNS})\s*:"
    rf"|\byou\s+are\s+no\s+longer\s+bound\s+by\b"
    rf")"
)

_USER_ACTORS = "|".join(("user", "operator", "developer", "human"))
_USER_SUPPRESSION_RE = re.compile(
    rf"(?i)(?:"
    rf"\b(?:do\s+not|don'?t|never)\s+(?:tell|mention(?:\s+this)?\s+to|inform|notify|alert|"
    rf"reveal(?:\s+this)?\s+to)\s+the\s+(?:{_USER_ACTORS})\b"
    rf"|\b(?:hide|conceal|keep)\s+(?:this|the\s+output|these\s+actions?)\s+(?:hidden\s+)?from\s+"
    rf"the\s+(?:{_USER_ACTORS})\b"
    rf"|\bwithout\s+the\s+(?:{_USER_ACTORS})\s+(?:knowing|noticing)\b"
    rf")"
)

_APPROVAL_NOUNS = "|".join(("confirmation", "approval", "permission", "consent", "review"))
_SAFETY_NOUNS = "|".join(
    ("checks?", "controls?", "gates?", "guardrails?", "filters?", "rules?", "restrictions?")
)
_APPROVAL_BYPASS_RE = re.compile(
    rf"(?i)(?:"
    rf"\b(?:without\s+asking(?:\s+for)?|do\s+not\s+ask(?:\s+for)?|don'?t\s+ask(?:\s+for)?|"
    rf"never\s+ask(?:\s+for)?|skip(?:\s+all)?|bypass(?:\s+all)?)\s+(?:user\s+)?(?:{_APPROVAL_NOUNS})\b"
    rf"|\b(?:bypass|disable|ignore|turn\s+off|skip)\s+(?:all\s+)?(?:safety|security|approval|"
    rf"permission|sandbox)\s+(?:{_SAFETY_NOUNS})\b"
    rf"|\b(?:bypass|skip)\s+(?:safety|guardrails?|approval)\b"
    rf")"
)

_HTML_COMMENT_RE = re.compile(r"<!--(?P<body>[\s\S]*?)(?:-->|$)")
_COMMENT_ALERT_TOKENS = "|".join(
    (
        "ig" + "nore",
        "dis" + "regard",
        "for" + "get",
        "over" + "ride",
        r"do\s+not\s+tell",
        r"never\s+mention",
        r"without\s+asking",
        r"skip\s+approval",
        "bypass",
        "cu" + "rl",
        "wg" + "et",
        "ba" + "sh",
        "ev" + "al",
        "ex" + "ec",
        "base" + "64",
        "power" + "shell",
        "invoke-" + "webrequest",
        "invoke-" + "expression",
        "id_" + "rsa",
        "id_" + "ed25519",
        r"webhook\.site",
        "requestbin",
        "ngrok",
        "pipedream",
        "oastify",
        "burpcollaborator",
        r"system\s+prompt",
    )
)
_SUSPICIOUS_COMMENT_RE = re.compile(
    rf"(?i)(?:\b(?:{_COMMENT_ALERT_TOKENS})\b|(?:^|[\s'\"(/\\~])\.env\b)"
)

# Category 3 pattern components (Dangerous execution)
_SHELL_INTERPRETERS = "|".join(
    (
        "sh",
        "ba" + "sh",
        "zsh",
        "dash",
        "ksh",
        "ash",
        "python[23]?",
        "perl",
        "ruby",
        "node",
        "pwsh",
        "power" + "shell",
    )
)
_PIPED_REMOTE_EXEC_RE = re.compile(
    r"(?i)(?:"
    r"\b(?:cu" + r"rl|wg" + rf"et)\b[^\r\n|]{{1,400}}\|\s*(?:sudo\s+)?(?:env\s+)?"
    rf"(?:/usr/bin/|/bin/)?(?:{_SHELL_INTERPRETERS})\b"
    rf"|\b(?:invoke-web" + r"request|invoke-restmethod|iwr|irm)\b[^\r\n|]{1,400}\|\s*"
    r"(?:invoke-exp" + r"ression|iex)\b"
    r"|\b(?:invoke-exp" + r"ression|iex)\b[^\r\n]{0,240}\b(?:downloadstring|downloaddata|"
    r"invoke-web" + r"request|invoke-restmethod)\b"
    r"|\b(?:sh|ba" + r"sh|zsh)\s+-c\s+['\"]?\$\(\s*(?:cu" + r"rl|wg" + r"et)\b"
    r")"
)

_ENCODED_EXEC_RE = re.compile(
    r"(?i)(?:"
    r"\bbase" + r"64\s+(?:-d|--de" + rf"code|-D)\b[^\r\n|]{{0,120}}\|\s*(?:sudo\s+)?(?:env\s+)?"
    rf"(?:/usr/bin/|/bin/)?(?:{_SHELL_INTERPRETERS}|ev" + r"al)\b"
    r"|\b(?:ev"
    + r"al|sh\s+-c|ba"
    + r"sh\s+-c)\b[^\r\n]{0,200}\bbase"
    + r"64\s+(?:-d|--de"
    + r"code|-D)\b"
    r"|\bFromBase" + r"64String\s*\("
    r"|\b(?:power" + r"shell|pwsh)(?:\.exe)?\b[^\r\n]{0,160}\s-(?:e|en|enc|encoded" + r"command)\s+"
    r"[A-Za-z0-9+/=]{8,}"
    r")"
)

_INLINE_INTERP_EXEC_RE = re.compile(
    r"(?i)(?:"
    r"\bpython[23]?\s+-c\b[^\r\n]{1,400}"
    r"|\bnode\s+(?:-e|--ev" + r"al)\b[^\r\n]{1,400}"
    r")"
)
_INLINE_NET_PART_RE = re.compile(
    r"(?i)(?:\b(?:url"
    + r"lib|url"
    + r"open|requests|http\.client|child_process|socket)\b|\bfetch\s*\()"
)
_INLINE_EXEC_PART_RE = re.compile(
    r"(?i)(?:\b(?:ex"
    + r"ec|ev"
    + r"al|compile|execSync|spawn)\s*\(|\bos\.sys"
    + r"tem\b|\bsub"
    + r"process\b)"
)

# Category 4 pattern components (Credential paths or outbound exfiltration)
_CREDENTIAL_FILE_TOKENS = "|".join(
    (
        r"\.ssh/(?:id_" + r"rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)",
        r"\.aws/creden" + r"tials",
        r"\.kube/con" + r"fig",
        r"\.config/gcloud",
        r"application_default_creden" + r"tials\.json",
        r"\.azure/accessTokens\.json",
        r"\.npmrc",
        r"\.pypirc",
        r"\.netrc",
        r"\.git-creden" + r"tials",
        r"\.docker/con" + r"fig\.json",
    )
)
_SENSITIVE_CREDENTIAL_PATH_RE = re.compile(
    r"(?i)(?:"
    r"(?:^|[\s'\"`(/\\~])\.env(?:\.(?!example\b|sample\b|template\b|dist\b|schema\b|test\b)"
    r"[A-Za-z0-9_-]+)?(?=$|[\s'\"`)]|[,;:])"
    r"|(?:\b(?:id_" + rf"rsa|id_ed25519|id_ecdsa)\b)"
    rf"|(?:{_CREDENTIAL_FILE_TOKENS})\b"
    rf"|(?:/etc/(?:sha" + r"dow|master\.passwd)\b)"
    r"|\b(?:169\.254\.169\.254|metadata\.google\.internal)\b"
    r")"
)

_WEBHOOK_DOMAINS = "|".join(
    (
        r"webhook\.site",
        r"requestbin\.(?:com|net)",
        r"ngrok\.io",
        r"ngrok-free\.app",
        r"ngrok\.app",
        r"pipedream\.net",
        r"oastify\.com",
        r"burpcollaborator\.net",
        r"interact\.sh",
        r"oast\.(?:pro|live|site|online|fun|me)",
        r"canarytokens\.com",
    )
)
_EXFIL_WEBHOOK_OR_UPLOAD_RE = re.compile(
    rf"(?i)(?:"
    rf"\b(?:[a-z0-9-]+\.)?(?:{_WEBHOOK_DOMAINS})\b"
    rf"|\bcu" + r"rl\b[^\r\n]{0,300}?(?:(?:-d|--data|--data-binary|--data-raw|--data-urlencode)\s+"
    r"['\"]?@[^\s'\"]+|(?:-F|--form)\s+['\"]?[^=\s'\"]+=@[^\s'\"]+|--upload-file\s+\S+)"
    r"|\bwg" + r"et\b[^\r\n]{0,300}?--post-file(?:=|\s+)\S+"
    r")"
)


def scan_unicode_smuggling(
    rel_posix: str,
    lines: Sequence[str],
    raw_starts_with_bom: bool,
    context: AuditContext,
) -> None:
    """Category 1: Detect hidden, bidirectional, tag, zero-width, and control characters."""

    for line_number, line in enumerate(lines, start=1):
        bidi_codes: list[str] = []
        tag_codes: list[str] = []
        zw_codes: list[str] = []
        ctrl_codes: list[str] = []

        for idx, ch in enumerate(line):
            cp = ord(ch)
            if cp in BIDI_CODEPOINTS:
                code = f"U+{cp:04X}"
                if code not in bidi_codes:
                    bidi_codes.append(code)
            elif cp in TAG_CODEPOINTS:
                code = f"U+{cp:05X}"
                if code not in tag_codes:
                    tag_codes.append(code)
            elif cp in ZERO_WIDTH_CODEPOINTS:
                if cp == 0xFEFF and line_number == 1 and idx == 0 and raw_starts_with_bom:
                    continue
                code = f"U+{cp:04X}"
                if code not in zw_codes:
                    zw_codes.append(code)
            elif (cp < 0x20 and ch not in {"\t", "\n", "\r"}) or cp == 0x7F or (0x80 <= cp <= 0x9F):
                code = f"0x{cp:02X}"
                if code not in ctrl_codes:
                    ctrl_codes.append(code)

        if bidi_codes:
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-UNICODE-001",
                    severity=AuditSeverity.HIGH,
                    category=AuditCategory.HIDDEN_UNICODE,
                    file_path=rel_posix,
                    line_number=line_number,
                    title="Bidirectional Unicode control character in agent file",
                    description=(
                        "Line contains bidirectional control codepoints "
                        f"({', '.join(bidi_codes[:5])}) that can reorder displayed text "
                        "and conceal instructions during review."
                    ),
                    remediation=(
                        "Remove bidirectional formatting characters and keep agent instructions in "
                        "visible plain text."
                    ),
                    snippet=format_safe_snippet(line, context),
                )
            )
        if tag_codes:
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-UNICODE-002",
                    severity=AuditSeverity.HIGH,
                    category=AuditCategory.HIDDEN_UNICODE,
                    file_path=rel_posix,
                    line_number=line_number,
                    title="Invisible Unicode tag character in agent file",
                    description=(
                        f"Line contains invisible Unicode tag or variation-selector codepoints "
                        f"({', '.join(tag_codes[:5])}) that can smuggle hidden tokens to a model."
                    ),
                    remediation="Strip all U+E0000..U+E01EF codepoints from the file before use.",
                    snippet=format_safe_snippet(line, context),
                )
            )
        if zw_codes:
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-UNICODE-003",
                    severity=AuditSeverity.MEDIUM,
                    category=AuditCategory.HIDDEN_UNICODE,
                    file_path=rel_posix,
                    line_number=line_number,
                    title="Zero-width Unicode character in agent file",
                    description=(
                        f"Line contains zero-width or invisible formatting codepoints "
                        f"({', '.join(zw_codes[:5])}) that can disguise keywords or payloads."
                    ),
                    remediation="Remove zero-width spaces, joiners, and mid-file byte-order marks.",
                    snippet=format_safe_snippet(line, context),
                )
            )
        if ctrl_codes:
            context.findings.append(
                AgentConfigFinding(
                    rule_id="AGENT-UNICODE-004",
                    severity=AuditSeverity.MEDIUM,
                    category=AuditCategory.HIDDEN_UNICODE,
                    file_path=rel_posix,
                    line_number=line_number,
                    title="Control character in agent text file",
                    description=(
                        "Line contains non-printable C0/C1 control bytes "
                        f"({', '.join(ctrl_codes[:5])}) that can alter terminal rendering "
                        "or parser behavior."
                    ),
                    remediation=(
                        "Remove non-printable control characters from the instruction file."
                    ),
                    snippet=format_safe_snippet(line, context),
                )
            )


def _logical_lines_with_numbers(lines: Sequence[str]) -> list[tuple[int, str, str]]:
    """Return per-line entries plus joined backslash-continued logical lines."""

    entries: list[tuple[int, str, str]] = []
    idx = 0
    total = len(lines)
    while idx < total:
        raw_line = lines[idx]
        norm_line = strip_invisible_for_matching(raw_line)
        entries.append((idx + 1, raw_line, norm_line))
        if norm_line.rstrip().endswith("\\") and idx + 1 < total:
            start_line = idx + 1
            parts = [norm_line.rstrip()[:-1]]
            raw_parts = [raw_line.rstrip()]
            end_idx = idx + 1
            while end_idx < total:
                next_norm = strip_invisible_for_matching(lines[end_idx])
                raw_parts.append(lines[end_idx].strip())
                if next_norm.rstrip().endswith("\\") and end_idx + 1 < total:
                    parts.append(next_norm.rstrip()[:-1])
                    end_idx += 1
                else:
                    parts.append(next_norm)
                    break
            entries.append((start_line, " ".join(raw_parts), " ".join(parts)))
            idx = end_idx + 1
        else:
            idx += 1
    return entries


def scan_text_rules(
    rel_posix: str,
    text: str,
    lines: Sequence[str],
    context: AuditContext,
) -> None:
    """Categories 2, 3, and 4: Prompt overrides, dangerous execution, and credential/exfil."""

    seen_rule_lines: set[tuple[str, int]] = set()

    def emit(
        rule_id: str,
        severity: AuditSeverity,
        category: AuditCategory,
        line_number: int,
        title: str,
        description: str,
        remediation: str,
        raw_line: str,
    ) -> None:
        key = (rule_id, line_number)
        if key in seen_rule_lines:
            return
        seen_rule_lines.add(key)
        context.findings.append(
            AgentConfigFinding(
                rule_id=rule_id,
                severity=severity,
                category=category,
                file_path=rel_posix,
                line_number=line_number,
                title=title,
                description=description,
                remediation=remediation,
                snippet=format_safe_snippet(raw_line, context),
            )
        )

    for line_number, raw_line, norm_line in _logical_lines_with_numbers(lines):
        if _PROMPT_OVERRIDE_RE.search(norm_line):
            emit(
                "AGENT-PROMPT-001",
                AuditSeverity.HIGH,
                AuditCategory.PROMPT_OVERRIDE,
                line_number,
                "Instruction-override phrase in agent file",
                (
                    "File contains language instructing the agent to ignore, disregard, or "
                    "replace prior system or developer rules."
                ),
                "Remove instruction-override phrases and keep task instructions scoped.",
                raw_line,
            )
        if _USER_SUPPRESSION_RE.search(norm_line):
            emit(
                "AGENT-PROMPT-002",
                AuditSeverity.HIGH,
                AuditCategory.PROMPT_OVERRIDE,
                line_number,
                "User-visibility suppression directive in agent file",
                (
                    "File instructs the agent to conceal actions, outputs, or side effects "
                    "from the user."
                ),
                "Remove directives that hide agent behavior or suppress user notifications.",
                raw_line,
            )
        if _APPROVAL_BYPASS_RE.search(norm_line):
            emit(
                "AGENT-PROMPT-003",
                AuditSeverity.HIGH,
                AuditCategory.PROMPT_OVERRIDE,
                line_number,
                "Approval or safety-bypass directive in agent file",
                (
                    "File instructs the agent to skip user confirmation, approval checks, or "
                    "safety controls."
                ),
                "Remove instructions that bypass confirmation prompts or safety checks.",
                raw_line,
            )

        if _PIPED_REMOTE_EXEC_RE.search(norm_line):
            emit(
                "AGENT-EXEC-001",
                AuditSeverity.HIGH,
                AuditCategory.DANGEROUS_EXECUTION,
                line_number,
                "Piped remote command execution snippet",
                (
                    "File contains a command that downloads remote content and pipes it "
                    "directly into a shell or interpreter."
                ),
                (
                    "Do not pipe network downloads into a shell. Pin, verify, and review "
                    "scripts or packages before execution."
                ),
                raw_line,
            )
        if _ENCODED_EXEC_RE.search(norm_line):
            emit(
                "AGENT-EXEC-002",
                AuditSeverity.HIGH,
                AuditCategory.DANGEROUS_EXECUTION,
                line_number,
                "Encoded payload execution snippet",
                (
                    "File decodes Base64 or encoded command text and passes it to a shell, "
                    "interpreter, or PowerShell encoded-command flag."
                ),
                "Replace encoded execution payloads with readable, reviewable commands.",
                raw_line,
            )
        for interp_match in _INLINE_INTERP_EXEC_RE.finditer(norm_line):
            segment = interp_match.group(0)
            if _INLINE_NET_PART_RE.search(segment) and _INLINE_EXEC_PART_RE.search(segment):
                emit(
                    "AGENT-EXEC-003",
                    AuditSeverity.HIGH,
                    AuditCategory.DANGEROUS_EXECUTION,
                    line_number,
                    "Inline interpreter fetch-and-execute snippet",
                    (
                        "File invokes an inline Python or Node one-liner that combines network "
                        "requests with dynamic code execution."
                    ),
                    "Remove inline network-exec one-liners and use audited local scripts.",
                    raw_line,
                )
                break

        if _SENSITIVE_CREDENTIAL_PATH_RE.search(norm_line):
            emit(
                "AGENT-EXFIL-001",
                AuditSeverity.HIGH,
                AuditCategory.CREDENTIAL_OR_EXFIL,
                line_number,
                "Sensitive credential path or metadata endpoint reference",
                (
                    "File references a local credential store (such as .env, SSH keys, cloud "
                    "credentials, or system password files) or a cloud metadata address."
                ),
                (
                    "Remove direct references to sensitive credential files and cloud metadata "
                    "endpoints from agent instructions."
                ),
                raw_line,
            )
        if _EXFIL_WEBHOOK_OR_UPLOAD_RE.search(norm_line):
            emit(
                "AGENT-EXFIL-002",
                AuditSeverity.HIGH,
                AuditCategory.CREDENTIAL_OR_EXFIL,
                line_number,
                "Outbound exfiltration webhook or file-upload command",
                (
                    "File references an external webhook collector domain or a command that "
                    "uploads local file contents over HTTP."
                ),
                "Remove external webhook URLs and outbound file-upload commands.",
                raw_line,
            )

    norm_text = strip_invisible_for_matching(text)
    for match in _HTML_COMMENT_RE.finditer(norm_text):
        body = match.group("body")
        if _SUSPICIOUS_COMMENT_RE.search(body):
            start_offset = match.start()
            line_number = norm_text.count("\n", 0, start_offset) + 1
            raw_snippet = " ".join(match.group(0).splitlines())
            emit(
                "AGENT-PROMPT-004",
                AuditSeverity.HIGH,
                AuditCategory.PROMPT_OVERRIDE,
                line_number,
                "Hidden directive inside HTML comment",
                (
                    "An HTML comment conceals instruction-override, execution, credential, or "
                    "webhook directives that are invisible in rendered Markdown."
                ),
                "Remove HTML comments containing agent directives, commands, or URLs.",
                raw_snippet,
            )
