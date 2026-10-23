"""Centralized, deterministic sensitive-data redaction."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from mcp_toolbox.config.settings import RedactionSettings


@dataclass(frozen=True, slots=True)
class RedactionResult:
    """Redacted text plus non-secret metadata for correlation and auditing."""

    text: str
    redaction_count: int
    fingerprints: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Rule:
    category: str
    pattern: re.Pattern[str]


# An exact redaction marker is already safe only when nothing but delimiters follows it on
# the line (``password=[REDACTED_X] realsecret`` still leaks ``realsecret``).
_MARKER_AHEAD = r"(?:\[REDACTED_[A-Z_]+\]['\"]?[ \t,;}\]]*)+\r?$"
# Rest of line is only closing brackets or trailing commas (``\r`` allowed before the newline).
_CLOSERS_TO_EOL = r"[ \t,}\])]*\r?$"
# A quoted identifier-like key (not a marker) followed by ``:`` and a structured value start.
_NEXT_KEY = (
    r"(?:\"(?!\[REDACTED_)[A-Za-z0-9_.-]+\"|'(?!\[REDACTED_)[A-Za-z0-9_.-]+')"
    r"[ \t]*:[ \t]*(?:['\"\d\[{]|-[0-9]|true\b|false\b|null\b|None\b|True\b|False\b|Full\b"
    r"|\[REDACTED_)"
)
# After a quoted-key ``"k": "v"`` value: closers to EOL, or ``,`` and the next key/value.
_STRUCTURAL_COLON = (
    r"(?=" + _CLOSERS_TO_EOL + r"|[ \t}\])]*,[ \t]*(?:[{\[][ \t]*)*" + _NEXT_KEY + r")"
)
# After ``k=...`` or an unquoted-key ``k: ...`` value, only closers/commas to EOL may follow.
_STRUCTURAL_EQUALS = r"(?=" + _CLOSERS_TO_EOL + r")"
_STRUCTURAL_TAIL = (
    r"(?(colon)(?(kquote)"
    + _STRUCTURAL_COLON
    + r"|"
    + _STRUCTURAL_EQUALS
    + r")|"
    + _STRUCTURAL_EQUALS
    + r")"
)
_QUOTED_MARKER = r"(?P<mq>['\"])\[REDACTED_[A-Z_]+\](?P=mq)" + _STRUCTURAL_TAIL


_TRAILING_DELIMITERS = " \t,;}]'\""
_MARKER_NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_MARKER_BODY = re.compile(r"\[REDACTED_[A-Z_]+\]")


def _trim_trailing_markers(text: str, start: int, end: int) -> int:
    """Return ``end`` moved left past trailing blanks and already-redacted markers.

    A to-end-of-line value must not swallow a marker an earlier rule left after it, nor the
    whitespace that separates it from what follows. Runs in linear time on long lines.
    """

    while end > start and text[end - 1] in " \t\r":
        end -= 1
    probe = end
    while probe > start:
        if text[probe - 1] == "]":
            # Scan left over the marker's own alphabet only, so each character is visited a
            # bounded number of times and long runs of "]" stay linear.
            cursor = probe - 1
            while cursor > start and text[cursor - 1] in _MARKER_NAME_CHARS:
                cursor -= 1
            opening = cursor - 1
            if opening >= start and _MARKER_BODY.fullmatch(text, opening, probe):
                # Drop the marker and anything blank before it; keep scanning left.
                end = opening
                while end > start and text[end - 1] in " \t\r":
                    end -= 1
                probe = end
                continue
        if text[probe - 1] in _TRAILING_DELIMITERS:
            probe -= 1
            continue
        break
    return end


def _keyed_rules(category: str, key: str) -> tuple[_Rule, _Rule]:
    """Rules for ``key = value`` style secrets: no length floor, since the key names a secret.

    The quoted form takes everything up to the matching unescaped quote (backslash escapes and
    YAML's doubled-quote escape included). The unquoted form takes the rest of the line, so a
    value with spaces or punctuation cannot leak its tail.
    """

    key_pattern = rf"(?>(?P<kquote>['\"]){key}(?P=kquote)|(?<!['\"]){key}['\"]?|['\"]{key}['\"]?)"
    prefix = rf"(?im){key_pattern}[ \t]*(?:(?P<colon>:)|=)[ \t]*"
    quoted = _Rule(
        category,
        re.compile(
            # Only `key: "value"` (JSON, YAML, dict reprs). With `key=` an opening quote
            # proves nothing about where the value ends, so the unquoted rule takes the line.
            rf"(?im){key_pattern}[ \t]*(?P<colon>:)[ \t]*" + r"(?P<quote>['\"])"
            r"(?!\[REDACTED_[A-Z_]+\](?P=quote)" + _STRUCTURAL_TAIL + r")"
            r"(?P<secret>(?:\\[^\r\n]|(?P=quote)(?P=quote)|(?!(?P=quote))[^\\\r\n])+)"
            # The closing quote must end the value; otherwise the unquoted rule takes the line.
            r"(?P=quote)" + _STRUCTURAL_TAIL
        ),
    )
    unquoted = _Rule(
        category,
        re.compile(
            prefix
            # An empty quoted JSON/YAML value (``"k": ""``) holds nothing to leak; keep its
            # quotes and the line. After ``=`` the quotes may be the secret itself.
            + r"(?(colon)(?!(?:\"\"|'')"
            + _STRUCTURAL_TAIL
            + r"))"
            + r"(?!['\"]?"
            + _MARKER_AHEAD
            + r"|"
            + _QUOTED_MARKER
            # Greedy to end of line (linear); trailing markers are trimmed in ``redact``.
            + r")(?P<secret>\S[^\r\n]*)"
        ),
    )
    return quoted, unquoted


class Redactor:
    """Redact common secret formats before tool responses or audit writes."""

    _BASE_RULES = (
        _Rule(
            "GITHUB_TOKEN",
            re.compile(r"(?P<secret>gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"),
        ),
        _Rule("GITLAB_TOKEN", re.compile(r"(?P<secret>glpat-[A-Za-z0-9_-]{20,})")),
        _Rule(
            "SLACK_TOKEN",
            re.compile(r"(?P<secret>xox[baprs]-[A-Za-z0-9-]{20,})"),
        ),
        _Rule("STRIPE_KEY", re.compile(r"(?P<secret>sk_(?:live|test)_[A-Za-z0-9]{16,})")),
        _Rule("GOOGLE_API_KEY", re.compile(r"(?P<secret>AIza[A-Za-z0-9_-]{20,})")),
        _Rule("AWS_ACCESS_KEY", re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})")),
        _Rule(
            "JWT",
            re.compile(r"(?P<secret>eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})"),
        ),
        _Rule(
            "BEARER_TOKEN",
            re.compile(r"(?i)Bearer\s+(?P<secret>[A-Za-z0-9._~+/=-]{12,})"),
        ),
        *_keyed_rules("PASSWORD", r"(?:password|passwd|pwd)"),
        _Rule(
            "CONNECTION_PASSWORD",
            re.compile(
                r"(?i)(?<![a-z0-9+.-])[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<secret>[^\r\n]{1,256}?)@"
                r"(?=[a-z0-9.-]+(?::\d+)?(?:[/?#]|$))"
            ),
        ),
        _Rule(
            "CONNECTION_SECRET",
            re.compile(
                r"(?i)(?:accountkey|sharedaccesskey)\s*=\s*"
                r"['\"]?(?P<secret>[^\s;'\"]{8,})"
            ),
        ),
        *_keyed_rules("SECRET_ASSIGNMENT", r"(?<![a-z0-9_.-])(?=[a-z0-9_.-]*?secret)[a-z0-9_.-]++"),
        *_keyed_rules("PRIVATE_KEY_ASSIGNMENT", r"(?<![a-z0-9_.-])private[-_]?key(?![a-z0-9_.-])"),
        *_keyed_rules(
            "CREDENTIAL_ASSIGNMENT",
            r"(?<![a-z0-9_.-])(?:[a-z0-9_.-]*[-_.])?credentials?(?![a-z0-9_.-])",
        ),
        *_keyed_rules("PASSWORD", r"(?<![a-z0-9_.-])(?:[a-z0-9_.-]*[-_.])?pass(?![a-z0-9_.-])"),
        _Rule(
            "XML_SECRET",
            re.compile(
                r"(?i)<(?P<tag>(?:[a-z0-9_.-]*[-_.:])?(?:pass|token|api[-_]?key"
                r"|private[-_]?key|credentials?)"
                r"|(?=[a-z0-9_.:-]*?(?:password|passwd|pwd|secret))[a-z0-9_.:-]++"
                # Case-sensitive, matching the key=value rules: authToken, myApiKey, AUTHTOKEN.
                r"|(?-i:(?:[A-Za-z0-9_.-]*[-_.:])?[A-Z0-9]+(?:TOKEN|APIKEY)"
                r"|[A-Za-z0-9_.:-]*[a-z0-9](?:Token|ApiKey)))"
                r"(?:\s[^<>]*)?>(?!\[REDACTED_[A-Z_]+\]</)(?P<secret>[^<]+)</(?P=tag)>"
            ),
        ),
        _Rule(
            "COOKIE",
            re.compile(r"(?im)^(?:set-)?cookie\s*:\s*(?P<secret>[^\r\n]{1,2048})"),
        ),
        *_keyed_rules(
            "API_KEY",
            r"(?<![a-z0-9_.-])(?:[a-z0-9_.-]*[-_.])?(?:api[-_]?key|token)(?![a-z0-9_.-])",
        ),
        # All-caps keys with no separator, such as AUTHTOKEN or MYAPIKEY.
        *_keyed_rules(
            "API_KEY",
            r"(?-i:(?<![A-Za-z0-9_.-])[A-Z0-9]+(?:TOKEN|APIKEY)(?![A-Za-z0-9_.-]))",
        ),
        # camelCase keys such as authToken, accessToken, refreshToken, idToken, myApiKey.
        *_keyed_rules(
            "API_KEY",
            r"(?-i:(?<![A-Za-z0-9_.-])(?=[A-Za-z0-9_.-]*?[a-z0-9](?:Token|ApiKey)"
            r"(?![A-Za-z0-9_.-]))[A-Za-z0-9_.-]++)",
        ),
        _Rule(
            "AUTHORIZATION_HEADER",
            re.compile(
                r"(?im)(?:authorization|proxy-authorization)\s*:\s*(?P<secret>[^\r\n]{1,2048})"
            ),
        ),
    )
    # Mapping keys whose string values are always secrets, whatever the value looks like.
    # The word must end the key or be followed by a separator or a capital (camelCase), so
    # ``tokenizer`` or ``private_key_path`` (a name, not the secret) keep their values.
    _SENSITIVE_KEY = re.compile(
        r"(?i)(?:password|passwd|passphrase|pwd|secret|token|api[-_]?key|private[-_]?key"
        r"|authorization|cookie|credential)s?(?-i:(?![a-z]))"
        r"(?![-_.]?(?:path|file|dir|name|id|type|url|env|ref)(?-i:(?![a-z])))"
    )
    # Only an exact marker counts as already redacted; a marker prefix proves nothing.
    _REDACTION_MARKER = re.compile(r"\[REDACTED_[A-Z_]+\]")
    _PRIVATE_KEY_BEGIN = re.compile(r"-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----")
    _PRIVATE_KEY_END = re.compile(r"-----END(?: [A-Z0-9]+)* PRIVATE KEY-----")
    _EMAIL_RULE = _Rule(
        "EMAIL", re.compile(r"(?P<secret>\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)")
    )
    _IPV4_RULE = _Rule("IP_ADDRESS", re.compile(r"(?P<secret>\b(?:\d{1,3}\.){3}\d{1,3}\b)"))
    _HOME_RULES = (
        _Rule("HOME_PATH", re.compile(r"(?P<secret>[A-Za-z]:\\Users\\[^\\\s]+)")),
        _Rule("HOME_PATH", re.compile(r"(?P<secret>/(?:home|Users)/[^/\s]+)")),
    )

    def __init__(self, settings: RedactionSettings | None = None) -> None:
        self._settings = settings or RedactionSettings()
        rules = list(self._BASE_RULES)
        if self._settings.redact_emails:
            rules.append(self._EMAIL_RULE)
        if self._settings.redact_ip_addresses:
            rules.append(self._IPV4_RULE)
        if self._settings.redact_home_paths:
            rules.extend(self._HOME_RULES)
        self._rules = tuple(rules)

    def redact(self, value: str) -> RedactionResult:
        """Redact all supported values, preserving only safe category labels."""

        redacted, count, fingerprints = self._redact_private_keys(value)

        for rule in self._rules:

            def replace(match: re.Match[str], current_rule: _Rule = rule) -> str:
                nonlocal count
                # Replace only the secret's own span: a short secret such as "a" must
                # not also rewrite the same letters inside the key name.
                start, end = match.span("secret")
                offset = match.start()
                whole = match.group(0)
                # Keep whitespace that separates a to-end-of-line value from what follows.
                end = _trim_trailing_markers(whole, start - offset, end - offset) + offset
                if end == start:
                    return whole
                fingerprints.append(self.fingerprint(whole[start - offset : end - offset]))
                count += 1
                return (
                    whole[: start - offset]
                    + f"[REDACTED_{current_rule.category}]"
                    + whole[end - offset :]
                )

            redacted = rule.pattern.sub(replace, redacted)

        return RedactionResult(redacted, count, tuple(dict.fromkeys(fingerprints)))

    def _redact_private_keys(self, value: str) -> tuple[str, int, list[str]]:
        """Redact PEM blocks with bounded linear scans, including unterminated blocks."""

        cursor = 0
        pieces: list[str] = []
        fingerprints: list[str] = []
        count = 0
        while begin := self._PRIVATE_KEY_BEGIN.search(value, cursor):
            pieces.append(value[cursor : begin.start()])
            end = self._PRIVATE_KEY_END.search(value, begin.end())
            secret_end = end.end() if end is not None else len(value)
            secret = value[begin.start() : secret_end]
            fingerprints.append(self.fingerprint(secret))
            pieces.append("[REDACTED_PRIVATE_KEY]" + ("\n" * secret.count("\n")))
            count += 1
            cursor = secret_end
        pieces.append(value[cursor:])
        return "".join(pieces), count, fingerprints

    def redact_value(self, value: Any) -> tuple[Any, int]:
        """Recursively redact strings in data retained for responses or audits."""

        if isinstance(value, str):
            result = self.redact(value)
            return result.text, result.redaction_count
        if isinstance(value, Mapping):
            redacted: dict[str, Any] = {}
            count = 0
            for key, item in value.items():
                safe_item, item_count = self.redact_value(item)
                if self._is_sensitive_string(str(key), item):
                    # The key says the whole value is a secret, so never keep any part of
                    # it, even when a pattern already redacted a piece.
                    safe_item, item_count = "[REDACTED_SENSITIVE_FIELD]", max(item_count, 1)
                redacted[str(key)] = safe_item
                count += item_count
            return redacted, count
        if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            items: list[Any] = []
            count = 0
            for item in value:
                safe_item, item_count = self.redact_value(item)
                items.append(safe_item)
                count += item_count
            return items, count
        return value, 0

    @classmethod
    def _is_sensitive_string(cls, key: str, item: Any) -> bool:
        """Return True for a non-empty value (string, list or mapping) under a secret key."""

        if isinstance(item, str):
            if not item or cls._REDACTION_MARKER.fullmatch(item) is not None:
                return False
        elif not (isinstance(item, (Mapping, list, tuple)) and bool(item)):
            return False
        return cls._SENSITIVE_KEY.search(key) is not None

    @staticmethod
    def fingerprint(secret: str) -> str:
        """Return a non-reversible short fingerprint; never return the secret itself."""

        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
        return f"sha256:{digest}"
