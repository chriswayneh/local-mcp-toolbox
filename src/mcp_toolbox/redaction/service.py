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


# An exact redaction marker followed by a delimiter (or end of value) is already safe.
_MARKER_AHEAD = r"\[REDACTED_[A-Z_]+\](?=[\s'\",;}\]]|$)"


def _keyed_rules(category: str, key: str) -> tuple[_Rule, _Rule]:
    """Rules for ``key = value`` style secrets: no length floor, since the key names a secret.

    The quoted form takes everything up to the matching unescaped quote (backslash escapes and
    YAML's doubled-quote escape included). The unquoted form takes the rest of the line, so a
    value with spaces or punctuation cannot leak its tail.
    """

    prefix = rf"(?im){key}['\"]?[ \t]*[:=][ \t]*"
    quoted = _Rule(
        category,
        re.compile(
            prefix + r"(?P<quote>['\"])"
            r"(?!\[REDACTED_[A-Z_]+\](?P=quote))"
            r"(?P<secret>(?:\\[^\r\n]|(?P=quote)(?P=quote)|(?!(?P=quote))[^\\\r\n])+)"
            r"(?P=quote)(?!(?P=quote))"
        ),
    )
    unquoted = _Rule(
        category,
        re.compile(
            prefix
            + r"(?!['\"]?"
            + _MARKER_AHEAD
            + r")(?P<secret>\S(?:(?!\[REDACTED_[A-Z_]+\])[^\r\n])*)"
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
                r"(?i)[a-z][a-z0-9+.-]*://[^\s:/@]+:(?P<secret>[^\r\n]{1,256}?)@"
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
        *_keyed_rules("SECRET_ASSIGNMENT", r"(?<![a-z0-9_.-])[a-z0-9_.-]*secret[a-z0-9_.-]*"),
        _Rule(
            "COOKIE",
            re.compile(r"(?im)^(?:set-)?cookie\s*:\s*(?P<secret>[^\r\n]{1,2048})"),
        ),
        *_keyed_rules(
            "API_KEY",
            r"(?<![a-z0-9])(?:[a-z0-9_.-]*[-_.])?(?:api[-_]?key|token)(?![a-z0-9_.-])",
        ),
        _Rule(
            "AUTHORIZATION_HEADER",
            re.compile(
                r"(?im)(?:authorization|proxy-authorization)\s*:\s*(?P<secret>[^\r\n]{1,2048})"
            ),
        ),
    )
    # Mapping keys whose string values are always secrets, whatever the value looks like.
    _SENSITIVE_KEY = re.compile(
        r"(?i)(?:password|passwd|passphrase|pwd|secret|token|api[-_]?key|private[-_]?key"
        r"|authorization|cookie|credential)"
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
                while end > start and whole[end - 1 - offset] in " \t":
                    end -= 1
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
        """Return True for a non-empty string stored under a secret-looking key."""

        return (
            isinstance(item, str)
            and bool(item)
            and cls._REDACTION_MARKER.fullmatch(item) is None
            and cls._SENSITIVE_KEY.search(key) is not None
        )

    @staticmethod
    def fingerprint(secret: str) -> str:
        """Return a non-reversible short fingerprint; never return the secret itself."""

        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
        return f"sha256:{digest}"
