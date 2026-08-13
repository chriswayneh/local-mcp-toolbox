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
        _Rule(
            "PASSWORD",
            re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?(?P<secret>[^\s'\";]{4,})"),
        ),
        _Rule(
            "CONNECTION_PASSWORD",
            re.compile(
                r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:/@]+:(?P<secret>[^\s@]+)@"
            ),
        ),
        _Rule(
            "CONNECTION_SECRET",
            re.compile(
                r"(?i)(?:accountkey|sharedaccesskey|clientsecret|client_secret)\s*=\s*"
                r"['\"]?(?P<secret>[^\s;'\"]{8,})"
            ),
        ),
        _Rule(
            "API_KEY",
            re.compile(
                r"(?i)(?:api[-_]?key|service[-_]?token|access[-_]?token|token)\s*[:=]\s*"
                r"['\"]?(?P<secret>[A-Za-z0-9._~+/=-]{12,})"
            ),
        ),
        _Rule(
            "AUTHORIZATION_HEADER",
            re.compile(
                r"(?im)(?:authorization|proxy-authorization)\s*:\s*(?P<secret>[^\r\n]{1,2048})"
            ),
        ),
    )
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
                matched_value = match.group("secret")
                fingerprints.append(self.fingerprint(matched_value))
                count += 1
                return match.group(0).replace(matched_value, f"[REDACTED_{current_rule.category}]")

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

    @staticmethod
    def fingerprint(secret: str) -> str:
        """Return a non-reversible short fingerprint; never return the secret itself."""

        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
        return f"sha256:{digest}"
