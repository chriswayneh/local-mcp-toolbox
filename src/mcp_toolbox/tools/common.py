"""Shared result controls for read-only tool modules."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from mcp_toolbox.models import ErrorCategory, ResponseMetadata, ToolboxError, ToolResponse

if TYPE_CHECKING:
    from mcp_toolbox.server.runtime import ServerRuntime


# Characters that can hide or reorder text: C0 controls, DEL, C1 controls, the soft
# hyphen, the Mongolian vowel separator, zero-width and invisible format characters,
# bidi marks and controls, line and paragraph separators, variation selectors, the
# byte order mark, lone surrogates, tag characters, and supplementary variation
# selectors. A backslash is matched too so that every escape is unambiguous.
_CONTROL_CHARACTERS = re.compile(
    r"[\\\x00-\x1f\x7f-\x9f\xad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2064"
    r"\u2066-\u2069\ufe00-\ufe0f\ufeff\ud800-\udfff\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


def _escape_one(match: re.Match[str]) -> str:
    character = match.group()
    if character == "\\":
        return "\\\\"
    code = ord(character)
    if code <= 0x9F:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def escape_control_characters(value: Any) -> Any:  # noqa: ANN401
    """Escape terminal and bidi control characters in every string inside `value`.

    A backslash becomes two backslashes, control characters up to U+009F become `\\xNN`,
    other listed characters become
    `\\uNNNN` (or `\\UNNNNNNNN` above U+FFFF). Other text is unchanged.
    """

    if isinstance(value, str):
        return _CONTROL_CHARACTERS.sub(_escape_one, value)
    if isinstance(value, dict):
        return {key: escape_control_characters(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [escape_control_characters(item) for item in value]
    return value


def bounded_response(
    runtime: ServerRuntime,
    summary: str,
    data: dict[str, Any],
    *,
    untrusted_content: bool = True,
    prior_redactions: int = 0,
    escape_controls: bool = False,
) -> dict[str, Any]:
    """Redact and bound structured tool data before it reaches the MCP transport.

    With `escape_controls`, control and bidi characters are escaped after redaction, so
    redaction still sees the original text and the client never sees the raw characters.
    """

    redacted_data, redaction_count = runtime.redactor.redact_value(data)
    if escape_controls:
        redacted_data = escape_control_characters(redacted_data)
    response = ToolResponse(
        summary=summary,
        data=redacted_data,
        metadata=ResponseMetadata(
            redaction_count=prior_redactions + redaction_count,
            untrusted_content=untrusted_content,
        ),
    )
    payload = response.model_dump_json()
    encoded = payload.encode("utf-8")
    if len(encoded) > runtime.settings.limits.max_output_bytes:
        raise ToolboxError(
            ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
            "The requested result exceeds the configured output limit.",
            remediation="Use a narrower path, lower limit, or more specific query.",
        )
    return response.model_dump(mode="json")


def require_bounded_limit(runtime: ServerRuntime, limit: int) -> int:
    """Validate an operator-configured result limit at a tool boundary."""

    if not 1 <= limit <= runtime.settings.limits.max_records:
        raise ToolboxError(
            ErrorCategory.INVALID_INPUT,
            "The requested result limit is outside the configured bounds.",
            remediation=f"Use a limit between 1 and {runtime.settings.limits.max_records}.",
        )
    return limit
