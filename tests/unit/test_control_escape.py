from __future__ import annotations

from mcp_toolbox.tools.common import escape_control_characters


def test_c0_c1_and_delete_are_escaped() -> None:
    assert escape_control_characters("a\x1b[31mb\x00c\x7fd\x85e\x9f") == (
        "a\\x1b[31mb\\x00c\\x7fd\\x85e\\x9f"
    )


def test_tab_and_newline_are_escaped() -> None:
    assert escape_control_characters("a\tb\nc\rd") == "a\\x09b\\x0ac\\x0dd"


def test_bidi_controls_are_escaped() -> None:
    text = "".join(chr(c) for c in [*range(0x202A, 0x202F), *range(0x2066, 0x206A)])
    escaped = escape_control_characters(text)
    assert escaped == "".join(
        f"\\u{c:04x}" for c in [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]
    )
    assert escape_control_characters("\u200e\u200f\u061c\u2028\u2029") == (
        "\\u200e\\u200f\\u061c\\u2028\\u2029"
    )


def test_backslash_is_doubled_so_escapes_are_unambiguous() -> None:
    assert escape_control_characters("C:\\x1b") == "C:\\\\x1b"


def test_ordinary_unicode_is_kept() -> None:
    assert escape_control_characters("caf\u00e9 \u65e5\u672c \U0001f600") == (
        "caf\u00e9 \u65e5\u672c \U0001f600"
    )


def test_nested_values_are_escaped_and_non_strings_kept() -> None:
    value = {"a": ["x\x1by", {"b": "\u202e"}], "n": 3, "t": True, "z": None}
    assert escape_control_characters(value) == {
        "a": ["x\\x1by", {"b": "\\u202e"}],
        "n": 3,
        "t": True,
        "z": None,
    }


def test_invisible_format_characters_are_escaped() -> None:
    for code in [0x00AD, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2064, 0xFEFF, 0xFE00, 0xFE0F]:
        assert escape_control_characters(f"a{chr(code)}b") == f"a\\u{code:04x}b"


def test_astral_tag_and_variation_selectors_are_escaped() -> None:
    assert escape_control_characters("a\U000e0041b") == "a\\U000e0041b"
    for code in [0xE0000, 0xE007F, 0xE0100, 0xE01EF]:
        assert escape_control_characters(chr(code)) == f"\\U{code:08x}"


def test_lone_surrogates_are_escaped() -> None:
    assert escape_control_characters("a\ud800b\udfffc") == "a\\ud800b\\udfffc"
