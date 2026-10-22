"""Pin each redaction branch so a mutant that drops it fails a test (QE review of #33)."""

from __future__ import annotations

from mcp_toolbox.redaction.service import Redactor

R = Redactor()


def text(value: str) -> str:
    return R.redact(value).text


def test_quoted_value_after_quoted_key_keeps_closing_quote_and_rest() -> None:
    assert text('{"password": "a b", "x": 1}') == '{"password": "[REDACTED_PASSWORD]", "x": 1}'


def test_yaml_doubled_quote_escape_is_part_of_value() -> None:
    assert text("password: 'it''s secret'") == "password: '[REDACTED_PASSWORD]'"


def test_closing_quote_must_end_value_or_line_is_taken() -> None:
    out = text('password: "abc"def ghi')
    assert "def" not in out and "ghi" not in out and "abc" not in out


def test_already_redacted_quoted_marker_is_left_alone() -> None:
    result = R.redact('password: "[REDACTED_PASSWORD]"')
    assert result.text == 'password: "[REDACTED_PASSWORD]"'
    assert result.redaction_count == 0


def test_marker_prefix_without_delimiter_is_redacted() -> None:
    out = text("password=[REDACTED_PASSWORD]tail")
    assert "tail" not in out


def test_trailing_whitespace_is_kept_and_not_fingerprinted() -> None:
    result = R.redact("password=abc  ")
    assert result.text == "password=[REDACTED_PASSWORD]  "
    assert result.fingerprints == (Redactor.fingerprint("abc"),)


def test_fingerprint_covers_secret_only_not_whole_match() -> None:
    result = R.redact("password=hunter2")
    assert result.fingerprints == (Redactor.fingerprint("hunter2"),)


def test_url_password_with_space_is_redacted() -> None:
    out = text("postgres://user:pa ss@db.example/app")
    assert "pa ss" not in out and "pa" not in out.split("@")[0].split(":")[-1]


def test_api_key_rule_needs_word_boundary() -> None:
    assert text("retoken=value") == "retoken=value"
    assert text("my_token=value") == "my_token=[REDACTED_API_KEY]"


def test_empty_json_password_keeps_quotes_and_line() -> None:
    assert text('{"password": "", "user": "bob"}') == '{"password": "", "user": "bob"}'


def test_plain_text_secret_keys_are_redacted() -> None:
    for raw, leak in (
        ('{"privateKey": "abc123"}', "abc123"),
        ('{"credentials": "u:p"}', "u:p"),
        ('{"pass": "hunter2"}', "hunter2"),
        ("<password>hunter2</password>", "hunter2"),
        ("<apiKey>zzz999</apiKey>", "zzz999"),
    ):
        out = text(raw)
        assert leak not in out, raw
        assert "[REDACTED_" in out


def test_plain_text_name_keys_are_not_secrets() -> None:
    assert text("tokenizer: bert") == "tokenizer: bert"
    assert text("private_key_path: /etc/key.pem") == "private_key_path: /etc/key.pem"


def test_xml_marker_is_not_redacted_twice() -> None:
    result = R.redact("<password>[REDACTED_PASSWORD]</password>")
    assert result.redaction_count == 0


def test_mapping_secret_key_replaces_plain_value_and_counts() -> None:
    assert R.redact_value({"apiToken": "plainvalue"}) == (
        {"apiToken": "[REDACTED_SENSITIVE_FIELD]"},
        1,
    )


def test_mapping_empty_secret_stays_empty() -> None:
    assert R.redact_value({"password": ""}) == ({"password": ""}, 0)


def test_mapping_marker_prefix_value_is_redacted() -> None:
    value, _ = R.redact_value({"password": "[REDACTED_PASSWORD]tail"})
    assert value == {"password": "[REDACTED_SENSITIVE_FIELD]"}


def test_mapping_exact_marker_is_kept() -> None:
    assert R.redact_value({"password": "[REDACTED_PASSWORD]"}) == (
        {"password": "[REDACTED_PASSWORD]"},
        0,
    )


def test_mapping_credential_and_pwd_keys() -> None:
    for key in ("credential", "pwd", "privateKey", "db_password", "accessToken"):
        value, count = R.redact_value({key: "x"})
        assert value == {key: "[REDACTED_SENSITIVE_FIELD]"}, key
        assert count == 1


def test_mapping_name_keys_keep_values() -> None:
    data = {"tokenizer": "bert", "private_key_path": "/k.pem", "secret_name": "prod"}
    assert R.redact_value(data) == (data, 0)


def test_list_or_dict_under_secret_key_is_redacted() -> None:
    assert R.redact_value({"x": {"secret": ["a", "b"]}}) == (
        {"x": {"secret": "[REDACTED_SENSITIVE_FIELD]"}},
        1,
    )
    value, count = R.redact_value({"credentials": {"user": "u", "pw": "p"}})
    assert value == {"credentials": "[REDACTED_SENSITIVE_FIELD]"} and count == 1
    assert R.redact_value({"secret": []}) == ({"secret": []}, 0)
