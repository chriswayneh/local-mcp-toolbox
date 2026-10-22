"""Red Team and QE round-3 findings for #33: marker tails, camelCase keys, ReDoS, XML, empties."""

from __future__ import annotations

import time

import pytest

from mcp_toolbox.redaction.service import Redactor

R = Redactor()


@pytest.mark.parametrize(
    ("raw", "leak"),
    [
        ("password=[REDACTED_X] realsecret", "realsecret"),
        ("password=[REDACTED_X];hunter2", "hunter2"),
        ("api_key=[REDACTED_API_KEY],hunter2", "hunter2"),
        ("pwd=[REDACTED_PASSWORD]\tleak", "leak"),
        ('password="[REDACTED_X]" realsecret', "realsecret"),
        ('password: "abc" realsecret', "realsecret"),
        ("password=''hunter2", "hunter2"),
        ("PASSWORD: ''s3cret", "s3cret"),
        ('password=""hunter2 rest', "hunter2"),
    ],
)
def test_text_after_a_marker_or_empty_quotes_is_redacted(raw: str, leak: str) -> None:
    assert leak not in R.redact(raw).text


@pytest.mark.parametrize(
    "raw",
    [
        "password=[REDACTED_PASSWORD]",
        "password=[REDACTED_PASSWORD] [REDACTED_PRIVATE_KEY]",
        '{"password": "[REDACTED_PASSWORD]", "user": "bob"}',
        '{"password": "", "user": "bob"}',
        "password: ''",
    ],
)
def test_already_safe_values_are_left_alone(raw: str) -> None:
    result = R.redact(raw)
    assert result.text == raw
    assert result.redaction_count == 0


def test_marker_after_secret_is_kept() -> None:
    result = R.redact("password=hunter2 [REDACTED_X]")
    assert result.text == "password=[REDACTED_PASSWORD] [REDACTED_X]"
    assert result.fingerprints == (Redactor.fingerprint("hunter2"),)


@pytest.mark.parametrize("key", ["authToken", "accessToken", "refreshToken", "idToken", "myApiKey"])
def test_camel_case_token_keys_are_redacted(key: str) -> None:
    for raw in (f"{key}=abc123", f'{{"{key}": "abc123", "n": 1}}', f"{key}: abc123"):
        out = R.redact(raw).text
        assert "abc123" not in out, raw
    assert '"n": 1' in R.redact(f'{{"{key}": "abc123", "n": 1}}').text


def test_camel_case_rule_does_not_hit_ordinary_words() -> None:
    for raw in ("publicKey=abc", "tokenizer=bert", "retoken=value"):
        assert R.redact(raw).text == raw


@pytest.mark.parametrize(
    ("raw", "leak"),
    [
        ('<password type="x">h</password>', ">h<"),
        ("<db_password>hunter2</db_password>", "hunter2"),
        ("<ns:token>zzz</ns:token>", "zzz"),
        ("client_credentials=abc123", "abc123"),
        ("user_pass=hunter2", "hunter2"),
    ],
)
def test_more_key_shapes_are_redacted(raw: str, leak: str) -> None:
    assert leak not in R.redact(raw).text


def test_bypass_is_not_a_pass_key() -> None:
    assert R.redact("bypass=yes").text == "bypass=yes"


@pytest.mark.parametrize(
    "raw",
    [
        "secret" * 8000 + "=1",
        "a_" * 30000 + "=1",
        "a." * 30000 + "token",
        "authT" * 10000 + "oken=1",
        "x" * 60000 + "Token",
        "pwd" * 20000,
        "a" * 60000,
        "a1+" * 20000 + "://",
        "password=a" + " ;" * 30000 + "b",
        '"password": "' + "\\\\" * 30000,
        "<password>" * 6000,
        "password=" + "[REDACTED_X] " * 5000 + "z",
    ],
    # Keep test ids short: pytest puts the id in PYTEST_CURRENT_TEST, and Windows caps an
    # environment variable at 32767 characters.
    ids=lambda raw: f"{raw[:12]!r}x{len(raw)}",
)
def test_pathological_lines_redact_in_linear_time(raw: str) -> None:
    started = time.perf_counter()
    R.redact(raw)
    assert time.perf_counter() - started < 2.0


def test_value_with_text_after_closing_quote_is_one_line_redaction() -> None:
    result = R.redact('password: "abc" realsecret')
    assert result.text == "password: [REDACTED_PASSWORD]"
    assert result.redaction_count == 1


def test_rule_matching_only_a_marker_counts_nothing() -> None:
    result = R.redact("cookie: [REDACTED_COOKIE]")
    assert result.text == "cookie: [REDACTED_COOKIE]"
    assert result.redaction_count == 0


@pytest.mark.parametrize(
    "raw",
    [
        'password="[REDACTED_X]", hunter22',
        "password='[REDACTED_X]' }hunter22",
        'password="[REDACTED_X]";hunter22',
        '"password": "[REDACTED_X]", hunter22',
        'authToken="[REDACTED_X]"]hunter22',
        '{"password": "[REDACTED_X]"}, hunter22',
    ],
)
def test_fake_quoted_marker_cannot_hide_a_secret(raw: str) -> None:
    assert "hunter22" not in R.redact(raw).text


@pytest.mark.parametrize(
    "raw",
    [
        '{"a": {"password": "[REDACTED_PASSWORD]"}, "b": 1}',
        "password: '[REDACTED_PASSWORD]'",
    ],
)
def test_quoted_marker_with_structural_rest_is_kept(raw: str) -> None:
    result = R.redact(raw)
    assert result.text == raw
    assert result.redaction_count == 0


@pytest.mark.parametrize("key", ["AUTHTOKEN", "ACCESSTOKEN", "MYAPIKEY", "GITHUBTOKEN"])
def test_all_caps_keys_without_separator_are_redacted(key: str) -> None:
    assert "abc" not in R.redact(f"{key}=abc").text
    assert "abc" not in R.redact(f'{{"{key}": "abc"}}').text


def test_all_caps_rule_skips_plain_words() -> None:
    assert R.redact("TOKENS=3 MONKEY=1").text == "TOKENS=3 MONKEY=1"


@pytest.mark.parametrize(
    "raw",
    [
        "password=[REDACTED_ " + "]" * 300_000,
        "password=x" + "[REDACTED_A]" * 30_000,
        "password=x" + "A]" * 150_000,
        "AUTH" * 50_000 + "TOKEN=1",
    ],
    ids=["brackets-300k", "markers-30k", "letters-brackets-150k", "caps-200k"],
)
def test_trailing_marker_trim_is_linear(raw: str) -> None:
    started = time.perf_counter()
    R.redact(raw)
    assert time.perf_counter() - started < 2.0
