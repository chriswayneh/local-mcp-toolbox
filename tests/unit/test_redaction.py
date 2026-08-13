from __future__ import annotations

from time import perf_counter

import pytest

from mcp_toolbox.config.settings import RedactionSettings
from mcp_toolbox.redaction import Redactor

_REMAINING_SECRET_CASES = (
    (
        "aws_secret_access_key = " + "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY",
    ),
    ("APP_SECRET=s3cr3t-value-not-a-password-field", "s3cr3t-value-not-a-password-field"),
    (
        "Cookie: session=abc123def456; auth_token=zzzz9999",
        "session=abc123def456; auth_token=zzzz9999",
    ),
    ("Set-Cookie: SESSIONID=9f8e7d6c5b4a3210; HttpOnly", "SESSIONID=9f8e7d6c5b4a3210; HttpOnly"),
    ("REDIS_URL=redis://default:SuperSecret123@cache.internal:6379/0", "SuperSecret123"),
    ("amqp://guest:guestpassword@rabbit:5672/", "guestpassword"),
    ("mssql://sa:P@ssw0rd!@db:1433/app", "P@ssw0rd!"),
    ("https://admin:hunter2@internal.example.test/api", "hunter2"),
)


def test_redacts_common_secret_formats_without_retaining_values() -> None:
    github_token = "ghp_123456789012345678901234567890"
    aws_key = "AKIA1234567890ABCDEF"
    private_key = "-----BEGIN PRIVATE KEY-----\npretend-key\n-----END PRIVATE KEY-----"
    text = f"token={github_token} aws={aws_key} password=demo-pass {private_key}"

    result = Redactor().redact(text)

    assert github_token not in result.text
    assert aws_key not in result.text
    assert private_key not in result.text
    assert "[REDACTED_GITHUB_TOKEN]" in result.text
    assert "[REDACTED_AWS_ACCESS_KEY]" in result.text
    assert "[REDACTED_PRIVATE_KEY]" in result.text
    assert result.redaction_count == 4
    assert all(fingerprint.startswith("sha256:") for fingerprint in result.fingerprints)


def test_optional_privacy_redaction_is_configurable() -> None:
    redactor = Redactor(RedactionSettings(redact_emails=True, redact_ip_addresses=True))

    result = redactor.redact("owner@example.test connected from 192.0.2.42")

    assert "owner@example.test" not in result.text
    assert "192.0.2.42" not in result.text
    assert result.redaction_count == 2


def test_redacts_nested_audit_like_values() -> None:
    token = "github_pat_abcdefghijklmnopqrstuv_abcdefghijklmnopqrstuv"
    redacted, count = Redactor().redact_value({"headers": [f"Bearer {token}"]})

    assert token not in str(redacted)
    assert count == 1


def test_redacts_service_credentials_and_authorization_headers() -> None:
    slack_token = "xoxb-" + "123456789012-123456789012-abcdefghijklmnopqrstuvwx"
    stripe_key = "sk_live_" + "abcdefghijklmnopqrstuvwx"
    secrets = {
        "api_key": ("api_key=generic-api-key-value-12345", "generic-api-key-value-12345"),
        "gitlab": ("glpat-abcdefghijklmnopqrst", "glpat-abcdefghijklmnopqrst"),
        "slack": (slack_token, slack_token),
        "stripe": (stripe_key, stripe_key),
        "google": ("AIzaSyDUMMYKEYVALUE123456789012345", "AIzaSyDUMMYKEYVALUE123456789012345"),
        "connection": ("AccountKey=connection-secret-value-12345", "connection-secret-value-12345"),
        "authorization": (
            "Authorization: Basic ZGVtbzpzdXBlci1zZWNyZXQ=",
            "Basic ZGVtbzpzdXBlci1zZWNyZXQ=",
        ),
    }

    result = Redactor().redact("\n".join(value for value, _ in secrets.values()))

    for _, secret in secrets.values():
        assert secret not in result.text
    assert result.redaction_count == len(secrets)


def test_private_key_redaction_is_linear_for_unterminated_input() -> None:
    malicious = "-----BEGIN PRIVATE KEY-----\n" + ("A" * 895_000)
    started = perf_counter()

    result = Redactor().redact(malicious)

    assert perf_counter() - started < 1.0
    assert "A" * 100 not in result.text
    assert "[REDACTED_PRIVATE_KEY]" in result.text


@pytest.mark.parametrize(("value", "secret"), _REMAINING_SECRET_CASES)
def test_redacts_remaining_credential_shapes(value: str, secret: str) -> None:
    result = Redactor().redact(value)

    assert secret not in result.text
    assert result.redaction_count == 1


def test_public_ssh_key_is_not_redacted() -> None:
    non_secret_values = (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7f3 user@host",
        "INFO worker_count=10 connection established",
        "https://internal.example.test/api",
        "feature_flag=enabled",
    )

    for value in non_secret_values:
        result = Redactor().redact(value)

        assert result.text == value
        assert result.redaction_count == 0
