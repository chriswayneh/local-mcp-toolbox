from __future__ import annotations

from mcp_toolbox.config.settings import RedactionSettings
from mcp_toolbox.redaction import Redactor


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
