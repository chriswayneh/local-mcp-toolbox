from __future__ import annotations

import asyncio
from hashlib import sha256

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import mcp_toolbox.server.http_auth as http_auth
from mcp_toolbox.server.http_auth import (
    AuthorizationHeaderGuard,
    BearerAuthenticationError,
    BearerTokenVerifier,
)

_TOKEN = "correct-token-value-with-at-least-32-characters"
_RESOURCE = "http://127.0.0.1:8765/mcp"


def test_verifier_accepts_exact_token_and_case_insensitive_scheme() -> None:
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)

    verifier.verify_authorization_headers([f"Bearer {_TOKEN}"])
    verifier.verify_authorization_headers([f"bEaReR {_TOKEN}"])


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [f"Bearer {_TOKEN}", f"Bearer {_TOKEN}"],
        ["Basic ZGVtbzpkZW1v"],
        ["Bearer"],
        [f"Bearer  {_TOKEN}"],
        [f"Bearer\t{_TOKEN}"],
        [f" Bearer {_TOKEN}"],
        [f"Bearer {_TOKEN} "],
        ["Bearer wrong-token-value-with-at-least-32-characters"],
        ["Bearer invalid token value with spaces"],
        ["Bearer non-ascii-token-value-with-emoji-xxxxxxxxx☃"],
    ],
)
def test_verifier_rejects_missing_duplicate_malformed_and_wrong_headers(
    headers: list[str],
) -> None:
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)

    with pytest.raises(BearerAuthenticationError, match=r"^Unauthorized\.$"):
        verifier.verify_authorization_headers(headers)


def test_all_runtime_failures_use_the_same_generic_error() -> None:
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)
    messages: set[str] = set()

    for headers in ([], ["Bearer malformed"], [f"Bearer {'x' * len(_TOKEN)}"]):
        with pytest.raises(BearerAuthenticationError) as raised:
            verifier.verify_authorization_headers(headers)
        messages.add(str(raised.value))

    assert messages == {"Unauthorized."}


@pytest.mark.parametrize(
    "token",
    [
        "short",
        "x" * 513,
        "token with whitespace that is longer than thirty-two",
        "non-ascii-token-value-with-emoji-xxxxxxxxx☃",
        "invalid!token-value-with-at-least-32-characters",
    ],
)
def test_configured_token_validation_is_strict(token: str) -> None:
    with pytest.raises(ValueError, match="Bearer token"):
        BearerTokenVerifier(token, _RESOURCE)


def test_verifier_retains_only_the_sha256_digest() -> None:
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)

    assert not hasattr(verifier, "__dict__")
    assert verifier._expected_digest == sha256(_TOKEN.encode("ascii")).digest()
    assert isinstance(verifier._expected_digest, bytes)
    assert len(verifier._expected_digest) == 32
    assert _TOKEN not in repr(verifier)


def test_verification_uses_constant_time_digest_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)
    comparisons: list[tuple[bytes, bytes]] = []

    def recording_compare_digest(candidate: bytes, expected: bytes) -> bool:
        comparisons.append((candidate, expected))
        return candidate == expected

    monkeypatch.setattr(http_auth, "compare_digest", recording_compare_digest)

    verifier.verify_authorization_headers([f"Bearer {_TOKEN}"])
    with pytest.raises(BearerAuthenticationError):
        verifier.verify_authorization_headers(["Bearer malformed"])

    assert len(comparisons) == 2
    assert all(len(candidate) == len(expected) == 32 for candidate, expected in comparisons)
    assert comparisons[0][0] == sha256(_TOKEN.encode("ascii")).digest()
    assert comparisons[1][0] == sha256(b"").digest()


def test_sdk_verifier_returns_identity_without_token_material() -> None:
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)

    accepted = asyncio.run(verifier.verify_token(_TOKEN))
    denied = asyncio.run(verifier.verify_token("wrong-token-value-with-at-least-32-characters"))

    assert accepted is not None
    assert accepted.token == ""
    assert accepted.client_id == "local-mcp-toolbox"
    assert accepted.scopes == ["toolbox:read"]
    assert accepted.resource == _RESOURCE
    assert denied is None


def test_header_guard_blocks_missing_and_duplicate_headers() -> None:
    async def endpoint(_request: object) -> PlainTextResponse:
        return PlainTextResponse("accepted")

    app = Starlette(routes=[Route("/mcp", endpoint)])
    verifier = BearerTokenVerifier(_TOKEN, _RESOURCE)

    with TestClient(AuthorizationHeaderGuard(app, verifier)) as client:
        missing = client.get("/mcp")
        duplicate = client.get(
            "/mcp",
            headers=[
                ("Authorization", f"Bearer {_TOKEN}"),
                ("Authorization", f"Bearer {_TOKEN}"),
            ],
        )
        accepted = client.get("/mcp", headers={"Authorization": f"Bearer {_TOKEN}"})

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert duplicate.status_code == 401
    assert accepted.status_code == 200
    assert accepted.text == "accepted"
