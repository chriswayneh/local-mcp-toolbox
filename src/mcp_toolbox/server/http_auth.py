"""Strict bearer-token verification for the loopback HTTP transport."""

from __future__ import annotations

import re
from collections.abc import Sequence
from hashlib import sha256
from hmac import compare_digest

from mcp.server.auth.provider import AccessToken
from starlette.types import ASGIApp, Receive, Scope, Send

_MIN_TOKEN_LENGTH = 32
_MAX_TOKEN_LENGTH = 512
_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9._~+/\-]+={0,2}\Z", re.ASCII)
_INVALID_TOKEN_DIGEST = sha256(b"").digest()
_UNAUTHORIZED_MESSAGE = "Unauthorized."
_EMPTY = ""


class BearerAuthenticationError(Exception):
    """Generic authentication failure that never includes credential material."""

    def __init__(self) -> None:
        super().__init__(_UNAUTHORIZED_MESSAGE)


class BearerTokenVerifier:
    """Verify one strict Authorization header while retaining only a token digest."""

    __slots__ = ("_expected_digest", "_resource")

    def __init__(self, token: str, resource: str) -> None:
        """Hash a valid configured token immediately instead of retaining its raw value."""

        if not _is_valid_token(token):
            raise ValueError(
                "Bearer token must be 32 to 512 ASCII token characters without whitespace."
            )
        self._expected_digest = _digest(token)
        self._resource = resource

    def verify_authorization_headers(self, values: Sequence[str]) -> None:
        """Require exactly one well-formed Bearer header with the configured token."""

        header = values[0] if len(values) == 1 and isinstance(values[0], str) else None
        token = _parse_bearer_header(header)
        candidate_digest = _digest(token) if token is not None else _INVALID_TOKEN_DIGEST

        matches = compare_digest(candidate_digest, self._expected_digest)
        if token is None or not matches:
            raise BearerAuthenticationError

    async def verify_token(self, token: str) -> AccessToken | None:
        """Implement the SDK verifier contract without returning credential material."""

        candidate_digest = _digest(token) if _is_valid_token(token) else _INVALID_TOKEN_DIGEST
        if not compare_digest(candidate_digest, self._expected_digest):
            return None
        return AccessToken(
            token=_EMPTY,
            client_id="local-mcp-toolbox",
            scopes=["toolbox:read"],
            resource=self._resource,
        )


class AuthorizationHeaderGuard:
    """Reject duplicate, malformed, or invalid bearer headers before SDK routing."""

    def __init__(self, app: ASGIApp, verifier: BearerTokenVerifier) -> None:
        self._app = app
        self._verifier = verifier

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        try:
            values = [
                value.decode("ascii", errors="strict")
                for name, value in scope.get("headers", [])
                if name.lower() == b"authorization"
            ]
            self._verifier.verify_authorization_headers(values)
        except (BearerAuthenticationError, UnicodeDecodeError):
            await _send_unauthorized(send)
            return
        await self._app(scope, receive, send)


async def _send_unauthorized(send: Send) -> None:
    body = b'{"error":"unauthorized"}'
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"www-authenticate", b"Bearer"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _parse_bearer_header(header: str | None) -> str | None:
    if header is None or header != header.strip():
        return None
    parts = header.split(" ")
    if len(parts) != 2 or parts[0].casefold() != "bearer":
        return None
    token = parts[1]
    return token if _is_valid_token(token) else None


def _is_valid_token(token: object) -> bool:
    return (
        isinstance(token, str)
        and _MIN_TOKEN_LENGTH <= len(token) <= _MAX_TOKEN_LENGTH
        and _TOKEN_PATTERN.fullmatch(token) is not None
    )


def _digest(token: str) -> bytes:
    return sha256(token.encode("ascii")).digest()
