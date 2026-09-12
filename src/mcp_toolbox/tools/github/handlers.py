"""Read-only GitHub inspection through a bounded HTTPS adapter."""

from __future__ import annotations

import json
import os
from typing import Any, Literal, cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from mcp.server import MCPServer
from mcp_types import ToolAnnotations

from mcp_toolbox import __version__
from mcp_toolbox.models import ErrorCategory, ToolboxError
from mcp_toolbox.server.runtime import ServerRuntime
from mcp_toolbox.tools.common import bounded_response, require_bounded_limit

_API_BASE_URL = "https://api.github.com"
_READ_ONLY_EXTERNAL = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=True,
)


class _RejectRedirects(HTTPRedirectHandler):
    """Reject every redirect so credentials cannot cross an origin boundary."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401
        return None


class GitHubGateway:
    """Minimal GitHub REST adapter with no mutation methods or configurable host."""

    def __init__(self, runtime: ServerRuntime) -> None:
        self._runtime = runtime
        self._opener = build_opener(_RejectRedirects())

    def request_json(self, path: str, query: dict[str, str | int] | None = None) -> Any:
        """Fetch one bounded JSON response from the fixed GitHub API origin."""

        url = f"{_API_BASE_URL}{path}"
        if query:
            url = f"{url}?{urlencode(query)}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": f"local-mcp-toolbox/{__version__}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token := os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = f"Bearer {token}"
        request = Request(  # noqa: S310  # nosec B310
            url, headers=headers, method="GET"
        )
        output_limit = self._runtime.settings.limits.max_output_bytes
        try:
            with self._opener.open(  # noqa: S310  # nosec B310
                request,
                timeout=self._runtime.settings.limits.timeout_seconds,
            ) as response:
                payload = response.read(output_limit + 1)
        except HTTPError as error:
            raise _github_http_error(error.code) from error
        except (TimeoutError, URLError) as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "GitHub could not be reached within the configured timeout.",
                remediation="Check network access or disable the GitHub integration.",
            ) from error
        if len(payload) > output_limit:
            raise ToolboxError(
                ErrorCategory.OUTPUT_LIMIT_EXCEEDED,
                "The GitHub response exceeded the configured output limit.",
                remediation="Use a smaller result limit.",
            )
        try:
            return json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ToolboxError(
                ErrorCategory.INTEGRATION_UNAVAILABLE,
                "GitHub returned an unreadable response.",
                remediation="Retry the request or check GitHub service status.",
            ) from error


def register_github_tools(server: MCPServer, runtime: ServerRuntime) -> tuple[str, ...]:
    """Register GitHub metadata tools only after explicit network enablement."""

    if not runtime.permissions.check_integration("github").allowed:
        return ()
    gateway = GitHubGateway(runtime)

    @server.tool(
        name="github_repository_summary",
        title="GitHub repository summary",
        description="Return safe metadata for one explicitly approved GitHub repository.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def github_repository_summary(repository: str) -> dict[str, Any]:
        approved = runtime.permissions.require_github_repository(repository)
        payload = _require_mapping(gateway.request_json(f"/repos/{_repository_path(approved)}"))
        return bounded_response(
            runtime,
            "Collected read-only GitHub repository metadata.",
            _repository_summary(payload),
        )

    @server.tool(
        name="github_recent_issues",
        title="Recent GitHub issues",
        description="Return bounded issue metadata for an explicitly approved repository.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def github_recent_issues(
        repository: str,
        limit: int = 20,
        state: Literal["open", "closed", "all"] = "open",
    ) -> dict[str, Any]:
        approved = runtime.permissions.require_github_repository(repository)
        result_limit = require_bounded_limit(runtime, limit)
        payload = _require_list(
            gateway.request_json(
                f"/repos/{_repository_path(approved)}/issues",
                {"state": state, "per_page": result_limit},
            )
        )
        issues = [
            _issue_summary(item)
            for item in payload
            if isinstance(item, dict) and "pull_request" not in item
        ]
        return bounded_response(
            runtime,
            f"Collected {len(issues)} recent GitHub issues.",
            {"repository": approved, "state": state, "issues": issues},
        )

    @server.tool(
        name="github_recent_pull_requests",
        title="Recent GitHub pull requests",
        description="Return bounded pull-request metadata for an approved repository.",
        annotations=_READ_ONLY_EXTERNAL,
    )
    def github_recent_pull_requests(
        repository: str,
        limit: int = 20,
        state: Literal["open", "closed", "all"] = "open",
    ) -> dict[str, Any]:
        approved = runtime.permissions.require_github_repository(repository)
        result_limit = require_bounded_limit(runtime, limit)
        payload = _require_list(
            gateway.request_json(
                f"/repos/{_repository_path(approved)}/pulls",
                {"state": state, "per_page": result_limit},
            )
        )
        pull_requests = [_pull_request_summary(item) for item in payload if isinstance(item, dict)]
        return bounded_response(
            runtime,
            f"Collected {len(pull_requests)} recent GitHub pull requests.",
            {"repository": approved, "state": state, "pull_requests": pull_requests},
        )

    return (
        "github_repository_summary",
        "github_recent_issues",
        "github_recent_pull_requests",
    )


def _repository_path(repository: str) -> str:
    owner, name = repository.split("/", maxsplit=1)
    return f"{quote(owner, safe='')}/{quote(name, safe='')}"


def _github_http_error(status: int) -> ToolboxError:
    if 300 <= status < 400:
        return ToolboxError(
            ErrorCategory.INTEGRATION_UNAVAILABLE,
            "GitHub returned a redirect that the fixed-origin policy rejected.",
            remediation="Retry later or verify the GitHub API endpoint from a trusted network.",
        )
    if status == 401:
        return ToolboxError(
            ErrorCategory.AUTHENTICATION_FAILED,
            "GitHub rejected the configured authentication token.",
            remediation="Replace or remove the GITHUB_TOKEN environment variable.",
        )
    if status in {403, 429}:
        return ToolboxError(
            ErrorCategory.RATE_LIMITED,
            "GitHub denied the request or its API rate limit was reached.",
            remediation="Check token permissions and GitHub API rate limits.",
        )
    if status == 404:
        return ToolboxError(
            ErrorCategory.RESOURCE_NOT_FOUND,
            "The approved GitHub repository or resource was not found.",
            remediation="Check the repository name and token read access.",
        )
    return ToolboxError(
        ErrorCategory.INTEGRATION_UNAVAILABLE,
        "GitHub returned an unexpected HTTP error.",
        remediation="Retry the request or check GitHub service status.",
    )


def _require_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ToolboxError(
            ErrorCategory.INTEGRATION_UNAVAILABLE,
            "GitHub returned an unexpected response shape.",
            remediation="Retry the request or check GitHub API compatibility.",
        )
    return cast(dict[str, Any], value)


def _require_list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ToolboxError(
            ErrorCategory.INTEGRATION_UNAVAILABLE,
            "GitHub returned an unexpected response shape.",
            remediation="Retry the request or check GitHub API compatibility.",
        )
    return value


def _repository_summary(payload: dict[str, Any]) -> dict[str, Any]:
    license_value = payload.get("license")
    return {
        "full_name": payload.get("full_name"),
        "description": payload.get("description"),
        "visibility": payload.get("visibility"),
        "private": payload.get("private"),
        "archived": payload.get("archived"),
        "default_branch": payload.get("default_branch"),
        "open_issues_count": payload.get("open_issues_count"),
        "pushed_at": payload.get("pushed_at"),
        "html_url": payload.get("html_url"),
        "license": license_value.get("spdx_id") if isinstance(license_value, dict) else None,
        "topics": payload.get("topics") if isinstance(payload.get("topics"), list) else [],
    }


def _issue_summary(payload: dict[str, Any]) -> dict[str, Any]:
    user = payload.get("user")
    labels = payload.get("labels")
    return {
        "number": payload.get("number"),
        "title": payload.get("title"),
        "state": payload.get("state"),
        "author": user.get("login") if isinstance(user, dict) else None,
        "labels": [
            label.get("name")
            for label in labels
            if isinstance(label, dict) and isinstance(label.get("name"), str)
        ]
        if isinstance(labels, list)
        else [],
        "created_at": payload.get("created_at"),
        "updated_at": payload.get("updated_at"),
        "html_url": payload.get("html_url"),
    }


def _pull_request_summary(payload: dict[str, Any]) -> dict[str, Any]:
    user = payload.get("user")
    head = payload.get("head")
    base = payload.get("base")
    return {
        "number": payload.get("number"),
        "title": payload.get("title"),
        "state": payload.get("state"),
        "draft": payload.get("draft"),
        "author": user.get("login") if isinstance(user, dict) else None,
        "head": head.get("ref") if isinstance(head, dict) else None,
        "base": base.get("ref") if isinstance(base, dict) else None,
        "created_at": payload.get("created_at"),
        "updated_at": payload.get("updated_at"),
        "merged_at": payload.get("merged_at"),
        "html_url": payload.get("html_url"),
    }
