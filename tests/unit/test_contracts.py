from __future__ import annotations

from mcp_toolbox.models import ErrorCategory, ToolboxError, ToolResponse


def test_tool_response_marks_data_as_untrusted_by_default() -> None:
    response = ToolResponse(summary="Found one file", data={"path": "example.txt"})

    assert response.metadata.untrusted_content is True


def test_toolbox_error_returns_safe_structured_response() -> None:
    error = ToolboxError(
        ErrorCategory.PERMISSION_DENIED,
        "Access denied.",
        request_id="request-123",
        remediation="Use an approved root.",
    )

    response = error.to_response()

    assert response.category is ErrorCategory.PERMISSION_DENIED
    assert response.request_id == "request-123"
