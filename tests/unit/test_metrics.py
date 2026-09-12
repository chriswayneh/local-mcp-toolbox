from __future__ import annotations

from mcp_toolbox.metrics import MetricsRegistry


def test_metrics_registry_aggregates_sanitized_counts() -> None:
    metrics = MetricsRegistry()

    metrics.record("filesystem", "success", 10)
    metrics.record("filesystem", "denied", 4)
    metrics.record("x" * 150, "unexpected", -1)

    snapshot = metrics.snapshot()
    assert snapshot["request_count"] == 3
    assert snapshot["status_counts"] == {"denied": 1, "error": 1, "success": 1}
    assert snapshot["module_counts"]["filesystem"] == 2
    assert snapshot["module_counts"]["x" * 100] == 1
    assert snapshot["duration_ms_total"] == 14
    assert snapshot["duration_ms_max"] == 10
    assert snapshot["duration_ms_average"] == 4.67
