"""Thread-safe aggregate runtime metrics."""

from __future__ import annotations

import threading
from collections import Counter
from datetime import UTC, datetime
from time import monotonic
from typing import Any


class MetricsRegistry:
    """Keep bounded aggregate counts only; never store request or response content."""

    def __init__(self) -> None:
        self._started_at = datetime.now(UTC)
        self._started_monotonic = monotonic()
        self._lock = threading.Lock()
        self._request_count = 0
        self._duration_ms_total = 0
        self._duration_ms_max = 0
        self._statuses: Counter[str] = Counter()
        self._modules: Counter[str] = Counter()

    def record(self, module: str, status: str, duration_ms: int) -> None:
        """Record one sanitized aggregate request outcome."""

        safe_module = module[:100]
        safe_status = status if status in {"success", "error", "denied"} else "error"
        safe_duration = max(0, duration_ms)
        with self._lock:
            self._request_count += 1
            self._duration_ms_total += safe_duration
            self._duration_ms_max = max(self._duration_ms_max, safe_duration)
            self._statuses[safe_status] += 1
            self._modules[safe_module] += 1

    def snapshot(self) -> dict[str, Any]:
        """Return a consistent content-free snapshot."""

        with self._lock:
            request_count = self._request_count
            duration_total = self._duration_ms_total
            return {
                "started_at": self._started_at.isoformat(),
                "uptime_seconds": max(0, int(monotonic() - self._started_monotonic)),
                "request_count": request_count,
                "status_counts": dict(sorted(self._statuses.items())),
                "module_counts": dict(sorted(self._modules.items())),
                "duration_ms_total": duration_total,
                "duration_ms_max": self._duration_ms_max,
                "duration_ms_average": (
                    round(duration_total / request_count, 2) if request_count else 0.0
                ),
            }
