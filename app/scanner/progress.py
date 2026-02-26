"""Thread-safe in-memory scan progress tracker."""

import threading
from collections import deque
from datetime import datetime, timezone

_STAGE_NAMES = {
    0: "Vorbereitung",
    1: "OSINT",
    2: "GitHub-Suche",
    3: "Repo-Analyse",
    4: "Abschluss",
}

MAX_LOG_ENTRIES = 200
MAX_ACTIVITIES = 20


class ScanCancelled(Exception):
    """Raised when the user requests scan cancellation."""


class ScanProgress:
    """Singleton-style progress object updated by the orchestrator, read by the API."""

    def __init__(self):
        self._lock = threading.Lock()
        self._running = False
        self._stage = 0
        self._stage_name = ""
        self._message = ""
        self._current_item = ""
        self._count = 0
        self._total = 0
        self._findings_so_far = 0
        self._repos_scanned_so_far = 0
        self._cancel_requested = False
        self._log: deque[dict] = deque(maxlen=MAX_LOG_ENTRIES)
        # Activities persist across resets so the dashboard always shows recent items
        self._activities: deque[dict] = deque(maxlen=MAX_ACTIVITIES)

    def update(
        self,
        stage: int,
        stage_name: str | None = None,
        message: str = "",
        current_item: str = "",
        count: int = 0,
        total: int = 0,
    ):
        with self._lock:
            self._running = True
            self._stage = stage
            self._stage_name = stage_name or _STAGE_NAMES.get(stage, f"Stage {stage}")
            self._message = message
            self._current_item = current_item
            self._count = count
            self._total = total

    def set_findings(self, n: int):
        with self._lock:
            self._findings_so_far = n

    def set_repos_scanned(self, n: int):
        with self._lock:
            self._repos_scanned_so_far = n

    def add_log(self, text: str):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        with self._lock:
            self._log.append({"ts": ts, "text": text})

    def add_activity(self, activity_type: str, text: str):
        """Add a structured activity entry that persists after scan reset."""
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        with self._lock:
            self._activities.append({"ts": ts, "type": activity_type, "text": text})

    # --- Cancel ---
    def request_cancel(self):
        with self._lock:
            self._cancel_requested = True

    def is_cancel_requested(self) -> bool:
        with self._lock:
            return self._cancel_requested

    def check_cancelled(self):
        """Raise ScanCancelled if cancellation was requested."""
        if self.is_cancel_requested():
            raise ScanCancelled("Scan vom Benutzer abgebrochen")

    def to_dict(self) -> dict:
        with self._lock:
            total = self._total or 1
            percent = int((self._count / total) * 100) if self._total else 0
            return {
                "running": self._running,
                "stage": self._stage,
                "stage_name": self._stage_name,
                "message": self._message,
                "current_item": self._current_item,
                "count": self._count,
                "total": self._total,
                "percent": min(percent, 100),
                "findings_so_far": self._findings_so_far,
                "repos_scanned_so_far": self._repos_scanned_so_far,
                "cancel_requested": self._cancel_requested,
                "log": list(self._log),
                "activities": list(self._activities),
            }

    def reset(self):
        """Reset scan state. Activities are kept so the dashboard still shows them."""
        with self._lock:
            self._running = False
            self._stage = 0
            self._stage_name = ""
            self._message = ""
            self._current_item = ""
            self._count = 0
            self._total = 0
            self._findings_so_far = 0
            self._repos_scanned_so_far = 0
            self._cancel_requested = False
            self._log.clear()


# Module-level singleton
scan_progress = ScanProgress()
