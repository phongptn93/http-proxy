import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

logger = logging.getLogger("proxy_logger")


@dataclass
class LogEntry:
    id: str = ""
    timestamp: str = ""
    duration_ms: float = 0
    client_addr: str = ""

    # Request
    method: str = ""
    url: str = ""
    host: str = ""
    request_headers: dict = field(default_factory=dict)
    request_body: str = ""
    request_size: int = 0

    # Response
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body: str = ""
    response_size: int = 0

    # TLS
    tls: bool = False
    tls_version: str = ""

    # Error
    error: str = ""

    def to_json(self) -> str:
        d = asdict(self)
        # Remove empty optional fields
        return json.dumps(
            {k: v for k, v in d.items() if v or k in ("tls", "status_code", "request_size", "response_size")},
            ensure_ascii=False,
        )

    def to_text(self) -> str:
        status = str(self.status_code) if self.status_code else "ERR"
        return (
            f"[{self.timestamp}] {self.client_addr} {self.method} {self.url} "
            f"-> {status} ({self.duration_ms:.0f}ms, req:{self.request_size} resp:{self.response_size})"
        )


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.total_requests: int = 0
        self.total_bytes: int = 0
        self.active_conns: int = 0
        self.error_count: int = 0
        self.start_time: float = time.time()
        self.recent_entries: list[dict] = []
        self._max_recent = 200

    def record(self, entry: LogEntry):
        with self._lock:
            self.total_requests += 1
            self.total_bytes += entry.request_size + entry.response_size
            if entry.error:
                self.error_count += 1
            self.recent_entries.append(json.loads(entry.to_json()))
            if len(self.recent_entries) > self._max_recent:
                self.recent_entries = self.recent_entries[-self._max_recent:]

    def conn_open(self):
        with self._lock:
            self.active_conns += 1

    def conn_close(self):
        with self._lock:
            self.active_conns -= 1

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "total_requests": self.total_requests,
                "total_bytes": self.total_bytes,
                "active_conns": self.active_conns,
                "error_count": self.error_count,
                "uptime_seconds": int(time.time() - self.start_time),
            }


class ProxyLogger:
    """Structured logger with file rotation for proxy traffic."""

    def __init__(
        self,
        log_dir: str = "logs",
        max_size_mb: int = 100,
        max_backups: int = 10,
        log_format: str = "json",
    ):
        self.log_format = log_format
        self.stats = Stats()

        # Setup log directory
        Path(log_dir).mkdir(parents=True, exist_ok=True)

        # Setup rotating file handler
        log_file = os.path.join(log_dir, "proxy.log")
        self._handler = RotatingFileHandler(
            log_file,
            maxBytes=max_size_mb * 1024 * 1024,
            backupCount=max_backups,
            encoding="utf-8",
        )
        self._handler.setFormatter(logging.Formatter("%(message)s"))

        self._logger = logging.getLogger("proxy_traffic")
        self._logger.setLevel(logging.INFO)
        self._logger.addHandler(self._handler)
        # Prevent propagation to root logger
        self._logger.propagate = False

    def log(self, entry: LogEntry):
        """Log a proxy traffic entry."""
        self.stats.record(entry)

        if self.log_format == "text":
            self._logger.info(entry.to_text())
        else:
            self._logger.info(entry.to_json())

    def close(self):
        self._handler.close()
