import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Config:
    # Proxy
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    admin_port: int = 8081

    # MITM / TLS
    enable_mitm: bool = True
    ca_dir: str = "certs"

    # Logging
    log_dir: str = "logs"
    log_max_size_mb: int = 100
    log_max_backups: int = 10
    log_body_limit: int = 64 * 1024  # 64KB
    log_format: str = "json"  # "json" or "text"

    # Filtering
    blocked_hosts: list[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str) -> "Config":
        data = json.loads(Path(path).read_text())
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    @classmethod
    def from_args(cls) -> "Config":
        parser = argparse.ArgumentParser(description="HTTP Proxy Logger")
        parser.add_argument("--config", help="Path to JSON config file")
        parser.add_argument("--host", default=None, help="Listen host (default: 0.0.0.0)")
        parser.add_argument("--port", type=int, default=None, help="Proxy port (default: 8080)")
        parser.add_argument("--admin-port", type=int, default=None, help="Admin API port (default: 8081)")
        parser.add_argument("--no-mitm", action="store_true", help="Disable MITM HTTPS inspection")
        parser.add_argument("--log-dir", default=None, help="Log directory (default: logs)")
        parser.add_argument("--log-format", choices=["json", "text"], default=None, help="Log format")
        parser.add_argument("--log-body-limit", type=int, default=None, help="Max body bytes to log")
        args = parser.parse_args()

        # Load from file first, then override with CLI args
        if args.config:
            cfg = cls.from_file(args.config)
        else:
            cfg = cls()

        if args.host is not None:
            cfg.listen_host = args.host
        if args.port is not None:
            cfg.listen_port = args.port
        if args.admin_port is not None:
            cfg.admin_port = args.admin_port
        if args.no_mitm:
            cfg.enable_mitm = False
        if args.log_dir is not None:
            cfg.log_dir = args.log_dir
        if args.log_format is not None:
            cfg.log_format = args.log_format
        if args.log_body_limit is not None:
            cfg.log_body_limit = args.log_body_limit

        return cfg
