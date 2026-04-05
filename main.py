#!/usr/bin/env python3
"""HTTP Proxy Logger - Capture and log HTTP/HTTPS traffic."""

import logging
import signal
import sys

from proxy_logger.admin import AdminServer
from proxy_logger.cert_manager import CertManager
from proxy_logger.config import Config
from proxy_logger.logger import ProxyLogger
from proxy_logger.proxy_server import ThreadedProxyServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("proxy_logger")


def main():
    cfg = Config.from_args()

    # Initialize logger
    proxy_logger = ProxyLogger(
        log_dir=cfg.log_dir,
        max_size_mb=cfg.log_max_size_mb,
        max_backups=cfg.log_max_backups,
        log_format=cfg.log_format,
    )

    # Initialize certificate manager
    cert_manager = None
    if cfg.enable_mitm:
        try:
            cert_manager = CertManager(ca_dir=cfg.ca_dir)
            log.info(f"MITM enabled - CA certificate: {cert_manager.ca_cert_path}")
            log.info("Install the CA certificate in your browser/system to inspect HTTPS traffic")
        except ImportError:
            log.warning("cryptography package not installed - MITM disabled")
            log.warning("Install with: pip install cryptography")
            cfg.enable_mitm = False

    # Start admin API
    admin = AdminServer(proxy_logger, cert_manager)
    admin.start(cfg.listen_host, cfg.admin_port)

    # Start proxy server
    server = ThreadedProxyServer(cfg, proxy_logger, cert_manager)

    log.info("=" * 48)
    log.info("  HTTP Proxy Logger")
    log.info(f"  Proxy:  {cfg.listen_host}:{cfg.listen_port}")
    log.info(f"  Admin:  {cfg.listen_host}:{cfg.admin_port}")
    log.info(f"  Logs:   {cfg.log_dir}/")
    log.info(f"  MITM:   {cfg.enable_mitm}")
    log.info("=" * 48)

    # Graceful shutdown
    def shutdown(signum, frame):
        log.info("Shutting down...")
        server.shutdown()
        proxy_logger.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
