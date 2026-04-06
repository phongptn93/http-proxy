import http.client
import logging
import re
import select
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import urlparse

from .cert_manager import CertManager
from .config import Config
from .logger import LogEntry, ProxyLogger

log = logging.getLogger("proxy_logger")


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP Proxy request handler supporting both HTTP and HTTPS (CONNECT)."""

    # Shared across all handler instances
    config: Config
    proxy_logger: ProxyLogger
    cert_manager: Optional[CertManager] = None

    # Suppress default stderr logging
    def log_message(self, format, *args):
        pass

    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling."""
        self.server.proxy_logger.stats.conn_open()
        try:
            if self.config.enable_mitm and self.cert_manager:
                self._handle_mitm()
            else:
                self._handle_tunnel()
        finally:
            self.server.proxy_logger.stats.conn_close()

    def _handle_tunnel(self):
        """Plain TCP tunnel without MITM - logs connection but not content."""
        start = time.time()
        host, port = self._parse_host_port(self.path, 443)

        try:
            remote = socket.create_connection((host, port), timeout=30)
        except Exception as e:
            entry = LogEntry(
                id=_gen_id(), timestamp=_now(), client_addr=self.client_address[0],
                method="CONNECT", url=self.path, host=host, tls=True,
                error=str(e), duration_ms=(time.time() - start) * 1000,
            )
            self.server.proxy_logger.log(entry)
            self.send_error(502, f"Cannot connect: {e}")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        # Bidirectional copy
        sent, received = self._tunnel(self.connection, remote)
        remote.close()

        entry = LogEntry(
            id=_gen_id(), timestamp=_now(), client_addr=self.client_address[0],
            method="CONNECT", url=self.path, host=host, tls=True,
            status_code=200, request_size=sent, response_size=received,
            duration_ms=(time.time() - start) * 1000,
        )
        self.server.proxy_logger.log(entry)

    def _handle_mitm(self):
        """MITM TLS interception - decrypt, log, and forward HTTPS traffic."""
        host, port = self._parse_host_port(self.path, 443)

        # Tell client tunnel is established
        self.send_response(200, "Connection Established")
        self.end_headers()

        # Wrap client connection with our MITM certificate
        try:
            ssl_ctx = self.cert_manager.get_ssl_context(host)
            client_ssl = ssl_ctx.wrap_socket(self.connection, server_side=True)
        except ssl.SSLError as e:
            log.debug(f"MITM handshake failed for {host}: {e}")
            return
        except Exception as e:
            log.debug(f"MITM wrap failed for {host}: {e}")
            return

        # Read HTTP requests from the decrypted stream
        try:
            self._proxy_mitm_stream(client_ssl, host, port)
        except Exception:
            pass
        finally:
            try:
                client_ssl.close()
            except Exception:
                pass

    def _proxy_mitm_stream(self, client_ssl: ssl.SSLSocket, host: str, port: int):
        """Read and proxy requests from a MITM'd TLS connection."""
        while True:
            start = time.time()

            # Read request line
            try:
                request_line = b""
                while True:
                    byte = client_ssl.recv(1)
                    if not byte:
                        return
                    request_line += byte
                    if request_line.endswith(b"\r\n"):
                        break

                request_line = request_line.decode("utf-8", errors="replace").strip()
                if not request_line:
                    return

                parts = request_line.split(" ", 2)
                if len(parts) < 3:
                    return
                method, path, _version = parts
            except Exception:
                return

            # Read headers
            headers = {}
            raw_headers = b""
            while True:
                line = b""
                while True:
                    byte = client_ssl.recv(1)
                    if not byte:
                        return
                    line += byte
                    if line.endswith(b"\r\n"):
                        break
                raw_headers += line
                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    break
                if ":" in line_str:
                    k, v = line_str.split(":", 1)
                    headers[k.strip()] = v.strip()

            # Read body if Content-Length present
            req_body = b""
            content_length = int(headers.get("Content-Length", 0))
            if content_length > 0:
                remaining = content_length
                while remaining > 0:
                    chunk = client_ssl.recv(min(remaining, 8192))
                    if not chunk:
                        break
                    req_body += chunk
                    remaining -= len(chunk)

            url = f"https://{host}{path}"

            _print_take_answers(url, method, headers.get("Content-Type", ""), req_body)

            entry = LogEntry(
                id=_gen_id(), timestamp=_now(), client_addr=self.client_address[0],
                method=method, url=url, host=host,
                request_headers=headers, tls=True,
                request_size=len(req_body),
            )

            # Capture request body
            body_limit = self.config.log_body_limit
            if req_body:
                entry.request_body = _safe_body(req_body, body_limit)

            # Forward to actual server
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=30)
                conn.request(method, path, body=req_body if req_body else None, headers=headers)
                resp = conn.getresponse()

                resp_body = resp.read()
                resp_headers = dict(resp.getheaders())

                entry.status_code = resp.status
                entry.response_headers = resp_headers
                entry.response_size = len(resp_body)
                entry.response_body = _safe_body(resp_body, body_limit)
                entry.duration_ms = (time.time() - start) * 1000

                # Send response back to client
                response_line = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
                client_ssl.sendall(response_line.encode())
                for k, v in resp_headers.items():
                    client_ssl.sendall(f"{k}: {v}\r\n".encode())
                client_ssl.sendall(f"Content-Length: {len(resp_body)}\r\n".encode())
                client_ssl.sendall(b"\r\n")
                client_ssl.sendall(resp_body)

                conn.close()

            except Exception as e:
                entry.error = str(e)
                entry.duration_ms = (time.time() - start) * 1000
                try:
                    err_msg = f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway"
                    client_ssl.sendall(err_msg.encode())
                except Exception:
                    pass

            self.server.proxy_logger.log(entry)

    # ----- HTTP forwarding (non-CONNECT) -----

    def do_GET(self):
        self._forward_request()

    def do_POST(self):
        self._forward_request()

    def do_PUT(self):
        self._forward_request()

    def do_DELETE(self):
        self._forward_request()

    def do_PATCH(self):
        self._forward_request()

    def do_HEAD(self):
        self._forward_request()

    def do_OPTIONS(self):
        self._forward_request()

    def _forward_request(self):
        """Forward an HTTP request and log it."""
        self.server.proxy_logger.stats.conn_open()
        start = time.time()
        entry = None

        try:
            parsed = urlparse(self.path)
            host = parsed.hostname or ""
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"

            # Check blocked hosts
            if host.lower() in {h.lower() for h in self.config.blocked_hosts}:
                self.send_error(403, "Blocked by proxy")
                return

            entry = LogEntry(
                id=_gen_id(), timestamp=_now(), client_addr=self.client_address[0],
                method=self.command, url=self.path, host=host,
                request_headers=dict(self.headers), tls=False,
            )

            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            req_body = self.rfile.read(content_length) if content_length > 0 else b""
            entry.request_size = len(req_body)
            if req_body:
                entry.request_body = _safe_body(req_body, self.config.log_body_limit)

            _print_take_answers(self.path, self.command, self.headers.get("Content-Type", ""), req_body)

            try:
                conn = http.client.HTTPConnection(host, port, timeout=30)
                conn.request(self.command, path, body=req_body if req_body else None, headers=dict(self.headers))
                resp = conn.getresponse()

                resp_body = resp.read()
                resp_headers = dict(resp.getheaders())

                entry.status_code = resp.status
                entry.response_headers = resp_headers
                entry.response_size = len(resp_body)
                entry.response_body = _safe_body(resp_body, self.config.log_body_limit)
                entry.duration_ms = (time.time() - start) * 1000

                # Send response to client
                self.send_response(resp.status)
                for k, v in resp_headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(resp_body)

                conn.close()

            except Exception as e:
                entry.error = str(e)
                entry.duration_ms = (time.time() - start) * 1000
                try:
                    self.send_error(502, f"Bad gateway: {e}")
                except Exception:
                    pass

        except (BrokenPipeError, ConnectionResetError):
            if entry and not entry.error:
                entry.error = "client disconnected"
                entry.duration_ms = (time.time() - start) * 1000
        except Exception as e:
            if entry:
                entry.error = str(e)
                entry.duration_ms = (time.time() - start) * 1000
        finally:
            if entry:
                self.server.proxy_logger.log(entry)
            self.server.proxy_logger.stats.conn_close()

    # ----- Helpers -----

    def _tunnel(self, client: socket.socket, remote: socket.socket) -> tuple[int, int]:
        """Bidirectional TCP copy. Returns (sent, received) bytes."""
        sent = 0
        received = 0
        sockets = [client, remote]
        timeout = 60

        while True:
            readable, _, errors = select.select(sockets, [], sockets, timeout)
            if errors:
                break
            if not readable:
                break

            for sock in readable:
                try:
                    data = sock.recv(8192)
                except Exception:
                    return sent, received

                if not data:
                    return sent, received

                if sock is client:
                    remote.sendall(data)
                    sent += len(data)
                else:
                    client.sendall(data)
                    received += len(data)

        return sent, received

    @staticmethod
    def _parse_host_port(address: str, default_port: int) -> tuple[str, int]:
        if ":" in address:
            host, port_str = address.rsplit(":", 1)
            try:
                return host, int(port_str)
            except ValueError:
                return address, default_port
        return address, default_port


class ThreadedProxyServer(HTTPServer):
    """Threaded HTTP server for handling concurrent proxy connections."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config: Config, proxy_logger: ProxyLogger, cert_manager: Optional[CertManager] = None):
        self.proxy_logger = proxy_logger

        # Configure the handler class
        ProxyHandler.config = config
        ProxyHandler.proxy_logger = proxy_logger
        ProxyHandler.cert_manager = cert_manager

        super().__init__((config.listen_host, config.listen_port), ProxyHandler)

    def process_request(self, request, client_address):
        """Handle each request in a new thread."""
        t = threading.Thread(target=self.process_request_thread, args=(request, client_address))
        t.daemon = True
        t.start()

    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Client disconnected
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)


# ----- Utility functions -----

def _parse_take_answers(content_type: str, body: bytes) -> dict[int, str]:
    """Parse take_info[N][correct] values from multipart form-data body.

    Returns a mapping of question index -> correct answer value.
    """
    if not content_type or "multipart/form-data" not in content_type:
        return {}

    boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
    if not boundary_match:
        return {}

    boundary = boundary_match.group(1).strip('"')
    delimiter = f"--{boundary}".encode()

    answers: dict[int, str] = {}
    for part in body.split(delimiter):
        if not part or part.startswith(b"--"):
            continue
        if b"\r\n\r\n" not in part:
            continue

        headers_raw, value = part.split(b"\r\n\r\n", 1)
        headers_str = headers_raw.decode("utf-8", errors="replace")

        name_match = re.search(r'name="([^"]+)"', headers_str)
        if not name_match:
            continue

        name = name_match.group(1)
        correct_match = re.match(r"take_info\[(\d+)\]\[correct\]$", name)
        if correct_match:
            idx = int(correct_match.group(1))
            answers[idx] = value.rstrip(b"\r\n").decode("utf-8", errors="replace")

    return answers


def _print_take_answers(url: str, method: str, content_type: str, body: bytes) -> None:
    """If the request is a save-take POST, print correct answers to console."""
    if method != "POST" or "save-take" not in url:
        return

    answers = _parse_take_answers(content_type, body)
    if not answers:
        return

    log.info(f"[save-take] {url}")
    for idx in sorted(answers):
        log.info(f"  Câu {idx + 1}: Đáp án {answers[idx]}")


def _gen_id() -> str:
    return uuid.uuid4().hex[:16]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_body(data: bytes, limit: int) -> str:
    """Convert body bytes to a safe string for logging."""
    if not data:
        return ""

    # Check for binary content
    if _is_binary(data[:512]):
        return f"[binary data: {len(data)} bytes]"

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return f"[binary data: {len(data)} bytes]"

    if limit > 0 and len(text) > limit:
        return text[:limit] + "...[truncated]"

    return text


def _is_binary(data: bytes) -> bool:
    """Check if data appears to be binary."""
    if not data:
        return False
    if b"\x00" in data:
        return True
    non_printable = sum(1 for b in data if b < 32 and b not in (10, 13, 9))
    return non_printable / len(data) > 0.3
