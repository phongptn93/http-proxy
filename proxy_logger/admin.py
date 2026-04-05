import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .cert_manager import CertManager
from .logger import ProxyLogger

log = logging.getLogger("proxy_logger")

DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head><title>HTTP Proxy Logger - Admin</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #0d1117; color: #c9d1d9; }
  h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 16px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin: 16px 0; }
  .card h2 { color: #58a6ff; margin-top: 0; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .stat { display: inline-block; margin: 10px 20px 10px 0; }
  .stat-value { font-size: 2em; font-weight: bold; color: #f0f6fc; }
  .stat-label { color: #8b949e; font-size: 0.9em; }
  code { color: #e6edf3; background: #0d1117; padding: 2px 6px; border-radius: 4px; }
  .endpoint { background: #1f2937; padding: 8px 12px; border-radius: 4px; margin: 4px 0; display: block; font-family: monospace; }
  table { width: 100%%; border-collapse: collapse; margin-top: 12px; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.85em; }
  th { color: #8b949e; }
  .method { font-weight: bold; }
  .status-2xx { color: #3fb950; } .status-3xx { color: #d29922; } .status-4xx { color: #f85149; } .status-5xx { color: #f85149; font-weight: bold; }
  .error { color: #f85149; }
  #auto-refresh { margin-left: 8px; }
</style>
</head>
<body>
  <h1>HTTP Proxy Logger</h1>
  <div class="card">
    <h2>Dashboard <label><input type="checkbox" id="auto-refresh" checked> Auto-refresh (5s)</label></h2>
    <div id="stats">Loading...</div>
  </div>
  <div class="card">
    <h2>Recent Requests</h2>
    <div id="requests" style="overflow-x:auto;">Loading...</div>
  </div>
  <div class="card">
    <h2>API Endpoints</h2>
    <a class="endpoint" href="/api/stats">GET /api/stats - Proxy statistics (JSON)</a>
    <a class="endpoint" href="/api/logs?limit=50">GET /api/logs?limit=N - Recent log entries (JSON)</a>
    <a class="endpoint" href="/ca.crt">GET /ca.crt - Download CA certificate</a>
    <a class="endpoint" href="/api/health">GET /api/health - Health check</a>
  </div>
  <div class="card">
    <h2>Setup</h2>
    <p>1. Set HTTP proxy to <code>localhost:8080</code></p>
    <p>2. For HTTPS inspection, install the CA cert: <a href="/ca.crt">Download CA Certificate</a></p>
    <p>3. Import into your browser/system trust store</p>
  </div>
  <script>
    function statusClass(s){if(s>=500)return'status-5xx';if(s>=400)return'status-4xx';if(s>=300)return'status-3xx';return'status-2xx';}
    function formatUptime(s){var d=Math.floor(s/86400),h=Math.floor((s%%86400)/3600),m=Math.floor((s%%3600)/60);return(d>0?d+'d ':'')+(h>0?h+'h ':'')+(m>0?m+'m':'<1m');}
    function refresh(){
      fetch('/api/stats').then(r=>r.json()).then(d=>{
        document.getElementById('stats').innerHTML=
          '<div class="stat"><div class="stat-value">'+d.total_requests+'</div><div class="stat-label">Total Requests</div></div>'+
          '<div class="stat"><div class="stat-value">'+(d.total_bytes/1024/1024).toFixed(2)+' MB</div><div class="stat-label">Total Traffic</div></div>'+
          '<div class="stat"><div class="stat-value">'+d.active_conns+'</div><div class="stat-label">Active Conns</div></div>'+
          '<div class="stat"><div class="stat-value">'+d.error_count+'</div><div class="stat-label">Errors</div></div>'+
          '<div class="stat"><div class="stat-value">'+formatUptime(d.uptime_seconds)+'</div><div class="stat-label">Uptime</div></div>';
      });
      fetch('/api/logs?limit=30').then(r=>r.json()).then(d=>{
        var rows='<table><tr><th>Time</th><th>Method</th><th>URL</th><th>Status</th><th>Size</th><th>Duration</th></tr>';
        (d.entries||[]).reverse().forEach(e=>{
          var sc=e.status_code||0;
          var scStr=e.error?'<span class="error">ERR</span>':'<span class="'+statusClass(sc)+'">'+sc+'</span>';
          var url=e.url||'';if(url.length>60)url=url.substring(0,60)+'...';
          rows+='<tr><td>'+(e.timestamp||'').substring(11,23)+'</td><td class="method">'+e.method+'</td><td>'+url+'</td><td>'+scStr+'</td><td>'+(e.response_size||0)+'</td><td>'+(e.duration_ms||0).toFixed(0)+'ms</td></tr>';
        });
        rows+='</table>';
        document.getElementById('requests').innerHTML=rows;
      });
    }
    refresh();
    setInterval(()=>{if(document.getElementById('auto-refresh').checked)refresh();},5000);
  </script>
</body>
</html>"""


class AdminHandler(BaseHTTPRequestHandler):
    proxy_logger: ProxyLogger
    cert_manager: Optional[CertManager] = None

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/" or path == "":
            self._serve_html(DASHBOARD_HTML)
        elif path == "/api/stats":
            self._serve_json(self.proxy_logger.stats.to_dict())
        elif path == "/api/logs":
            limit = int(params.get("limit", [100])[0])
            entries = self.proxy_logger.stats.recent_entries[-limit:]
            self._serve_json({"count": len(entries), "entries": entries})
        elif path == "/api/health":
            self._serve_json({"status": "ok"})
        elif path == "/ca.crt":
            self._serve_ca_cert()
        else:
            self.send_error(404, "Not found")

    def _serve_json(self, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _serve_html(self, html: str):
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_ca_cert(self):
        if self.cert_manager is None:
            self.send_error(404, "MITM not enabled")
            return
        pem = self.cert_manager.ca_cert_pem
        self.send_response(200)
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Disposition", "attachment; filename=proxy-ca.crt")
        self.send_header("Content-Length", str(len(pem)))
        self.end_headers()
        self.wfile.write(pem)


class AdminServer:
    def __init__(self, proxy_logger: ProxyLogger, cert_manager: Optional[CertManager] = None):
        self.proxy_logger = proxy_logger
        self.cert_manager = cert_manager

    def start(self, host: str, port: int):
        AdminHandler.proxy_logger = self.proxy_logger
        AdminHandler.cert_manager = self.cert_manager

        HTTPServer.allow_reuse_address = True
        server = HTTPServer((host, port), AdminHandler)
        server.daemon_threads = True
        log.info(f"Admin API listening on {host}:{port}")

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server
