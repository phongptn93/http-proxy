package admin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/phongptn93/http-proxy/internal/cert"
	"github.com/phongptn93/http-proxy/internal/logger"
)

// Server provides an admin API for monitoring and managing the proxy.
type Server struct {
	logger  *logger.Logger
	certMgr *cert.Manager
	logDir  string
	mux     *http.ServeMux
}

// New creates a new admin API server.
func New(lg *logger.Logger, cm *cert.Manager, logDir string) *Server {
	s := &Server{
		logger:  lg,
		certMgr: cm,
		logDir:  logDir,
		mux:     http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/stats", s.handleStats)
	s.mux.HandleFunc("/logs", s.handleLogs)
	s.mux.HandleFunc("/logs/tail", s.handleLogsTail)
	s.mux.HandleFunc("/ca.crt", s.handleCACert)
	s.mux.HandleFunc("/health", s.handleHealth)
}

// Start starts the admin API server.
func (s *Server) Start(addr string) error {
	log.Printf("Admin API listening on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!DOCTYPE html>
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
  pre { background: #0d1117; padding: 16px; border-radius: 6px; overflow-x: auto; border: 1px solid #30363d; }
  code { color: #e6edf3; }
  .endpoint { background: #1f2937; padding: 8px 12px; border-radius: 4px; margin: 4px 0; display: block; font-family: monospace; }
</style>
</head>
<body>
  <h1>HTTP Proxy Logger</h1>
  <div class="card">
    <h2>Dashboard</h2>
    <div id="stats">Loading...</div>
  </div>
  <div class="card">
    <h2>API Endpoints</h2>
    <a class="endpoint" href="/stats">GET /stats - Proxy statistics (JSON)</a>
    <a class="endpoint" href="/logs?limit=50">GET /logs?limit=N - Recent log entries</a>
    <a class="endpoint" href="/logs/tail?n=20">GET /logs/tail?n=N - Tail log file</a>
    <a class="endpoint" href="/ca.crt">GET /ca.crt - Download CA certificate</a>
    <a class="endpoint" href="/health">GET /health - Health check</a>
  </div>
  <div class="card">
    <h2>Setup</h2>
    <p>1. Configure your browser/system to use <code>HTTP proxy: localhost:8080</code></p>
    <p>2. For HTTPS inspection, install the CA certificate: <a href="/ca.crt">Download CA Certificate</a></p>
    <p>3. Import the certificate into your browser/system trust store</p>
  </div>
  <script>
    fetch('/stats').then(r=>r.json()).then(d=>{
      document.getElementById('stats').innerHTML =
        '<div class="stat"><div class="stat-value">'+d.total_requests+'</div><div class="stat-label">Total Requests</div></div>'+
        '<div class="stat"><div class="stat-value">'+(d.total_bytes/1024/1024).toFixed(2)+' MB</div><div class="stat-label">Total Traffic</div></div>'+
        '<div class="stat"><div class="stat-value">'+d.active_conns+'</div><div class="stat-label">Active Connections</div></div>'+
        '<div class="stat"><div class="stat-value">'+d.error_count+'</div><div class="stat-label">Errors</div></div>'+
        '<div class="stat"><div class="stat-value">'+formatUptime(d.uptime_seconds)+'</div><div class="stat-label">Uptime</div></div>';
    });
    function formatUptime(s){
      var d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);
      return (d>0?d+'d ':'')+(h>0?h+'h ':'')+(m>0?m+'m':'<1m');
    }
  </script>
</body>
</html>`)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.logger.GetStats())
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
		}
	}

	logFile := filepath.Join(s.logDir, "proxy.log")
	entries, err := readLastEntries(logFile, limit)
	if err != nil {
		http.Error(w, fmt.Sprintf("read logs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(entries),
		"entries": entries,
	})
}

func (s *Server) handleLogsTail(w http.ResponseWriter, r *http.Request) {
	n := 20
	if nStr := r.URL.Query().Get("n"); nStr != "" {
		if parsed, err := strconv.Atoi(nStr); err == nil && parsed > 0 {
			n = parsed
		}
	}

	logFile := filepath.Join(s.logDir, "proxy.log")
	lines, err := tailFile(logFile, n)
	if err != nil {
		http.Error(w, fmt.Sprintf("tail logs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
}

func (s *Server) handleCACert(w http.ResponseWriter, r *http.Request) {
	if s.certMgr == nil {
		http.Error(w, "MITM not enabled", http.StatusNotFound)
		return
	}

	pem, err := s.certMgr.CACertPEM()
	if err != nil {
		http.Error(w, "Failed to get CA cert", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=proxy-ca.crt")
	w.Write(pem)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// readLastEntries reads the last N JSON log entries from a file.
func readLastEntries(filename string, limit int) ([]json.RawMessage, error) {
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var all []json.RawMessage
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		all = append(all, json.RawMessage(cp))
	}

	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	return all, scanner.Err()
}

// tailFile reads the last N lines from a file.
func tailFile(filename string, n int) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, scanner.Err()
}
