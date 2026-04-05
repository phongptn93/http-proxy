package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phongptn93/http-proxy/internal/cert"
	"github.com/phongptn93/http-proxy/internal/config"
	"github.com/phongptn93/http-proxy/internal/logger"
)

// Server is the main HTTP proxy server.
type Server struct {
	cfg      *config.Config
	logger   *logger.Logger
	certMgr  *cert.Manager
	client   *http.Client
	srv      *http.Server

	mu            sync.RWMutex
	blockedHosts  map[string]bool
}

// New creates a new proxy server.
func New(cfg *config.Config, lg *logger.Logger, cm *cert.Manager) *Server {
	blocked := make(map[string]bool)
	for _, h := range cfg.BlockedHosts {
		blocked[strings.ToLower(h)] = true
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	s := &Server{
		cfg:          cfg,
		logger:       lg,
		certMgr:      cm,
		blockedHosts: blocked,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
			Timeout: 60 * time.Second,
		},
	}

	s.srv = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// Start starts the proxy server.
func (s *Server) Start() error {
	log.Printf("Proxy server listening on %s", s.cfg.ListenAddr)
	return s.srv.ListenAndServe()
}

// Shutdown gracefully shuts down the proxy server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// ServeHTTP handles all incoming proxy requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.Stats.ActiveConns.Add(1)
	defer s.logger.Stats.ActiveConns.Add(-1)

	// Check if host is blocked
	host := extractHost(r.Host)
	if s.isBlocked(host) {
		http.Error(w, "Blocked by proxy", http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
	} else {
		s.handleHTTP(w, r)
	}
}

func (s *Server) isBlocked(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.blockedHosts[strings.ToLower(host)]
}

func extractHost(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// handleHTTP proxies plain HTTP requests and logs them.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	entry := &logger.Entry{
		ID:        generateID(),
		Timestamp: start,
		Client:    r.RemoteAddr,
		Method:    r.Method,
		URL:       r.URL.String(),
		Host:      r.Host,
		ReqHeaders: flattenHeaders(r.Header),
		TLS:       false,
	}

	// Read request body
	reqBody, reqSize := readBody(r.Body, s.cfg.LogBodyLimit)
	entry.ReqBody = reqBody
	entry.ReqSize = reqSize

	// Create outbound request
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), strings.NewReader(reqBody))
	if err != nil {
		entry.Error = fmt.Sprintf("create request: %v", err)
		entry.Duration = time.Since(start).Milliseconds()
		s.logger.Log(entry)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	copyHeaders(outReq.Header, r.Header)

	// Execute request
	resp, err := s.client.Do(outReq)
	if err != nil {
		entry.Error = fmt.Sprintf("upstream: %v", err)
		entry.Duration = time.Since(start).Milliseconds()
		s.logger.Log(entry)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body
	respBody, respSize := readBody(resp.Body, s.cfg.LogBodyLimit)
	entry.StatusCode = resp.StatusCode
	entry.RespHeaders = flattenHeaders(resp.Header)
	entry.RespBody = respBody
	entry.RespSize = respSize
	entry.Duration = time.Since(start).Milliseconds()

	// Write response to client
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.WriteString(w, respBody)

	s.logger.Log(entry)
}

// handleConnect handles HTTPS CONNECT tunneling with optional MITM.
func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	if s.cfg.EnableMITM && s.certMgr != nil {
		s.handleMITM(w, r)
		return
	}

	// Plain tunnel (no inspection)
	s.handleTunnel(w, r)
}

// handleTunnel creates a plain TCP tunnel without MITM (no logging of content).
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	destConn, err := net.DialTimeout("tcp", r.Host, 30*time.Second)
	if err != nil {
		entry := &logger.Entry{
			ID:        generateID(),
			Timestamp: start,
			Client:    r.RemoteAddr,
			Method:    "CONNECT",
			URL:       r.Host,
			Host:      r.Host,
			TLS:       true,
			Error:     fmt.Sprintf("dial: %v", err),
			Duration:  time.Since(start).Milliseconds(),
		}
		s.logger.Log(entry)
		http.Error(w, "Bad gateway", http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Log the CONNECT request (without body)
	entry := &logger.Entry{
		ID:        generateID(),
		Timestamp: start,
		Client:    r.RemoteAddr,
		Method:    "CONNECT",
		URL:       r.Host,
		Host:      r.Host,
		TLS:       true,
		StatusCode: 200,
	}

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	var sent, received int64
	go func() {
		defer wg.Done()
		sent, _ = io.Copy(destConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		received, _ = io.Copy(clientConn, destConn)
	}()
	wg.Wait()

	entry.ReqSize = sent
	entry.RespSize = received
	entry.Duration = time.Since(start).Milliseconds()
	s.logger.Log(entry)
}
