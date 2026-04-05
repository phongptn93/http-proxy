package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/phongptn93/http-proxy/internal/logger"
)

// handleMITM performs man-in-the-middle TLS interception to log HTTPS traffic.
func (s *Server) handleMITM(w http.ResponseWriter, r *http.Request) {
	hostname := extractHost(r.Host)

	// Get or generate certificate for this host
	tlsCert, err := s.certMgr.GetCertificate(hostname)
	if err != nil {
		http.Error(w, "Certificate error", http.StatusBadGateway)
		return
	}

	// Hijack the connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	// Send 200 to client to signal tunnel established
	w.WriteHeader(http.StatusOK)
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	// Wrap client connection with TLS (MITM)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}
	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	// Read HTTP requests from the TLS connection
	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return
		}

		s.proxyMITMRequest(tlsConn, req, r.Host, r.RemoteAddr)
	}
}

// proxyMITMRequest proxies a single HTTPS request through MITM and logs it.
func (s *Server) proxyMITMRequest(clientConn net.Conn, req *http.Request, targetHost, clientAddr string) {
	start := time.Now()

	// Determine target URL
	host := targetHost
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	scheme := "https"
	targetURL := fmt.Sprintf("%s://%s%s", scheme, extractHost(host), req.URL.RequestURI())

	entry := &logger.Entry{
		ID:         generateID(),
		Timestamp:  start,
		Client:     clientAddr,
		Method:     req.Method,
		URL:        targetURL,
		Host:       extractHost(host),
		ReqHeaders: flattenHeaders(req.Header),
		TLS:        true,
	}

	// Read request body
	reqBody, reqSize := readBody(req.Body, s.cfg.LogBodyLimit)
	entry.ReqBody = reqBody
	entry.ReqSize = reqSize

	// Create outbound HTTPS request
	outReq, err := http.NewRequest(req.Method, targetURL, strings.NewReader(reqBody))
	if err != nil {
		entry.Error = fmt.Sprintf("create request: %v", err)
		entry.Duration = time.Since(start).Milliseconds()
		s.logger.Log(entry)
		writeErrorResponse(clientConn, http.StatusBadRequest, "Bad request")
		return
	}
	copyHeaders(outReq.Header, req.Header)
	outReq.Host = req.Host

	// Execute
	resp, err := s.client.Do(outReq)
	if err != nil {
		entry.Error = fmt.Sprintf("upstream: %v", err)
		entry.Duration = time.Since(start).Milliseconds()
		s.logger.Log(entry)
		writeErrorResponse(clientConn, http.StatusBadGateway, "Bad gateway")
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

	// Write response back to client through TLS connection
	var respBuf strings.Builder
	respBuf.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))
	for key, values := range resp.Header {
		for _, v := range values {
			respBuf.WriteString(fmt.Sprintf("%s: %s\r\n", key, v))
		}
	}
	respBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(respBody)))
	respBuf.WriteString("\r\n")
	respBuf.WriteString(respBody)

	clientConn.Write([]byte(respBuf.String()))

	s.logger.Log(entry)
}

func writeErrorResponse(conn net.Conn, status int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s",
		status, http.StatusText(status), len(msg), msg)
	conn.Write([]byte(resp))
}

// streamBidirectional copies data between two connections.
func streamBidirectional(dst, src net.Conn) (sent, received int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sent, _ = io.Copy(dst, src)
	}()
	go func() {
		defer wg.Done()
		received, _ = io.Copy(src, dst)
	}()
	wg.Wait()
	return
}
