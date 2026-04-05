package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// generateID creates a unique request ID.
func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// flattenHeaders converts http.Header to a simple map (first value only).
func flattenHeaders(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}

// copyHeaders copies headers from src to dst.
func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// readBody reads up to limit bytes from a reader and returns the string content and total size.
func readBody(r io.ReadCloser, limit int) (string, int64) {
	if r == nil {
		return "", 0
	}
	defer r.Close()

	var reader io.Reader = r
	if limit > 0 {
		reader = io.LimitReader(r, int64(limit)+1)
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Sprintf("[read error: %v]", err), 0
	}

	size := int64(len(data))
	body := string(data)

	// If we hit the limit, indicate truncation
	if limit > 0 && len(data) > limit {
		body = string(data[:limit]) + "...[truncated]"
	}

	// Check if body is binary (contains null bytes or high proportion of non-printable)
	if isBinary(data) {
		body = fmt.Sprintf("[binary data: %d bytes]", size)
	}

	return body, size
}

// isBinary checks if data appears to be binary content.
func isBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Sample first 512 bytes
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	nonPrintable := 0
	for _, b := range sample {
		if b == 0 {
			return true
		}
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(sample)) > 0.3
}
