package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Entry represents a single proxied HTTP transaction log entry.
type Entry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Duration  int64     `json:"duration_ms"`
	Client    string    `json:"client_addr"`

	// Request
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Host       string            `json:"host"`
	ReqHeaders map[string]string `json:"request_headers"`
	ReqBody    string            `json:"request_body,omitempty"`
	ReqSize    int64             `json:"request_size"`

	// Response
	StatusCode  int               `json:"status_code"`
	RespHeaders map[string]string `json:"response_headers,omitempty"`
	RespBody    string            `json:"response_body,omitempty"`
	RespSize    int64             `json:"response_size"`

	// TLS info
	TLS        bool   `json:"tls"`
	TLSVersion string `json:"tls_version,omitempty"`

	// Error
	Error string `json:"error,omitempty"`
}

// Stats tracks proxy statistics.
type Stats struct {
	TotalRequests   atomic.Int64
	TotalBytes      atomic.Int64
	ActiveConns     atomic.Int64
	ErrorCount      atomic.Int64
	StartTime       time.Time
}

// Logger handles structured logging with file rotation.
type Logger struct {
	mu          sync.Mutex
	dir         string
	maxSizeMB   int
	maxBackups  int
	format      string
	currentFile *os.File
	currentSize int64

	Stats Stats
}

// New creates a new Logger.
func New(dir string, maxSizeMB, maxBackups int, format string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}

	l := &Logger{
		dir:        dir,
		maxSizeMB:  maxSizeMB,
		maxBackups: maxBackups,
		format:     format,
	}
	l.Stats.StartTime = time.Now()

	if err := l.openFile(); err != nil {
		return nil, err
	}

	return l, nil
}

func (l *Logger) openFile() error {
	filename := filepath.Join(l.dir, "proxy.log")
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	l.currentFile = f
	l.currentSize = info.Size()
	return nil
}

func (l *Logger) rotate() error {
	if l.currentFile != nil {
		l.currentFile.Close()
	}

	// Rotate existing backups
	base := filepath.Join(l.dir, "proxy.log")
	for i := l.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", base, i)
		dst := fmt.Sprintf("%s.%d", base, i+1)
		os.Rename(src, dst)
	}
	os.Rename(base, base+".1")

	// Remove oldest backup if exceeds maxBackups
	oldest := fmt.Sprintf("%s.%d", base, l.maxBackups+1)
	os.Remove(oldest)

	return l.openFile()
}

// Log writes an entry to the log file.
func (l *Logger) Log(entry *Entry) error {
	l.Stats.TotalRequests.Add(1)
	l.Stats.TotalBytes.Add(entry.ReqSize + entry.RespSize)
	if entry.Error != "" {
		l.Stats.ErrorCount.Add(1)
	}

	var line []byte
	var err error

	switch l.format {
	case "text":
		line = []byte(formatText(entry))
	default:
		line, err = json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal log entry: %w", err)
		}
		line = append(line, '\n')
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	maxBytes := int64(l.maxSizeMB) * 1024 * 1024
	if l.currentSize+int64(len(line)) > maxBytes {
		if err := l.rotate(); err != nil {
			return fmt.Errorf("rotate log: %w", err)
		}
	}

	n, err := l.currentFile.Write(line)
	if err != nil {
		return fmt.Errorf("write log: %w", err)
	}
	l.currentSize += int64(n)

	return nil
}

func formatText(e *Entry) string {
	status := fmt.Sprintf("%d", e.StatusCode)
	if e.Error != "" {
		status = "ERR"
	}
	return fmt.Sprintf("[%s] %s %s %s -> %s (%dms, req:%d resp:%d)\n",
		e.Timestamp.Format("2006-01-02 15:04:05.000"),
		e.Client,
		e.Method,
		e.URL,
		status,
		e.Duration,
		e.ReqSize,
		e.RespSize,
	)
}

// Close closes the logger.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.currentFile != nil {
		return l.currentFile.Close()
	}
	return nil
}

// GetStats returns current statistics as a map.
func (l *Logger) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"total_requests": l.Stats.TotalRequests.Load(),
		"total_bytes":    l.Stats.TotalBytes.Load(),
		"active_conns":   l.Stats.ActiveConns.Load(),
		"error_count":    l.Stats.ErrorCount.Load(),
		"uptime_seconds": int64(time.Since(l.Stats.StartTime).Seconds()),
	}
}
