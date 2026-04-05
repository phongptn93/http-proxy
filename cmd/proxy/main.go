package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/phongptn93/http-proxy/internal/admin"
	"github.com/phongptn93/http-proxy/internal/cert"
	"github.com/phongptn93/http-proxy/internal/config"
	"github.com/phongptn93/http-proxy/internal/logger"
	"github.com/phongptn93/http-proxy/internal/proxy"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize logger
	lg, err := logger.New(cfg.LogDir, cfg.LogMaxSizeMB, cfg.LogMaxBackups, cfg.LogFormat)
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer lg.Close()

	// Initialize certificate manager (for MITM)
	var certMgr *cert.Manager
	if cfg.EnableMITM {
		certMgr, err = cert.NewManager(cfg.CACertFile, cfg.CAKeyFile)
		if err != nil {
			log.Fatalf("Failed to initialize certificate manager: %v", err)
		}
		log.Printf("MITM enabled - CA certificate: %s", cfg.CACertFile)
		log.Printf("Install the CA certificate in your browser/system to inspect HTTPS traffic")
	}

	// Start admin API
	adminSrv := admin.New(lg, certMgr, cfg.LogDir)
	go func() {
		if err := adminSrv.Start(cfg.AdminAddr); err != nil {
			log.Fatalf("Admin server error: %v", err)
		}
	}()

	// Start proxy server
	proxySrv := proxy.New(cfg, lg, certMgr)
	go func() {
		if err := proxySrv.Start(); err != nil {
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	log.Println("========================================")
	log.Printf("  HTTP Proxy Logger")
	log.Printf("  Proxy:  %s", cfg.ListenAddr)
	log.Printf("  Admin:  %s", cfg.AdminAddr)
	log.Printf("  Logs:   %s", cfg.LogDir)
	log.Printf("  MITM:   %v", cfg.EnableMITM)
	log.Println("========================================")

	// Wait for shutdown signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := proxySrv.Shutdown(ctx); err != nil {
		log.Printf("Proxy shutdown error: %v", err)
	}

	log.Println("Shutdown complete")
}
