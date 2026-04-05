#!/usr/bin/env bash
set -e

echo "=========================================="
echo "  HTTP Proxy Logger - Setup & Run"
echo "=========================================="

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python3 is required but not installed."
    exit 1
fi
echo "[OK] Python3: $(python3 --version)"

# Check OpenSSL (needed for MITM cert generation)
if ! command -v openssl &>/dev/null; then
    echo "[WARN] OpenSSL not found - MITM HTTPS inspection will be disabled."
    MITM_FLAG="--no-mitm"
else
    echo "[OK] OpenSSL: $(openssl version)"
    MITM_FLAG=""
fi

# Create config if not exists
if [ ! -f config.json ]; then
    echo "[INFO] Creating config.json from example..."
    cp config.example.json config.json
    echo "[OK] Config created: config.json"
else
    echo "[OK] Config exists: config.json"
fi

# Create directories
mkdir -p logs certs
echo "[OK] Directories: logs/ certs/"

echo ""
echo "=========================================="
echo "  Starting HTTP Proxy Logger..."
echo "=========================================="
echo ""
echo "  Proxy:     http://localhost:8080"
echo "  Dashboard: http://localhost:8081"
echo "  Logs:      ./logs/proxy.log"
echo ""
echo "  Press Ctrl+C to stop"
echo "=========================================="
echo ""

exec python3 main.py --config config.json $MITM_FLAG "$@"
