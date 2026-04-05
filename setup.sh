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

# Generate CA cert if not exists
if [ ! -f certs/ca.crt ]; then
    echo "[INFO] Generating CA certificate..."
    python3 -c "from proxy_logger.cert_manager import CertManager; CertManager(ca_dir='certs')"
    echo "[OK] CA certificate generated: certs/ca.crt"
else
    echo "[OK] CA certificate exists: certs/ca.crt"
fi

# Offer to install CA cert
if [ ! -f ".cert_installed" ]; then
    echo ""
    echo "=========================================="
    echo "  Install CA Certificate"
    echo "=========================================="
    echo ""
    echo "  De HTTPS inspection hoat dong, ban can cai"
    echo "  CA certificate vao trust store."
    echo ""
    read -p "  Ban co muon cai CA cert khong? (y/n): " INSTALL_CERT

    if [ "$INSTALL_CERT" = "y" ] || [ "$INSTALL_CERT" = "Y" ]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            # macOS
            echo "[INFO] Cai dat CA cert vao macOS Keychain..."
            sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt
            echo "[OK] Da cai dat thanh cong!"
        else
            # Linux
            if command -v update-ca-certificates &>/dev/null; then
                echo "[INFO] Cai dat CA cert (Ubuntu/Debian)..."
                sudo cp certs/ca.crt /usr/local/share/ca-certificates/proxy-logger-ca.crt
                sudo update-ca-certificates
                echo "[OK] Da cai dat thanh cong!"
            elif command -v update-ca-trust &>/dev/null; then
                echo "[INFO] Cai dat CA cert (CentOS/RHEL)..."
                sudo cp certs/ca.crt /etc/pki/ca-trust/source/anchors/proxy-logger-ca.crt
                sudo update-ca-trust
                echo "[OK] Da cai dat thanh cong!"
            else
                echo "[WARN] Khong the cai tu dong. Cai thu cong:"
                echo "       Chrome: Settings > Privacy > Manage certificates > Authorities > Import"
                echo "       Firefox: Settings > Privacy > Certificates > View > Authorities > Import"
                echo "       File: certs/ca.crt"
            fi
        fi
        touch .cert_installed
    else
        echo "[SKIP] Bo qua. Cai thu cong neu can:"
        echo "       Chrome: Settings > Privacy > Manage certificates > Authorities > Import"
        echo "       File: certs/ca.crt"
    fi
fi

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

exec python3 main.py --config config.json "$@"
