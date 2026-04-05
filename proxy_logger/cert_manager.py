import os
import ssl
import subprocess
import tempfile
from pathlib import Path
from threading import Lock


class CertManager:
    """Manages CA certificate and per-host certificate generation for MITM.

    Uses OpenSSL CLI for certificate generation (no external Python packages needed).
    """

    def __init__(self, ca_dir: str = "certs"):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self.ca_cert_path = self.ca_dir / "ca.crt"
        self.ca_key_path = self.ca_dir / "ca.key"

        self._lock = Lock()
        self._cache: dict[str, tuple[str, str]] = {}

        if not (self.ca_cert_path.exists() and self.ca_key_path.exists()):
            self._generate_ca()

    def _generate_ca(self):
        """Generate a self-signed CA certificate using OpenSSL."""
        subprocess.run(
            [
                "openssl", "ecparam", "-genkey", "-name", "prime256v1",
                "-out", str(self.ca_key_path),
            ],
            check=True, capture_output=True,
        )
        os.chmod(self.ca_key_path, 0o600)

        subprocess.run(
            [
                "openssl", "req", "-new", "-x509",
                "-key", str(self.ca_key_path),
                "-out", str(self.ca_cert_path),
                "-days", "3650",
                "-subj", "/O=HTTP Proxy Logger/CN=HTTP Proxy Logger CA",
            ],
            check=True, capture_output=True,
        )

    def get_cert_for_host(self, hostname: str) -> tuple[str, str]:
        """Returns (cert_path, key_path) for the given hostname."""
        with self._lock:
            if hostname in self._cache:
                return self._cache[hostname]

            cert_path, key_path = self._generate_host_cert(hostname)
            self._cache[hostname] = (cert_path, key_path)
            return cert_path, key_path

    def _generate_host_cert(self, hostname: str) -> tuple[str, str]:
        """Generate a certificate for a specific host, signed by our CA."""
        host_dir = self.ca_dir / "hosts"
        host_dir.mkdir(exist_ok=True)

        safe_name = hostname.replace("*", "_wildcard_").replace(":", "_")
        key_path = host_dir / f"{safe_name}.key"
        csr_path = host_dir / f"{safe_name}.csr"
        cert_path = host_dir / f"{safe_name}.crt"
        ext_path = host_dir / f"{safe_name}.ext"

        # Generate host key
        subprocess.run(
            ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", str(key_path)],
            check=True, capture_output=True,
        )

        # Generate CSR
        subprocess.run(
            [
                "openssl", "req", "-new",
                "-key", str(key_path),
                "-out", str(csr_path),
                "-subj", f"/O=HTTP Proxy Logger/CN={hostname}",
            ],
            check=True, capture_output=True,
        )

        # Write SAN extension file
        ext_path.write_text(
            f"authorityKeyIdentifier=keyid,issuer\n"
            f"basicConstraints=CA:FALSE\n"
            f"keyUsage=digitalSignature,keyEncipherment\n"
            f"extendedKeyUsage=serverAuth\n"
            f"subjectAltName=DNS:{hostname}\n"
        )

        # Sign with CA
        subprocess.run(
            [
                "openssl", "x509", "-req",
                "-in", str(csr_path),
                "-CA", str(self.ca_cert_path),
                "-CAkey", str(self.ca_key_path),
                "-CAcreateserial",
                "-out", str(cert_path),
                "-days", "1",
                "-extfile", str(ext_path),
            ],
            check=True, capture_output=True,
        )

        # Clean up temp files
        csr_path.unlink(missing_ok=True)
        ext_path.unlink(missing_ok=True)

        return str(cert_path), str(key_path)

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """Get an SSL context configured for the given hostname."""
        cert_path, key_path = self.get_cert_for_host(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    @property
    def ca_cert_pem(self) -> bytes:
        return self.ca_cert_path.read_bytes()
