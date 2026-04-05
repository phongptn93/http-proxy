import hashlib
import os
import random
import ssl
import struct
import textwrap
import time
from base64 import b64encode
from pathlib import Path
from threading import Lock

from .asn1 import (
    build_ca_certificate,
    build_host_certificate,
    generate_ec_key,
    private_key_to_pem,
    public_key_from_private,
)


class CertManager:
    """Manages CA certificate and per-host certificate generation for MITM.

    Pure Python implementation - no external dependencies required.
    """

    def __init__(self, ca_dir: str = "certs"):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self.ca_cert_path = self.ca_dir / "ca.crt"
        self.ca_key_path = self.ca_dir / "ca.key"

        self._lock = Lock()
        self._cache: dict[str, tuple[str, str]] = {}

        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._load_ca()
        else:
            self._generate_ca()

    def _load_ca(self):
        """Load existing CA cert and key from PEM files."""
        from .asn1 import load_ec_private_key, load_certificate_der

        key_pem = self.ca_key_path.read_text()
        cert_pem = self.ca_cert_path.read_text()

        self._ca_private_key = load_ec_private_key(key_pem)
        self._ca_cert_der = load_certificate_der(cert_pem)
        self._ca_cert_pem = cert_pem.encode()

    def _generate_ca(self):
        """Generate a new self-signed CA certificate."""
        private_key = generate_ec_key()
        public_key = public_key_from_private(private_key)

        cert_der = build_ca_certificate(private_key, public_key)

        # Save cert PEM
        cert_pem = der_to_pem(cert_der, "CERTIFICATE")
        self.ca_cert_path.write_text(cert_pem)

        # Save key PEM
        key_pem = private_key_to_pem(private_key)
        self.ca_key_path.write_text(key_pem)
        try:
            os.chmod(self.ca_key_path, 0o600)
        except OSError:
            pass  # Windows may not support chmod

        self._ca_private_key = private_key
        self._ca_cert_der = cert_der
        self._ca_cert_pem = cert_pem.encode()

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
        cert_file = host_dir / f"{safe_name}.crt"
        key_file = host_dir / f"{safe_name}.key"

        # Generate host key pair
        host_private_key = generate_ec_key()
        host_public_key = public_key_from_private(host_private_key)

        # Build and sign certificate
        cert_der = build_host_certificate(
            hostname=hostname,
            host_public_key=host_public_key,
            ca_private_key=self._ca_private_key,
            ca_cert_der=self._ca_cert_der,
        )

        cert_file.write_text(der_to_pem(cert_der, "CERTIFICATE"))
        key_file.write_text(private_key_to_pem(host_private_key))

        return str(cert_file), str(key_file)

    def get_ssl_context(self, hostname: str) -> ssl.SSLContext:
        """Get an SSL context configured for the given hostname."""
        cert_path, key_path = self.get_cert_for_host(hostname)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    @property
    def ca_cert_pem(self) -> bytes:
        return self._ca_cert_pem


def der_to_pem(der_data: bytes, label: str) -> str:
    b64 = b64encode(der_data).decode("ascii")
    lines = textwrap.wrap(b64, 64)
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"
