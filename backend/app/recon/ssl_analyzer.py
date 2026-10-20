"""AEGIS Reconnaissance Engine — SSL/TLS Certificate & Cipher Inspector

Audits TLS configurations, certificate chains, expiration countdowns,
self-signed certificates, SAN listings, weak cipher suites, and deprecated protocols.
"""
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("aegis.recon.ssl")

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"}
WEAK_CIPHER_KEYWORDS = {"RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon"}


class SSLAnalyzer:
    """Audits TLS connection parameters and X.509 certificates."""

    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout

    def inspect(self, host: str, port: int = 443) -> Dict[str, Any]:
        """
        Connects via TLS and extracts certificate metadata, validity, and security posture.
        """
        result: Dict[str, Any] = {
            "is_valid": False,
            "issuer": None,
            "subject": None,
            "valid_from": None,
            "valid_to": None,
            "expires_in_days": 0,
            "is_expired": False,
            "is_self_signed": False,
            "has_weak_cipher": False,
            "has_weak_protocol": False,
            "tls_version": None,
            "cipher_suite": None,
            "san_entries": [],
            "error": None
        }

        # Create context allowing unverified / self-signed certs so we can still inspect them
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cipher_info = ssock.cipher()
                    protocol = ssock.version()

                    result["tls_version"] = protocol
                    result["has_weak_protocol"] = protocol in DEPRECATED_PROTOCOLS

                    if cipher_info:
                        cipher_name = cipher_info[0]
                        result["cipher_suite"] = cipher_name
                        result["has_weak_cipher"] = any(w in cipher_name.upper() for w in WEAK_CIPHER_KEYWORDS)

                    if not der_cert:
                        result["error"] = "No peer certificate returned"
                        return result

                    # Parse X.509 Certificate
                    cert = x509.load_der_x509_certificate(der_cert)
                    now = datetime.now(timezone.utc)

                    # Expiration and validity
                    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc))
                    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc))

                    days_left = (not_after - now).days
                    is_expired = days_left < 0

                    result["valid_from"] = not_before.isoformat()
                    result["valid_to"] = not_after.isoformat()
                    result["expires_in_days"] = days_left
                    result["is_expired"] = is_expired

                    issuer_str = cert.issuer.rfc4514_string()
                    subject_str = cert.subject.rfc4514_string()
                    result["issuer"] = issuer_str
                    result["subject"] = subject_str
                    result["is_self_signed"] = (issuer_str == subject_str)

                    # Extract Subject Alternative Names (SANs)
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
                        result["san_entries"] = list(dns_names)
                    except Exception:
                        result["san_entries"] = []

                    # Valid if not expired, not self-signed, and not weak protocol
                    result["is_valid"] = (
                        not result["is_expired"]
                        and not result["is_self_signed"]
                        and not result["has_weak_protocol"]
                    )

        except (socket.timeout, TimeoutError):
            result["error"] = "Connection timed out"
        except ConnectionRefusedError:
            result["error"] = "Connection refused"
        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"SSL analysis failed for {host}:{port}: {e}")

        return result
