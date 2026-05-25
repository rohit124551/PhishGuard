"""
SSL / HTTPS Check
Verifies that the URL uses HTTPS and that the SSL certificate is valid.
HTTP-only sites or sites with bad certs are strong phishing indicators.
"""

import ssl
import socket
import tldextract
from urllib.parse import urlparse
from typing import Dict, Any

CONNECT_TIMEOUT = 5  # seconds


def _verify_ssl_cert(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Attempt a TLS handshake with the given hostname.
    Returns a dict describing the result.
    """
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
                # If we reach here the cert is valid per the system trust store
                subject = dict(x[0] for x in cert.get("subject", []))
                expiry = cert.get("notAfter", "unknown")
                return {
                    "valid": True,
                    "common_name": subject.get("commonName", hostname),
                    "expiry": expiry,
                }
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": str(exc)[:200]}
    except ssl.SSLError as exc:
        return {"valid": False, "error": str(exc)[:200]}
    except socket.timeout:
        return {"valid": None, "error": "Connection timed out"}
    except OSError as exc:
        return {"valid": None, "error": str(exc)[:200]}


def check(url: str) -> Dict[str, Any]:
    """
    Check HTTPS usage and SSL certificate validity.

    Scoring:
      - HTTP (no TLS at all)     → score 20 (danger)
      - HTTPS + invalid cert     → score 25 (danger)
      - HTTPS + cert unreachable → score 10 (warning)
      - HTTPS + valid cert       → score 0  (safe)
    """
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme == "http":
            return {
                "name": "SSL / HTTPS",
                "score": 20,
                "status": "danger",
                "reason": "Site uses plain HTTP — no encryption. Credentials and data are transmitted in clear text.",
            }

        if scheme != "https":
            return {
                "name": "SSL / HTTPS",
                "score": 10,
                "status": "warning",
                "reason": f"Unrecognised URL scheme '{scheme}' — cannot verify SSL.",
            }

        # Extract hostname for SSL verification
        hostname = parsed.hostname or tldextract.extract(url).registered_domain

        if not hostname:
            return {
                "name": "SSL / HTTPS",
                "score": 10,
                "status": "warning",
                "reason": "Could not determine hostname for SSL verification.",
            }

        port = parsed.port or 443
        result = _verify_ssl_cert(hostname, port)

        if result["valid"] is True:
            return {
                "name": "SSL / HTTPS",
                "score": 0,
                "status": "safe",
                "reason": (
                    f"Valid SSL certificate confirmed for '{hostname}' "
                    f"(CN: {result.get('common_name', 'N/A')}, expires: {result.get('expiry', 'N/A')})."
                ),
            }
        elif result["valid"] is False:
            return {
                "name": "SSL / HTTPS",
                "score": 25,
                "status": "danger",
                "reason": f"SSL certificate is invalid for '{hostname}': {result.get('error', 'unknown error')}.",
            }
        else:
            # Timed out or OS error — can't confirm, give partial warning
            return {
                "name": "SSL / HTTPS",
                "score": 10,
                "status": "warning",
                "reason": f"Could not verify SSL certificate for '{hostname}': {result.get('error', 'unknown error')}.",
            }

    except Exception as exc:
        return {
            "name": "SSL / HTTPS",
            "score": 10,
            "status": "warning",
            "reason": f"SSL check encountered an unexpected error: {str(exc)[:120]}",
        }
