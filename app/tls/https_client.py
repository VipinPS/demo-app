"""
HTTPS / TLS client operations.

Scenario C — Runtime Through Dependency:
The application source contains minimal explicit cryptographic configuration,
but at runtime a full TLS handshake (RSA/ECDSA/AES/HMAC) is executed through
the Python ssl/OpenSSL stack — making this visible to an eBPF agent while
being relatively invisible to a pure static source-code scanner.

A self-contained local HTTPS server is also provided so that the demo works
without relying on an external internet endpoint.
"""

import logging
import ssl
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Minimal self-hosted HTTPS server (started lazily, runs in a daemon thread)
# ---------------------------------------------------------------------------

_LOCAL_HTTPS_PORT = 8443
_local_server_started = False
_server_lock = threading.Lock()


class _SimpleHandler(BaseHTTPRequestHandler):
    """Minimal handler that serves a static JSON response over HTTPS."""

    def do_GET(self):  # noqa: N802
        body = b'{"status":"ok","message":"Local HTTPS demo endpoint","tls":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # suppress default access logs
        pass


def _start_local_https_server(certfile: str, keyfile: str) -> None:
    """Start the local HTTPS server in a background daemon thread."""
    global _local_server_started
    with _server_lock:
        if _local_server_started:
            return
        server = HTTPServer(("127.0.0.1", _LOCAL_HTTPS_PORT), _SimpleHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        _local_server_started = True
        logger.info("[DEMO] Local HTTPS server started on port %d", _LOCAL_HTTPS_PORT)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def make_https_request(url: str = "", certfile: str = "certs/demo.crt", keyfile: str = "certs/demo.key") -> dict:
    """
    Perform an HTTPS GET request.

    If *url* is empty or points to the local demo endpoint the built-in
    self-hosted HTTPS server is used, ensuring the demo works offline.

    The TLS handshake itself (key exchange, certificate validation, symmetric
    cipher negotiation) is performed by the Python ssl/OpenSSL layer and is
    therefore observable at runtime by an eBPF agent even though no explicit
    cryptographic API is called in this source file.
    """
    logger.info("[DEMO] HTTPS request executed")

    use_local = not url or "localhost" in url or "127.0.0.1" in url or url == ""

    if use_local:
        _start_local_https_server(certfile=certfile, keyfile=keyfile)
        target_url = f"https://127.0.0.1:{_LOCAL_HTTPS_PORT}/"
        # Trust our self-signed cert
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.load_verify_locations(certfile)
        ssl_ctx.check_hostname = False
    else:
        target_url = url
        ssl_ctx = ssl.create_default_context()

    req = urllib.request.Request(target_url, headers={"User-Agent": "pqc-demo-app/1.0"})
    with urllib.request.urlopen(req, context=ssl_ctx, timeout=10) as resp:
        body = resp.read(4096).decode(errors="replace")
        tls_version = resp.fp.raw._sock.version() if hasattr(resp.fp, "raw") else "unknown"

    logger.info("[DEMO] HTTPS response received — status=200")

    return {
        "url": target_url,
        "status": 200,
        "tls_note": "TLS handshake performed by Python ssl/OpenSSL — minimal explicit crypto in source",
        "body_preview": body[:256],
    }
