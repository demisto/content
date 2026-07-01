"""Reusable HTTP capture proxy for observing outgoing traffic from integrations.

This is a lightweight, stdlib-only HTTP server that:

  * Accepts ANY HTTP method on ANY path that does not begin with the control
    plane prefixes ``/_session`` or ``/_sessions``.
  * Records the request (method, path, query, headers, body, timestamp) under
    the most recently created session.
  * Always responds with ``200 OK`` and an empty JSON body ``{}``.

It also accepts HTTPS-proxy-style ``CONNECT host:port`` requests, terminates
the TLS handshake using a single self-signed cert (generated lazily at
``start()``), and routes the inner decrypted HTTP request through the same
``_handle_capture`` path. Captured records carry a ``"transport"`` key
identifying which mechanism delivered them (``"url-rewrite"`` for the
plain-HTTP origin path and ``"connect-mitm"`` for the CONNECT-tunneled path).

Control-plane endpoints used by test harnesses:

  * ``POST   /_session/new``           -> ``{"session_id": "..."}``
  * ``GET    /_session/<id>/requests`` -> ``[{...}, ...]``
  * ``DELETE /_session/<id>``          -> ``{"deleted": true}``
  * ``GET    /_sessions``              -> ``["s_...", ...]``

Usage as a library::

    from capture_proxy import CaptureProxy

    proxy = CaptureProxy(port=0)   # 0 = OS picks free port
    proxy.start()
    sid = proxy.new_session()
    # ... drive integration through http://localhost:proxy.port ...
    requests = proxy.get_requests(sid)
    proxy.stop()

Usage as a standalone process::

    python3 connectus/capture_proxy.py --port 18080
"""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


_CONTROL_PREFIXES = ("/_session", "/_sessions")


# --------------------------------------------------------------------------
# TLS / cert generation
# --------------------------------------------------------------------------


def _generate_self_signed_cert(cert_dir: Path) -> tuple[Path, Path]:
    """Generate a single self-signed cert+key into ``cert_dir``.

    Lazy-imports :mod:`cryptography` so module-load of ``capture_proxy``
    stays cheap (the proxy can be used without ever generating a cert if
    no ``CONNECT`` ever arrives).

    The cert is RSA 2048, CN ``auth-parity-mitm``, with SANs
    ``DNS:*``, ``DNS:localhost``, ``IP:127.0.0.1`` so it matches any
    host an HTTPS_PROXY client tunnels to. Validity is ``[now-1d, now+365d]``.
    Acts as its own CA (``BasicConstraints CA=TRUE``).

    Returns ``(cert_path, key_path)``.
    """
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "auth-parity-mitm")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("*"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


class CaptureProxy:
    """Thread-safe HTTP capture server with session-scoped request storage."""

    def __init__(self, port: int = 0) -> None:
        self._requested_port = port
        self.port: int = 0
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._sessions: dict[str, list[dict[str, Any]]] = {}
        self._session_order: list[str] = []
        self._active_session: str | None = None
        # TLS state for the MITM CONNECT path. Lazily populated in start().
        self._cert_tmpdir: tempfile.TemporaryDirectory[str] | None = None
        self._cert_dir: Path | None = None
        self._cert_path: Path | None = None
        self._key_path: Path | None = None
        self._tls_context: ssl.SSLContext | None = None

    # ----- lifecycle ----------------------------------------------------

    def start(self) -> None:
        """Start the server in a daemon background thread.

        Also generates the self-signed MITM cert into a fresh
        :class:`tempfile.TemporaryDirectory` that lives for the proxy's
        lifetime. The directory is removed by :meth:`stop`.
        """
        # Generate cert + TLS context BEFORE binding the socket so a
        # failed ``cryptography`` import does not leave the port leaked.
        self._cert_tmpdir = tempfile.TemporaryDirectory(prefix="auth_parity_mitm_")
        self._cert_dir = Path(self._cert_tmpdir.name)
        self._cert_path, self._key_path = _generate_self_signed_cert(self._cert_dir)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(self._cert_path), keyfile=str(self._key_path))
        self._tls_context = ctx

        handler = _make_handler(self)
        self._server = ThreadingHTTPServer(("127.0.0.1", self._requested_port), handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"CaptureProxy:{self.port}",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the server, release the socket, and clean up the cert dir."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        # Clean up cert tempdir after the listener is fully torn down so
        # no in-flight CONNECT can race on disk access.
        if self._cert_tmpdir is not None:
            try:
                self._cert_tmpdir.cleanup()
            except Exception:
                pass
            self._cert_tmpdir = None
            self._cert_dir = None
            self._cert_path = None
            self._key_path = None
            self._tls_context = None

    # ----- session API --------------------------------------------------

    def new_session(self) -> str:
        """Create a new session and mark it as the active one."""
        session_id = f"s_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"
        with self._lock:
            self._sessions[session_id] = []
            self._session_order.append(session_id)
            self._active_session = session_id
        return session_id

    def get_requests(self, session_id: str) -> list[dict[str, Any]]:
        """Return a copy of the requests captured under ``session_id``."""
        with self._lock:
            return list(self._sessions.get(session_id, []))

    def delete_session(self, session_id: str) -> bool:
        """Drop a session's storage. Returns True if it existed."""
        with self._lock:
            existed = session_id in self._sessions
            self._sessions.pop(session_id, None)
            if session_id in self._session_order:
                self._session_order.remove(session_id)
            if self._active_session == session_id:
                self._active_session = self._session_order[-1] if self._session_order else None
        return existed

    def list_sessions(self) -> list[str]:
        """Return all currently known session IDs."""
        with self._lock:
            return list(self._session_order)

    def ca_cert_path(self) -> Path | None:
        """Return the on-disk path of the generated CA cert, or ``None``.

        ``None`` if :meth:`start` has not yet been called (or if the
        proxy has been stopped). The cert is the same self-signed root
        that terminates ``CONNECT`` tunnels, suitable for plumbing into
        ``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE`` env vars.
        """
        return self._cert_path

    def cert_dir(self) -> Path | None:
        """Return the directory holding ``cert.pem`` + ``key.pem``.

        ``None`` if :meth:`start` has not been called. The directory is
        a :class:`tempfile.TemporaryDirectory` that survives for the
        proxy's lifetime and is removed by :meth:`stop`.
        """
        return self._cert_dir

    # ----- internal -----------------------------------------------------

    def _record(self, request: dict[str, Any]) -> None:
        with self._lock:
            sid = self._active_session
            if sid is None:
                # No session created yet -> create an implicit one so we
                # never silently drop captured traffic.
                sid = f"s_implicit_{uuid.uuid4().hex[:8]}"
                self._sessions[sid] = []
                self._session_order.append(sid)
                self._active_session = sid
            self._sessions[sid].append(request)


def _make_handler(proxy: CaptureProxy) -> type[BaseHTTPRequestHandler]:
    """Build a BaseHTTPRequestHandler subclass bound to ``proxy``."""

    class _CaptureHandler(BaseHTTPRequestHandler):
        # Silence default access logging on stderr; harness owns stderr.
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        # ----- helpers --------------------------------------------------

        def _read_body(self) -> bytes:
            length_header = self.headers.get("Content-Length")
            if not length_header:
                return b""
            try:
                length = int(length_header)
            except ValueError:
                return b""
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _is_control(self, path: str) -> bool:
            return path.startswith(_CONTROL_PREFIXES)

        # ----- dispatch -------------------------------------------------

        def _dispatch(self) -> None:
            split = urlsplit(self.path)
            if self._is_control(split.path):
                self._handle_control(split.path, split.query)
                return
            self._handle_capture(split.path, split.query, transport="url-rewrite")

        do_GET = _dispatch  # noqa: N815
        do_POST = _dispatch  # noqa: N815
        do_PUT = _dispatch  # noqa: N815
        do_DELETE = _dispatch  # noqa: N815
        do_PATCH = _dispatch  # noqa: N815
        do_HEAD = _dispatch  # noqa: N815
        do_OPTIONS = _dispatch  # noqa: N815

        # ----- CONNECT / MITM ------------------------------------------

        def do_CONNECT(self) -> None:  # noqa: N802 — http.server convention
            """Terminate an HTTPS_PROXY ``CONNECT host:port`` tunnel.

            Responds 200, wraps our side of the socket with the proxy's
            self-signed cert, then re-parses one HTTP request off the
            decrypted stream and routes it through ``_handle_capture``
            tagged with ``transport="connect-mitm"``. Refuses loopback
            CONNECTs aimed at the proxy's own port with 403.
            """
            host, _, port_s = self.path.partition(":")
            try:
                port = int(port_s) if port_s else 443
            except ValueError:
                self.send_error(400, "Bad CONNECT target")
                return

            # Loopback guard: refuse CONNECT 127.0.0.1:<own_port>. The
            # harness's plain-HTTP origin path uses the SAME port for
            # control-plane traffic; allowing a CONNECT to ourselves
            # would let a misconfigured client tunnel TLS into the
            # control-plane handler and confuse the session model.
            if host in ("127.0.0.1", "localhost") and port == proxy.port:
                self.send_error(403, "Loopback Forbidden")
                return

            if proxy._tls_context is None:
                self.send_error(500, "TLS context not initialised")
                return

            self.send_response(200, "Connection Established")
            self.end_headers()

            try:
                tls_sock = proxy._tls_context.wrap_socket(
                    self.connection,
                    server_side=True,
                    do_handshake_on_connect=True,
                )
            except (ssl.SSLError, OSError):
                # Client gave up the handshake; nothing to record.
                return

            try:
                _serve_inner_request(proxy, tls_sock, host, port)
            finally:
                try:
                    tls_sock.unwrap()
                except (ssl.SSLError, OSError):
                    pass
                try:
                    tls_sock.close()
                except OSError:
                    pass
                # Prevent the outer handler's finally from trying to
                # double-close the now-unwrapped raw socket.
                self.close_connection = True

        # ----- catch-all capture ---------------------------------------

        def _handle_capture(
            self,
            path: str,
            query: str,
            *,
            transport: str = "url-rewrite",
            connect_host: str | None = None,
            connect_port: int | None = None,
        ) -> None:
            body_bytes = self._read_body()
            try:
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            record: dict[str, Any] = {
                "method": self.command,
                "path": path,
                "query": query,
                "url": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body_text,
                "timestamp": time.time(),
                "transport": transport,
            }
            if connect_host is not None:
                record["connect_host"] = connect_host
            if connect_port is not None:
                record["connect_port"] = connect_port
            proxy._record(record)
            self._send_json(200, {})

        # ----- control plane -------------------------------------------

        def _handle_control(self, path: str, query: str) -> None:
            method = self.command

            # GET /_sessions
            if path == "/_sessions" and method == "GET":
                self._send_json(200, proxy.list_sessions())
                return

            # POST /_session/new
            if path == "/_session/new" and method == "POST":
                sid = proxy.new_session()
                self._send_json(200, {"session_id": sid})
                return

            # /_session/<id>/requests   (GET)
            # /_session/<id>            (DELETE)
            parts = [p for p in path.split("/") if p]
            if len(parts) >= 2 and parts[0] == "_session":
                sid = parts[1]
                if len(parts) == 3 and parts[2] == "requests" and method == "GET":
                    self._send_json(200, proxy.get_requests(sid))
                    return
                if len(parts) == 2 and method == "DELETE":
                    proxy.delete_session(sid)
                    self._send_json(200, {"deleted": True})
                    return

            self._send_json(404, {"error": "unknown control endpoint", "path": path, "method": method})

    return _CaptureHandler


def _serve_inner_request(
    proxy: CaptureProxy,
    tls_sock: ssl.SSLSocket,
    connect_host: str,
    connect_port: int,
) -> None:
    """Parse one decrypted HTTP request off ``tls_sock`` and record it.

    Uses :class:`BaseHTTPRequestHandler` directly against the wrapped
    socket so we get its battle-tested header parsing. The handler
    instance is short-circuited via a synthetic ``client_address`` and
    we never call ``handle()`` — instead we manually drive
    :meth:`handle_one_request` once, dispatch through
    :meth:`_handle_capture`, and return. The outer ``do_CONNECT``
    closes the socket on return.
    """

    class _InnerHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def _read_body(self) -> bytes:
            length_header = self.headers.get("Content-Length")
            if not length_header:
                return b""
            try:
                length = int(length_header)
            except ValueError:
                return b""
            if length <= 0:
                return b""
            return self.rfile.read(length)

        def _send_json(self, status: int, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _dispatch(self) -> None:
            split = urlsplit(self.path)
            body_bytes = self._read_body()
            try:
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            record: dict[str, Any] = {
                "method": self.command,
                "path": split.path,
                "query": split.query,
                "url": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body_text,
                "timestamp": time.time(),
                "transport": "connect-mitm",
                "connect_host": connect_host,
                "connect_port": connect_port,
            }
            proxy._record(record)
            self._send_json(200, {})

        do_GET = _dispatch  # noqa: N815
        do_POST = _dispatch  # noqa: N815
        do_PUT = _dispatch  # noqa: N815
        do_DELETE = _dispatch  # noqa: N815
        do_PATCH = _dispatch  # noqa: N815
        do_HEAD = _dispatch  # noqa: N815
        do_OPTIONS = _dispatch  # noqa: N815

    # Build a handler instance without invoking its __init__ machinery
    # (which would try to call .handle() on the socket). We need just
    # enough state to run handle_one_request().
    handler = _InnerHandler.__new__(_InnerHandler)
    handler.rfile = tls_sock.makefile("rb", buffering=0)
    handler.wfile = tls_sock.makefile("wb", buffering=0)
    handler.connection = tls_sock
    handler.request = tls_sock
    handler.client_address = ("127.0.0.1", 0)
    handler.server = None  # not referenced by handle_one_request
    handler.close_connection = True
    handler.requestline = ""
    handler.request_version = ""
    handler.command = ""
    handler.raw_requestline = b""
    try:
        handler.handle_one_request()
    except (ssl.SSLError, OSError, ValueError):
        # Bad TLS / truncated request -- swallow; nothing recorded.
        pass
    finally:
        try:
            handler.wfile.flush()
        except (ssl.SSLError, OSError):
            pass


# --------------------------------------------------------------------------
# Standalone entry point
# --------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the capture proxy as a standalone HTTP server.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18080,
        help="Port to bind to. Use 0 to let the OS pick a free port. Default: 18080.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    proxy = CaptureProxy(port=args.port)
    proxy.start()
    print(f"capture_proxy listening on http://127.0.0.1:{proxy.port}", file=sys.stderr)
    print(
        "Try: curl -X POST http://127.0.0.1:"
        f"{proxy.port}/_session/new   then   curl http://127.0.0.1:{proxy.port}/_sessions",
        file=sys.stderr,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nShutting down capture_proxy...", file=sys.stderr)
    finally:
        proxy.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
