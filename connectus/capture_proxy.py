"""Reusable HTTP capture proxy for observing outgoing traffic from integrations.

This is a lightweight, stdlib-only HTTP server that:

  * Accepts ANY HTTP method on ANY path that does not begin with the control
    plane prefixes ``/_session`` or ``/_sessions``.
  * Records the request (method, path, query, headers, body, timestamp) under
    the most recently created session.
  * Always responds with ``200 OK`` and an empty JSON body ``{}``.

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
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit


_CONTROL_PREFIXES = ("/_session", "/_sessions")


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

    # ----- lifecycle ----------------------------------------------------

    def start(self) -> None:
        """Start the server in a daemon background thread."""
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
        """Stop the server and release the socket."""
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

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
            self._handle_capture(split.path, split.query)

        do_GET = _dispatch  # noqa: N815
        do_POST = _dispatch  # noqa: N815
        do_PUT = _dispatch  # noqa: N815
        do_DELETE = _dispatch  # noqa: N815
        do_PATCH = _dispatch  # noqa: N815
        do_HEAD = _dispatch  # noqa: N815
        do_OPTIONS = _dispatch  # noqa: N815

        # ----- catch-all capture ---------------------------------------

        def _handle_capture(self, path: str, query: str) -> None:
            body_bytes = self._read_body()
            try:
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            record = {
                "method": self.command,
                "path": path,
                "query": query,
                "url": self.path,
                "headers": {k: v for k, v in self.headers.items()},
                "body": body_text,
                "timestamp": time.time(),
            }
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
