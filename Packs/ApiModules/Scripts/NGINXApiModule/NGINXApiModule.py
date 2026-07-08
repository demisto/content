import os
import subprocess
import traceback
import uuid
from itertools import count
from math import ceil
from pathlib import Path
from signal import SIGUSR1
from string import Template
from typing import Any

import demistomock as demisto  # noqa: F401
import gevent
import requests
from CommonServerPython import *  # noqa: F401
from flask.logging import default_handler
from gevent.pywsgi import WSGIHandler, WSGIServer

from CommonServerUserPython import *


class Handler:
    @staticmethod
    def write(msg: str):
        # gevent's pywsgi writes one Common-Log-Format access line per request here.
        # Tag it so it is easy to grep for and correlate with the nginx access log.
        demisto.info(f"wsgi access: {msg.rstrip()}")


class ErrorHandler:
    @staticmethod
    def write(msg: str):
        demisto.error(f"wsgi error: {msg.rstrip()}")


DEMISTO_LOGGER: Handler = Handler()
ERROR_LOGGER: ErrorHandler = ErrorHandler()


# --- Request lifecycle / concurrency instrumentation -------------------------
# Monotonic sequence so every request can be correlated across the start line,
# the end line and the gevent access line.
_REQUEST_SEQ = count(1)
# The environ key under which we stash the per-request id so DemistoWSGIHandler
# can print the same id on the "wsgi access:" line.
REQUEST_ID_ENVIRON_KEY = "nginxapimodule.request_id"
# The environ key under which the middleware stashes the number of body bytes the
# APP produced, so the gevent handler can compare it against the bytes actually
# written to the socket and flag a discrepancy on the "wsgi access:" line.
APP_BYTES_ENVIRON_KEY = "nginxapimodule.app_bytes"
# When the app-produced bytes and the socket-sent bytes differ by MORE than this
# many bytes, the access line includes a short body_diff note (a 1-byte trailing
# newline difference is normal and must not be reported).
BODY_DIFF_THRESHOLD_BYTES = 1000


def _new_request_id(environ: dict) -> str:
    """Return a correlation id for the request.

    Prefers nginx's ``X-Request-ID`` (propagated via ``proxy_set_header``) so the
    same id appears in the nginx access log, the ``wsgi request:`` line and the
    ``wsgi access:`` line. Falls back to a fresh short uuid when nginx did not
    forward one (e.g. direct upstream hit during tests).
    """
    forwarded = environ.get(_header_env_key("X-Request-ID"))
    return forwarded if forwarded else uuid.uuid4().hex[:12]


def _next_request_seq() -> int:
    """Return the next monotonic per-request sequence number."""
    return next(_REQUEST_SEQ)


def _iso_now() -> str:
    """Human-readable UTC timestamp for absolute received/responded times in logs."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# Request headers worth capturing for client/cache/conditional diagnostics.
# Shared by both the gevent access log (DemistoWSGIHandler) and the per-request
# RequestLoggingMiddleware so the two log lines stay consistent.
LOGGED_REQUEST_HEADERS = (
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Proto",
    "X-Original-URI",
    "Host",
    "User-Agent",
    "Range",
    "If-None-Match",
    "If-Modified-Since",
    "Authorization",
)


def _header_env_key(header_name: str) -> str:
    # WSGI exposes request headers as HTTP_<UPPER_SNAKE> in the environ.
    return "HTTP_" + header_name.upper().replace("-", "_")


def format_request_headers(environ: dict) -> str:
    """Render the allow-listed request headers from a WSGI ``environ`` into a log string.

    Produces a space-separated ``Name="value"`` sequence for every header in
    ``LOGGED_REQUEST_HEADERS`` that is present. The ``Authorization`` header is
    reduced to ``present`` so credentials are never written to the logs.

    Args:
        environ (dict): The WSGI request environment.

    Returns:
        str: e.g. ``X-Forwarded-For="1.2.3.4" Host="server" Authorization="present"``.
    """
    header_parts = []
    for header_name in LOGGED_REQUEST_HEADERS:
        value = environ.get(_header_env_key(header_name))
        if value is None:
            continue
        if header_name == "Authorization":
            value = "present"
        header_parts.append(f'{header_name}="{value}"')
    return " ".join(header_parts)


class DemistoWSGIHandler(WSGIHandler):
    """gevent WSGI handler that enriches the access line with transfer diagnostics + headers.

    gevent's ``WSGIServer`` formats one Common-Log-Format access line per request
    via ``WSGIHandler.format_request()`` and writes it to the configured ``log``
    (our :class:`Handler`, which prefixes it with ``wsgi access:``). The default
    line only reports the body bytes gevent sent, which - when compared with the
    ``content_length`` the app declared in :class:`RequestLoggingMiddleware` - can
    silently hide truncated/aborted transfers (client disconnects mid-stream).

    To make that gap explicit on a single line, ``format_request`` appends data
    that only gevent's handler knows:
      * ``sent_bytes``      - bytes actually written to the socket (``self.response_length``).
      * ``content_length``  - the ``Content-Length`` the app declared (``-`` if chunked/unset).
      * ``truncated``       - ``true`` when a numeric ``Content-Length`` was declared but
                              fewer bytes reached the socket (i.e. the transfer was cut short).
      * ``connection``      - ``close`` or ``keep-alive``, derived from ``self.close_connection``.
    It also appends the allow-listed request headers (via :func:`format_request_headers`)
    so the real client/conditional headers are visible alongside the byte accounting.
    """

    @staticmethod
    def _coerce_int(value: Any) -> int | None:
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def _transfer_diagnostics(self, environ: dict) -> str:
        # Bytes gevent actually wrote to the socket for the response body.
        sent_bytes = getattr(self, "response_length", None)
        sent_bytes_str = str(sent_bytes) if sent_bytes is not None else "-"

        # The Content-Length the app declared, if any (chunked responses won't have one).
        declared_length: int | None = None
        for header_key, header_value in getattr(self, "response_headers", None) or []:
            if header_key.lower() == "content-length":
                declared_length = self._coerce_int(header_value)
                break
        content_length_str = str(declared_length) if declared_length is not None else "-"

        # The number of body bytes the APP produced (counted by RequestLoggingMiddleware
        # and stashed in environ), so we can compare the two independent counts.
        app_bytes = self._coerce_int(environ.get(APP_BYTES_ENVIRON_KEY))
        app_bytes_str = str(app_bytes) if app_bytes is not None else "-"

        # truncated=true only when we can prove fewer bytes reached the socket than promised.
        if declared_length is not None and isinstance(sent_bytes, int):
            truncated = "true" if sent_bytes < declared_length else "false"
        else:
            truncated = "unknown"

        # Whether the connection is being closed (vs reused for keep-alive).
        connection = "close" if getattr(self, "close_connection", True) else "keep-alive"

        # client_disconnected mirrors the truncated detection but phrased from the
        # connection's point of view: a proven short write means the peer went away
        # (or nginx/the firewall dropped) before the full body was sent.
        client_disconnected = "true" if truncated == "true" else "false"

        # Number of requests served on this (keep-alive) connection, if gevent tracks it.
        requests_on_conn = getattr(self, "_requests_on_connection", None)
        requests_on_conn_str = str(requests_on_conn) if requests_on_conn is not None else "-"

        diagnostics = (
            f"sent_bytes={sent_bytes_str} app_bytes={app_bytes_str} content_length={content_length_str} "
            f"truncated={truncated} client_disconnected={client_disconnected} "
            f"connection={connection} requests_on_conn={requests_on_conn_str}"
        )

        # When the app produced N bytes but a meaningfully different number reached
        # the socket, surface a short, human-readable explanation right on the line.
        diff_note = self._body_diff_note(app_bytes, sent_bytes, declared_length)
        if diff_note:
            diagnostics = f"{diagnostics} {diff_note}"
        return diagnostics

    @staticmethod
    def _body_diff_note(app_bytes: int | None, sent_bytes: Any, declared_length: int | None) -> str:
        """Return a short 'body_diff=...' note when app vs socket bytes diverge.

        Only emitted when both counts are known and differ by MORE than
        ``BODY_DIFF_THRESHOLD_BYTES`` (a normal trailing-newline 1-byte delta is
        ignored). The note names the likely cause so a reader instantly knows
        whether the body was truncated on the wire or grew/shrank unexpectedly.
        """
        if app_bytes is None or not isinstance(sent_bytes, int):
            return ""
        delta = sent_bytes - app_bytes
        if abs(delta) <= BODY_DIFF_THRESHOLD_BYTES:
            return ""
        if delta < 0:
            # Fewer bytes on the wire than the app produced -> cut short.
            missing = -delta
            pct = (missing / app_bytes * 100) if app_bytes else 0.0
            cause = (
                "client/proxy closed the connection before the full body was sent"
                if (declared_length is not None and sent_bytes < declared_length)
                else "write stopped before the app finished streaming"
            )
            detail = (
                f"body_diff=\"app produced {app_bytes} body bytes but only {sent_bytes} "
                f"reached the socket; {missing} bytes ({pct:.1f}%) were not sent - "
                f"likely {cause}\""
            )
        else:
            extra = delta
            detail = (
                f"body_diff=\"socket sent {sent_bytes} bytes, {extra} MORE than the "
                f"{app_bytes} body bytes the app counted - extra bytes are likely "
                f"response framing/headers or a double-write\""
            )
        return detail

    def format_request(self):
        environ = self.environ or {}
        base_line = super().format_request()
        rid = environ.get(REQUEST_ID_ENVIRON_KEY, "-")
        parts = [base_line, f"rid={rid}", self._transfer_diagnostics(environ)]
        headers_str = format_request_headers(environ)
        if headers_str:
            parts.append(headers_str)
        return " ".join(parts)


class RequestLoggingMiddleware:
    """WSGI middleware that emits a detailed, structured log line per request.

    This is the Python-side counterpart to the nginx ``edl_detailed`` access log.
    Because nginx serves cache HITs without ever reaching this upstream, a request
    that appears in the nginx log with ``cache=HIT`` but is absent here was served
    entirely from cache - making the cache-vs-upstream distinction explicit.

    For every request it logs: the real client (X-Forwarded-For / X-Real-IP) as
    forwarded by nginx, the original URI, conditional/range headers, user-agent,
    the cache status nginx attached (X-Proxy-Cache), the response status, the
    number of body bytes written, and the wall-clock time spent in the app.
    """

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        # --- request received ------------------------------------------------
        # Wall-clock for absolute timestamps; perf_counter for accurate durations.
        t_received = time.time()
        received_iso = _iso_now()
        start_perf = time.perf_counter()

        # Correlation id: reuse nginx's X-Request-ID when present, else generate.
        # Stash it in environ so DemistoWSGIHandler prints the SAME id on the
        # "wsgi access:" line, tying the two python log lines together.
        rid = _new_request_id(environ)
        environ[REQUEST_ID_ENVIRON_KEY] = rid

        method = environ.get("REQUEST_METHOD", "-")
        path = environ.get("PATH_INFO", "-")
        query = environ.get("QUERY_STRING", "")
        full_path = f"{path}?{query}" if query else path
        remote_addr = environ.get("REMOTE_ADDR", "-")

        # How long the request waited inside nginx (queueing / cache-lock / connect)
        # BEFORE this app handler started. nginx forwards its forward-time as the
        # X-Request-Start epoch header; the difference vs our receive time is the
        # gap that explains why nginx's time_total_secs >> the app's elapsed time.
        nginx_wait_str = "-"
        request_start_header = environ.get(_header_env_key("X-Request-Start"))
        if request_start_header:
            try:
                nginx_wait = t_received - float(request_start_header)
                # Clamp tiny negative values from clock skew to 0.
                nginx_wait_str = f"{max(0.0, nginx_wait):.3f}s"
            except (TypeError, ValueError):
                nginx_wait_str = "-"

        # Collect the interesting request headers (auth is reduced to presence only).
        headers_str = format_request_headers(environ)

        # Monotonic sequence per request for correlation across log lines.
        seq = _next_request_seq()

        # Emit a START line immediately. A request that then hangs for 125s (or
        # never finishes because the client vanished) is visible right away here,
        # even though its END line would only appear much later (or not at all).
        demisto.info(
            f"wsgi request-start: rid={rid} seq={seq} received={received_iso} "
            f"nginx_wait={nginx_wait_str} "
            f"client={remote_addr} method={method} uri=\"{full_path}\" {headers_str}"
        )

        # Capture the response status/headers via a wrapped start_response.
        response_info: dict = {"status": "-", "cache": "-", "edl_size": "-", "content_length": "-"}
        # When start_response is invoked = app produced its response headers
        # (time-to-headers). Captured via closure so we can log it below.
        timings: dict = {"t_headers": None, "t_first_byte": None}

        def logging_start_response(status, response_headers, exc_info=None):
            if timings["t_headers"] is None:
                timings["t_headers"] = time.perf_counter()
            response_info["status"] = status.split(" ", 1)[0] if status else "-"
            for header_key, header_value in response_headers:
                lowered = header_key.lower()
                if lowered == "x-proxy-cache":
                    response_info["cache"] = header_value
                elif lowered == "x-edl-size":
                    response_info["edl_size"] = header_value
                elif lowered == "content-length":
                    response_info["content_length"] = header_value
            return start_response(status, response_headers, exc_info)

        bytes_sent = 0
        error_str = "-"
        t_app_start = time.perf_counter()
        try:
            result = self.app(environ, logging_start_response)
            # Count the bytes actually produced by the app so we can detect
            # size-vs-bytes mismatches / truncated bodies on the Python side.
            for chunk in result:
                if chunk:
                    if timings["t_first_byte"] is None:
                        timings["t_first_byte"] = time.perf_counter()
                    bytes_sent += len(chunk)
                    # Continuously expose the app-produced byte count so the gevent
                    # handler (DemistoWSGIHandler) can compare it with the bytes that
                    # actually reached the socket - even if we are cut off mid-stream.
                    environ[APP_BYTES_ENVIRON_KEY] = bytes_sent
                yield chunk
            if hasattr(result, "close"):
                result.close()
        except Exception as exc:  # noqa: BLE001 - we re-raise after logging
            # A client disconnect / write error surfaces here; record it so the
            # END line explains why a transfer stopped short.
            error_str = type(exc).__name__
            raise
        finally:
            end_perf = time.perf_counter()
            responded_iso = _iso_now()

            # Phase breakdown so it's obvious WHERE the time went:
            #   time_to_headers : app entry -> start_response (the "thinking" time).
            #   ttfb            : request received -> first body byte.
            #   stream_time     : first byte -> last byte (the streaming cost).
            #   elapsed         : total time inside the app.
            elapsed = end_perf - start_perf
            time_to_headers = (timings["t_headers"] - t_app_start) if timings["t_headers"] else None
            ttfb = (timings["t_first_byte"] - start_perf) if timings["t_first_byte"] else None
            stream_time = (
                end_perf - timings["t_first_byte"] if timings["t_first_byte"] else None
            )

            def _fmt(value):
                return f"{value:.3f}s" if value is not None else "-"

            demisto.info(
                f"wsgi request: rid={rid} seq={seq} "
                f"received={received_iso} responded={responded_iso} "
                f"client={remote_addr} method={method} uri=\"{full_path}\" "
                f"status={response_info['status']} "
                f"app_bytes={bytes_sent} content_length={response_info['content_length']} "
                f'cache="{response_info["cache"]}" edl_size={response_info["edl_size"]} '
                f"nginx_wait={nginx_wait_str} time_to_headers={_fmt(time_to_headers)} ttfb={_fmt(ttfb)} "
                f"stream_time={_fmt(stream_time)} elapsed={_fmt(elapsed)} "
                f"error={error_str} {headers_str}"
            )


# nginx server params
NGINX_SERVER_ACCESS_LOG = "/var/log/nginx/access.log"
NGINX_SERVER_ERROR_LOG = "/var/log/nginx/error.log"
NGINX_SERVER_CONF_FILE = "/etc/nginx/conf.d/default.conf"
NGINX_SSL_KEY_FILE = "/etc/nginx/ssl/ssl.key"
NGINX_SSL_CRT_FILE = "/etc/nginx/ssl/ssl.crt"
NGINX_SSL_CERTS = f"""
    ssl_certificate {NGINX_SSL_CRT_FILE};
    ssl_certificate_key {NGINX_SSL_KEY_FILE};
"""
# Detailed access log format with self-explanatory key names, grouped so the line
# reads top-to-bottom like the life of one request. Fields are ordered:
#
#   1. IDENTITY (first, so every line starts with "who/when/which request"):
#        when_finished         - ISO8601 timestamp of when nginx FINISHED the request
#                                and wrote this log line (i.e. request end). NOTE: stock
#                                nginx evaluates ALL log variables at write-time, so there
#                                is no built-in variable for the absolute arrival time.
#                                Derive it from the durations below:
#                                  arrival       = when_finished - time_total_secs
#                                  sent_upstream = arrival + time_to_upstream_connect_secs
#        request_id            - unique id for THIS request; the SAME id is sent to
#                                the Python upstream (X-Request-ID) and printed on the
#                                "wsgi request:"/"wsgi access:" lines, so one request
#                                can be followed across nginx and Python.
#        connection_id         - id of the TCP connection (many requests can share one).
#        requests_on_connection- how many requests have used this keep-alive connection
#                                (rising numbers = reuse; helps spot CLOSE_WAIT buildup).
#
#   2. WHO CONNECTED (client identity through the proxy chain):
#        client_real_ip        - the true client (the firewall), via X-Real-IP.
#        client_forwarded_chain- full X-Forwarded-For chain of proxies in between.
#        client_nearest_peer   - the immediate TCP peer nginx saw (usually localhost/edge).
#        client_user_agent     - the client's User-Agent string.
#
#   3. WHAT WAS ASKED (the request itself):
#        request_method        - GET/HEAD/...
#        request_uri           - the full requested URI.
#        request_host          - the Host header.
#        request_range         - Range header (partial-content requests).
#        request_if_none_match - ETag the client already has (conditional GET).
#        request_if_modified_since - date the client already has (conditional GET).

#
#   4. WHAT HAPPENED (response outcome + cache decision):
#        response_status       - HTTP status code returned.
#        cache_status          - HIT/MISS/BYPASS/EXPIRED/STALE/UPDATING/REVALIDATED.
#        upstream_address      - which upstream served it (empty on a cache HIT).
#        response_etag         - ETag we returned.
#
#   5. HOW BIG (payload accounting; mismatch = truncated/aborted transfer):
#        response_body_bytes   - body bytes sent to the client.
#        response_total_bytes  - total bytes sent (headers + body).
#        edl_indicator_count   - number of indicators in the EDL response.
#        edl_origin_count      - number of origin indicators before filtering.
#
#   6. HOW LONG (ALL timings grouped together at the end, in seconds). These are the
#      source of truth for the timeline - use them to reconstruct WHEN nginx received
#      the request from the client and WHEN it forwarded it to the upstream:
#        time_total_secs            - total time to serve the request (from when nginx
#                                     read the first client bytes until the last byte was
#                                     sent to the client). The client request therefore
#                                     ARRIVED at: when_finished - time_total_secs.
#        time_to_upstream_connect_secs - seconds AFTER arrival that nginx established the
#                                     upstream connection. This marks WHEN nginx forwarded
#                                     the request to the upstream:
#                                       sent_to_upstream = (when_finished - time_total_secs)
#                                                          + time_to_upstream_connect_secs
#                                     ("-" on a cache HIT, because no upstream request was made.)
#        time_upstream_headers_secs - seconds after the upstream request until the upstream
#                                     returned its response headers.
#        time_upstream_response_secs- seconds after the upstream request until the upstream
#                                     finished sending its response.
#        time_edl_query_secs        - time the EDL spent building the list (app side).
NGINX_LOG_FORMAT = """
log_format edl_detailed
    'when_finished=$time_iso8601 request_id=$request_id '
    'connection_id=$connection requests_on_connection=$connection_requests '
    'client_real_ip="$http_x_real_ip" client_forwarded_chain="$http_x_forwarded_for" '
    'client_nearest_peer=$remote_addr client_user_agent="$http_user_agent" '
    'request_method=$request_method request_uri="$request_uri" request_host="$host" '
    'request_range="$http_range" request_if_none_match="$http_if_none_match" '
    'request_if_modified_since="$http_if_modified_since" '
    'response_status=$status cache_status=$upstream_cache_status upstream_address="$upstream_addr" '
    'response_etag="$sent_http_etag" '
    'response_body_bytes=$body_bytes_sent response_total_bytes=$bytes_sent '
    'edl_indicator_count="$sent_http_x_edl_size" edl_origin_count="$sent_http_x_edl_origin_size" '
    'time_total_secs=$request_time time_to_upstream_connect_secs="$upstream_connect_time" '
    'time_upstream_headers_secs="$upstream_header_time" time_upstream_response_secs="$upstream_response_time" '
    'time_edl_query_secs="$sent_http_x_edl_query_time_secs"';
"""
NGINX_SERVER_CONF = """
$log_format

# Per-URI concurrency zone used to FAIL (not queue) concurrent cold-MISS requests
# for the same URI. Keyed on $request_uri so the limit is per-resource, not per-client.
limit_conn_zone $request_uri zone=concurrent_conn_zone:1m;
server {

    listen $port default_server $ssl;

    $sslcerts

    # Per-request detailed access log + verbose error log so cache decisions,
    # real client IPs, timings and upstream warnings are all captured.
    access_log /var/log/nginx/access.log edl_detailed;
    error_log /var/log/nginx/error.log info;


    proxy_cache_key $scheme$proxy_host$request_uri$extra_cache_key;
    $proxy_set_range_header
    $extra_headers
# Cache-vs-fetch policy (TWO-TIER, HIT-safe fail-fast on cold MISS)
# ---------------------------------------------------------------------------
# We want two behaviors that plain `proxy_cache_lock` cannot give together:
#   * On a TRUE cold MISS (nothing cached to fall back on), concurrent requests
#     for the SAME URI must FAIL FAST (429) instead of queueing behind a lock.
#   * On STALE / UPDATING (a cached copy exists but is expired/being refreshed)
#     clients must be served the STALE copy and must NEVER be rejected.
#
# `limit_conn` is the only mechanism that REJECTS (proxy_cache_lock only WAITS),
# but it runs in the preaccess phase - before the cache status is known - so
# applying it on the public cache location would ALSO count cache HITs and could
# 429 two simultaneous HITs of the same URI. nginx's `proxy_cache` cannot route
# "only on miss" to a different location within one server, so we use TWO server
# blocks:
#   Tier 1 = public server on $port : does the cache read. HIT / STALE / UPDATING
#            are answered here from the cache (see proxy_cache_use_stale +
#            proxy_cache_background_update) and, on a MISS, proxy_pass to Tier 2.
#            HIT/STALE/UPDATING never leave Tier 1, so they are never counted and
#            never rejected.
#   Tier 2 = internal server on localhost:$fetchport : reached ONLY when Tier 1's
#            cache must populate a new entry (true MISS / expired-with-no-stale).
#            It carries `limit_conn ... 1`, so the first fetch for a URI proceeds
#            and every concurrent same-URI fetch is rejected immediately with 429.

# Cache validity by status
proxy_cache_valid 200 301 302 $cache_refresh_rate;

# Optional: cache other responses briefly (helps absorb spikes)
proxy_cache_valid 404 $cache_404_ttl;
# NEVER cache the fail-fast rejection: a 429 from the Tier-2 limiter is a
# transient "someone else is already building this" signal. Caching it (via the
# `any` rule below) would poison the URI and serve 429s even after the real
# content is ready. `0s` = do not cache; being status-specific it overrides `any`.
proxy_cache_valid 429 0s;
# NEVER cache upstream errors / timeouts either. A 504 means the build exceeded
# proxy_read_timeout and a 5xx is a transient upstream failure - caching them via
# the `any` rule below would poison the URI and keep serving the error (as a
# cache HIT) even after a later build would succeed, blocking recovery. `0s` = do
# not cache; being status-specific these override `any`. Note: this does NOT stop
# `proxy_cache_use_stale timeout http_50x` from serving a previously-cached GOOD
# copy on timeout - that stale-serving is desirable and is what we keep.
proxy_cache_valid 500 502 503 504 0s;
proxy_cache_valid any $cache_default_ttl;

# Revalidation (use conditional requests when expired)
proxy_cache_revalidate on;

# Serve stale content in failure/update scenarios. `updating` is what lets a
# STALE entry be served immediately to every waiting client while a single
# background refresh runs - so STALE/UPDATING never reach the Tier-2 limiter.
proxy_cache_use_stale
    updating
    error
    timeout
    invalid_header
    http_500
    http_502
    http_503
    http_504;

# Background refresh of expired cache: the refresh runs as a detached subrequest,
# so serving stale is always allowed and never fails.
proxy_cache_background_update on;

    # Static test file
    location = /nginx-test {
        alias /var/lib/nginx/html/index.html;
        default_type text/html;
    }

    # ---- Tier 1: public cache front --------------------------------------
    # Serves HIT / STALE / UPDATING from the cache. On a MISS, the cache module
    # fetches from Tier 2 (the internal fetch server) where the fail-fast limiter
    # lives. HITs/STALE/UPDATING are served straight from cache and never reach
    # Tier 2, so they are never counted by limit_conn and never rejected.
    location / {
        proxy_pass http://localhost:$fetchport/;

        # CRITICAL: the base flask-nginx image ENABLES the cache lock in the
        # http{} block, and that setting is inherited here. While enabled,
        # concurrent cold-MISS requests for the same URI WAIT for the first
        # request to populate the cache (then get served HIT) - they never fall
        # through to Tier 2, so the fail-fast limit_conn never fires. We MUST turn
        # the inherited lock OFF here so misses proceed to Tier 2 and the 2nd+
        # concurrent miss is rejected with 429 instead of queued.
        proxy_cache_lock off;

        # Surface the cache decision both to the client and (via the access log
        # variable) to our logging: HIT/MISS/BYPASS/EXPIRED/STALE/UPDATING/REVALIDATED.
        add_header X-Proxy-Cache $upstream_cache_status always;
        $extra_headers
        # allow bypassing the cache with an arg of nocache=1 ie http://server:7000/?nocache=1
        proxy_cache_bypass $arg_nocache;
        proxy_read_timeout $timeout;
        proxy_connect_timeout 3600;
        proxy_send_timeout 3600;
        send_timeout 3600;

        # Forward the real client identity through the chain so the Python (gevent)
        # upstream's WSGI middleware can log the actual firewall/client instead of
        # 127.0.0.1. Tier 2 forwards these on to the app.
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Original-URI $request_uri;
        # Propagate nginx's per-request id to the upstream so the same request_id
        # appears in the nginx access log AND the wsgi request/access lines,
        # giving a single correlation id end-to-end.
        proxy_set_header X-Request-ID $request_id;
        # Forward, as an epoch (seconds.ms), the moment nginx is about to hand the
        # request to the upstream. The WSGI middleware compares this with its own
        # receive time and logs "nginx_wait" - the time the request spent inside
        # nginx (queueing / cache-lock / connect) BEFORE the app started working.
        proxy_set_header X-Request-Start $msec;
    }

    # How long an idle keep-alive client connection stays open. Lowering this lets nginx
    # reap connections from clients (e.g. firewalls) that polled and went away, instead of
    # leaving them pinned in CLOSE_WAIT and consuming a worker_connections slot + an FD.
    # Default "65" matches nginx's built-in default, so behavior is unchanged unless tuned.
    keepalive_timeout $keepalive_timeout;
}

# ---- Tier 2: internal fetch server (cold-MISS path only) -----------------
# Reached ONLY via Tier 1's cache fetch on a MISS. Because Tier 1 answers
# HIT/STALE/UPDATING from cache, only requests that actually need the upstream
# arrive here, so `limit_conn ... 1` counts ONLY cold-miss fetches: the first
# request for a URI builds the cache entry, and every concurrent same-URI fetch
# is rejected immediately with 429. Listens on loopback only, so it is never
# reachable directly by external clients.
server {
    listen localhost:$fetchport;

    access_log /var/log/nginx/access.log edl_detailed;
    error_log /var/log/nginx/error.log info;

    location / {
        limit_conn concurrent_conn_zone 1;
        limit_conn_status 429;

        # Tier 2 must NOT cache: caching is owned entirely by Tier 1 (the public
        # server). If proxy_cache is inherited from the http{} block, disable it
        # here so this tier is purely the rate-limited cold-MISS fetch path.
        proxy_cache off;

        proxy_pass http://localhost:$serverport/;

        # Preserve the forwarded client identity headers set by Tier 1.
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $http_x_real_ip;
        proxy_set_header X-Forwarded-For $http_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
        proxy_set_header X-Original-URI $http_x_original_uri;
        proxy_set_header X-Request-ID $http_x_request_id;
        proxy_set_header X-Request-Start $http_x_request_start;

        proxy_read_timeout $timeout;
        proxy_connect_timeout 3600;
        proxy_send_timeout 3600;
        send_timeout 3600;
    }
}

"""
NGINX_MAX_POLLING_TRIES = 5
def create_nginx_server_conf(file_path: str, port: int, params: dict):
    """Create nginx conf file

    Args:
        file_path (str): path of server conf file
        port (int): listening port. server port to proxy to will be port+1
        params (Dict): additional nginx params

    Raises:
        DemistoException: raised if there is a detected config error
    """
    params = params if params else demisto.params()
    template_str = params.get("nginx_server_conf") or NGINX_SERVER_CONF
    certificate: str = params.get("certificate", "")
    private_key: str = params.get("key", "")
    # Normalize all five `cache_*` time params (plus `timeout`) through a single helper so the
    # rendered nginx directives are always a safe `<int>s` token.
    timeout = _normalize_nginx_time(params.get("timeout"), default="3600", param_name="timeout")
    cache_refresh_rate = _normalize_nginx_time(params.get("cache_refresh_rate"), default=timeout, param_name="cache_refresh_rate")

    # Ensure cache lock directives are at least as large as the upstream timeout. Otherwise, when an
    # upstream request takes longer than the lock timeout/age, waiting clients bypass the cache lock
    # and stampede the upstream (each waiter then produces an uncached response), defeating the purpose
    # of `proxy_cache_lock on`. Defaults match `timeout`; explicit smaller values are bumped up.
    cache_lock_timeout = _normalize_nginx_time(params.get("cache_lock_timeout"), default=timeout, param_name="cache_lock_timeout")
    cache_lock_age = _normalize_nginx_time(params.get("cache_lock_age"), default=timeout, param_name="cache_lock_age")
    cache_404_ttl = _normalize_nginx_time(params.get("cache_404_ttl"), default="1m", param_name="cache_404_ttl")
    cache_default_ttl = _normalize_nginx_time(params.get("cache_default_ttl"), default="1m", param_name="cache_default_ttl")

    # Idle keep-alive timeout for client connections. Normalized independently of `timeout` and
    # deliberately NOT floored to it: a small value (default "65", nginx's own default) lets nginx
    # promptly reap connections from clients that polled and disconnected, preventing the CLOSE_WAIT
    # buildup that otherwise exhausts the worker's connection/FD budget. Behavior is unchanged unless
    # the `keepalive_timeout` param is explicitly set.
    keepalive_timeout = _normalize_nginx_time(params.get("keepalive_timeout"), default="65", param_name="keepalive_timeout")

    # Ensure cache_refresh_rate is at least as large as timeout, and apply the same anti-stampede
    # floor to the cache lock directives. All values are now guaranteed to end in "s" (the helper
    # always returns `<int>s`), so an O(1) integer compare on the prefix is safe.
    timeout_seconds = int(timeout[:-1])
    if int(cache_refresh_rate[:-1]) < timeout_seconds:
        cache_refresh_rate = timeout
    if int(cache_lock_timeout[:-1]) < timeout_seconds:
        cache_lock_timeout = timeout
    if int(cache_lock_age[:-1]) < timeout_seconds:
        cache_lock_age = timeout

    ssl, extra_headers, sslcerts, proxy_set_range_header = "", "", "", ""
    serverport = port + 1
    # Internal loopback port for the Tier-2 cold-MISS fetch server. Tier 1 (public,
    # $port) proxies cache misses to localhost:$fetchport, which applies the
    # fail-fast `limit_conn` and then proxies on to the gevent app on $serverport.
    fetchport = serverport + 1
    extra_cache_keys = []
    if (certificate and not private_key) or (private_key and not certificate):
        raise DemistoException("If using HTTPS connection, both certificate and private key should be provided.")
    if certificate and private_key:
        demisto.debug("Using HTTPS for nginx conf")
        with open(NGINX_SSL_CRT_FILE, "w") as f:
            f.write(certificate)
        with open(NGINX_SSL_KEY_FILE, "w") as f:
            f.write(private_key)
        ssl = "ssl"  # to be included in the listen directive
        sslcerts = NGINX_SSL_CERTS
        if argToBoolean(params.get("hsts_header", False)):
            extra_headers = 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
    credentials = params.get("credentials") or {}
    if credentials.get("identifier"):
        extra_cache_keys.append("$http_authorization")
    if get_integration_name() == "TAXII2 Server":
        extra_cache_keys.append("$http_accept")
        if params.get("version") == "2.0":
            proxy_set_range_header = "proxy_set_header Range $http_range;"
            extra_cache_keys.extend(["$http_range", "$http_content_range"])

    extra_cache_keys_str = "".join(extra_cache_keys)
    server_conf = Template(template_str).safe_substitute(
        log_format=NGINX_LOG_FORMAT,
        port=port,
        serverport=serverport,
        fetchport=fetchport,
        ssl=ssl,
        sslcerts=sslcerts,
        extra_cache_key=extra_cache_keys_str,
        proxy_set_range_header=proxy_set_range_header,
        timeout=timeout,
        cache_refresh_rate=cache_refresh_rate,
        cache_lock_timeout=cache_lock_timeout,
        cache_lock_age=cache_lock_age,
        cache_404_ttl=cache_404_ttl,
        cache_default_ttl=cache_default_ttl,
        keepalive_timeout=keepalive_timeout,
        extra_headers=extra_headers,
    )
    # Log the effective cache / timeout settings so each (re)start records exactly
    # which values are active - essential for interpreting cache=HIT/STALE/UPDATING
    # decisions and the upstream timing fields in the access logs.
    demisto.info(
        "edl: nginx effective settings -> "
        f"listen_port={port} upstream_port={serverport} fetch_tier_port={fetchport} ssl={'on' if ssl else 'off'} "
        f"timeout={timeout} cache_refresh_rate={cache_refresh_rate} "
        f"cache_lock_timeout={cache_lock_timeout} cache_lock_age={cache_lock_age} "
        f"cache_404_ttl={cache_404_ttl} cache_default_ttl={cache_default_ttl} "
        f"keepalive_timeout={keepalive_timeout} "
        f"extra_cache_keys=[{extra_cache_keys_str}]"
    )
    with open(file_path, mode="w+") as f:
        f.write(server_conf)


def start_nginx_server(port: int, params: dict = {}) -> subprocess.Popen:
    params = params if params else demisto.params()
    create_nginx_server_conf(NGINX_SERVER_CONF_FILE, port, params)
    nginx_global_directives = "daemon off;"
    global_directives_conf = params.get("nginx_global_directives")
    if global_directives_conf:
        nginx_global_directives = f"{nginx_global_directives} {global_directives_conf}"
    directive_args = ["-g", nginx_global_directives]
    # we first do a test that all config is good and log it
    try:
        nginx_test_command = ["nginx", "-T"]
        nginx_test_command.extend(directive_args)
        test_output = subprocess.check_output(nginx_test_command, stderr=subprocess.STDOUT, text=True)
        demisto.info(f"ngnix test passed. command: [{nginx_test_command}]")
        # Promote the fully rendered config to info so the active log_format, cache,
        # timeout and proxy_set_header directives are recorded on every (re)start.
        demisto.info(f"nginx effective rendered config (nginx -T):\n{test_output}")
    except subprocess.CalledProcessError as err:
        raise ValueError(f"Failed testing nginx conf. Return code: {err.returncode}. Output: {err.output}")
    nginx_command = ["nginx"]
    nginx_command.extend(directive_args)
    res = subprocess.Popen(nginx_command, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    demisto.info(f"done starting nginx with pid: {res.pid}")
    return res


def nginx_log_process(nginx_process: subprocess.Popen):
    old_access = NGINX_SERVER_ACCESS_LOG + ".old"
    old_error = NGINX_SERVER_ERROR_LOG + ".old"
    log_access = False
    log_error = False
    # first check if one of the logs are missing. This may happen on rare ocations that we renamed and deleted the file
    # before nginx completed the role over of the logs
    missing_log = False
    if not os.path.isfile(NGINX_SERVER_ACCESS_LOG):
        missing_log = True
        demisto.info(f"Missing access log: {NGINX_SERVER_ACCESS_LOG}. Will send roll signal to nginx.")
    if not os.path.isfile(NGINX_SERVER_ERROR_LOG):
        missing_log = True
        demisto.info(f"Missing error log: {NGINX_SERVER_ERROR_LOG}. Will send roll signal to nginx.")
    if missing_log:
        nginx_process.send_signal(int(SIGUSR1))
        demisto.info(
            f"Done sending roll signal to nginx (pid: {nginx_process.pid}) after detecting missing log file."
            " Will skip this iteration."
        )
        return
    if os.path.getsize(NGINX_SERVER_ACCESS_LOG):
        log_access = True
        Path(NGINX_SERVER_ACCESS_LOG).rename(old_access)
    if os.path.getsize(NGINX_SERVER_ERROR_LOG):
        log_error = True
        Path(NGINX_SERVER_ERROR_LOG).rename(old_error)
    if log_access or log_error:
        # nginx rolls the logs when getting sigusr1
        nginx_process.send_signal(int(SIGUSR1))
        gevent.sleep(0.5)  # sleep 0.5 to let nginx complete the roll
    if log_access:
        with open(old_access) as f:
            start = 1
            for lines in batch(f.readlines(), 100):
                end = start + len(lines)
                demisto.info(f"nginx access log ({start}-{end-1}): " + "".join(lines))
                start = end
        Path(old_access).unlink()
    if log_error:
        with open(old_error) as f:
            start = 1
            for lines in batch(f.readlines(), 100):
                end = start + len(lines)
                demisto.error(f"nginx error log ({start}-{end-1}): " + "".join(lines))
                start = end
        Path(old_error).unlink()


def nginx_log_monitor_loop(nginx_process: subprocess.Popen):
    """An endless loop to monitor nginx logs. Meant to be spawned as a greenlet.
    Will run every minute and if needed will dump the nginx logs and roll them if needed.

    Args:
        nginx_process (subprocess.Popen): the nginx process. Will send signal for log rolling.
    """
    while True:
        gevent.sleep(60)
        nginx_log_process(nginx_process)



def test_nginx_web_server(port: int, params: dict):
    polling_tries = 1
    is_test_done = False
    try:
        while polling_tries <= NGINX_MAX_POLLING_TRIES and not is_test_done:
            try:
                # let nginx startup
                time.sleep(0.5)
                protocol = "https" if params.get("key") else "http"
                res = requests.get(
                    f"{protocol}://localhost:{port}/nginx-test", verify=False, proxies={"http": "", "https": ""}
                )  # guardrails-disable-line # nosec
                res.raise_for_status()
                welcome = "Welcome to nginx"
                if welcome not in res.text:
                    raise ValueError(f'Unexpected response from nginx-test (does not contain "{welcome}"): {res.text}')
                is_test_done = True
            except Exception:
                if polling_tries == NGINX_MAX_POLLING_TRIES:
                    raise
                polling_tries += 1
    except Exception as ex:
        err_msg = f"Testing nginx server: {ex}"
        demisto.error(err_msg)
        raise DemistoException(err_msg) from ex


def test_nginx_server(port: int, params: dict):
    nginx_process = start_nginx_server(port, params)
    try:
        test_nginx_web_server(port, params)
    finally:
        try:
            nginx_process.terminate()
            nginx_process.wait(1.0)
        except Exception as ex:
            demisto.error(f"failed stopping test nginx process: {ex}")


def try_parse_integer(int_to_parse: Any, err_msg: str) -> int:
    """
    Tries to parse an integer, and if fails will throw DemistoException with given err_msg
    """
    try:
        res = int(int_to_parse)
    except (TypeError, ValueError):
        raise DemistoException(err_msg)
    return res


def parse_nginx_time_to_seconds(time_str: str) -> int:
    """Parses an NGINX time string (or a human-readable equivalent) into seconds.

    NGINX uses suffixes to denote time units (e.g., ``"3600"``, ``"1h"``,
    ``"30m"``, ``"60s"``). Supported suffixes are ``s`` (seconds), ``m``
    (minutes), ``h`` (hours), ``d`` (days), ``w`` (weeks), ``M`` (30 days),
    and ``y`` (years). If no suffix is supplied, the value is treated as
    seconds.

    Additionally, human-readable values used by some integrations (e.g., EDL's
    ``cache_refresh_rate`` parameter such as ``"5 minutes"``, ``"1 hour"``,
    ``"2 days"``) are also supported by falling back to ``dateparser``.

    Args:
        time_str (str): The time string to parse.

    Returns:
        int: The time converted to seconds.

    Raises:
        DemistoException: If ``time_str`` is empty, whitespace-only, ``None``,
            or otherwise cannot be parsed as a valid time value.
    """
    if not time_str or not (time_str := time_str.strip()):
        raise DemistoException(f"Invalid NGINX time format: {time_str}")
    if time_str.isdigit():
        return int(time_str)

    units = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
        "M": 2592000,  # 30 days
        "y": 31536000,
    }

    unit = time_str[-1]
    value_str = time_str[:-1]

    if unit in units and value_str.isdigit():
        return int(value_str) * units[unit]

    # If it doesn't match the NGINX-native format, try parsing it as a
    # human-readable relative time (e.g., "5 minutes", "1 hour", "2 days").
    try:
        seconds = ceil((datetime.now() - dateparser.parse(time_str)).total_seconds())  # type: ignore[operator]
        if seconds > 0:
            return seconds
    except Exception:
        pass

    # Last resort: try to interpret the value as an integer number of seconds.
    try:
        return int(time_str)
    except (ValueError, TypeError):
        raise DemistoException(f"Invalid NGINX time format: {time_str}")


# Human-readable units accepted in the "<int> <unit>" form (e.g. "12 hours",
# "1 minute"). Anything outside this allow-list is rejected up-front so we do
# not silently inherit dateparser's permissive interpretation of unit-only
# tokens (e.g. "hours" -> midnight today) or compound expressions
# (e.g. "12 hours and 5 minutes" -> "12 hours ago at 23:25").
_NORMALIZE_NGINX_TIME_HUMAN_UNITS = frozenset(
    {
        "second",
        "seconds",
        "minute",
        "minutes",
        "hour",
        "hours",
        "day",
        "days",
        "week",
        "weeks",
        "month",
        "months",
        "year",
        "years",
    }
)


def _normalize_nginx_time(value: Any, default: str, param_name: str) -> str:
    """Normalize a user-supplied time value to an nginx-valid ``"<int>s"`` token.

    Accepts:
      * pure ints       : ``300``, ``"300"`` (must be non-negative)
      * nginx-native    : ``"12h"``, ``"30m"``, ``"1d"``, ``"2w"``, ``"1M"``,
                          ``"1y"``, ``"60s"``
      * human-readable  : strict ``"<positive-int> <unit>"`` form, where unit
                          is one of ``second(s)``, ``minute(s)``, ``hour(s)``,
                          ``day(s)``, ``week(s)``, ``month(s)``, ``year(s)``.

    Always returns ``f"{seconds}s"`` (e.g. ``"43200s"``) so the rendered nginx
    directive is unambiguous and unit-safe — the entire class of unit-string
    typo bugs in the template is eliminated.

    Falls back to ``default`` (which is itself normalized through the same
    helper) when ``value`` is ``None``, an empty string, or whitespace-only,
    so callers can pass either form for the default.

    Args:
        value: The user-supplied value (may be ``None``, ``int``, or ``str``).
        default: The fallback value used when ``value`` is empty/missing.
            Accepts the same formats as ``value``.
        param_name: Name of the originating parameter; included verbatim in
            error messages so users can pinpoint the offending field.

    Returns:
        An nginx-valid time token of the form ``"<int>s"``.

    Raises:
        DemistoException: If ``value`` (or, when ``value`` is empty,
            ``default``) is non-empty but cannot be parsed as a valid time
            value, or resolves to a non-positive number of seconds. The
            message includes ``param_name`` and the original ``value``.
    """
    raw = "" if value is None else str(value).strip()
    if not raw:
        raw = str(default).strip()

    # Pre-validate the shape before delegating.
    tokens = raw.split()
    accepted_shape = (
        # nginx-native single token: pure int, or <int><unit-letter>
        (len(tokens) == 1 and (raw.isdigit() or (raw[:-1].isdigit() and raw[-1] in "smhdwMy")))
        # strict "<int> <unit>" human-readable form
        or (len(tokens) == 2 and tokens[0].isdigit() and tokens[1].lower() in _NORMALIZE_NGINX_TIME_HUMAN_UNITS)
    )
    if not accepted_shape:
        raise DemistoException(
            f"Invalid value for parameter '{param_name}': {value!r}. "
            f"Expected an nginx-native value (e.g. '12h', '30m', '300') "
            f"or a human-readable value (e.g. '12 hours', '30 minutes')."
        )

    try:
        seconds = parse_nginx_time_to_seconds(raw)
    except DemistoException as e:
        raise DemistoException(
            f"Invalid value for parameter '{param_name}': {value!r}. "
            f"Expected an nginx-native value (e.g. '12h', '30m', '300') "
            f"or a human-readable value (e.g. '12 hours', '30 minutes'). "
            f"Original parser error: {e}"
        )
    if seconds <= 0:
        raise DemistoException(
            f"Invalid value for parameter '{param_name}': {value!r}. " f"Value must resolve to a positive number of seconds."
        )
    return f"{seconds}s"


def get_params_port(params: dict = None) -> int:
    """
    Gets port from the integration parameters
    """
    params = params if params else demisto.params()
    port_mapping: str = params.get("longRunningPort", "")
    err_msg: str
    port: int
    if port_mapping:
        err_msg = f"Listen Port must be an integer. {port_mapping} is not valid."
        if ":" in port_mapping:
            port = try_parse_integer(port_mapping.split(":")[1], err_msg)
        else:
            port = try_parse_integer(port_mapping, err_msg)
    else:
        raise ValueError("Please provide a Listen Port.")
    return port




def run_long_running(params: dict = None, is_test: bool = False):
    """
    Start the long running server
    :param params: Demisto params
    :param is_test: Indicates whether it's test-module run or regular run
    :return: None
    """
    params = params if params else demisto.params()
    nginx_process = None
    nginx_log_monitor = None

    try:
        nginx_port = get_params_port()
        server_port = nginx_port + 1
        # set our own log handlers
        APP.logger.removeHandler(default_handler)  # type: ignore[name-defined] # pylint: disable=E0602
        integration_logger = IntegrationLogger()
        integration_logger.buffering = False
        log_handler = DemistoHandler(integration_logger)
        log_handler.setFormatter(logging.Formatter("flask log: [%(asctime)s] %(levelname)s in %(module)s: %(message)s"))
        APP.logger.addHandler(log_handler)  # type: ignore[name-defined] # pylint: disable=E0602
        demisto.debug("done setting demisto handler for logging")
        demisto.info(f"edl: starting server on 0.0.0.0:{server_port}; nginx proxy on port {nginx_port}.")

        if is_test:
            test_nginx_server(nginx_port, params)
            server = WSGIServer(
                ("0.0.0.0", server_port),
                APP,  # type: ignore[name-defined] # pylint: disable=E0602
                log=DEMISTO_LOGGER,
                error_log=ERROR_LOGGER,
            )
            server.start()
            time.sleep(5)
            server.stop()

        else:
            nginx_process = start_nginx_server(nginx_port, params)
            test_nginx_web_server(nginx_port, params)
            nginx_log_monitor = gevent.spawn(nginx_log_monitor_loop, nginx_process)
            wsgi_app = RequestLoggingMiddleware(APP)  # type: ignore[name-defined] # pylint: disable=E0602
            server = WSGIServer(
                ("0.0.0.0", server_port),
                wsgi_app,
                log=DEMISTO_LOGGER,  # type: ignore[name-defined] # pylint: disable=E0602
                error_log=ERROR_LOGGER,
                handler_class=DemistoWSGIHandler,
            )
            demisto.updateModuleHealth("")
            server.serve_forever()
    except Exception as e:
        error_message = str(e)
        if isinstance(e, ValueError) and "Try to write when connection closed" in error_message:
            # This indicates that the XSOAR platform is unreachable, and there is no way to recover from this, so we need to exit.
            sys.exit(1)  # pylint: disable=E9001

        demisto.error(f"An error occurred: {error_message}. Exception: {traceback.format_exc()}")
        demisto.updateModuleHealth(f"An error occurred: {error_message}")
        raise ValueError(error_message)

    finally:
        if nginx_process:
            try:
                nginx_process.terminate()
            except Exception as ex:
                demisto.error(f"Failed stopping nginx process when exiting: {ex}")
        if nginx_log_monitor:
            try:
                nginx_log_monitor.kill(timeout=1.0)
            except Exception as ex:
                demisto.error(f"Failed stopping nginx_log_monitor when exiting: {ex}")
