import asyncio
import base64
import os
import re
import threading
import time
import uuid
from collections import deque
from secrets import compare_digest
from tempfile import NamedTemporaryFile
from traceback import format_exc
from contextlib import asynccontextmanager
from urllib.parse import urlparse
import concurrent.futures

import uvicorn
from CommonServerPython import *  # noqa: F401
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.openapi.models import APIKey
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.api_key import APIKeyHeader
from M2Crypto import X509

from CommonServerUserPython import *


PARAMS: dict = demisto.params()


# Defensive serialisation of the get/append/set RMW on the integration-context
# `sample_events` key. Effectively uncontended now that all writes go through
# the single-thread `_SAMPLE_EXECUTOR` below.
_sample_events_lock = threading.Lock()
_SAMPLE_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None
_sample_executor_install_lock = threading.Lock()
_sample_pending = 0
_sample_pending_lock = threading.Lock()
_SAMPLE_PENDING_MAX = 100  # absolute cap on backlog


def _install_sample_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Lazily create the single-thread background pool for `store_samples`.

    Idempotent + thread-safe (double-checked locking).
    """
    global _SAMPLE_EXECUTOR
    if _SAMPLE_EXECUTOR is not None:
        return _SAMPLE_EXECUTOR
    with _sample_executor_install_lock:
        if _SAMPLE_EXECUTOR is not None:
            return _SAMPLE_EXECUTOR
        _SAMPLE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
            max_workers=1,
            thread_name_prefix="sns-sample-writer",
        )
        demisto.debug("sns.sample_executor.installed max_workers=1")
        return _SAMPLE_EXECUTOR


def _submit_store_samples(incident: dict, req_id: str) -> None:
    """Fire-and-forget submission of `store_samples(incident)` to the background pool.

    Drops with an error log when pending exceeds `_SAMPLE_PENDING_MAX`.
    Never blocks the caller.
    """
    global _sample_pending
    with _sample_pending_lock:
        if _sample_pending >= _SAMPLE_PENDING_MAX:
            demisto.error(
                f"sns.sample_writer.dropped req_id={req_id} "
                f"pending={_sample_pending} max={_SAMPLE_PENDING_MAX} "
                f"reason=backlog_full"
            )
            return
        _sample_pending += 1
        current = _sample_pending

    executor = _install_sample_executor()
    t_submit = time.monotonic()

    def _runner() -> None:
        global _sample_pending
        t_start = time.monotonic()
        wait_ms = (t_start - t_submit) * 1000.0
        try:
            store_samples(incident)
            took_ms = (time.monotonic() - t_start) * 1000.0
            demisto.debug(f"sns.sample_writer.done req_id={req_id} " f"queue_wait_ms={wait_ms:.1f} took_ms={took_ms:.1f}")
        except Exception as e:
            # Defensive: a raise here would kill the single writer thread.
            demisto.error(f"sns.sample_writer.error req_id={req_id} err={e}\n{format_exc()}")
        finally:
            with _sample_pending_lock:
                _sample_pending -= 1

    try:
        executor.submit(_runner)
        demisto.debug(f"sns.sample_writer.submitted req_id={req_id} pending={current}")
    except RuntimeError as e:
        # Executor shut down (e.g. container teardown) — roll back the gauge.
        with _sample_pending_lock:
            _sample_pending -= 1
        demisto.error(f"sns.sample_writer.submit_failed req_id={req_id} err={e}")


# ---------------------------------------------------------------------------
# Concurrency diagnostics — in-process counters for capacity logging.
# `_inflight` = requests currently inside `_process_request_blocking`.
# `_inflight_peak` = high-water mark since container start.
# Lock is never held across I/O.
# ---------------------------------------------------------------------------
_inflight = 0
_inflight_peak = 0
_inflight_lock = threading.Lock()


def _inflight_enter() -> tuple[int, int]:
    """Increment the in-flight gauge and return (current, peak) for logging."""
    global _inflight, _inflight_peak
    with _inflight_lock:
        _inflight += 1
        if _inflight > _inflight_peak:
            _inflight_peak = _inflight
        return _inflight, _inflight_peak


def _inflight_exit() -> int:
    """Decrement the in-flight gauge and return the new current value."""
    global _inflight
    with _inflight_lock:
        _inflight -= 1
        return _inflight


def _thread_tag() -> str:
    """Return a compact `name#id` tag for the current thread (log-friendly)."""
    t = threading.current_thread()
    return f"{t.name}#{t.ident}"


# ---------------------------------------------------------------------------
# DIAGNOSTIC (socket-timeout investigation): event-loop heartbeat.
# Logs the actual wall-clock gap between expected and observed ticks. If
# `gap_ms` is consistently > ~200 ms, the event loop is being blocked by
# AWS SNS HttpClient default timeout is ~15 s — anything that pegs the loop
# longer than that produces the socket-timeout symptom in the SNS console.
# REMOVE after investigation: cheap (one async task), but adds 1 log/sec.
# ---------------------------------------------------------------------------
_HEARTBEAT_INTERVAL_S = 1.0
_heartbeat_task: "asyncio.Task | None" = None


async def _loop_heartbeat() -> None:  # pragma: no cover
    """Tick once per second. Log only when the loop was actually blocked.

    Using `monotonic` (not wall clock) so NTP jumps don't trigger false
    positives. We log every tick at debug to give a continuous baseline,
    plus an INFO line when the gap exceeds 2× the interval (the threshold
    at which AWS SNS retries start to overlap).
    """
    expected = time.monotonic() + _HEARTBEAT_INTERVAL_S
    while True:
        try:
            await asyncio.sleep(_HEARTBEAT_INTERVAL_S)
        except asyncio.CancelledError:
            return
        now = time.monotonic()
        gap_ms = (now - expected) * 1000.0
        if gap_ms > _HEARTBEAT_INTERVAL_S * 1000.0:
            # Stall longer than one full interval — call it out loudly.
            demisto.info(
                f"sns.loop.stall gap_ms={gap_ms:.0f} " f"(loop blocked > {_HEARTBEAT_INTERVAL_S}s; sync work on event loop)"
            )
        else:
            demisto.debug(f"sns.loop.heartbeat gap_ms={gap_ms:.1f}")
        expected = now + _HEARTBEAT_INTERVAL_S


@asynccontextmanager
async def _lifespan(_app: FastAPI):  # pragma: no cover
    """Install the SNS worker pool once after uvicorn starts the event loop."""
    global _heartbeat_task
    _install_default_executor()
    # Kick off the heartbeat once per process. Survives across requests; the
    # uvicorn shutdown path cancels it via the `finally` block below.
    try:
        _heartbeat_task = asyncio.create_task(_loop_heartbeat(), name="sns-heartbeat")
        demisto.debug("sns.loop.heartbeat.started")
    except Exception as e:
        demisto.error(f"sns.loop.heartbeat.start_failed err={e}")
    try:
        yield
    finally:
        if _heartbeat_task is not None:
            _heartbeat_task.cancel()
            _heartbeat_task = None
            demisto.debug("sns.loop.heartbeat.stopped")


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
basic_auth = HTTPBasic(auto_error=False)
token_auth = APIKeyHeader(auto_error=False, name="Authorization")

PROXIES, USE_SSL = handle_proxy_for_long_running()


_SNS_EXECUTOR: concurrent.futures.ThreadPoolExecutor | None = None
_executor_install_lock = threading.Lock()
_thread_local = threading.local()


def _install_default_executor() -> concurrent.futures.ThreadPoolExecutor:
    """Create the SNS worker pool and install it as the loop's default executor.

    Idempotent + thread-safe (double-checked locking).
    """
    global _SNS_EXECUTOR
    if _SNS_EXECUTOR is not None:
        return _SNS_EXECUTOR
    with _executor_install_lock:
        if _SNS_EXECUTOR is not None:
            return _SNS_EXECUTOR
        max_workers = min(32, (os.cpu_count() or 1) * 5)
        pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="sns-worker",
        )
        asyncio.get_running_loop().set_default_executor(pool)
        _SNS_EXECUTOR = pool
        # Log the local var — `pool._max_workers` is private CPython internals.
        demisto.debug(f"sns.executor.installed max_workers={max_workers}")
        return pool


def _get_thread_local_client() -> "AWS_SNS_CLIENT":
    """Return this worker thread's own AWS_SNS_CLIENT (one session per thread)."""
    cli = getattr(_thread_local, "client", None)
    if cli is None:
        cli = AWS_SNS_CLIENT()
        _thread_local.client = cli
    return cli


def _resolve_processing_mode(params: dict | None = None) -> str:
    """Resolve the configured processing mode (`concurrent` | `sequential`).

    Uses the supplied snapshot if any; otherwise reads `demisto.params()` live
    so UI changes take effect on the next POST. Defaults to `sequential`.
    """
    effective: dict
    if params is not None:
        effective = params
    else:
        try:
            effective = demisto.params() or {}
        except Exception as e:
            demisto.debug(f"sns.params.live_read_failed err={e}; using module snapshot")
            effective = PARAMS or {}
    raw = effective.get("processing_mode") or "sequential"
    mode = str(raw).strip().lower()
    if mode not in ("concurrent", "sequential"):
        mode = "sequential"
    return mode


# ---------------------------------------------------------------------------
# AWS SNS HTTP client
# ---------------------------------------------------------------------------


class AWS_SNS_CLIENT(BaseClient):  # pragma: no cover
    def __init__(self, base_url=None):
        if PROXIES:
            self.proxies = PROXIES
        elif PARAMS.get("proxy"):
            self.proxies = handle_proxy()
        headers = {"Accept": "application/json"}
        super().__init__(base_url=base_url, proxy=bool(PROXIES), verify=USE_SSL, headers=headers)

    def get(self, full_url, resp_type="json"):
        return self._http_request(method="GET", full_url=full_url, proxies=PROXIES, resp_type=resp_type)


# Back-compat only — internal paths use `_get_thread_local_client()`.
client = AWS_SNS_CLIENT()


def _validate_sns_url(url: str, field_name: str) -> None:
    """Validate that a URL points to a legitimate AWS SNS endpoint.

    Args:
        url: The URL to validate.
        field_name: Name of the field (for error messages).

    Raises:
        DemistoException: If the URL is not a valid AWS SNS endpoint.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DemistoException(f"{field_name} must use HTTPS, got: {parsed.scheme}")
    if not parsed.hostname or not re.fullmatch(r"sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?", parsed.hostname):
        raise DemistoException(f"{field_name} host not an AWS SNS endpoint: {parsed.hostname}")


class ServerConfig:  # pragma: no cover
    def __init__(self, certificate_path, private_key_path, log_config, ssl_args, access_log=True):
        self.certificate_path = certificate_path
        self.private_key_path = private_key_path
        self.log_config = log_config
        self.ssl_args = ssl_args
        self.access_log = access_log


class SNSCertificateManager:
    """Caches the AWS SNS signing certificate PEM text keyed by SigningCertURL.

    Concurrency: lock-free reads (atomic ref-read of `_cached` tuple), writes
    serialised under `_cache_lock`. X509/PKey re-parsed per verify because
    `EVP_MD_CTX` is mutated by verify_init/update/final and not thread-safe.
    """

    def __init__(self):
        # Atomic snapshot of (cert_url, cert_text) — single-ref read is atomic
        # in CPython so readers never observe a torn pair.
        self._cached: tuple[str, str] | None = None
        self.cached_cert_url: str | None = None
        self.cached_cert_text: str | None = None
        self._cache_lock = threading.Lock()

    def _commit_cache(self, cert_url: str, cert_text: str) -> None:
        """Atomically install (cert_url, cert_text) as the new cache entry."""
        with self._cache_lock:
            self._cached = (cert_url, cert_text)
            self.cached_cert_url = cert_url
            self.cached_cert_text = cert_text

    def _evict_if_url_matches(self, cert_url: str) -> None:
        """Evict only if the cache currently points at `cert_url`.

        Prevents a transient failure on URL B from poisoning a cached URL A.
        """
        with self._cache_lock:
            if self._cached and self._cached[0] == cert_url:
                self._cached = None
                self.cached_cert_url = None
                self.cached_cert_text = None

    def _load_cached_cert_text(self, sns_payload) -> str | None:
        """Return cached PEM text for `SigningCertURL`, or fetch + cache it.

        Returns None on fetch failure or non-AWS subject CN.
        """
        cert_url = sns_payload["SigningCertURL"]

        # Lock-free fast path: one atomic ref-read of `_cached`.
        cached = self._cached
        if cached and cached[0] == cert_url:
            demisto.debug("Using cached certificate for SigningCertURL")
            return cached[1]

        # Cache miss: fetch + parse + CN check WITHOUT holding the lock.
        try:
            _validate_sns_url(cert_url, "SigningCertURL")
            demisto.debug(f"sns_payload['SigningCertURL'] = {cert_url}")
            thread_client = _get_thread_local_client()
            response: requests.models.Response = thread_client.get(full_url=cert_url, resp_type="response")
            response.raise_for_status()
            cert_text = response.text
            certificate = X509.load_cert_string(cert_text)
        except DemistoException:
            raise
        except Exception as e:
            demisto.error(f"Exception validating sign cert url: {e}")
            if "502" in str(e):
                demisto.error("SigningCertURL: 502")
            elif "Verify that the server URL parameter" in str(e):
                demisto.error("client base url (fetched url)")
            elif "Proxy Error" in str(e):
                demisto.error(f"PROXIES = {PROXIES}")
            demisto.debug("SigningCertURL fetch failed. Clearing cached certificate.")
            self._evict_if_url_matches(cert_url)
            return None

        # Subject CN check — must NOT touch the cache (a bad-CN cert at a
        # different URL would otherwise evict a previously-cached good cert).
        subject_cn = ""
        try:
            subject_cn = certificate.get_subject().CN or ""
        except Exception:
            pass
        if "amazonaws.com" not in subject_cn.lower():
            demisto.error(f"Certificate subject CN not AWS: {subject_cn}")
            return None

        self._commit_cache(cert_url, cert_text)
        return cert_text

    def is_valid_sns_message(self, sns_payload):
        """Validate an incoming AWS SNS message signature.

        Args:
            sns_payload (dict): The SNS payload containing relevant fields.

        Returns:
            bool: True if the message is valid, False otherwise.
        """
        # taken from https://github.com/boto/boto3/issues/2508
        demisto.debug("In is_valid_sns_message")
        if sns_payload["Type"] not in ["SubscriptionConfirmation", "Notification", "UnsubscribeConfirmation"]:
            demisto.error("Not a valid SNS message")
            return False

        if sns_payload.get("SignatureVersion") not in ["1", "2"]:
            demisto.error("Not using the supported AWS-SNS SignatureVersion 1 or 2")
            return False
        demisto.debug(f'Handling Signature Version: {sns_payload.get("SignatureVersion")}')

        fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]
        if sns_payload["Type"] in ["SubscriptionConfirmation", "UnsubscribeConfirmation"]:
            fields = ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"]

        parts: list[str] = []
        for field in fields:
            value = sns_payload.get(field)
            if value is None:
                continue
            parts.append(f"{field}\n{value}\n")
        string_to_sign = "".join(parts)

        decoded_signature = base64.b64decode(sns_payload["Signature"])

        cert_text = self._load_cached_cert_text(sns_payload)
        if not cert_text:
            return False
        try:
            certificate = X509.load_cert_string(cert_text)
        except Exception as e:
            demisto.error(f"Failed re-parsing cached cert text: {e}")
            return False

        public_key = certificate.get_pubkey()
        if sns_payload["SignatureVersion"] == "1":
            public_key.reset_context(md="sha1")
        else:
            public_key.reset_context(md="sha256")

        public_key.verify_init()
        public_key.verify_update(string_to_sign.encode())
        verification_result = public_key.verify_final(decoded_signature)

        if verification_result != 1:
            demisto.debug("Signature verification failed. Clearing cached certificate.")
            self._evict_if_url_matches(sns_payload["SigningCertURL"])
            return False

        demisto.debug("Signature verification succeeded.")
        return True


sns_cert_manager = SNSCertificateManager()


def is_valid_integration_credentials(credentials, request_headers, token):
    credentials_param = PARAMS.get("credentials")
    auth_failed = False
    header_name = None
    if credentials_param and (username := credentials_param.get("identifier")):
        password = credentials_param.get("password", "")
        if username.startswith("_header"):
            header_name = username.split(":")[1]
            if not token or not compare_digest(token, password):
                auth_failed = True
        elif (not credentials) or (
            not (compare_digest(credentials.username, username) and compare_digest(credentials.password, password))
        ):
            auth_failed = True
        if auth_failed:
            secret_header = (header_name or "Authorization").lower()
            if secret_header in request_headers:
                request_headers[secret_header] = "***"
            demisto.debug(f"Authorization failed - request headers {request_headers}")
    if auth_failed:
        return False, header_name
    else:
        return True, header_name


def handle_subscription_confirmation(subscribe_url) -> requests.Response:  # pragma: no cover
    """Follow the SubscribeURL using THIS thread's own requests.Session."""
    demisto.debug("SubscriptionConfirmation request")
    _validate_sns_url(subscribe_url, "SubscribeURL")
    thread_client = _get_thread_local_client()
    response: requests.models.Response = thread_client.get(full_url=subscribe_url, resp_type="response")
    response.raise_for_status()
    return response


def handle_notification(payload, raw_json):
    message = payload["Message"]
    # `Subject` is optional in AWS SNS — fall back to a message-id-based name
    # so a missing Subject doesn't KeyError and `name` is never empty.
    message_id = payload.get("MessageId", "")
    demisto.debug(f"Notification request msg: {message_id}")
    subject = payload.get("Subject") or f"AWS-SNS Notification {message_id}"
    return {
        "name": subject,
        "labels": [],
        "rawJSON": raw_json,
        "occurred": payload["Timestamp"],
        "details": f'ExternalID:{message_id} TopicArn:{payload["TopicArn"]} Message:{message}',
        "type": "AWS-SNS Notification",
    }


def store_samples(incident):
    """Append `incident` to the persisted `sample_events` ring buffer (cap 20).

    Lock-serialised get/append/set RMW on integration context to avoid update loss.
    """
    with _sample_events_lock:
        try:
            integration_context = get_integration_context()
            sample_events = deque(
                json.loads(integration_context.get("sample_events", "[]")),
                maxlen=20,
            )
            sample_events.append(incident)
            integration_context["sample_events"] = list(sample_events)
            set_to_integration_context_with_retries(integration_context)
        except Exception as e:
            demisto.error(f"Failed storing sample events - {e}")


def _process_request_blocking(prep: dict) -> "Response | str":
    """Run the full per-request pipeline synchronously.

    `prep` carries the parsed payload, raw_json, type, a params snapshot, and
    the `req_id` for cross-thread log correlation. Same body for both modes —
    only the caller differs (inline vs `asyncio.to_thread(...)`).
    """
    payload = prep["payload"]
    type_ = prep["type"]
    params = prep.get("params") or PARAMS
    req_id = prep.get("req_id", "?")
    raw_json = prep.get("raw_json")
    if raw_json is None:
        t_dump = time.monotonic()
        raw_json = json.dumps(payload)
        dump_ms = (time.monotonic() - t_dump) * 1000.0
        demisto.info(
            f"sns.raw_json.built_in_worker req_id={req_id} thread={_thread_tag()} "
            f"dump_ms={dump_ms:.2f} payload_keys={len(payload) if isinstance(payload, dict) else 0}"
        )

    cur, peak = _inflight_enter()
    t_enter = time.monotonic()
    # DIAGNOSTIC (load-test ack-timeout investigation): `submit_ts` is stamped
    # by `handle_post` BEFORE `asyncio.to_thread` schedules us. `to_thread_wait_ms`
    # is the time this request spent QUEUED in the SNS worker pool before a
    # thread picked it up. Under burst:
    #   wait_ms < ~50  -> pool has free capacity; bottleneck is elsewhere
    #   wait_ms > 1000 -> pool saturated (Hypothesis B confirmed)
    # Emitted at INFO so it surfaces without Debug mode (Debug mode itself is
    # the other suspect; we don't want to require it to see this metric).
    submit_ts = prep.get("submit_ts")
    if submit_ts is not None:
        wait_ms = (t_enter - submit_ts) * 1000.0
    else:
        wait_ms = -1.0
    body_type = payload.get("Type") if isinstance(payload, dict) else None
    demisto.debug(
        f"sns.process.start req_id={req_id} thread={_thread_tag()} "
        f"hdr_type={type_} body_type={body_type!r} "
        f"inflight={cur} peak={peak} to_thread_wait_ms={wait_ms:.1f}"
    )

    try:
        # ---- Stage 1: signature verification ---------------------------
        t0 = time.monotonic()
        valid = sns_cert_manager.is_valid_sns_message(payload)
        verify_ms = (time.monotonic() - t0) * 1000.0
        demisto.debug(f"sns.verify.done req_id={req_id} thread={_thread_tag()} " f"valid={valid} took_ms={verify_ms:.1f}")
        if not valid:
            return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Validation of SNS message failed.")

        if type_ == "SubscriptionConfirmation":
            demisto.debug(f"sns.subscribe.start req_id={req_id} thread={_thread_tag()}")
            subscribe_url = payload["SubscribeURL"]
            t0 = time.monotonic()
            try:
                response = handle_subscription_confirmation(subscribe_url=subscribe_url)
            except Exception as e:
                status_code = getattr(getattr(e, "response", None), "status_code", None)
                demisto.error(f"sns.subscribe.failed req_id={req_id} " f"err_type={type(e).__name__} status_code={status_code}")
                # Return 503 (not a plain string, which FastAPI wraps as 200)
                # so SNS retries the SubscriptionConfirmation per its delivery
                # policy. A 200 here would make SNS think the subscription was
                # confirmed when it was not, silently breaking the topic.
                return Response(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content="Failed handling SubscriptionConfirmation",
                )
            subscribe_ms = (time.monotonic() - t0) * 1000.0
            demisto.debug(
                f"sns.subscribe.done req_id={req_id} thread={_thread_tag()} "
                f"status={getattr(response, 'status_code', '?')} took_ms={subscribe_ms:.1f}"
            )
            return Response(status_code=response.status_code)

        if type_ == "Notification":
            # ---- Stage 2: createIncidents (the expensive one) ----------
            incident = handle_notification(payload, raw_json)
            msg_id = payload.get("MessageId", "?")
            demisto.debug(f"sns.createIncident.start req_id={req_id} thread={_thread_tag()} " f"message_id={msg_id}")
            t0 = time.monotonic()
            data = demisto.createIncidents(incidents=[incident])
            create_ms = (time.monotonic() - t0) * 1000.0
            demisto.debug(
                f"sns.createIncident.done req_id={req_id} thread={_thread_tag()} " f"ok={bool(data)} took_ms={create_ms:.1f}"
            )

            if params.get("store_samples"):
                # Fire-and-forget to the single-thread background writer
                t0 = time.monotonic()
                _submit_store_samples(incident, req_id)
                submit_ms = (time.monotonic() - t0) * 1000.0
                demisto.debug(f"sns.store_samples.submitted req_id={req_id} thread={_thread_tag()} " f"submit_ms={submit_ms:.3f}")

            if not data:
                demisto.error(f"sns.createIncident.failed req_id={req_id} message_id={msg_id}")
                # Return 503 so SNS retries per its delivery policy. Returning
                # a plain string here causes FastAPI to wrap it in a 200, which
                # SNS treats as a successful delivery — silently dropping the
                # message.
                return Response(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content="Failed creating incident",
                )
            return data

        if type_ == "UnsubscribeConfirmation":
            message = payload["Message"]
            demisto.debug(f"sns.unsubscribe req_id={req_id} thread={_thread_tag()} msg={message}")
            return f"UnsubscribeConfirmation request msg: {message}"

        demisto.error(f"sns.unknown_type req_id={req_id} type={payload.get('Type')!r}")
        # Return 400 (client error) — an unknown `Type` is a malformed/unsupported
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=f'Failed handling AWS SNS request, unknown type: {payload["Type"]}',
        )
    finally:
        total_ms = (time.monotonic() - t_enter) * 1000.0
        remaining = _inflight_exit()
        demisto.debug(
            f"sns.process.end req_id={req_id} thread={_thread_tag()} " f"total_ms={total_ms:.1f} inflight_after={remaining}"
        )


async def _prepare_request(request: Request, credentials, token) -> "dict | Response":
    """Auth + parse the incoming request on the event-loop thread.

    Takes ONE `demisto.params()` snapshot per request (shared with the worker
    via `prep`) and mints a short `req_id` for cross-thread log correlation.
    For `_header:<name>` auth reads the header off `request.headers` directly
    instead of mutating the shared `token_auth` singleton (would race).
    """
    req_id = uuid.uuid4().hex[:8]
    t_start = time.monotonic()
    try:
        live_params = demisto.params() or {}
    except Exception as e:
        demisto.debug(f"sns.params.live_read_failed req_id={req_id} err={e}; using module snapshot")
        live_params = PARAMS or {}

    request_headers = dict(request.headers)

    credentials_param = live_params.get("credentials") or {}
    identifier = (credentials_param or {}).get("identifier") or ""
    if identifier.startswith("_header") and ":" in identifier:
        header_name = identifier.split(":", 1)[1]
        token = request_headers.get(header_name.lower()) or request_headers.get(header_name) or token

    is_valid_credentials = False
    header_name = None
    try:
        is_valid_credentials, header_name = is_valid_integration_credentials(credentials, request_headers, token)
    except Exception as e:
        demisto.error(f"sns.auth.error req_id={req_id} err={e}")
    if not is_valid_credentials:
        demisto.debug(
            f"sns.auth.rejected req_id={req_id} thread={_thread_tag()} " f"took_ms={(time.monotonic() - t_start) * 1000.0:.1f}"
        )
        return Response(status_code=status.HTTP_401_UNAUTHORIZED, content="Authorization failed.")

    secret_header = (header_name or "Authorization").lower()
    request_headers.pop(secret_header, None)

    try:
        type_ = request_headers["x-amz-sns-message-type"]
        body_bytes = await request.body()
        body_len = len(body_bytes)
        payload = json.loads(body_bytes)
    except Exception as e:
        demisto.error(f"sns.parse.error req_id={req_id} err={e}")
        return Response(status_code=status.HTTP_400_BAD_REQUEST, content="Failed parsing request.")

    prep_ms = (time.monotonic() - t_start) * 1000.0
    await asyncio.to_thread(
        demisto.debug,
        f"sns.prepare.done req_id={req_id} thread={_thread_tag()} type={type_} "
        f"message_id={payload.get('MessageId', '?')} body_len={body_len} "
        f"took_ms={prep_ms:.1f}",
    )
    return {
        "payload": payload,
        # NOTE: "raw_json" intentionally omitted — built in the worker by
        # `_process_request_blocking` to keep `json.dumps` off the event loop.
        "type": type_,
        "params": live_params,
        "req_id": req_id,
    }


@app.post(f'/{PARAMS.get("endpoint","")}')
async def handle_post(
    request: Request, credentials: HTTPBasicCredentials = Depends(basic_auth), token: APIKey = Depends(token_auth)
):
    """Handle incoming AWS-SNS POSTs (SubscriptionConfirmation / Notification / Unsubscribe).

    `processing_mode=concurrent`: runs on a worker thread (no head-of-line
    blocking). `sequential` (default): runs inline (byte-for-byte v1.0.15).
    """
    handler_t0 = time.monotonic()
    handler_thread = _thread_tag()
    demisto.debug(f"sns.handle_post.entry thread={handler_thread}")

    try:
        prep_or_response = await _prepare_request(request, credentials, token)
        if isinstance(prep_or_response, Response):
            status_code = getattr(prep_or_response, "status_code", "?")
            handler_ms = (time.monotonic() - handler_t0) * 1000.0
            demisto.info(
                f"sns.handle_post.exit thread={handler_thread} "
                f"outcome=early_response status={status_code} "
                f"total_ms={handler_ms:.1f}"
            )
            return prep_or_response
        prep = prep_or_response

        req_id = prep.get("req_id", "?")
        mode = _resolve_processing_mode(prep.get("params"))
        dispatch_t0 = time.monotonic()
        if mode == "sequential":
            result = _process_request_blocking(prep)
        else:
            _install_default_executor()
            prep["submit_ts"] = time.monotonic()
            pool_qsize = -1
            try:
                if _SNS_EXECUTOR is not None:
                    pool_qsize = _SNS_EXECUTOR._work_queue.qsize()  # type: ignore[attr-defined]
            except Exception:
                pool_qsize = -1
            with _inflight_lock:
                inflight_now = _inflight
                inflight_peak_now = _inflight_peak
            demisto.debug(
                f"sns.dispatch.submit req_id={req_id} thread={handler_thread} "
                f"inflight={inflight_now} peak={inflight_peak_now} "
                f"pool_qsize={pool_qsize}"
            )
            result = await asyncio.to_thread(_process_request_blocking, prep)
        dispatch_ms = (time.monotonic() - dispatch_t0) * 1000.0
        handler_ms = (time.monotonic() - handler_t0) * 1000.0
        demisto.info(
            f"sns.handle_post.exit req_id={req_id} thread={handler_thread} "
            f"mode={mode} dispatch_ms={dispatch_ms:.1f} total_ms={handler_ms:.1f}"
        )
        return result
    except Exception:
        handler_ms = (time.monotonic() - handler_t0) * 1000.0
        demisto.error(f"sns.handle_post.exception thread={handler_thread} " f"total_ms={handler_ms:.1f} tb={format_exc()}")
        raise


def unlink_certificate(certificate_path, private_key_path):  # pragma: no cover
    if certificate_path:
        os.unlink(certificate_path)
    if private_key_path:
        os.unlink(private_key_path)
    time.sleep(5)


def setup_server():  # pragma: no cover
    certificate = PARAMS.get("certificate", "")
    private_key = PARAMS.get("key", "")

    certificate_path = ""
    private_key_path = ""
    ssl_args = {}
    if certificate and private_key:
        certificate_file = NamedTemporaryFile(delete=False)
        certificate_path = certificate_file.name
        certificate_file.write(bytes(certificate, "utf-8"))
        certificate_file.close()
        ssl_args["ssl_certfile"] = certificate_path

        private_key_file = NamedTemporaryFile(delete=False)
        private_key_path = private_key_file.name
        private_key_file.write(bytes(private_key, "utf-8"))
        private_key_file.close()
        ssl_args["ssl_keyfile"] = private_key_path

        demisto.debug("Starting HTTPS Server")
    else:
        demisto.debug("Starting HTTP Server")

    integration_logger = IntegrationLogger()
    integration_logger.buffering = False
    log_config = dict(uvicorn.config.LOGGING_CONFIG)
    log_config["handlers"]["default"]["stream"] = integration_logger
    log_config["handlers"]["access"]["stream"] = integration_logger

    processing_mode = _resolve_processing_mode()
    access_log_enabled = processing_mode != "concurrent"
    demisto.debug(f"sns.setup_server.access_log mode={processing_mode} access_log={access_log_enabled}")

    return ServerConfig(
        log_config=log_config,
        ssl_args=ssl_args,
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        access_log=access_log_enabled,
    )


def test_module():  # pragma: no cover
    """Assigns a temporary port for longRunningPort and returns 'ok'."""
    if not PARAMS.get("longRunningPort"):
        PARAMS["longRunningPort"] = "1111"
    return "ok"


""" MAIN FUNCTION """


def main():  # pragma: no cover
    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        if demisto.command() == "test-module":
            return return_results(test_module())
        try:
            port = int(demisto.params().get("longRunningPort"))
        except ValueError as e:
            raise ValueError(f"Invalid listen port - {e}")
        if demisto.command() == "long-running-execution":
            demisto.debug("Started long-running-execution.")
            while True:
                server_config = setup_server()
                if not server_config:
                    raise DemistoException("Failed to configure server.")
                try:
                    uvicorn.run(
                        app,
                        host="0.0.0.0",
                        port=port,
                        log_config=server_config.log_config,  # type: ignore[arg-type]
                        access_log=server_config.access_log,
                        **server_config.ssl_args,
                    )
                except Exception as e:
                    demisto.error(f"An error occurred in the long running loop: {e!s} - {format_exc()}")
                    demisto.updateModuleHealth(f"An error occurred: {e!s}")
                finally:
                    unlink_certificate(server_config.certificate_path, server_config.private_key_path)
        else:
            raise NotImplementedError(f"Command {demisto.command()} is not implemented.")
    except Exception as e:
        demisto.error(format_exc())
        return_error(f"Failed to execute {demisto.command()} command. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
