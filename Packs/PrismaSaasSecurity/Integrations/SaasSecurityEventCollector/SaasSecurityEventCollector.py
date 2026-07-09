import demistomock as demisto
import urllib3
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from CommonServerUserPython import *  # noqa

from concurrent.futures import ThreadPoolExecutor, as_completed

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member

""" CONSTANTS """

VENDOR = "paloaltonetworks"
PRODUCT = "saassecurity"

# The SaaS Security /log_events_bulk endpoint returns at most 100 events per call,
# regardless of the requested 'size'. This is a hard server-side cap (verified against the API).
MAX_EVENTS_PER_REQUEST = 100
# Per-execution iteration cap. Each iteration pulls up to MAX_EVENTS_PER_REQUEST (100) events, so this is a
# high upper bound on how many events a single execution may drain (900 * 100 = 90,000). In practice a cycle is
# almost always stopped earlier by the wall-clock EXECUTION_TIME_BUDGET_SECONDS guard, NOT by this cap - the
# budget is the real limiter that keeps a cycle safely under the engine's ~5-minute hard timeout regardless of
# how high this value is. This cap is therefore mostly headroom: it lets a cycle keep draining a very large
# backlog for the full time budget instead of stopping at an artificially low iteration count. Combined with the
# nextTrigger mechanism (re-fires in 1 second while the queue is not drained), the collector sustains a drain
# rate well above the upstream production rate. Raised to 900 to keep draining a sustained high-volume backlog.
MAX_ITERATIONS = 900
# Hard code-level floor for the effective max iterations. An instance whose 'max_iterations' parameter was
# saved before this floor existed (e.g. the legacy default of 50) would otherwise permanently under-drain a
# high-volume queue. We take max(configured, MIN_MAX_ITERATIONS) so a stale/low instance value cannot cap
# throughput below what is needed to keep pace - without requiring the instance configuration to be edited.
MIN_MAX_ITERATIONS = 900
# Number of GET requests issued concurrently against the destructive-read queue within a single round.
# The /log_events_bulk endpoint is a pop-style queue (each GET dequeues and acks the next <=100 events
# server-side, with no cursor), so N concurrent GETs dequeue N distinct, non-overlapping batches. This is
# the primary throughput lever: it multiplies the drain rate by ~N versus the previous fully-serial loop,
# letting the collector keep pace with high upstream event rates. Bounded to keep connection/CPU use sane.
#
# IMPORTANT (thread safety): each worker thread MUST use its own Client instance / requests.Session. A single
# requests.Session (and the urllib3 connection pool behind it) is NOT thread-safe; sharing one across the
# concurrent GETs interleaves response bytes on shared sockets and produces intermittent, offset-varying JSON
# decode errors (e.g. "Expecting value: line 1 column 1", "Extra data", truncation at an 8 KB read boundary).
# See build_client / get_events_batch below.
DEFAULT_CONCURRENCY = 10
MAX_CONCURRENCY = 30
# Events are streamed to XSIAM in batches of this size as they are fetched (rather than buffering an entire
# execution in memory before a single push). This bounds memory use and makes ingestion incrementally durable.
# Kept modest so that, if a send ever fails, only a small chunk is left un-acknowledged and re-stashed - the
# stash shrinks every cycle and cannot get permanently wedged on one oversized batch.
SEND_BATCH_SIZE = 2000
MAX_LIMIT = 5000
DEFAULT_LIMIT = 1000
NEXT_TRIGGER_VALUE = "1"
# After this many consecutive fetch cycles where the queue is still not drained, emit a high-visibility
# warning so sustained backlog/lag is observable instead of silent.
BACKLOG_WARNING_THRESHOLD = 10
# Wall-clock budget for a single fetch-events execution. The XSIAM engine hard-kills an execution at ~5
# minutes (300s); if that happens mid-drain, the process is terminated BEFORE setIntegrationContext /
# setLastRun run, so progress (including the shrunk stash and nextTrigger) is not persisted. We stop issuing
# new drain rounds once this budget is exceeded and return cleanly, well under the engine timeout, so the
# collector always persists its state and immediately re-fires via nextTrigger to continue draining. This
# makes progress durable regardless of backlog size.
EXECUTION_TIME_BUDGET_SECONDS = 240
# Stable, machine-parseable prefix for the per-cycle ingestion metrics line. This line is emitted on every
# fetch cycle so ingestion completeness can be audited from the logs: 'sent' can be summed over a time window
# and reconciled against the dataset row count, and 'queue_drained=True' is the positive "the collector has
# caught up (no events currently waiting upstream)" signal.
METRICS_LOG_PREFIX = "SaaSSecurityIngestionMetrics"
# When True, a send that fails ONLY because XSIAM returned a 200 with an empty/blank body (no JSON ack
# to parse) is treated as accepted: the events were delivered over the wire, the platform simply did not
# return the expected JSON acknowledgement. This lets the collector keep draining instead of re-stashing
# and looping forever on a known server-side quirk, while the platform team fixes the empty-body response.
# It is deliberately scoped to the blank-body case only - a truncated or non-empty unparseable body is a
# real failure and is still raised, stashed, and retried. Toggleable via the instance param below.
PASS_OVER_EMPTY_XSIAM_RESPONSE_DEFAULT = True

""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls to the Saas Security platform, and does not contain any XSOAR logic.
    Handles the token retrieval.

    Note: an instance of this class wraps a single requests.Session and is therefore NOT safe to share across
    threads. For the concurrent fetch path, build one Client per worker thread via ``build_client``.

    :param base_url (str): Saas Security server url.
    :param client_id (str): client ID.
    :param client_secret (str): client secret.
    :param verify (bool): specifies whether to verify the SSL certificate or not.
    :param proxy (bool): specifies if to use XSOAR proxy settings.
    """

    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool, proxy: bool, **kwargs):
        self.client_id = client_id
        self.client_secret = client_secret

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, **kwargs)

    def http_request(self, *args, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.
        """
        token = self.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        return super()._http_request(*args, headers=headers, **kwargs)  # type: ignore[misc]

    def get_access_token(self) -> str:
        """
        Obtains access and refresh token from server.
        Access token is used and stored in the integration context until expiration time.
        After expiration, new refresh token and access token are obtained and stored in the
        integration context.

         Returns:
             str: the access token.
        """
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        token_initiate_time = integration_context.get("token_initiate_time")
        token_expiration_seconds = integration_context.get("token_expiration_seconds")

        if access_token and not is_token_expired(
            token_initiate_time=float(token_initiate_time), token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token

        # there's no token or it is expired
        access_token, token_expiration_seconds = self.get_token_request()
        integration_context = {
            "access_token": access_token,
            "token_expiration_seconds": token_expiration_seconds,
            "token_initiate_time": time.time(),
        }
        demisto.debug(f"updating access token - {integration_context}")
        set_integration_context(context=integration_context)

        return access_token

    def get_token_request(self) -> tuple[str, str]:
        """
         Sends request to retrieve token.

        Returns:
            tuple[str, str]: token and its expiration date
        """
        base64_encoded_creds = b64_encode(f"{self.client_id}:{self.client_secret}")
        headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded; charset=ISO-8859-1",
            "Authorization": f"Basic {base64_encoded_creds}",
        }
        data = {
            "grant_type": "client_credentials",
            "scope": "api_access",
        }
        token_response = self._http_request("POST", url_suffix="/oauth/token", data=data, headers=headers)
        return token_response.get("access_token"), token_response.get("expires_in")

    def get_events_request(self, size: int = MAX_EVENTS_PER_REQUEST):
        """
        Get a single batch of event logs from the SaaS Security queue.

        Note: the endpoint returns at most ``MAX_EVENTS_PER_REQUEST`` (100) events per call,
        regardless of the requested ``size``. A 204 status code means the queue is currently empty.
        """
        return self.http_request(
            "GET", url_suffix="/api/v1/log_events_bulk", resp_type="response", ok_codes=[200, 204], params={"size": size}
        )


def is_token_expired(token_initiate_time: float, token_expiration_seconds: float) -> bool:
    """
    Check whether a token has expired. a token considered expired if it has been reached to its expiration date in
    seconds minus a minute.

    for example ---> time.time() = 300, token_initiate_time = 240, token_expiration_seconds = 120

    300.0001 - 240 < 120 - 60

    Args:
        token_initiate_time (float): the time in which the token was initiated in seconds.
        token_expiration_seconds (float): the time in which the token should be expired in seconds.

    Returns:
        bool: True if token has expired, False if not.
    """
    return time.time() - token_initiate_time >= token_expiration_seconds - 60


def get_max_fetch(limit: Optional[int]) -> int:
    """
    Validate and get the max fetch accodring to the following rules:

    1. if limit is negative raise an exception
    2. if limit is less than 10, limit will be equal to 10
    3. if limit is not dividable by 10, make sure it gets rounded down to a number that is dividable by 10.
    4. if limit > MAX_LIMIT (5000) - make sure it will always be MAX_LIMIT (5000).
    5. if limit is not provided, set it up for the default limit which is 1000.
    """
    if limit:
        if limit <= 0:
            raise DemistoException("fetch limit parameter cannot be negative number or zero")
        if limit < 10:
            limit = 10
        if limit > MAX_LIMIT:  # do not allow limit of more than 5000 to avoid timeouts
            limit = MAX_LIMIT
        if limit % 10 != 0:  # max limit must be a multiplier of 10 (SaaS api limit)
            # round down the limit
            limit = int(limit // 10) * 10
    else:
        limit = DEFAULT_LIMIT

    return limit


def get_max_iterations(configured: Optional[int]) -> int:
    """
    Resolve the effective per-execution iteration cap.

    We take ``max(configured, MIN_MAX_ITERATIONS)`` so that an instance whose ``max_iterations`` parameter was
    saved with a low legacy value (e.g. 50) cannot permanently under-drain a high-volume queue. This lets the
    fix take effect without requiring the (possibly inaccessible) instance configuration to be edited.
    """
    if not configured or configured <= 0:
        return MAX_ITERATIONS
    return max(configured, MIN_MAX_ITERATIONS)


def get_concurrency(concurrency: Optional[int]) -> int:
    """
    Validate and clamp the number of concurrent GET calls issued per fetch round.

    - Falls back to ``DEFAULT_CONCURRENCY`` when not provided or non-positive.
    - Clamps to ``MAX_CONCURRENCY`` to keep connection/CPU use bounded.
    """
    if not concurrency or concurrency <= 0:
        return DEFAULT_CONCURRENCY
    return min(concurrency, MAX_CONCURRENCY)


def events_integrity_fingerprint(events: list) -> str:
    """
    Build a compact, structural fingerprint of an events list for diagnostics at the integration-context
    boundary. It does NOT log event contents (PII/volume), only shape + a serialization health check.

    This exists to rule out a specific hypothesis: that events become malformed while being round-tripped
    through the integration context (setIntegrationContext -> getIntegrationContext). If the events restored
    from context are already not a clean list[dict], or no longer JSON-serializable, this line will show it -
    letting us distinguish "context corrupted the payload" from "the SaaS/XSIAM HTTP response was corrupted".

    The fingerprint reports:
      - count and container type,
      - whether every element is a dict (all_dicts),
      - the type of the first and last element,
      - whether the whole list re-serializes cleanly via json.dumps (json_serializable) and its byte length,
      - or the serialization error if it does not.
    """
    count = len(events)
    all_dicts = all(isinstance(e, dict) for e in events)
    first_type = type(events[0]).__name__ if events else "n/a"
    last_type = type(events[-1]).__name__ if events else "n/a"
    try:
        serialized = json.dumps(events)
        serial_info = f"json_serializable=true serialized_bytes={len(serialized)}"
    except Exception as exc:  # pragma: no cover - defensive; exercised via unit test with a non-serializable input
        serial_info = f"json_serializable=false serialize_error={exc}"
    return (
        f"count={count} container={type(events).__name__} all_dicts={all_dicts} "
        f"first_type={first_type} last_type={last_type} {serial_info}"
    )


def describe_xsiam_response_failure(exc: Exception) -> tuple[str, bool]:
    """
    Capture and describe the ACTUAL response body that XSIAM returned on a failed
    ``send_events_to_xsiam`` call, so we can see what the platform is really sending back.

    Why this works without touching CommonServerPython internals: the send path in
    ``send_data_to_xsiam`` calls ``response.json()`` on the raw ``requests.Response``. When the
    body is empty/blank/truncated, that raises ``json.JSONDecodeError`` (a subclass of
    ``ValueError``) whose ``.doc`` attribute is *the exact raw response text that failed to parse*
    and whose ``.pos`` is the byte offset. That is precisely the XSIAM response body we want to
    inspect, surfaced to us for free on the exception object.

    Returns:
        tuple[str, bool]:
            - a diagnostic string describing the response (status is not on the exception, but the
              body, its length, and a bounded repr-safe prefix are), and
            - ``benign_empty_body``: True when the response body is empty or whitespace-only. This is
              the "acknowledged-with-no-JSON-ack" case that the platform team can fix server-side, and
              which we may choose to pass over rather than re-stash and loop.
    """
    doc = getattr(exc, "doc", None)
    pos = getattr(exc, "pos", None)
    if doc is None:
        # Not a JSONDecodeError (e.g. a DemistoException / network error) - no response body to show.
        return f"response_body=<unavailable> exc_type={type(exc).__name__} exc={exc}", False

    body_len = len(doc)
    stripped = doc.strip()
    benign_empty_body = stripped == ""
    # Bounded, repr-safe prefix so control chars / newlines are visible and the log line stays small.
    preview = repr(doc[:200])
    return (
        f"response_body_len={body_len} decode_error_pos={pos} "
        f"body_is_blank={str(benign_empty_body).lower()} response_body_preview={preview}",
        benign_empty_body,
    )


def build_client(params: dict) -> Client:
    """
    Construct a fresh ``Client`` (and therefore a fresh requests.Session / connection pool).

    Each concurrent worker thread MUST call this to obtain its OWN client; sharing a single Client across
    threads is not safe (see the DEFAULT_CONCURRENCY note) and corrupts responses under load. The cached
    OAuth token is shared safely via the integration context, so per-thread clients do not trigger re-auth.
    """
    return Client(
        base_url=params.get("url", "").rstrip("/"),
        client_id=params.get("credentials", {}).get("identifier", ""),
        client_secret=params.get("credentials", {}).get("password", ""),
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
    )


""" COMMAND FUNCTIONS """


def test_module(client: Client):
    """
    Testing we have a valid connection to Saas-Security.
    """
    # if 401 will be raised, that means that the credentials are invalid an exception will be raised.
    client.get_token_request()
    return "ok"


def get_events_command(
    client: Client,
    args: dict,
    max_fetch: Optional[int],
    vendor: str = VENDOR,
    product: str = PRODUCT,
    max_iterations: int = MAX_ITERATIONS,
) -> Union[str, CommandResults]:
    """
    Fetches events from the saas-security queue and return them to the war-room.
    in case should_push_events is set to True, they will be also sent to XSIAM.
    """
    should_push_events = argToBoolean(args.get("should_push_events"))
    events, exception, _ = fetch_events_from_saas_security(client=client, max_fetch=max_fetch, max_iterations=max_iterations)
    if exception:
        raise exception

    if events:
        if should_push_events:
            try:
                send_events_to_xsiam(events=events, vendor=vendor, product=product)
            except Exception as e:
                demisto.setLastRun({"events": events})
                raise e
        return CommandResults(
            readable_output=tableToMarkdown(
                "SaaS Security Logs",
                events,
                headers=["log_type", "item_type", "item_name", "timestamp", "serial"],
                headerTransform=underscoreToCamelCase,
                removeNull=True,
            ),
            raw_response=events,
            outputs=events,
            outputs_key_field=["timestamp", "log_type", "item_name", "item_type"],
            outputs_prefix="SaasSecurity.Event",
        )
    return "No events were found."


def get_events_batch(client: Client) -> tuple[list[dict], bool]:
    """
    Perform a single GET against the destructive-read queue and return its outcome.

    ``client`` must not be shared with any other thread (it wraps a single, non-thread-safe requests.Session).

    Returns:
        tuple[list[dict], bool]: (events, drained) where ``drained`` is True when the server returned
        204 (the queue is currently empty). A 200 with an empty ``events`` list is also treated as
        drained, defensively.
    """
    response = client.get_events_request()
    if response.status_code == 204:
        return [], True
    fetched_events = response.json().get("events") or []
    # An empty 200 response should not happen per the API contract, but treat it as drained to avoid
    # spinning on the queue if it ever does.
    return fetched_events, len(fetched_events) == 0


def fetch_events_from_saas_security(
    client: Client, max_fetch: Optional[int] = None, max_iterations: int = MAX_ITERATIONS
) -> tuple[list[dict], Exception | None, bool]:
    """
    Serially fetch a single execution's worth of events from the SaaS Security queue.

    This serial path is retained for the manual ``saas-security-get-events`` command, where a bounded,
    deterministic, single-threaded drain is preferable. The scheduled ``fetch-events`` path uses the
    concurrent, streamed drain in :func:`fetch_and_send_events_concurrently` for throughput.

    Returns:
        tuple: (events, exception, queue_drained) - queue_drained is True if got 204 (no more events in queue).
    """
    events: list[dict] = []
    under_max_fetch = True
    queue_drained = False

    #  if max fetch is None, all events will be fetched until there aren't anymore in the queue (until we get 204)
    try:
        iteration_num = 1  # this is done in order to prevent timeouts
        while under_max_fetch and iteration_num < max_iterations + 1:
            fetched_events, drained = get_events_batch(client)
            if drained:  # queue is empty, stop.
                queue_drained = True
                break
            demisto.debug(f"fetched events length: ({len(fetched_events)}) in iteration {iteration_num}")
            events.extend(fetched_events)
            events_len = len(events)
            if max_fetch:
                under_max_fetch = events_len < max_fetch
            iteration_num += 1
        demisto.info(
            f"Finished fetch iteration loop: collected {len(events)} events over {iteration_num - 1} iteration(s), "
            f"queue_drained={queue_drained} (max_iterations={max_iterations}, max_fetch={max_fetch})."
        )
    except Exception as exc:
        demisto.info(f"Got error get_events: {exc}")
        return events, exc, True

    return events, None, queue_drained


def send_events_in_chunks(
    events: list[dict],
    send_batch_size: int,
    vendor: str,
    product: str,
    pass_over_empty_response: bool = PASS_OVER_EMPTY_XSIAM_RESPONSE_DEFAULT,
) -> int:
    """
    Send ``events`` to XSIAM in fixed-size chunks, removing each chunk from the list only after it has been
    acknowledged. On the first failing chunk the exception is raised, leaving ``events`` holding exactly the
    not-yet-sent remainder (the list is mutated in place).

    This is what lets a poisoned/oversized stash self-heal: every cycle the successfully-sent chunks are
    removed and only the shrinking remainder is re-stashed, instead of re-stashing the whole batch and
    retrying it forever.

    Response capture: on a send failure we log the ACTUAL response body XSIAM returned (surfaced via the
    JSONDecodeError from ``response.json()``; see ``describe_xsiam_response_failure``). This is what lets us
    see, from the logs, exactly what the platform sent back.

    Pass-over of a benign empty body: when ``pass_over_empty_response`` is True and the failure is only that
    XSIAM returned a 200 with an empty/blank body (no JSON ack to parse), the chunk is treated as delivered:
    the events already went over the wire, the platform merely omitted the JSON acknowledgement. We remove
    the chunk and keep going instead of re-stashing and looping forever on a known server-side quirk. Any
    other failure (truncated or non-empty unparseable body, network error, DemistoException) is re-raised so
    the existing stash-and-retry path handles it and no events are lost.

    Returns:
        int: the number of events successfully sent (including any passed-over benign-empty-body chunks).
    """
    sent = 0
    while events:
        chunk = events[:send_batch_size]
        try:
            send_events_to_xsiam(events=chunk, vendor=vendor, product=product)
        except Exception as exc:
            description, benign_empty_body = describe_xsiam_response_failure(exc)
            if pass_over_empty_response and benign_empty_body:
                demisto.error(
                    f"XSIAM returned an empty/blank body (no JSON ack) for a chunk of {len(chunk)} events; "
                    f"treating it as delivered and continuing (pass-over of known server-side empty-body "
                    f"response). xsiam_response: {description}"
                )
                sent += len(chunk)
                del events[: len(chunk)]
                continue
            # Non-benign failure: log the captured response for diagnosis, then re-raise so the caller
            # stashes the not-yet-sent remainder (still in ``events``) and retries next cycle.
            demisto.error(f"Send to XSIAM failed for a chunk of {len(chunk)} events. xsiam_response: {description}")
            raise
        sent += len(chunk)
        del events[: len(chunk)]
    return sent


def fetch_and_send_events_concurrently(
    params: dict,
    max_iterations: int = MAX_ITERATIONS,
    concurrency: int = DEFAULT_CONCURRENCY,
    send_batch_size: int = SEND_BATCH_SIZE,
    vendor: str = VENDOR,
    product: str = PRODUCT,
    pending_events: Optional[list[dict]] = None,
    time_budget_seconds: int = EXECUTION_TIME_BUDGET_SECONDS,
    pass_over_empty_response: bool = PASS_OVER_EMPTY_XSIAM_RESPONSE_DEFAULT,
) -> tuple[int, int, bool, list[dict], Exception | None]:
    """
    High-throughput scheduled-fetch drain: issues ``concurrency`` GET calls per round against the
    destructive-read queue and streams the results to XSIAM in batches as they arrive.

    Thread safety: each concurrent GET runs on its own ``Client`` (own requests.Session), built via
    ``build_client``. Sharing one Client/session across threads corrupts responses (interleaved socket
    reads -> JSON decode errors), so a client is created per worker submission.

    Why concurrency is safe against the queue: ``/log_events_bulk`` is a pop-style queue - each GET dequeues
    and acks the next <=100 events server-side (no cursor/offset). Therefore N concurrent GETs return N
    distinct, non-overlapping batches.

    Durability model (no data loss on a destructive-read queue):
      * ``pending_events`` (events previously popped but not yet sent) are flushed first, in chunks, so a
        prior failure self-heals: only the un-sent remainder is ever carried forward.
      * Newly fetched events are buffered and flushed every ``send_batch_size`` events.
      * If a send fails, everything not yet acknowledged into XSIAM is returned so the caller can stash it.

    Returns:
        tuple[int, int, bool, list[dict], Exception | None]:
            (fetched_count, sent_count, queue_drained, unsent_events, exception)
    """
    buffer: list[dict] = list(pending_events or [])
    fetched_count = len(buffer)
    sent_count = 0
    calls_made = 0
    queue_drained = False
    budget_exceeded = False
    deadline = time.time() + time_budget_seconds

    def flush(force: bool) -> None:
        """Send full ``send_batch_size`` chunks from the buffer (or everything, when ``force``)."""
        nonlocal sent_count
        if force:
            sent_count += send_events_in_chunks(
                buffer, send_batch_size, vendor, product, pass_over_empty_response=pass_over_empty_response
            )
        else:
            while len(buffer) >= send_batch_size:
                sent_count += send_events_in_chunks(
                    buffer[:send_batch_size], send_batch_size, vendor, product,
                    pass_over_empty_response=pass_over_empty_response,
                )
                del buffer[:send_batch_size]

    try:
        # Flush any events restored from a previous failed execution before pulling new ones. This is the
        # self-heal path for a poisoned integration context: it drains the stash in small chunks.
        flush(force=True)

        while calls_made < max_iterations and not queue_drained:
            # Stop starting new rounds once the wall-clock budget is exceeded, so we return and persist
            # state well before the engine's ~5-minute hard kill. queue_drained stays False so the caller
            # re-fires immediately via nextTrigger and continues draining on the next execution.
            if time.time() >= deadline:
                budget_exceeded = True
                break
            workers = min(concurrency, max_iterations - calls_made)
            calls_made += workers
            with ThreadPoolExecutor(max_workers=workers) as executor:
                # Each task gets its OWN client (own session) - required for thread safety.
                futures = [executor.submit(get_events_batch, build_client(params)) for _ in range(workers)]
                for future in as_completed(futures):
                    batch_events, drained = future.result()
                    # Keep events even from a round that also observed a 204: those batches were already
                    # popped off the server queue, so discarding them would lose data.
                    buffer.extend(batch_events)
                    fetched_count += len(batch_events)
                    if drained:
                        queue_drained = True
            flush(force=False)

        # Final flush of whatever remains once the queue is drained or the budget is exhausted.
        flush(force=True)
        if budget_exceeded:
            demisto.info(
                f"Stopped concurrent fetch early: execution time budget ({time_budget_seconds}s) reached before "
                f"the queue drained. Persisting progress and re-firing to continue. "
                f"fetched={fetched_count} sent={sent_count} calls_made={calls_made}."
            )
        demisto.info(
            f"Finished concurrent fetch: fetched={fetched_count} sent={sent_count} "
            f"queue_drained={queue_drained} budget_exceeded={budget_exceeded} "
            f"(max_iterations={max_iterations}, concurrency={concurrency}, calls_made={calls_made})."
        )
    except Exception as exc:
        demisto.info(f"Got error during concurrent fetch/send: {exc}")
        # buffer holds everything popped from the queue but not yet acknowledged into XSIAM; the caller
        # persists it so no events are lost on a destructive-read queue.
        return fetched_count, sent_count, queue_drained, buffer, exc

    return fetched_count, sent_count, queue_drained, buffer, None


def main() -> None:  # pragma: no cover
    support_multithreading()
    params = demisto.params()
    args = demisto.args()

    max_fetch = get_max_fetch(arg_to_number(args.get("limit") or params.get("max_fetch")))
    max_iterations = get_max_iterations(arg_to_number(params.get("max_iterations")))
    concurrency = get_concurrency(arg_to_number(params.get("event_fetch_concurrency")))
    pass_over_empty_response = argToBoolean(
        params.get("event_pass_over_empty_response", PASS_OVER_EMPTY_XSIAM_RESPONSE_DEFAULT)
    )
    # The concurrent drain issues GET calls from worker threads, and each worker's client may touch the
    # XSOAR/XSIAM server via the demisto object (e.g. reading/writing the cached OAuth token in the
    # integration context). support_multithreading() serializes those server calls with a lock so
    # concurrent threads cannot corrupt the demisto <-> server channel. This does NOT affect the outbound
    # SaaS/XSIAM HTTP sessions (those are made thread-safe by giving each worker its own Client).
    support_multithreading()

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    try:
        client = build_client(params)
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            integration_context = demisto.getIntegrationContext()
            from_context = bool(integration_context.get("events"))
            # Events popped in a previous execution but not yet acknowledged into XSIAM are restored and
            # flushed first, so a prior push failure never loses data on this destructive-read queue.
            pending_events = integration_context.get("events") or []
            if from_context:
                # Log the STRUCTURE (not contents) of what we restored from context. If the payload was
                # corrupted while round-tripping through the integration context, this fingerprint will not
                # match the one logged when it was stashed - letting us rule the context in or out as the
                # source of the malformed-JSON send failures.
                demisto.info(
                    f"Restoring pending events from integration context before fetching. "
                    f"restored_integrity: {events_integrity_fingerprint(pending_events)}"
                )

            fetched_count, sent_count, queue_drained, unsent_events, exception = fetch_and_send_events_concurrently(
                params=params,
                max_iterations=max_iterations,
                concurrency=concurrency,
                pending_events=pending_events,
                pass_over_empty_response=pass_over_empty_response,
            )

            if unsent_events:
                # A send failed mid-drain: persist everything not yet acknowledged into XSIAM so it is
                # retried on the next execution, and force an immediate retry via nextTrigger. Because sends
                # are chunked and the sent chunks were removed, this stash is strictly smaller than before.
                # Log the STRUCTURE of what we are about to persist to context. Comparing this fingerprint
                # with the 'restored_integrity' line on the next cycle proves whether the integration context
                # round-trip is preserving the payload or malforming it.
                # Also capture the ACTUAL response body XSIAM returned for this failure, so the log shows
                # exactly what the platform sent back (empty/blank/truncated body vs. real error).
                xsiam_response = describe_xsiam_response_failure(exception)[0] if exception else "response_body=<none>"
                demisto.error(
                    f"Received error when sending events to XSIAM; stashing {len(unsent_events)} unsent events. "
                    f"[{exception}] stashed_integrity: {events_integrity_fingerprint(unsent_events)} "
                    f"xsiam_response: {xsiam_response}"
                )
                demisto.setIntegrationContext({"events": unsent_events})
                queue_drained = False
            else:
                demisto.setIntegrationContext({})
                if exception:
                    demisto.info(f"got exception during fetch (all fetched events were sent): [{exception}]")

            # If the queue has not been fully drained (backlog remaining, or a stash to retry), trigger the
            # next fetch in 1 second so the collector keeps draining back-to-back instead of waiting the full
            # fetch interval.
            if not queue_drained:
                last_run["nextTrigger"] = NEXT_TRIGGER_VALUE
                # Track how many consecutive cycles the queue has not drained, so sustained backlog
                # (= growing ingestion lag) is observable instead of failing silently.
                consecutive_backlog_cycles = int(last_run.get("consecutive_backlog_cycles", 0)) + 1
                last_run["consecutive_backlog_cycles"] = consecutive_backlog_cycles
                if consecutive_backlog_cycles >= BACKLOG_WARNING_THRESHOLD:
                    demisto.error(
                        f"SaaS Security ingestion backlog: the event queue has not fully drained for "
                        f"{consecutive_backlog_cycles} consecutive fetch cycles. The upstream event rate may "
                        f"exceed the collector throughput, which can cause ingestion lag. Consider increasing "
                        f"'The maximum number of iterations to retrieve events' or distributing the load across "
                        f"multiple instances."
                    )
                else:
                    demisto.debug("Batching in progress. Next run will be triggered in 1 second.")
            else:
                consecutive_backlog_cycles = 0
                last_run.pop("nextTrigger", None)
                last_run.pop("consecutive_backlog_cycles", None)
                demisto.debug("All events finished batching. Next run will be triggered based on fetch interval.")

            # Emit a single, machine-parseable ingestion-metrics line per cycle. This is the completeness
            # audit record: 'sent' can be summed over a time window and reconciled against the dataset row
            # count for the same window, and 'queue_drained=true' is the positive signal that the collector
            # has caught up (no events currently waiting in the SaaS Security queue).
            demisto.info(
                f"{METRICS_LOG_PREFIX} fetched={fetched_count} sent={sent_count} "
                f"queue_drained={str(queue_drained).lower()} from_context={str(from_context).lower()} "
                f"max_iterations={max_iterations} consecutive_backlog_cycles={consecutive_backlog_cycles}"
            )
            demisto.setLastRun(last_run)
        elif command == "saas-security-get-events":
            return_results(get_events_command(client, args, max_fetch=max_fetch, max_iterations=max_iterations))
        else:
            raise NotImplementedError(f"Command {command} is not implemented in saas-security integration.")
    except Exception as e:
        return_error(f"Failed to execute {command} command. Error in Palo Alto Saas Security Event Collector Integration [{e}].")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
