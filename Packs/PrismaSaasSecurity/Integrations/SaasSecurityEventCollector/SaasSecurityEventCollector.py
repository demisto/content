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

# The /log_events_bulk endpoint returns at most 100 events per GET, regardless of the requested 'size'
# (hard server-side cap). Throughput therefore comes only from issuing many GETs.
MAX_EVENTS_PER_REQUEST = 100

# Max GET calls per execution. At 100 events/call this is a high upper bound (900 * 100 = 90,000 events),
# but in practice EXECUTION_TIME_BUDGET_SECONDS stops a cycle first. MIN_MAX_ITERATIONS is a code-level floor
# so an instance saved with a low legacy value (e.g. 50) cannot cap throughput without editing its config.
MAX_ITERATIONS = 900
MIN_MAX_ITERATIONS = 900

# Number of GETs issued concurrently per round. /log_events_bulk is a pop-style queue (each GET dequeues the
# next <=100 events server-side, no cursor), so N concurrent GETs return N distinct, non-overlapping batches.
# This is the main throughput lever. Each worker MUST use its own Client/requests.Session: a Session is not
# thread-safe, and sharing one across threads interleaves response bytes and corrupts the JSON (see build_client).
DEFAULT_CONCURRENCY = 10
MAX_CONCURRENCY = 30

# Events are streamed to XSIAM in batches of this size as they are fetched, so memory stays bounded and a
# failed send leaves only a small un-acked chunk to re-stash (the stash shrinks each cycle, never wedges).
SEND_BATCH_SIZE = 2000

MAX_LIMIT = 5000
DEFAULT_LIMIT = 1000
NEXT_TRIGGER_VALUE = "1"

# Emit a high-visibility warning after this many consecutive cycles where the queue never drained, so a
# sustained backlog (growing lag) is observable instead of silent. Once past the threshold, re-emit only
# every BACKLOG_WARNING_INTERVAL cycles so a long-running backlog does not flood the logs.
BACKLOG_WARNING_THRESHOLD = 10
BACKLOG_WARNING_INTERVAL = 10

# Wall-clock budget for one fetch-events execution. The engine hard-kills an execution at ~5 minutes; if that
# happens mid-drain, state is not persisted. We stop starting new rounds past this budget and return cleanly
# (well under the timeout), so progress is always persisted and re-fired via nextTrigger.
EXECUTION_TIME_BUDGET_SECONDS = 240

# Prefix for the per-cycle ingestion metrics log line. 'sent' can be summed over a window and reconciled
# against the dataset row count; 'queue_drained=True' means the collector has caught up.
METRICS_LOG_PREFIX = "SaaSSecurityIngestionMetrics"

# When True, a send that fails ONLY because XSIAM returned a 200 with an empty/blank body (no JSON ack) is
# treated as delivered: the events went over the wire, the platform just omitted the ack. Scoped to the blank
# -body case only; a truncated/non-empty unparseable body is still raised, stashed, and retried.
PASS_OVER_EMPTY_XSIAM_RESPONSE_DEFAULT = True

""" CLIENT CLASS """


class Client(BaseClient):
    """API client for the SaaS Security platform (token handling + event fetch).

    Wraps a single requests.Session, so a Client instance is NOT thread-safe. In the concurrent fetch path,
    build one Client per worker thread via ``build_client``.
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
        """Return a valid access token, caching it in the integration context until it expires."""
        integration_context = get_integration_context()
        access_token = integration_context.get("access_token")
        token_initiate_time = integration_context.get("token_initiate_time")
        token_expiration_seconds = integration_context.get("token_expiration_seconds")

        if access_token and not is_token_expired(
            token_initiate_time=float(token_initiate_time), token_expiration_seconds=float(token_expiration_seconds)
        ):
            return access_token

        # No token yet, or it expired: request a new one.
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
        """Request a new token from the server. Returns (access_token, expires_in_seconds)."""
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
    """Return True if the token is within 60 seconds of its expiry (refresh a minute early to be safe)."""
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
    """Resolve the per-execution iteration cap, floored at MIN_MAX_ITERATIONS so a low legacy instance value
    (e.g. 50) can't under-drain the queue without editing the instance config."""
    if not configured or configured <= 0:
        return MAX_ITERATIONS
    return max(configured, MIN_MAX_ITERATIONS)


def get_concurrency(concurrency: Optional[int]) -> int:
    """Resolve the per-round concurrency: default when unset/non-positive, clamped to MAX_CONCURRENCY."""
    if not concurrency or concurrency <= 0:
        return DEFAULT_CONCURRENCY
    return min(concurrency, MAX_CONCURRENCY)


def describe_xsiam_response_failure(exc: Exception) -> tuple[str, bool]:
    """Describe the XSIAM response body behind a failed send, for logging.

    When ``send_data_to_xsiam`` calls ``response.json()`` on a bad body it raises ``json.JSONDecodeError``,
    whose ``.doc`` holds the raw response text and ``.pos`` the byte offset - so we can inspect what the
    platform actually returned.

    Returns (description, benign_empty_body), where ``benign_empty_body`` is True when the body is empty or
    whitespace-only (the "delivered but no JSON ack" case we may pass over instead of re-stashing).
    """
    doc = getattr(exc, "doc", None)
    pos = getattr(exc, "pos", None)
    if doc is None:
        # Not a JSONDecodeError (e.g. a DemistoException / network error) - no response body to show.
        return f"response_body=<unavailable> exc_type={type(exc).__name__} exc={exc}", False

    body_len = len(doc)
    benign_empty_body = doc.strip() == ""
    # Bounded, repr-safe prefix so control chars / newlines are visible and the log line stays small.
    preview = repr(doc[:200])
    return (
        f"response_body_len={body_len} decode_error_pos={pos} "
        f"body_is_blank={str(benign_empty_body).lower()} response_body_preview={preview}",
        benign_empty_body,
    )


def build_client(params: dict) -> Client:
    """Build a fresh ``Client`` (and its own requests.Session). Each concurrent worker MUST call this to get
    its OWN client; sharing one across threads corrupts responses. The cached token is shared via the
    integration context, so per-thread clients don't re-auth."""
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
    """Serially drain the queue for one execution. Used by the manual ``saas-security-get-events`` command;
    the scheduled ``fetch-events`` path uses the concurrent drain for throughput.

    Returns (events, exception, queue_drained); queue_drained is True on a 204 (queue empty).
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
            demisto.debug(f"[Pagination Loop] fetched events length: ({len(fetched_events)}) in iteration {iteration_num}")
            events.extend(fetched_events)
            events_len = len(events)
            if max_fetch:
                under_max_fetch = events_len < max_fetch
            iteration_num += 1
        demisto.info(
            f"[Fetch] Finished fetch iteration loop: collected {len(events)} events over {iteration_num - 1} "
            f"iteration(s), queue_drained={queue_drained} (max_iterations={max_iterations}, max_fetch={max_fetch})."
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
    """Send ``events`` to XSIAM in fixed-size chunks, removing each chunk from the list only after it is
    acknowledged. On the first failing chunk we raise, leaving ``events`` holding just the not-yet-sent
    remainder (mutated in place) - so a stash self-heals, shrinking each cycle instead of retrying forever.

    If ``pass_over_empty_response`` is True and the only failure is a 200 with an empty/blank body (no JSON
    ack), the chunk is treated as delivered and removed. Any other failure is re-raised for stash-and-retry.

    Returns the number of events successfully sent (including passed-over empty-body chunks).
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
    High-throughput scheduled-fetch drain: issues ``concurrency`` GETs per round and streams the results to
    XSIAM in batches. Each GET runs on its own ``Client`` (own Session) via ``build_client`` - sharing a
    Session across threads corrupts responses. This is safe because /log_events_bulk is a pop-style queue,
    so N concurrent GETs return N distinct, non-overlapping batches.

    No data loss on this destructive-read queue: ``pending_events`` from a prior failed run are flushed first
    (self-heal), new events are flushed every ``send_batch_size``, and on a send failure everything not yet
    acknowledged is returned so the caller can stash it.

    Returns (fetched_count, sent_count, queue_drained, unsent_events, exception).
    """
    buffer: list[dict] = list(pending_events or [])
    fetched_count = len(buffer)
    sent_count = 0
    calls_made = 0
    queue_drained = False
    budget_exceeded = False
    deadline = time.time() + time_budget_seconds

    def flush(force: bool) -> None:
        """Send full ``send_batch_size`` chunks from the buffer (or everything, when ``force``).

        ``send_events_in_chunks`` removes each acknowledged chunk from ``buffer`` in place, so we count sent
        events by the drop in ``buffer`` length. This is done in a ``finally`` so a mid-flush send failure
        still credits the chunks that did land before the exception propagates.
        """
        nonlocal sent_count
        if force:
            before = len(buffer)
            try:
                send_events_in_chunks(buffer, send_batch_size, vendor, product, pass_over_empty_response=pass_over_empty_response)
            finally:
                sent_count += before - len(buffer)
        else:
            while len(buffer) >= send_batch_size:
                chunk = buffer[:send_batch_size]
                send_events_in_chunks(
                    chunk,
                    send_batch_size,
                    vendor,
                    product,
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
                round_error: Exception | None = None
                for future in as_completed(futures):
                    # A single worker failing must NOT discard its sibling batches: /log_events_bulk is a
                    # destructive-read (pop) queue, so every sibling that completed already dequeued its
                    # events server-side. Harvest all successful siblings first, remember the first error,
                    # and re-raise it only after the whole round is collected so those events are stashed
                    # (via the outer except) instead of silently lost.
                    try:
                        batch_events, drained = future.result()
                    except Exception as worker_exc:  # noqa: BLE001
                        demisto.error(f"A concurrent fetch worker failed; preserving sibling batches. error: {worker_exc}")
                        if round_error is None:
                            round_error = worker_exc
                        continue
                    # Keep events even from a round that also observed a 204: those batches were already
                    # popped off the server queue, so discarding them would lose data.
                    buffer.extend(batch_events)
                    fetched_count += len(batch_events)
                    if drained:
                        queue_drained = True
                if round_error is not None:
                    # Sibling events are now safely in ``buffer``; propagate so the caller stashes everything
                    # not yet acknowledged and retries next cycle.
                    raise round_error
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


def handle_fetch_events(
    params: dict,
    max_iterations: int,
    concurrency: int,
    pass_over_empty_response: bool,
) -> dict:
    """fetch-events orchestration: drains the queue, persists any unsent events, manages the backlog
    signal, and returns the ``last_run`` dict to persist.

    Extracted from ``main`` so the stash -> nextTrigger, clean-drain, and consecutive_backlog_cycles /
    warn-threshold branches are reachable by unit tests (``main`` itself stays ``# pragma: no cover``).

    Side effects (via the ``demisto`` object):
      * ``setIntegrationContext`` - stashes unsent events on a send failure, or clears the stash.
      * emits the per-cycle ingestion metrics line and the backlog warning.

    Returns the ``last_run`` dict for the caller to pass to ``demisto.setLastRun``.
    """
    last_run = demisto.getLastRun()
    integration_context = demisto.getIntegrationContext()
    from_context = bool(integration_context.get("events"))
    # Events popped in a previous execution but not yet acknowledged into XSIAM are restored and
    # flushed first, so a prior push failure never loses data on this destructive-read queue.
    pending_events = integration_context.get("events") or []
    if from_context:
        demisto.info(f"Restoring {len(pending_events)} pending events from integration context before fetching.")

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
        # Capture the actual XSIAM response body for the failure so the log shows what the platform
        # sent back (empty/blank/truncated body vs. a real error).
        xsiam_response = describe_xsiam_response_failure(exception)[0] if exception else "response_body=<none>"
        demisto.error(
            f"Received error when sending events to XSIAM; stashing {len(unsent_events)} unsent events. "
            f"[{exception}] xsiam_response: {xsiam_response}"
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
        # Only surface the high-visibility error at the threshold and then periodically (every
        # BACKLOG_WARNING_INTERVAL cycles) so a sustained backlog does not flood the logs with an
        # identical error on every back-to-back cycle.
        should_warn = (
            consecutive_backlog_cycles >= BACKLOG_WARNING_THRESHOLD
            and (consecutive_backlog_cycles - BACKLOG_WARNING_THRESHOLD) % BACKLOG_WARNING_INTERVAL == 0
        )
        if should_warn:
            demisto.error(
                f"[Fetch] SaaS Security ingestion backlog: the event queue has not fully drained for "
                f"{consecutive_backlog_cycles} consecutive fetch cycles. The upstream event rate may "
                f"exceed the collector throughput, which can cause ingestion lag. Consider increasing "
                f"'The maximum number of iterations to retrieve events' or distributing the load across "
                f"multiple instances."
            )
        else:
            demisto.debug("[Fetch] Batching in progress. Next run will be triggered in 1 second.")
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
    return last_run


def main() -> None:  # pragma: no cover
    # The concurrent drain issues GET calls from worker threads that touch the demisto object (e.g. the
    # cached OAuth token in the integration context). support_multithreading() serializes those server
    # calls with a lock so concurrent threads cannot corrupt the demisto <-> server channel.
    support_multithreading()
    params = demisto.params()
    args = demisto.args()

    max_fetch = get_max_fetch(arg_to_number(args.get("limit") or params.get("max_fetch")))
    max_iterations = get_max_iterations(arg_to_number(params.get("max_iterations")))
    concurrency = get_concurrency(arg_to_number(params.get("event_fetch_concurrency")))
    pass_over_empty_response = argToBoolean(params.get("event_pass_over_empty_response", PASS_OVER_EMPTY_XSIAM_RESPONSE_DEFAULT))

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    try:
        client = build_client(params)
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-events":
            last_run = handle_fetch_events(
                params=params,
                max_iterations=max_iterations,
                concurrency=concurrency,
                pass_over_empty_response=pass_over_empty_response,
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
