import copy
import itertools
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from typing import Any

import urllib3
from dateutil import parser

import demistomock as demisto
from CommonServerPython import *

# Disable insecure warnings
urllib3.disable_warnings()

EVENT_TYPE_ALERTS = "alerts"
EVENT_TYPE_ACTIVITIES = "activity"
EVENT_TYPE_DEVICES = "devices"
MAX_PAGINATION_DURATION_SECONDS = 90  # Lowered from 120 to leave more margin within the 5-min Docker timeout
MAX_PAGE_SIZE = 10000  # Armis recommended max page size per request
TOKEN_TTL_SECONDS = 30 * 60  # Armis token TTL is exactly 30 minutes (confirmed by Armis)
TOKEN_REFRESH_BUFFER_SECONDS = 5 * 60  # Refresh 5 minutes before expiry (at 25 min mark)
BULK_ENRICHMENT_BATCH_SIZE = 1000  # IDs per bulk enrichment query (Armis-recommended)
JSONDECODE_MAX_RETRIES = 3  # Per Armis recommendation for transient nginx malformed JSON
# Bound how long the main thread waits for the background enrichment to finish. If exceeded,
# we ship alerts without enrichment instead of blowing the 5-min Docker timeout (graceful
# degrade, same philosophy as the per-batch fallback inside _bulk_fetch_entities_by_id).
ENRICHMENT_WAIT_TIMEOUT_SECONDS = 180


class EVENT_TYPE:
    """
    This class defines an Event used to dynamically store different types of events data.
    """

    def __init__(self, unique_id_key, aql_query, type, order_by, dataset_name):
        self.unique_id_key = unique_id_key
        self.aql_query = aql_query
        self.type = type
        self.order_by = order_by
        self.dataset_name = dataset_name


""" CONSTANTS """


DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"
VENDOR = "armis"
PRODUCT = "security"
API_V1_ENDPOINT = "/api/v1"
DEFAULT_MAX_FETCH = 5000
DEFAULT_FETCH_DELAY = 10
DEVICES_DEFAULT_MAX_FETCH = 10000
EVENT_TYPES = {
    "Alerts": EVENT_TYPE(
        unique_id_key="alertId",
        aql_query=f"in:{EVENT_TYPE_ALERTS}",  # noqa: E231
        type=EVENT_TYPE_ALERTS,
        order_by="time",
        dataset_name=EVENT_TYPE_ALERTS,
    ),
    "Activities": EVENT_TYPE(
        unique_id_key="activityUUID",
        aql_query=f"in:{EVENT_TYPE_ACTIVITIES}",  # noqa: E231
        type=EVENT_TYPE_ACTIVITIES,
        order_by="time",
        dataset_name="activities",
    ),
    "Devices": EVENT_TYPE(
        unique_id_key="id",
        aql_query=f"in:{EVENT_TYPE_DEVICES}",  # noqa: E231
        type=EVENT_TYPE_DEVICES,
        order_by="lastSeen",
        dataset_name=EVENT_TYPE_DEVICES,
    ),
}
DEVICES_LAST_FETCH = "devices_last_fetch_time"
API_TIMEOUT = BaseClient.REQUESTS_TIMEOUT * 3

""" INTEGRATION CONTEXT MANAGER """


class IntegrationContextManager:
    """Thread-safe manager for integration context + last_run operations.

    Provides serialized access to two distinct backing stores:
      * ``demisto.getIntegrationContext()`` — holds the shared access token and its
        ``token_generated_at`` timestamp (read/written by token-management methods).
      * ``demisto.getLastRun()`` — holds per-event-type fetch state (read/written by
        ``update_event_type_state`` and ``get_last_run``).

    All methods are safe to call from worker threads.
    """

    def __init__(self):
        """Initialize the context manager with thread locks.

        Two distinct locks are used to separate concerns and optimize performance:

        Lock #1 (_lock): General-purpose RLock for protecting both backing stores
        - Type: threading.RLock() - Reentrant lock (same thread can acquire multiple times)
        - Purpose: Protects read/write of integration context (access token + timestamp) AND last_run
        - Used by: get_access_token(), save_access_token_to_context() (integration context);
                   update_event_type_state(), get_last_run() (last_run)
        - Why RLock: Methods can call each other while holding the lock without deadlocking

        Lock #2 (_token_refresh_lock): Specialized lock for coordinating token refresh
        - Type: threading.Lock() - Standard lock (only one thread can hold it)
        - Purpose: Ensures only ONE thread performs the expensive token refresh API call
        - Used by: refresh_access_token() method exclusively
        - Why separate: Prevents multiple threads from calling the token refresh API simultaneously

        How they work together (Double-Check Locking Pattern):
        When multiple threads detect an expired token:
        1. Thread A acquires _token_refresh_lock (others wait)
        2. Thread A checks context using _lock, sees no fresh token
        3. Thread A calls API to get new token (expensive operation)
        4. Thread A saves token to context using _lock
        5. Thread A releases _token_refresh_lock
        6. Thread B acquires _token_refresh_lock
        7. Thread B checks context using _lock, finds fresh token from Thread A
        8. Thread B uses existing token, skips API call (optimization!)
        9. Thread B releases _token_refresh_lock

        Result: Only 1 API call instead of N calls for N threads, preventing rate limiting
        and improving performance while maintaining thread safety.
        """
        self._lock = threading.RLock()  # Lock #1: General context operations
        self._token_refresh_lock = threading.Lock()  # Lock #2: Token refresh coordination

    def get_access_token(self) -> str | None:
        """Thread-safe retrieval of access token from integration context.

        Returns:
            Optional[str]: The current access token, or None if not set.
        """
        with self._lock:
            integration_context = demisto.getIntegrationContext()
            return integration_context.get("access_token")

    def save_access_token_to_context(self, new_token: str) -> None:
        """Thread-safe persistence of access token to integration context.

        This method saves the access token to the integration context,
        making it available to all threads and persisting it between executions.
        Also saves the generation timestamp to enable proactive time-based refresh.

        Args:
            new_token (str): The new access token to store.
        """
        with self._lock:
            integration_context = demisto.getIntegrationContext()
            integration_context["access_token"] = new_token
            integration_context["token_generated_at"] = datetime.now(timezone.utc).isoformat()
            demisto.setIntegrationContext(integration_context)
            demisto.debug(f"Access token saved to integration context by thread {threading.current_thread().name}")

    def update_event_type_state(self, state: dict) -> None:
        """Thread-safe update of event type specific state in integration context.

        Args:
            state (dict): Dictionary containing event type state to merge into last_run.
        """
        with self._lock:
            last_run = demisto.getLastRun()
            last_run.update(state)
            demisto.setLastRun(last_run)

    def get_last_run(self) -> dict:
        """Thread-safe retrieval of entire last_run dictionary.

        Returns:
            dict: A copy of the current last_run state.
        """
        with self._lock:
            return demisto.getLastRun().copy()

    def acquire_token_refresh_lock(self):
        """Acquire the token refresh lock for coordinated token refresh.

        Returns:
            The token refresh lock context manager.
        """
        return self._token_refresh_lock


""" CLIENT CLASS """


class Client(BaseClient):
    """Client class to interact with Armis API - this Client implements API calls"""

    def __init__(
        self,
        base_url,
        api_key,
        access_token,
        context_manager: IntegrationContextManager,
        verify=False,
        proxy=False,
    ):
        # context_manager is REQUIRED — main() always builds one, and refresh_access_token,
        # auth-retry, and IntegrationContextManager-based locking all depend on it. Tests that
        # used to pass it positionally still work because we moved it before the kw-args.
        self._api_key = api_key
        self._context_manager = context_manager
        self._access_token = None  # Initialize to prevent AttributeError in refresh_access_token
        super().__init__(base_url=base_url, verify=verify, proxy=proxy)
        if not access_token or not self._is_token_still_fresh():
            demisto.debug("Access token missing or expired, attempting to get new access token.")
            access_token = self.refresh_access_token()
            demisto.debug("New access token was successfully generated.")
        else:
            integration_context = demisto.getIntegrationContext()
            token_generated_at = integration_context.get("token_generated_at", "unknown")
            token_prefix = access_token[:8] if access_token else "None"
            demisto.debug(f"Reusing existing token (prefix: {token_prefix}..., generated_at: {token_generated_at})")
        self.apply_access_token(access_token)

    def _is_token_still_fresh(self) -> bool:
        """Check if the token is still within its valid TTL window using a saved timestamp.

        Armis tokens have a fixed 30-minute TTL (confirmed by Armis).
        We proactively refresh at 25 minutes to avoid mid-cycle 401 errors.

        The freshness decision is made entirely from `demisto.getIntegrationContext()`
        (`token_generated_at`), so the actual token string is not needed as a parameter.

        If no timestamp is available (e.g., first run, or upgrade from a version that did not
        save token_generated_at), we treat the token as stale and force a refresh. This is
        safer than a live API ping which can succeed for a token that is seconds from expiry.

        Returns:
            bool: True if the token is still fresh (< 25 min old), False if it needs refresh.
        """
        integration_context = demisto.getIntegrationContext()
        token_generated_at_str = integration_context.get("token_generated_at")
        if not token_generated_at_str:
            # No timestamp - force refresh (safer than trusting the existing token)
            safe_debug("No token_generated_at in integration context - forcing refresh")
            return False
        try:
            token_generated_at = datetime.fromisoformat(token_generated_at_str)
        except Exception as ex:
            safe_debug(f"Could not parse token_generated_at '{token_generated_at_str}': {_safe_error_str(ex)} - forcing refresh")
            return False
        # Normalize: tokens written by current code are tz-aware UTC; tokens written by older
        # versions of this integration (or by a manual edit) may be naive. Treat naive as UTC.
        if token_generated_at.tzinfo is None:
            token_generated_at = token_generated_at.replace(tzinfo=timezone.utc)
        age_seconds = (datetime.now(timezone.utc) - token_generated_at).total_seconds()
        is_fresh = age_seconds < (TOKEN_TTL_SECONDS - TOKEN_REFRESH_BUFFER_SECONDS)
        safe_debug(
            f"Token age: {age_seconds:.0f}s, fresh: {is_fresh} (threshold: {TOKEN_TTL_SECONDS - TOKEN_REFRESH_BUFFER_SECONDS}s)"
        )
        return is_fresh

    def apply_access_token(self, access_token: str) -> None:
        """Apply an already-acquired access token to client instance (updates headers + internal state).

        This method only updates the client's in-memory state with the provided token; it
        does NOT acquire a new token and does NOT persist anything to integration context.
        Callers must therefore pass a non-empty token that they obtained via
        ``refresh_access_token`` / ``IntegrationContextManager.get_access_token`` (those paths
        own the timestamp persistence).

        Thread-safety: assigns to ``self._headers`` and ``self._access_token`` without an
        explicit lock. Safe because all callers invoke it from coordinated paths that have
        already serialized token-refresh decisions:
          - ``__init__``: runs before any worker thread is spawned.
          - ``_handle_auth_error_and_retry``: the fresh token has just been obtained either
            from ``IntegrationContextManager`` (its own lock) or via ``refresh_access_token``
            (which holds ``_token_refresh_lock`` end-to-end).
        Worst-case interleaving therefore reassigns the same fresh token, which is benign.

        Args:
            access_token (str): The access token to apply. Must be non-empty.
        """
        self._headers = {"Authorization": f"{access_token}", "Accept": "application/json"}
        self._access_token = access_token

    def refresh_access_token(self) -> str:
        """Coordinate token refresh across threads to prevent collisions.

        When multiple threads detect an expired token, this method ensures only one
        thread performs the actual refresh while others wait and use the refreshed token.

        Returns:
            str: The refreshed access token.
        """
        # Use token refresh lock to ensure only one thread refreshes at a time
        with self._context_manager.acquire_token_refresh_lock():
            # Double-check: another thread might have refreshed while we were waiting.
            # Use timestamp-based freshness (_is_token_still_fresh) instead of a live API ping
            # (is_valid_access_token used in older revisions) — the live ping can return success
            # for a token that is within seconds of expiring, which then 401s a few seconds
            # later mid-fetch.
            current_token = self._context_manager.get_access_token()
            if current_token and current_token != self._access_token and self._is_token_still_fresh():
                # Token was updated by another thread and is still fresh per our timestamp
                demisto.debug(
                    f"Thread {threading.current_thread().name}: Token was refreshed by another thread, using updated token"
                )
                return current_token

            # This thread needs to perform the refresh
            demisto.debug(f"Thread {threading.current_thread().name}: Refreshing access token")
            try:
                new_token = self.get_access_token()
            except Exception as e:
                # Handle gracefully if token refresh fails (e.g., API errors)
                safe_debug(f"Thread {threading.current_thread().name}: Token refresh failed: {_safe_error_str(e)}")
                raise

            # Save to context so other threads can see it (also writes token_generated_at)
            self._context_manager.save_access_token_to_context(new_token)
            return new_token

    def _do_search_request(self, params: dict) -> dict:
        """Single chokepoint for the GET /search/ call.

        Every call site (initial fetch, auth-retry, JSON-decode-retry) goes through here
        so the retry policy (``retries=1``, ``status_list_to_retry={500, 502}``) is applied
        uniformly. Adding upstream/proxy 5xx codes here will propagate everywhere.
        """
        return self._http_request(
            url_suffix="/search/",
            method="GET",
            params=params,
            headers=self._headers,
            timeout=API_TIMEOUT,
            retries=1,
            status_list_to_retry={500, 502},
        )

    def perform_fetch(self, params):
        """Perform API fetch with coordinated token refresh on expiration.

        Args:
            params (dict): Query parameters for the API request.

        Returns:
            dict: The API response.

        Raises:
            Exception: If the request fails for reasons other than token expiration.
        """
        try:
            return self._do_search_request(params)
        except Exception as e:
            error_str = _safe_error_str(e)

            # Detect authentication errors more broadly - including JSON parse errors from HTML responses
            is_auth_error = "Invalid access token" in error_str or "401" in error_str or "Unauthorized" in error_str

            if is_auth_error:
                return self._handle_auth_error_and_retry(params, error_str)
            if isinstance(e, json.JSONDecodeError):
                return self._handle_json_decode_error_and_retry(params, e)

            safe_debug(f"Error occurred while fetching events: {error_str}")
            raise

    def _handle_auth_error_and_retry(self, params: dict, error_str: str) -> dict:
        """Handle a detected auth error: try the in-context token, else perform a full refresh, then retry.

        Extracted from ``perform_fetch`` to keep the dispatcher small. Behaviour is
        identical to the previous inline implementation.
        """
        integration_context = demisto.getIntegrationContext()
        token_generated_at = integration_context.get("token_generated_at", "unknown")
        # Cast to str for mypy: the truthiness check above already guards against None,
        # but mypy doesn't narrow self._access_token (declared Optional) across the boolean.
        token_prefix = str(self._access_token)[:8] if self._access_token else "None"
        safe_debug(
            f"Thread {threading.current_thread().name}: Authentication error detected (401/Unauthorized): {error_str}. "
            f"Token prefix: {token_prefix}..., generated_at: {token_generated_at}"
        )

        # If using context manager, try to get fresh token from context first
        if self._context_manager:
            fresh_token = self._context_manager.get_access_token()
            if fresh_token and fresh_token != self._access_token:
                safe_debug(f"Thread {threading.current_thread().name}: Using refreshed token from context")
                self.apply_access_token(fresh_token)
                # Retry with the fresh token (uses the same retry policy as the initial call)
                try:
                    return self._do_search_request(params)
                except Exception as retry_e:
                    retry_error_str = _safe_error_str(retry_e)
                    # Check if retry with context token failed for a non-auth reason
                    # If it's not an auth error (e.g., network issue, timeout), raise immediately
                    is_retry_auth_error = "Invalid access token" in retry_error_str or "401" in retry_error_str
                    if not is_retry_auth_error:
                        raise
                    # If we reach here, the token from context was also invalid - proceed to full refresh
                    safe_debug(f"Thread {threading.current_thread().name}: Context token also invalid, performing full refresh")

        # Perform coordinated token refresh (handles 401 gracefully during refresh)
        try:
            new_token = self.refresh_access_token()
            self.apply_access_token(new_token)
            safe_debug(f"Thread {threading.current_thread().name}: Access token successfully refreshed and applied")
        except Exception as refresh_e:
            safe_debug(f"Thread {threading.current_thread().name}: Token refresh failed: {_safe_error_str(refresh_e)}")
            raise

        # Retry the request with new token (uses the same retry policy as the initial call)
        return self._do_search_request(params)

    def _handle_json_decode_error_and_retry(self, params: dict, original_exc: Exception) -> dict:
        """Handle a JSONDecodeError: retry up to JSONDECODE_MAX_RETRIES times with exponential backoff.

        Armis occasionally returns malformed/truncated JSON (nginx internal timeout on large
        responses). Per Armis recommendation we retry with backoff before giving up.
        """
        safe_debug(f"JSONDecodeError on fetch, will retry up to {JSONDECODE_MAX_RETRIES} times: {_safe_error_str(original_exc)}")
        last_retry_exc: Exception = original_exc
        for attempt in range(1, JSONDECODE_MAX_RETRIES + 1):
            backoff = 2 ** (attempt - 1)  # 1s, 2s, 4s
            safe_debug(f"JSONDecodeError retry {attempt}/{JSONDECODE_MAX_RETRIES}, backing off {backoff}s")
            # Intentional: simple exponential-backoff sleep between retries on transient
            # malformed-JSON responses from Armis (nginx-side parse errors). There is no event
            # loop to yield to in this single-threaded fetch path, so a blocking sleep is the
            # right primitive. The xsoar-lint "no sleep" rule (E9003) is suppressed below for
            # the same reason — Armis explicitly recommends a small backoff between retries.
            time.sleep(backoff)  # pylint: disable=E9003
            try:
                raw_response = self._do_search_request(params)
                safe_debug(f"JSONDecodeError retry {attempt}/{JSONDECODE_MAX_RETRIES} succeeded")
                return raw_response
            except Exception as retry_e:
                last_retry_exc = retry_e
                safe_debug(f"JSONDecodeError retry {attempt}/{JSONDECODE_MAX_RETRIES} failed: {_safe_error_str(retry_e)}")

        # All retries exhausted
        safe_debug(f"JSONDecodeError: all {JSONDECODE_MAX_RETRIES} retries exhausted, raising last exception")
        raise last_retry_exc

    def fetch_by_ids_in_aql_query(self, aql_query: str, order_by: str = "time", length: int = 1000):
        """Fetches events using AQL query (single page, no pagination).

        Args:
            aql_query (str): AQL query request parameter for the API call.
            order_by (str): Order by parameter for the API call. Defaults to 'time'.
            length (int): Page size for the API call. Defaults to 1000 (matches BATCH_SIZE
                used by bulk_enrich_alerts so a single response covers all batched IDs).
        Returns:
            list[dict]: List of events objects represented as dictionaries.
        """
        params: dict[str, Any] = {"aql": aql_query, "includeTotal": "false", "orderBy": order_by, "length": length}
        raw_response = self.perform_fetch(params)
        return raw_response.get("data", {}).get("results", [])

    def fetch_by_aql_query(
        self,
        aql_query: str,
        max_fetch: int,
        after: datetime,
        order_by: str = "time",
        from_param: None | int = None,
        before: datetime | None = None,
        event_type: str = "",
    ):
        """Fetches events using AQL query.

        Args:
            aql_query (str): AQL query request parameter for the API call.
            max_fetch (int): Max number of events to fetch.
            after (None): The date and time to fetch events from.
            order_by (str): Order by parameter for the API call. Defaults to 'time'.
            from_param (None | int): The next incident to start the fetch from. Defaults to None.
            before (datetime): The time to fetch until.
        Returns:
            (list[dict], int): A tuple with the List of events objects represented as dictionaries and the next event pointer.
        """
        aql_query = f"{aql_query} after:{after.strftime(DATE_FORMAT)}"  # noqa: E231
        if before:
            aql_query = f"{aql_query} before:{before.strftime(DATE_FORMAT)}"  # noqa: E231
            demisto.info(f"Fetching events until {before}.")
        # Cap page size to MAX_PAGE_SIZE per Armis recommendation (100K causes nginx timeouts)
        page_size = min(max_fetch, MAX_PAGE_SIZE)
        params: dict[str, Any] = {"aql": aql_query, "includeTotal": "false", "length": page_size, "orderBy": order_by}
        if from_param:
            params["from"] = from_param
        raw_response = self.perform_fetch(params)
        results = raw_response.get("data", {}).get("results", [])
        next = raw_response.get("data", {}).get("next") or 0
        # perform pagination if needed (until max_fetch limit),  cycle through all pages and add results to results list.
        # The response's 'next' attribute carries the index to start the next request in the
        # pagination (using the 'from' request parameter), or null if there are no more pages left.
        start_time = datetime.now()
        try:
            while next and (len(results) < max_fetch):
                params["length"] = min(max_fetch - len(results), MAX_PAGE_SIZE)
                params["from"] = next
                raw_response = self.perform_fetch(params)
                next = raw_response.get("data", {}).get("next") or 0
                current_results = raw_response.get("data", {}).get("results", [])
                results.extend(current_results)
                demisto.info(f"fetched {len(current_results)} results, total is {len(results)}, and {next=}.")

                total_seconds = (datetime.now() - start_time).total_seconds()
                demisto.debug(f"total {total_seconds} seconds so far")
                if next and total_seconds >= MAX_PAGINATION_DURATION_SECONDS:
                    demisto.debug(
                        f"Reached pagination time limit of {MAX_PAGINATION_DURATION_SECONDS}s for {event_type}, "
                        f"breaking early with {next=} to avoid timeout. Pagination will resume in the next fetch cycle."
                    )
                    break

        except Exception as e:
            demisto.info(f"caught an exception during pagination:\n{str(e)}")  # noqa: E231

        return results, next

    def get_access_token(self):
        """Generates access token for Armis API.

        Raises:
            DemistoException: If access token could not be generated.
        Returns:
            str: Access token.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        params = {"secret_key": self._api_key}
        response = self._http_request(url_suffix="/access_token/", method="POST", params=params, headers=headers)
        if access_token := response.get("data", {}).get("access_token"):
            return access_token
        else:
            raise DemistoException("Could not generate access token.")


""" TEST MODULE """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.
    When 'ok' is returned it indicates the integration works like it is supposed to and connection to the service is
    successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Armis client to use for API calls.

    Returns:
        str: 'ok' if test passed, anything else will raise an exception and will fail the test.
    """
    try:
        client.fetch_by_aql_query("in:alerts", 1, after=(datetime.now() - timedelta(minutes=1)))

    except Exception as e:
        raise DemistoException(f"Error in test-module: {e}") from e

    return "ok"


""" HELPER FUNCTIONS """


def safe_debug(message: str) -> None:
    """Safely log debug messages, handling JSON serialization errors.

    Args:
        message (str): The message to log.
    """
    try:
        demisto.debug(message)
    except Exception as e:
        try:
            demisto.debug(f"[safe_debug] Error: {type(e).__name__}\nTraceback:\n{traceback.format_exc()}")
        except Exception:
            try:
                demisto.debug(f"[safe_debug] Logging failed: {type(e).__name__}")
            except Exception:
                # Final fallback - silently continue to prevent cascade failures
                demisto.debug("[safe_debug] Final fallback - silently continue to prevent cascade failures")


def _safe_error_str(e: Exception) -> str:
    """Format an exception safely — repr for JSONDecodeError (avoids re-parsing), str for others."""
    return repr(e) if isinstance(e, json.JSONDecodeError) else str(e)


def calculate_fetch_start_time(
    last_fetch_time: datetime | str | None, fetch_start_time: datetime | None, fetch_delay: int = DEFAULT_FETCH_DELAY
):
    """Calculates the fetch start time.
        There are three cases for fetch start time calculation:
        - Case 1: last_fetch_time exist in last_run, thus being prioritized (fetch-events / armis-get-events commands).
        - Case 2: last_run is empty & from_date parameter exist (armis-get-events command with from_date argument).
        - Case 3: first fetch in the instance (no last_run), this will leave after as None.
                  (This will eventually be evaluated to before time - 1 minute)

    Args:
        last_fetch_time (datetime | str | None): Last fetch time (from last run).
        fetch_start_time (datetime | None): Fetch start time.
        fetch_delay (int): The number of minutes to delay the search until.

    Raises:
        DemistoException: If the transformation to to datetime object failed.

    Returns:
        datetime: Fetch start time value for current fetch cycle, and the time until to run the query for.
    """
    before_time = datetime.now()
    after_time = None
    if fetch_delay:
        before_time = before_time - timedelta(minutes=(fetch_delay))
    # case 1
    if last_fetch_time:
        if isinstance(last_fetch_time, str):
            demisto.info(f"calculating_fetch_time for {last_fetch_time=}")
            last_fetch_datetime = arg_to_datetime(last_fetch_time)
        else:
            last_fetch_datetime = last_fetch_time
        if not last_fetch_datetime:
            raise DemistoException(f"last_fetch_time is not a valid date: {last_fetch_time}")
        after_time = last_fetch_datetime
    # case 2
    elif fetch_start_time:
        after_time = fetch_start_time
    if after_time:
        after_time = after_time.replace(tzinfo=None)
    if not after_time or after_time >= before_time:
        demisto.info("last run time is later than before time, overwriting after time.")
        after_time = before_time - timedelta(minutes=1)
    return after_time, before_time


def are_two_datetime_equal_by_second(x: datetime, y: datetime):
    """Calculate if two datetime objects are equal up to the seconds value.
        Even though the 'time' attribute of each event has milliseconds,
        the API request supports time filtering of only up to seconds.
        There for, all events with the same time up to a seconds are considered to have the same time.

    Args:
        x (datetime): First datetime.
        y (datetime): Second datetime.

    Returns:
        Boolean: True if both datetime objects have the same time up to seconds, False otherwise.
    """
    return (
        (x.year == y.year)
        and (x.month == y.month)
        and (x.day == y.day)
        and (x.hour == y.hour)
        and (x.minute == y.minute)
        and (x.second == y.second)
    )


def dedup_events(events: list[dict], events_last_fetch_ids: list[str], unique_id_key: str, event_order_by: str):
    """Dedup events response.
    Armis API V.1.8 supports time filtering in requests only up to level of seconds (and not milliseconds).
    Therefore, if there are more events with the same timestamp than in the current fetch cycle,
    additional handling is necessary.

    Cases:
    1.  Empty event list (no new events received from API response).
        Meaning: Usually means there are not any more events to fetch at the moment.
        Handle: Return empty list of events and the unchanged list of 'events_last_fetch_ids' for next run.

    2.  All events from the current fetch cycle have the same timestamp.
        Meaning: There are potentially more events with the same timestamp in the next fetch.
        Handle: Add the list of fetched events IDs to current 'events_last_fetch_ids' from last run,
                return list of new events and updated list of 'events_last_fetch_ids' for next run.

    3.  Most recent event has later timestamp then other events in the response.
        Meaning: This is the normal case where events in the response have different timestamps.
        Handle: Return list of new events and a list of 'new_ids' containing only IDs of
                events with identical latest time (up to second) for next run.

    Args:
        events (list[dict]): List of events from the current fetch response.
        events_last_fetch_ids (list[str]): List of IDs of events from last fetch cycle.
        unique_id_key (str): Unique event ID key of specific event type (Alert, Threat Activity etc.)

    Returns:
        tuple[list[dict], list[str]: The list of dedup events and ID list of events of current fetch.
    """
    # case 1
    if not events:
        demisto.debug("Dedup case 1 - Empty event list (no new events received from API response).")
        return [], events_last_fetch_ids

    # Convert to set for O(1) lookups
    last_fetch_ids_set = set(events_last_fetch_ids)
    new_events: list[dict] = [event for event in events if event.get(unique_id_key) not in last_fetch_ids_set]

    earliest_event_datetime = arg_to_datetime(events[0].get(event_order_by))
    latest_event_datetime = arg_to_datetime(events[-1].get(event_order_by))

    # case 2
    if (
        earliest_event_datetime
        and latest_event_datetime
        and are_two_datetime_equal_by_second(latest_event_datetime, earliest_event_datetime)
    ):
        demisto.debug("Dedup case 2 - All events from the current fetch cycle have the same timestamp.")
        new_ids = [event.get(unique_id_key, "") for event in new_events]
        events_last_fetch_ids.extend(new_ids)
        return new_events, events_last_fetch_ids

    # case 3
    else:
        # Note that the following timestamps comparison are made between strings and assume
        # the following timestamp format from the response: "YYYY-MM-DDTHH:MM:SS.fffff+Z"
        demisto.debug("Dedup case 3 - Most recent event has later timestamp then other events in the response.")

        latest_event_timestamp = events[-1].get(event_order_by, "")[:19]
        # itertools.takewhile is used to iterate over the list of events (from latest time to earliest)
        # and take only the events with identical latest time
        events_with_identical_latest_time = list(
            itertools.takewhile(lambda x: x.get(event_order_by, "")[:19] == latest_event_timestamp, reversed(events))
        )
        new_ids = [event.get(unique_id_key, "") for event in events_with_identical_latest_time]

        return new_events, new_ids


def fetch_by_event_type(
    client: Client,
    event_type: EVENT_TYPE,
    events: dict,
    max_fetch: int,
    last_run: dict,
    next_run: dict,
    fetch_start_time: datetime | None,
    fetch_delay: int = DEFAULT_FETCH_DELAY,
):
    """Fetch events by specific event type.

    Args:
        client (Client): Armis client to use for API calls.
        event_type (EVENT_TYPE): A namedtuple object containing the event's unique ID key, AQL query and type name.
        events (list): List of fetched events.
        max_fetch (int): Max number of events to fetch.
        last_run (dict): Last run dictionary.
        next_run (dict): Last run dictionary for next fetch cycle.
        fetch_start_time (datetime | None): Fetch start time.
        fetch_delay (int): The number of minutes to delay in the search.
    """
    last_fetch_ids = f"{event_type.type}_last_fetch_ids"
    last_fetch_time_field = f"{event_type.type}_last_fetch_time"
    last_fetch_next_field = f"{event_type.type}_last_fetch_next_field"

    demisto.debug(f"handling event-type: {event_type.type}")
    if last_fetch_time := last_run.get(last_fetch_time_field):
        demisto.debug(f"last run of type: {event_type.type} time is: {last_fetch_time}")
    last_fetch_next = last_run.get(last_fetch_next_field, 0)
    demisto.debug(f"last run of type: {event_type.type} next is: {last_fetch_next}")
    event_type_fetch_start_time, before_time = calculate_fetch_start_time(last_fetch_time, fetch_start_time, fetch_delay)
    response, next = client.fetch_by_aql_query(
        aql_query=event_type.aql_query,
        max_fetch=max_fetch,
        after=event_type_fetch_start_time,
        order_by=event_type.order_by,
        from_param=last_fetch_next,
        before=before_time,
        event_type=event_type.type,
    )
    new_events: list[dict] = []
    demisto.debug(f"fetched {len(response)} {event_type.type} from API")
    if response:
        new_events, next_run[last_fetch_ids] = dedup_events(
            response, last_run.get(last_fetch_ids, []), event_type.unique_id_key, event_type.order_by
        )
        events.setdefault(event_type.dataset_name, []).extend(new_events)
        demisto.debug(f"overall {len(new_events)} {event_type.dataset_name} (after dedup)")
        last_event_str = str(new_events[-1])[:500] if new_events else "{}"
        demisto.debug(f"last {event_type.dataset_name} in list: {last_event_str}")

    if not next:  # we wish to update the time only in case the next is 0 because the next is relative to the time.
        event_type_fetch_start_time = new_events[-1].get(event_type.order_by) if new_events else last_fetch_time
        #  can empty the list.
    next_run[last_fetch_next_field] = next
    if isinstance(event_type_fetch_start_time, datetime):
        event_type_fetch_start_time = event_type_fetch_start_time.strftime(DATE_FORMAT)
    next_run[last_fetch_time_field] = event_type_fetch_start_time
    demisto.debug(f"updated next_run for event type {event_type.type} with {next=} and {event_type_fetch_start_time=}")


def _collect_unique_enrichment_ids(alerts: list[dict]) -> tuple[set[str], set[str]]:
    """Collect deduplicated activityUUIDs and deviceIds across alerts (str-coerced).

    Also initializes each alert's `activitiesData` and `devicesData` to empty lists so
    callers always see consistent keys.
    """
    uuids: set[str] = set()
    device_ids: set[str] = set()
    for alert in alerts:
        uuids.update(str(u) for u in (alert.get("activityUUIDs") or []) if u is not None)
        device_ids.update(str(d) for d in (alert.get("deviceIds") or []) if d is not None)
        alert["activitiesData"] = []
        alert["devicesData"] = []
    return uuids, device_ids


def _bulk_fetch_entities_by_id(
    client: Client,
    entity_type: str,
    aql_field: str,
    ids: list[str],
    response_key: str,
    order_by: str,
) -> dict[str, dict]:
    """Bulk-fetch entities (activities or devices) by ID in batches.

    Args:
        client (Client): The Armis API client.
        entity_type (str): AQL entity ('activity' / 'devices').
        aql_field (str): AQL field name to filter on ('UUID' / 'deviceId').
        ids (list[str]): IDs to query (already str-coerced).
        response_key (str): Field name on the returned entity used as the dict key.
        order_by (str): order_by AQL parameter.

    Returns:
        dict[str, dict]: Map of `str(response_key)` -> entity dict.
    """
    tname = threading.current_thread().name
    by_id: dict[str, dict] = {}
    if not ids:
        demisto.debug(f"[{tname}] bulk_enrich: no {entity_type} IDs to fetch")
        return by_id

    total_batches = (len(ids) + BULK_ENRICHMENT_BATCH_SIZE - 1) // BULK_ENRICHMENT_BATCH_SIZE
    demisto.debug(f"[{tname}] bulk_enrich: starting {entity_type} fetch — {len(ids)} IDs in {total_batches} batch(es)")
    section_start = datetime.now()

    for batch_idx, offset in enumerate(range(0, len(ids), BULK_ENRICHMENT_BATCH_SIZE), start=1):
        chunk = ids[offset : offset + BULK_ENRICHMENT_BATCH_SIZE]
        # No timeFrame: per Armis (Sefi Maman, 2026-05-11) it is not required when
        # the query specifies explicit IDs (UUID:... or deviceId:...).
        aql = f"in:{entity_type} {aql_field}:{','.join(chunk)}"  # noqa: E231
        batch_start = datetime.now()
        try:
            # Use MAX_PAGE_SIZE (10K) for the response page size: we only send 1000 IDs per batch,
            # so we should never get back more than that. The 10K headroom protects us from
            # silent truncation if a single ID happens to map to multiple entities.
            results = client.fetch_by_ids_in_aql_query(aql_query=aql, order_by=order_by, length=MAX_PAGE_SIZE)
            if len(results) > BULK_ENRICHMENT_BATCH_SIZE:
                demisto.error(
                    f"[{tname}] bulk_enrich: {entity_type} batch {batch_idx}/{total_batches} returned "
                    f"{len(results)} results for {len(chunk)} IDs (more than expected) — investigate"
                )
            for entity in results:
                key = entity.get(response_key)
                if key is not None:
                    by_id[str(key)] = entity
            demisto.debug(
                f"[{tname}] bulk_enrich: {entity_type} batch {batch_idx}/{total_batches} OK — "
                f"{len(results)} returned in {(datetime.now() - batch_start).total_seconds():.2f}s"
            )
        except Exception as ex:
            # Intentional: per-batch isolation — one failed batch (e.g., transient network/parse error
            # on a chunk of 1000 IDs) must not abort the entire enrichment cycle. We log and move on
            # so other batches can still complete; alerts whose IDs fell in the failed batch will simply
            # ship without their enrichment data, which is preferable to dropping the whole cycle.
            demisto.error(f"[{tname}] bulk_enrich: {entity_type} batch {batch_idx}/{total_batches} FAILED: {_safe_error_str(ex)}")

    demisto.debug(
        f"[{tname}] bulk_enrich: {entity_type} fetch done in "
        f"{(datetime.now() - section_start).total_seconds():.2f}s — "
        f"{len(by_id)}/{len(ids)} matched"
    )
    return by_id


def _attach_enrichment(
    alerts: list[dict],
    activities_by_uuid: dict[str, dict],
    devices_by_id: dict[str, dict],
) -> None:
    """Map fetched entities back onto each alert, with deepcopy to keep alerts independent.

    The deepcopy mirrors the previous per-alert behaviour where each alert owned a
    separate copy of its activities/devices (no shared references between alerts).
    """
    for alert in alerts:
        alert["activitiesData"] = [
            copy.deepcopy(activities_by_uuid[str(u)])
            for u in (alert.get("activityUUIDs") or [])
            if u is not None and str(u) in activities_by_uuid
        ]
        alert["devicesData"] = [
            copy.deepcopy(devices_by_id[str(d)])
            for d in (alert.get("deviceIds") or [])
            if d is not None and str(d) in devices_by_id
        ]


def bulk_enrich_alerts(client: Client, alerts: list[dict]) -> None:
    """Bulk-enrich alerts with their related Activities and Devices.

    Replaces the previous N+1 per-alert loop. Pattern recommended by Armis (Sefi Maman):
    use the activityUUIDs/deviceIds arrays already on each alert, dedupe across the page,
    and bulk-fetch in chunks of BULK_ENRICHMENT_BATCH_SIZE.

    Each alert is updated in-place with `activitiesData` and `devicesData` lists.

    Args:
        client (Client): The Armis API client.
        alerts (list[dict]): The list of alerts in the current fetch page.
    """
    tname = threading.current_thread().name
    if not alerts:
        demisto.debug(f"[{tname}] bulk_enrich: no alerts to enrich, returning")
        return

    start = datetime.now()
    demisto.debug(f"[{tname}] bulk_enrich: START enriching {len(alerts)} alerts")

    uuids, device_ids = _collect_unique_enrichment_ids(alerts)
    demisto.debug(f"[{tname}] bulk_enrich: collected {len(uuids)} unique activityUUIDs, {len(device_ids)} unique deviceIds")

    activities_by_uuid = _bulk_fetch_entities_by_id(
        client=client,
        entity_type=EVENT_TYPE_ACTIVITIES,
        aql_field="UUID",
        ids=list(uuids),
        response_key=EVENT_TYPES["Activities"].unique_id_key,
        order_by=EVENT_TYPES["Activities"].order_by,
    )
    devices_by_id = _bulk_fetch_entities_by_id(
        client=client,
        entity_type=EVENT_TYPE_DEVICES,
        aql_field="deviceId",
        ids=list(device_ids),
        response_key=EVENT_TYPES["Devices"].unique_id_key,
        order_by=EVENT_TYPES["Devices"].order_by,
    )

    _attach_enrichment(alerts, activities_by_uuid, devices_by_id)

    demisto.debug(
        f"[{tname}] bulk_enrich: DONE in {(datetime.now() - start).total_seconds():.2f}s — "
        f"matched {len(activities_by_uuid)}/{len(uuids)} activities, "
        f"{len(devices_by_id)}/{len(device_ids)} devices"
    )


def _wait_for_enrichment(future, executor, timeout_seconds: int = ENRICHMENT_WAIT_TIMEOUT_SECONDS) -> None:
    """Block until the background enrichment task completes (bounded) and tear down its executor.

    Safe to call with ``(None, None)`` if no enrichment was scheduled (e.g., no Alerts in cycle).

    Failure modes (all graceful-degrade — alerts ship without enrichment instead of losing the cycle):
      * The enrichment raises -> logged, suppressed.
      * The enrichment exceeds ``timeout_seconds`` -> logged, the executor is shut down without
        waiting, and the enrichment thread is left to either finish naturally and be GC'd or be
        torn down with the integration container. This is the same philosophy as the per-batch
        fallback inside ``_bulk_fetch_entities_by_id``: we'd rather ship partial data than blow
        the 5-minute Docker timeout that would lose ALL events in the cycle.
    """
    tname = threading.current_thread().name
    if future is None:
        return
    wait_start = datetime.now()
    try:
        future.result(timeout=timeout_seconds)
        demisto.debug(
            f"[{tname}] bulk_enrich: background enrichment joined after {(datetime.now() - wait_start).total_seconds():.2f}s"
        )
    except FuturesTimeoutError:
        demisto.error(
            f"[{tname}] bulk_enrich: background enrichment did NOT finish within {timeout_seconds}s — "
            f"shipping alerts without (full) enrichment to avoid the 5-min Docker timeout"
        )
    except Exception as ex:
        demisto.error(f"[{tname}] bulk_enrich: background enrichment FAILED: {ex!r}")
    finally:
        if executor is not None:
            # wait=False: do NOT block on outstanding enrichment threads in the timeout case.
            executor.shutdown(wait=False)


def fetch_event_type_worker(
    client: Client,
    event_type_name: str,
    event_type: EVENT_TYPE,
    max_fetch: int,
    last_run: dict,
    fetch_start_time: datetime | None,
    fetch_delay: int,
    context_manager: IntegrationContextManager,
) -> tuple[str, dict, dict]:
    """Worker function to fetch events for a specific event type in a thread.

    Args:
        client (Client): Armis client to use for API calls.
        event_type_name (str): Name of the event type being fetched.
        event_type (EVENT_TYPE): Event type configuration object.
        max_fetch (int): Maximum number of events to fetch.
        last_run (dict): Last run state for this event type.
        fetch_start_time (datetime | None): Start time for fetching.
        fetch_delay (int): Delay in minutes for fetching.
        context_manager (IntegrationContextManager): Thread-safe context manager.

    Returns:
        tuple[str, dict, dict]: Event type name, fetched events dict, and next_run state.
    """
    thread_id = threading.current_thread().name
    safe_debug(f"[{thread_id}] Starting fetch for {event_type_name}")

    events: dict[str, list[dict]] = {}
    next_run: dict[str, list | str | None] = {}

    try:
        fetch_by_event_type(client, event_type, events, max_fetch, last_run, next_run, fetch_start_time, fetch_delay=fetch_delay)

        # Update context for this event type atomically
        context_manager.update_event_type_state(next_run)

        event_count = len(events.get(event_type.dataset_name, []))
        safe_debug(f"[{thread_id}] Completed fetch for {event_type_name}: {event_count} events")

        return event_type_name, events, next_run

    except Exception as e:
        safe_debug(f"[{thread_id}] Error fetching {event_type_name}: {_safe_error_str(e)}")
        raise


def fetch_events(
    client: Client,
    max_fetch: int,
    devices_max_fetch: int,
    last_run: dict,
    fetch_start_time: datetime | None,
    event_types_to_fetch: list[str],
    device_fetch_interval: timedelta | None,
    fetch_delay: int = DEFAULT_FETCH_DELAY,
    use_multithreading: bool = True,
    context_manager: IntegrationContextManager | None = None,
):
    """Fetch events from Armis API with optional multithreading support.

    Args:
        client (Client): Armis client to use for API calls.
        max_fetch (int): Max number of alerts and activities to fetch.
        devices_max_fetch (int): Max number of devices to fetch.
        last_run (dict): Last run dictionary.
        fetch_start_time (datetime | None): Fetch start time.
        event_types_to_fetch (list[str]): List of event types to fetch.
        device_fetch_interval (timedelta | None): Time interval to fetch devices.
        fetch_delay (int): The number of minutes to delay in the search.
        use_multithreading (bool): Whether to use multithreading for parallel fetching. Multithreading
            is always on for the periodic ``fetch-events`` command and disabled for the manual
            ``armis-get-events`` command (which only fetches a single event type at a time).
        context_manager (Optional[IntegrationContextManager]): Thread-safe context manager.
    Returns:
        (list[dict], dict) : List of fetched events and next run dictionary.
    """
    fetch_start = datetime.now()
    safe_debug(f"=== Starting fetch_events cycle at {fetch_start.strftime('%Y-%m-%d %H:%M:%S')} ===")
    safe_debug(f"Event types requested: {event_types_to_fetch}")
    safe_debug(f"Multithreading enabled: {use_multithreading}")
    safe_debug(f"Max fetch - Alerts/Activities: {max_fetch}, Devices: {devices_max_fetch}")

    events: dict[str, list[dict]] = {}
    next_run: dict[str, list | str | None] = {}

    # Filter out Devices if not ready
    if "Devices" in event_types_to_fetch and not should_run_device_fetch(last_run, device_fetch_interval, datetime.now()):
        safe_debug("Skipping Devices fetch - interval not reached")
        event_types_to_fetch.remove("Devices")

    safe_debug(f"Event types after filtering: {event_types_to_fetch}")

    # Handle Alerts: fetch them first (sequential), then run bulk enrichment IN PARALLEL with
    # the standalone Activities/Devices fetches below. This is the biggest single optimisation
    # available — bulk enrichment dominates cycle time (~3-4 min) and previously blocked the
    # cycle. Running it concurrently with the other workers keeps total cycle time ≈ max(workers)
    # instead of sum, which is what lets us fit inside the 5-minute Docker timeout.
    enrichment_future = None
    enrichment_executor = None
    if "Alerts" in event_types_to_fetch:
        main_tname = threading.current_thread().name
        safe_debug(f"[{main_tname}] Fetching Alerts (then enrichment will run in parallel with other workers)")
        alerts_start = datetime.now()
        fetch_by_event_type(
            client, EVENT_TYPES["Alerts"], events, max_fetch, last_run, next_run, fetch_start_time, fetch_delay=fetch_delay
        )
        alerts_count = len(events.get(EVENT_TYPE_ALERTS, []))
        safe_debug(f"[{main_tname}] Fetched {alerts_count} alerts in {(datetime.now() - alerts_start).total_seconds():.2f}s")

        if events and events.get(EVENT_TYPE_ALERTS):
            safe_debug(
                f"[{main_tname}] Submitting bulk-enrichment of {alerts_count} alerts to background "
                f"thread (ArmisEnrich-*) — will run in parallel with Activities/Devices workers"
            )
            enrichment_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ArmisEnrich")
            enrichment_future = enrichment_executor.submit(bulk_enrich_alerts, client, events[EVENT_TYPE_ALERTS])
        event_types_to_fetch.remove("Alerts")

    # Process remaining event types
    if not event_types_to_fetch:
        safe_debug("No remaining event types to fetch")
        _wait_for_enrichment(enrichment_future, enrichment_executor)
        fetch_duration = (datetime.now() - fetch_start).total_seconds()
        total_events = sum(len(event_list) for event_list in events.values())
        safe_debug(f"=== Fetch cycle completed in {fetch_duration:.2f}s - Total events: {total_events} ===")
        return events, next_run

    # Use multithreading only if it's beneficial: more than one event type AND the caller is the
    # periodic ``fetch-events`` command (manual ``armis-get-events`` always passes False).
    # ``not context_manager`` is a defensive guard — in production it is always set.
    if not use_multithreading or len(event_types_to_fetch) == 1 or not context_manager:
        # Fallback to sequential processing
        safe_debug(f"Using sequential processing for {len(event_types_to_fetch)} event type(s): {event_types_to_fetch}")
        for event_type in event_types_to_fetch:
            event_max_fetch = max_fetch if event_type != "Devices" else devices_max_fetch
            type_start = datetime.now()
            safe_debug(f"Starting sequential fetch for {event_type} (max: {event_max_fetch})")

            fetch_by_event_type(
                client,
                EVENT_TYPES[event_type],
                events,
                event_max_fetch,
                last_run,
                next_run,
                fetch_start_time,
                fetch_delay=fetch_delay,
            )

            type_duration = (datetime.now() - type_start).total_seconds()
            type_count = len(events.get(EVENT_TYPES[event_type].dataset_name, []))
            safe_debug(f"Completed {event_type} fetch: {type_count} events in {type_duration:.2f}s")
    else:
        # Parallel processing with ThreadPoolExecutor
        max_workers = min(len(event_types_to_fetch), len(EVENT_TYPES))
        parallel_start = datetime.now()
        safe_debug(f"=== Starting parallel processing with {max_workers} worker(s) ===")
        safe_debug(f"Event types for parallel fetch: {event_types_to_fetch}")

        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ArmisWorker") as executor:
            submitted_tasks = {}

            worker_num = 0
            for event_type_name in event_types_to_fetch:
                worker_num += 1
                event_max_fetch = max_fetch if event_type_name != "Devices" else devices_max_fetch
                safe_debug(f"[Worker-{worker_num}:{event_type_name}] Submitting task (max: {event_max_fetch})")

                task = executor.submit(
                    fetch_event_type_worker,
                    client,
                    event_type_name,
                    EVENT_TYPES[event_type_name],
                    event_max_fetch,
                    copy.deepcopy(last_run),  # Each thread gets its own deep copy
                    fetch_start_time,
                    fetch_delay,
                    context_manager,
                )
                submitted_tasks[task] = event_type_name

            safe_debug(f"All {len(submitted_tasks)} worker tasks submitted, waiting for completion...")
            completed_count = 0

            # Collect results as they complete
            for completed_task in as_completed(submitted_tasks):
                event_type_name = submitted_tasks[completed_task]
                completed_count += 1
                try:
                    _, thread_events, thread_next_run = completed_task.result()

                    # Merge events
                    events_merged = 0
                    for dataset_name, event_list in thread_events.items():
                        events.setdefault(dataset_name, []).extend(event_list)
                        events_merged += len(event_list)

                    # Merge next_run (already updated in context by worker)
                    next_run.update(thread_next_run)

                    safe_debug(
                        f"[Worker:{event_type_name}] Completed ({completed_count}/{len(submitted_tasks)}) - "
                        f"{events_merged} events merged"
                    )

                except Exception as e:
                    safe_debug(f"[Worker:{event_type_name}] Failed: {_safe_error_str(e)}")
                    safe_debug(f"Continuing with remaining workers ({completed_count}/{len(submitted_tasks)} completed)")

            parallel_duration = (datetime.now() - parallel_start).total_seconds()
            safe_debug(f"=== Parallel processing completed in {parallel_duration:.2f}s ===")

    # Block until the background enrichment task finishes; this is the join point that lets
    # us run enrichment in parallel with Activities/Devices fetches above.
    _wait_for_enrichment(enrichment_future, enrichment_executor)

    # Final summary
    fetch_duration = (datetime.now() - fetch_start).total_seconds()
    total_events = sum(len(event_list) for event_list in events.values())
    events_by_type = {dataset: len(event_list) for dataset, event_list in events.items()}
    safe_debug(f"=== Fetch cycle completed in {fetch_duration:.2f}s ===")
    safe_debug(f"Total events fetched: {total_events}")
    safe_debug(f"Events by type: {events_by_type}")

    return events, next_run


def add_time_to_events(events, event_type):
    """Adds the _time key to the events.

    Args:
        events: list[dict] - list of events to add the _time key to.

    Returns:
        list: The events with the _time key.
    """
    if events:
        for event in events:
            if event_type == "devices":
                event["_time"] = event.get("lastSeen")
            else:
                event["_time"] = event.get("time")


def handle_from_date_argument(from_date: str) -> datetime | None:
    """Converts the from_date argument to a datetime object.
        This argument is used only in the armis-get-events command.

    Args:
        from_date: The from_date argument.

    Returns:
        datetime: The from_date argument as a datetime object or None if the argument is invalid.
    """
    from_date_datetime = arg_to_datetime(from_date)
    return from_date_datetime if from_date_datetime else None


def handle_fetched_events(events: dict[str, list[dict[str, Any]]], next_run: dict[str, str | list | None]):
    """Handle fetched events.
    - Send the fetched events to XSIAM.
    - Set last run values for next fetch cycle.

    Args:
        events (list[dict[str, Any]]): Fetched events.
        next_run (dict[str, str | list]): Next run dictionary.
    """
    if events:
        for event_type, events_list in events.items():
            if not events_list:
                demisto.debug(f"No events of type: {event_type} fetched from API.")
            else:
                add_time_to_events(events_list, event_type)
                demisto.debug(f"{len(events_list)} events of type: {event_type} are about to be sent to XSIAM.")
            product = f"{PRODUCT}_{event_type}" if event_type != EVENT_TYPE_ALERTS else PRODUCT
            send_events_to_xsiam(events_list, vendor=VENDOR, product=product)
            demisto.debug(f"{len(events)} events were sent to XSIAM.")
    else:
        demisto.debug("No new events fetched. Sending 0 to XSIAM.")
        send_events_to_xsiam(events=[], vendor=VENDOR, product=PRODUCT)

    demisto.debug(f"setting {next_run=}")
    next_run["nextTrigger"] = "1"
    demisto.setLastRun(next_run)


def events_to_command_results(events: dict[str, list], event_type) -> CommandResults:
    """Return a CommandResults object with a table of fetched events.

    Args:
        events [dict[str, Any]]: fetched events.
        event_type str: type of the fetched events.

    Returns:
        CommandResults: CommandResults containing table of fetched events.
    """
    events_output = events[event_type] if events else []
    product = f"{PRODUCT}_{event_type}" if event_type != EVENT_TYPE_ALERTS else PRODUCT
    return CommandResults(
        raw_response=events_output,
        readable_output=tableToMarkdown(name=f"{VENDOR} {product} events", t=events_output, removeNull=True),
    )


def set_last_run_for_last_minute(last_run: dict) -> None:
    """Set last fetch time values for all event types to current time.
        This will set a fetch starting time until events are fetched for each event type.
    Args:
        last_run (dict): Last run dictionary.
    """
    now: datetime = datetime.now() - timedelta(minutes=1)
    now_str: str = now.strftime(DATE_FORMAT)
    for event_type in EVENT_TYPES.values():
        last_fetch_time = f"{event_type.type}_last_fetch_time"
        last_run[last_fetch_time] = now_str


def should_run_device_fetch(last_run, device_fetch_interval: timedelta | None, datetime_now: datetime):
    """
    Args:
        last_run: last run object.
        device_fetch_interval: device fetch interval.
        datetime_now: time now

    Returns: True if fetch device interval time has passed since last time that fetch run.

    """
    if not device_fetch_interval:
        return False
    if last_fetch_time := last_run.get(DEVICES_LAST_FETCH):
        last_fetch_datetime = parser.parse(last_fetch_time).replace(tzinfo=None)
    else:
        # first time device fetch
        return True
    demisto.debug(f"Should run device fetch? {last_fetch_datetime=}, {device_fetch_interval=}")
    return datetime_now - last_fetch_datetime > device_fetch_interval


""" MAIN FUNCTION """


def main():  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    last_run = demisto.getLastRun()
    access_token = demisto.getIntegrationContext().get("access_token")
    api_key = params.get("credentials", {}).get("password")
    base_url = urljoin(params.get("server_url"), API_V1_ENDPOINT)
    verify_certificate = not params.get("insecure", True)
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    devices_max_fetch = arg_to_number(params.get("devices_max_fetch")) or DEVICES_DEFAULT_MAX_FETCH
    proxy = params.get("proxy", False)
    event_types_to_fetch = argToList(params.get("event_types_to_fetch", []))
    event_types_to_fetch = [event_type.strip(" ") for event_type in event_types_to_fetch]
    should_push_events = argToBoolean(args.get("should_push_events", False))
    from_date = args.get("from_date")
    fetch_start_time = handle_from_date_argument(from_date) if from_date else None
    parsed_interval = dateparser.parse(params.get("deviceFetchInterval", "24 hours")) or dateparser.parse("24 hours")
    device_fetch_interval: timedelta = datetime.now() - parsed_interval  # type: ignore[operator]
    fetch_delay = arg_to_number(params.get("fetch_delay")) or DEFAULT_FETCH_DELAY

    demisto.debug(f"Command being called is {command}")

    try:
        # Multithreading is always on; the context manager is required for thread-safe operations.
        context_manager = IntegrationContextManager()

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            proxy=proxy,
            api_key=api_key,
            access_token=access_token,
            context_manager=context_manager,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command in ("fetch-events", "armis-get-events"):
            should_return_results = False

            if not last_run:  # initial fetch - update last fetch time values to current time
                set_last_run_for_last_minute(last_run)
                demisto.debug("Initial fetch - updating last fetch time value to current time for each event type.")

            if command == "armis-get-events":
                event_type_name = args.get("event_type")
                if aql := args.get("aql"):
                    EVENT_TYPES[event_type_name].aql_query = aql
                event_type: EVENT_TYPE = EVENT_TYPES[event_type_name]
                last_run = {}
                should_return_results = True
                event_types_to_fetch = [event_type_name]
                fetch_delay = 0

            should_push_events = command == "fetch-events" or should_push_events

            events, next_run = fetch_events(
                client=client,
                max_fetch=max_fetch,
                devices_max_fetch=devices_max_fetch,
                last_run=last_run,
                fetch_start_time=fetch_start_time,
                event_types_to_fetch=event_types_to_fetch,
                device_fetch_interval=device_fetch_interval,
                fetch_delay=fetch_delay,
                use_multithreading=command == "fetch-events",
                context_manager=context_manager,
            )
            for key, value in events.items():
                demisto.debug(f"{len(value)} events of type: {key} fetched from armis api")

            if should_push_events:
                handle_fetched_events(events, next_run)

            if should_return_results:
                return_results(
                    events_to_command_results(events=events, event_type=event_type.dataset_name)  # pylint: disable=E0606
                )

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")  # noqa: E231


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
