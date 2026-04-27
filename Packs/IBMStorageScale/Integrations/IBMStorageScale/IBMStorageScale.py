import asyncio
import hashlib
import httpx
from datetime import UTC as _UTC  # type: ignore[attr-defined]
from datetime import tzinfo
from urllib.parse import urlparse, urlencode, quote_plus

UTC = _UTC

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# --- CONSTANTS ---
API_ENDPOINT = "/scalemgmt/v2/cliauditlog"
PRODUCT = "StorageScale"
VENDOR = "IBM"

DEDUPLICATION_WINDOW_MINUTES = 2
MAX_STORED_HASHES = 10000  # Cap dedup cache to 10k: handles short high-EPS bursts (1-min window) while bounding memory

DEFAULT_PAGE_SIZE = 1000  # Default page size for IBM Storage Scale API
DEFAULT_FIRST_FETCH_MINUTES = 1  # Default minutes to look back on first fetch

# Hash substring length to show in logs for readability while minimizing noise
HASH_LOG_PREVIEW_LEN = 12

# Maximum number of sample hash timestamps to include in debug info
MAX_SAMPLE_SIZE = 5

# Time/regex formatting
ISO_MINUTE_FORMAT = "%Y-%m-%dT%H:%M"  # Minute bucket (chosen to keep filter length bounded)
SECOND_WILDCARD_REGEX = "[0-5][0-9]"  # Seconds 00-59 as a compact class
TIME_BUCKET_MINUTES = 1  # Step across minutes when constructing time-window regex


# --- TIMEZONE HELPERS ---
def set_dt_to_utc(dt: datetime) -> datetime:
    """
    Return a timezone-aware UTC datetime for any naive or tz-aware input.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def to_iso_z(dt: datetime, *, timespec: str = "seconds") -> str:
    """
    Convert datetime to ISO-8601 with 'Z' suffix (UTC).
    """
    dt_utc = set_dt_to_utc(dt)
    return dt_utc.isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_iso_to_utc(s: str) -> datetime:
    """
    Parse an ISO-8601 string which may end with 'Z' or include an offset,
    returning a timezone-aware UTC datetime. If parsing fails, fall back to now(UTC).
    """
    try:
        if s.endswith("Z"):
            s = s.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        return set_dt_to_utc(dt)
    except Exception as e:
        demisto.debug(f"parse_iso_to_utc: failed to parse '{s}': {e}; falling back to now(UTC)")
        return set_dt_to_utc(datetime.now())


def parse_timezone_param(tz_param: str | None) -> tuple[tzinfo, str]:
    """
    Parse a timezone parameter into a tzinfo. Supports:
    - IANA names (e.g., "UTC", "America/New_York") via zoneinfo
    - Fixed offsets like "+03:00", "-0500", "UTC+2", "-7"

    Returns a tuple of (tzinfo, normalized_name)
    """
    if not tz_param:
        return UTC, "UTC"

    tz_param = tz_param.strip()
    # Common UTC indicators
    if tz_param.upper() in {"UTC", "Z", "GMT", "UTC+0", "UTC-0", "Etc/UTC"}:
        return UTC, "UTC"

    # Try to parse fixed offset formats
    m = re.fullmatch(r"(?i)(?:UTC)?\s*([+-])\s*(\d{1,2})(?::?(\d{2}))?$", tz_param)
    if m:
        sign, hh, mm = m.group(1), m.group(2), m.group(3)
        hours = int(hh)
        minutes = int(mm) if mm is not None else 0
        if hours > 23 or minutes > 59:
            demisto.debug(f"parse_timezone_param: invalid offset values in '{tz_param}', defaulting to UTC")
            return UTC, "UTC"
        delta = timedelta(hours=hours, minutes=minutes)
        if sign == "-":
            delta = -delta
        return timezone(delta), f"UTC{sign}{hours:02d}:{minutes:02d}"

    demisto.debug(f"parse_timezone_param: could not parse '{tz_param}', defaulting to UTC")
    return UTC, "UTC"


# --- UTILITY FUNCTIONS ---
def generate_event_hash(event: dict[str, Any]) -> str:
    """
    Generate a unique hash for an event based on key identifying fields.
    Uses fields that uniquely identify an event to prevent duplicates.
    """
    # Key fields that should uniquely identify an event
    hash_fields = [
        event.get("oid", ""),  # Object ID
        event.get("entryTime", ""),  # Timestamp
        event.get("user", ""),  # User who executed command
        event.get("command", ""),  # Command executed
        event.get("node", ""),  # Node where command was executed
        event.get("originator", ""),  # Originator of the command
        event.get("returnCode", ""),  # Return code
    ]

    # Create a deterministic string from the key fields
    hash_string = "|".join(str(field) for field in hash_fields)

    # Generate SHA256 hash
    return hashlib.sha256(hash_string.encode("utf-8")).hexdigest()


def get_stored_event_hashes() -> dict[str, str]:
    """
    Retrieve stored event hashes from last run object.
    Returns dict with hash as key and timestamp as value.
    """
    last_run = demisto.getLastRun()
    return last_run.get("event_hashes", {})


def store_event_hashes(event_hashes: dict[str, str]) -> None:
    """
    Store event hashes in last run object with timestamp cleanup.
    Keeps only recent hashes within DEDUPLICATION_WINDOW_MINUTES and caps total to MAX_STORED_HASHES.

    Sorting rationale: we sort by timestamp descending to retain the *most recent* hashes when trimming
    the cache to MAX_STORED_HASHES, maximizing dedup effectiveness for the next fetch window.
    """
    # Clean up old hashes outside the deduplication window
    current_time = set_dt_to_utc(datetime.utcnow())
    cutoff_time = to_iso_z(current_time - timedelta(minutes=DEDUPLICATION_WINDOW_MINUTES))

    cleaned_hashes: dict[str, str] = {}
    for hash_val, timestamp in event_hashes.items():
        # timestamps stored as ISO Z strings; lexicographic compare works for ISO-8601
        if timestamp >= cutoff_time:
            cleaned_hashes[hash_val] = timestamp

    # Limit the number of stored hashes to prevent memory issues
    if len(cleaned_hashes) > MAX_STORED_HASHES:
        # Keep only the most recent hashes (see rationale above)
        sorted_hashes = sorted(cleaned_hashes.items(), key=lambda x: x[1], reverse=True)
        cleaned_hashes = dict(sorted_hashes[:MAX_STORED_HASHES])

    # Update last run with cleaned hashes
    last_run = demisto.getLastRun()
    last_run["event_hashes"] = cleaned_hashes
    demisto.setLastRun(last_run)
    demisto.debug(f"Stored {len(cleaned_hashes)} event hashes for deduplication")


def deduplicate_events(events: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """
    Remove duplicate events using stored hashes and return deduplication stats.

    Returns:
        tuple: (deduplicated_events, stats_dict)
    """
    if not events:
        return events, {"total_events": 0, "duplicates_found": 0, "unique_events": 0}

    stored_hashes = get_stored_event_hashes()
    new_hashes: dict[str, str] = {}
    deduplicated_events: list[dict[str, Any]] = []
    duplicates_found = 0

    for event in events:
        event_hash = generate_event_hash(event)
        event_time = event.get("entryTime", to_iso_z(datetime.utcnow()))

        # Check if this event hash already exists
        if event_hash in stored_hashes:
            duplicates_found += 1
            demisto.debug(f"Duplicate event found with hash {event_hash[:HASH_LOG_PREVIEW_LEN]}...")
            continue

        # Add to deduplicated events and track new hash
        deduplicated_events.append(event)
        new_hashes[event_hash] = event_time

    # Merge new hashes with stored hashes and store
    all_hashes = {**stored_hashes, **new_hashes}
    store_event_hashes(all_hashes)

    stats = {
        "total_events": len(events),
        "duplicates_found": duplicates_found,
        "unique_events": len(deduplicated_events),
        "stored_hashes_count": len(all_hashes),
    }

    demisto.debug(f"Deduplication complete: {stats}")
    return deduplicated_events, stats


def get_fetch_start_time() -> datetime:
    """
    Get the start time for the fetch window from the last run object.
    Returns a timezone-aware UTC datetime.
    """
    last_run = demisto.getLastRun()
    last_fetch_time_str = last_run.get("last_fetch_time")

    if last_fetch_time_str:
        demisto.debug(f"Using last fetch time from last run: {last_fetch_time_str}")
        return parse_iso_to_utc(last_fetch_time_str)
    else:
        # First run - use default lookback period (minutes)
        start_time = set_dt_to_utc(datetime.utcnow() - timedelta(minutes=DEFAULT_FIRST_FETCH_MINUTES))
        demisto.debug(f"First run - using default lookback time: {to_iso_z(start_time)}")
        return start_time


def update_last_run_time(new_fetch_time: datetime) -> None:
    """
    Update the last run object with the given timestamp (stored as ISO-8601 with 'Z').
    """
    last_run = demisto.getLastRun()
    last_run["last_fetch_time"] = to_iso_z(new_fetch_time)
    demisto.setLastRun(last_run)
    demisto.debug(f"Updated last run with fetch time: {last_run['last_fetch_time']}")


def generate_time_filter_regex(start_time: datetime, end_time: datetime, *, server_tz: tzinfo = UTC) -> str:
    """
    Generates a regex for the 'entryTime' field to cover the given time window.
    The regex covers full minutes (seconds wildcard), relying on deduplication to handle overlaps.

    Example:
        >>> s = parse_iso_to_utc("2025-08-07T14:30:00Z")
        >>> e = parse_iso_to_utc("2025-08-07T14:32:15Z")
        >>> generate_time_filter_regex(s, e)
        '2025-08-07T14:30:[0-5][0-9]|2025-08-07T14:31:[0-5][0-9]|2025-08-07T14:32:[0-5][0-9]'
    """
    # Normalize to server local time and floor the start time to the beginning of the minute
    start_time = set_dt_to_utc(start_time).astimezone(server_tz)
    end_time = set_dt_to_utc(end_time).astimezone(server_tz)

    current_minute = start_time.replace(second=0, microsecond=0)
    regex_parts: list[str] = []

    # Iterate minute by minute through the time window
    while current_minute <= end_time:
        minute_prefix = current_minute.strftime(ISO_MINUTE_FORMAT)
        # Create a regex for all 60 seconds within that minute
        regex_parts.append(f"{minute_prefix}:{SECOND_WILDCARD_REGEX}")
        # Move to the next minute
        current_minute += timedelta(minutes=TIME_BUCKET_MINUTES)

    if not regex_parts:
        minute_prefix = start_time.strftime(ISO_MINUTE_FORMAT)
        return f"{minute_prefix}:{SECOND_WILDCARD_REGEX}"

    # Join all minute-regexes with an OR operator
    return "|".join(regex_parts)


def build_fetch_query(limit: int, start_time: datetime, end_time: datetime, *, server_tz: tzinfo = UTC) -> str:
    """
    Build API query string with regex filtering for time.
    Uses urllib.parse.urlencode to avoid manual concatenation and stray ampersands.
    """
    regex_filter = generate_time_filter_regex(start_time, end_time, server_tz=server_tz)
    params: dict[str, str | int] = {"fields": ":all:", "limit": limit}
    if regex_filter:
        # The API expects triple-quoted regex value: entryTime='''<regex>'''
        params["filter"] = f"entryTime='''{regex_filter}'''"
    # Preserve characters we intend to send verbatim (quotes, brackets, colon, pipe)
    # IMPORTANT: keep '=' unencoded inside the filter value. IBM Storage Scale filter parser
    # requires a literal '=' in the expression (entryTime='''<regex>'''). If encoded as '%3D',
    # the server returns empty results. Therefore, include '=' in the safe set.
    return urlencode(params, safe=":'|[]=", quote_via=quote_plus)


def build_minute_fetch_queries(limit: int, start_time: datetime, end_time: datetime, *, server_tz: tzinfo = UTC) -> list[str]:
    """
    Build a list of API query strings, one per minute between start_time and end_time inclusive.

    Rationale: Some IBM Storage Scale deployments do not accept alternation ('|') in regex filters.
    To ensure compatibility, we avoid using '|' entirely and instead send multiple requests,
    each matching a single minute using the seconds wildcard.

    Example single-minute filter: entryTime='''2025-06-19T13:17:[0-5][0-9]'''
    """
    # Convert the window to the server's local time for building the regex filters
    start_time = set_dt_to_utc(start_time).astimezone(server_tz).replace(second=0, microsecond=0)
    end_time = set_dt_to_utc(end_time).astimezone(server_tz).replace(second=0, microsecond=0)

    queries: list[str] = []
    current = start_time
    while current <= end_time:
        minute_prefix = current.strftime(ISO_MINUTE_FORMAT)
        regex_filter = f"{minute_prefix}:{SECOND_WILDCARD_REGEX}"
        params: dict[str, str | int] = {"fields": ":all:", "limit": limit}
        params["filter"] = f"entryTime='''{regex_filter}'''"
        queries.append(urlencode(params, safe=":'|[]=", quote_via=quote_plus))
        current += timedelta(minutes=TIME_BUCKET_MINUTES)

    # Ensure at least one query exists (edge case if start > end due to clock issues)
    if not queries:
        minute_prefix = start_time.strftime(ISO_MINUTE_FORMAT)
        regex_filter = f"{minute_prefix}:{SECOND_WILDCARD_REGEX}"
        params = {"fields": ":all:", "limit": limit, "filter": f"entryTime='''{regex_filter}'''"}
        queries.append(urlencode(params, safe=":'|[]=", quote_via=quote_plus))

    return queries


class Client:
    """
    A unified, high-performance async client for the IBM Storage Scale API.

    This class manages all API interactions, using httpx.AsyncClient for
    connection pooling and asyncio for concurrent operations.
    """

    def __init__(
        self,
        server_url: str,
        auth: tuple[str | bytes, str | bytes],
        verify: bool,
        proxy: str | None,
        concurrency: int = 5,
        server_tz: tzinfo = UTC,
        server_tz_name: str = "UTC",
    ):
        self.base_url = server_url
        self.auth = auth
        self.verify = verify
        self.proxy = proxy
        self.concurrency = concurrency
        self.server_tz = server_tz
        self.server_tz_name = server_tz_name

    async def test_connection(self):
        """
        Performs a connection test using the async client to validate credentials and connectivity.
        This ensures the test path is identical to the operational path.
        """
        async with httpx.AsyncClient(base_url=self.base_url, auth=self.auth, verify=self.verify, proxy=self.proxy) as client:
            try:
                response = await client.get(f"{API_ENDPOINT}?fields=:all:")
                response.raise_for_status()
            except httpx.HTTPStatusError as e:
                if e.response.status_code in (401, 403):
                    raise DemistoException(
                        "Authorization Error: Ensure the credentials are correct and have the required permissions."
                    )
                raise DemistoException(f"HTTP Error: Failed to connect to API. Status code: {e.response.status_code}")
            except httpx.RequestError as e:
                raise DemistoException(f"Connection Error: Could not connect to {self.base_url}. Reason: {e}")

    async def get_events(self, limit: int | None) -> tuple[list[dict[str, Any]], bool]:
        """
        Orchestrates fetching events for manual commands, returning them for display.
        """
        fetcher = _ConcurrentEventFetcher(self, limit or DEFAULT_PAGE_SIZE)
        events, has_more = await fetcher.run()
        return events, has_more

    async def fetch_events(self, max_events: int | None) -> None:
        """
        Orchestrates the high-performance, concurrent fetching of events for ingestion.
        """
        demisto.info("Starting fetch-events cycle.")
        start_time_mono = time.monotonic()

        # Define the fetch window using the regex method (with small overlap to avoid boundary misses)
        fetch_window_end_time = set_dt_to_utc(datetime.utcnow())
        base_start_time = get_fetch_start_time()
        overlap_seconds = 30
        fetch_window_start_time = base_start_time - timedelta(seconds=overlap_seconds)
        demisto.info(
            f"Fetching events from {to_iso_z(fetch_window_start_time)} to {to_iso_z(fetch_window_end_time)} "
            f"(overlap={overlap_seconds}s)"
        )

        # Build minute-scoped queries to avoid unsupported '|' alternation in regex filters
        queries = build_minute_fetch_queries(
            max_events or DEFAULT_PAGE_SIZE, fetch_window_start_time, fetch_window_end_time, server_tz=self.server_tz
        )

        fetcher = _ConcurrentEventFetcher(self, max_events or DEFAULT_PAGE_SIZE, initial_queries=queries)
        events, has_more = await fetcher.run()

        # Apply deduplication
        deduplicated_events, dedup_stats = deduplicate_events(events)
        demisto.info(
            f"Deduplication: {dedup_stats['duplicates_found']} duplicates removed, "
            f"{dedup_stats['unique_events']} unique events processed"
        )

        # Update last run time to the end of the window we just fetched
        update_last_run_time(fetch_window_end_time)

        # Update fetch health metrics in last run without altering last_fetch_time
        try:
            last_run = demisto.getLastRun()
            last_run["last_fetch_attempt_time"] = to_iso_z(fetch_window_end_time)
            if dedup_stats.get("unique_events", 0) > 0:
                last_run["last_successful_fetch_time"] = to_iso_z(fetch_window_end_time)
                last_run["consecutive_empty_runs"] = 0
                demisto.info("This fetch cycle ingested events; resetting consecutive_empty_runs to 0.")
            else:
                last_run["consecutive_empty_runs"] = int(last_run.get("consecutive_empty_runs", 0)) + 1
                demisto.info(f"No new events ingested. consecutive_empty_runs={last_run['consecutive_empty_runs']}")
            demisto.setLastRun(last_run)
        except Exception as e:
            demisto.debug(f"Failed to update fetch health metrics: {e}")

        end_time_mono = time.monotonic()
        duration = end_time_mono - start_time_mono
        total_events = len(deduplicated_events)
        eps = total_events / duration if duration > 0 else 0

        performance_summary = (
            f"Fetch cycle finished. Fetched {total_events} unique events (filtered {dedup_stats['duplicates_found']} duplicates) "
            f"in {duration:.2f} seconds ({eps:.2f} events/sec)."
        )
        demisto.info(performance_summary)

        for event in deduplicated_events:
            event["_time"] = event.get("entryTime")

        push_events_start_time = time.monotonic()
        demisto.debug("Pushing events to XSIAM.")
        send_events_to_xsiam(events=deduplicated_events, vendor=VENDOR, product=PRODUCT)
        push_events_end_time = time.monotonic()
        push_events_duration = push_events_end_time - push_events_start_time
        demisto.info(f"Pushed events to XSIAM. Completed push process in {push_events_duration} seconds.")

        if has_more:
            demisto.info("Fetch cycle reached the event limit. More events may be available on the server.")

    async def debug_connection_info(self) -> dict[str, Any]:
        """
        Comprehensive debugging command to provide troubleshooting information.
        """
        debug_info: dict[str, Any] = {
            "connection_status": "unknown",
            "server_url": self.base_url,
            "api_endpoint": API_ENDPOINT,
            "last_run_info": {},
            "current_time": to_iso_z(datetime.utcnow()),
            "configuration": {},
            "sample_api_response": {},
            "time_filter_info": {},
            "deduplication_info": {},
            "error_details": None,
        }

        try:
            # Test basic connection
            async with httpx.AsyncClient(base_url=self.base_url, auth=self.auth, verify=self.verify, proxy=self.proxy) as client:
                response = await client.get(f"{API_ENDPOINT}?limit=1&fields=oid,entryTime")
                response.raise_for_status()
                debug_info["connection_status"] = "success"

                # Get sample response
                data = response.json()
                debug_info["sample_api_response"] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "sample_data": data,
                }

        except Exception as e:
            debug_info["connection_status"] = "failed"
            debug_info["error_details"] = str(e)

        # Get last run information
        try:
            last_run = demisto.getLastRun()
            debug_info["last_run_info"] = {
                "last_fetch_time": last_run.get("last_fetch_time", "None (first run)"),
                "last_fetch_attempt_time": last_run.get("last_fetch_attempt_time"),
                "last_successful_fetch_time": last_run.get("last_successful_fetch_time"),
                "consecutive_empty_runs": last_run.get("consecutive_empty_runs", 0),
                "stored_event_hashes": len(last_run.get("event_hashes", {})),
                "last_run_raw": last_run,
            }
        except Exception as e:
            debug_info["last_run_info"] = {"error": str(e)}

        # Time filter information
        try:
            start_time = get_fetch_start_time()
            end_time = set_dt_to_utc(datetime.utcnow())
            queries = build_minute_fetch_queries(10, start_time, end_time, server_tz=self.server_tz)
            debug_info["time_filter_info"] = {
                "fetch_window_start": to_iso_z(start_time),
                "fetch_window_end": to_iso_z(end_time),
                "server_timezone": self.server_tz_name,
                "fetch_window_start_local": set_dt_to_utc(start_time).astimezone(self.server_tz).isoformat(timespec="seconds"),
                "fetch_window_end_local": set_dt_to_utc(end_time).astimezone(self.server_tz).isoformat(timespec="seconds"),
                "overlap_window_seconds": 30,
                "constructed_query": queries[0] if queries else None,
                "constructed_queries_total": len(queries),
                "full_url": f"{self.base_url}{API_ENDPOINT}?{queries[0]}" if queries else None,
            }
        except Exception as e:
            debug_info["time_filter_info"] = {"error": str(e)}

        # Deduplication information
        try:
            stored_hashes = get_stored_event_hashes()
            cutoff_time = to_iso_z(set_dt_to_utc(datetime.utcnow()) - timedelta(minutes=DEDUPLICATION_WINDOW_MINUTES))
            debug_info["deduplication_info"] = {
                "stored_hashes_count": len(stored_hashes),
                "deduplication_window_minutes": DEDUPLICATION_WINDOW_MINUTES,
                "cutoff_time": cutoff_time,
                "sample_hash_timestamps": list(stored_hashes.values())[:MAX_SAMPLE_SIZE] if stored_hashes else [],
            }
        except Exception as e:
            debug_info["deduplication_info"] = {"error": str(e)}

        # Configuration info (without sensitive data)
        debug_info["configuration"] = {
            "verify_ssl": self.verify,
            "proxy_configured": bool(self.proxy),
            "auth_configured": bool(self.auth and self.auth[0]),
            "concurrency_level": self.concurrency,
            "server_timezone": self.server_tz_name,
        }

        return debug_info


class _ConcurrentEventFetcher:
    """
    Internal helper class to manage the producer-consumer fetching logic.
    This revised implementation uses a more robust concurrent crawling model where any worker
    can queue the next page of work.
    """

    def __init__(self, client: Client, max_events: int, query: str = "", initial_queries: list[str] | None = None):
        self.client = client
        self.max_events = max_events
        self.query = query
        self.initial_queries = initial_queries or []
        self.queue: asyncio.Queue = asyncio.Queue()
        self.collected_events: list[dict[str, Any]] = []
        self.has_more_available = False
        self._lock = asyncio.Lock()

    async def _worker(self, name: str, async_client: httpx.AsyncClient):
        """Pulls a URL from the queue, fetches events, and queues the next URL."""
        while True:
            url_suffix = None
            try:
                url_suffix = await self.queue.get()
                demisto.debug(f"[{name}] got task: {url_suffix}")

                # Check if we should stop before making the API call
                should_stop = False
                async with self._lock:
                    if len(self.collected_events) >= self.max_events:
                        should_stop = True
                        self.has_more_available = True

                if should_stop:
                    demisto.debug(f"[{name}] stopping, max events limit reached before processing task.")
                    continue  # Go to finally block to mark task as done

                response = await async_client.get(url_suffix)
                response.raise_for_status()
                data = response.json()
                events = data.get("auditLogRecords", [])
                demisto.debug(f"[{name}] fetched {len(events)} events from {url_suffix}")

                # Add events to the shared list under a lock
                async with self._lock:
                    if len(self.collected_events) < self.max_events:
                        remaining_space = self.max_events - len(self.collected_events)
                        self.collected_events.extend(events[:remaining_space])
                        demisto.debug(f"[{name}] total events collected: {len(self.collected_events)}")

                # Queue next page if present
                paging_info = data.get("paging", {})
                next_full_url = paging_info.get("next")
                if next_full_url and len(self.collected_events) < self.max_events:
                    parsed = urlparse(next_full_url)
                    next_url_suffix = f"{parsed.path}?{parsed.query}"
                    demisto.debug(f"[{name}] queuing next URL: {next_url_suffix}")
                    await self.queue.put(next_url_suffix)

            except httpx.HTTPStatusError as e:
                demisto.error(f"[{name}] failed to process page {url_suffix} with status {e.response.status_code}: {e}")
            except Exception as e:
                demisto.error(f"[{name}] failed to process page {url_suffix}: {e}")
            finally:
                if url_suffix is not None:
                    self.queue.task_done()

    async def run(self) -> tuple[list[dict[str, Any]], bool]:
        """Orchestrates the workers to fetch all events."""
        # Seed the queue with the first page
        if self.initial_queries:
            for q in self.initial_queries:
                self.queue.put_nowait(f"{API_ENDPOINT}?{q}")
        else:
            if self.query:
                initial_url = f"{API_ENDPOINT}?{self.query}"
            else:
                params = {"fields": ":all:", "limit": self.max_events}
                initial_url = f"{API_ENDPOINT}?{urlencode(params, safe=':', quote_via=quote_plus)}"
            self.queue.put_nowait(initial_url)

        async with httpx.AsyncClient(
            base_url=self.client.base_url, auth=self.client.auth, verify=self.client.verify, proxy=self.client.proxy
        ) as async_client:
            # Create a pool of workers to process the queue
            worker_tasks = [
                asyncio.create_task(self._worker(f"Worker-{i}", async_client)) for i in range(self.client.concurrency)
            ]

            # Wait for the queue to be fully processed
            await self.queue.join()
            demisto.debug("Queue processing complete. Cancelling workers.")

            # Cancel all worker tasks
            for task in worker_tasks:
                task.cancel()
            await asyncio.gather(*worker_tasks, return_exceptions=True)

        demisto.debug(f"Fetcher finished. Total events: {len(self.collected_events)}")
        return self.collected_events[: self.max_events], self.has_more_available


async def main() -> None:
    """Main function, serves as the orchestra for the integration."""
    params = demisto.params()
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")

    # Handle whether integration is in debug mode. If so, set the environment variable
    # to enable asyncio debugging
    if is_debug_mode():
        os.environ["PYTHONASYNCIODEBUG"] = "1"

    # Get proxy settings as a dictionary
    proxies = handle_proxy()

    # Select a single proxy URL, prioritizing HTTPS, then HTTP
    proxy_url = proxies.get("https") or proxies.get("http") or None

    try:
        # Parse server timezone parameter (defaults to UTC)
        tzinfo, tzname = parse_timezone_param(params.get("server_timezone"))

        client = Client(
            server_url=params.get("server_url"),
            auth=(params.get("credentials", {}).get("identifier"), params.get("credentials", {}).get("password")),
            verify=not params.get("insecure", False),
            proxy=proxy_url,
            server_tz=tzinfo,
            server_tz_name=tzname,
        )

        if command == "test-module":
            await client.test_connection()
            return_results("ok")
        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch", "10000"))
            await client.fetch_events(max_fetch)
        elif command == "ibm-storage-scale-get-events":
            limit = arg_to_number(demisto.args().get("limit", 50))
            should_push_events = argToBoolean(demisto.args().get("should_push_events", False))
            events, _ = await client.get_events(limit=limit)
            if should_push_events:
                push_events_start_time = time.monotonic()
                demisto.debug("Pushing events to XSIAM.")
                for event in events:
                    event["_time"] = event.get("entryTime")
                send_events_to_xsiam(events=events, vendor=VENDOR, product=PRODUCT)
                push_events_end_time = time.monotonic()
                push_events_duration = push_events_end_time - push_events_start_time
                demisto.info(f"Pushed events to XSIAM. Completed in {push_events_duration} seconds.")
            command_results = CommandResults(
                outputs_prefix="IBMStorageScale.AuditLog",
                outputs_key_field="oid",
                outputs=events,
                readable_output=tableToMarkdown(
                    f"IBM Storage Scale Events (first {len(events)} events)",
                    events,
                    headers=["entryTime", "user", "command", "node", "returnCode", "originator"],
                    removeNull=True,
                    headerTransform=pascalToSpace,
                ),
            )
            return_results(command_results)
        elif command == "ibm-storage-scale-debug-connection":
            debug_info = await client.debug_connection_info()
            command_results = CommandResults(
                outputs_prefix="IBMStorageScale.Debug",
                outputs=debug_info,
                readable_output=tableToMarkdown(
                    "IBM Storage Scale Debug Information",
                    [debug_info],
                    headers=["connection_status", "server_url", "current_time", "api_endpoint"],
                    removeNull=True,
                    headerTransform=string_to_table_header,
                ),
            )
            return_results(command_results)
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command}. Error: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    try:
        asyncio.run(main())
    except Exception as e:
        # Fallback error handling: pretty error with stack trace for easier troubleshooting
        try:
            cmd = demisto.command()
        except Exception:
            cmd = "unknown"
        exc_type = type(e).__name__
        tb = traceback.format_exc()
        demisto.error(f"Unhandled exception in entrypoint for command '{cmd}': {exc_type}: {e}\n{tb}")
        pretty_message = (
            f"IBM Storage Scale: failed to execute command '{cmd}'.\n"
            f"Exception: {exc_type}\n"
            f"Message: {e}\n\n"
            f"Traceback:\n{tb}"
        )
        return_error(pretty_message)
