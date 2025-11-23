import urllib3
from datetime import datetime, timedelta
from typing import Any
import threading
import queue
from dataclasses import dataclass, field
from enum import Enum
import time

import demistomock as demisto
from CommonServerPython import *  # noqa # pylylint: disable=unused-wildcard-import

# Disable insecure warnings
urllib3.disable_warnings()

VENDOR = "twilio"
PRODUCT = "sendgrid"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSIAM
MAX_EVENTS_PER_FETCH = 1000
DEFAULT_MAX_FETCH = 10000

# Producer-Consumer constants
QUEUE_MAX_SIZE = 1000
CONSUMER_BATCH_SIZE = 100
PRODUCER_TIMEOUT = 30
CONSUMER_TIMEOUT = 5
MAX_CONSUMER_THREADS = 3


""" PRODUCER-CONSUMER DATA STRUCTURES """


class EventBatchStatus(Enum):
    """
    Enum for the status of an event batch.
    """

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class EventBatch:
    """
    A batch of events with metadata for processing.
    """

    events: list[dict[str, Any]]
    batch_id: int
    timestamp: datetime = field(default_factory=datetime.utcnow)
    status: EventBatchStatus = field(default=EventBatchStatus.PENDING)
    retry_count: int = 0


class ProducerConsumerMetrics:
    """
    A thread-safe class for tracking metrics in the producer-consumer model.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.events_produced = 0
        self.events_consumed = 0
        self.batches_processed = 0
        self.duplicates_filtered = 0
        self.error_count = 0
        self.start_time = time.time()

    def increment_produced(self, count: int):
        with self._lock:
            self.events_produced += count

    def increment_consumed(self, count: int):
        with self._lock:
            self.events_consumed += count
            self.batches_processed += 1

    def increment_duplicates(self, count: int):
        with self._lock:
            self.duplicates_filtered += count

    def increment_errors(self):
        with self._lock:
            self.error_count += 1

    def get_summary(self) -> str:
        with self._lock:
            elapsed_time = time.time() - self.start_time
            rate = self.events_consumed / elapsed_time if elapsed_time > 0 else 0
            return (
                f"Producer-Consumer Metrics Summary:\n"
                f"  - Events Produced: {self.events_produced}\n"
                f"  - Events Consumed: {self.events_consumed}\n"
                f"  - Batches Processed: {self.batches_processed}\n"
                f"  - Duplicates Filtered: {self.duplicates_filtered}\n"
                f"  - Errors: {self.error_count}\n"
                f"  - Processing Rate: {rate:.2f} events/sec"
            )


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Client for Twilio SendGrid Email Activity API.

    Handles API authentication with Bearer token and HTTP requests to /v3/messages endpoint.
    """

    def __init__(self, base_url: str, api_key: str, verify: bool = True, proxy: bool = False):
        """
        Initialize the SendGrid client.

        Args:
            base_url: The base URL for the SendGrid API (e.g., 'api.sendgrid.com')
            api_key: The SendGrid API secret key
            verify: Whether to verify SSL certificates
            proxy: Whether to use system proxy settings
        """
        # Ensure base_url has https:// prefix
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers=headers)

    def get_email_activity(self, query: str, limit: int = DEFAULT_MAX_FETCH) -> list[dict[str, Any]]:
        """
        Fetch email activity events from SendGrid.

        Args:
            query: Filter query string (e.g., "last_event_time BETWEEN '2024-01-01' AND '2024-01-02'")
            limit: Maximum number of events to return (1-1000)

        Returns:
            List of email activity event dictionaries

        Raises:
            DemistoException: If the API request fails
        """
        # Validate limit
        if limit < 1 or limit > MAX_EVENTS_PER_FETCH:
            raise DemistoException(f"Limit must be between 1 and {MAX_EVENTS_PER_FETCH}. Got: {limit}")

        params = {"query": query, "limit": limit}

        demisto.debug(f"Fetching email activity with query: {query}, limit: {limit}")

        try:
            response = self._http_request(
                method="GET", url_suffix="/v3/messages", params=params, timeout=60, retries=3, backoff_factor=2
            )

            # The response should contain a 'messages' key with the list of events
            messages = response.get("messages", [])
            demisto.debug(f"Retrieved {len(messages)} email activity events")

            return messages

        except DemistoException as e:
            error_msg = str(e)

            # Handle specific error codes
            if "401" in error_msg or "403" in error_msg:
                demisto.error(f"Authentication error: {error_msg}")
                raise DemistoException(
                    "Authentication failed. Please verify your API Secret Key is correct and has the necessary permissions."
                )
            elif "429" in error_msg:
                demisto.info(f"Rate limit hit: {error_msg}")
                raise
            elif "5" in error_msg and any(code in error_msg for code in ["500", "502", "503", "504"]):
                demisto.info(f"Server error: {error_msg}")
                raise
            else:
                demisto.error(f"API request failed: {error_msg}")
                raise


""" HELPER FUNCTIONS """


def build_query_filter(from_time: str, to_time: str | None = None) -> str:
    """
    Build a SendGrid query filter string for the API.

    Args:
        from_time: Start time in ISO format (e.g., '2024-01-15T10:00:00Z')
        to_time: Optional end time in ISO format

    Returns:
        Query filter string for the SendGrid API
    """
    if to_time:
        query = f"last_event_time BETWEEN TIMESTAMP '{from_time}' AND TIMESTAMP '{to_time}'"
    else:
        query = f"last_event_time > TIMESTAMP '{from_time}'"

    demisto.debug(f"Built query filter: {query}")
    return query


def get_last_event_time(last_run: dict[str, Any]) -> str:
    """
    Get the starting timestamp for fetching events.

    Args:
        last_run: Dictionary containing the last fetch timestamp

    Returns:
        ISO format timestamp string
    """
    last_fetch_time = last_run.get("last_event_time")

    if last_fetch_time:
        demisto.debug(f"Using last_event_time from last_run: {last_fetch_time}")
        return last_fetch_time

    # First fetch - default to 1 minute ago
    demisto.debug("First fetch - defaulting to 1 minute ago")
    first_fetch_dt = datetime.utcnow() - timedelta(minutes=1)

    return first_fetch_dt.strftime(DATE_FORMAT)


def deduplicate_events(
    events: list[dict[str, Any]], previous_ids: set[str], last_time: str
) -> tuple[list[dict[str, Any]], set[str]]:
    """
    Remove duplicate events based on message_id.

    This function filters out events that were processed in the previous run
    by tracking message IDs from the latest timestamp bracket.

    Args:
        events: List of events fetched from the API
        previous_ids: Set of message IDs from the previous run's latest timestamp
        last_time: The last_event_time from the previous run

    Returns:
        Tuple of (unique_events, new_previous_ids)
    """
    if not events:
        return [], set()

    unique_events = []
    last_run_timestamp = datetime.strptime(last_time, DATE_FORMAT)
    new_previous_ids = previous_ids.copy()
    duplicate_count = 0

    for event in events:
        message_id = event.get("msg_id") or event.get("message_id") or event.get("id")
        event_time_str = event.get("last_event_time")

        if not message_id or not event_time_str:
            demisto.debug(f"Event missing message_id or last_event_time, skipping: {event}")
            continue

        # Skip if this event was part of the last run's boundary check
        if message_id in previous_ids:
            duplicate_count += 1
            continue

        # Parse event timestamp
        try:
            event_timestamp = datetime.strptime(event_time_str, DATE_FORMAT)
        except ValueError:
            demisto.debug(f"Failed to parse event timestamp: {event_time_str}")
            continue

        # If this event's timestamp is newer than the last one we were tracking,
        # we've crossed the time boundary and can reset the ID tracking set
        if event_timestamp > last_run_timestamp:
            new_previous_ids = set()
            last_run_timestamp = event_timestamp

        new_previous_ids.add(message_id)
        unique_events.append(event)

    demisto.debug(
        f"Deduplication complete: {len(unique_events)} unique events, "
        f"{duplicate_count} duplicates filtered, "
        f"{len(new_previous_ids)} IDs tracked for next run"
    )

    return unique_events, new_previous_ids


def enrich_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Enrich events with XSIAM-required fields.

    Args:
        events: List of event dictionaries

    Returns:
        List of enriched event dictionaries
    """
    for event in events:
        # Map last_event_time to _time for XSIAM
        if "last_event_time" in event:
            event["_time"] = event["last_event_time"]

        # Add source log type
        event["source_log_type"] = "email_activity"

    return events


def update_last_run(last_run: dict[str, Any], events: list[dict[str, Any]], previous_ids: set[str]) -> dict[str, Any]:
    """
    Update the last_run dictionary with the latest timestamp and message IDs.

    Args:
        last_run: Current last_run dictionary
        events: List of events that were processed
        previous_ids: Set of message IDs from the latest timestamp bracket

    Returns:
        Updated last_run dictionary
    """
    if not events:
        demisto.debug("No events to update last_run with")
        return last_run

    # Get the latest event's timestamp
    latest_event = max(events, key=lambda e: e.get("last_event_time", ""))
    latest_time = latest_event.get("last_event_time")

    if latest_time:
        last_run["last_event_time"] = latest_time
        last_run["previous_ids"] = list(previous_ids)
        demisto.debug(f"Updated last_run: last_event_time={latest_time}, " f"previous_ids count={len(previous_ids)}")

    return last_run


""" COMMAND FUNCTIONS """


def sg_test_module(client: Client) -> str:
    """
    Test API connectivity and authentication.

    Args:
        client: SendGrid client instance

    Returns:
        'ok' if the test passed

    Raises:
        DemistoException: If the test fails
    """
    try:
        # Try to fetch a small number of events to test connectivity
        from_time = get_last_event_time({})
        query = build_query_filter(from_time)

        demisto.debug("Testing API connectivity...")
        client.get_email_activity(query=query, limit=1)

        demisto.debug("Test successful")
        return "ok"

    except Exception as e:
        demisto.error(f"Test module failed: {str(e)}")
        raise DemistoException(f"Test failed: {str(e)}")


def get_events_command(
    client: Client, args: dict[str, Any], last_run: dict[str, Any]
) -> tuple[list[dict[str, Any]], CommandResults]:
    """
    Manual command to fetch events (for debugging).

    Args:
        client: SendGrid client instance
        args: Command arguments
        last_run: Last run state

    Returns:
        Tuple of (events, CommandResults)
    """
    # Parse arguments
    limit = arg_to_number(args.get("limit", DEFAULT_MAX_FETCH)) or DEFAULT_MAX_FETCH
    from_date = args.get("from_date")
    to_date = args.get("to_date")

    # Determine from_time
    if from_date:
        from_time_dt = dateparser.parse(from_date, settings={"TIMEZONE": "UTC"})
        if not from_time_dt:
            raise DemistoException(f"Failed to parse from_date: {from_date}")
        from_time = from_time_dt.strftime(DATE_FORMAT)
    else:
        from_time = get_last_event_time(last_run)

    # Determine to_time
    to_time = None
    if to_date:
        to_time_dt = dateparser.parse(to_date, settings={"TIMEZONE": "UTC"})
        if not to_time_dt:
            raise DemistoException(f"Failed to parse to_date: {to_date}")
        to_time = to_time_dt.strftime(DATE_FORMAT)

    # Build query and fetch events
    query = build_query_filter(from_time, to_time)
    events = client.get_email_activity(query=query, limit=limit)

    # Enrich events
    enriched_events = enrich_events(events)

    demisto.debug(f"Retrieved {len(enriched_events)} events for get-events command")

    # Create human-readable output
    hr = tableToMarkdown(
        name="Twilio SendGrid Email Activity Events",
        t=enriched_events,
        headers=["msg_id", "from_email", "subject", "status", "last_event_time", "opens_count", "clicks_count"],
        removeNull=True,
    )

    command_results = CommandResults(
        readable_output=hr, outputs_prefix="TwilioSendGrid.EmailActivity", outputs_key_field="msg_id", outputs=enriched_events
    )

    return enriched_events, command_results


def fetch_events_command(client: Client, last_run: dict[str, Any], max_fetch: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Fetch events from SendGrid for XSIAM using the producer-consumer model.

    Args:
        client: SendGrid client instance
        last_run: Last run state from previous fetch
        max_fetch: Maximum events to fetch

    Returns:
        Tuple of (events, next_run)
    """
    return fetch_events_producer_consumer(client, last_run, max_fetch)


""" PRODUCER-CONSUMER CORE FUNCTIONS """


def _event_producer(
    client: Client,
    event_queue: queue.Queue,
    stop_event: threading.Event,
    metrics: ProducerConsumerMetrics,
    last_run: dict[str, Any],
    max_fetch: int,
):
    """
    The producer thread function. Fetches events from the API and puts them in the queue.
    """
    try:
        from_time = get_last_event_time(last_run)
        batch_id = 0
        total_fetched = 0

        while not stop_event.is_set() and (not max_fetch or total_fetched < max_fetch):
            limit = min(max_fetch - total_fetched, MAX_EVENTS_PER_FETCH) if max_fetch else MAX_EVENTS_PER_FETCH
            if limit <= 0:
                break

            query = build_query_filter(from_time)
            events = client.get_email_activity(query=query, limit=limit)

            if not events:
                demisto.debug("Producer: No more events found.")
                break

            event_batch = EventBatch(events=events, batch_id=batch_id)
            event_queue.put(event_batch, timeout=PRODUCER_TIMEOUT)
            metrics.increment_produced(len(events))
            total_fetched += len(events)
            batch_id += 1

            # Update from_time for the next iteration
            latest_event = max(events, key=lambda e: e.get("last_event_time", ""))
            from_time = str(latest_event.get("last_event_time"))

    except queue.Full:
        demisto.info("Producer: Event queue is full. Pausing.")
        metrics.increment_errors()
    except Exception as e:
        demisto.error(f"Producer thread encountered an error: {e}")
        metrics.increment_errors()
    finally:
        demisto.debug("Producer: Stopping.")
        stop_event.set()


def _event_consumer(
    event_queue: queue.Queue, stop_event: threading.Event, metrics: ProducerConsumerMetrics, last_run: dict[str, Any]
):
    """
    The consumer thread function. Gets events from the queue, processes, and sends them.
    """
    while not stop_event.is_set() or not event_queue.empty():
        try:
            event_batch = event_queue.get(timeout=CONSUMER_TIMEOUT)
            event_batch.status = EventBatchStatus.PROCESSING

            previous_ids = set(last_run.get("previous_ids", []))
            from_time = get_last_event_time(last_run)

            unique_events, new_previous_ids = deduplicate_events(event_batch.events, previous_ids, from_time)

            if unique_events:
                enriched_events = enrich_events(unique_events)
                send_events_to_xsiam(enriched_events, vendor=VENDOR, product=PRODUCT)
                metrics.increment_consumed(len(enriched_events))
                metrics.increment_duplicates(len(event_batch.events) - len(unique_events))

                # Update last_run for the main thread
                last_run.update(update_last_run(last_run, enriched_events, new_previous_ids))

            event_batch.status = EventBatchStatus.COMPLETED
            event_queue.task_done()

        except queue.Empty:
            continue
        except Exception as e:
            demisto.error(f"Consumer thread encountered an error: {e}")
            metrics.increment_errors()
            if "event_batch" in locals():
                event_batch.status = EventBatchStatus.FAILED
                event_batch.retry_count += 1
                if event_batch.retry_count <= 3:
                    event_queue.put(event_batch)  # Re-queue for retry
            time.sleep(1)


def fetch_events_producer_consumer(
    client: Client, last_run: dict[str, Any], max_fetch: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Orchestrates the producer-consumer pattern for fetching events.
    """
    metrics = ProducerConsumerMetrics()
    event_queue: queue.Queue[EventBatch] = queue.Queue(maxsize=QUEUE_MAX_SIZE)
    stop_event = threading.Event()

    producer = threading.Thread(target=_event_producer, args=(client, event_queue, stop_event, metrics, last_run, max_fetch))
    producer.start()

    consumers = []
    for i in range(MAX_CONSUMER_THREADS):
        consumer = threading.Thread(
            target=_event_consumer, args=(event_queue, stop_event, metrics, last_run), name=f"Consumer-{i + 1}"
        )
        consumer.start()
        consumers.append(consumer)

    producer.join()
    for consumer in consumers:
        consumer.join()

    demisto.debug(metrics.get_summary())
    return [], last_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Main function - parses params and runs command functions."""

    command = demisto.command()
    params = demisto.params()
    args = demisto.args()

    demisto.debug(f"Command being called: {command}")

    try:
        # Parse parameters
        server_url = params.get("server_url", "api.sendgrid.com")
        api_key = params.get("api_key", {}).get("password") or params.get("api_key")
        verify_certificate = not params.get("insecure", False)
        proxy = params.get("proxy", False)
        max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH)) or DEFAULT_MAX_FETCH

        # Validate max_fetch
        if max_fetch < 1 or max_fetch > MAX_EVENTS_PER_FETCH:
            raise DemistoException(f"Maximum Email Activity Messages per fetch must be between 1 and {MAX_EVENTS_PER_FETCH}")

        # Initialize client
        client = Client(base_url=server_url, api_key=api_key, verify=verify_certificate, proxy=proxy)

        # Get last run
        last_run = demisto.getLastRun()

        # Execute command
        if command == "test-module":
            result = sg_test_module(client)
            return_results(result)

        elif command == "twilio-sendgrid-get-events":
            events, command_results = get_events_command(client, args, last_run)
            return_results(command_results)

            # Push events to XSIAM if requested
            should_push = argToBoolean(args.get("should_push_events", False))
            if should_push and events:
                demisto.debug(f"Pushing {len(events)} events to XSIAM")
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

        elif command == "fetch-events":
            events, next_run = fetch_events_command(client, last_run, max_fetch)

            if events:
                demisto.debug(f"Sending {len(events)} events to XSIAM")
                # send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

                # Update last run
                demisto.debug(f"Setting next_run: {next_run}")
                demisto.setLastRun(next_run)
            else:
                demisto.debug("No events to send, last_run unchanged")

        else:
            raise NotImplementedError(f"Command {command} is not implemented")

    except Exception as e:
        demisto.error(f"Error in {command}: {str(e)}")
        return_error(f"Failed to execute {command} command.\nError: {str(e)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
