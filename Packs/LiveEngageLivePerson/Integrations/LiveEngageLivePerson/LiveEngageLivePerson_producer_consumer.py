
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import hashlib
import traceback
from typing import Any, Optional, Tuple
from datetime import datetime, timedelta
import random
import time
import threading
import queue
from dataclasses import dataclass
from enum import Enum

""" CONSTANTS """

INTEGRATION_NAME = "LivePerson"
INTEGRATION_PREFIX = f"[{INTEGRATION_NAME}]"
DEFAULT_MAX_FETCH = 5000
API_PAGE_SIZE = 500  # The max allowed by the API is 500
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # Standard ISO format for last_run

# Deduplication settings
DEDUP_WINDOW_MINUTES = 5
MAX_DEDUP_CACHE_SIZE = 10000

# Producer-Consumer settings
QUEUE_MAX_SIZE = 1000  # Maximum number of event batches in queue
CONSUMER_BATCH_SIZE = 100  # Number of events to process at once
PRODUCER_TIMEOUT = 30  # Timeout for producer operations
CONSUMER_TIMEOUT = 5  # Timeout for consumer operations
MAX_CONSUMER_THREADS = 3  # Maximum number of consumer threads

# --- API Endpoints ---
# Domain API is public, unauthenticated
DOMAIN_API_URL = "https://api.liveperson.net/api/account/{account_id}/service/accountConfigReadOnly/baseURI.json?version=1.0"
# Auth API path (prepended with user-provided auth_server_url)
OAUTH_PATH_SUFFIX = "/sentinel/api/v2/account/{account_id}/app/token"
# Event API path (prepended with *discovered* event_base_url)
FETCH_PATH_SUFFIX = "/api/account/{account_id}/configuration/metadata/audit"

""" HELPER CLASSES """


class EventBatchStatus(Enum):
    """Status of an event batch in the processing pipeline."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class EventBatch:
    """Container for a batch of events with metadata."""
    events: list[dict[str, Any]]
    batch_id: str
    timestamp: datetime
    status: EventBatchStatus = EventBatchStatus.PENDING
    retry_count: int = 0
    error_message: Optional[str] = None


class ProducerConsumerMetrics:
    """Track metrics for the producer-consumer system."""

    def __init__(self):
        self.events_produced = 0
        self.events_consumed = 0
        self.batches_produced = 0
        self.batches_consumed = 0
        self.errors = 0
        self.duplicates_filtered = 0
        self.start_time = datetime.utcnow()
        self._lock = threading.Lock()

    def increment_produced(self, count: int = 1) -> None:
        """Thread-safe increment of produced events."""
        with self._lock:
            self.events_produced += count
            self.batches_produced += 1

    def increment_consumed(self, count: int = 1) -> None:
        """Thread-safe increment of consumed events."""
        with self._lock:
            self.events_consumed += count
            self.batches_consumed += 1

    def increment_errors(self) -> None:
        """Thread-safe increment of error count."""
        with self._lock:
            self.errors += 1

    def increment_duplicates(self, count: int = 1) -> None:
        """Thread-safe increment of duplicate count."""
        with self._lock:
            self.duplicates_filtered += count

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of metrics."""
        with self._lock:
            elapsed = (datetime.utcnow() - self.start_time).total_seconds()
            return {
                "events_produced": self.events_produced,
                "events_consumed": self.events_consumed,
                "batches_produced": self.batches_produced,
                "batches_consumed": self.batches_consumed,
                "duplicates_filtered": self.duplicates_filtered,
                "errors": self.errors,
                "elapsed_seconds": elapsed,
                "events_per_second": self.events_consumed / elapsed if elapsed > 0 else 0
            }


""" HELPER FUNCTIONS """


def retry_with_backoff(
    func,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True
):
    """
    Retry a function with exponential backoff.

    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries
        exponential_base: Base for exponential backoff
        jitter: Add randomization to prevent thundering herd
    
    Returns:
        The result of the function call
    
    Raises:
        The last exception if all retries fail
    """
    last_exception: Optional[Exception] = None
    
    for attempt in range(max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_exception = e
            
            if attempt == max_retries:
                demisto.error(f"{INTEGRATION_PREFIX} Max retries ({max_retries}) exceeded: {str(e)}")
                raise
            
            # Calculate delay with exponential backoff
            delay = min(base_delay * (exponential_base ** attempt), max_delay)
            
            # Add jitter to prevent thundering herd
            if jitter:
                delay = delay * (0.5 + random.random())
            
            demisto.info(f"{INTEGRATION_PREFIX} Retry {attempt + 1}/{max_retries} after {delay:.2f}s. Error: {str(e)}")
            time.sleep(delay)
    
    if last_exception:
        raise last_exception
    raise Exception("Unexpected error in retry logic")


def generate_event_hash(event: dict[str, Any]) -> str:
    """
    Generate a unique hash for an event to enable deduplication.
    
    Args:
        event: The event dictionary
    
    Returns:
        A SHA256 hash string representing the event
    """
    # Key fields that uniquely identify an event
    hash_fields = [
        event.get("accountId", ""),
        event.get("changeDate", ""),
        event.get("objectType", ""),
        event.get("element", ""),
        event.get("changeType", ""),
        event.get("objectName", ""),
        event.get("originator", ""),
    ]
    
    hash_string = "|".join(str(field) for field in hash_fields)
    return hashlib.sha256(hash_string.encode("utf-8")).hexdigest()


class EventDeduplicator:
    """
    Manages event deduplication using a time-windowed hash cache.
    """
    
    def __init__(self, window_minutes: int = DEDUP_WINDOW_MINUTES, max_size: int = MAX_DEDUP_CACHE_SIZE):
        self.window_minutes = window_minutes
        self.max_size = max_size
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load the deduplication cache from integration context."""
        ctx = demisto.getIntegrationContext()
        cache_data = ctx.get("dedup_cache", {})
        
        # Clean expired entries
        current_time = datetime.utcnow()
        cutoff_time = current_time - timedelta(minutes=self.window_minutes)
        
        self.cache = {}
        for hash_val, timestamp_str in cache_data.items():
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
                if timestamp > cutoff_time:
                    self.cache[hash_val] = timestamp
            except (ValueError, TypeError):
                continue
        
        demisto.debug(f"{INTEGRATION_PREFIX} Loaded {len(self.cache)} hashes from dedup cache")
    
    def _save_cache(self) -> None:
        """Save the deduplication cache to integration context."""
        # Limit cache size
        if len(self.cache) > self.max_size:
            # Keep most recent entries
            sorted_items = sorted(self.cache.items(), key=lambda x: x[1], reverse=True)
            self.cache = dict(sorted_items[:self.max_size])
        
        # Convert to serializable format
        cache_data = {
            hash_val: timestamp.isoformat() 
            for hash_val, timestamp in self.cache.items()
        }
        
        ctx = demisto.getIntegrationContext()
        ctx["dedup_cache"] = cache_data
        demisto.setIntegrationContext(ctx)
        
        demisto.debug(f"{INTEGRATION_PREFIX} Saved {len(cache_data)} hashes to dedup cache")
    
    def is_duplicate(self, event: dict[str, Any]) -> bool:
        """
        Check if an event is a duplicate.
        
        Args:
            event: The event to check
        
        Returns:
            True if the event is a duplicate, False otherwise
        """
        event_hash = generate_event_hash(event)
        
        if event_hash in self.cache:
            demisto.debug(f"{INTEGRATION_PREFIX} Duplicate event found: {event_hash[:12]}...")
            return True
        
        # Add to cache
        self.cache[event_hash] = datetime.utcnow()
        return False
    
    def deduplicate_batch(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Deduplicate a batch of events.
        
        Args:
            events: List of events to deduplicate
        
        Returns:
            List of unique events
        """
        unique_events = []
        duplicates_found = 0
        
        for event in events:
            if not self.is_duplicate(event):
                unique_events.append(event)
            else:
                duplicates_found += 1
        
        if duplicates_found > 0:
            demisto.info(f"{INTEGRATION_PREFIX} Deduplication: {duplicates_found} duplicates removed from {len(events)} events")
        
        # Save cache after processing batch
        self._save_cache()
        
        return unique_events


""" CLIENT CLASS """


class Client(BaseClient):
    """
    Enhanced LivePerson API client with improved token management and streaming capabilities.
    """

    def __init__(
        self, base_url: str, account_id: str, auth_server_url: str, 
        client_id: str, client_secret: str, verify: bool, proxy: bool
    ):
        """
        Initializes the enhanced client with proactive token management.
        
        :param base_url: The discovered Event API domain
        :param account_id: The user's LivePerson Account ID
        :param auth_server_url: The user-provided Auth server
        :param client_id: OAuth Client ID
        :param client_secret: OAuth Client Secret
        :param verify: SSL verification flag
        :param proxy: Proxy usage flag
        """
        self.account_id = account_id
        self.auth_url = f"https://{auth_server_url}"
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Token management
        self._token_expiry: Optional[datetime] = None
        self._token_lifetime = 3600  # Default 1 hour, adjust based on your API
        
        # Deduplication
        self.deduplicator = EventDeduplicator()
        
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, headers={"Content-Type": "application/json"})

        demisto.info(f"{INTEGRATION_PREFIX} Enhanced client initialized. Event API Base URL: {base_url}")

    @staticmethod
    def _get_event_domain(account_id: str, verify: bool, proxy: bool) -> str:
        """
        Uses the public LivePerson Domain API to find the correct base URL.
        Now with retry logic for improved reliability.
        """
        domain_api_base = "https://api.liveperson.net"
        domain_api_path = f"/api/account/{account_id}/service/accountConfigReadOnly/baseURI.json"
        params = {"version": "1.0"}

        demisto.info(f"{INTEGRATION_PREFIX} Attempting to fetch event domain from: {domain_api_base}{domain_api_path}")

        def fetch_domain():
            temp_client = BaseClient(base_url=domain_api_base, verify=verify, proxy=proxy)
            data = temp_client._http_request(
                method="GET",
                url_suffix=domain_api_path,
                params=params,
                resp_type="json",
                ok_codes=(200,)
            )
            
            event_domain = data.get("baseURI")
            if not event_domain:
                raise DemistoException(f'Event domain API response missing "baseURI" field. Response: {data}')
            
            return f"https://{event_domain}"

        try:
            event_domain = retry_with_backoff(fetch_domain, max_retries=3)
            demisto.info(f"{INTEGRATION_PREFIX} Successfully fetched event domain: {event_domain}")
            return event_domain
        except Exception as e:
            msg = f"Failed to fetch event domain after retries. Error: {str(e)}"
            demisto.error(f"{INTEGRATION_PREFIX} {msg}")
            raise DemistoException(msg, e)

    def _should_refresh_token(self) -> bool:
        """Check if token should be refreshed proactively."""
        if not self._token_expiry:
            return True
        
        # Refresh 5 minutes before expiry
        buffer_time = timedelta(minutes=5)
        return datetime.utcnow() >= (self._token_expiry - buffer_time)

    def _get_access_token(self) -> str:
        """
        Generates an OAuth 2.0 access token with retry logic.
        """
        token_path = OAUTH_PATH_SUFFIX.format(account_id=self.account_id)
        full_auth_url = urljoin(self.auth_url, token_path)

        data = {"client_id": self.client_id, "client_secret": self.client_secret, "grant_type": "client_credentials"}
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        demisto.info(f"{INTEGRATION_PREFIX} Attempting to get new OAuth 2.0 token from: {self.auth_url}")

        def fetch_token():
            token_data = super(Client, self)._http_request(
                method="POST",
                full_url=full_auth_url,
                data=data,
                headers=headers,
                resp_type="json",
                ok_codes=(200,)
            )
            
            access_token = token_data.get("access_token")
            if not access_token:
                raise DemistoException(f'Auth response missing "access_token" field. Response: {token_data}')
            
            return access_token

        try:
            access_token = retry_with_backoff(fetch_token, max_retries=3)
            demisto.info(f"{INTEGRATION_PREFIX} Successfully retrieved new access token.")
            return access_token
        except Exception as e:
            msg = f"Failed to get access token after retries. Error: {str(e)}"
            demisto.error(f"{INTEGRATION_PREFIX} {msg}")
            raise DemistoException(msg, e)

    def _generate_token(self) -> None:
        """
        Enhanced token generation with expiry tracking.
        """
        access_token = self._get_access_token()
        self._headers["Authorization"] = f"Bearer {access_token}"
        
        # Set token expiry (adjust based on your API's token lifetime)
        self._token_expiry = datetime.utcnow() + timedelta(seconds=self._token_lifetime)
        demisto.info(f"{INTEGRATION_PREFIX} Token refreshed, expires at {self._token_expiry.isoformat()}")

    def _http_request(self, *args, **kwargs) -> dict[str, Any]:
        """
        Override with proactive token refresh and retry logic.
        """
        # Proactively refresh token if needed
        if self._should_refresh_token():
            demisto.info(f"{INTEGRATION_PREFIX} Proactively refreshing token")
            self._generate_token()

        try:
            demisto.debug(f"{INTEGRATION_PREFIX} Making API request to {self._base_url}")
            return super()._http_request(*args, **kwargs)

        except DemistoException as e:
            # If we get a 401/403, our token might be expired despite proactive refresh
            if "401" in str(e) or "403" in str(e):
                demisto.info(f"{INTEGRATION_PREFIX} Token expired, refreshing and retrying")
                self._generate_token()
                return super()._http_request(*args, **kwargs)
            else:
                demisto.error(f"{INTEGRATION_PREFIX} HTTP request failed: {str(e)}")
                raise e

    def _event_producer(
        self,
        event_queue: queue.Queue,
        max_fetch: int,
        last_run_time: datetime,
        stop_event: threading.Event,
        metrics: ProducerConsumerMetrics
    ) -> datetime:
        """
        Producer thread that fetches events from the API and puts them in the queue.

        :param event_queue: Queue to put event batches
        :param max_fetch: Maximum number of events to fetch
        :param last_run_time: Timestamp of the last event from previous run
        :param stop_event: Event to signal stop
        :param metrics: Metrics tracker
        :return: New maximum timestamp
        """
        fetch_url_suffix = FETCH_PATH_SUFFIX.format(account_id=self.account_id)
        from_date_str = last_run_time.strftime(DATE_FORMAT)

        new_max_timestamp = last_run_time
        offset = 0
        total_events_produced = 0
        batch_counter = 0

        demisto.info(f"{INTEGRATION_PREFIX} Producer starting. Max: {max_fetch}, From: {from_date_str}")

        try:
            while total_events_produced < max_fetch and not stop_event.is_set():
                # Calculate how many more events to fetch
                events_to_fetch = min(API_PAGE_SIZE, max_fetch - total_events_produced)

                request_body = {
                    "fromData": from_date_str,
                    "first": events_to_fetch,
                    "offset": offset,
                    "orderBy": "changeTimestamp:ASC",
                }

                demisto.debug(f"{INTEGRATION_PREFIX} Producer fetching page. Offset: {offset}, Limit: {events_to_fetch}")

                try:
                    response = self._http_request(method="POST", url_suffix=fetch_url_suffix, json_data=request_body)
                    events = response.get("data", [])
                    
                    if not events:
                        demisto.info(f"{INTEGRATION_PREFIX} Producer: No more events from API.")
                        break

                    demisto.debug(f"{INTEGRATION_PREFIX} Producer received {len(events)} events.")

                    # Process timestamps
                    for event in events:
                        timestamp_str = event.get("changeDate")
                        if timestamp_str:
                            event["_time"] = timestamp_str
                            try:
                                event_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                                if event_time > new_max_timestamp:
                                    new_max_timestamp = event_time
                            except ValueError:
                                demisto.debug(f"{INTEGRATION_PREFIX} Could not parse timestamp: {timestamp_str}")

                    # Create batch and put in queue
                    batch_counter += 1
                    batch = EventBatch(
                        events=events,
                        batch_id=f"batch_{batch_counter}_{datetime.utcnow().timestamp()}",
                        timestamp=datetime.utcnow()
                    )
                    
                    # Put batch in queue with timeout
                    try:
                        event_queue.put(batch, timeout=PRODUCER_TIMEOUT)
                        metrics.increment_produced(len(events))
                        total_events_produced += len(events)
                        demisto.debug(f"{INTEGRATION_PREFIX} Producer queued batch {batch.batch_id} with {len(events)} events")
                    except queue.Full:
                        demisto.info(f"{INTEGRATION_PREFIX} Producer: Queue full, waiting for consumers")
                        # Try again with longer timeout
                        event_queue.put(batch, timeout=PRODUCER_TIMEOUT * 2)
                        metrics.increment_produced(len(events))
                        total_events_produced += len(events)

                    # Prepare for the next page
                    offset += len(events)

                    # If we received fewer events than requested, we're on the last page
                    if len(events) < events_to_fetch:
                        demisto.info(f"{INTEGRATION_PREFIX} Producer: Received fewer events than requested, last page.")
                        break

                except Exception as e:
                    metrics.increment_errors()
                    demisto.error(f"{INTEGRATION_PREFIX} Producer error: {str(e)}")
                    if "401" in str(e) or "403" in str(e):
                        # Auth error, stop producer
                        break
                    # For other errors, continue after a delay
                    time.sleep(5)

        except Exception as e:
            metrics.increment_errors()
            demisto.error(f"{INTEGRATION_PREFIX} Producer fatal error: {str(e)}")
        finally:
            demisto.info(f"{INTEGRATION_PREFIX} Producer finished. Produced {total_events_produced} events")
            
        return new_max_timestamp

    def _event_consumer(
        self,
        event_queue: queue.Queue,
        stop_event: threading.Event,
        metrics: ProducerConsumerMetrics,
        consumer_id: int
    ) -> None:
        """
        Consumer thread that processes events from the queue and sends them to XSIAM.
        
        :param event_queue: Queue to get event batches from
        :param stop_event: Event to signal stop
        :param metrics: Metrics tracker
        :param consumer_id: ID of this consumer thread
        """
        demisto.info(f"{INTEGRATION_PREFIX} Consumer {consumer_id} starting")
        events_buffer = []
        
        try:
            while not stop_event.is_set() or not event_queue.empty():
                try:
                    # Get batch from queue with timeout
                    batch = event_queue.get(timeout=CONSUMER_TIMEOUT)
                    
                    if batch.status != EventBatchStatus.PENDING:
                        demisto.debug(
                            f"{INTEGRATION_PREFIX} Consumer {consumer_id}: "
                            f"Skipping batch {batch.batch_id} with status {batch.status}"
                        )
                        continue
                    
                    batch.status = EventBatchStatus.PROCESSING
                    demisto.debug(f"{INTEGRATION_PREFIX} Consumer {consumer_id} processing batch {batch.batch_id}")
                    
                    # Deduplicate events
                    unique_events = self.deduplicator.deduplicate_batch(batch.events)
                    duplicates_count = len(batch.events) - len(unique_events)
                    
                    if duplicates_count > 0:
                        metrics.increment_duplicates(duplicates_count)
                        demisto.debug(f"{INTEGRATION_PREFIX} Consumer {consumer_id}: Filtered {duplicates_count} duplicates")
                    
                    # Add to buffer
                    events_buffer.extend(unique_events)
                    
                    # Send to XSIAM when buffer reaches threshold or queue is empty
                    if len(events_buffer) >= CONSUMER_BATCH_SIZE or event_queue.empty():
                        if events_buffer:
                            try:
                                demisto.info(
                                    f"{INTEGRATION_PREFIX} Consumer {consumer_id} "
                                    f"sending {len(events_buffer)} events to XSIAM"
                                )
                                send_events_to_xsiam(events_buffer, vendor=INTEGRATION_NAME, product="liveperson")
                                metrics.increment_consumed(len(events_buffer))
                                events_buffer = []
                            except Exception as e:
                                metrics.increment_errors()
                                demisto.error(f"{INTEGRATION_PREFIX} Consumer {consumer_id} failed to send events: {str(e)}")
                                # Keep events in buffer for retry
                    
                    batch.status = EventBatchStatus.COMPLETED
                    event_queue.task_done()
                    
                except queue.Empty:
                    # Send any remaining events in buffer
                    if events_buffer:
                        try:
                            demisto.info(f"{INTEGRATION_PREFIX} Consumer {consumer_id} sending final {len(events_buffer)} events")
                            send_events_to_xsiam(events_buffer, vendor=INTEGRATION_NAME, product="liveperson")
                            metrics.increment_consumed(len(events_buffer))
                            events_buffer = []
                        except Exception as e:
                            metrics.increment_errors()
                            demisto.error(f"{INTEGRATION_PREFIX} Consumer {consumer_id} failed to send final events: {str(e)}")
                except Exception as e:
                    metrics.increment_errors()
                    demisto.error(f"{INTEGRATION_PREFIX} Consumer {consumer_id} error: {str(e)}")
                    
        except Exception as e:
            metrics.increment_errors()
            demisto.error(f"{INTEGRATION_PREFIX} Consumer {consumer_id} fatal error: {str(e)}")
        finally:
            # Send any remaining events before exiting
            if events_buffer:
                try:
                    demisto.info(f"{INTEGRATION_PREFIX} Consumer {consumer_id} sending remaining {len(events_buffer)} events")
                    send_events_to_xsiam(events_buffer, vendor=INTEGRATION_NAME, product="liveperson")
                    metrics.increment_consumed(len(events_buffer))
                except Exception as e:
                    demisto.error(f"{INTEGRATION_PREFIX} Consumer {consumer_id} failed to send remaining events: {str(e)}")
            
            demisto.info(f"{INTEGRATION_PREFIX} Consumer {consumer_id} finished")

    def fetch_events_producer_consumer(self, max_fetch: int, last_run_time: datetime) -> Tuple[int, datetime]:
        """
        Enhanced fetch method using producer-consumer pattern for improved performance.
        
        :param max_fetch: Maximum number of events to fetch
        :param last_run_time: Timestamp of the last event from previous run
        :return: Tuple of (total_events_sent, new_last_run_time)
        """
        demisto.info(f"{INTEGRATION_PREFIX} Starting producer-consumer fetch. Max: {max_fetch}")
        
        # Initialize metrics
        metrics = ProducerConsumerMetrics()
        
        # Create queue and synchronization primitives
        event_queue: queue.Queue[EventBatch] = queue.Queue(maxsize=QUEUE_MAX_SIZE)
        stop_event = threading.Event()
        
        # Track the new maximum timestamp
        new_max_timestamp_container = [last_run_time]  # Use list to allow modification in thread
        
        # Start producer thread
        producer_thread = threading.Thread(
            target=lambda: new_max_timestamp_container.__setitem__(
                0, self._event_producer(event_queue, max_fetch, last_run_time, stop_event, metrics)
            ),
            name="EventProducer"
        )
        producer_thread.start()
        
        # Start consumer threads
        num_consumers = min(MAX_CONSUMER_THREADS, max(1, max_fetch // 1000))  # Scale consumers based on load
        consumer_threads = []
        
        for i in range(num_consumers):
            consumer_thread = threading.Thread(
                target=self._event_consumer,
                args=(event_queue, stop_event, metrics, i + 1),
                name=f"EventConsumer-{i + 1}"
            )
            consumer_thread.start()
            consumer_threads.append(consumer_thread)
        
        demisto.info(f"{INTEGRATION_PREFIX} Started {num_consumers} consumer threads")
        
        # Wait for producer to finish
        producer_thread.join()
        
        # Signal consumers to stop after processing remaining events
        stop_event.set()
        
        # Wait for all consumers to finish
        for consumer_thread in consumer_threads:
            consumer_thread.join()
        
        # Get final metrics
        summary = metrics.get_summary()
        
        demisto.info(
            f"{INTEGRATION_PREFIX} Producer-consumer fetch complete. "
            f"Produced: {summary['events_produced']}, "
            f"Consumed: {summary['events_consumed']}, "
            f"Duplicates: {summary['duplicates_filtered']}, "
            f"Errors: {summary['errors']}, "
            f"Rate: {summary['events_per_second']:.2f} events/sec"
        )
        
        return summary['events_consumed'], new_max_timestamp_container[0]

    def fetch_events_streaming(self, max_fetch: int, last_run_time: datetime) -> tuple[int, datetime]:
        """
        Enhanced fetch method that can use either streaming or producer-consumer pattern.
        For now, delegates to producer-consumer for better performance.
        
        :param max_fetch: Maximum number of events to fetch
        :param last_run_time: Timestamp of the last event from previous run
        :return: Tuple of (total_events_sent, new_last_run_time)
        """
        # Use producer-consumer pattern for better performance
        return self.fetch_events_producer_consumer(max_fetch, last_run_time)


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication with improved error handling.
    """
    demisto.info(f"{INTEGRATION_PREFIX} Starting test-module.")
    try:
        # Test with a minimal fetch to verify all components work
        one_day_ago = datetime.utcnow() - timedelta(days=1)
        demisto.info(f"{INTEGRATION_PREFIX} test-module: Attempting to fetch 1 event from 1 day ago.")
        
        # Use the streaming fetch but with a small limit
        events_sent, _ = client.fetch_events_streaming(max_fetch=1, last_run_time=one_day_ago)
        
        demisto.info(f"{INTEGRATION_PREFIX} test-module PASSED.")
        return "ok"
    except Exception as e:
        tb = traceback.format_exc()
        demisto.error(f"{INTEGRATION_PREFIX} test-module FAILED. Error: {str(e)}\nTraceback:\n{tb}")
        return f"Test failed: {str(e)}\nTraceback:\n{tb}"


def get_events_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Manual command to fetch events with streaming support.
    """
    try:
        limit = arg_to_number(args.get("limit", 50))
        if limit is None or limit <= 0:
            limit = 50
        start_time_str = args.get("start_time", "3 days")
        should_push_events = argToBoolean(args.get("should_push_events", False))

        demisto.info(
            f"{INTEGRATION_PREFIX} Running get-events command. "
            f"Limit: {limit}, Start Time: {start_time_str}, Should Push Events: {should_push_events}"
        )

        start_time, _ = parse_date_range(start_time_str)
        if not start_time:
            raise ValueError("Invalid 'start_time' format. Use phrases like '3 days ago' or '2023-10-25T10:00:00Z'.")

        # For manual command, we need to collect events for display
        # So we'll use a modified approach
        fetch_url_suffix = FETCH_PATH_SUFFIX.format(account_id=client.account_id)
        from_date_str = start_time.strftime(DATE_FORMAT)
        
        all_events: list[dict[str, Any]] = []
        offset = 0
        
        while len(all_events) < limit:
            events_to_fetch = min(API_PAGE_SIZE, limit - len(all_events))
            request_body = {
                "fromData": from_date_str,
                "first": events_to_fetch,
                "offset": offset,
                "orderBy": "changeTimestamp:ASC",
            }
            
            response = client._http_request(method="POST", url_suffix=fetch_url_suffix, json_data=request_body)
            events = response.get("data", [])
            
            if not events:
                break
                
            # Process timestamps
            for event in events:
                timestamp_str = event.get("changeDate")
                if timestamp_str:
                    event["_time"] = timestamp_str
            
            # Deduplicate
            unique_events = client.deduplicator.deduplicate_batch(events)
            all_events.extend(unique_events)
            
            offset += len(events)
            
            if len(events) < events_to_fetch:
                break
        
        # Limit to requested amount
        all_events = all_events[:limit]
        
        demisto.info(f"{INTEGRATION_PREFIX} get-events command fetched {len(all_events)} unique events.")

        # Push events to XSIAM if requested
        if should_push_events and all_events:
            demisto.info(f"{INTEGRATION_PREFIX} Pushing {len(all_events)} events to XSIAM.")
            send_events_to_xsiam(all_events, vendor=INTEGRATION_NAME, product="liveperson")

        readable_output = tableToMarkdown(
            f"LivePerson Audit Events (Last {len(all_events)})",
            all_events,
            headers=["changeDate", "accountId", "objectType", "element"],
            headerTransform=string_to_table_header,
        )

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="LivePerson.Event",
            outputs_key_field="changeDate",
            outputs=all_events
        )
    except Exception as e:
        tb = traceback.format_exc()
        demisto.error(f"{INTEGRATION_PREFIX} get-events command failed: {str(e)}\nTraceback:\n{tb}")
        raise


def fetch_events_command(
    client: Client, max_fetch: int, first_fetch_time: datetime
) -> None:
    """
    Enhanced fetch events command using streaming approach.
    """
    last_run = demisto.getLastRun()
    last_run_time_str = last_run.get("last_fetch_time")

    if last_run_time_str:
        last_run_time = datetime.fromisoformat(last_run_time_str)
        demisto.info(f"{INTEGRATION_PREFIX} Found last run time: {last_run_time_str}")
    else:
        last_run_time = first_fetch_time
        demisto.info(f"{INTEGRATION_PREFIX} No last run time found. Using first_fetch time: {first_fetch_time.isoformat()}")

    # Use the streaming fetch method
    events_sent, new_max_timestamp = client.fetch_events_streaming(max_fetch=max_fetch, last_run_time=last_run_time)

    # Update last run time only if we successfully processed events
    if new_max_timestamp > last_run_time:
        # Add 1 second to avoid fetching the same event again
        new_last_run_time_plus_one = new_max_timestamp + timedelta(seconds=1)
        new_last_run_time_str = new_last_run_time_plus_one.isoformat()
        demisto.setLastRun({"last_fetch_time": new_last_run_time_str})
        demisto.info(
            f"{INTEGRATION_PREFIX} Setting new last run time to {new_last_run_time_str} "
            f"(based on event time {new_max_timestamp.isoformat()})"
        )
    elif events_sent == 0:
        demisto.info(f"{INTEGRATION_PREFIX} No new events found. Last run time not updated.")
    else:
        # We sent events but timestamp didn't advance - advance by 1 second to avoid infinite loop
        new_last_run_time_str = (last_run_time + timedelta(seconds=1)).isoformat()
        demisto.setLastRun({"last_fetch_time": new_last_run_time_str})
        demisto.info(f"{INTEGRATION_PREFIX} Setting new last run time to {new_last_run_time_str} to avoid duplicates.")


""" MAIN FUNCTION """


def main() -> None:
    """
    Main function, parses params and executes the command.
    """
    params = demisto.params()

    auth_url = params.get("auth_server_url")
    account_id = params.get("account_id")
    client_creds = params.get("credentials", {})
    client_id = client_creds.get("identifier")
    client_secret = client_creds.get("password")

    verify_ssl = not params.get("insecure", False)
    proxies = handle_proxy(params.get("proxy", False))

    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH))
    first_fetch_str = params.get("first_fetch", "3 days")

    command = demisto.command()
    demisto.debug(f"{INTEGRATION_PREFIX} Command being run: {command}")

    try:
        # --- Parameter Validation ---
        if not (auth_url and account_id and client_id and client_secret):
            raise DemistoException(
                "Missing required parameters: Authorization Server URL, Account ID, Client ID, or Client Secret."
            )

        first_fetch_time, _ = parse_date_range(first_fetch_str)
        if not first_fetch_time:
            raise DemistoException(
                f"Invalid 'first_fetch' format: {first_fetch_str}. Use phrases like '3 days ago' or '2023-10-25T10:00:00Z'."
            )
        if max_fetch is None or max_fetch <= 0:
            raise DemistoException(f"'max_fetch' must be a positive integer. Got: {max_fetch}")

        # --- Dynamic Domain Lookup ---
        # This is the first network call. It validates account_id and proxy/SSL.
        demisto.debug(f"{INTEGRATION_PREFIX} Attempting to discover Event API domain for account {account_id}...")
        event_base_url = Client._get_event_domain(account_id, verify_ssl, proxies)
        demisto.debug(f"{INTEGRATION_PREFIX} Successfully discovered Event API domain: {event_base_url}")

        # --- Client Initialization ---
        client = Client(
            base_url=event_base_url,
            account_id=account_id,
            auth_server_url=auth_url,
            client_id=client_id,
            client_secret=client_secret,
            verify=verify_ssl,
            proxy=params.get("proxy", False),  # BaseClient __init__ expects the bool
        )

        # --- Command Execution ---
        if command == "test-module":
            result = test_module(client)
            return_results(result)

        elif command == "liveperson-get-events":
            return_results(get_events_command(client, demisto.args()))

        elif command == "fetch-events":
            fetch_events_command(client, max_fetch, first_fetch_time)
            demisto.info(f"{INTEGRATION_PREFIX} fetch-events command completed successfully.")

    except Exception as e:
        # Get the full traceback for debugging
        tb = traceback.format_exc()
        demisto.error(f"{INTEGRATION_PREFIX} Failed to execute {command} command. Error: {str(e)}\nTraceback:\n{tb}")
        return_error(f"Failed to execute {command} command. Error: {str(e)}\nTraceback:\n{tb}", error=e)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
