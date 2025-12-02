import asyncio
import base64
import contextlib
import json
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from threading import Lock
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    Final,
    Iterable,
    List,
    Literal,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypedDict,
    Union,
)

import anyio
import demistomock as demisto
import httpx
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

"""CollectorClient: High-performance async-first HTTP client for event collection.

This module provides a complete solution for building event collectors in XSOAR/XSIAM.
It handles pagination, authentication, retry logic, rate limiting, state management,
and timeout handling automatically.

**Quick Start:**

```python
from CollectorClient import (
    CollectorClient,
    CollectorBlueprint,
    CollectorRequest,
    PaginationConfig,
    APIKeyAuthHandler,
)

# Create blueprint
blueprint = CollectorBlueprint(
    name="MyCollector",
    base_url="https://api.example.com",
    request=CollectorRequest(
        endpoint="/v1/events",
        data_path="data.events",
        pagination=PaginationConfig(
            mode="cursor",
            next_cursor_path="meta.next_cursor",
        ),
    ),
    auth_handler=APIKeyAuthHandler("secret", header_name="X-API-Key"),
)

# Create client and collect
client = CollectorClient(blueprint)
result = client.collect_events_sync(limit=1000)

# Process events
for event in result.events:
    send_to_xsiam(event)
```

**Key Classes:**

- `CollectorClient`: Main client class for making requests and collecting events
- `CollectorBlueprint`: Declarative configuration for the collector
- `CollectorRequest`: HTTP request configuration with pagination
- `PaginationConfig`: Pagination strategy configuration (cursor, page, offset, link)
- `AuthHandler`: Base class for authentication (APIKey, Bearer, Basic, OAuth2)
- `CollectorState`: State for resuming after timeouts
- `CollectorRunResult`: Result containing events, state, and metrics

**Features:**

- Async-first with sync wrappers for easy integration
- Automatic pagination (cursor, page, offset, link-based)
- Pluggable authentication (API key, Bearer token, Basic auth, OAuth2)
- Automatic retry with exponential backoff
- Rate limiting with token bucket algorithm
- Circuit breaker for fault tolerance
- State persistence for resume after timeout
- Structured logging and metrics
- Concurrent collection for multiple shards/endpoints

**See individual class docstrings for detailed usage examples.**
"""

# Type aliases for semantic clarity (using type aliases instead of NewType for better ergonomics)
Cursor = str  # Semantic type: pagination cursor token
EventID = str  # Semantic type: unique event identifier
StateKey = str  # Semantic type: state storage key identifier

# HTTP method literal type
HTTPMethod = Literal["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

# Pagination mode literal type
PaginationMode = Literal["cursor", "page", "offset", "link", "none"]

# Collection strategy name literal type
StrategyName = Literal["sequential", "concurrent", "batch", "stream"]

# Constants
SENSITIVE_KEYS: Final[Tuple[str, ...]] = ("token", "secret", "authorization", "password", "credential", "key")
STATE_NAMESPACE: Final[str] = "collector_client"
DEFAULT_USER_AGENT: Final[str] = "CollectorClient/1.0"
DEFAULT_STREAM_CHUNK: Final[int] = 500


class ShardConfig(TypedDict, total=False):
    """Configuration for a single shard in concurrent collection.
    
    All fields are optional except those required by the specific use case.
    """
    endpoint: str
    method: HTTPMethod
    params: Dict[str, Any]
    json_body: Any
    headers: Dict[str, str]
    data_path: Optional[str]
    pagination: Optional["PaginationConfig"]
    timeout: Optional["TimeoutSettings"]
    state_key: str  # Will be converted to StateKey when creating CollectorRequest


class CollectorError(DemistoException):
    """Base error for all collector failures."""


class CollectorAuthenticationError(CollectorError):
    """Raised when authentication cannot be completed."""


class CollectorRateLimitError(CollectorError):
    """Raised when the client hits a user-defined rate limit."""


class CollectorTimeoutError(CollectorError):
    """Raised when the execution timeout window is about to be exceeded."""


class CollectorCircuitOpenError(CollectorError):
    """Raised when the circuit breaker prevents additional requests."""


class CollectorRetryError(CollectorError):
    """Raised when requests exhaust all retry attempts."""


class CollectorConfigurationError(CollectorError):
    """Raised when the blueprint or request definition is invalid."""


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in SENSITIVE_KEYS)


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("<redacted>" if _is_sensitive(k) else sanitize(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    return value


def _ensure_dict(value: Optional[MutableMapping[str, Any]]) -> Dict[str, Any]:
    if value is None:
        return {}
    return dict(value)


def _resolve_path(data: Any, path: Optional[str]) -> Any:
    if not path:
        return data
    current = data
    for part in path.strip(".").split("."):
        if current is None:
            return None
        if not part:
            continue
        if "[" in part and part.endswith("]"):
            name, _, index_part = part.partition("[")
            if name:
                current = current.get(name) if isinstance(current, dict) else None
                if current is None:
                    return None
            index_part = index_part.rstrip("]")
            if index_part == "*":
                return current
            try:
                idx = int(index_part)
            except ValueError:
                return None
            if isinstance(current, list) and 0 <= idx < len(current):
                current = current[idx]
            else:
                return None
        else:
            current = current.get(part) if isinstance(current, dict) else None
    return current


def _extract_list(data: Any, path: Optional[str]) -> List[Any]:
    extracted = _resolve_path(data, path)
    if extracted is None:
        return []
    if isinstance(extracted, list):
        return extracted
    if isinstance(extracted, dict):
        return [extracted]
    return [extracted]


def _now() -> float:
    return time.monotonic()


@dataclass(slots=True)
class RetryPolicy:
    """Retry policy for handling transient API failures.
    
    Configures automatic retry behavior with exponential backoff and jitter.
    Retries are attempted for retryable HTTP status codes and network exceptions.
    
    **Default Configuration:**
    
    - 5 retry attempts
    - Exponential backoff: 1s, 2s, 4s, 8s, 16s (capped at max_delay)
    - 20% jitter to prevent thundering herd
    - Respects `Retry-After` headers when present
    - Retries on: 408, 413, 425, 429, 500, 502, 503, 504
    
    **Custom Configuration:**
    
    ```python
    RetryPolicy(
        max_attempts=10,  # More retries for unreliable APIs
        initial_delay=0.5,  # Start with shorter delay
        multiplier=2.0,  # Double delay each retry
        max_delay=120.0,  # Cap at 2 minutes
        jitter=0.3,  # 30% jitter
        respect_retry_after=True,  # Honor API's Retry-After header
    )
    ```
    
    **Retry Logic:**
    
    1. On retryable error, wait: `min(max_delay, initial_delay * (multiplier ^ attempt))`
    2. Add random jitter: `±(delay * jitter)`
    3. If `Retry-After` header present and `respect_retry_after=True`, use that value instead
    4. Retry up to `max_attempts` times
    5. After all retries exhausted, raise `CollectorRetryError`
    
    **Retryable Status Codes:**
    
    - 408: Request Timeout
    - 413: Payload Too Large
    - 425: Too Early
    - 429: Too Many Requests (rate limit)
    - 500: Internal Server Error
    - 502: Bad Gateway
    - 503: Service Unavailable
    - 504: Gateway Timeout
    
    **Retryable Exceptions:**
    
    - `httpx.ConnectError`: Connection failed
    - `httpx.ReadTimeout`: Read timeout
    - `httpx.WriteTimeout`: Write timeout
    - `httpx.RemoteProtocolError`: Protocol error
    - `httpx.PoolTimeout`: Connection pool timeout
    
    Args:
        max_attempts: Maximum retry attempts (must be >= 1, default: 5)
        initial_delay: Initial delay in seconds before first retry (must be >= 0, default: 1.0)
        multiplier: Exponential backoff multiplier (must be >= 1.0, default: 2.0)
        max_delay: Maximum delay between retries in seconds (must be > initial_delay, default: 60.0)
        jitter: Random jitter as fraction of delay (0.0-1.0, default: 0.2 = 20%)
        retryable_status_codes: HTTP status codes that trigger retry (default: 408, 413, 425, 429, 500, 502, 503, 504)
        retryable_exceptions: Exception types that trigger retry (default: network/timeout exceptions)
        respect_retry_after: Honor `Retry-After` header from API responses (default: True)
    """
    max_attempts: int = 5
    initial_delay: float = 1.0
    multiplier: float = 2.0
    max_delay: float = 60.0
    jitter: float = 0.2
    retryable_status_codes: Tuple[int, ...] = (408, 413, 425, 429, 500, 502, 503, 504)
    retryable_exceptions: Tuple[Type[Exception], ...] = (
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.RemoteProtocolError,
        httpx.PoolTimeout,
    )
    respect_retry_after: bool = True

    def next_delay(self, attempt: int, retry_after: Optional[float] = None) -> float:
        if retry_after is not None and self.respect_retry_after:
            return retry_after
        delay = min(self.max_delay, self.initial_delay * (self.multiplier ** (attempt - 1)))
        jitter_value = delay * self.jitter
        return max(0.0, delay + random.uniform(-jitter_value, jitter_value))


@dataclass(slots=True)
class CircuitBreakerPolicy:
    failure_threshold: int = 5
    recovery_timeout: float = 60.0
    half_open_threshold: int = 2


class CircuitBreaker:
    def __init__(self, policy: CircuitBreakerPolicy):
        self.policy = policy
        self._failure_count = 0
        self._opened_at: Optional[float] = None

    def can_execute(self) -> bool:
        if self._opened_at is None:
            return True
        elapsed = _now() - self._opened_at
        if elapsed >= self.policy.recovery_timeout:
            self._failure_count = 0
            self._opened_at = None
            return True
        return False

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.policy.failure_threshold:
            self._opened_at = _now()


@dataclass(slots=True)
class RateLimitPolicy:
    """Rate limiting policy using token bucket algorithm.
    
    Proactively limits request rate to prevent hitting API rate limits.
    Uses a token bucket algorithm: tokens refill at `rate_per_second`, with a maximum
    burst capacity of `burst` tokens.
    
    **How It Works:**
    
    - Each request consumes 1 token
    - Tokens refill at `rate_per_second` per second
    - Maximum burst capacity is `burst` tokens
    - If no tokens available, request waits until token refills
    
    **Example:**
    
    ```python
    # Limit to 10 requests per second, allow burst of 20
    RateLimitPolicy(rate_per_second=10.0, burst=20)
    ```
    
    This means:
    - Can make 20 requests immediately (burst)
    - Then limited to 10 requests per second
    - If you make 20 requests, you must wait 2 seconds before next request
    
    **When to Use:**
    
    - API has documented rate limits (e.g., "100 requests/minute")
    - You want to avoid 429 (Too Many Requests) errors
    - You need predictable, steady request rate
    
    **Disabling Rate Limiting:**
    
    Set `rate_per_second=0.0` (default) to disable. The client will still respect
    `Retry-After` headers from the API, but won't proactively limit requests.
    
    **Common Configurations:**
    
    ```python
    # 10 requests/second, burst of 10
    RateLimitPolicy(rate_per_second=10.0, burst=10)
    
    # 100 requests/minute = ~1.67 requests/second
    RateLimitPolicy(rate_per_second=100.0/60.0, burst=5)
    
    # 1000 requests/hour = ~0.28 requests/second
    RateLimitPolicy(rate_per_second=1000.0/3600.0, burst=10)
    ```
    
    Args:
        rate_per_second: Request rate limit (requests per second). Set to 0.0 to disable (default).
        burst: Maximum burst capacity (number of tokens). Must be >= 1 (default: 1).
            Higher values allow more requests in quick succession.
        respect_retry_after: Honor `Retry-After` header from API responses (default: True).
            Even with rate limiting enabled, the API may still send 429 responses.
    
    Note:
        Rate limiting is disabled by default (`rate_per_second=0.0`). Set to a positive
        value to enable proactive rate limiting.
    """
    rate_per_second: float = 0.0
    burst: int = 1
    respect_retry_after: bool = True

    @property
    def enabled(self) -> bool:
        return self.rate_per_second > 0


class TokenBucketRateLimiter:
    def __init__(self, policy: RateLimitPolicy):
        self.policy = policy
        self._capacity = max(1, policy.burst)
        self._tokens = float(self._capacity)
        self._updated = _now()
        self._lock = anyio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            await self._refill_locked()
            if self._tokens >= 1:
                self._tokens -= 1
                return
            needed = 1 - self._tokens
            wait_seconds = needed / self.policy.rate_per_second
        await anyio.sleep(wait_seconds)
        await self.acquire()

    async def _refill_locked(self) -> None:
        now = _now()
        delta = now - self._updated
        if delta <= 0:
            return
        refill = delta * self.policy.rate_per_second
        self._tokens = min(self._capacity, self._tokens + refill)
        self._updated = now


@dataclass(slots=True)
class TimeoutSettings:
    """Timeout configuration for HTTP requests and execution deadline.
    
    Configures timeouts for different phases of HTTP requests and overall execution.
    Setting `execution` enables timeout awareness and automatic state preservation.
    
    **Timeout Types:**
    
    - `connect`: Time to establish connection (default: 10s)
    - `read`: Time to read response data (default: 60s)
    - `write`: Time to write request data (default: 60s)
    - `pool`: Time to get connection from pool (default: 60s)
    - `execution`: Total execution time limit (default: None = disabled)
    - `safety_buffer`: Seconds before execution timeout to abort (default: 30s)
    
    **Execution Timeout (Recommended):**
    
    Setting `execution` enables timeout awareness:
    - Detects when execution deadline is approaching
    - Automatically saves state before timeout
    - Raises `CollectorTimeoutError` with preserved state
    - Allows seamless resume on next run
    
    ```python
    TimeoutSettings(
        execution=300,  # 5 minutes total execution time
        safety_buffer=30,  # Abort 30s before deadline
    )
    ```
    
    **Common Configurations:**
    
    ```python
    # Fast API, short execution window
    TimeoutSettings(
        connect=5.0,
        read=30.0,
        execution=120,  # 2 minutes
        safety_buffer=20,
    )
    
    # Slow API, long execution window
    TimeoutSettings(
        connect=15.0,
        read=120.0,
        execution=600,  # 10 minutes
        safety_buffer=60,
    )
    ```
    
    Args:
        connect: Connection timeout in seconds (default: 10.0)
        read: Read timeout in seconds (default: 60.0)
        write: Write timeout in seconds (default: 60.0)
        pool: Connection pool timeout in seconds (default: 60.0)
        execution: Total execution time limit in seconds (default: None = disabled).
            **Recommended**: Set this to enable timeout awareness and state preservation.
        safety_buffer: Seconds before execution timeout to abort (default: 30.0).
            Ensures state is saved before hard timeout. Should be < execution.
    """
    connect: float = 10.0
    read: float = 60.0
    write: float = 60.0
    pool: float = 60.0
    execution: Optional[float] = None
    safety_buffer: float = 30.0

    def as_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(connect=self.connect, read=self.read, write=self.write, pool=self.pool)


@dataclass(slots=True)
class PaginationConfig:
    """Configuration for API pagination handling.
    
    The CollectorClient supports multiple pagination strategies. Choose the mode that matches
    your API's pagination style.
    
    **Pagination Mode Selection:**
    
    - **"cursor"**: Use when API returns a cursor/token in response (e.g., `{"next_cursor": "abc123"}`)
      - Required: `next_cursor_path` (e.g., "meta.next_cursor")
      - Optional: `cursor_param` (query param name, default: "cursor")
      - Example response: `{"data": {"events": [...]}, "meta": {"next_cursor": "abc123"}}`
      
    - **"page"**: Use when API uses page numbers (e.g., `?page=1&page=2`)
      - Required: `page_param` (default: "page")
      - Optional: `page_size_param` and `page_size` for fixed page sizes
      - Optional: `has_more_path` to check if more pages exist (e.g., "meta.has_more")
      - Example response: `{"events": [...], "page": 1, "has_more": true}`
      
    - **"offset"**: Use when API uses offset/limit (e.g., `?offset=0&limit=100`)
      - Required: `offset_param` (default: "offset")
      - Required: `page_size` and `page_size_param` for consistent page sizes
      - Example response: `{"items": [...], "total": 1000}`
      
    - **"link"**: Use when API returns RFC5988 Link headers or next URL in response
      - Required: `link_path` (e.g., "links.next" or "pagination.next_url")
      - Example response: `{"data": [...], "links": {"next": "https://api.example.com/events?page=2"}}`
      
    - **"none"**: No pagination (single request, all data in one response)
    
    **Examples:**
    
    Cursor-based pagination:
    ```python
    PaginationConfig(
        mode="cursor",
        next_cursor_path="meta.next_cursor",  # Path to cursor in JSON response
        cursor_param="cursor",  # Query param name (default)
        data_path="data.events",  # Optional: path to event array
    )
    ```
    
    Page-based pagination:
    ```python
    PaginationConfig(
        mode="page",
        page_param="page",
        page_size_param="per_page",
        page_size=100,
        start_page=1,  # Use 0 for zero-indexed pages
        has_more_path="meta.has_more",  # Optional: check this field
    )
    ```
    
    Offset-based pagination:
    ```python
    PaginationConfig(
        mode="offset",
        offset_param="offset",
        page_size_param="limit",
        page_size=100,  # Required for offset mode
    )
    ```
    
    **Common Mistakes:**
    
    1. Setting `mode="cursor"` but forgetting `next_cursor_path` (required!)
    2. Using `mode="offset"` without setting `page_size` (required!)
    3. Forgetting to set `data_path` when events are nested (e.g., response is `{"data": {"events": [...]}}`)
    4. Using wrong `start_page` value (check if API uses 0-indexed or 1-indexed pages)
    
    Args:
        mode: Pagination strategy. Must be one of: "cursor", "page", "offset", "link", "none"
        data_path: Optional dot-notation path to event array in response (e.g., "data.events").
            If not set, assumes events are at root level or uses CollectorRequest.data_path.
        cursor_param: Query parameter name for cursor token (default: "cursor")
        next_cursor_path: Dot-notation path to next cursor in response JSON.
            Required for cursor mode. Example: "meta.next_cursor" or "pagination.next"
        page_param: Query parameter name for page number (default: "page")
        start_page: First page number (default: 1, use 0 for zero-indexed APIs)
        page_size_param: Query parameter name for page size (e.g., "limit", "per_page", "size")
        page_size: Number of items per page. Required for offset mode, optional for page mode.
        has_more_path: Dot-notation path to boolean indicating more pages exist.
            Example: "meta.has_more" or "pagination.has_next"
        link_path: Dot-notation path to next page URL in response. Required for link mode.
            Example: "links.next" or "pagination.next_url"
        offset_param: Query parameter name for offset value (default: "offset")
        offset_step: Increment for offset (default: 0, auto-calculated from page_size if set)
        stop_when_empty: Stop pagination if a page returns 0 items (default: True)
        max_pages: Maximum number of pages to fetch (None = unlimited). Useful for testing or
            preventing runaway pagination.
    """
    mode: PaginationMode = "none"
    data_path: Optional[str] = None
    cursor_param: str = "cursor"
    next_cursor_path: Optional[str] = None
    page_param: str = "page"
    start_page: int = 1
    page_size_param: Optional[str] = None
    page_size: Optional[int] = None
    has_more_path: Optional[str] = None
    link_path: Optional[str] = None
    offset_param: str = "offset"
    offset_step: int = 0
    stop_when_empty: bool = True
    max_pages: Optional[int] = None


@dataclass(slots=True)
class CollectorRequest:
    """HTTP request configuration for event collection.
    
    Defines a single API request to fetch events. Can be used standalone or with shards
    for concurrent multi-endpoint collection.
    
    **Basic Usage:**
    
    ```python
    CollectorRequest(
        endpoint="/v1/events",
        data_path="data.events",  # Path to event array in response
        params={"filter": "active"},
    )
    ```
    
    **With Pagination:**
    
    ```python
    CollectorRequest(
        endpoint="/v1/events",
        data_path="data.events",
        pagination=PaginationConfig(
            mode="cursor",
            next_cursor_path="meta.next_cursor",
        ),
    )
    ```
    
    **With Shards (Concurrent Collection):**
    
    ```python
    CollectorRequest(
        endpoint="/v1/events",
        data_path="data.events",
        shards=[
            {"params": {"region": "us"}, "state_key": "events-us"},
            {"params": {"region": "eu"}, "state_key": "events-eu"},
        ],
    )
    ```
    
    **Common Mistakes:**
    
    1. Forgetting to set `data_path` when events are nested in response
       - Response: `{"data": {"events": [...]}}` → `data_path="data.events"`
       - Response: `{"items": [...]}` → `data_path="items"`
       - Response: `[...]` (array at root) → `data_path` not needed
    
    2. Setting `pagination` on request but also on blueprint (request takes precedence)
    
    3. Using `shards` without setting `default_strategy="concurrent"` in blueprint
    
    Args:
        endpoint: API endpoint path (must start with "/"). Example: "/v1/events"
        method: HTTP method to use. Default: "GET". Valid: "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
        params: Query parameters as dict. Example: `{"page": 1, "limit": 100}`
        json_body: Request body for POST/PUT requests. Can be dict, list, or any JSON-serializable value.
        headers: Custom HTTP headers. Example: `{"X-Custom-Header": "value"}`
        data_path: Dot-notation path to event array in response JSON.
            Example: "data.events" for `{"data": {"events": [...]}}`
            If not set, uses PaginationConfig.data_path or assumes root-level array.
        pagination: Pagination configuration. If None, uses blueprint's default pagination.
        stream: Enable streaming response (for large payloads). Default: False
        timeout: Per-request timeout override. If None, uses blueprint timeout settings.
        state_key: Key for storing pagination state in integration context.
            If None, uses endpoint path. Use unique keys for multiple requests.
        shards: List of shard configurations for concurrent collection.
            Each shard can override endpoint, params, headers, etc.
            Each shard maintains separate pagination state under its state_key.
    """
    endpoint: str
    method: HTTPMethod = "GET"
    params: Optional[Dict[str, Any]] = None
    json_body: Optional[Any] = None
    headers: Optional[Dict[str, str]] = None
    data_path: Optional[str] = None
    pagination: Optional[PaginationConfig] = None
    stream: bool = False
    timeout: Optional[TimeoutSettings] = None
    state_key: Optional[StateKey] = None
    shards: Optional[List[ShardConfig]] = None


@dataclass
class CollectorState:
    """Pagination and collection state for resuming after timeouts.
    
    Stores pagination position (cursor, page, offset) and metadata to allow seamless
    resumption of collection after timeouts or interruptions.
    
    **State Lifecycle:**
    
    1. **Initial State**: Created empty or loaded from integration context
       ```python
       state = CollectorState()  # Empty state
       # or
       state = CollectorState.from_dict(demisto.getLastRun().get("state", {}))
       ```
    
    2. **During Collection**: Automatically updated by PaginationEngine
       - Cursor mode: `state.cursor = next_cursor_value`
       - Page mode: `state.page += 1`
       - Offset mode: `state.offset += page_size`
    
    3. **After Timeout**: Saved to integration context for resume
       ```python
       if result.timed_out:
           demisto.setLastRun({"state": result.state.to_dict()})
       ```
    
    4. **Resume**: Loaded and passed to collect_events()
       ```python
       resume_state = CollectorState.from_dict(demisto.getLastRun().get("state", {}))
       result = client.collect_events_sync(resume_state=resume_state)
       ```
    
    **State Storage:**
    
    State is stored in integration context under:
    `integration_context["collector_client"][blueprint.name][state_key]`
    
    Each request/shard maintains separate state under its `state_key`.
    
    Args:
        cursor: Current cursor value for cursor-based pagination
        page: Current page number for page-based pagination
        offset: Current offset value for offset-based pagination
        last_event_id: Last processed event ID (for deduplication)
        partial_results: Events from incomplete pages (preserved on timeout)
        metadata: Custom metadata dictionary for storing additional state
    """
    cursor: Optional[Cursor] = None
    page: Optional[int] = None
    offset: Optional[int] = None
    last_event_id: Optional[EventID] = None
    partial_results: List[Any] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cursor": self.cursor,
            "page": self.page,
            "offset": self.offset,
            "last_event_id": self.last_event_id,
            "partial_results": self.partial_results,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, raw: Optional[Dict[str, Any]]) -> "CollectorState":
        if not raw:
            return cls()
        return cls(
            cursor=raw.get("cursor"),
            page=raw.get("page"),
            offset=raw.get("offset"),
            last_event_id=raw.get("last_event_id"),
            partial_results=raw.get("partial_results", []),
            metadata=raw.get("metadata", {}),
        )


class IntegrationContextStore:
    def __init__(self, collector_name: str):
        self.collector_name = collector_name
        self._lock = Lock()

    def read(self) -> Dict[str, Any]:
        context = demisto.getIntegrationContext() or {}
        namespace = context.get(STATE_NAMESPACE, {})
        return namespace.get(self.collector_name, {})

    def write(self, data: Dict[str, Any]) -> None:
        with self._lock:
            context = demisto.getIntegrationContext() or {}
            namespace = context.get(STATE_NAMESPACE, {})
            namespace[self.collector_name] = data
            context[STATE_NAMESPACE] = namespace
            demisto.setIntegrationContext(context)


class CollectorStateStore:
    def __init__(self, collector_name: str):
        self._store = IntegrationContextStore(collector_name)

    def load(self, key: StateKey = "default") -> CollectorState:
        raw = self._store.read()
        return CollectorState.from_dict(raw.get(key))

    def save(self, state: CollectorState, key: StateKey = "default") -> None:
        raw = self._store.read()
        raw[key] = state.to_dict()
        self._store.write(raw)


@dataclass
class CollectorRunResult:
    """Result of a collection run.
    
    Contains all events collected, state for resuming, and execution metrics.
    
    **Usage:**
    
    ```python
    result = client.collect_events_sync(limit=1000)
    
    # Process events
    for event in result.events:
        send_to_xsiam(event)
    
    # Check if timed out (need to resume)
    if result.timed_out:
        demisto.setLastRun({"state": result.state.to_dict()})
        return_warning(f"Collected {len(result.events)} events, will resume")
    
    # Check if collection is complete
    if result.exhausted:
        demisto.info("All events collected, collection complete")
    
    # Check metrics
    print(f"API calls: {result.metrics.success}, Errors: {result.metrics.general_error}")
    ```
    
    Args:
        events: List of collected events. Empty if no events found or collection failed.
        state: Aggregated state for all requests/shards. Use for resuming after timeout.
        timed_out: True if collection was interrupted by execution timeout.
            If True, save state and resume next run.
        exhausted: True if all pagination is complete (no more data available).
            If True, collection is fully complete.
        metrics: ExecutionMetrics with API call statistics (success, errors, retries, etc.)
    """
    events: List[Any]
    state: CollectorState
    timed_out: bool = False
    exhausted: bool = False
    metrics: Optional[ExecutionMetrics] = None


@dataclass
class CollectorBlueprint:
    """Blueprint defining a collector's complete configuration.
    
    The blueprint is the main configuration object that defines how the collector
    interacts with the API. It combines authentication, retry logic, rate limiting,
    pagination, and collection strategy into a single declarative configuration.
    
    **Minimal Setup (3 required fields):**
    
    ```python
    blueprint = CollectorBlueprint(
        name="MyCollector",
        base_url="https://api.example.com",
        request=CollectorRequest(endpoint="/v1/events", data_path="data.events"),
    )
    ```
    
    **Complete Example:**
    
    ```python
    blueprint = CollectorBlueprint(
        name="MyCollector",
        base_url=params["url"],
        request=CollectorRequest(
            endpoint="/v1/events",
            data_path="data.events",
            pagination=PaginationConfig(
                mode="cursor",
                next_cursor_path="meta.next_cursor",
            ),
        ),
        auth_handler=APIKeyAuthHandler(params["api_key"], header_name="X-API-Key"),
        retry_policy=RetryPolicy(max_attempts=5, initial_delay=1.0),
        rate_limit=RateLimitPolicy(rate_per_second=10, burst=20),
        timeout=TimeoutSettings(execution=300, safety_buffer=30),
        default_strategy="sequential",
        default_limit=1000,
        verify=params.get("insecure", "false").lower() != "true",  # SSL verification
        proxy=params.get("proxy", "false").lower() == "true",  # Use system proxy
    )
    ```
    
    **Collection Strategy Selection:**
    
    - **"sequential"** (default): Fetch pages one at a time, in order. Best for:
      - Single endpoint collection
      - APIs that require strict ordering
      - Low resource usage
    
    - **"concurrent"**: Fetch multiple shards in parallel. Best for:
      - Multiple endpoints/shards (must provide `request.shards`)
      - Independent data sources that can be fetched simultaneously
      - Higher throughput requirements
    
    - **"batch"**: Collect events and flush in batches. Best for:
      - Downstream systems that prefer batch processing
      - Memory-efficient processing of large datasets
    
    - **"stream"**: Process events as they arrive. Best for:
      - Real-time event processing
      - Large datasets where immediate processing is needed
    
    **Validation Rules:**
    
    - `name`: Must be a valid identifier (alphanumeric + underscores). Used for state storage.
    - `base_url`: Must be a valid HTTP(S) URL. Trailing slashes are automatically removed.
    - `request.endpoint`: Must start with "/"
    - `default_strategy`: Must be one of: "sequential", "concurrent", "batch", "stream"
    - `concurrency`: Must be >= 1 (only used with "concurrent" strategy)
    - `default_limit`: If set, must be > 0
    
    **Common Mistakes:**
    
    1. Forgetting to set `data_path` when events are nested (e.g., `{"data": {"events": [...]}}`)
    2. Setting `pagination.mode="cursor"` but forgetting `next_cursor_path`
    3. Using `default_strategy="concurrent"` without providing `shards` in request
    4. Setting `timeout.execution` to None when you need timeout awareness
    5. Using OAuth2 without providing `context_store` to auth handler (tokens won't persist)
    
    Args:
        name: Unique identifier for this collector. Used for state storage in integration context.
            Must be alphanumeric with underscores. Example: "MyCollector" or "EventCollector_v2"
        base_url: Base URL of the API. Must include protocol (http:// or https://).
            Trailing slashes are automatically removed.
        request: Primary request configuration. Defines endpoint, pagination, and request parameters.
        auth_handler: Authentication handler. None for unauthenticated APIs.
            Use APIKeyAuthHandler, BearerTokenAuthHandler, BasicAuthHandler, or OAuth2ClientCredentialsHandler.
        retry_policy: Retry configuration for handling transient failures.
            Default: 5 attempts with exponential backoff.
        rate_limit: Rate limiting configuration. Set rate_per_second > 0 to enable.
            Default: disabled (rate_per_second=0.0)
        circuit_breaker: Circuit breaker configuration for preventing cascading failures.
            Opens after failure_threshold consecutive failures.
        timeout: Timeout settings for HTTP requests and execution deadline.
            Set execution to enable timeout awareness and state preservation.
        default_strategy: Default collection strategy when not specified in collect_events().
            Must be: "sequential", "concurrent", "batch", or "stream"
        default_limit: Default maximum number of events to collect per run.
            None = unlimited. Can be overridden in collect_events(limit=...)
        concurrency: Maximum concurrent requests when using "concurrent" strategy.
            Default: 4. Only used with concurrent strategy and shards.
        diagnostic_mode: Enable verbose debug logging. Useful for troubleshooting.
            Default: False
        verify: Whether to verify SSL certificates (default: True).
            Set False to allow self-signed certificates. Matches BaseClient behavior.
        proxy: Whether to use system proxy (default: False).
            Set True to use HTTP_PROXY/HTTPS_PROXY environment variables.
            Matches BaseClient behavior.
    """
    name: str
    base_url: str
    request: CollectorRequest
    auth_handler: Optional["AuthHandler"] = None
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    rate_limit: RateLimitPolicy = field(default_factory=RateLimitPolicy)
    circuit_breaker: CircuitBreakerPolicy = field(default_factory=CircuitBreakerPolicy)
    timeout: TimeoutSettings = field(default_factory=TimeoutSettings)
    default_strategy: StrategyName = "sequential"
    default_limit: Optional[int] = None
    concurrency: int = 4
    diagnostic_mode: bool = False
    verify: bool = True
    proxy: bool = False


class ExecutionDeadline:
    def __init__(self, timeout: TimeoutSettings):
        self.settings = timeout
        self.started = _now()

    def seconds_remaining(self) -> Optional[float]:
        if self.settings.execution is None:
            return None
        elapsed = _now() - self.started
        remaining = self.settings.execution - elapsed
        return remaining

    def should_abort(self) -> bool:
        if self.settings.execution is not None and self.settings.execution <= self.settings.safety_buffer:
            return False
        remaining = self.seconds_remaining()
        if remaining is None:
            return False
        return remaining < self.settings.safety_buffer

    def enforce(self) -> None:
        if self.should_abort():
            raise CollectorTimeoutError(
                f"Execution deadline is approaching (<{self.settings.safety_buffer}s remaining)"
            )


class AuthHandler:
    """Abstract base class for authentication handlers.
    
    Subclasses must implement on_request() to add authentication to requests.
    Optionally override on_auth_failure() to handle 401/403 responses.
    """
    name: str = "auth"

    async def on_request(self, request: httpx.Request) -> None:
        """Modify the request to add authentication credentials.
        
        Args:
            request: The HTTP request to modify in-place.
        """
        raise NotImplementedError("Subclasses must implement on_request()")

    async def on_auth_failure(self, response: httpx.Response) -> bool:
        """Handle authentication failure response.
        
        Args:
            response: The HTTP response indicating auth failure (typically 401/403).
            
        Returns:
            True if the request should be retried immediately after refreshing auth,
            False otherwise.
        """
        return False


class APIKeyAuthHandler(AuthHandler):
    """Authentication handler for API key-based authentication.
    
    Supports API keys sent either in HTTP headers or query parameters.
    
    **Header-based API Key:**
    
    ```python
    auth = APIKeyAuthHandler(
        key=params["api_key"],
        header_name="X-API-Key",  # Common: "X-API-Key", "Authorization", "X-Auth-Token"
    )
    ```
    
    **Query Parameter API Key:**
    
    ```python
    auth = APIKeyAuthHandler(
        key=params["api_key"],
        query_param="api_key",  # Common: "api_key", "key", "apikey"
    )
    ```
    
    **Common Header Names:**
    - `X-API-Key` (most common)
    - `X-Auth-Token`
    - `Authorization` (if API expects just the key, not "Bearer {key}")
    - `X-API-Token`
    - `API-Key`
    
    **Common Query Parameter Names:**
    - `api_key`
    - `key`
    - `apikey`
    - `token`
    
    Args:
        key: The API key value (from integration parameters)
        header_name: HTTP header name to send the key in. Either this or query_param must be set.
        query_param: Query parameter name to send the key in. Either this or header_name must be set.
    
    Raises:
        CollectorConfigurationError: If neither header_name nor query_param is provided.
    """
    def __init__(self, key: str, header_name: Optional[str] = None, query_param: Optional[str] = None):
        if not header_name and not query_param:
            raise CollectorConfigurationError("APIKeyAuthHandler requires header_name or query_param")
        self.key = key
        self.header_name = header_name
        self.query_param = query_param
        self.name = "api_key"

    async def on_request(self, request: httpx.Request) -> None:
        if self.header_name:
            request.headers[self.header_name] = self.key
        if self.query_param:
            request.url = request.url.copy_add_param(self.query_param, self.key)


class BearerTokenAuthHandler(AuthHandler):
    """Authentication handler for Bearer token authentication.
    
    Adds `Authorization: Bearer {token}` header to requests.
    
    **Usage:**
    
    ```python
    auth = BearerTokenAuthHandler(token=params["bearer_token"])
    ```
    
    This is the simplest auth handler for APIs that use static Bearer tokens.
    For OAuth2 with automatic token refresh, use `OAuth2ClientCredentialsHandler` instead.
    
    Args:
        token: The Bearer token value (from integration parameters)
    """
    def __init__(self, token: str):
        self.token = token
        self.name = "bearer"

    async def on_request(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {self.token}"


class BasicAuthHandler(AuthHandler):
    """Authentication handler for HTTP Basic Authentication.
    
    Adds `Authorization: Basic {base64(username:password)}` header to requests.
    
    **Usage:**
    
    ```python
    auth = BasicAuthHandler(
        username=params["username"],
        password=params["password"],
    )
    ```
    
    This handler automatically base64-encodes the credentials according to RFC 7617.
    
    Args:
        username: HTTP Basic Auth username
        password: HTTP Basic Auth password
    """
    def __init__(self, username: str, password: str):
        credentials = f"{username}:{password}".encode("utf-8")
        self._encoded = base64.b64encode(credentials).decode("utf-8")
        self.name = "basic"

    async def on_request(self, request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Basic {self._encoded}"


class OAuth2ClientCredentialsHandler(AuthHandler):
    """Authentication handler for OAuth2 Client Credentials flow.
    
    Automatically fetches and refreshes OAuth2 access tokens using the client credentials
    grant type. Tokens are cached in memory and optionally persisted to integration context
    to survive across collector runs.
    
    **Basic Usage:**
    
    ```python
    context_store = IntegrationContextStore("MyCollector")
    auth = OAuth2ClientCredentialsHandler(
        token_url="https://api.example.com/oauth/token",
        client_id=params["client_id"],
        client_secret=params["client_secret"],
        context_store=context_store,  # Required for token persistence
    )
    ```
    
    **With Scope and Audience:**
    
    ```python
    auth = OAuth2ClientCredentialsHandler(
        token_url="https://api.example.com/oauth/token",
        client_id=params["client_id"],
        client_secret=params["client_secret"],
        scope="read:events write:events",  # Space-separated scopes
        audience="https://api.example.com",  # API audience/identifier
        context_store=context_store,
    )
    ```
    
    **Token Refresh Behavior:**
    
    - Tokens are automatically refreshed when they expire
    - Refresh happens `refresh_buffer` seconds before expiration (default: 60s)
    - If `context_store` is provided, tokens persist across collector runs
    - On 401 errors, token is invalidated and a new one is fetched
    
    **Token Persistence:**
    
    If `context_store` is provided, tokens are stored in integration context under:
    `integration_context["collector_client"][collector_name]["oauth2_token"]`
    
    This allows tokens to survive across collector runs, reducing API calls.
    
    **Common Mistakes:**
    
    1. Forgetting to provide `context_store` - tokens won't persist, causing extra API calls
    2. Setting `refresh_buffer` too low - may cause race conditions near expiration
    3. Not handling `CollectorAuthenticationError` - token fetch failures need handling
    
    **Error Handling:**
    
    Raises `CollectorAuthenticationError` if:
    - Token URL is unreachable
    - Client credentials are invalid
    - Token response is malformed
    
    Args:
        token_url: OAuth2 token endpoint URL. Example: "https://api.example.com/oauth/token"
        client_id: OAuth2 client ID (from integration parameters)
        client_secret: OAuth2 client secret (from integration parameters)
        scope: Optional space-separated list of OAuth2 scopes. Example: "read:events write:events"
        audience: Optional API audience/identifier. Some OAuth2 providers require this.
        verify: Whether to verify SSL certificates (default: True).
            **Should match CollectorBlueprint.verify** for consistency.
            Set False to allow self-signed certificates.
        proxy: Optional explicit proxy URL. Format: "http://proxy.example.com:8080"
            If None, uses HTTP_PROXY/HTTPS_PROXY environment variables (when CollectorBlueprint.proxy=True).
            **Note**: For consistency with CollectorBlueprint, prefer setting CollectorBlueprint.proxy=True
            and leaving this as None to use system proxy.
        refresh_buffer: Seconds before expiration to refresh token (default: 60).
            Prevents using expired tokens. Should be > 0.
        context_store: Optional IntegrationContextStore for token persistence.
            **Highly recommended** - without it, tokens are only cached in memory.
    """
    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: Optional[str] = None,
        audience: Optional[str] = None,
        verify: bool = True,
        proxy: Optional[str] = None,
        refresh_buffer: int = 60,
        context_store: Optional[IntegrationContextStore] = None,
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.audience = audience
        self.verify = verify
        self.proxy = proxy
        self.refresh_buffer = refresh_buffer
        self._context_store = context_store
        self._lock = anyio.Lock()
        self._token: Optional[str] = None
        self._expires_at: Optional[float] = None
        self.name = "oauth2"
        if context_store:
            self._load_from_context()

    def _load_from_context(self) -> None:
        if not self._context_store:
            return
        raw = self._context_store.read()
        token_data = raw.get("oauth2_token")
        if not token_data:
            return
        self._token = token_data.get("access_token")
        expires_at = token_data.get("expires_at")
        self._expires_at = float(expires_at) if expires_at is not None else None

    def _persist(self) -> None:
        if not self._context_store:
            return
        payload = {
            "oauth2_token": {
                "access_token": self._token,
                "expires_at": self._expires_at,
            }
        }
        current = self._context_store.read()
        current.update(payload)
        self._context_store.write(current)

    async def on_request(self, request: httpx.Request) -> None:
        await self._ensure_token()
        if not self._token:
            raise CollectorAuthenticationError("OAuth token is not available")
        request.headers["Authorization"] = f"Bearer {self._token}"

    async def on_auth_failure(self, response: httpx.Response) -> bool:
        if response.status_code == 401:
            async with self._lock:
                self._token = None
                self._expires_at = None
                await self._fetch_token()
            return True
        return False

    async def _ensure_token(self) -> None:
        async with self._lock:
            if self._token and self._expires_at:
                if _now() < (self._expires_at - self.refresh_buffer):
                    return
            await self._fetch_token()

    async def _fetch_token(self) -> None:
        data = {"grant_type": "client_credentials"}
        if self.scope:
            data["scope"] = self.scope
        if self.audience:
            data["audience"] = self.audience
        auth = (self.client_id, self.client_secret)
        timeout = httpx.Timeout(15.0)
        async with httpx.AsyncClient(verify=self.verify, proxies=self.proxy, timeout=timeout) as client:
            response = await client.post(self.token_url, data=data, auth=auth)
            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                raise CollectorAuthenticationError(f"OAuth token request failed: {exc.response.text}") from exc
            payload = response.json()
            self._token = payload.get("access_token")
            expires_in = payload.get("expires_in", 0)
            self._expires_at = _now() + float(expires_in)
            self._persist()


@dataclass
class RequestTrace:
    """Trace information for a single HTTP request."""
    method: str
    url: str
    headers: Dict[str, str]
    params: Dict[str, Any]
    body: Optional[Any]
    timestamp: float
    response_status: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[Any] = None
    elapsed_ms: Optional[float] = None
    error: Optional[str] = None
    retry_attempt: int = 0


@dataclass
class DiagnosticReport:
    """Comprehensive diagnostic report for troubleshooting."""
    collector_name: str
    configuration: Dict[str, Any]
    request_traces: List[RequestTrace]
    state_snapshots: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    errors: List[Dict[str, Any]]
    recommendations: List[str]
    timestamp: float


class CollectorLogger:
    """Enhanced logger with diagnostic capabilities."""
    
    def __init__(self, collector_name: str, diagnostic_mode: bool = False):
        self.collector_name = collector_name
        self.diagnostic_mode = diagnostic_mode
        self._traces: List[RequestTrace] = []
        self._errors: List[Dict[str, Any]] = []
        self._performance: Dict[str, List[float]] = {
            "request_times": [],
            "pagination_times": [],
            "auth_times": [],
        }

    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        if self.diagnostic_mode:
            demisto.debug(self._format("DEBUG", message, extra))

    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        demisto.info(self._format("INFO", message, extra))

    def error(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        demisto.error(self._format("ERROR", message, extra))
        if self.diagnostic_mode and extra:
            self._errors.append({"message": message, "context": extra})

    def trace_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Dict[str, Any],
        body: Optional[Any] = None,
        retry_attempt: int = 0,
    ) -> RequestTrace:
        """Record a request trace for diagnostic purposes.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            params: Query parameters
            body: Request body
            retry_attempt: Retry attempt number
            
        Returns:
            RequestTrace object for updating with response
        """
        trace = RequestTrace(
            method=method,
            url=url,
            headers=headers.copy(),
            params=params.copy(),
            body=body,
            timestamp=_now(),
            retry_attempt=retry_attempt,
        )
        if self.diagnostic_mode:
            self._traces.append(trace)
        return trace

    def trace_response(
        self,
        trace: RequestTrace,
        status: int,
        headers: Dict[str, str],
        body: Any,
        elapsed_ms: float,
    ) -> None:
        """Update trace with response information.
        
        Args:
            trace: RequestTrace to update
            status: HTTP status code
            headers: Response headers
            body: Response body
            elapsed_ms: Request duration in milliseconds
        """
        trace.response_status = status
        trace.response_headers = headers.copy()
        trace.response_body = body
        trace.elapsed_ms = elapsed_ms
        
        if self.diagnostic_mode:
            self._performance["request_times"].append(elapsed_ms)
            self.debug(
                "HTTP request completed",
                {
                    "method": trace.method,
                    "url": trace.url,
                    "status": status,
                    "elapsed_ms": elapsed_ms,
                    "retry_attempt": trace.retry_attempt,
                },
            )

    def trace_error(
        self,
        trace: RequestTrace,
        error: str,
        elapsed_ms: Optional[float] = None,
    ) -> None:
        """Record an error in a trace.
        
        Args:
            trace: RequestTrace to update
            error: Error message
            elapsed_ms: Request duration before error
        """
        trace.error = error
        if elapsed_ms:
            trace.elapsed_ms = elapsed_ms
        
        if self.diagnostic_mode:
            self.error("HTTP request failed", {"url": trace.url, "error": error, "retry_attempt": trace.retry_attempt})

    def get_diagnostic_report(
        self,
        configuration: Dict[str, Any],
        state_snapshots: Optional[List[Dict[str, Any]]] = None,
    ) -> DiagnosticReport:
        """Generate a comprehensive diagnostic report.
        
        Args:
            configuration: Collector configuration
            state_snapshots: State snapshots at different points
            
        Returns:
            DiagnosticReport with all diagnostic information
        """
        # Calculate performance metrics
        perf_metrics: Dict[str, Any] = {}
        if self._performance["request_times"]:
            times = self._performance["request_times"]
            perf_metrics["avg_request_time_ms"] = sum(times) / len(times)
            perf_metrics["min_request_time_ms"] = min(times)
            perf_metrics["max_request_time_ms"] = max(times)
            perf_metrics["total_requests"] = len(times)
        
        # Generate recommendations
        recommendations: List[str] = []
        
        if self._errors:
            error_types = {}
            for err in self._errors:
                err_type = err.get("context", {}).get("error_type", "unknown")
                error_types[err_type] = error_types.get(err_type, 0) + 1
            
            if error_types.get("auth", 0) > 0:
                recommendations.append("Authentication errors detected. Check credentials and token expiration.")
            if error_types.get("rate_limit", 0) > 0:
                recommendations.append("Rate limit errors detected. Consider increasing rate_limit.rate_per_second.")
            if error_types.get("timeout", 0) > 0:
                recommendations.append("Timeout errors detected. Consider increasing timeout settings.")
            if error_types.get("network", 0) > 0:
                recommendations.append("Network errors detected. Check connectivity and proxy settings.")
        
        if perf_metrics.get("avg_request_time_ms", 0) > 5000:
            recommendations.append("Slow request times detected. Consider optimizing API calls or increasing timeouts.")
        
        if self._traces:
            retry_count = sum(1 for t in self._traces if t.retry_attempt > 0)
            if retry_count > len(self._traces) * 0.5:
                recommendations.append("High retry rate detected. Check API health and retry policy configuration.")
        
        return DiagnosticReport(
            collector_name=self.collector_name,
            configuration=configuration,
            request_traces=self._traces.copy(),
            state_snapshots=state_snapshots or [],
            performance_metrics=perf_metrics,
            errors=self._errors.copy(),
            recommendations=recommendations,
            timestamp=_now(),
        )

    def _format(self, level: str, message: str, extra: Optional[Dict[str, Any]]) -> str:
        if not extra:
            return f"[CollectorClient:{self.collector_name}:{level}] {message}"
        return f"[CollectorClient:{self.collector_name}:{level}] {message} | extra={json.dumps(sanitize(extra))}"


class PaginationEngine:
    def __init__(self, config: Optional[PaginationConfig], state: CollectorState):
        self.config = config or PaginationConfig()
        self.state = state
        if self.state.page is None:
            self.state.page = self.config.start_page
        if self.state.offset is None:
            self.state.offset = 0

    def prepare(self, request: CollectorRequest) -> CollectorRequest:
        if self.config.mode == "none":
            return request
        params = _ensure_dict(request.params)
        if self.config.mode == "cursor" and self.state.cursor:
            params[self.config.cursor_param] = self.state.cursor
        elif self.config.mode == "page":
            params[self.config.page_param] = self.state.page or self.config.start_page
            if self.config.page_size_param and self.config.page_size:
                params[self.config.page_size_param] = self.config.page_size
        elif self.config.mode == "offset":
            params[self.config.offset_param] = self.state.offset or 0
            if self.config.page_size_param and self.config.page_size:
                params[self.config.page_size_param] = self.config.page_size
        return CollectorRequest(
            endpoint=request.endpoint,
            method=request.method,
            params=params,
            json_body=request.json_body,
            headers=request.headers,
            data_path=request.data_path,
            pagination=request.pagination,
            stream=request.stream,
            timeout=request.timeout,
        )

    def advance(self, response_payload: Dict[str, Any], items_returned: int) -> bool:
        if self.config.mode == "none":
            return False
        if self.config.mode == "cursor":
            cursor_value = _resolve_path(response_payload, self.config.next_cursor_path)
            self.state.cursor = cursor_value
            self.state.metadata["has_more"] = bool(cursor_value)
            return bool(cursor_value)
        if self.config.mode == "page":
            has_more = _resolve_path(response_payload, self.config.has_more_path)
            if has_more is None and self.config.page_size and self.config.stop_when_empty:
                has_more = items_returned >= self.config.page_size
            if has_more:
                self.state.page = (self.state.page or self.config.start_page) + 1
            self.state.metadata["has_more"] = bool(has_more)
            return bool(has_more)
        if self.config.mode == "offset":
            if self.config.page_size:
                self.state.offset = (self.state.offset or 0) + self.config.page_size
                has_more = items_returned >= self.config.page_size
                self.state.metadata["has_more"] = has_more
                return has_more
            self.state.metadata["has_more"] = False
            return False
        if self.config.mode == "link":
            link = _resolve_path(response_payload, self.config.link_path)
            self.state.metadata["next_link"] = link
            return bool(link)
        return False


class CollectionStrategy:
    name = "sequential"

    async def collect(self, executor: "CollectorExecutor") -> List[Any]:  # pragma: no cover - interface
        raise NotImplementedError()

    async def collect_many(self, executors: List["CollectorExecutor"]) -> List[Any]:
        results: List[Any] = []
        for executor in executors:
            results.extend(await self.collect(executor))
        return results


class SequentialCollectionStrategy(CollectionStrategy):
    name = "sequential"

    async def collect(self, executor: "CollectorExecutor") -> List[Any]:
        events: List[Any] = []
        async for page in executor.iter_pages():
            events.extend(page)
            if executor.limit and len(events) >= executor.limit:
                return events[: executor.limit]
        return events


class ConcurrentCollectionStrategy(CollectionStrategy):
    name = "concurrent"

    def __init__(self, concurrency: int = 4):
        self.concurrency = max(1, concurrency)

    async def collect(self, executor: "CollectorExecutor") -> List[Any]:
        # Default to sequential for single executor usage.
        return await SequentialCollectionStrategy().collect(executor)

    async def collect_many(self, executors: List["CollectorExecutor"]) -> List[Any]:
        results: List[Any] = []
        results_lock = anyio.Lock()
        semaphore = anyio.Semaphore(self.concurrency)

        async def run(executor: "CollectorExecutor") -> None:
            async with semaphore:
                chunk = await SequentialCollectionStrategy().collect(executor)
            async with results_lock:
                results.extend(chunk)

        async with anyio.create_task_group() as task_group:
            for executor in executors:
                task_group.start_soon(run, executor)

        return results


class BatchCollectionStrategy(CollectionStrategy):
    name = "batch"

    def __init__(self, batch_size: int = 500):
        self.batch_size = batch_size

    async def collect(self, executor: "CollectorExecutor") -> List[Any]:
        batch: List[Any] = []
        async for page in executor.iter_pages():
            batch.extend(page)
            if len(batch) >= self.batch_size:
                executor.flush_batch(batch)
                batch = []
        if batch:
            executor.flush_batch(batch)
        return executor.fetched_events


class StreamCollectionStrategy(CollectionStrategy):
    name = "stream"

    async def collect(self, executor: "CollectorExecutor") -> List[Any]:
        async for page in executor.iter_pages():
            executor.stream_batch(page)
        return executor.fetched_events


STRATEGY_MAP: Dict[str, Type[CollectionStrategy]] = {
    SequentialCollectionStrategy.name: SequentialCollectionStrategy,
    ConcurrentCollectionStrategy.name: ConcurrentCollectionStrategy,
    BatchCollectionStrategy.name: BatchCollectionStrategy,
    StreamCollectionStrategy.name: StreamCollectionStrategy,
}


class CollectorExecutor:
    def __init__(
        self,
        client: "CollectorClient",
        request: CollectorRequest,
        pagination: PaginationEngine,
        limit: Optional[int],
        deadline: ExecutionDeadline,
        state_key: StateKey,
    ):
        self.client: "CollectorClient" = client
        self.original_request: CollectorRequest = request
        self.pagination: PaginationEngine = pagination
        self.limit: Optional[int] = limit
        self.deadline: ExecutionDeadline = deadline
        self.metrics: ExecutionMetrics = client.metrics
        self.fetched_events: List[Any] = []
        self.state_key: StateKey = state_key

    async def iter_pages(self) -> AsyncIterator[List[Any]]:
        page = 0
        keep_going = True
        while keep_going:
            self.deadline.enforce()
            prepared = self.pagination.prepare(self.original_request)
            response = await self.client._request(prepared)
            payload = response.json()
            events = _extract_list(payload, prepared.data_path or self.original_request.data_path)
            self.fetched_events.extend(events)
            keep_going = self.pagination.advance(payload, len(events))
            page += 1
            yield events
            if self.pagination.config.max_pages and page >= self.pagination.config.max_pages:
                break
            if self.limit and len(self.fetched_events) >= self.limit:
                break

    async def page_indexes(self) -> AsyncIterator[int]:
        index = 0
        while True:
            self.deadline.enforce()
            prepared = self.pagination.prepare(self.original_request)
            response = await self.client._request(prepared)
            payload = response.json()
            events = _extract_list(payload, prepared.data_path or self.original_request.data_path)
            self.fetched_events.extend(events)
            keep_going = self.pagination.advance(payload, len(events))
            yield index
            index += 1
            if not keep_going or (self.limit and len(self.fetched_events) >= self.limit):
                break

    async def fetch_page(self, index: int) -> List[Any]:
        prepared = self.pagination.prepare(self.original_request)
        response = await self.client._request(prepared)
        payload = response.json()
        page_events = _extract_list(payload, prepared.data_path or self.original_request.data_path)
        self.fetched_events.extend(page_events)
        self.pagination.advance(payload, len(page_events))
        return page_events

    def flush_batch(self, batch: List[Any]) -> None:
        self.client.logger.info("Flushing batch", {"batch_size": len(batch)})
        self.fetched_events.extend(batch)

    def stream_batch(self, batch: List[Any]) -> None:
        self.client.logger.debug("Streaming batch", {"batch_size": len(batch)})
        self.fetched_events.extend(batch)


class CollectorClient:
    """High-performance async-first HTTP client for event collection.
    
    The CollectorClient provides a complete solution for fetching events from REST APIs
    with built-in pagination, authentication, retry logic, rate limiting, and state management.
    
    **Basic Usage:**
    
    ```python
    # Create blueprint
    blueprint = CollectorBlueprint(
        name="MyCollector",
        base_url="https://api.example.com",
        request=CollectorRequest(endpoint="/v1/events", data_path="data.events"),
        auth_handler=APIKeyAuthHandler("secret", header_name="X-API-Key"),
    )
    
    # Create client
    client = CollectorClient(blueprint)
    
    # Collect events (synchronous wrapper)
    result = client.collect_events_sync(limit=1000)
    
    # Process results
    for event in result.events:
        process_event(event)
    
    # Check metrics
    print(f"Success: {result.metrics.success}, Errors: {result.metrics.general_error}")
    ```
    
    **Resume After Timeout:**
    
    ```python
    # Load previous state
    last_run = demisto.getLastRun()
    resume_state = None
    if last_run.get("state"):
        resume_state = CollectorState.from_dict(last_run["state"])
    
    # Collect with resume
    result = client.collect_events_sync(resume_state=resume_state, limit=5000)
    
    # Save state if timed out
    if result.timed_out:
        demisto.setLastRun({"state": result.state.to_dict()})
        return_warning(f"Fetched {len(result.events)} events, will resume next run")
    ```
    
    **Error Handling:**
    
    The client raises these exceptions (all inherit from CollectorError):
    
    - `CollectorAuthenticationError`: Auth failed and cannot be recovered
      → Check credentials, token expiration, OAuth configuration
    
    - `CollectorRateLimitError`: Client-side rate limit exceeded
      → Increase RateLimitPolicy.rate_per_second or RateLimitPolicy.burst
    
    - `CollectorTimeoutError`: Execution deadline approaching
      → Check result.timed_out, use result.state to resume next run
    
    - `CollectorCircuitOpenError`: Too many failures, circuit breaker opened
      → Wait for recovery_timeout, check API health
    
    - `CollectorRetryError`: All retry attempts exhausted
      → Check retry_policy.max_attempts, examine last_error
    
    - `CollectorConfigurationError`: Invalid blueprint/request configuration
      → Check required fields, validate pagination config matches API
    
    **State Management:**
    
    State is automatically stored in integration context under:
    `integration_context["collector_client"][blueprint.name][state_key]`
    
    Each request (or shard) maintains separate state under its `state_key`.
    State includes pagination cursors, page numbers, offsets, and custom metadata.
    
    Args:
        blueprint: Complete collector configuration (required)
        metrics: Optional ExecutionMetrics instance for tracking API calls.
            If None, creates a new instance.
        state_store: Optional state store for persistence. If None, creates
            CollectorStateStore using blueprint.name.
    """
    def __init__(
        self,
        blueprint: CollectorBlueprint,
        *,
        metrics: Optional[ExecutionMetrics] = None,
        state_store: Optional[CollectorStateStore] = None,
    ):
        self.blueprint = blueprint
        self.metrics = metrics or ExecutionMetrics()
        self.state_store = state_store or CollectorStateStore(blueprint.name)
        self.logger = CollectorLogger(blueprint.name, diagnostic_mode=blueprint.diagnostic_mode)
        self.auth_handler = blueprint.auth_handler
        self.retry_policy = blueprint.retry_policy
        self.circuit_breaker = CircuitBreaker(blueprint.circuit_breaker)
        self.rate_limiter = (
            TokenBucketRateLimiter(blueprint.rate_limit) if blueprint.rate_limit.enabled else None
        )
        self.timeouts = blueprint.timeout
        
        # Handle proxy configuration (matches BaseClient behavior)
        if blueprint.proxy:
            ensure_proxy_has_http_prefix()  # type: ignore[name-defined]  # noqa: F405
        else:
            skip_proxy()  # type: ignore[name-defined]  # noqa: F405
        
        # Handle SSL verification (matches BaseClient behavior)
        if not blueprint.verify:
            skip_cert_verification()  # type: ignore[name-defined]  # noqa: F405
        
        # httpx automatically uses HTTP_PROXY/HTTPS_PROXY environment variables when available
        # We configure verify parameter for SSL certificate validation
        try:
            self._client = httpx.AsyncClient(
                base_url=blueprint.base_url.rstrip("/"),
                timeout=self.timeouts.as_httpx(),
                headers={"User-Agent": DEFAULT_USER_AGENT},
                verify=blueprint.verify,
                http2=True,
            )
        except ImportError:
            self.logger.info("HTTP/2 dependencies missing, falling back to HTTP/1.1 transport")
            self._client = httpx.AsyncClient(
                base_url=blueprint.base_url.rstrip("/"),
                timeout=self.timeouts.as_httpx(),
                headers={"User-Agent": DEFAULT_USER_AGENT},
                verify=blueprint.verify,
                http2=False,
            )
        self._client_lock = anyio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    def close(self) -> None:
        anyio.run(self.aclose)

    async def _request(self, request: CollectorRequest) -> httpx.Response:
        if not self.circuit_breaker.can_execute():
            raise CollectorCircuitOpenError("Circuit breaker is open, refusing to send request")

        if self.rate_limiter:
            await self.rate_limiter.acquire()

        params = _ensure_dict(request.params)
        headers = _ensure_dict(request.headers)
        if "User-Agent" not in headers:
            headers["User-Agent"] = DEFAULT_USER_AGENT

        attempt = 0
        last_error: Optional[Exception] = None
        trace: Optional[RequestTrace] = None
        
        while attempt < self.retry_policy.max_attempts:
            attempt += 1
            start = _now()
            try:
                http_request = self._client.build_request(
                    request.method.upper(),
                    url=request.endpoint,
                    params=params,
                    json=request.json_body,
                    headers=headers,
                )

                if self.auth_handler:
                    await self.auth_handler.on_request(http_request)

                # Trace request if in diagnostic mode
                if self.blueprint.diagnostic_mode:
                    full_url = str(http_request.url)
                    trace = self.logger.trace_request(
                        method=request.method.upper(),
                        url=full_url,
                        headers=dict(http_request.headers),
                        params=params,
                        body=request.json_body,
                        retry_attempt=attempt - 1,
                    )

                response = await self._client.send(http_request, stream=request.stream)
                elapsed_ms = (_now() - start) * 1000
                
                if self.blueprint.diagnostic_mode and trace:
                    try:
                        response_body = response.json() if response.content else None
                    except Exception:
                        response_body = response.text[:1000]  # Truncate large responses
                    
                    self.logger.trace_response(
                        trace,
                        status=response.status_code,
                        headers=dict(response.headers),
                        body=response_body,
                        elapsed_ms=elapsed_ms,
                    )
                
                if response.status_code == 401 and self.auth_handler:
                    should_retry = await self.auth_handler.on_auth_failure(response)
                    if should_retry:
                        continue
                if response.status_code in self.retry_policy.retryable_status_codes:
                    raise httpx.HTTPStatusError("Retryable status", request=http_request, response=response)
                response.raise_for_status()
                self.metrics.success += 1
                self.circuit_breaker.record_success()
                self.logger.debug(
                    "HTTP request completed",
                    {"status": response.status_code, "elapsed": elapsed_ms, "endpoint": request.endpoint},
                )
                return response
            except tuple(self.retry_policy.retryable_exceptions) as exc:
                last_error = exc
                elapsed_ms = (_now() - start) * 1000
                if self.blueprint.diagnostic_mode and trace:
                    self.logger.trace_error(trace, str(exc), elapsed_ms)
                
                should_retry = attempt < self.retry_policy.max_attempts
                if not should_retry:
                    break
                retry_after = _parse_retry_after(getattr(exc, "response", None))
                delay = self.retry_policy.next_delay(attempt, retry_after)
                self.metrics.retry_error += 1
                self.logger.debug(
                    "Retryable exception occurred",
                    {"attempt": attempt, "delay": delay, "error": str(exc), "error_type": type(exc).__name__},
                )
                await anyio.sleep(delay)
            except httpx.HTTPStatusError as exc:
                last_error = exc
                elapsed_ms = (_now() - start) * 1000
                if self.blueprint.diagnostic_mode and trace:
                    try:
                        response_body = exc.response.json() if exc.response.content else None
                    except Exception:
                        response_body = exc.response.text[:1000]
                    self.logger.trace_response(
                        trace,
                        status=exc.response.status_code,
                        headers=dict(exc.response.headers),
                        body=response_body,
                        elapsed_ms=elapsed_ms,
                    )
                    self.logger.trace_error(trace, f"HTTP {exc.response.status_code}: {exc.response.text[:200]}")
                
                if exc.response.status_code == 429:
                    self.metrics.quota_error += 1
                    self.logger.error("Rate limit error", {"status": 429, "error_type": "rate_limit"})
                elif exc.response.status_code in (401, 403):
                    self.metrics.auth_error += 1
                    self.logger.error("Authentication error", {"status": exc.response.status_code, "error_type": "auth"})
                else:
                    self.metrics.service_error += 1
                    self.logger.error("Service error", {"status": exc.response.status_code, "error_type": "service"})
                
                should_retry = exc.response.status_code in self.retry_policy.retryable_status_codes
                if should_retry and attempt < self.retry_policy.max_attempts:
                    retry_after = _parse_retry_after(exc.response)
                    delay = self.retry_policy.next_delay(attempt, retry_after)
                    self.metrics.retry_error += 1
                    await anyio.sleep(delay)
                    continue
                self.circuit_breaker.record_failure()
                raise CollectorError(f"Request failed: {exc.response.text}") from exc
            except Exception as exc:
                elapsed_ms = (_now() - start) * 1000
                if self.blueprint.diagnostic_mode and trace:
                    self.logger.trace_error(trace, str(exc), elapsed_ms)
                
                self.metrics.general_error += 1
                self.circuit_breaker.record_failure()
                self.logger.error("Non-retryable exception occurred", {"error": str(exc), "error_type": type(exc).__name__})
                raise
        self.circuit_breaker.record_failure()
        raise CollectorRetryError(f"Exceeded retry attempts: {last_error}")  # type: ignore[name-defined]

    def request_sync(self, request: CollectorRequest) -> httpx.Response:
        return anyio.run(self._request, request)

    async def collect_events(
        self,
        request: Optional[Union[CollectorRequest, Sequence[CollectorRequest]]] = None,
        strategy: Union[StrategyName, CollectionStrategy, None] = None,
        limit: Optional[int] = None,
        resume_state: Optional[CollectorState] = None,
    ) -> CollectorRunResult:
        """Asynchronously collect events from the API.
        
        This is the main collection method. It handles pagination, state management,
        timeout detection, and error recovery automatically.
        
        **Basic Usage:**
        
        ```python
        result = await client.collect_events(limit=1000)
        events = result.events
        ```
        
        **With Custom Request:**
        
        ```python
        custom_request = CollectorRequest(
            endpoint="/v1/other-events",
            data_path="items",
            pagination=PaginationConfig(mode="page", page_param="p"),
        )
        result = await client.collect_events(request=custom_request)
        ```
        
        **With Multiple Requests:**
        
        ```python
        requests = [
            CollectorRequest(endpoint="/v1/events", state_key="events"),
            CollectorRequest(endpoint="/v1/alerts", state_key="alerts"),
        ]
        result = await client.collect_events(request=requests, strategy="concurrent")
        ```
        
        **Resume After Timeout:**
        
        ```python
        # Load previous state
        last_state = CollectorState.from_dict(demisto.getLastRun().get("state"))
        
        # Resume collection
        result = await client.collect_events(resume_state=last_state, limit=5000)
        
        # Check if timed out
        if result.timed_out:
            # Save state for next run
            demisto.setLastRun({"state": result.state.to_dict()})
        ```
        
        **State Management:**
        
        - If `resume_state` is provided, it's used to restore pagination position
        - State is automatically saved after collection completes
        - Each request/shard maintains separate state under its `state_key`
        - State includes: cursor, page, offset, last_event_id, partial_results, metadata
        
        **Timeout Handling:**
        
        - If execution timeout is approaching, raises `CollectorTimeoutError`
        - Partial results are preserved in `result.events`
        - State is saved automatically, allowing seamless resume
        - Set `blueprint.timeout.execution` to enable timeout awareness
        
        **Return Value:**
        
        Returns `CollectorRunResult` containing:
        - `events`: List of collected events
        - `state`: Aggregated state for all requests/shards
        - `timed_out`: True if collection was interrupted by timeout
        - `exhausted`: True if all pagination is complete (no more data)
        - `metrics`: ExecutionMetrics with API call statistics
        
        Args:
            request: Optional request override. Can be:
                - None: Uses blueprint.request
                - CollectorRequest: Single request override
                - List[CollectorRequest]: Multiple requests (use with "concurrent" strategy)
            strategy: Collection strategy override. Can be:
                - None: Uses blueprint.default_strategy
                - StrategyName: "sequential", "concurrent", "batch", or "stream"
                - CollectionStrategy: Custom strategy instance
            limit: Maximum number of events to collect. Overrides blueprint.default_limit.
                None = unlimited. Applies across all requests/shards.
            resume_state: State to resume from (typically from previous timeout).
                If provided, restores pagination position. Can be:
                - None: Starts fresh or loads from integration context
                - CollectorState: Single state for all requests
                - Dict with state_key -> CollectorState mapping (for multiple shards)
        
        Returns:
            CollectorRunResult with events, state, and metrics.
        
        Raises:
            CollectorTimeoutError: Execution deadline approaching (if timeout.execution is set)
            CollectorAuthenticationError: Authentication failed
            CollectorRateLimitError: Rate limit exceeded
            CollectorCircuitOpenError: Circuit breaker is open
            CollectorRetryError: All retry attempts exhausted
            CollectorConfigurationError: Invalid request/strategy configuration
        """
        requests = self._normalize_requests(request)
        expanded_requests: List[CollectorRequest] = []
        for req in requests:
            expanded_requests.extend(self._expand_shards(req))

        resume_map = self._resume_state_map(resume_state)
        executors: List[CollectorExecutor] = []
        for req in expanded_requests:
            state_key: StateKey = req.state_key or req.endpoint
            state = resume_map.get(state_key) or resume_map.get("default") or self.state_store.load(state_key)
            pagination = PaginationEngine(req.pagination or self.blueprint.request.pagination, state)
            executor = CollectorExecutor(
                self,
                req,
                pagination,
                limit or self.blueprint.default_limit,
                ExecutionDeadline(self.timeouts),
                state_key,
            )
            executors.append(executor)

        strategy_instance = self._build_strategy(strategy)
        timed_out = False
        try:
            events = await strategy_instance.collect_many(executors)
        except CollectorTimeoutError:
            timed_out = True
            events = []
            for executor in executors:
                events.extend(executor.fetched_events)

        for executor in executors:
            self.state_store.save(executor.pagination.state, executor.state_key)

        aggregated_state = self._aggregate_state(executors)
        exhausted = all(self._is_state_exhausted(executor.pagination.state) for executor in executors)

        return CollectorRunResult(
            events=events,
            state=aggregated_state,
            timed_out=timed_out,
            exhausted=exhausted,
            metrics=self.metrics,
        )

    def collect_events_sync(
        self,
        request: Optional[Union[CollectorRequest, Sequence[CollectorRequest]]] = None,
        strategy: Union[StrategyName, CollectionStrategy, None] = None,
        limit: Optional[int] = None,
        resume_state: Optional[CollectorState] = None,
    ) -> CollectorRunResult:
        """Synchronous wrapper for collect_events().
        
        This is the recommended method for most integrations as it provides a simple
        synchronous interface while using async internals for performance.
        
        **Usage:**
        
        ```python
        # Simple collection
        result = client.collect_events_sync(limit=1000)
        
        # With resume
        last_state = CollectorState.from_dict(demisto.getLastRun().get("state", {}))
        result = client.collect_events_sync(resume_state=last_state)
        
        # Check results
        if result.timed_out:
            demisto.setLastRun({"state": result.state.to_dict()})
        else:
            send_events_to_xsiam(result.events)
        ```
        
        This method is equivalent to `anyio.run(client.collect_events, ...)` and provides
        the same functionality as the async version, but can be called from synchronous code.
        
        Args:
            request: Optional request override (see collect_events() for details)
            strategy: Optional strategy override (see collect_events() for details)
            limit: Maximum events to collect (see collect_events() for details)
            resume_state: State to resume from (see collect_events() for details)
        
        Returns:
            CollectorRunResult with events, state, and metrics.
        
        Raises:
            Same exceptions as collect_events().
        """
        return anyio.run(self.collect_events, request, strategy, limit, resume_state)

    def get_diagnostic_report(self, state_snapshots: Optional[List[Dict[str, Any]]] = None) -> DiagnosticReport:
        """Generate a comprehensive diagnostic report for troubleshooting.
        
        This method collects all diagnostic information including request traces,
        performance metrics, errors, and provides actionable recommendations.
        
        **Usage:**
        
        ```python
        # Enable diagnostic mode
        blueprint.diagnostic_mode = True
        client = CollectorClient(blueprint)
        
        try:
            result = client.collect_events_sync()
        except Exception as e:
            # Get diagnostic report
            report = client.get_diagnostic_report()
            
            # Print recommendations
            for rec in report.recommendations:
                print(f"Recommendation: {rec}")
            
            # Inspect errors
            for error in report.errors:
                print(f"Error: {error['message']}")
                print(f"Context: {error['context']}")
        ```
        
        **Report Contents:**
        
        - Configuration: Full collector configuration
        - Request Traces: All HTTP requests with full request/response data
        - State Snapshots: State at different points in execution
        - Performance Metrics: Request times, throughput, etc.
        - Errors: All errors encountered with context
        - Recommendations: Actionable suggestions for fixing issues
        
        Args:
            state_snapshots: Optional list of state snapshots at different points
            
        Returns:
            DiagnosticReport with all diagnostic information
        """
        config = {
            "name": self.blueprint.name,
            "base_url": self.blueprint.base_url,
            "endpoint": self.blueprint.request.endpoint,
            "data_path": self.blueprint.request.data_path,
            "pagination_mode": self.blueprint.request.pagination.mode if self.blueprint.request.pagination else None,
            "auth_type": self.blueprint.auth_handler.name if self.blueprint.auth_handler else None,
            "retry_policy": {
                "max_attempts": self.retry_policy.max_attempts,
                "initial_delay": self.retry_policy.initial_delay,
                "max_delay": self.retry_policy.max_delay,
            },
            "rate_limit": {
                "rate_per_second": self.blueprint.rate_limit.rate_per_second,
                "burst": self.blueprint.rate_limit.burst,
            },
            "timeout": {
                "execution": self.timeouts.execution,
                "connect": self.timeouts.connect,
                "read": self.timeouts.read,
            },
        }
        
        return self.logger.get_diagnostic_report(config, state_snapshots)

    def diagnose_error(self, error: Exception) -> Dict[str, Any]:
        """Diagnose a specific error and provide actionable guidance.
        
        Analyzes the error type and context to provide specific recommendations.
        
        **Usage:**
        
        ```python
        try:
            result = client.collect_events_sync()
        except CollectorError as e:
            diagnosis = client.diagnose_error(e)
            print(f"Issue: {diagnosis['issue']}")
            print(f"Solution: {diagnosis['solution']}")
        ```
        
        Args:
            error: The exception to diagnose
            
        Returns:
            Dictionary with issue description, root cause, and solution
        """
        diagnosis: Dict[str, Any] = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "issue": "",
            "root_cause": "",
            "solution": "",
            "related_config": {},
        }
        
        if isinstance(error, CollectorAuthenticationError):
            diagnosis["issue"] = "Authentication failed"
            diagnosis["root_cause"] = "Invalid credentials, expired token, or incorrect auth configuration"
            diagnosis["solution"] = (
                "1. Verify credentials are correct\n"
                "2. Check token expiration (for OAuth2)\n"
                "3. Verify auth handler configuration matches API requirements\n"
                "4. Check if API requires additional scopes or permissions"
            )
            diagnosis["related_config"] = {
                "auth_handler": self.blueprint.auth_handler.name if self.blueprint.auth_handler else None,
            }
        
        elif isinstance(error, CollectorRateLimitError):
            diagnosis["issue"] = "Rate limit exceeded"
            diagnosis["root_cause"] = "Request rate exceeds API limits or configured rate limit"
            diagnosis["solution"] = (
                "1. Increase rate_limit.rate_per_second in blueprint\n"
                "2. Increase rate_limit.burst for temporary spikes\n"
                "3. Reduce concurrency if using concurrent strategy\n"
                "4. Check API documentation for actual rate limits"
            )
            diagnosis["related_config"] = {
                "rate_per_second": self.blueprint.rate_limit.rate_per_second,
                "burst": self.blueprint.rate_limit.burst,
            }
        
        elif isinstance(error, CollectorTimeoutError):
            diagnosis["issue"] = "Execution timeout"
            diagnosis["root_cause"] = "Collection took longer than execution timeout"
            diagnosis["solution"] = (
                "1. Increase timeout.execution in blueprint\n"
                "2. Reduce limit parameter to collect fewer events per run\n"
                "3. Use resume_state to continue from where it left off\n"
                "4. Check network latency and API response times"
            )
            diagnosis["related_config"] = {
                "execution_timeout": self.timeouts.execution,
                "safety_buffer": self.timeouts.safety_buffer,
            }
        
        elif isinstance(error, CollectorCircuitOpenError):
            diagnosis["issue"] = "Circuit breaker is open"
            diagnosis["root_cause"] = "Too many consecutive failures, circuit breaker opened to prevent cascading failures"
            diagnosis["solution"] = (
                "1. Wait for recovery_timeout seconds\n"
                "2. Check API health and connectivity\n"
                "3. Review error logs to identify root cause\n"
                "4. Adjust circuit_breaker.failure_threshold if needed"
            )
            diagnosis["related_config"] = {
                "failure_threshold": self.blueprint.circuit_breaker.failure_threshold,
                "recovery_timeout": self.blueprint.circuit_breaker.recovery_timeout,
            }
        
        elif isinstance(error, CollectorRetryError):
            diagnosis["issue"] = "All retry attempts exhausted"
            diagnosis["root_cause"] = "Request failed after all retry attempts"
            diagnosis["solution"] = (
                "1. Check API health and connectivity\n"
                "2. Increase retry_policy.max_attempts\n"
                "3. Review error logs to identify persistent issues\n"
                "4. Verify request parameters and authentication"
            )
            diagnosis["related_config"] = {
                "max_attempts": self.retry_policy.max_attempts,
                "retryable_status_codes": self.retry_policy.retryable_status_codes,
            }
        
        elif isinstance(error, CollectorConfigurationError):
            diagnosis["issue"] = "Configuration error"
            diagnosis["root_cause"] = "Invalid or missing configuration"
            diagnosis["solution"] = (
                "1. Run validate_blueprint(blueprint) to check for errors\n"
                "2. Review configuration against API documentation\n"
                "3. Check required fields are set (e.g., next_cursor_path for cursor pagination)"
            )
        
        else:
            diagnosis["issue"] = "Unexpected error"
            diagnosis["root_cause"] = "Unknown error type"
            diagnosis["solution"] = (
                "1. Enable diagnostic_mode=True in blueprint\n"
                "2. Check get_diagnostic_report() for detailed traces\n"
                "3. Review error message and stack trace\n"
                "4. Check API documentation and integration logs"
            )
        
        return diagnosis

    def inspect_state(self, state_key: Optional[StateKey] = None) -> Dict[str, Any]:
        """Inspect current state for a specific key or all states.
        
        Useful for debugging pagination issues and state management.
        
        **Usage:**
        
        ```python
        # Inspect all states
        all_states = client.inspect_state()
        
        # Inspect specific state
        state = client.inspect_state("/v1/events")
        print(f"Current cursor: {state['cursor']}")
        print(f"Current page: {state['page']}")
        ```
        
        Args:
            state_key: Optional state key to inspect. If None, returns all states.
            
        Returns:
            Dictionary with state information
        """
        all_states = self.state_store._store.read()
        
        if state_key:
            state_data = all_states.get(state_key)
            if not state_data:
                return {"error": f"State not found for key: {state_key}"}
            return {
                "state_key": state_key,
                "state": CollectorState.from_dict(state_data).to_dict(),
                "raw": state_data,
            }
        
        return {
            "collector_name": self.blueprint.name,
            "states": {
                key: CollectorState.from_dict(value).to_dict()
                for key, value in all_states.items()
            },
            "raw": all_states,
        }

    def validate_configuration(self) -> List[str]:
        """Validate the current configuration and return any errors.
        
        This is a convenience method that calls validate_blueprint().
        
        **Usage:**
        
        ```python
        errors = client.validate_configuration()
        if errors:
            for error in errors:
                print(f"Configuration error: {error}")
        ```
        
        Returns:
            List of error messages (empty if configuration is valid)
        """
        from CollectorClient import validate_blueprint  # type: ignore[attr-defined]
        return validate_blueprint(self.blueprint)

    def health_check(self) -> Dict[str, Any]:
        """Perform a health check of the collector configuration and state.
        
        Checks configuration validity, state consistency, and provides
        a health status.
        
        **Usage:**
        
        ```python
        health = client.health_check()
        if health["status"] != "healthy":
            print(f"Health issues: {health['issues']}")
        ```
        
        Returns:
            Dictionary with health status and details
        """
        health: Dict[str, Any] = {
            "status": "healthy",
            "issues": [],
            "warnings": [],
            "configuration_valid": True,
            "state_consistent": True,
        }
        
        # Check configuration
        config_errors = self.validate_configuration()
        if config_errors:
            health["status"] = "unhealthy"
            health["configuration_valid"] = False
            health["issues"].extend(config_errors)
        
        # Check state consistency
        try:
            states = self.inspect_state()
            if "error" in states:
                health["status"] = "degraded"
                health["warnings"].append(states["error"])
        except Exception as e:
            health["status"] = "degraded"
            health["warnings"].append(f"State inspection failed: {e}")
        
        # Check metrics
        if self.metrics.general_error > 0:
            health["warnings"].append(f"{self.metrics.general_error} general errors recorded")
        
        if self.metrics.auth_error > 0:
            health["warnings"].append(f"{self.metrics.auth_error} authentication errors recorded")
        
        if health["warnings"] and health["status"] == "healthy":
            health["status"] = "degraded"
        
        return health

    def _build_strategy(self, strategy: Union[StrategyName, CollectionStrategy, None]) -> CollectionStrategy:
        if isinstance(strategy, CollectionStrategy):
            return strategy
        name: StrategyName = strategy or self.blueprint.default_strategy  # type: ignore[assignment]
        strategy_cls = STRATEGY_MAP.get(name)  # type: ignore[arg-type]
        if not strategy_cls:
            raise CollectorConfigurationError(f"Unknown collection strategy: {name}")
        if strategy_cls is ConcurrentCollectionStrategy:
            return strategy_cls(self.blueprint.concurrency)
        return strategy_cls()

    def _normalize_requests(
        self, request: Optional[Union[CollectorRequest, Sequence[CollectorRequest]]]
    ) -> List[CollectorRequest]:
        if request is None:
            return [self.blueprint.request]
        if isinstance(request, CollectorRequest):
            return [request]
        return list(request)

    def _expand_shards(self, request: CollectorRequest) -> List[CollectorRequest]:
        if not request.shards:
            return [request]
        clones: List[CollectorRequest] = [
            CollectorRequest(
                endpoint=request.endpoint,
                method=request.method,
                params=_ensure_dict(request.params),
                json_body=request.json_body,
                headers=_ensure_dict(request.headers),
                data_path=request.data_path,
                pagination=request.pagination,
                stream=request.stream,
                timeout=request.timeout,
                state_key=request.state_key or request.endpoint,
                shards=None,
            )
        ]
        for idx, shard in enumerate(request.shards):
            params = _ensure_dict(request.params)
            params.update(shard.get("params", {}))
            headers = _ensure_dict(request.headers)
            headers.update(shard.get("headers", {}))
            shard_request = CollectorRequest(
                endpoint=shard.get("endpoint", request.endpoint),
                method=shard.get("method", request.method),
                params=params,
                json_body=shard.get("json_body", request.json_body),
                headers=headers,
                data_path=shard.get("data_path", request.data_path),
                pagination=shard.get("pagination", request.pagination),
                stream=request.stream,
                timeout=shard.get("timeout", request.timeout),
                state_key=shard.get("state_key") or f"{request.state_key or request.endpoint}:{idx}",
                shards=None,
            )
            clones.append(shard_request)
        return clones

    def _resume_state_map(self, resume_state: Optional[CollectorState]) -> Dict[str, CollectorState]:
        if not resume_state:
            return {}
        requests_state = resume_state.metadata.get("requests")
        if isinstance(requests_state, dict):
            return {key: CollectorState.from_dict(value) for key, value in requests_state.items()}
        return {"default": resume_state}

    def _aggregate_state(self, executors: List[CollectorExecutor]) -> CollectorState:
        metadata: Dict[str, Any] = {"requests": {}}
        cursor = None
        last_event = None
        for executor in executors:
            metadata["requests"][executor.state_key] = executor.pagination.state.to_dict()
            cursor = cursor or executor.pagination.state.cursor
            last_event = last_event or executor.pagination.state.last_event_id
        return CollectorState(cursor=cursor, last_event_id=last_event, metadata=metadata)

    @staticmethod
    def _is_state_exhausted(state: CollectorState) -> bool:
        if state.cursor:
            return False
        if state.metadata.get("next_link"):
            return False
        if state.metadata.get("has_more"):
            return False
        return True


def _parse_retry_after(response: Optional[httpx.Response]) -> Optional[float]:
    if not response:
        return None
    retry_after = response.headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        return float(retry_after)
    except ValueError:
        try:
            parsed = datetime.strptime(retry_after, "%a, %d %b %Y %H:%M:%S GMT")
            return max(0.0, (parsed - datetime.utcnow()).total_seconds())
        except ValueError:
            return None


# ============================================================================
# Developer-Friendly Helper Functions
# ============================================================================


class CollectorBlueprintBuilder:
    """Fluent builder for creating CollectorBlueprints with method chaining.
    
    Makes it easier to construct blueprints step-by-step, especially for GenAI
    and junior developers who may not be familiar with all the configuration options.
    
    **Usage:**
    
    ```python
    blueprint = (
        CollectorBlueprintBuilder("MyCollector", "https://api.example.com")
        .with_endpoint("/v1/events", data_path="data.events")
        .with_cursor_pagination(next_cursor_path="meta.next_cursor")
        .with_api_key_auth(params["api_key"], header_name="X-API-Key")
        .with_rate_limit(rate_per_second=10, burst=20)
        .build()
    )
    ```
    
    **Benefits:**
    - Method chaining makes configuration more readable
    - Each method validates its inputs
    - Clear, discoverable API (IDE autocomplete helps)
    - Reduces cognitive load vs. large constructor calls
    """
    
    def __init__(self, name: str, base_url: str):
        self.name = name
        self.base_url = base_url
        self._request: Optional[CollectorRequest] = None
        self._auth_handler: Optional[AuthHandler] = None
        self._retry_policy: Optional[RetryPolicy] = None
        self._rate_limit: Optional[RateLimitPolicy] = None
        self._timeout: Optional[TimeoutSettings] = None
        self._default_strategy: StrategyName = "sequential"
        self._default_limit: Optional[int] = None
        self._concurrency: int = 4
        self._diagnostic_mode: bool = False
        self._verify: bool = True
        self._proxy: bool = False
    
    def with_endpoint(
        self,
        endpoint: str,
        method: HTTPMethod = "GET",
        data_path: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        state_key: Optional[StateKey] = None,
    ) -> "CollectorBlueprintBuilder":
        """Configure the main request endpoint.
        
        Args:
            endpoint: API endpoint path (must start with "/")
            method: HTTP method (default: "GET")
            data_path: Path to event array in response (e.g., "data.events")
            params: Query parameters
            headers: Custom headers
            state_key: State storage key (default: uses endpoint)
        """
        self._request = CollectorRequest(
            endpoint=endpoint,
            method=method,
            data_path=data_path,
            params=params,
            headers=headers,
            state_key=state_key,
        )
        return self
    
    def with_cursor_pagination(
        self,
        next_cursor_path: str,
        cursor_param: str = "cursor",
        data_path: Optional[str] = None,
    ) -> "CollectorBlueprintBuilder":
        """Configure cursor-based pagination.
        
        Args:
            next_cursor_path: Path to next cursor in response (e.g., "meta.next_cursor")
            cursor_param: Query parameter name (default: "cursor")
            data_path: Path to event array (overrides endpoint data_path if set)
        """
        if not self._request:
            raise CollectorConfigurationError("Must call with_endpoint() before with_cursor_pagination()")
        self._request.pagination = PaginationConfig(
            mode="cursor",
            next_cursor_path=next_cursor_path,
            cursor_param=cursor_param,
            data_path=data_path or self._request.data_path,
        )
        return self
    
    def with_page_pagination(
        self,
        page_param: str = "page",
        start_page: int = 1,
        page_size: Optional[int] = None,
        page_size_param: Optional[str] = None,
        has_more_path: Optional[str] = None,
    ) -> "CollectorBlueprintBuilder":
        """Configure page-based pagination.
        
        Args:
            page_param: Query parameter name for page number (default: "page")
            start_page: First page number (default: 1)
            page_size: Items per page
            page_size_param: Query parameter name for page size
            has_more_path: Path to has_more boolean in response
        """
        if not self._request:
            raise CollectorConfigurationError("Must call with_endpoint() before with_page_pagination()")
        self._request.pagination = PaginationConfig(
            mode="page",
            page_param=page_param,
            start_page=start_page,
            page_size=page_size,
            page_size_param=page_size_param,
            has_more_path=has_more_path,
        )
        return self
    
    def with_api_key_auth(
        self,
        key: str,
        header_name: Optional[str] = None,
        query_param: Optional[str] = None,
    ) -> "CollectorBlueprintBuilder":
        """Configure API key authentication.
        
        Args:
            key: API key value
            header_name: Header name (e.g., "X-API-Key")
            query_param: Query parameter name (e.g., "api_key")
        """
        self._auth_handler = APIKeyAuthHandler(key, header_name=header_name, query_param=query_param)
        return self
    
    def with_bearer_auth(self, token: str) -> "CollectorBlueprintBuilder":
        """Configure Bearer token authentication.
        
        Args:
            token: Bearer token value
        """
        self._auth_handler = BearerTokenAuthHandler(token)
        return self
    
    def with_basic_auth(self, username: str, password: str) -> "CollectorBlueprintBuilder":
        """Configure HTTP Basic authentication.
        
        Args:
            username: Basic auth username
            password: Basic auth password
        """
        self._auth_handler = BasicAuthHandler(username, password)
        return self
    
    def with_rate_limit(self, rate_per_second: float, burst: int = 1) -> "CollectorBlueprintBuilder":
        """Configure rate limiting.
        
        Args:
            rate_per_second: Request rate limit
            burst: Maximum burst capacity
        """
        self._rate_limit = RateLimitPolicy(rate_per_second=rate_per_second, burst=burst)
        return self
    
    def with_timeout(
        self,
        execution: Optional[float] = None,
        connect: float = 10.0,
        read: float = 60.0,
        safety_buffer: float = 30.0,
    ) -> "CollectorBlueprintBuilder":
        """Configure timeout settings.
        
        Args:
            execution: Total execution time limit (enables timeout awareness)
            connect: Connection timeout (default: 10.0)
            read: Read timeout (default: 60.0)
            safety_buffer: Seconds before execution timeout to abort (default: 30.0)
        """
        self._timeout = TimeoutSettings(
            execution=execution,
            connect=connect,
            read=read,
            safety_buffer=safety_buffer,
        )
        return self
    
    def with_retry_policy(
        self,
        max_attempts: int = 5,
        initial_delay: float = 1.0,
        max_delay: float = 60.0,
    ) -> "CollectorBlueprintBuilder":
        """Configure retry policy.
        
        Args:
            max_attempts: Maximum retry attempts (default: 5)
            initial_delay: Initial delay in seconds (default: 1.0)
            max_delay: Maximum delay in seconds (default: 60.0)
        """
        self._retry_policy = RetryPolicy(
            max_attempts=max_attempts,
            initial_delay=initial_delay,
            max_delay=max_delay,
        )
        return self
    
    def with_strategy(self, strategy: StrategyName, concurrency: int = 4) -> "CollectorBlueprintBuilder":
        """Configure collection strategy.
        
        Args:
            strategy: Strategy name ("sequential", "concurrent", "batch", "stream")
            concurrency: Max concurrent requests (for "concurrent" strategy, default: 4)
        """
        self._default_strategy = strategy
        self._concurrency = concurrency
        return self
    
    def with_ssl_verification(self, verify: bool) -> "CollectorBlueprintBuilder":
        """Configure SSL certificate verification.
        
        Args:
            verify: Whether to verify SSL certificates (default: True)
        """
        self._verify = verify
        return self
    
    def with_proxy(self, use_proxy: bool) -> "CollectorBlueprintBuilder":
        """Configure proxy usage.
        
        Args:
            use_proxy: Whether to use system proxy (default: False)
        """
        self._proxy = use_proxy
        return self
    
    def build(self) -> CollectorBlueprint:
        """Build the CollectorBlueprint from the configured options.
        
        Returns:
            Configured CollectorBlueprint
            
        Raises:
            CollectorConfigurationError: If required fields are missing
        """
        if not self._request:
            raise CollectorConfigurationError("Must call with_endpoint() before build()")
        
        return CollectorBlueprint(
            name=self.name,
            base_url=self.base_url,
            request=self._request,
            auth_handler=self._auth_handler,
            retry_policy=self._retry_policy or RetryPolicy(),
            rate_limit=self._rate_limit or RateLimitPolicy(),
            timeout=self._timeout or TimeoutSettings(),
            default_strategy=self._default_strategy,
            default_limit=self._default_limit,
            concurrency=self._concurrency,
            diagnostic_mode=self._diagnostic_mode,
            verify=self._verify,
            proxy=self._proxy,
        )


def validate_blueprint(blueprint: CollectorBlueprint) -> List[str]:
    """Validate a CollectorBlueprint and return a list of errors (empty if valid).
    
    This helps catch configuration mistakes early with helpful error messages.
    
    **Usage:**
    
    ```python
    errors = validate_blueprint(blueprint)
    if errors:
        return_error(f"Configuration errors: {', '.join(errors)}")
    ```
    
    **Checks:**
    
    - Required fields are present
    - Pagination configuration matches mode
    - Endpoint starts with "/"
    - Base URL is valid
    - Strategy is valid
    - Timeout settings are reasonable
    
    Args:
        blueprint: The blueprint to validate
        
    Returns:
        List of error messages (empty if valid)
    """
    errors: List[str] = []
    
    # Check required fields
    if not blueprint.name:
        errors.append("blueprint.name is required")
    if not blueprint.base_url:
        errors.append("blueprint.base_url is required")
    if not blueprint.request:
        errors.append("blueprint.request is required")
    
    # Check base URL format
    if blueprint.base_url and not (blueprint.base_url.startswith("http://") or blueprint.base_url.startswith("https://")):
        errors.append(f"base_url must start with http:// or https://, got: {blueprint.base_url}")
    
    # Check endpoint format
    if blueprint.request and not blueprint.request.endpoint.startswith("/"):
        errors.append(f"request.endpoint must start with '/', got: {blueprint.request.endpoint}")
    
    # Check pagination configuration
    if blueprint.request and blueprint.request.pagination:
        pag = blueprint.request.pagination
        if pag.mode == "cursor" and not pag.next_cursor_path:
            errors.append("PaginationConfig: mode='cursor' requires next_cursor_path")
        if pag.mode == "offset" and not pag.page_size:
            errors.append("PaginationConfig: mode='offset' requires page_size")
        if pag.mode == "link" and not pag.link_path:
            errors.append("PaginationConfig: mode='link' requires link_path")
    
    # Check strategy
    valid_strategies = ("sequential", "concurrent", "batch", "stream")
    if blueprint.default_strategy not in valid_strategies:
        errors.append(f"default_strategy must be one of {valid_strategies}, got: {blueprint.default_strategy}")
    
    # Check concurrency
    if blueprint.concurrency < 1:
        errors.append(f"concurrency must be >= 1, got: {blueprint.concurrency}")
    
    # Check timeout
    if blueprint.timeout.execution is not None and blueprint.timeout.execution <= blueprint.timeout.safety_buffer:
        errors.append(
            f"timeout.execution ({blueprint.timeout.execution}) must be > safety_buffer ({blueprint.timeout.safety_buffer})"
        )
    
    return errors


def create_simple_collector(
    name: str,
    base_url: str,
    endpoint: str,
    auth_handler: AuthHandler,
    data_path: Optional[str] = None,
    pagination: Optional[PaginationConfig] = None,
) -> CollectorClient:
    """Create a CollectorClient with minimal configuration (sensible defaults).
    
    This is the fastest way to get started with CollectorClient. Perfect for simple
    APIs that don't need custom retry/rate limiting configuration.
    
    **Usage:**
    
    ```python
    client = create_simple_collector(
        name="MyCollector",
        base_url="https://api.example.com",
        endpoint="/v1/events",
        auth_handler=APIKeyAuthHandler("secret", header_name="X-API-Key"),
        data_path="data.events",
        pagination=PaginationConfig(mode="cursor", next_cursor_path="meta.next_cursor"),
    )
    result = client.collect_events_sync(limit=1000)
    ```
    
    **Defaults Applied:**
    
    - RetryPolicy: 5 attempts, exponential backoff
    - RateLimitPolicy: Disabled
    - TimeoutSettings: Standard timeouts, no execution limit
    - Strategy: Sequential
    - SSL verification: Enabled
    - Proxy: Disabled
    
    Args:
        name: Collector name
        base_url: Base API URL
        endpoint: API endpoint path
        auth_handler: Authentication handler
        data_path: Path to event array in response
        pagination: Optional pagination configuration
        
    Returns:
        Configured CollectorClient instance
    """
    request = CollectorRequest(
        endpoint=endpoint,
        data_path=data_path,
        pagination=pagination,
    )
    blueprint = CollectorBlueprint(
        name=name,
        base_url=base_url,
        request=request,
        auth_handler=auth_handler,
    )
    return CollectorClient(blueprint)


def discover_pagination_mode(sample_response: Dict[str, Any]) -> Optional[PaginationConfig]:
    """Auto-discover pagination configuration from a sample API response.
    
    This helper analyzes a sample response and suggests a PaginationConfig.
    Useful for developers who aren't sure what pagination mode to use.
    
    **Usage:**
    
    ```python
    # Make a test request to get sample response
    sample = requests.get("https://api.example.com/v1/events").json()
    
    # Auto-discover pagination
    pagination = discover_pagination_mode(sample)
    if pagination:
        print(f"Suggested pagination: {pagination.mode}")
        print(f"Next cursor path: {pagination.next_cursor_path}")
    ```
    
    **Detection Logic:**
    
    - Cursor: Looks for "cursor", "next_cursor", "pagination.cursor", etc.
    - Page: Looks for "page", "current_page", "pagination.page", etc.
    - Offset: Looks for "offset", "skip", "pagination.offset", etc.
    - Link: Looks for "links.next", "next_url", "pagination.next", etc.
    
    Args:
        sample_response: Sample JSON response from the API
        
    Returns:
        Suggested PaginationConfig, or None if pagination not detected
    """
    if not isinstance(sample_response, dict):
        return None
    
    # Check for cursor-based pagination
    cursor_paths = [
        "next_cursor",
        "cursor",
        "pagination.next_cursor",
        "meta.next_cursor",
        "pagination.cursor",
        "page_info.next_cursor",
    ]
    for path in cursor_paths:
        if _resolve_path(sample_response, path):
            return PaginationConfig(mode="cursor", next_cursor_path=path, cursor_param="cursor")
    
    # Check for page-based pagination
    page_paths = [
        "page",
        "current_page",
        "pagination.page",
        "meta.page",
    ]
    has_more_paths = [
        "has_more",
        "pagination.has_more",
        "meta.has_more",
        "next_page",
    ]
    for path in page_paths:
        if _resolve_path(sample_response, path) is not None:
            has_more = next((p for p in has_more_paths if _resolve_path(sample_response, p) is not None), None)
            return PaginationConfig(
                mode="page",
                page_param="page",
                start_page=1,
                has_more_path=has_more,
            )
    
    # Check for offset-based pagination
    offset_paths = [
        "offset",
        "skip",
        "pagination.offset",
    ]
    for path in offset_paths:
        if _resolve_path(sample_response, path) is not None:
            return PaginationConfig(
                mode="offset",
                offset_param="offset",
                page_size_param="limit",
            )
    
    # Check for link-based pagination
    link_paths = [
        "links.next",
        "next_url",
        "pagination.next",
        "meta.next",
        "next",
    ]
    for path in link_paths:
        if _resolve_path(sample_response, path):
            return PaginationConfig(mode="link", link_path=path)
    
    return None


def discover_data_path(sample_response: Dict[str, Any]) -> Optional[str]:
    """Auto-discover the data_path from a sample API response.
    
    Looks for common patterns like "data", "items", "results", "events", etc.
    
    **Usage:**
    
    ```python
    sample = requests.get("https://api.example.com/v1/events").json()
    data_path = discover_data_path(sample)
    if data_path:
        print(f"Suggested data_path: {data_path}")
    ```
    
    Args:
        sample_response: Sample JSON response from the API
        
    Returns:
        Suggested data_path, or None if not detected
    """
    if not isinstance(sample_response, dict):
        return None
    
    # Common patterns for event arrays
    common_paths = [
        "data",
        "items",
        "results",
        "events",
        "records",
        "entries",
        "data.items",
        "data.events",
        "data.results",
        "response.data",
        "response.items",
    ]
    
    for path in common_paths:
        value = _resolve_path(sample_response, path)
        if isinstance(value, list) and len(value) > 0:
            return path
    
    return None


# Public exports to match API Module expectations
__all__ = [
    "CollectorClient",
    "CollectorBlueprint",
    "CollectorRequest",
    "PaginationConfig",
    "RetryPolicy",
    "RateLimitPolicy",
    "TimeoutSettings",
    "CollectorRunResult",
    "CollectorState",
    "APIKeyAuthHandler",
    "BearerTokenAuthHandler",
    "BasicAuthHandler",
    "OAuth2ClientCredentialsHandler",
    "CollectorConfigurationError",
    "CollectorError",
    "CollectorAuthenticationError",
    "CollectorRateLimitError",
    "CollectorTimeoutError",
    # Helper functions
    "CollectorBlueprintBuilder",
    "validate_blueprint",
    "create_simple_collector",
    "discover_pagination_mode",
    "discover_data_path",
    # Diagnostic classes
    "RequestTrace",
    "DiagnosticReport",
]
