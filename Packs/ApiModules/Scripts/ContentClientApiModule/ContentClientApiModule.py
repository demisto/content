import asyncio
import concurrent.futures
import json
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, UTC
from typing import (
    Any,
    Final,
)
from collections.abc import Callable, MutableMapping

import anyio
import demistomock as demisto
import httpx
from pydantic import BaseModel, Field  # pylint: disable=E0611
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

# Type aliases for better readability
HeadersType = dict[str, str]
ParamsType = dict[str, Any]
JsonType = dict[str, Any]
StatusCodesType = tuple[int, ...]


# Constants
DEFAULT_USER_AGENT: Final[str] = "ContentClient/1.0"


def _now() -> float:
    return time.monotonic()


def _ensure_dict(value: MutableMapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    return dict(value)


def _get_value_by_path(obj: Any, path: str) -> Any:
    """Retrieve a value from a nested dictionary using dot notation.

    Args:
        obj: The dictionary or object to search.
        path: The dot-separated path (e.g., "data.items").

    Returns:
        The value at the path, or None if not found.
    """
    if not path or not isinstance(path, str):
        return obj

    current = obj
    for part in path.split("."):
        if not part:  # Skip empty parts from ".." or leading/trailing dots
            continue
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                idx = int(part)
                if 0 <= idx < len(current):
                    current = current[idx]
                else:
                    return None
            except ValueError:
                return None
        else:
            return None

        if current is None:
            return None

    return current


def _extract_list(data: Any, path: str | None) -> list[Any]:
    extracted = _get_value_by_path(data, path) if path else data
    if extracted is None:
        return []
    if isinstance(extracted, list):
        return extracted
    if isinstance(extracted, dict):
        return [extracted]
    # Handle primitive types explicitly
    if isinstance(extracted, str | int | float | bool):
        return [extracted]
    return [extracted]


def _parse_retry_after(response: httpx.Response | None) -> float | None:
    if not response:
        return None
    retry_after = response.headers.get("Retry-After")
    if not retry_after:
        return None
    try:
        return float(retry_after)
    except ValueError:
        try:
            parsed = datetime.strptime(retry_after, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=UTC)
            return max(0.0, (parsed - datetime.now(UTC)).total_seconds())
        except ValueError:
            return None


# Error Classes


class ContentClientError(DemistoException):
    """Base error for all content client failures."""

    def __init__(self, message: str, response: httpx.Response | None = None):
        super().__init__(message)
        self.response = response


class ContentClientAuthenticationError(ContentClientError):
    """Raised when authentication cannot be completed."""


class ContentClientRateLimitError(ContentClientError):
    """Raised when the client hits a user-defined rate limit."""


class ContentClientTimeoutError(ContentClientError):
    """Raised when the execution timeout window is about to be exceeded."""


class ContentClientCircuitOpenError(ContentClientError):
    """Raised when the circuit breaker prevents additional requests."""


class ContentClientRetryError(ContentClientError):
    """Raised when requests exhaust all retry attempts."""


class ContentClientConfigurationError(ContentClientError):
    """Raised when the blueprint or request definition is invalid."""


@dataclass
class ClientExecutionMetrics:
    """Metrics for content client execution."""

    success: int = 0
    retry_error: int = 0
    quota_error: int = 0
    auth_error: int = 0
    service_error: int = 0
    general_error: int = 0


# Helper Classes
class RetryPolicy(BaseModel):
    """Retry policy for handling transient API failures.

    Configures exponential backoff with jitter for retrying failed requests.

    Attributes:
        max_attempts: Maximum number of retry attempts (default: 5).
        initial_delay: Initial delay in seconds before first retry (default: 1.0).
        multiplier: Multiplier for exponential backoff (default: 2.0).
        max_delay: Maximum delay between retries in seconds (default: 60.0).
        jitter: Random jitter factor (0.0-1.0) to prevent thundering herd (default: 0.2).
        retryable_status_codes: HTTP status codes that trigger a retry.
        retryable_exceptions: Exception types that trigger a retry.
        respect_retry_after: Whether to honor Retry-After headers (default: True).
    """

    class Config:
        extra = "forbid"
        arbitrary_types_allowed = True  # Required for Tuple[Type[Exception], ...]

    max_attempts: int = Field(5, ge=1)
    initial_delay: float = Field(1.0, ge=0)
    multiplier: float = Field(2.0, ge=1.0)
    max_delay: float = Field(60.0, gt=0)
    jitter: float = Field(0.2, ge=0.0, le=1.0)
    retryable_status_codes: tuple[int, ...] = (408, 413, 425, 429, 500, 502, 503, 504)
    retryable_exceptions: tuple[type[Exception], ...] = (
        httpx.ConnectError,
        httpx.ReadTimeout,
        httpx.WriteTimeout,
        httpx.RemoteProtocolError,
        httpx.PoolTimeout,
    )
    respect_retry_after: bool = True

    def next_delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Calculate the next delay for retry with exponential backoff and jitter.

        Args:
            attempt: The current attempt number (1-based).
            retry_after: Optional server-provided retry-after value in seconds.

        Returns:
            The delay in seconds before the next retry attempt.
        """
        if retry_after is not None and self.respect_retry_after:
            return retry_after
        delay = min(self.max_delay, self.initial_delay * (self.multiplier ** (attempt - 1)))
        jitter_value = delay * self.jitter
        return max(0.0, delay + random.uniform(-jitter_value, jitter_value))


class CircuitBreakerPolicy(BaseModel):
    """Circuit breaker policy for preventing cascading failures."""

    class Config:
        extra = "forbid"

    failure_threshold: int = Field(5, ge=1)
    recovery_timeout: float = Field(60.0, gt=0)


class CircuitBreaker:
    """Circuit breaker implementation for preventing cascading failures.

    Tracks failures and opens the circuit when the failure threshold is reached,
    preventing further requests until the recovery timeout expires.

    This implementation uses a half-open state with probe request support:
    - CLOSED: Normal operation, requests are allowed
    - OPEN: Circuit is tripped, requests are blocked
    - HALF_OPEN: Recovery timeout expired, one probe request is allowed

    The circuit only fully closes after a successful probe request.

    This implementation is thread-safe using a threading lock.

    Attributes:
        policy: The circuit breaker policy configuration.
    """

    def __init__(self, policy: CircuitBreakerPolicy) -> None:
        self.policy: CircuitBreakerPolicy = policy
        self._failure_count: int = 0
        self._opened_at: float | None = None
        self._half_open: bool = False
        self._lock: threading.Lock = threading.Lock()

    def can_execute(self) -> bool:
        """Check if the circuit allows execution.

        Returns:
            True if the circuit is closed or half-open (allowing probe), False if open.
        """
        with self._lock:
            if self._opened_at is None:
                return True
            elapsed: float = _now() - self._opened_at
            if elapsed >= self.policy.recovery_timeout:
                # Enter half-open state - allow one probe request
                if not self._half_open:
                    self._half_open = True
                    return True
                # Already in half-open and probe is in progress, block additional requests
                return False
            return False

    def record_success(self) -> None:
        """Record a successful execution, resetting the failure count and closing the circuit."""
        with self._lock:
            self._failure_count = 0
            self._opened_at = None
            self._half_open = False

    def record_failure(self) -> None:
        """Record a failed execution, potentially opening the circuit."""
        with self._lock:
            self._failure_count += 1
            if self._half_open:
                # Probe failed, re-open the circuit
                self._opened_at = _now()
                self._half_open = False
            elif self._failure_count >= self.policy.failure_threshold:
                self._opened_at = _now()


class RateLimitPolicy(BaseModel):
    """Rate limiting policy using token bucket algorithm."""

    class Config:
        extra = "forbid"

    rate_per_second: float = Field(0.0, ge=0)
    burst: int = Field(1, ge=1)
    respect_retry_after: bool = True

    @property
    def enabled(self) -> bool:
        return self.rate_per_second > 0


class TokenBucketRateLimiter:
    """Token bucket rate limiter for controlling request rate.

    Uses the token bucket algorithm to limit the rate of requests.
    Tokens are refilled at a constant rate up to a maximum capacity (burst).

    This implementation uses threading.Lock for thread safety, which works
    correctly across different event loops and in synchronous contexts.

    Attributes:
        policy: The rate limit policy configuration.
    """

    def __init__(self, policy: RateLimitPolicy) -> None:
        self.policy: RateLimitPolicy = policy
        self._capacity: int = max(1, policy.burst)
        self._tokens: float = float(self._capacity)
        self._updated: float = _now()
        self._lock: threading.Lock = threading.Lock()  # Thread-safe lock

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary until one is available."""
        while True:
            with self._lock:
                self._refill_locked()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                needed = 1 - self._tokens
                # Protect against division by zero - this should not happen in normal usage
                # since the rate limiter is only created when rate_per_second > 0
                rate = self.policy.rate_per_second
                if rate <= 0:
                    raise ContentClientConfigurationError("rate_per_second must be positive when rate limiting is enabled")
                wait_seconds = needed / rate
            await anyio.sleep(wait_seconds)

    def _refill_locked(self) -> None:
        """Refill tokens based on elapsed time (must be called with lock held)."""
        now = _now()
        delta = now - self._updated
        if delta <= 0:
            return
        refill = delta * self.policy.rate_per_second
        self._tokens = min(self._capacity, self._tokens + refill)
        self._updated = now


class TimeoutSettings(BaseModel):
    """Timeout configuration for HTTP requests and execution deadline."""

    class Config:
        extra = "forbid"

    connect: float = Field(10.0, gt=0)
    read: float = Field(60.0, gt=0)
    write: float = Field(60.0, gt=0)
    pool: float = Field(60.0, gt=0)
    execution: float | None = Field(None, gt=0)
    safety_buffer: float = Field(30.0, gt=0)

    def as_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(connect=self.connect, read=self.read, write=self.write, pool=self.pool)


@dataclass
class ContentClientState:
    """Pagination and collection state for resuming after timeouts.

    Stores pagination position (cursor, page, offset) and metadata to allow seamless
    resumption of collection after timeouts or interruptions.

    Attributes:
        cursor: Current cursor value for cursor-based pagination.
        page: Current page number for page-based pagination.
        offset: Current offset value for offset-based pagination.
        last_event_id: Last processed event ID (for deduplication).
        partial_results: Events from incomplete pages (preserved on timeout).
        metadata: Custom metadata dictionary for storing additional state.
    """

    cursor: str | None = None
    page: int | None = None
    offset: int | None = None
    last_event_id: str | None = None
    partial_results: list[Any] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert state to a dictionary for serialization.

        Returns:
            Dictionary representation of the state.
        """
        return {
            "cursor": self.cursor,
            "page": self.page,
            "offset": self.offset,
            "last_event_id": self.last_event_id,
            "partial_results": self.partial_results,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "ContentClientState":
        """Create a ContentClientState from a dictionary.

        Args:
            raw: Dictionary containing state data.

        Returns:
            A new ContentClientState instance.
        """
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


class ContentClientContextStore:
    """Store for persisting state to Demisto integration context.

    Provides read/write access to the integration context with retry logic
    for handling transient failures. Uses thread-safe locking to prevent
    race conditions during concurrent read-modify-write operations.

    Attributes:
        namespace: A namespace prefix for storing data (e.g., client name).
        max_retries: Maximum number of retry attempts for write operations.
    """

    def __init__(self, namespace: str, max_retries: int = 3) -> None:
        self.namespace: str = namespace
        self.max_retries: int = max_retries
        self._lock: threading.Lock = threading.Lock()

    def read(self) -> dict[str, Any]:
        """Read the current integration context.

        Returns:
            The integration context dictionary.
        """
        with self._lock:
            context: dict[str, Any] = demisto.getIntegrationContext() or {}
            return context

    def write(self, data: dict[str, Any]) -> None:
        """Write data to the integration context with retry logic.

        Uses thread-safe locking to prevent race conditions.

        Args:
            data: The data dictionary to write to the context.

        Raises:
            Exception: If all retry attempts fail.
        """
        last_error: Exception | None = None
        with self._lock:
            for attempt in range(self.max_retries):
                try:
                    demisto.setIntegrationContext(data)
                    return
                except Exception as e:
                    last_error = e
                    time.sleep(0.1 * (attempt + 1))  # Simple backoff
        if last_error:
            raise last_error


# Auth Handlers
class AuthHandler:
    """Abstract base class for authentication handlers."""

    name: str = "auth"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        """Modify the request to add authentication credentials."""
        raise NotImplementedError("Subclasses must implement on_request()")

    async def on_auth_failure(self, client: "ContentClient", response: httpx.Response) -> bool:
        """Handle authentication failure response."""
        return False


class APIKeyAuthHandler(AuthHandler):
    """Authentication handler for API key-based authentication.

    Supports adding the API key either as a header or as a query parameter.
    At least one of header_name or query_param must be provided.

    Args:
        key: The API key value.
        header_name: Optional header name to add the key to (e.g., 'X-API-Key').
        query_param: Optional query parameter name to add the key to (e.g., 'api_key').

    Raises:
        ContentClientConfigurationError: If neither header_name nor query_param is provided,
            or if the key is empty.
    """

    def __init__(self, key: str, header_name: str | None = None, query_param: str | None = None):
        super().__init__()
        if not key:
            raise ContentClientConfigurationError("APIKeyAuthHandler requires a non-empty key")
        if not header_name and not query_param:
            raise ContentClientConfigurationError("APIKeyAuthHandler requires header_name or query_param")
        self.key = key
        self.header_name = header_name
        self.query_param = query_param
        self.name = "api_key"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        if self.header_name:
            request.headers[self.header_name] = self.key
        if self.query_param:
            # Use copy_add_param for proper URL parameter handling
            request.url = request.url.copy_add_param(self.query_param, self.key)


class BearerTokenAuthHandler(AuthHandler):
    """Authentication handler for Bearer token authentication.

    Args:
        token: The bearer token value.

    Raises:
        ContentClientConfigurationError: If the token is empty.
    """

    def __init__(self, token: str):
        super().__init__()
        if not token:
            raise ContentClientConfigurationError("BearerTokenAuthHandler requires a non-empty token")
        self.token = token
        self.name = "bearer"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {self.token}"


class BasicAuthHandler(AuthHandler):
    """Authentication handler for HTTP Basic Authentication.

    Args:
        username: The username for authentication.
        password: The password for authentication.

    Raises:
        ContentClientConfigurationError: If username is empty.
    """

    def __init__(self, username: str, password: str):
        super().__init__()
        if not username:
            raise ContentClientConfigurationError("BasicAuthHandler requires a non-empty username")
        credentials = f"{username}:{password}"
        self._encoded = b64_encode(credentials)
        self.name = "basic"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Basic {self._encoded}"


class OAuth2ClientCredentialsHandler(AuthHandler):
    """Authentication handler for OAuth2 Client Credentials flow.

    Implements the OAuth2 client credentials grant type for machine-to-machine
    authentication. Automatically handles token refresh when tokens expire.

    Uses thread-safe locking to prevent race conditions during token refresh,
    which is important when the handler is used across different event loops
    or in synchronous contexts.

    Args:
        token_url: The OAuth2 token endpoint URL.
        client_id: The client ID for authentication.
        client_secret: The client secret for authentication.
        scope: Optional OAuth2 scope(s) to request.
        audience: Optional audience parameter for the token request.
        auth_params: Optional additional parameters to include in token requests.
        context_store: Optional context store for persisting tokens across executions.
        token_timeout: Timeout in seconds for token refresh requests (default: 30).

    Raises:
        ContentClientConfigurationError: If required parameters are missing or invalid.
    """

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str | None = None,
        audience: str | None = None,
        auth_params: dict[str, str] | None = None,
        context_store: Any | None = None,
        token_timeout: float = 30.0,
    ):
        super().__init__()
        if not token_url:
            raise ContentClientConfigurationError("OAuth2ClientCredentialsHandler requires a non-empty token_url")
        if not client_id:
            raise ContentClientConfigurationError("OAuth2ClientCredentialsHandler requires a non-empty client_id")
        if not client_secret:
            raise ContentClientConfigurationError("OAuth2ClientCredentialsHandler requires a non-empty client_secret")

        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.audience = audience
        self.auth_params = auth_params or {}
        self.context_store = context_store
        self.token_timeout = token_timeout
        self.name = "oauth2_client_credentials"

        self._access_token: str | None = None
        self._expires_at: float = 0
        self._lock: threading.Lock = threading.Lock()  # Thread-safe lock

        # Try to load cached token from context store
        if self.context_store:
            try:
                context = self.context_store.read()
                cached_token = context.get("oauth2_token", {})
                if cached_token.get("access_token") and cached_token.get("expires_at", 0) > _now():
                    self._access_token = cached_token["access_token"]
                    self._expires_at = cached_token["expires_at"]
            except Exception as e:
                # Log but don't fail if cache read fails
                demisto.debug(f"Failed to load cached OAuth2 token: {e}")

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        # Check if refresh is needed (thread-safe read)
        if self._should_refresh():
            # Perform refresh outside the lock to avoid blocking async operations
            await self._refresh_token_if_needed(client)

        # Read token under lock to ensure visibility
        with self._lock:
            if self._access_token:
                request.headers["Authorization"] = f"Bearer {self._access_token}"

    async def on_auth_failure(self, client: "ContentClient", response: httpx.Response) -> bool:
        # If we get 401, force refresh token
        await self._force_refresh_token(client)
        return True

    def _should_refresh(self) -> bool:
        """Check if token needs refresh. Thread-safe read."""
        with self._lock:
            return not self._access_token or _now() >= self._expires_at - 60  # Refresh 60s before expiry

    async def _refresh_token_if_needed(self, client: "ContentClient") -> None:
        """Refresh token if needed, with proper locking that doesn't block async operations."""
        # Double-check pattern: check again after we're ready to refresh
        # We use a flag to track if we should refresh, then release the lock before awaiting
        should_refresh = False
        with self._lock:
            if self._should_refresh_unlocked():
                should_refresh = True

        if should_refresh:
            await self._refresh_token(client)

    async def _force_refresh_token(self, client: "ContentClient") -> None:
        """Force refresh the token (used after auth failure)."""
        await self._refresh_token(client)

    def _should_refresh_unlocked(self) -> bool:
        """Check if token needs refresh. Must be called with lock held."""
        return not self._access_token or _now() >= self._expires_at - 60

    async def _refresh_token(self, client: "ContentClient") -> None:
        """Refresh the OAuth2 access token.

        Uses a separate HTTP client for token refresh to avoid recursion/deadlocks
        and to not share state with the main client. This method should be called
        with the lock held.

        Args:
            client: The ContentClient instance (used for SSL verification settings).

        Raises:
            ContentClientAuthenticationError: If token refresh fails.
        """
        # Use a separate client for token refresh to avoid recursion/deadlocks
        # and to not share state with the main client
        async with httpx.AsyncClient(verify=client._verify, timeout=httpx.Timeout(self.token_timeout)) as token_client:
            data = {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            }
            if self.scope:
                data["scope"] = self.scope
            if self.audience:
                data["audience"] = self.audience
            if self.auth_params:
                data.update(self.auth_params)

            try:
                response = await token_client.post(self.token_url, data=data)
                response.raise_for_status()
                token_data = response.json()

                self._access_token = token_data.get("access_token")
                if not self._access_token:
                    raise ContentClientAuthenticationError("No access_token in response")

                expires_in = token_data.get("expires_in", 3600)
                self._expires_at = _now() + expires_in

                # Persist token if context store is available
                if self.context_store:
                    try:
                        current_context = self.context_store.read()
                        current_context["oauth2_token"] = {"access_token": self._access_token, "expires_at": self._expires_at}
                        self.context_store.write(current_context)
                    except Exception as e:
                        # Log but don't fail auth if persistence fails
                        demisto.debug(f"Failed to persist OAuth2 token: {e}")

            except httpx.HTTPStatusError as e:
                raise ContentClientAuthenticationError(
                    f"Token refresh failed with status {e.response.status_code}: {e.response.text}"
                ) from e
            except httpx.TimeoutException as e:
                raise ContentClientAuthenticationError(f"Token refresh timed out: {str(e)}") from e
            except Exception as e:
                raise ContentClientAuthenticationError(f"Failed to refresh token: {str(e)}") from e


# Structured Logging for Google Cloud


class StructuredLogEntry:
    """Structured log entry optimized for Google Cloud Logs Explorer and BigQuery.

    Creates JSON-formatted log entries with consistent fields that can be easily
    queried in Google Cloud Logs Explorer and exported to BigQuery for analysis.

    Fields follow Google Cloud Logging conventions:
    - severity: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - message: Human-readable log message
    - timestamp: ISO 8601 formatted timestamp
    - labels: Key-value pairs for filtering (client_name, request_id, etc.)
    - httpRequest: HTTP request details (method, url, status, latency)
    - Additional custom fields for debugging
    """

    def __init__(self, severity: str, message: str, client_name: str, request_id: str | None = None, **kwargs: Any) -> None:
        self.entry: dict[str, Any] = {
            "severity": severity.upper(),
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
            "labels": {
                "client_name": client_name,
                "component": "ContentClient",
            },
        }

        if request_id:
            self.entry["labels"]["request_id"] = request_id

        # Add any additional fields
        for key, value in kwargs.items():
            if key == "http_request":
                self.entry["httpRequest"] = value
            elif key == "error":
                self.entry["error"] = value
            elif key == "labels":
                self.entry["labels"].update(value)
            else:
                self.entry[key] = value

    def to_json(self) -> str:
        """Convert to JSON string for logging."""
        return json.dumps(self.entry, default=str)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return self.entry


def create_http_request_log(
    method: str,
    url: str,
    status: int | None = None,
    latency_ms: float | None = None,
    request_size: int | None = None,
    response_size: int | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """Create an httpRequest object following Google Cloud Logging format.

    This format is recognized by Google Cloud Logs Explorer and enables
    automatic HTTP request analysis and filtering.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        status: HTTP response status code
        latency_ms: Request latency in milliseconds
        request_size: Size of request body in bytes
        response_size: Size of response body in bytes
        user_agent: User-Agent header value

    Returns:
        Dictionary in Google Cloud httpRequest format
    """
    http_request: dict[str, Any] = {
        "requestMethod": method.upper(),
        "requestUrl": url,
    }

    if status is not None:
        http_request["status"] = status

    if latency_ms is not None:
        # Google Cloud expects latency as a string with 's' suffix
        http_request["latency"] = f"{latency_ms / 1000:.3f}s"

    if request_size is not None:
        http_request["requestSize"] = str(request_size)

    if response_size is not None:
        http_request["responseSize"] = str(response_size)

    if user_agent:
        http_request["userAgent"] = user_agent

    return http_request


def create_error_log(
    error_type: str,
    error_message: str,
    stack_trace: str | None = None,
    error_code: str | None = None,
) -> dict[str, Any]:
    """Create an error object for structured logging.

    Args:
        error_type: Type/class of the error
        error_message: Error message
        stack_trace: Optional stack trace
        error_code: Optional error code for categorization

    Returns:
        Dictionary with error details
    """
    error: dict[str, Any] = {
        "type": error_type,
        "message": error_message,
    }

    if stack_trace:
        error["stackTrace"] = stack_trace

    if error_code:
        error["code"] = error_code

    return error


# Diagnostics


@dataclass
class RequestTrace:
    """Trace information for a single HTTP request."""

    method: str
    url: str
    headers: dict[str, str]
    params: dict[str, Any]
    body: Any | None
    timestamp: float
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: Any | None = None
    elapsed_ms: float | None = None
    error: str | None = None
    retry_attempt: int = 0


@dataclass
class DiagnosticReport:
    """Comprehensive diagnostic report for troubleshooting."""

    content_item_name: str
    configuration: dict[str, Any]
    request_traces: list[RequestTrace]
    state_snapshots: list[dict[str, Any]]
    performance_metrics: dict[str, Any]
    errors: list[dict[str, Any]]
    recommendations: list[str]
    timestamp: float


class ContentClientLogger:
    """Enhanced logger with diagnostic capabilities and structured logging.

    Provides structured JSON logging optimized for Google Cloud Logs Explorer
    and BigQuery analysis. Supports request tracing, performance metrics,
    and correlation IDs for distributed tracing.

    Attributes:
        client_name: Name of the client for log identification.
        diagnostic_mode: Whether to enable detailed diagnostic logging.
        structured_logging: Whether to use JSON structured logging (default: True).

    Example BigQuery queries:
        -- Find all errors for a specific client
        SELECT * FROM `project.dataset.logs`
        WHERE JSON_VALUE(jsonPayload.labels.client_name) = 'MyClient'
        AND severity = 'ERROR'

        -- Analyze request latencies
        SELECT
            JSON_VALUE(jsonPayload.httpRequest.requestUrl) as url,
            AVG(CAST(REPLACE(JSON_VALUE(jsonPayload.httpRequest.latency), 's', '') AS FLOAT64) * 1000) as avg_latency_ms
        FROM `project.dataset.logs`
        WHERE JSON_VALUE(jsonPayload.labels.component) = 'ContentClient'
        GROUP BY url

        -- Find requests by correlation ID
        SELECT * FROM `project.dataset.logs`
        WHERE JSON_VALUE(jsonPayload.labels.request_id) = 'abc-123'
        ORDER BY timestamp
    """

    def __init__(self, client_name: str, diagnostic_mode: bool = False, structured_logging: bool = True) -> None:
        self.client_name: str = client_name
        self.diagnostic_mode: bool = diagnostic_mode
        self.structured_logging: bool = structured_logging
        self._traces: list[RequestTrace] = []
        self._errors: list[dict[str, Any]] = []
        self._performance: dict[str, list[float]] = {
            "request_times": [],
            "pagination_times": [],
            "auth_times": [],
        }
        self._current_request_id: str | None = None

    def new_request_id(self) -> str:
        """Generate a new request ID for correlation.

        Returns:
            A unique request ID string.
        """
        self._current_request_id = str(uuid.uuid4())[:8]
        return self._current_request_id

    def get_request_id(self) -> str | None:
        """Get the current request ID.

        Returns:
            The current request ID or None if not set.
        """
        return self._current_request_id

    def debug(self, message: str, extra: dict[str, Any] | None = None) -> None:
        """Log a debug message (only in diagnostic mode)."""
        if self.diagnostic_mode:
            if self.structured_logging:
                log_entry = StructuredLogEntry(
                    severity="DEBUG",
                    message=message,
                    client_name=self.client_name,
                    request_id=self._current_request_id,
                    **(extra or {}),
                )
                demisto.debug(log_entry.to_json())
            else:
                demisto.debug(self._format("DEBUG", message, extra))

    def info(self, message: str, extra: dict[str, Any] | None = None) -> None:
        """Log an info message."""
        if self.structured_logging:
            log_entry = StructuredLogEntry(
                severity="INFO",
                message=message,
                client_name=self.client_name,
                request_id=self._current_request_id,
                **(extra or {}),
            )
            demisto.info(log_entry.to_json())
        else:
            demisto.info(self._format("INFO", message, extra))

    def warning(self, message: str, extra: dict[str, Any] | None = None) -> None:
        """Log a warning message."""
        if self.structured_logging:
            log_entry = StructuredLogEntry(
                severity="WARNING",
                message=message,
                client_name=self.client_name,
                request_id=self._current_request_id,
                **(extra or {}),
            )
            demisto.debug(log_entry.to_json())
        else:
            demisto.debug(self._format("WARNING", message, extra))

    def error(self, message: str, extra: dict[str, Any] | None = None) -> None:
        """Log an error message."""
        if self.structured_logging:
            error_info = None
            # Create a copy of extra to avoid modifying the original
            extra_copy = dict(extra) if extra else {}

            if extra_copy and "error_type" in extra_copy:
                error_info = create_error_log(
                    error_type=extra_copy.get("error_type", "unknown"),
                    error_message=extra_copy.get("error", message),
                )
                # Remove keys that are handled separately to avoid conflicts
                extra_copy.pop("error_type", None)
                extra_copy.pop("error", None)

            log_entry = StructuredLogEntry(
                severity="ERROR",
                message=message,
                client_name=self.client_name,
                request_id=self._current_request_id,
                error=error_info,
                **extra_copy,
            )
            demisto.error(log_entry.to_json())
        else:
            demisto.error(self._format("ERROR", message, extra))

        if self.diagnostic_mode and extra:
            self._errors.append({"message": message, "context": extra})

    def log_http_request(
        self,
        method: str,
        url: str,
        status: int | None = None,
        latency_ms: float | None = None,
        request_size: int | None = None,
        response_size: int | None = None,
        retry_attempt: int = 0,
        error: str | None = None,
    ) -> None:
        """Log an HTTP request with structured format for Google Cloud.

        This creates a log entry that can be easily queried in Logs Explorer
        and analyzed in BigQuery.

        Args:
            method: HTTP method
            url: Request URL
            status: HTTP response status code
            latency_ms: Request latency in milliseconds
            request_size: Size of request body in bytes
            response_size: Size of response body in bytes
            retry_attempt: Current retry attempt number
            error: Optional error message
        """
        http_request = create_http_request_log(
            method=method,
            url=url,
            status=status,
            latency_ms=latency_ms,
            request_size=request_size,
            response_size=response_size,
        )

        severity = "INFO"
        message = f"HTTP {method} {url}"

        if error:
            severity = "ERROR"
            message = f"HTTP {method} {url} failed: {error}"
        elif status and status >= 400:
            severity = "WARNING" if status < 500 else "ERROR"
            message = f"HTTP {method} {url} returned {status}"

        extra: dict[str, Any] = {
            "http_request": http_request,
            "retry_attempt": retry_attempt,
        }

        if error:
            extra["error"] = create_error_log(
                error_type="HTTPError",
                error_message=error,
            )

        log_entry = StructuredLogEntry(
            severity=severity, message=message, client_name=self.client_name, request_id=self._current_request_id, **extra
        )

        if severity == "ERROR":
            demisto.error(log_entry.to_json())
        elif severity == "WARNING":
            demisto.debug(log_entry.to_json())
        else:
            if self.diagnostic_mode:
                demisto.debug(log_entry.to_json())

    def log_metrics_summary(self) -> None:
        """Log a summary of execution metrics for analysis.

        This creates a structured log entry with aggregated metrics that can
        be used for monitoring and alerting in Google Cloud.
        """
        if not self._performance["request_times"]:
            return

        times = self._performance["request_times"]
        metrics = {
            "total_requests": len(times),
            "avg_latency_ms": sum(times) / len(times),
            "min_latency_ms": min(times),
            "max_latency_ms": max(times),
            "p50_latency_ms": sorted(times)[len(times) // 2] if times else 0,
            "p95_latency_ms": sorted(times)[int(len(times) * 0.95)] if len(times) >= 20 else max(times),
            "error_count": len(self._errors),
            "retry_count": sum(1 for t in self._traces if t.retry_attempt > 0),
        }

        log_entry = StructuredLogEntry(
            severity="INFO",
            message="Request metrics summary",
            client_name=self.client_name,
            request_id=self._current_request_id,
            metrics=metrics,
            labels={"metric_type": "summary"},
        )
        demisto.info(log_entry.to_json())

    def trace_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        params: dict[str, Any],
        body: Any | None = None,
        retry_attempt: int = 0,
    ) -> RequestTrace:
        """Create a trace record for an HTTP request.

        Args:
            method: HTTP method.
            url: Request URL.
            headers: Request headers (sensitive values will be redacted).
            params: Query parameters.
            body: Request body.
            retry_attempt: Current retry attempt number.

        Returns:
            A RequestTrace instance for tracking the request.
        """
        # Generate a new request ID for this request
        if retry_attempt == 0:
            self.new_request_id()

        # Redact sensitive headers for security
        safe_headers = headers.copy()
        sensitive_keys = ["Authorization", "X-API-Key", "X-Auth-Token", "API-Key", "Api-Key", "apikey"]
        for key in list(safe_headers.keys()):
            if key.lower() in [k.lower() for k in sensitive_keys]:
                safe_headers[key] = "***REDACTED***"

        trace = RequestTrace(
            method=method,
            url=url,
            headers=safe_headers,
            params=params.copy(),
            body=body,
            timestamp=_now(),
            retry_attempt=retry_attempt,
        )
        if self.diagnostic_mode:
            self._traces.append(trace)
            # Limit trace history to prevent memory issues
            if len(self._traces) > 1000:
                self._traces.pop(0)
        return trace

    def trace_response(
        self,
        trace: RequestTrace,
        status: int,
        headers: dict[str, str],
        body: Any,
        elapsed_ms: float,
    ) -> None:
        trace.response_status = status
        trace.response_headers = headers.copy()
        trace.response_body = body
        trace.elapsed_ms = elapsed_ms

        if self.diagnostic_mode:
            self._performance["request_times"].append(elapsed_ms)

            # Log with structured format for Google Cloud
            self.log_http_request(
                method=trace.method,
                url=trace.url,
                status=status,
                latency_ms=elapsed_ms,
                response_size=len(str(body)) if body else 0,
                retry_attempt=trace.retry_attempt,
            )

    def trace_error(
        self,
        trace: RequestTrace,
        error: str,
        elapsed_ms: float | None = None,
    ) -> None:
        trace.error = error
        if elapsed_ms:
            trace.elapsed_ms = elapsed_ms

        if self.diagnostic_mode:
            # Log with structured format for Google Cloud
            self.log_http_request(
                method=trace.method,
                url=trace.url,
                status=trace.response_status,
                latency_ms=elapsed_ms,
                retry_attempt=trace.retry_attempt,
                error=error,
            )

    def get_diagnostic_report(
        self,
        configuration: dict[str, Any],
        state_snapshots: list[dict[str, Any]] | None = None,
    ) -> DiagnosticReport:
        # Calculate performance metrics
        perf_metrics: dict[str, Any] = {}
        if self._performance["request_times"]:
            times = self._performance["request_times"]
            perf_metrics["avg_request_time_ms"] = sum(times) / len(times)
            perf_metrics["min_request_time_ms"] = min(times)
            perf_metrics["max_request_time_ms"] = max(times)
            perf_metrics["total_requests"] = len(times)

        # Generate recommendations
        recommendations: list[str] = []

        if self._errors:
            error_types: dict[str, int] = {}
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
            content_item_name=self.client_name,
            configuration=configuration,
            request_traces=self._traces.copy(),
            state_snapshots=state_snapshots or [],
            performance_metrics=perf_metrics,
            errors=self._errors.copy(),
            recommendations=recommendations,
            timestamp=_now(),
        )

    def _format(self, level: str, message: str, extra: dict[str, Any] | None) -> str:
        if not extra:
            return f"[ContentClient:{self.client_name}:{level}] {message}"
        try:
            extra_str = json.dumps(extra)
        except (TypeError, ValueError):
            extra_str = str(extra)
        return f"[ContentClient:{self.client_name}:{level}] {message} | extra={extra_str}"


def _create_rate_limiter(policy: RateLimitPolicy | None) -> TokenBucketRateLimiter | None:
    """Create a rate limiter from policy if enabled.

    Factory function that encapsulates the rate limiter creation logic,
    improving readability and making the initialization more maintainable.

    Args:
        policy: Optional rate limit policy configuration.

    Returns:
        TokenBucketRateLimiter instance if policy is provided and enabled,
        None otherwise.
    """
    if policy is None:
        return None
    if not policy.enabled:
        return None
    return TokenBucketRateLimiter(policy)


class ContentClient:
    """Drop-in replacement for BaseClient with enhanced features.

    Fully compatible with BaseClient constructor and _http_request() method.
    Existing integrations can switch from BaseClient to ContentClient with zero code changes.

    Attributes:
        timeout: Default timeout for HTTP requests in seconds.
        execution_metrics: Metrics tracking for request outcomes.
        logger: Logger instance for diagnostic output.
    """

    def __init__(
        self,
        base_url: str,
        verify: bool = True,
        proxy: bool = False,
        ok_codes: StatusCodesType = (),
        headers: HeadersType | None = None,
        auth: tuple[str, str] | None = None,
        timeout: float = 60.0,
        # New optional parameters (backward compatible):
        auth_handler: AuthHandler | None = None,
        retry_policy: RetryPolicy | None = None,
        rate_limiter: RateLimitPolicy | None = None,
        circuit_breaker: CircuitBreakerPolicy | None = None,
        diagnostic_mode: bool = False,
        client_name: str = "ContentClient",
        is_multithreaded: bool = True,
        reuse_client: bool = True,
    ) -> None:
        """Initialize ContentClient with BaseClient-compatible parameters.

        Args:
            base_url: The base URL for all API requests.
            verify: Whether to verify SSL certificates.
            proxy: Whether to use system proxy settings.
            ok_codes: Tuple of HTTP status codes considered successful.
            headers: Default headers to include in all requests.
            auth: Authentication credentials (tuple of username/password or AuthBase).
            timeout: Default timeout for requests in seconds.
            auth_handler: Optional custom authentication handler.
            retry_policy: Optional retry policy configuration.
            rate_limiter: Optional rate limiting policy.
            circuit_breaker: Optional circuit breaker policy.
            diagnostic_mode: Whether to enable diagnostic logging.
            client_name: Name for logging identification.
            is_multithreaded: Whether to enable multithreading support.
            reuse_client: Whether to reuse the HTTP client across sync requests (default: True).
                When True, the client is kept open for better performance.
                When False, the client is closed after each sync request to avoid event loop issues.
        """
        # Store BaseClient-compatible parameters
        self._base_url: str = base_url
        self._verify: bool = verify
        self._ok_codes: StatusCodesType = ok_codes
        self._headers: HeadersType = headers or {}
        self._auth: tuple[str, str] | None = auth
        self.timeout: float = timeout
        self._closed: bool = False
        self._is_multithreaded: bool = is_multithreaded
        self._reuse_client: bool = reuse_client

        # Handle proxy exactly like BaseClient
        if proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()
        if not verify:
            skip_cert_verification()

        # Enhanced features (optional, backward compatible)
        self._auth_handler: AuthHandler | None = auth_handler
        self._retry_policy: RetryPolicy = retry_policy if retry_policy is not None else RetryPolicy()  # type: ignore[call-arg]
        self._rate_limiter: TokenBucketRateLimiter | None = _create_rate_limiter(rate_limiter)
        self._circuit_breaker: CircuitBreaker = CircuitBreaker(
            circuit_breaker if circuit_breaker is not None else CircuitBreakerPolicy()  # type: ignore[call-arg]
        )
        self._diagnostic_mode = diagnostic_mode

        # Execution metrics (like BaseClient)
        self.execution_metrics = ClientExecutionMetrics()

        # Logger
        self.logger = ContentClientLogger(client_name, diagnostic_mode=diagnostic_mode)

        # httpx client for async operations - created lazily per event loop
        self._local_storage = threading.local()
        self._http2_available: bool = True  # Will be set to False if HTTP/2 fails

        if self._is_multithreaded:
            support_multithreading()

    def _get_async_client(self) -> httpx.AsyncClient:
        """Get or create an async client for the current event loop.

        This method ensures that the httpx.AsyncClient is created for and used
        within the same event loop, preventing issues when request_sync creates
        new event loops.

        Returns:
            An httpx.AsyncClient instance bound to the current event loop.
        """
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None

        # Check if we need to create a new client
        if (
            not hasattr(self._local_storage, "client")
            or self._local_storage.client is None
            or getattr(self._local_storage, "client_event_loop", None) != current_loop
        ):
            # Close existing client if any
            if getattr(self._local_storage, "client", None) is not None:
                try:
                    # Schedule close on the old loop if possible
                    old_loop = getattr(self._local_storage, "client_event_loop", None)
                    old_client = self._local_storage.client
                    if old_loop is not None and not old_loop.is_closed():
                        old_loop.call_soon_threadsafe(lambda c=old_client: asyncio.create_task(c.aclose()))
                except Exception:
                    pass  # Best effort cleanup

            # Create new client for current loop
            try:
                if self._http2_available:
                    self._local_storage.client = httpx.AsyncClient(
                        base_url=self._base_url.rstrip("/"),
                        timeout=self.timeout,
                        headers={"User-Agent": DEFAULT_USER_AGENT},
                        verify=self._verify,
                        http2=True,
                    )
            except ImportError:
                self._http2_available = False
                self.logger.info("HTTP/2 dependencies missing, falling back to HTTP/1.1 transport")

            if not self._http2_available or getattr(self._local_storage, "client", None) is None:
                self._local_storage.client = httpx.AsyncClient(
                    base_url=self._base_url.rstrip("/"),
                    timeout=self.timeout,
                    headers={"User-Agent": DEFAULT_USER_AGENT},
                    verify=self._verify,
                    http2=False,
                )

            self._local_storage.client_event_loop = current_loop

        return self._local_storage.client

    async def aclose(self) -> None:
        """Close the async HTTP client and release resources."""
        if self._closed:
            return
        self._closed = True
        if hasattr(self._local_storage, "client") and self._local_storage.client is not None:
            try:
                await self._local_storage.client.aclose()
            except Exception as e:
                self.logger.error(f"Error closing async client: {e}")
            finally:
                self._local_storage.client = None
                self._local_storage.client_event_loop = None

    def __enter__(self) -> "ContentClient":
        """Enter context manager."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager and close resources."""
        self.close()

    async def __aenter__(self) -> "ContentClient":
        """Enter async context manager."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit async context manager and close resources."""
        await self.aclose()

    def close(self) -> None:
        """Close the client synchronously.

        Note: If called from within an async context, use aclose() instead.
        This method handles various event loop scenarios gracefully.
        """
        if self._closed:
            return

        try:
            # Try to get the current event loop
            try:
                loop = asyncio.get_running_loop()
                # We're in an async context - schedule the close
                self.logger.warning("close() called from async context. Use 'await client.aclose()' instead.")
                # Schedule the close but don't wait - the caller should use aclose()
                loop.call_soon(lambda: asyncio.create_task(self.aclose()))
                return
            except RuntimeError:
                # No running loop - we can safely run synchronously
                pass

            # Try to use existing event loop or create new one
            try:
                loop = asyncio.get_event_loop()
                if loop.is_closed():
                    raise RuntimeError("Event loop is closed")
                loop.run_until_complete(self.aclose())
            except RuntimeError:
                # No event loop or it's closed, create a new one
                asyncio.run(self.aclose())
        except Exception as e:
            self.logger.error(f"Error closing client: {e}")
            # Mark as closed even if there was an error to prevent repeated attempts
            self._closed = True

    async def _request(
        self,
        method: str,
        url_suffix: str = "",
        full_url: str | None = None,
        headers: HeadersType | None = None,
        auth: tuple[str, str] | None = None,
        json_data: JsonType | None = None,
        params: ParamsType | None = None,
        data: Any | None = None,
        files: dict[str, Any] | None = None,
        timeout: float | None = None,
        resp_type: str = "json",
        ok_codes: StatusCodesType | None = None,
        return_empty_response: bool = False,
        retries: int = 0,
        status_list_to_retry: list[int] | None = None,
        backoff_factor: float = 5.0,
        backoff_jitter: float = 0.0,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
        error_handler: Callable[[httpx.Response], None] | None = None,
        empty_valid_codes: list[int] | None = None,
        params_parser: Callable[[ParamsType], ParamsType] | None = None,
        with_metrics: bool = False,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an async HTTP request with retry and error handling.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            url_suffix: URL path to append to base_url.
            full_url: Complete URL (overrides base_url + url_suffix).
            headers: Additional headers for this request.
            auth: Authentication tuple (username, password) for this request.
            json_data: JSON body data.
            params: Query parameters.
            data: Form data or raw body.
            files: Files to upload.
            timeout: Request timeout in seconds.
            resp_type: Expected response type ('json', 'text', 'content', 'response', 'xml').
            ok_codes: HTTP status codes considered successful.
            return_empty_response: Whether to return empty dict for empty responses.
            retries: Number of retry attempts (BaseClient compatibility).
            status_list_to_retry: Status codes that trigger retry.
            backoff_factor: Backoff multiplier for retries.
            backoff_jitter: Jitter factor for retry delays.
            raise_on_redirect: Whether to raise on redirect responses.
            raise_on_status: Whether to raise on non-2xx responses.
            error_handler: Custom error handler callback.
            empty_valid_codes: Status codes that return empty response.
            params_parser: Custom parameter parser function.
            with_metrics: Whether to include metrics in response.
            **kwargs: Additional arguments.

        Returns:
            The HTTP response object.

        Raises:
            ContentClientCircuitOpenError: If circuit breaker is open.
            ContentClientRateLimitError: If rate limit is exceeded.
            ContentClientAuthenticationError: If authentication fails.
            ContentClientRetryError: If all retry attempts are exhausted.
            ContentClientError: For other request failures.
        """

        if not self._circuit_breaker.can_execute():
            raise ContentClientCircuitOpenError("Circuit breaker is open, refusing to send request")

        if self._rate_limiter:
            await self._rate_limiter.acquire()

        # Prepare request
        url = full_url if full_url else urljoin(self._base_url, url_suffix)
        req_headers = self._headers.copy()
        if headers:
            req_headers.update(headers)
        if "User-Agent" not in req_headers:
            req_headers["User-Agent"] = DEFAULT_USER_AGENT

        req_params = _ensure_dict(params)

        attempt = 0
        last_error: Exception = Exception("Unknown error")
        trace: RequestTrace | None = None

        # Determine max attempts
        # If retries param is passed (BaseClient style), use it. Otherwise use retry_policy.
        max_attempts = retries + 1 if retries > 0 else self._retry_policy.max_attempts

        while attempt < max_attempts:
            attempt += 1
            start = _now()
            try:
                client = self._get_async_client()
                http_request = client.build_request(
                    method.upper(),
                    url=url,
                    params=req_params,
                    json=json_data,
                    data=data,
                    files=files,
                    headers=req_headers,
                    timeout=timeout or self.timeout,
                )

                if self._auth_handler:
                    await self._auth_handler.on_request(self, http_request)
                elif auth:
                    # Manual auth override
                    if isinstance(auth, tuple):
                        http_request.headers["Authorization"] = f"Basic {b64_encode(f'{auth[0]}:{auth[1]}')}"
                elif self._auth and isinstance(self._auth, tuple):
                    http_request.headers["Authorization"] = f"Basic {b64_encode(f'{self._auth[0]}:{self._auth[1]}')}"

                # Trace request if in diagnostic mode
                if self._diagnostic_mode:
                    full_req_url = str(http_request.url)
                    trace = self.logger.trace_request(
                        method=method.upper(),
                        url=full_req_url,
                        headers=dict(http_request.headers),
                        params=req_params,
                        body=json_data or data,
                        retry_attempt=attempt - 1,
                    )

                response = await client.send(http_request)
                elapsed_ms = (_now() - start) * 1000

                if self._diagnostic_mode and trace:
                    try:
                        response_body = response.json() if response.content else None
                    except Exception:
                        response_body = response.text[:1000]

                    self.logger.trace_response(
                        trace,
                        status=response.status_code,
                        headers=dict(response.headers),
                        body=response_body,
                        elapsed_ms=elapsed_ms,
                    )

                if response.status_code == 401 and self._auth_handler:
                    should_retry = await self._auth_handler.on_auth_failure(self, response)
                    if should_retry:
                        continue

                # Check for retryable status codes
                # Use status_list_to_retry if provided, else use policy
                retry_codes = status_list_to_retry if status_list_to_retry else self._retry_policy.retryable_status_codes

                if response.status_code in retry_codes:
                    raise httpx.HTTPStatusError("Retryable status", request=http_request, response=response)

                # Check for ok_codes
                # BaseClient logic: if ok_codes provided, check against it.
                # If not, check _ok_codes instance variable. Else check response.ok
                is_ok = False
                effective_ok_codes = ok_codes or self._ok_codes
                if effective_ok_codes:
                    is_ok = response.status_code in effective_ok_codes
                else:
                    is_ok = response.is_success

                if not is_ok:
                    # Raise exception to trigger error handling
                    response.raise_for_status()

                self.execution_metrics.success += 1
                self._circuit_breaker.record_success()
                self.logger.debug(  # noqa: PLE1205
                    "HTTP request completed",
                    {"status": response.status_code, "elapsed": elapsed_ms, "endpoint": url},
                )
                return response

            except ContentClientError:
                # Re-raise ContentClientError (including subclasses) without wrapping
                raise
            except (
                httpx.ConnectError,
                httpx.ReadTimeout,
                httpx.WriteTimeout,
                httpx.RemoteProtocolError,
                httpx.PoolTimeout,
            ) as exc:
                last_error = exc
                elapsed_ms = (_now() - start) * 1000
                if self._diagnostic_mode and trace:
                    self.logger.trace_error(trace, str(exc), elapsed_ms)

                should_retry = attempt < max_attempts
                if not should_retry:
                    break
                retry_after = _parse_retry_after(getattr(exc, "response", None))
                delay = self._retry_policy.next_delay(attempt, retry_after)
                self.execution_metrics.retry_error += 1
                self.logger.debug(  # noqa: PLE1205
                    "Retryable exception occurred",
                    {"attempt": attempt, "delay": delay, "error": str(exc), "error_type": type(exc).__name__},
                )
                await anyio.sleep(delay)
            except httpx.HTTPStatusError as exc:
                last_error = exc
                elapsed_ms = (_now() - start) * 1000
                if self._diagnostic_mode and trace:
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

                # Map HTTP status codes to specific exception types
                if exc.response.status_code == 429:
                    self.execution_metrics.quota_error += 1
                    self.logger.error("Rate limit error", {"status": 429, "error_type": "rate_limit"})  # noqa: PLE1205
                    should_retry = exc.response.status_code in (status_list_to_retry or self._retry_policy.retryable_status_codes)
                    if should_retry and attempt < max_attempts:
                        retry_after = _parse_retry_after(exc.response)
                        delay = self._retry_policy.next_delay(attempt, retry_after)
                        self.execution_metrics.retry_error += 1
                        await anyio.sleep(delay)
                        continue
                    self._circuit_breaker.record_failure()
                    raise ContentClientRateLimitError(f"Rate limit exceeded: {exc.response.text}", response=exc.response) from exc
                elif exc.response.status_code in (401, 403):
                    self.execution_metrics.auth_error += 1
                    self.logger.error(  # noqa: PLE1205
                        "Authentication error",
                        {"status": exc.response.status_code, "error_type": "auth"},
                    )
                    should_retry = exc.response.status_code in (status_list_to_retry or self._retry_policy.retryable_status_codes)
                    if should_retry and attempt < max_attempts:
                        retry_after = _parse_retry_after(exc.response)
                        delay = self._retry_policy.next_delay(attempt, retry_after)
                        self.execution_metrics.retry_error += 1
                        await anyio.sleep(delay)
                        continue
                    self._circuit_breaker.record_failure()
                    raise ContentClientAuthenticationError(
                        f"Authentication failed: {exc.response.text}", response=exc.response
                    ) from exc
                else:
                    self.execution_metrics.service_error += 1
                    self.logger.error(  # noqa: PLE1205
                        "Service error",
                        {"status": exc.response.status_code, "error_type": "service"},
                    )
                    should_retry = exc.response.status_code in (status_list_to_retry or self._retry_policy.retryable_status_codes)
                    if should_retry and attempt < max_attempts:
                        retry_after = _parse_retry_after(exc.response)
                        delay = self._retry_policy.next_delay(attempt, retry_after)
                        self.execution_metrics.retry_error += 1
                        await anyio.sleep(delay)
                        continue
                    self._circuit_breaker.record_failure()
                    raise ContentClientError(f"Request failed: {exc.response.text}", response=exc.response) from exc
            except Exception as exc:
                elapsed_ms = (_now() - start) * 1000
                if self._diagnostic_mode and trace:
                    self.logger.trace_error(trace, str(exc), elapsed_ms)

                self.execution_metrics.general_error += 1
                self._circuit_breaker.record_failure()
                self.logger.error(  # noqa: PLE1205
                    "Non-retryable exception occurred",
                    {"error": str(exc), "error_type": type(exc).__name__},
                )
                raise

        self._circuit_breaker.record_failure()
        last_response = getattr(last_error, "response", None)
        raise ContentClientRetryError(f"Exceeded retry attempts: {last_error}", response=last_response)

    def _http_request(
        self,
        method: str,
        url_suffix: str = "",
        full_url: str | None = None,
        headers: HeadersType | None = None,
        auth: tuple[str, str] | None = None,
        json_data: JsonType | None = None,
        params: ParamsType | None = None,
        data: Any | None = None,
        files: dict[str, Any] | None = None,
        timeout: float | None = None,
        resp_type: str = "json",
        ok_codes: StatusCodesType | None = None,
        return_empty_response: bool = False,
        retries: int = 0,
        status_list_to_retry: list[int] | None = None,
        backoff_factor: float = 5.0,
        backoff_jitter: float = 0.0,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
        error_handler: Callable[[httpx.Response], None] | None = None,
        empty_valid_codes: list[int] | None = None,
        params_parser: Callable[[ParamsType], ParamsType] | None = None,
        with_metrics: bool = False,
        **kwargs: Any,
    ) -> Any:
        """Synchronous wrapper for _request to maintain BaseClient compatibility.

        This method provides the same interface as BaseClient._http_request().
        See _request() for full parameter documentation.

        Returns:
            The processed response based on resp_type parameter.
        """
        return self.request_sync(
            method=method,
            url_suffix=url_suffix,
            full_url=full_url,
            headers=headers,
            auth=auth,
            json_data=json_data,
            params=params,
            data=data,
            files=files,
            timeout=timeout,
            resp_type=resp_type,
            ok_codes=ok_codes,
            return_empty_response=return_empty_response,
            retries=retries,
            status_list_to_retry=status_list_to_retry,
            backoff_factor=backoff_factor,
            backoff_jitter=backoff_jitter,
            raise_on_redirect=raise_on_redirect,
            raise_on_status=raise_on_status,
            error_handler=error_handler,
            empty_valid_codes=empty_valid_codes,
            params_parser=params_parser,
            with_metrics=with_metrics,
            **kwargs,
        )

    def request_sync(self, *args: Any, **kwargs: Any) -> Any:
        """Execute a request synchronously.

        This method wraps the async _request method for synchronous usage.
        It handles response processing based on the resp_type parameter.

        The implementation creates a new event loop for each synchronous request
        to avoid issues with event loop reuse. The httpx.AsyncClient is automatically
        recreated for each new event loop.

        Args:
            *args: Positional arguments passed to _request.
            **kwargs: Keyword arguments passed to _request.

        Returns:
            The processed response based on resp_type (json, text, content, response, xml).
        """

        async def _do_request() -> Any:
            try:
                response = await self._request(*args, **kwargs)

                # Handle response processing (json, text, content) similar to BaseClient
                resp_type = kwargs.get("resp_type", "json")
                return_empty_response = kwargs.get("return_empty_response", False)
                empty_valid_codes = kwargs.get("empty_valid_codes")

                if return_empty_response and empty_valid_codes and response.status_code in empty_valid_codes:
                    return {}

                if resp_type == "json":
                    try:
                        return response.json()
                    except json.JSONDecodeError:
                        if not response.content:
                            return {}
                        raise
                elif resp_type == "text":
                    return response.text
                elif resp_type == "content":
                    return response.content
                elif resp_type == "response":
                    return response
                elif resp_type == "xml":
                    return response.text

                # Default fallback - try JSON
                try:
                    return response.json()
                except json.JSONDecodeError:
                    # If JSON parsing fails, return the response object
                    return response
            finally:
                # Clean up the client after each sync request only if reuse_client is False
                # When reuse_client is True (default), the client is kept open for better performance
                if not self._reuse_client and hasattr(self._local_storage, "client") and self._local_storage.client is not None:
                    try:
                        await self._local_storage.client.aclose()
                    except Exception:
                        pass
                    self._local_storage.client = None
                    self._local_storage.client_event_loop = None

        # Check if we're already in an async context
        try:
            asyncio.get_running_loop()
            # We're in an async context, need to use a thread pool
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(asyncio.run, _do_request())
                return future.result()
        except RuntimeError:
            # No running event loop, safe to use asyncio.run
            return asyncio.run(_do_request())

    # Standard HTTP verb helpers
    def get(self, url_suffix: str, params: ParamsType | None = None, **kwargs: Any) -> Any:
        """Execute a GET request.

        Args:
            url_suffix: URL path to append to base_url.
            params: Query parameters.
            **kwargs: Additional arguments passed to _http_request.

        Returns:
            The response object or processed response data.
        """
        if "resp_type" not in kwargs:
            kwargs["resp_type"] = "response"
        return self._http_request("GET", url_suffix, params=params, **kwargs)

    def post(self, url_suffix: str, json_data: JsonType | None = None, **kwargs: Any) -> Any:
        """Execute a POST request.

        Args:
            url_suffix: URL path to append to base_url.
            json_data: JSON body data.
            **kwargs: Additional arguments passed to _http_request.

        Returns:
            The response object or processed response data.
        """
        if "resp_type" not in kwargs:
            kwargs["resp_type"] = "response"
        return self._http_request("POST", url_suffix, json_data=json_data, **kwargs)

    def put(self, url_suffix: str, json_data: JsonType | None = None, **kwargs: Any) -> Any:
        """Execute a PUT request.

        Args:
            url_suffix: URL path to append to base_url.
            json_data: JSON body data.
            **kwargs: Additional arguments passed to _http_request.

        Returns:
            The response object or processed response data.
        """
        if "resp_type" not in kwargs:
            kwargs["resp_type"] = "response"
        return self._http_request("PUT", url_suffix, json_data=json_data, **kwargs)

    def patch(self, url_suffix: str, json_data: JsonType | None = None, **kwargs: Any) -> Any:
        """Execute a PATCH request.

        Args:
            url_suffix: URL path to append to base_url.
            json_data: JSON body data.
            **kwargs: Additional arguments passed to _http_request.

        Returns:
            The response object or processed response data.
        """
        if "resp_type" not in kwargs:
            kwargs["resp_type"] = "response"
        return self._http_request("PATCH", url_suffix, json_data=json_data, **kwargs)

    def delete(self, url_suffix: str, **kwargs: Any) -> Any:
        """Execute a DELETE request.

        Args:
            url_suffix: URL path to append to base_url.
            **kwargs: Additional arguments passed to _http_request.

        Returns:
            The response object or processed response data.
        """
        if "resp_type" not in kwargs:
            kwargs["resp_type"] = "response"
        return self._http_request("DELETE", url_suffix, **kwargs)

    @property
    def metrics(self) -> ClientExecutionMetrics:
        """Get the execution metrics for this client.

        Returns:
            The ClientExecutionMetrics instance tracking request outcomes.
        """
        return self.execution_metrics

    def get_diagnostic_report(self) -> DiagnosticReport:
        """Generate a diagnostic report for troubleshooting.

        Returns:
            A DiagnosticReport containing traces, metrics, and recommendations.
        """
        return self.logger.get_diagnostic_report(
            configuration={"name": self.logger.client_name, "base_url": self._base_url, "timeout": self.timeout}
        )

    def diagnose_error(self, error: Exception) -> dict[str, str]:
        """Diagnose an error and provide a solution recommendation.

        Args:
            error: The exception to diagnose.

        Returns:
            A dictionary with 'issue' and 'solution' keys.
        """
        if isinstance(error, ContentClientAuthenticationError):
            return {"issue": "Authentication failed", "solution": "Check credentials and token expiration."}
        if isinstance(error, ContentClientRateLimitError):
            return {"issue": "Rate limit exceeded", "solution": "Increase retry delay or request quota."}
        if isinstance(error, ContentClientTimeoutError):
            return {"issue": "Execution timeout", "solution": "Increase timeout settings or reduce batch size."}
        if isinstance(error, ContentClientCircuitOpenError):
            return {"issue": "Circuit breaker is open", "solution": "Wait for recovery timeout."}
        if isinstance(error, ContentClientRetryError):
            return {"issue": "All retry attempts exhausted", "solution": "Check API availability and retry policy."}
        if isinstance(error, ContentClientConfigurationError):
            return {"issue": "Configuration error", "solution": "Check integration parameters."}
        return {"issue": "Unexpected error", "solution": f"Check logs for details: {str(error)}"}

    def health_check(self) -> dict[str, Any]:
        """Perform a health check on the client.

        Returns:
            A dictionary with 'status', 'configuration_valid', 'warnings', and 'metrics'.
        """
        status: str = "healthy"
        warnings: list[str] = []

        if self.execution_metrics.auth_error > 0:
            status = "degraded"
            warnings.append("Authentication errors detected")
        if self.execution_metrics.general_error > 0:
            status = "degraded"
            warnings.append("General errors detected")
        if self.execution_metrics.quota_error > 0:
            status = "degraded"
            warnings.append("Rate limit errors detected")

        return {"status": status, "configuration_valid": True, "warnings": warnings, "metrics": self.execution_metrics}
