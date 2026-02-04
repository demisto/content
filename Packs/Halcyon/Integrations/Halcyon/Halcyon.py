import urllib3
from enum import Enum
from typing import Any

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import asyncio
import concurrent.futures
import json
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any,
    Callable,
    Dict,
    Final,
    List,
    MutableMapping,
    Optional,
    Tuple,
    Type,
)

import anyio
import demistomock as demisto
import httpx
from pydantic import BaseModel, Field
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

# Type aliases for better readability
HeadersType = Dict[str, str]
ParamsType = Dict[str, Any]
JsonType = Dict[str, Any]
StatusCodesType = Tuple[int, ...]

# Constants
DEFAULT_USER_AGENT: Final[str] = "ContentClient/1.0"


def _now() -> float:
    return time.monotonic()


def _ensure_dict(value: Optional[MutableMapping[str, Any]]) -> Dict[str, Any]:
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


def _extract_list(data: Any, path: Optional[str]) -> List[Any]:
    extracted = _get_value_by_path(data, path) if path else data
    if extracted is None:
        return []
    if isinstance(extracted, list):
        return extracted
    if isinstance(extracted, dict):
        return [extracted]
    # Handle primitive types explicitly
    if isinstance(extracted, (str, int, float, bool)):
        return [extracted]
    return [extracted]


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
            parsed = datetime.strptime(retry_after, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
            return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
        except ValueError:
            return None


# Error Classes


class ContentClientError(DemistoException):
    """Base error for all content client failures."""

    def __init__(self, message: str, response: Optional[httpx.Response] = None):
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
        self._opened_at: Optional[float] = None
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
    execution: Optional[float] = Field(None, gt=0)
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

    cursor: Optional[str] = None
    page: Optional[int] = None
    offset: Optional[int] = None
    last_event_id: Optional[str] = None
    partial_results: List[Any] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
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
    def from_dict(cls, raw: Optional[Dict[str, Any]]) -> "ContentClientState":
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

    def read(self) -> Dict[str, Any]:
        """Read the current integration context.

        Returns:
            The integration context dictionary.
        """
        with self._lock:
            context: Dict[str, Any] = demisto.getIntegrationContext() or {}
            return context

    def write(self, data: Dict[str, Any]) -> None:
        """Write data to the integration context with retry logic.

        Uses thread-safe locking to prevent race conditions.

        Args:
            data: The data dictionary to write to the context.

        Raises:
            Exception: If all retry attempts fail.
        """
        last_error: Optional[Exception] = None
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

    def load(self) -> Optional["ContentClientState"]:
        """Load state from integration context.

        This is an alias for read() that returns a ContentClientState object.
        Provided for convenience when working with ContentClientState.

        Returns:
            ContentClientState object if data exists, None otherwise.
        """
        data = self.read()
        if not data:
            return None
        return ContentClientState.from_dict(data.get(self.namespace, {}))

    def save(self, state: "ContentClientState") -> None:
        """Save state to integration context.

        This is an alias for write() that accepts a ContentClientState object.
        Provided for convenience when working with ContentClientState.

        Args:
            state: The ContentClientState object to save.
        """
        data = self.read()
        data[self.namespace] = state.to_dict()
        self.write(data)


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

    def __init__(self, key: str, header_name: Optional[str] = None, query_param: Optional[str] = None):
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
        scope: Optional[str] = None,
        audience: Optional[str] = None,
        auth_params: Optional[Dict[str, str]] = None,
        context_store: Optional[Any] = None,
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

        self._access_token: Optional[str] = None
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

    def __init__(self, severity: str, message: str, client_name: str, request_id: Optional[str] = None, **kwargs: Any) -> None:
        self.entry: Dict[str, Any] = {
            "severity": severity.upper(),
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return self.entry


def create_http_request_log(
    method: str,
    url: str,
    status: Optional[int] = None,
    latency_ms: Optional[float] = None,
    request_size: Optional[int] = None,
    response_size: Optional[int] = None,
    user_agent: Optional[str] = None,
) -> Dict[str, Any]:
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
    http_request: Dict[str, Any] = {
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
    stack_trace: Optional[str] = None,
    error_code: Optional[str] = None,
) -> Dict[str, Any]:
    """Create an error object for structured logging.

    Args:
        error_type: Type/class of the error
        error_message: Error message
        stack_trace: Optional stack trace
        error_code: Optional error code for categorization

    Returns:
        Dictionary with error details
    """
    error: Dict[str, Any] = {
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

    content_item_name: str
    configuration: Dict[str, Any]
    request_traces: List[RequestTrace]
    state_snapshots: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    errors: List[Dict[str, Any]]
    recommendations: List[str]
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
        self._traces: List[RequestTrace] = []
        self._errors: List[Dict[str, Any]] = []
        self._performance: Dict[str, List[float]] = {
            "request_times": [],
            "pagination_times": [],
            "auth_times": [],
        }
        self._current_request_id: Optional[str] = None

    def new_request_id(self) -> str:
        """Generate a new request ID for correlation.

        Returns:
            A unique request ID string.
        """
        self._current_request_id = str(uuid.uuid4())[:8]
        return self._current_request_id

    def get_request_id(self) -> Optional[str]:
        """Get the current request ID.

        Returns:
            The current request ID or None if not set.
        """
        return self._current_request_id

    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
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

    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
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

    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
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

    def error(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
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
        status: Optional[int] = None,
        latency_ms: Optional[float] = None,
        request_size: Optional[int] = None,
        response_size: Optional[int] = None,
        retry_attempt: int = 0,
        error: Optional[str] = None,
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

        extra: Dict[str, Any] = {
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
        headers: Dict[str, str],
        params: Dict[str, Any],
        body: Optional[Any] = None,
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
        headers: Dict[str, str],
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
        elapsed_ms: Optional[float] = None,
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
        configuration: Dict[str, Any],
        state_snapshots: Optional[List[Dict[str, Any]]] = None,
    ) -> DiagnosticReport:
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
            error_types: Dict[str, int] = {}
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

    def _format(self, level: str, message: str, extra: Optional[Dict[str, Any]]) -> str:
        if not extra:
            return f"[ContentClient:{self.client_name}:{level}] {message}"
        try:
            extra_str = json.dumps(extra)
        except (TypeError, ValueError):
            extra_str = str(extra)
        return f"[ContentClient:{self.client_name}:{level}] {message} | extra={extra_str}"


def _create_rate_limiter(policy: Optional[RateLimitPolicy]) -> Optional[TokenBucketRateLimiter]:
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
        headers: Optional[HeadersType] = None,
        auth: Optional[Tuple[str, str]] = None,
        timeout: float = 60.0,
        # New optional parameters (backward compatible):
        auth_handler: Optional[AuthHandler] = None,
        retry_policy: Optional[RetryPolicy] = None,
        rate_limiter: Optional[RateLimitPolicy] = None,
        circuit_breaker: Optional[CircuitBreakerPolicy] = None,
        diagnostic_mode: bool = False,
        client_name: str = "ContentClient",
        is_multithreaded: bool = True,
        reuse_client: bool = True
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
        self._auth: Optional[Tuple[str, str]] = auth
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
        self._auth_handler: Optional[AuthHandler] = auth_handler
        self._retry_policy: RetryPolicy = retry_policy if retry_policy is not None else RetryPolicy()
        self._rate_limiter: Optional[TokenBucketRateLimiter] = _create_rate_limiter(rate_limiter)
        self._circuit_breaker: CircuitBreaker = CircuitBreaker(
            circuit_breaker if circuit_breaker is not None else CircuitBreakerPolicy()
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
        if not hasattr(self._local_storage, "client") or self._local_storage.client is None or \
                getattr(self._local_storage, "client_event_loop", None) != current_loop:
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
            # Merge default headers with User-Agent
            client_headers = {"User-Agent": DEFAULT_USER_AGENT}
            if self._headers:
                client_headers.update(self._headers)

            try:
                if self._http2_available:
                    self._local_storage.client = httpx.AsyncClient(
                        base_url=self._base_url.rstrip("/"),
                        timeout=self.timeout,
                        headers=client_headers,
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
                    headers=client_headers,
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
        full_url: Optional[str] = None,
        headers: Optional[HeadersType] = None,
        auth: Optional[Tuple[str, str]] = None,
        json_data: Optional[JsonType] = None,
        params: Optional[ParamsType] = None,
        data: Optional[Any] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        resp_type: str = "json",
        ok_codes: Optional[StatusCodesType] = None,
        return_empty_response: bool = False,
        retries: int = 0,
        status_list_to_retry: Optional[List[int]] = None,
        backoff_factor: float = 5.0,
        backoff_jitter: float = 0.0,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
        error_handler: Optional[Callable[[httpx.Response], None]] = None,
        empty_valid_codes: Optional[List[int]] = None,
        params_parser: Optional[Callable[[ParamsType], ParamsType]] = None,
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
        trace: Optional[RequestTrace] = None

        # Determine max attempts
        # If retries param is passed (BaseClient style), use it. Otherwise use retry_policy.
        max_attempts = retries + 1 if retries > 0 else self._retry_policy.max_attempts

        while attempt < max_attempts:
            attempt += 1
            start = _now()
            try:
                client = self._get_async_client()
                demisto.debug(f"ContentClient._request: Building request with req_headers={req_headers}")
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

                demisto.debug(f"ContentClient._request: After build_request, headers={dict(http_request.headers)}")
                
                if self._auth_handler:
                    await self._auth_handler.on_request(self, http_request)
                    demisto.debug(f"ContentClient._request: After auth_handler.on_request, headers={dict(http_request.headers)}")
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
        full_url: Optional[str] = None,
        headers: Optional[HeadersType] = None,
        auth: Optional[Tuple[str, str]] = None,
        json_data: Optional[JsonType] = None,
        params: Optional[ParamsType] = None,
        data: Optional[Any] = None,
        files: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
        resp_type: str = "json",
        ok_codes: Optional[StatusCodesType] = None,
        return_empty_response: bool = False,
        retries: int = 0,
        status_list_to_retry: Optional[List[int]] = None,
        backoff_factor: float = 5.0,
        backoff_jitter: float = 0.0,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
        error_handler: Optional[Callable[[httpx.Response], None]] = None,
        empty_valid_codes: Optional[List[int]] = None,
        params_parser: Optional[Callable[[ParamsType], ParamsType]] = None,
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
                if not self._reuse_client:
                    if hasattr(self._local_storage, "client") and self._local_storage.client is not None:
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
    def get(self, url_suffix: str, params: Optional[ParamsType] = None, **kwargs: Any) -> Any:
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

    def post(self, url_suffix: str, json_data: Optional[JsonType] = None, **kwargs: Any) -> Any:
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

    def put(self, url_suffix: str, json_data: Optional[JsonType] = None, **kwargs: Any) -> Any:
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

    def patch(self, url_suffix: str, json_data: Optional[JsonType] = None, **kwargs: Any) -> Any:
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

    def diagnose_error(self, error: Exception) -> Dict[str, str]:
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

    def health_check(self) -> Dict[str, Any]:
        """Perform a health check on the client.

        Returns:
            A dictionary with 'status', 'configuration_valid', 'warnings', and 'metrics'.
        """
        status: str = "healthy"
        warnings: List[str] = []

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


# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

VENDOR = "halcyon"
PRODUCT = "halcyon"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # ISO8601 format with milliseconds
API_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"  # Format for API requests
DEFAULT_PAGE_SIZE = 100
DEFAULT_MAX_FETCH = 1000
CLIENT_NAME = "Halcyon"

""" LOG TYPE ENUM """


class LogType(Enum):
    """Enum to hold all configuration for different log types."""

    ALERTS = ("alerts", "Alerts", "/v2/alerts", "firstOccurredAt", "lastSeenAfter", "lastSeenBefore", "LastSeen")
    EVENTS = ("events", "Events", "/v2/events", "occurredAt", "occurredAfter", "occurredBefore", "OccurredAt")

    def __init__(
        self,
        type_string: str,
        title: str,
        api_endpoint: str,
        time_field: str,
        after_param: str,
        before_param: str,
        sort_by: str,
    ):
        self.type_string = type_string
        self.title = title
        self.api_endpoint = api_endpoint
        self.time_field = time_field
        self.after_param = after_param
        self.before_param = before_param
        self.sort_by = sort_by


""" CUSTOM AUTH HANDLER """


class HalcyonAuthHandler(AuthHandler):
    """Custom authentication handler for Halcyon API.

    Handles username/password login and automatic token refresh.
    Uses the Halcyon Login API to authenticate and stores tokens in integration context.
    """

    def __init__(
        self,
        username: str,
        password: str,
        tenant_id: str,
        login_url: str = "/identity/auth/login",
        refresh_url: str = "/identity/auth/refresh",
        context_store: ContentClientContextStore | None = None,
    ):
        """Initialize the Halcyon auth handler.

        Args:
            username: Halcyon account username.
            password: Halcyon account password.
            tenant_id: Halcyon Tenant ID (required for all API requests).
            login_url: URL suffix for login endpoint.
            refresh_url: URL suffix for token refresh endpoint.
            context_store: Optional context store for persisting tokens.
        """
        if not username:
            raise ContentClientAuthenticationError("HalcyonAuthHandler requires a non-empty username")
        if not password:
            raise ContentClientAuthenticationError("HalcyonAuthHandler requires a non-empty password")

        self.username = username
        self.password = password
        self.tenant_id = tenant_id
        self.login_url = login_url
        self.refresh_url = refresh_url
        self.context_store = context_store or ContentClientContextStore(CLIENT_NAME)

        self._access_token: str | None = None
        self._refresh_token: str | None = None
        self._load_tokens_from_context()

    def _load_tokens_from_context(self) -> None:
        """Load tokens from integration context."""
        state = self.context_store.load()
        if state and state.metadata:
            self._access_token = state.metadata.get("access_token")
            self._refresh_token = state.metadata.get("refresh_token")
            demisto.debug("Loaded tokens from integration context")

    def _save_tokens_to_context(self) -> None:
        """Save tokens to integration context."""
        state = ContentClientState(
            metadata={
                "access_token": self._access_token,
                "refresh_token": self._refresh_token,
            }
        )
        self.context_store.save(state)
        demisto.debug("Saved tokens to integration context")

    async def on_request(self, client: "ContentClient", request) -> None:
        """Add authentication header to the request.

        Args:
            client: The ContentClient instance.
            request: The HTTP request to modify.
        """
        # Ensure we have a valid token
        if not self._access_token:
            await self._login(client)

        request.headers["Authorization"] = f"Bearer {self._access_token}"

    async def on_auth_failure(self, client: "ContentClient", response) -> bool:
        """Handle authentication failure by refreshing the token.

        Args:
            client: The ContentClient instance.
            response: The HTTP response that failed.

        Returns:
            True if token was refreshed and request should be retried.
        """
        demisto.debug("Authentication failed, attempting token refresh")

        try:
            await self._refresh_access_token(client)
            return True
        except ContentClientAuthenticationError:
            demisto.debug("Token refresh failed, attempting full login")
            try:
                await self._login(client)
                return True
            except ContentClientAuthenticationError:
                return False

    async def _login(self, client: "ContentClient") -> None:
        """Authenticate with the Halcyon API using username/password.

        Args:
            client: The ContentClient instance.

        Raises:
            ContentClientAuthenticationError: If login fails.
        """
        import httpx

        demisto.debug("Authenticating with Halcyon API using username/password")

        # Build headers including X-TenantID which is required for all Halcyon API requests
        request_headers = {
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            request_headers["X-TenantID"] = self.tenant_id

        try:
            async with httpx.AsyncClient(verify=client._verify) as http_client:
                response = await http_client.post(
                    f"{client._base_url}{self.login_url}",
                    json={"username": self.username, "password": self.password},
                    headers=request_headers,
                )
                response.raise_for_status()
                data = response.json()

                self._access_token = data.get("accessToken")
                self._refresh_token = data.get("refreshToken")

                if not self._access_token or not self._refresh_token:
                    raise ContentClientAuthenticationError("No tokens in login response")

                self._save_tokens_to_context()
                demisto.debug("Successfully authenticated with Halcyon API")

        except httpx.HTTPStatusError as e:
            raise ContentClientAuthenticationError(
                f"Login failed with status {e.response.status_code}: {e.response.text}"
            ) from e
        except Exception as e:
            raise ContentClientAuthenticationError(f"Failed to login: {e!s}") from e

    async def _refresh_access_token(self, client: "ContentClient") -> None:
        """Refresh the access token using the refresh token.

        Args:
            client: The ContentClient instance.

        Raises:
            ContentClientAuthenticationError: If token refresh fails.
        """
        import httpx

        if not self._refresh_token:
            raise ContentClientAuthenticationError("No refresh token available")

        demisto.debug("Refreshing access token")

        # Build headers including X-TenantID which is required for all Halcyon API requests
        request_headers = {
            "Content-Type": "application/json",
        }
        if self.tenant_id:
            request_headers["X-TenantID"] = self.tenant_id

        try:
            async with httpx.AsyncClient(verify=client._verify) as http_client:
                response = await http_client.post(
                    f"{client._base_url}{self.refresh_url}",
                    json={"refreshToken": self._refresh_token},
                    headers=request_headers,
                )
                response.raise_for_status()
                data = response.json()

                self._access_token = data.get("accessToken")
                self._refresh_token = data.get("refreshToken")

                if not self._access_token or not self._refresh_token:
                    raise ContentClientAuthenticationError("No tokens in refresh response")

                self._save_tokens_to_context()
                demisto.debug("Successfully refreshed access token")

        except httpx.HTTPStatusError as e:
            raise ContentClientAuthenticationError(
                f"Token refresh failed with status {e.response.status_code}: {e.response.text}"
            ) from e
        except Exception as e:
            raise ContentClientAuthenticationError(f"Failed to refresh token: {e!s}") from e


""" CLIENT CLASS """


class Client(ContentClient):
    """Client class to interact with the Halcyon API.

    Extends ContentClient with Halcyon-specific functionality including
    custom authentication and API methods for alerts and events.
    """

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        tenant_id: str,
        verify: bool,
        proxy: bool,
        max_fetch_alerts: int,
        max_fetch_events: int,
    ):
        """Initialize the Halcyon client.

        Args:
            base_url: Halcyon API server URL.
            username: Halcyon account username.
            password: Halcyon account password.
            tenant_id: Halcyon Tenant ID (X-TenantID header).
            verify: Whether to verify SSL certificates.
            proxy: Whether to use proxy settings.
            max_fetch_alerts: Maximum alerts to fetch per cycle.
            max_fetch_events: Maximum events to fetch per cycle.
        """
        # Create context store for token persistence
        context_store = ContentClientContextStore(CLIENT_NAME)

        # Create custom auth handler
        auth_handler = HalcyonAuthHandler(
            username=username,
            password=password,
            tenant_id=tenant_id,
            context_store=context_store,
        )

        # Create retry policy with custom settings
        retry_policy = RetryPolicy(
            max_attempts=4,  # 3 retries + 1 initial attempt
            retryable_status_codes=(429, 500, 502, 503, 504),
        )

        # Set default headers including X-TenantID
        # Note: The Halcyon API expects X-TenantID as a plain UUID (e.g., "87d50c45-af11-405d-a556-f659e30a978d")
        # NOT in URN format (e.g., "urn:uuid:...")
        demisto.debug(f"Halcyon Client: Initializing with tenant_id={tenant_id}")
        headers = {
            "X-TenantID": tenant_id,
        }

        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers=headers,
            auth_handler=auth_handler,
            client_name=CLIENT_NAME,
            timeout=30,
            retry_policy=retry_policy,
        )

        self.max_fetch_alerts = max_fetch_alerts
        self.max_fetch_events = max_fetch_events

    def get_alerts(
        self,
        last_seen_after: str | None = None,
        last_seen_before: str | None = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict:
        """Fetch alerts from the Halcyon API.

        Args:
            last_seen_after: Filter alerts last seen after this datetime.
            last_seen_before: Filter alerts last seen before this datetime.
            page: Page number (1-based).
            page_size: Number of results per page.

        Returns:
            API response containing alerts.
        """
        params: dict[str, Any] = {
            "page": page,
            "pageSize": page_size,
            "sortBy": "LastSeen",
            "sortOrder": "Asc",  # Ascending to get oldest first for proper pagination
        }

        if last_seen_after:
            params["lastSeenAfter"] = last_seen_after
        if last_seen_before:
            params["lastSeenBefore"] = last_seen_before

        demisto.debug(f"Fetching alerts with params: {params}")
        return self._http_request(method="GET", url_suffix="/v2/alerts", params=params)

    def get_events(
        self,
        occurred_after: str | None = None,
        occurred_before: str | None = None,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict:
        """Fetch events from the Halcyon API.

        Args:
            occurred_after: Filter events occurred after this datetime.
            occurred_before: Filter events occurred before this datetime.
            page: Page number (1-based).
            page_size: Number of results per page.

        Returns:
            API response containing events.
        """
        params: dict[str, Any] = {
            "page": page,
            "pageSize": page_size,
            "sortBy": "OccurredAt",
            "sortOrder": "Asc",  # Ascending to get oldest first for proper pagination
        }

        if occurred_after:
            params["occurredAfter"] = occurred_after
        if occurred_before:
            params["occurredBefore"] = occurred_before

        demisto.debug(f"Fetching events with params: {params}")
        return self._http_request(method="GET", url_suffix="/v2/events", params=params)


""" HELPER FUNCTIONS """


def get_log_types_from_titles(event_types_to_fetch: list[str]) -> list[LogType]:
    """Converts a list of user-facing event type titles into a list of LogType Enum members.

    Args:
        event_types_to_fetch: A list of event type titles from the integration parameters
                              (e.g., ["Alerts", "Events"]).

    Raises:
        DemistoException: If any of the provided event type titles are invalid.

    Returns:
        A list of LogType Enum members corresponding to the provided titles.
    """
    valid_titles = {lt.title for lt in LogType}

    invalid_types = [title for title in event_types_to_fetch if title not in valid_titles]

    if invalid_types:
        valid_options = ", ".join(valid_titles)
        raise DemistoException(
            f"Invalid event type(s) provided: {invalid_types}. "
            f"Please select from the following list: {valid_options}"
        )

    return [lt for lt in LogType if lt.title in event_types_to_fetch]


def enrich_events(events: list[dict], log_type: LogType) -> list[dict]:
    """Enriches a list of events with the '_time' and 'source_log_type' fields.

    Args:
        events: A list of event dictionaries to enrich.
        log_type: The LogType Enum member representing the source of these events.

    Returns:
        The enriched list of events.
    """
    for event in events:
        # Set _time based on the log type's time field
        time_value = event.get(log_type.time_field)
        if time_value:
            event["_time"] = time_value
        event["source_log_type"] = log_type.type_string

    return events


def deduplicate_events(
    events: list[dict],
    previous_run_ids: set[str],
    previous_timestamp: str | None,
    log_type: LogType,
) -> tuple[list[dict], set[str], str | None]:
    """Removes duplicate events based on their IDs and tracks the last timestamp.

    This function implements proper deduplication based on end times:
    1. Events with timestamps earlier than the previous timestamp are skipped (already processed)
    2. Events with the same timestamp as the previous run are checked against previous_run_ids
    3. Events with timestamps later than the previous timestamp are always included
    4. The new set of IDs only contains events that share the LAST timestamp (for next run dedup)

    Args:
        events: List of events fetched from the API.
        previous_run_ids: Set of event IDs from the previous run that share the same timestamp.
        previous_timestamp: The timestamp from the previous run (used for comparison).
        log_type: The LogType Enum member for the logs being processed.

    Returns:
        A tuple containing:
        - A list of unique event dictionaries.
        - The new set of event IDs that share the last timestamp (for next run deduplication).
        - The last event timestamp (or None if no events).
    """
    unique_events = []
    last_timestamp: str | None = None
    last_timestamp_ids: set[str] = set()
    id_field = "alertId" if log_type == LogType.ALERTS else "eventId"

    for event in events:
        event_id = event.get(id_field)
        time_value = event.get(log_type.time_field)

        if not event_id:
            continue

        # If this event has the same timestamp as the previous run's last timestamp,
        # check if we've already processed it
        if previous_timestamp and time_value == previous_timestamp:
            if event_id in previous_run_ids:
                # Already processed this event, skip it
                continue

        # This is a new event, add it
        unique_events.append(event)

        # Track the last timestamp and IDs that share it
        if time_value:
            if time_value != last_timestamp:
                # New timestamp, reset the ID set
                last_timestamp = time_value
                last_timestamp_ids = {event_id}
            else:
                # Same timestamp, add to the set
                last_timestamp_ids.add(event_id)

    demisto.debug(
        f"Deduplicated {log_type.type_string}: {len(events)} -> {len(unique_events)} events. "
        f"Previous IDs: {len(previous_run_ids)}, Last timestamp IDs: {len(last_timestamp_ids)}"
    )

    return unique_events, last_timestamp_ids, last_timestamp


def fetch_events_for_log_type(
    client: Client,
    log_type: LogType,
    last_run: dict,
    max_fetch: int,
) -> tuple[list[dict], dict]:
    """Fetches events for a specific log type.

    Args:
        client: The Halcyon client.
        log_type: The LogType to fetch.
        last_run: The last run dictionary.
        max_fetch: Maximum number of events to fetch.

    Returns:
        A tuple of (events, updated_last_run).
    """
    # Get last run state for this log type
    last_fetch_key = f"last_fetch_{log_type.type_string}"
    previous_ids_key = f"previous_ids_{log_type.type_string}"

    last_fetch_time = last_run.get(last_fetch_key)
    previous_run_ids = set(last_run.get(previous_ids_key, []))

    # If no last fetch time, start from now (per Confluence guidelines)
    if not last_fetch_time:
        last_fetch_time = datetime.now(timezone.utc).strftime(API_DATE_FORMAT)
        demisto.debug(f"No previous fetch time for {log_type.type_string}, starting from: {last_fetch_time}")

    all_events: list[dict] = []
    page = 1
    page_size = min(DEFAULT_PAGE_SIZE, max_fetch)

    while len(all_events) < max_fetch:
        demisto.debug(f"Fetching {log_type.type_string} page {page} with page_size {page_size}")

        if log_type == LogType.ALERTS:
            response = client.get_alerts(
                last_seen_after=last_fetch_time,
                page=page,
                page_size=page_size,
            )
        else:  # LogType.EVENTS
            response = client.get_events(
                occurred_after=last_fetch_time,
                page=page,
                page_size=page_size,
            )

        # Extract events from response - adjust based on actual API response structure
        events = response.get("data", response.get("items", response.get("results", [])))

        if not events:
            demisto.debug(f"No more {log_type.type_string} to fetch.")
            break

        all_events.extend(events)
        demisto.debug(f"Fetched {len(events)} {log_type.type_string}, total: {len(all_events)}")

        # Check if we've reached the end
        if len(events) < page_size:
            break

        page += 1

        # Safety check to prevent infinite loops
        if page > 100:
            demisto.debug(f"Reached maximum page limit for {log_type.type_string}")
            break

    # Limit to max_fetch
    all_events = all_events[:max_fetch]

    # Deduplicate events
    unique_events, new_ids, last_timestamp = deduplicate_events(
        events=all_events,
        previous_run_ids=previous_run_ids,
        previous_timestamp=last_fetch_time,
        log_type=log_type,
    )

    # Enrich events
    enriched_events = enrich_events(unique_events, log_type)

    # Update last run
    if last_timestamp:
        last_run[last_fetch_key] = last_timestamp
        last_run[previous_ids_key] = list(new_ids)
    elif not last_run.get(last_fetch_key):
        # If no events and no previous fetch time, set current time
        last_run[last_fetch_key] = datetime.now(timezone.utc).strftime(API_DATE_FORMAT)

    return enriched_events, last_run


""" COMMAND FUNCTIONS """


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication.

    Args:
        client: The Halcyon client.

    Returns:
        'ok' if test passed, otherwise raises an exception.
    """
    try:
        # Try to fetch a small number of alerts to verify API access
        # Note: Halcyon API only accepts pageSize values of 10, 30, 50, or 100
        client.get_alerts(page=1, page_size=10)
        return "ok"
    except Exception as e:
        diagnosis = client.diagnose_error(e)
        raise DemistoException(f"Test failed: {e}. Diagnosis: {diagnosis}")


def get_alerts_command(
    client: Client,
    args: dict,
) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch alerts for debugging/development.

    This command is used for developing/debugging and is to be used with caution,
    as it can create events, leading to events duplication and API request limitation exceeding.

    Args:
        client: The Halcyon client.
        args: Command arguments.

    Returns:
        A tuple of (alerts, CommandResults).
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    # Parse time arguments using dateparser for flexibility
    if start_time:
        parsed_start = dateparser.parse(start_time)
        if parsed_start:
            start_time = parsed_start.strftime(API_DATE_FORMAT)

    if end_time:
        parsed_end = dateparser.parse(end_time)
        if parsed_end:
            end_time = parsed_end.strftime(API_DATE_FORMAT)

    log_type = LogType.ALERTS
    demisto.debug(f"Fetching {log_type.type_string} for get-alerts command")

    page = 1
    page_size = min(DEFAULT_PAGE_SIZE, limit)
    all_alerts: list[dict] = []

    while len(all_alerts) < limit:
        response = client.get_alerts(
            last_seen_after=start_time,
            last_seen_before=end_time,
            page=page,
            page_size=page_size,
        )

        alerts = response.get("data", response.get("items", response.get("results", [])))

        if not alerts:
            break

        all_alerts.extend(alerts)

        if len(alerts) < page_size:
            break

        page += 1

    # Limit and enrich
    all_alerts = all_alerts[:limit]
    enriched_alerts = enrich_events(all_alerts, log_type)

    # Push events to XSIAM if requested
    if should_push_events and enriched_alerts:
        send_events_to_xsiam(enriched_alerts, vendor=VENDOR, product=PRODUCT)

    # Create human-readable output
    hr = tableToMarkdown(
        name="Halcyon Alerts",
        t=enriched_alerts,
        removeNull=True,
        headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
    )

    return enriched_alerts, CommandResults(readable_output=hr)


def get_events_command(
    client: Client,
    args: dict,
) -> tuple[list[dict], CommandResults]:
    """Manual command to fetch events for debugging/development.

    This command is used for developing/debugging and is to be used with caution,
    as it can create events, leading to events duplication and API request limitation exceeding.

    Args:
        client: The Halcyon client.
        args: Command arguments.

    Returns:
        A tuple of (events, CommandResults).
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    start_time = args.get("start_time")
    end_time = args.get("end_time")
    should_push_events = argToBoolean(args.get("should_push_events", False))

    # Parse time arguments using dateparser for flexibility
    if start_time:
        parsed_start = dateparser.parse(start_time)
        if parsed_start:
            start_time = parsed_start.strftime(API_DATE_FORMAT)

    if end_time:
        parsed_end = dateparser.parse(end_time)
        if parsed_end:
            end_time = parsed_end.strftime(API_DATE_FORMAT)

    log_type = LogType.EVENTS
    demisto.debug(f"Fetching {log_type.type_string} for get-events command")

    page = 1
    page_size = min(DEFAULT_PAGE_SIZE, limit)
    all_events: list[dict] = []

    while len(all_events) < limit:
        response = client.get_events(
            occurred_after=start_time,
            occurred_before=end_time,
            page=page,
            page_size=page_size,
        )

        events = response.get("data", response.get("items", response.get("results", [])))

        if not events:
            break

        all_events.extend(events)

        if len(events) < page_size:
            break

        page += 1

    # Limit and enrich
    all_events = all_events[:limit]
    enriched_events = enrich_events(all_events, log_type)

    # Push events to XSIAM if requested
    if should_push_events and enriched_events:
        send_events_to_xsiam(enriched_events, vendor=VENDOR, product=PRODUCT)

    # Create human-readable output
    hr = tableToMarkdown(
        name="Halcyon Events",
        t=enriched_events,
        removeNull=True,
        headerTransform=lambda x: string_to_table_header(camel_case_to_underscore(x)),
    )

    return enriched_events, CommandResults(readable_output=hr)


def fetch_events_command(
    client: Client,
    last_run: dict,
    log_types: list[LogType],
    max_fetch_alerts: int,
    max_fetch_events: int,
) -> tuple[list[dict], dict]:
    """Fetches events for all specified log types from Halcyon.

    Args:
        client: The Halcyon client.
        last_run: The last run dictionary.
        log_types: List of log types to fetch.
        max_fetch_alerts: Maximum alerts to fetch.
        max_fetch_events: Maximum events to fetch.

    Returns:
        A tuple of (all_events, updated_last_run).
    """
    all_events: list[dict] = []

    for log_type in log_types:
        max_fetch = max_fetch_alerts if log_type == LogType.ALERTS else max_fetch_events

        demisto.debug(f"Fetching {log_type.type_string} with max_fetch={max_fetch}")

        events, last_run = fetch_events_for_log_type(
            client=client,
            log_type=log_type,
            last_run=last_run,
            max_fetch=max_fetch,
        )

        demisto.debug(f"Fetched {len(events)} {log_type.type_string}")
        all_events.extend(events)

    return all_events, last_run


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    """Main function, parses params and runs command functions."""
    command = demisto.command()
    args = demisto.args()
    params = demisto.params()

    # Get parameters
    base_url = params.get("url", "https://api.halcyon.ai").rstrip("/")
    credentials = params.get("credentials", {})
    username = credentials.get("identifier", "")
    password = credentials.get("password", "")
    tenant_id = params.get("tenant_id", "")

    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    max_fetch_alerts = arg_to_number(params.get("max_fetch_alerts")) or DEFAULT_MAX_FETCH
    max_fetch_events = arg_to_number(params.get("max_fetch_events")) or DEFAULT_MAX_FETCH

    event_types_to_fetch = argToList(params.get("event_types_to_fetch", ["Alerts", "Events"]))
    log_types_to_fetch = get_log_types_from_titles(event_types_to_fetch)

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(
            base_url=base_url,
            username=username,
            password=password,
            tenant_id=tenant_id,
            verify=verify_certificate,
            proxy=proxy,
            max_fetch_alerts=max_fetch_alerts,
            max_fetch_events=max_fetch_events,
        )

        if command == "test-module":
            return_results(test_module(client))

        elif command == "halcyon-get-alerts":
            alerts, results = get_alerts_command(
                client=client,
                args=args,
            )
            return_results(results)

        elif command == "halcyon-get-events":
            events, results = get_events_command(
                client=client,
                args=args,
            )
            return_results(results)

        elif command == "fetch-events":
            last_run = demisto.getLastRun()
            demisto.debug(f"Starting fetch with last_run: {last_run}")

            events, next_run = fetch_events_command(
                client=client,
                last_run=last_run,
                log_types=log_types_to_fetch,
                max_fetch_alerts=max_fetch_alerts,
                max_fetch_events=max_fetch_events,
            )

            demisto.debug(f"Fetched {len(events)} total events")

            if events:
                send_events_to_xsiam(events, vendor=VENDOR, product=PRODUCT)

            if next_run:
                demisto.debug(f"Setting new last_run: {next_run}")
                demisto.setLastRun(next_run)

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
