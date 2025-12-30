
from __future__ import annotations

import hashlib
import json
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    Final,
    List,
    Literal,
    MutableMapping,
    NewType,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypedDict,
    Union,
    cast,
)

import anyio
import demistomock as demisto
import httpx
import requests
from pydantic import BaseModel, Field, validator, root_validator
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

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
            from datetime import timezone
            parsed = datetime.strptime(retry_after, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
            return max(0.0, (parsed - datetime.now(timezone.utc)).total_seconds())
        except ValueError:
            return None

# Error Classes
class CollectorError(DemistoException):
    """Base error for all collector failures."""

    def __init__(self, message: str, response: Optional[httpx.Response] = None):
        super().__init__(message)
        self.response = response


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


@dataclass
class ExecutionMetrics:
    """Metrics for collector execution."""
    success: int = 0
    retry_error: int = 0
    quota_error: int = 0
    auth_error: int = 0
    service_error: int = 0
    general_error: int = 0


# Helper Classes
class RetryPolicy(BaseModel):
    """Retry policy for handling transient API failures."""
    class Config:
        extra = 'forbid'

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

    @root_validator(pre=False)
    def validate_delay(cls, values: Dict[str, Any]) -> Dict[str, Any]:  # pylint: disable=no-self-argument
        """Validate that max_delay is greater than initial_delay."""
        max_delay = values.get("max_delay")
        initial_delay = values.get("initial_delay")
        if max_delay is not None and initial_delay is not None and max_delay <= initial_delay:
            raise ValueError(f"max_delay ({max_delay}) must be > initial_delay ({initial_delay})")
        return values

    def next_delay(self, attempt: int, retry_after: Optional[float] = None) -> float:
        if retry_after is not None and self.respect_retry_after:
            return retry_after
        delay = min(self.max_delay, self.initial_delay * (self.multiplier ** (attempt - 1)))
        jitter_value = delay * self.jitter
        return max(0.0, delay + random.uniform(-jitter_value, jitter_value))


class CircuitBreakerPolicy(BaseModel):
    """Circuit breaker policy for preventing cascading failures."""
    class Config:
        extra = 'forbid'

    failure_threshold: int = Field(5, ge=1)
    recovery_timeout: float = Field(60.0, gt=0)


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


class RateLimitPolicy(BaseModel):
    """Rate limiting policy using token bucket algorithm."""
    class Config:
        extra = 'forbid'

    rate_per_second: float = Field(0.0, ge=0)
    burst: int = Field(1, ge=1)
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
        while True:
            async with self._lock:
                await self._refill_locked()
                if self._tokens >= 1:
                    self._tokens -= 1
                    return
                needed = 1 - self._tokens
                wait_seconds = needed / self.policy.rate_per_second
            await anyio.sleep(wait_seconds)

    async def _refill_locked(self) -> None:
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
        extra = 'forbid'

    connect: float = Field(10.0, gt=0)
    read: float = Field(60.0, gt=0)
    write: float = Field(60.0, gt=0)
    pool: float = Field(60.0, gt=0)
    execution: Optional[float] = Field(None, gt=0)
    safety_buffer: float = Field(30.0, gt=0)

    @root_validator(pre=False)
    def validate_execution_safety(cls, values: Dict[str, Any]) -> Dict[str, Any]:  # pylint: disable=no-self-argument
        """Validate that execution timeout is greater than safety buffer."""
        execution = values.get("execution")
        safety_buffer = values.get("safety_buffer")
        if execution is not None and safety_buffer is not None and execution <= safety_buffer:
            raise ValueError(f"execution ({execution}) must be > safety_buffer ({safety_buffer})")
        return values

    def as_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(connect=self.connect, read=self.read, write=self.write, pool=self.pool)

@dataclass
class DeduplicationState:
    """State for event deduplication."""
    latest_timestamp: Optional[Union[str, int, float]] = None
    seen_keys: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "latest_timestamp": self.latest_timestamp,
            "seen_keys": self.seen_keys,
        }

    @classmethod
    def from_dict(cls, raw: Optional[Dict[str, Any]]) -> "DeduplicationState":
        if not raw:
            return cls()
        return cls(
            latest_timestamp=raw.get("latest_timestamp"),
            seen_keys=raw.get("seen_keys", []),
        )


@dataclass
class CollectorState:
    """Pagination and collection state for resuming after timeouts.
    
    Stores pagination position (cursor, page, offset) and metadata to allow seamless
    resumption of collection after timeouts or interruptions.
    
    Args:
        cursor: Current cursor value for cursor-based pagination
        page: Current page number for page-based pagination
        offset: Current offset value for offset-based pagination
        last_event_id: Last processed event ID (for deduplication)
        deduplication: State for event deduplication (timestamp and keys)
        partial_results: Events from incomplete pages (preserved on timeout)
        metadata: Custom metadata dictionary for storing additional state
    """
    cursor: Optional[str] = None
    page: Optional[int] = None
    offset: Optional[int] = None
    last_event_id: Optional[str] = None
    deduplication: Optional[DeduplicationState] = None
    partial_results: List[Any] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cursor": self.cursor,
            "page": self.page,
            "offset": self.offset,
            "last_event_id": self.last_event_id,
            "deduplication": self.deduplication.to_dict() if self.deduplication else None,
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
            deduplication=DeduplicationState.from_dict(raw.get("deduplication")),
            partial_results=raw.get("partial_results", []),
            metadata=raw.get("metadata", {}),
        )


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
    """Authentication handler for API key-based authentication."""
    def __init__(self, key: str, header_name: Optional[str] = None, query_param: Optional[str] = None):
        if not header_name and not query_param:
            raise CollectorConfigurationError("APIKeyAuthHandler requires header_name or query_param")
        self.key = key
        self.header_name = header_name
        self.query_param = query_param
        self.name = "api_key"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        if self.header_name:
            request.headers[self.header_name] = self.key
        if self.query_param:
            request.url = request.url.copy_add_param(self.query_param, self.key)


class BearerTokenAuthHandler(AuthHandler):
    """Authentication handler for Bearer token authentication."""
    def __init__(self, token: str):
        self.token = token
        self.name = "bearer"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {self.token}"


class BasicAuthHandler(AuthHandler):
    """Authentication handler for HTTP Basic Authentication."""
    def __init__(self, username: str, password: str):
        credentials = f"{username}:{password}"
        self._encoded = b64_encode(credentials)
        self.name = "basic"

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Basic {self._encoded}"


class OAuth2ClientCredentialsHandler(AuthHandler):
    """Authentication handler for OAuth2 Client Credentials flow."""
    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: Optional[str] = None,
        audience: Optional[str] = None,
        auth_params: Optional[Dict[str, str]] = None,
        context_store: Optional[Any] = None,
    ):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.audience = audience
        self.auth_params = auth_params or {}
        self.context_store = context_store
        self.name = "oauth2_client_credentials"
        
        self._access_token: Optional[str] = None
        self._expires_at: float = 0
        self._lock = anyio.Lock()

    async def on_request(self, client: "ContentClient", request: httpx.Request) -> None:
        if self._should_refresh():
            async with self._lock:
                if self._should_refresh():
                    await self._refresh_token(client)
        
        if self._access_token:
            request.headers["Authorization"] = f"Bearer {self._access_token}"

    async def on_auth_failure(self, client: "ContentClient", response: httpx.Response) -> bool:
        # If we get 401, force refresh token
        async with self._lock:
            await self._refresh_token(client)
        return True

    def _should_refresh(self) -> bool:
        return not self._access_token or _now() >= self._expires_at - 60  # Refresh 60s before expiry

    async def _refresh_token(self, client: "ContentClient") -> None:
        # Use a separate client for token refresh to avoid recursion/deadlocks
        # and to not share state with the main client
        async with httpx.AsyncClient(verify=client._verify) as token_client:
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
                    raise CollectorAuthenticationError("No access_token in response")
                
                expires_in = token_data.get("expires_in", 3600)
                self._expires_at = _now() + expires_in
                
                # Persist token if context store is available
                if self.context_store:
                    try:
                        current_context = self.context_store.read()
                        current_context["oauth2_token"] = {
                            "access_token": self._access_token,
                            "expires_at": self._expires_at
                        }
                        self.context_store.write(current_context)
                    except Exception as e:
                        # Log but don't fail auth if persistence fails
                        demisto.debug(f"Failed to persist OAuth2 token: {e}")

            except Exception as e:
                raise CollectorAuthenticationError(f"Failed to refresh token: {str(e)}") from e

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

    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        demisto.debug(self._format("WARNING", message, extra))

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
        # Sanitize sensitive headers for security
        safe_headers = headers.copy()
        for sensitive_key in ['Authorization', 'X-API-Key', 'X-Auth-Token', 'API-Key']:
            if sensitive_key in safe_headers:
                safe_headers[sensitive_key] = '***REDACTED***'
        
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
        try:
            extra_str = json.dumps(extra)
        except (TypeError, ValueError):
            extra_str = str(extra)
        return f"[CollectorClient:{self.collector_name}:{level}] {message} | extra={extra_str}"

class ContentClient:
    """Drop-in replacement for BaseClient with enhanced features.
    
    Fully compatible with BaseClient constructor and _http_request() method.
    Existing integrations can switch from BaseClient to ContentClient with zero code changes.
    """
    
    def __init__(
        self,
        base_url: str,
        verify: bool = True,
        proxy: bool = False,
        ok_codes: tuple = tuple(),
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Union[tuple, requests.auth.AuthBase]] = None,
        timeout: float = 60,
        # New optional parameters (backward compatible):
        auth_handler: Optional[AuthHandler] = None,
        retry_policy: Optional[RetryPolicy] = None,
        rate_limiter: Optional[RateLimitPolicy] = None,
        circuit_breaker: Optional[CircuitBreakerPolicy] = None,
        diagnostic_mode: bool = False,
        collector_name: str = "ContentClient",
    ):
        """
        Initialize ContentClient with BaseClient-compatible parameters.
        
        All BaseClient parameters work identically. New parameters are optional
        and provide enhanced functionality when needed.
        """
        # Store BaseClient-compatible parameters
        self._base_url = base_url
        self._verify = verify
        self._ok_codes = ok_codes
        self._headers = headers or {}
        self._auth = auth
        self._session = requests.Session()
        self.timeout = timeout
        
        # Handle proxy exactly like BaseClient
        if proxy:
            ensure_proxy_has_http_prefix()
        else:
            skip_proxy()
        if not verify:
            skip_cert_verification()
        
        # Enhanced features (optional, backward compatible)
        self._auth_handler = auth_handler
        self._retry_policy = retry_policy or RetryPolicy()
        self._rate_limiter = TokenBucketRateLimiter(rate_limiter) if rate_limiter and rate_limiter.enabled else None
        self._circuit_breaker = CircuitBreaker(circuit_breaker or CircuitBreakerPolicy())
        self._diagnostic_mode = diagnostic_mode
        
        # Execution metrics (like BaseClient)
        self.execution_metrics = ExecutionMetrics()
        
        # Logger
        self.logger = CollectorLogger(collector_name, diagnostic_mode=diagnostic_mode)

        # httpx client for async operations
        try:
            self._client = httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                timeout=timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                verify=verify,
                http2=True,
            )
        except ImportError:
            self.logger.info("HTTP/2 dependencies missing, falling back to HTTP/1.1 transport")
            self._client = httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                timeout=timeout,
                headers={"User-Agent": DEFAULT_USER_AGENT},
                verify=verify,
                http2=False,
            )
        self._client_lock = anyio.Lock()

    async def aclose(self) -> None:
        await self._client.aclose()

    def close(self) -> None:
        try:
            anyio.run(self.aclose)
        except Exception as e:
            self.logger.error(f"Error closing client: {e}")

    async def _request(
        self,
        method: str,
        url_suffix: str = '',
        full_url: Optional[str] = None,
        headers: Optional[Dict] = None,
        auth: Optional[tuple] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        files: Optional[Dict] = None,
        timeout: Optional[float] = None,
        resp_type: str = 'json',
        ok_codes: Optional[tuple] = None,
        return_empty_response: bool = False,
        retries: int = 0,
        status_list_to_retry: Optional[List[int]] = None,
        backoff_factor: float = 5,
        backoff_jitter: float = 0.0,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
        error_handler: Optional[Callable] = None,
        empty_valid_codes: Optional[List[int]] = None,
        params_parser: Optional[Callable] = None,
        with_metrics: bool = False,
        **kwargs
    ) -> httpx.Response:
        
        if not self._circuit_breaker.can_execute():
            raise CollectorCircuitOpenError("Circuit breaker is open, refusing to send request")

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
                http_request = self._client.build_request(
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
                elif self._auth:
                    if isinstance(self._auth, tuple):
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

                response = await self._client.send(http_request)
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
                # BaseClient logic: if ok_codes provided, check against it. Else check response.ok
                is_ok = False
                if ok_codes:
                    is_ok = response.status_code in ok_codes
                else:
                    is_ok = response.is_success
                
                if not is_ok:
                    # Raise exception to trigger error handling
                    response.raise_for_status()

                self.execution_metrics.success += 1
                self._circuit_breaker.record_success()
                self.logger.debug(
                    "HTTP request completed",
                    {"status": response.status_code, "elapsed": elapsed_ms, "endpoint": url},
                )
                return response

            except CollectorError:
                # Re-raise CollectorError (including subclasses) without wrapping
                raise
            except tuple(self._retry_policy.retryable_exceptions) as exc:
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
                self.logger.debug(
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
                    self.logger.error("Rate limit error", {"status": 429, "error_type": "rate_limit"})
                    should_retry = exc.response.status_code in (status_list_to_retry or self._retry_policy.retryable_status_codes)
                    if should_retry and attempt < max_attempts:
                        retry_after = _parse_retry_after(exc.response)
                        delay = self._retry_policy.next_delay(attempt, retry_after)
                        self.execution_metrics.retry_error += 1
                        await anyio.sleep(delay)
                        continue
                    self._circuit_breaker.record_failure()
                    raise CollectorRateLimitError(f"Rate limit exceeded: {exc.response.text}", response=exc.response) from exc
                elif exc.response.status_code in (401, 403):
                    self.execution_metrics.auth_error += 1
                    self.logger.error("Authentication error", {"status": exc.response.status_code, "error_type": "auth"})
                    should_retry = exc.response.status_code in (status_list_to_retry or self._retry_policy.retryable_status_codes)
                    if should_retry and attempt < max_attempts:
                        retry_after = _parse_retry_after(exc.response)
                        delay = self._retry_policy.next_delay(attempt, retry_after)
                        self.execution_metrics.retry_error += 1
                        await anyio.sleep(delay)
                        continue
                    self._circuit_breaker.record_failure()
                    raise CollectorAuthenticationError(
                        f"Authentication failed: {exc.response.text}", response=exc.response
                    ) from exc
                else:
                    self.execution_metrics.service_error += 1
                    self.logger.error("Service error", {"status": exc.response.status_code, "error_type": "service"})
                    should_retry = exc.response.status_code in (status_list_to_retry or self._retry_policy.retryable_status_codes)
                    if should_retry and attempt < max_attempts:
                        retry_after = _parse_retry_after(exc.response)
                        delay = self._retry_policy.next_delay(attempt, retry_after)
                        self.execution_metrics.retry_error += 1
                        await anyio.sleep(delay)
                        continue
                    self._circuit_breaker.record_failure()
                    raise CollectorError(f"Request failed: {exc.response.text}", response=exc.response) from exc
            except Exception as exc:
                elapsed_ms = (_now() - start) * 1000
                if self._diagnostic_mode and trace:
                    self.logger.trace_error(trace, str(exc), elapsed_ms)
                
                self.execution_metrics.general_error += 1
                self._circuit_breaker.record_failure()
                self.logger.error("Non-retryable exception occurred", {"error": str(exc), "error_type": type(exc).__name__})
                raise
        
        self._circuit_breaker.record_failure()
        last_response = getattr(last_error, "response", None)
        raise CollectorRetryError(f"Exceeded retry attempts: {last_error}", response=last_response)

    def _http_request(
        self,
        method: str,
        url_suffix: str = '',
        full_url: Optional[str] = None,
        headers: Optional[Dict] = None,
        auth: Optional[tuple] = None,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[Any] = None,
        files: Optional[Dict] = None,
        timeout: Optional[float] = None,
        resp_type: str = 'json',
        ok_codes: Optional[tuple] = None,
        return_empty_response: bool = False,
        retries: int = 0,
        status_list_to_retry: Optional[List[int]] = None,
        backoff_factor: float = 5,
        backoff_jitter: float = 0.0,
        raise_on_redirect: bool = False,
        raise_on_status: bool = False,
        error_handler: Optional[Callable] = None,
        empty_valid_codes: Optional[List[int]] = None,
        params_parser: Optional[Callable] = None,
        with_metrics: bool = False,
        **kwargs
    ) -> Any:
        """
        Synchronous wrapper for _request to maintain BaseClient compatibility.
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
            **kwargs
        )

    def request_sync(self, *args, **kwargs) -> Any:
        """
        Execute a request synchronously using anyio.run.
        """
        async def _do_request():
            response = await self._request(*args, **kwargs)
            
            # Handle response processing (json, text, content) similar to BaseClient
            resp_type = kwargs.get('resp_type', 'json')
            return_empty_response = kwargs.get('return_empty_response', False)
            empty_valid_codes = kwargs.get('empty_valid_codes')
            
            if return_empty_response and empty_valid_codes and response.status_code in empty_valid_codes:
                return {}
                
            if resp_type == 'json':
                try:
                    return response.json()
                except json.JSONDecodeError:
                    if not response.content:
                        return {}
                    raise
            elif resp_type == 'text':
                return response.text
            elif resp_type == 'content':
                return response.content
            elif resp_type == 'response':
                return response
            elif resp_type == 'xml':
                return response.text
            
            return response.json()

        return anyio.run(_do_request)

    # Standard HTTP verb helpers
    def get(self, url_suffix: str, params: Optional[Dict] = None, **kwargs):
        if 'resp_type' not in kwargs:
            kwargs['resp_type'] = 'response'
        return self._http_request('GET', url_suffix, params=params, **kwargs)

    def post(self, url_suffix: str, json_data: Optional[Dict] = None, **kwargs):
        if 'resp_type' not in kwargs:
            kwargs['resp_type'] = 'response'
        return self._http_request('POST', url_suffix, json_data=json_data, **kwargs)

    def put(self, url_suffix: str, json_data: Optional[Dict] = None, **kwargs):
        if 'resp_type' not in kwargs:
            kwargs['resp_type'] = 'response'
        return self._http_request('PUT', url_suffix, json_data=json_data, **kwargs)

    def patch(self, url_suffix: str, json_data: Optional[Dict] = None, **kwargs):
        if 'resp_type' not in kwargs:
            kwargs['resp_type'] = 'response'
        return self._http_request('PATCH', url_suffix, json_data=json_data, **kwargs)

    def delete(self, url_suffix: str, **kwargs):
        if 'resp_type' not in kwargs:
            kwargs['resp_type'] = 'response'
        return self._http_request('DELETE', url_suffix, **kwargs)

    @property
    def metrics(self) -> ExecutionMetrics:
        return self.execution_metrics

    def get_diagnostic_report(self) -> DiagnosticReport:
        return self.logger.get_diagnostic_report(
            configuration={
                "name": self.logger.collector_name,
                "base_url": self._base_url,
                "timeout": self.timeout
            }
        )

    def diagnose_error(self, error: Exception) -> Dict[str, str]:
        if isinstance(error, CollectorAuthenticationError):
            return {"issue": "Authentication failed", "solution": "Check credentials and token expiration."}
        if isinstance(error, CollectorRateLimitError):
            return {"issue": "Rate limit exceeded", "solution": "Increase retry delay or request quota."}
        if isinstance(error, CollectorTimeoutError):
            return {"issue": "Execution timeout", "solution": "Increase timeout settings or reduce batch size."}
        if isinstance(error, CollectorCircuitOpenError):
            return {"issue": "Circuit breaker is open", "solution": "Wait for recovery timeout."}
        if isinstance(error, CollectorRetryError):
            return {"issue": "All retry attempts exhausted", "solution": "Check API availability and retry policy."}
        if isinstance(error, CollectorConfigurationError):
            return {"issue": "Configuration error", "solution": "Check integration parameters."}
        return {"issue": "Unexpected error", "solution": f"Check logs for details: {str(error)}"}

    def health_check(self) -> Dict[str, Any]:
        status = "healthy"
        warnings = []
        
        if self.execution_metrics.auth_error > 0:
            status = "degraded"
            warnings.append("Authentication errors detected")
        if self.execution_metrics.general_error > 0:
            status = "degraded"
            warnings.append("General errors detected")
        if self.execution_metrics.quota_error > 0:
            status = "degraded"
            warnings.append("Rate limit errors detected")
            
        return {
            "status": status,
            "configuration_valid": True,
            "warnings": warnings,
            "metrics": self.execution_metrics
        }