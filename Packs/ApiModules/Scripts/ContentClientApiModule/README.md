# ContentClient API Module

`ContentClient` is a drop-in replacement for `BaseClient` that provides enhanced reliability, observability, and developer experience features. It is designed to be fully backward compatible while offering powerful new capabilities for robust API integrations.

## Table of Contents

- [Key Features](#key-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Migration from BaseClient](#migration-from-baseclient)
- [Authentication Handlers](#authentication-handlers)
- [Resilience Policies](#resilience-policies)
- [Timeout Configuration](#timeout-configuration)
- [Error Handling](#error-handling)
- [Metrics & Diagnostics](#metrics--diagnostics)
- [State Management](#state-management)
- [Complete Integration Example](#-complete-integration-example)
- [API Reference](#api-reference)

---

## Key Features

| Feature | Description |
|---------|-------------|
| **Drop-in Replacement** | Fully compatible with `BaseClient` constructor and `_http_request` method |
| **Advanced Authentication** | Built-in handlers for API Key, Bearer Token, Basic Auth, and OAuth2 (with auto-refresh) |
| **Retry Policy** | Configurable exponential backoff with jitter for transient failures |
| **Rate Limiting** | Token bucket algorithm to respect API rate limits |
| **Circuit Breaker** | Prevents cascading failures by temporarily blocking requests |
| **Observability** | Detailed execution metrics, structured logging, and diagnostic reports |
| **Async Core** | Built on `httpx` and `anyio` for high-performance async I/O |

---

## Installation

Import the module in your integration:

```python
from ContentClientApiModule import *
```

---

## Quick Start

### Minimal Example

```python
from ContentClientApiModule import ContentClient

# Create a client with minimal configuration
client = ContentClient(
    base_url="https://api.example.com",
    verify=True,
    proxy=False
)

# Make a simple GET request
response = client._http_request(
    method="GET",
    url_suffix="/users",
    params={"limit": 10}
)

# Response is automatically parsed as JSON
for user in response:
    print(f"User: {user['name']}")
```

### Using HTTP Verb Helpers

```python
# GET request
response = client.get("/users", params={"status": "active"})

# POST request with JSON body
new_user = client.post("/users", json_data={"name": "John", "email": "john@example.com"})

# PUT request
updated = client.put("/users/123", json_data={"name": "John Doe"})

# PATCH request
patched = client.patch("/users/123", json_data={"status": "inactive"})

# DELETE request
client.delete("/users/123")
```

---

## Migration from BaseClient

Migrating from `BaseClient` to `ContentClient` requires **zero code changes** for basic usage. Simply replace the import and class name:

### Before (BaseClient)

```python
from CommonServerPython import BaseClient

class MyClient(BaseClient):
    def __init__(self, base_url, api_key, verify=True, proxy=False):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_key}"}
        )
    
    def get_incidents(self, limit=50):
        return self._http_request(
            method="GET",
            url_suffix="/incidents",
            params={"limit": limit}
        )
```

### After (ContentClient - Zero Changes)

```python
from ContentClientApiModule import ContentClient

class MyClient(ContentClient):
    def __init__(self, base_url, api_key, verify=True, proxy=False):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Authorization": f"Bearer {api_key}"}  # Works exactly like BaseClient
        )
    
    def get_incidents(self, limit=50):
        # Same method signature - no changes needed!
        return self._http_request(
            method="GET",
            url_suffix="/incidents",
            params={"limit": limit}
        )
```

### After (ContentClient - With Enhanced Auth)

Once migrated, you can optionally adopt enhanced features like built-in auth handlers:

```python
from ContentClientApiModule import ContentClient, BearerTokenAuthHandler

class MyClient(ContentClient):
    def __init__(self, base_url, api_key, verify=True, proxy=False):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            # Optional enhancement: Use built-in auth handler
            auth_handler=BearerTokenAuthHandler(token=api_key)
        )
    
    def get_incidents(self, limit=50):
        # Same method signature - no changes needed!
        return self._http_request(
            method="GET",
            url_suffix="/incidents",
            params={"limit": limit}
        )
```

### Gradual Enhancement

You can adopt enhanced features incrementally:

```python
# Step 1: Just replace the class (zero changes)
class MyClient(ContentClient):
    pass

# Step 2: Add retry policy for reliability
class MyClient(ContentClient):
    def __init__(self, base_url, **kwargs):
        super().__init__(
            base_url=base_url,
            retry_policy=RetryPolicy(max_attempts=3),
            **kwargs
        )

# Step 3: Add rate limiting to respect API limits
class MyClient(ContentClient):
    def __init__(self, base_url, **kwargs):
        super().__init__(
            base_url=base_url,
            retry_policy=RetryPolicy(max_attempts=3),
            rate_limiter=RateLimitPolicy(rate_per_second=10),
            **kwargs
        )

# Step 4: Enable diagnostics for troubleshooting
class MyClient(ContentClient):
    def __init__(self, base_url, **kwargs):
        super().__init__(
            base_url=base_url,
            retry_policy=RetryPolicy(max_attempts=3),
            rate_limiter=RateLimitPolicy(rate_per_second=10),
            diagnostic_mode=True,
            client_name="MyIntegration",
            **kwargs
        )
```

---

## Authentication Handlers

### API Key Authentication

Add an API key to request headers or query parameters:

```python
from ContentClientApiModule import ContentClient, APIKeyAuthHandler

# API key in header
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=APIKeyAuthHandler(
        key="your-api-key-here",
        header_name="X-API-Key"
    )
)

# API key in query parameter
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=APIKeyAuthHandler(
        key="your-api-key-here",
        query_param="api_key"
    )
)

# Both header and query parameter
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=APIKeyAuthHandler(
        key="your-api-key-here",
        header_name="X-API-Key",
        query_param="api_key"
    )
)
```

### Bearer Token Authentication

Add a Bearer token to the Authorization header:

```python
from ContentClientApiModule import ContentClient, BearerTokenAuthHandler

client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=BearerTokenAuthHandler(token="your-bearer-token")
)

# All requests will include: Authorization: Bearer your-bearer-token
response = client.get("/protected-resource")
```

### Basic Authentication

Use HTTP Basic Authentication:

```python
from ContentClientApiModule import ContentClient, BasicAuthHandler

client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=BasicAuthHandler(
        username="your-username",
        password="your-password"
    )
)

# All requests will include: Authorization: Basic <base64-encoded-credentials>
response = client.get("/protected-resource")
```

### OAuth2 Client Credentials

Automatically handle OAuth2 token acquisition and refresh:

```python
from ContentClientApiModule import (
    ContentClient,
    OAuth2ClientCredentialsHandler,
    ContentClientContextStore
)

# Basic OAuth2 setup
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/oauth/token",
        client_id="your-client-id",
        client_secret="your-client-secret"
    )
)

# With scope and audience
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/oauth/token",
        client_id="your-client-id",
        client_secret="your-client-secret",
        scope="read:data write:data",
        audience="https://api.example.com"
    )
)

# With token persistence (survives across execution runs)
context_store = ContentClientContextStore(namespace="MyIntegration")
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/oauth/token",
        client_id="your-client-id",
        client_secret="your-client-secret",
        context_store=context_store  # Tokens are persisted and reused
    )
)

# With additional auth parameters
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/oauth/token",
        client_id="your-client-id",
        client_secret="your-client-secret",
        auth_params={
            "resource": "https://api.example.com",
            "grant_type": "client_credentials"
        }
    )
)
```

### Custom Authentication Handler

Create your own authentication handler for custom auth schemes:

```python
from ContentClientApiModule import ContentClient, AuthHandler
import httpx

class CustomAuthHandler(AuthHandler):
    """Custom authentication using HMAC signature."""
    
    def __init__(self, api_key: str, secret_key: str):
        self.api_key = api_key
        self.secret_key = secret_key
        self.name = "custom_hmac"
    
    async def on_request(self, client: ContentClient, request: httpx.Request) -> None:
        import hmac
        import hashlib
        import time
        
        timestamp = str(int(time.time()))
        message = f"{request.method}{request.url.path}{timestamp}"
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        request.headers["X-API-Key"] = self.api_key
        request.headers["X-Timestamp"] = timestamp
        request.headers["X-Signature"] = signature
    
    async def on_auth_failure(self, client: ContentClient, response: httpx.Response) -> bool:
        # Return True to retry the request after handling the failure
        # Return False to propagate the error
        return False

# Use the custom handler
client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=CustomAuthHandler(
        api_key="your-api-key",
        secret_key="your-secret-key"
    )
)
```

---

## Resilience Policies

### Retry Policy

Configure automatic retries with exponential backoff:

```python
from ContentClientApiModule import ContentClient, RetryPolicy

# Default retry policy
client = ContentClient(
    base_url="https://api.example.com",
    retry_policy=RetryPolicy()  # Uses sensible defaults
)

# Custom retry policy
client = ContentClient(
    base_url="https://api.example.com",
    retry_policy=RetryPolicy(
        max_attempts=5,           # Maximum retry attempts (default: 5)
        initial_delay=1.0,        # Initial delay in seconds (default: 1.0)
        multiplier=2.0,           # Delay multiplier for exponential backoff (default: 2.0)
        max_delay=60.0,           # Maximum delay between retries (default: 60.0)
        jitter=0.2,               # Random jitter factor 0-1 (default: 0.2)
        respect_retry_after=True  # Honor Retry-After header (default: True)
    )
)

# Aggressive retry for critical operations
aggressive_retry = RetryPolicy(
    max_attempts=10,
    initial_delay=0.5,
    multiplier=1.5,
    max_delay=30.0,
    jitter=0.3
)

# Conservative retry for rate-limited APIs
conservative_retry = RetryPolicy(
    max_attempts=3,
    initial_delay=5.0,
    multiplier=3.0,
    max_delay=120.0,
    jitter=0.1,
    respect_retry_after=True
)
```

#### Retryable Status Codes

By default, the following HTTP status codes trigger a retry:

| Code | Description |
|------|-------------|
| 408 | Request Timeout |
| 413 | Payload Too Large |
| 425 | Too Early |
| 429 | Too Many Requests |
| 500 | Internal Server Error |
| 502 | Bad Gateway |
| 503 | Service Unavailable |
| 504 | Gateway Timeout |

#### Retryable Exceptions

The following network exceptions trigger a retry:

- `httpx.ConnectError` - Connection failed
- `httpx.ReadTimeout` - Read operation timed out
- `httpx.WriteTimeout` - Write operation timed out
- `httpx.RemoteProtocolError` - Protocol error from server
- `httpx.PoolTimeout` - Connection pool exhausted

### Rate Limiting

Prevent hitting API rate limits using the token bucket algorithm:

```python
from ContentClientApiModule import ContentClient, RateLimitPolicy

# Basic rate limiting: 10 requests per second
client = ContentClient(
    base_url="https://api.example.com",
    rate_limiter=RateLimitPolicy(
        rate_per_second=10.0,      # Sustained rate (default: 0 = disabled)
        burst=20,                   # Burst capacity (default: 1)
        respect_retry_after=True    # Honor Retry-After header (default: True)
    )
)

# Conservative rate limiting for strict APIs
client = ContentClient(
    base_url="https://api.example.com",
    rate_limiter=RateLimitPolicy(
        rate_per_second=1.0,  # 1 request per second
        burst=1               # No bursting allowed
    )
)

# High-throughput rate limiting
client = ContentClient(
    base_url="https://api.example.com",
    rate_limiter=RateLimitPolicy(
        rate_per_second=100.0,  # 100 requests per second
        burst=200               # Allow bursts up to 200 requests
    )
)
```

#### How Token Bucket Works

1. The bucket starts with `burst` tokens
2. Tokens are added at `rate_per_second` rate
3. Each request consumes 1 token
4. If no tokens available, the request waits until a token is available
5. Maximum tokens in bucket is capped at `burst`

### Circuit Breaker

Prevent cascading failures by temporarily blocking requests after repeated failures:

```python
from ContentClientApiModule import ContentClient, CircuitBreakerPolicy

client = ContentClient(
    base_url="https://api.example.com",
    circuit_breaker=CircuitBreakerPolicy(
        failure_threshold=5,     # Open circuit after 5 failures (default: 5)
        recovery_timeout=60.0    # Try again after 60 seconds (default: 60.0)
    )
)

# Sensitive circuit breaker for critical services
client = ContentClient(
    base_url="https://api.example.com",
    circuit_breaker=CircuitBreakerPolicy(
        failure_threshold=3,     # Open after just 3 failures
        recovery_timeout=120.0   # Wait 2 minutes before retrying
    )
)

# Tolerant circuit breaker for less critical services
client = ContentClient(
    base_url="https://api.example.com",
    circuit_breaker=CircuitBreakerPolicy(
        failure_threshold=10,    # Allow more failures
        recovery_timeout=30.0    # Recover faster
    )
)
```

#### Circuit Breaker States

| State | Description |
|-------|-------------|
| **Closed** | Normal operation, requests are allowed |
| **Open** | Requests are blocked, raises `ContentClientCircuitOpenError` |
| **Half-Open** | After recovery timeout, one request is allowed to test the service |

### Combining Policies

Use all resilience policies together for maximum reliability:

```python
from ContentClientApiModule import (
    ContentClient,
    BearerTokenAuthHandler,
    RetryPolicy,
    RateLimitPolicy,
    CircuitBreakerPolicy
)

client = ContentClient(
    base_url="https://api.example.com",
    auth_handler=BearerTokenAuthHandler(token="your-token"),
    
    # Retry transient failures
    retry_policy=RetryPolicy(
        max_attempts=5,
        initial_delay=1.0,
        multiplier=2.0
    ),
    
    # Respect API rate limits
    rate_limiter=RateLimitPolicy(
        rate_per_second=10.0,
        burst=20
    ),
    
    # Prevent cascading failures
    circuit_breaker=CircuitBreakerPolicy(
        failure_threshold=5,
        recovery_timeout=60.0
    ),
    
    # Enable diagnostics
    diagnostic_mode=True,
    client_name="MyIntegration"
)
```

---

## Timeout Configuration

Configure request timeout settings:

```python
from ContentClientApiModule import ContentClient

# Simple timeout (recommended)
client = ContentClient(
    base_url="https://api.example.com",
    timeout=60  # Timeout in seconds for all operations
)

# Quick timeout for fast APIs
client = ContentClient(
    base_url="https://api.example.com",
    timeout=10  # 10 second timeout
)

# Long timeout for slow APIs
client = ContentClient(
    base_url="https://api.example.com",
    timeout=300  # 5 minute timeout
)
```

### TimeoutSettings (Advanced)

For advanced use cases, the `TimeoutSettings` class provides granular control over different timeout phases. This is primarily used internally but can be useful for understanding timeout behavior:

```python
from ContentClientApiModule import TimeoutSettings

# TimeoutSettings structure (for reference)
timeout_config = TimeoutSettings(
    connect=10.0,        # Connection timeout in seconds (default: 10.0)
    read=60.0,           # Read timeout in seconds (default: 60.0)
    write=60.0,          # Write timeout in seconds (default: 60.0)
    pool=60.0,           # Connection pool timeout (default: 60.0)
    execution=300.0,     # Total execution timeout (default: None)
    safety_buffer=30.0   # Buffer before execution timeout (default: 30.0)
)
```

> **Note:** The `timeout` parameter in `ContentClient` constructor accepts a `float` value representing seconds. The `TimeoutSettings` class is used internally for advanced timeout management.

---

## Error Handling

### Exception Hierarchy

```
ContentClientError (base)
├── ContentClientAuthenticationError    # 401, 403 responses
├── ContentClientRateLimitError         # 429 responses
├── ContentClientTimeoutError           # Execution timeout exceeded
├── ContentClientCircuitOpenError       # Circuit breaker is open
├── ContentClientRetryError             # All retry attempts exhausted
└── ContentClientConfigurationError     # Invalid configuration
```

### Handling Errors

```python
from ContentClientApiModule import (
    ContentClient,
    ContentClientError,
    ContentClientAuthenticationError,
    ContentClientRateLimitError,
    ContentClientTimeoutError,
    ContentClientCircuitOpenError,
    ContentClientRetryError,
    ContentClientConfigurationError
)

client = ContentClient(base_url="https://api.example.com")

try:
    response = client.get("/resource")
except ContentClientAuthenticationError as e:
    # Handle authentication failures (401, 403)
    demisto.error(f"Authentication failed: {e}")
    # Check credentials, refresh tokens, etc.
    
except ContentClientRateLimitError as e:
    # Handle rate limiting (429)
    demisto.error(f"Rate limit exceeded: {e}")
    # Wait and retry, or reduce request frequency
    
except ContentClientTimeoutError as e:
    # Handle execution timeout
    demisto.error(f"Operation timed out: {e}")
    # Consider increasing timeout or reducing batch size
    
except ContentClientCircuitOpenError as e:
    # Handle circuit breaker open
    demisto.error(f"Service unavailable (circuit open): {e}")
    # Wait for recovery or use fallback
    
except ContentClientRetryError as e:
    # Handle exhausted retries
    demisto.error(f"All retries exhausted: {e}")
    # Check service health, escalate if needed
    
except ContentClientConfigurationError as e:
    # Handle configuration errors
    demisto.error(f"Configuration error: {e}")
    # Fix integration parameters
    
except ContentClientError as e:
    # Handle any other client errors
    demisto.error(f"Client error: {e}")
```

### Error Diagnosis

Use the built-in error diagnosis helper:

```python
try:
    response = client.get("/resource")
except ContentClientError as e:
    diagnosis = client.diagnose_error(e)
    demisto.error(f"Issue: {diagnosis['issue']}")
    demisto.error(f"Solution: {diagnosis['solution']}")
```

### Accessing Response Details

Error objects include the original response when available:

```python
try:
    response = client.get("/resource")
except ContentClientError as e:
    if e.response:
        demisto.error(f"Status: {e.response.status_code}")
        demisto.error(f"Headers: {e.response.headers}")
        demisto.error(f"Body: {e.response.text}")
```

---

## Metrics & Diagnostics

### Execution Metrics

Track request statistics automatically:

```python
from ContentClientApiModule import ContentClient

client = ContentClient(
    base_url="https://api.example.com",
    client_name="MyIntegration"
)

# Make some requests...
client.get("/users")
client.get("/orders")

# Access metrics
metrics = client.metrics
print(f"Successful requests: {metrics.success}")
print(f"Retry errors: {metrics.retry_error}")
print(f"Rate limit errors: {metrics.quota_error}")
print(f"Auth errors: {metrics.auth_error}")
print(f"Service errors: {metrics.service_error}")
print(f"General errors: {metrics.general_error}")
```

### Diagnostic Mode

Enable detailed request tracing for troubleshooting:

```python
from ContentClientApiModule import ContentClient

client = ContentClient(
    base_url="https://api.example.com",
    diagnostic_mode=True,  # Enable detailed tracing
    client_name="MyIntegration"
)

# Make requests...
try:
    client.get("/resource")
except Exception as e:
    pass

# Get comprehensive diagnostic report
report = client.get_diagnostic_report()

# Report includes:
# - collector_name: Client identifier
# - configuration: Client settings
# - request_traces: Detailed request/response logs
# - state_snapshots: State changes over time
# - performance_metrics: Timing statistics
# - errors: Error history
# - recommendations: Suggested fixes
# - timestamp: Report generation time

demisto.debug(f"Avg request time: {report.performance_metrics.get('avg_request_time_ms')}ms")
demisto.debug(f"Total requests: {report.performance_metrics.get('total_requests')}")

for recommendation in report.recommendations:
    demisto.debug(f"Recommendation: {recommendation}")
```

### Health Check

Perform a health check on the client:

```python
health = client.health_check()

print(f"Status: {health['status']}")  # 'healthy' or 'degraded'
print(f"Configuration valid: {health['configuration_valid']}")
print(f"Warnings: {health['warnings']}")
print(f"Metrics: {health['metrics']}")

# Example output:
# Status: degraded
# Configuration valid: True
# Warnings: ['Rate limit errors detected', 'Authentication errors detected']
# Metrics: ClientExecutionMetrics(success=45, retry_error=3, quota_error=2, ...)
```

### Structured Logging

The client provides structured logging with context:

```python
# Logs are automatically formatted with context
# [ContentClient:MyIntegration:DEBUG] HTTP request completed | extra={"status": 200, "elapsed": 150.5}
# [ContentClient:MyIntegration:ERROR] Authentication error | extra={"status": 401, "error_type": "auth"}
```

---

## State Management

### ContentClientState

Manage pagination and collection state for resumable operations:

```python
from ContentClientApiModule import ContentClientState

# Create state for cursor-based pagination
state = ContentClientState(
    cursor="next_page_token_123",
    last_event_id="event_456"
)

# Create state for page-based pagination
state = ContentClientState(
    page=5,
    offset=100
)

# Store partial results (for timeout recovery)
state.partial_results = [{"id": 1}, {"id": 2}]

# Custom metadata
state.metadata = {
    "last_sync": "2024-01-15T10:30:00Z",
    "total_collected": 1500
}

# Serialize for storage
state_dict = state.to_dict()

# Restore from storage
restored_state = ContentClientState.from_dict(state_dict)
```

### ContentClientContextStore

Persist state to Demisto integration context:

```python
from ContentClientApiModule import ContentClientContextStore, ContentClientState

# Create a context store
store = ContentClientContextStore(namespace="MyIntegration")

# Read current context
context = store.read()

# Write state to context
state = ContentClientState(cursor="token_123")
context["pagination_state"] = state.to_dict()
store.write(context)

# Later, restore state
context = store.read()
state = ContentClientState.from_dict(context.get("pagination_state"))
```

### Resumable Collection Example

```python
from ContentClientApiModule import (
    ContentClient,
    ContentClientState,
    ContentClientContextStore,
    ContentClientTimeoutError
)

def collect_events(client: ContentClient, max_events: int = 1000):
    """Collect events with resumable state."""
    
    store = ContentClientContextStore(namespace="EventCollector")
    context = store.read()
    
    # Restore state from previous run
    state = ContentClientState.from_dict(context.get("collection_state"))
    
    events = state.partial_results.copy()
    
    try:
        while len(events) < max_events:
            # Build request with current state
            params = {"limit": 100}
            if state.cursor:
                params["cursor"] = state.cursor
            
            response = client.get("/events", params=params)
            data = response.json()
            
            # Process events
            new_events = data.get("events", [])
            events.extend(new_events)
            
            # Update state
            state.cursor = data.get("next_cursor")
            state.last_event_id = new_events[-1]["id"] if new_events else state.last_event_id
            
            # No more pages
            if not state.cursor:
                break
                
    except ContentClientTimeoutError:
        # Save partial results for next run
        state.partial_results = events
        context["collection_state"] = state.to_dict()
        store.write(context)
        raise
    
    # Clear state on successful completion
    context["collection_state"] = None
    store.write(context)
    
    return events
```

---

## 🔧 Complete Integration Example

Here's a complete example of a production-ready integration:

```python
from ContentClientApiModule import (
    ContentClient,
    OAuth2ClientCredentialsHandler,
    ContentClientContextStore,
    RetryPolicy,
    RateLimitPolicy,
    CircuitBreakerPolicy,
    TimeoutSettings,
    ContentClientError,
    ContentClientAuthenticationError,
    ContentClientRateLimitError
)
import demistomock as demisto
from CommonServerPython import *


class SecurityVendorClient(ContentClient):
    """Client for Security Vendor API."""
    
    def __init__(self, base_url: str, client_id: str, client_secret: str, verify: bool = True, proxy: bool = False):
        # Create context store for token persistence
        context_store = ContentClientContextStore(namespace="SecurityVendor")
        
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            
            # OAuth2 authentication with token persistence
            auth_handler=OAuth2ClientCredentialsHandler(
                token_url=f"{base_url}/oauth/token",
                client_id=client_id,
                client_secret=client_secret,
                scope="read:alerts write:alerts",
                context_store=context_store
            ),
            
            # Retry policy for transient failures
            retry_policy=RetryPolicy(
                max_attempts=5,
                initial_delay=1.0,
                multiplier=2.0,
                max_delay=60.0
            ),
            
            # Rate limiting to respect API limits
            rate_limiter=RateLimitPolicy(
                rate_per_second=10.0,
                burst=20
            ),
            
            # Circuit breaker for fault tolerance
            circuit_breaker=CircuitBreakerPolicy(
                failure_threshold=5,
                recovery_timeout=60.0
            ),
            
            # Enable diagnostics
            diagnostic_mode=True,
            client_name="SecurityVendor"
        )
    
    def get_alerts(self, severity: str = None, limit: int = 50) -> List[Dict]:
        """Fetch security alerts."""
        params = {"limit": limit}
        if severity:
            params["severity"] = severity
        
        response = self._http_request(
            method="GET",
            url_suffix="/api/v1/alerts",
            params=params
        )
        return response.get("alerts", [])
    
    def get_alert_details(self, alert_id: str) -> Dict:
        """Get detailed information about an alert."""
        return self._http_request(
            method="GET",
            url_suffix=f"/api/v1/alerts/{alert_id}"
        )
    
    def update_alert_status(self, alert_id: str, status: str, comment: str = None) -> Dict:
        """Update alert status."""
        data = {"status": status}
        if comment:
            data["comment"] = comment
        
        return self._http_request(
            method="PATCH",
            url_suffix=f"/api/v1/alerts/{alert_id}",
            json_data=data
        )
    
    def search_alerts(self, query: str, start_time: str, end_time: str) -> List[Dict]:
        """Search alerts with a query."""
        return self._http_request(
            method="POST",
            url_suffix="/api/v1/alerts/search",
            json_data={
                "query": query,
                "start_time": start_time,
                "end_time": end_time
            }
        ).get("results", [])


def test_module(client: SecurityVendorClient) -> str:
    """Test the integration connection."""
    try:
        client.get_alerts(limit=1)
        return "ok"
    except ContentClientAuthenticationError:
        return "Authentication failed. Check your credentials."
    except ContentClientRateLimitError:
        return "Rate limit exceeded. Try again later."
    except ContentClientError as e:
        return f"Connection failed: {str(e)}"


def convert_severity(severity: str) -> int:
    """Convert vendor severity to XSOAR severity.
    
    Args:
        severity: Vendor severity string (e.g., 'low', 'medium', 'high', 'critical').
        
    Returns:
        XSOAR severity level (1-4).
    """
    severity_map = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    return severity_map.get(severity.lower() if severity else "", 1)


def fetch_incidents(client: SecurityVendorClient, max_fetch: int = 50) -> List[Dict]:
    """Fetch incidents for XSOAR."""
    alerts = client.get_alerts(severity="high", limit=max_fetch)
    
    incidents = []
    for alert in alerts:
        incidents.append({
            "name": alert.get("title"),
            "occurred": alert.get("created_at"),
            "severity": convert_severity(alert.get("severity")),
            "rawJSON": json.dumps(alert)
        })
    
    return incidents


def get_alerts_command(client: SecurityVendorClient, args: Dict) -> CommandResults:
    """Get alerts command."""
    severity = args.get("severity")
    limit = arg_to_number(args.get("limit", 50))
    
    alerts = client.get_alerts(severity=severity, limit=limit)
    
    return CommandResults(
        outputs_prefix="SecurityVendor.Alert",
        outputs_key_field="id",
        outputs=alerts,
        readable_output=tableToMarkdown("Alerts", alerts)
    )


def main():
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    
    try:
        client = SecurityVendorClient(
            base_url=params.get("url"),
            client_id=params.get("client_id"),
            client_secret=params.get("client_secret"),
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False)
        )
        
        if command == "test-module":
            return_results(test_module(client))
        elif command == "fetch-incidents":
            incidents = fetch_incidents(client, params.get("max_fetch", 50))
            demisto.incidents(incidents)
        elif command == "security-vendor-get-alerts":
            return_results(get_alerts_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} not implemented")
            
    except Exception as e:
        demisto.error(f"Error: {str(e)}")
        return_error(str(e))


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
```

---

## API Reference

### ContentClient

The main client class that extends `BaseClient` functionality.

#### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `base_url` | `str` | Required | Base URL for the API |
| `verify` | `bool` | `True` | Verify SSL certificates |
| `proxy` | `bool` | `False` | Use system proxy settings |
| `ok_codes` | `tuple` | `()` | HTTP status codes to consider successful (empty tuple means use standard HTTP success codes) |
| `headers` | `Dict[str, str]` | `None` | Default headers for all requests |
| `auth` | `tuple` | `None` | Basic auth credentials (username, password) |
| `timeout` | `float` | `60.0` | Request timeout in seconds |
| `auth_handler` | `AuthHandler` | `None` | Authentication handler instance |
| `retry_policy` | `RetryPolicy` | `None` | Retry policy configuration |
| `rate_limiter` | `RateLimitPolicy` | `None` | Rate limiting configuration |
| `circuit_breaker` | `CircuitBreakerPolicy` | `None` | Circuit breaker configuration |
| `diagnostic_mode` | `bool` | `False` | Enable detailed request tracing |
| `client_name` | `str` | `"ContentClient"` | Client identifier for logging |

#### Methods

| Method | Description |
|--------|-------------|
| `_http_request(...)` | Make an HTTP request (BaseClient compatible) |
| `get(url_suffix, ...)` | Make a GET request |
| `post(url_suffix, ...)` | Make a POST request |
| `put(url_suffix, ...)` | Make a PUT request |
| `patch(url_suffix, ...)` | Make a PATCH request |
| `delete(url_suffix, ...)` | Make a DELETE request |
| `get_diagnostic_report()` | Get comprehensive diagnostic report |
| `diagnose_error(error)` | Get diagnosis and solution for an error |
| `health_check()` | Check client health status |
| `close()` | Close the client and release resources |

### RetryPolicy

Configuration for automatic request retries.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_attempts` | `int` | `5` | Maximum number of retry attempts |
| `initial_delay` | `float` | `1.0` | Initial delay between retries (seconds) |
| `multiplier` | `float` | `2.0` | Delay multiplier for exponential backoff |
| `max_delay` | `float` | `60.0` | Maximum delay between retries (seconds) |
| `jitter` | `float` | `0.2` | Random jitter factor (0.0 to 1.0) |
| `respect_retry_after` | `bool` | `True` | Honor Retry-After header from server |

### RateLimitPolicy

Configuration for request rate limiting.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `rate_per_second` | `float` | `0.0` | Requests per second (0 = disabled) |
| `burst` | `int` | `1` | Maximum burst capacity |
| `respect_retry_after` | `bool` | `True` | Honor Retry-After header from server |

### CircuitBreakerPolicy

Configuration for circuit breaker pattern.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `failure_threshold` | `int` | `5` | Failures before opening circuit |
| `recovery_timeout` | `float` | `60.0` | Seconds before attempting recovery |

### TimeoutSettings

Granular timeout configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `connect` | `float` | `10.0` | Connection timeout (seconds) |
| `read` | `float` | `60.0` | Read timeout (seconds) |
| `write` | `float` | `60.0` | Write timeout (seconds) |
| `pool` | `float` | `60.0` | Connection pool timeout (seconds) |
| `execution` | `float` | `None` | Total execution timeout (seconds) |
| `safety_buffer` | `float` | `30.0` | Buffer before execution timeout |

### Authentication Handlers

| Handler | Parameters |
|---------|------------|
| `APIKeyAuthHandler` | `key`, `header_name`, `query_param` |
| `BearerTokenAuthHandler` | `token` |
| `BasicAuthHandler` | `username`, `password` |
| `OAuth2ClientCredentialsHandler` | `token_url`, `client_id`, `client_secret`, `scope`, `audience`, `auth_params`, `context_store` |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `ContentClientError` | Base exception for all client errors |
| `ContentClientAuthenticationError` | Authentication failed (401, 403) |
| `ContentClientRateLimitError` | Rate limit exceeded (429) |
| `ContentClientTimeoutError` | Execution timeout exceeded |
| `ContentClientCircuitOpenError` | Circuit breaker is open |
| `ContentClientRetryError` | All retry attempts exhausted |
| `ContentClientConfigurationError` | Invalid configuration |
