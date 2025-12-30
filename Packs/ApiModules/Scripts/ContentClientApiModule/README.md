# ContentClient API Module

`ContentClient` is a drop-in replacement for `BaseClient` that provides enhanced reliability, observability, and developer experience features. It is designed to be fully backward compatible while offering powerful new capabilities for robust API integrations.

## 🚀 Key Features

- **Drop-in Replacement**: Fully compatible with `BaseClient` constructor and `_http_request` method.
- **Advanced Authentication**: Built-in handlers for API Key, Bearer Token, Basic Auth, and OAuth2 (with auto-refresh).
- **Resilience**: Configurable Retry Policy, Rate Limiting (Token Bucket), and Circuit Breaker.
- **Observability**: Detailed execution metrics, structured logging, and diagnostic reports.
- **Async Core**: Built on `httpx` and `anyio` for high-performance async I/O, with synchronous wrappers for easy adoption.

## 📦 Installation

```python
from ContentClientApiModule import *
```

## 🛠 Usage

### Basic Usage (BaseClient Style)

You can use `ContentClient` exactly like `BaseClient`.

```python
client = ContentClient(
    base_url="https://api.example.com",
    verify=True,
    proxy=False
)

response = client._http_request(
    method="GET",
    url_suffix="/users",
    params={"limit": 10}
)
```

### Enhanced Usage

Unlock advanced features by passing policy objects.

```python
client = ContentClient(
    base_url="https://api.example.com",
    # 1. Advanced Auth
    auth_handler=APIKeyAuthHandler(key="secret", header_name="X-API-Key"),
    
    # 2. Resilience Policies
    retry_policy=RetryPolicy(max_attempts=5, initial_delay=1.0),
    rate_limiter=RateLimitPolicy(rate_per_second=10, burst=20),
    circuit_breaker=CircuitBreakerPolicy(failure_threshold=5, recovery_timeout=60),
    
    # 3. Timeouts
    timeout=TimeoutSettings(connect=5.0, read=30.0),
    
    # 4. Diagnostics
    diagnostic_mode=True
)
```

## 🔐 Authentication Handlers

| Handler | Description | Usage |
|---------|-------------|-------|
| `APIKeyAuthHandler` | Adds API key to header or query param. | `APIKeyAuthHandler(key="...", header_name="X-Key")` |
| `BearerTokenAuthHandler` | Adds Bearer token to Authorization header. | `BearerTokenAuthHandler(token="...")` |
| `BasicAuthHandler` | Adds Basic Auth header. | `BasicAuthHandler(username="...", password="...")` |
| `OAuth2ClientCredentialsHandler` | Handles OAuth2 flow with auto-refresh. | See example below. |

### OAuth2 Example

```python
auth = OAuth2ClientCredentialsHandler(
    token_url="https://auth.example.com/token",
    client_id="client_id",
    client_secret="client_secret",
    scope="read:data",
    # Optional: Persist token across execution runs
    context_store=IntegrationContextStore("MyIntegration") 
)
```

## 📊 Metrics & Diagnostics

`ContentClient` tracks execution metrics automatically.

```python
# Access metrics
metrics = client.metrics
print(f"Success: {metrics.success}, Retries: {metrics.retry_error}")

# Get diagnostic report (if diagnostic_mode=True)
report = client.get_diagnostic_report()
demisto.debug(f"Diagnostics: {report}")
