# CollectorClient API Module

CollectorClient is the canonical API module for XSOAR/XSIAM event collectors. It provides a single blueprint that defines authentication, pagination, retry/rate-limiting, collection strategies, logging, metrics, and resume logic—while exposing both async and sync entry points.

---

## 📋 Table of Contents

- [When Should I Use CollectorClient?](#when-should-i-use-collectorclient)
- [Quick Start Checklist](#quick-start-checklist)
- [Implementation Templates](#implementation-templates)
  - [Standard Implementation](#standard-implementation)
  - [Builder Pattern (Recommended)](#builder-pattern-recommended)
- [Authentication Recipes](#authentication-recipes)
- [Pagination Patterns](#pagination-patterns)
- [Collection Strategies](#collection-strategies)
- [Resilience & Performance](#resilience--performance)
- [Troubleshooting & Diagnostics](#troubleshooting--diagnostics)
- [Testing](#testing)

---

## When Should I Use CollectorClient?

- You are polling a remote API for events/logs/assets.
- You need consistent retry/backoff, metrics, and structured logging.
- You must resume from execution timeouts without losing pagination state.
- You want a template that GenAI or junior engineers can follow with minimal edits.

---

## Quick Start Checklist

| # | Step | Notes / Snippet |
|---|------|-----------------|
|1|Import CollectorClient module.|`from CollectorClientApiModule import *`|
|2|Read integration params.|`params = demisto.params()`|
|3|Pick an `AuthHandler`.|See [Authentication Recipes](#authentication-recipes).|
|4|Describe pagination via `PaginationConfig`.|Cursor/Page/Offset/Link examples below.|
|5|Create a `CollectorRequest`.|Define endpoint, params, and data path.|
|6|Configure Policies.|Retry, Rate Limit, and Timeouts.|
|7|Build a `CollectorBlueprint`.|Bundle everything together.|
|8|Instantiate `CollectorClient`.|`client = CollectorClient(blueprint)`|
|9|Call `collect_events_sync`.|`result = client.collect_events_sync(limit=1000)`|
|10|Persist State & Return Results.|Save `result.state` and return `CommandResults`.|

---

## Implementation Templates

### Standard Implementation

Use this for full control over every configuration option.

```python
from CollectorClientApiModule import *

def build_client() -> CollectorClient:
    params = demisto.params()

    # 1. Authentication
    auth = APIKeyAuthHandler(
        key=params["api_key"],
        header_name="X-API-Key",
    )

    # 2. Pagination
    pagination = PaginationConfig(
        mode="cursor",
        cursor_param="cursor",
        next_cursor_path="meta.next_cursor",
        page_size_param="limit",
        page_size=int(params.get("page_size", 200)),
    )

    # 3. Request Definition
    request = CollectorRequest(
        endpoint="/v1/events",
        params={"limit": pagination.page_size},
        data_path="data.events",
        pagination=pagination,
        state_key="events-default",
    )

    # 4. Blueprint
    blueprint = CollectorBlueprint(
        name="MyCollector",
        base_url=params["url"],
        request=request,
        auth_handler=auth,
        retry_policy=RetryPolicy(max_attempts=5, initial_delay=1),
        rate_limit=RateLimitPolicy(rate_per_second=5, burst=10),
        timeout=TimeoutSettings(execution=demisto.commandExecutionTime()),
    )

    return CollectorClient(blueprint)

def fetch_events_command():
    client = build_client()
    
    # Resume from previous state if available
    context = demisto.getIntegrationContext() or {}
    resume_state = CollectorState.from_dict(context.get("state")) if context.get("state") else None

    # Collect events
    result = client.collect_events_sync(limit=1000, resume_state=resume_state)

    # Save state for next run
    demisto.setIntegrationContext({"state": result.state.to_dict()})

    return_results(CommandResults(
        readable_output=f"Fetched {len(result.events)} events.",
        outputs_prefix="MyCollector.Event",
        outputs_key_field="id",
        outputs=result.events,
        metrics=result.metrics.metrics,
    ))
```

### Builder Pattern (Recommended)

Use `CollectorBlueprintBuilder` for a fluent, readable configuration.

```python
from CollectorClientApiModule import *

def build_client() -> CollectorClient:
    params = demisto.params()
    
    blueprint = (
        CollectorBlueprintBuilder("MyCollector", params["url"])
        .with_endpoint(
            endpoint="/v1/events", 
            data_path="data.events"
        )
        .with_cursor_pagination(
            next_cursor_path="meta.next_cursor",
            cursor_param="cursor"
        )
        .with_api_key_auth(
            key=params["api_key"], 
            header_name="X-API-Key"
        )
        .with_rate_limit(rate_per_second=10, burst=20)
        .with_timeout(execution=demisto.commandExecutionTime())
        .with_retry_policy(max_attempts=3)
        .build()
    )
    
    return CollectorClient(blueprint)
```

---

## Authentication Recipes

| Scenario | Handler | How to Configure |
|----------|---------|------------------|
| **Header API Key** | `APIKeyAuthHandler` | `APIKeyAuthHandler(key="...", header_name="X-Key")` |
| **Query Param Key** | `APIKeyAuthHandler` | `APIKeyAuthHandler(key="...", query_param="apikey")` |
| **Bearer Token** | `BearerTokenAuthHandler` | `BearerTokenAuthHandler(token="...")` |
| **Basic Auth** | `BasicAuthHandler` | `BasicAuthHandler(username="...", password="...")` |
| **OAuth2** | `OAuth2ClientCredentialsHandler` | See example below. |

### OAuth2 Example

```python
context_store = IntegrationContextStore("MyCollector")
auth = OAuth2ClientCredentialsHandler(
    token_url="https://api.example.com/oauth/token",
    client_id=params["client_id"],
    client_secret=params["client_secret"],
    scope="read:events",
    context_store=context_store,  # Persists token across runs
)
```

---

## Pagination Patterns

| Mode | Minimal Config | API Expectations | State Behavior |
|------|----------------|------------------|----------------|
| **Cursor** | `mode="cursor", cursor_param="cursor", next_cursor_path="meta.next"` | Response returns a cursor string. | `state.cursor` stores the next cursor. |
| **Page** | `mode="page", page_param="page", start_page=1` | API expects page numbers. | `state.page` increments after each request. |
| **Offset** | `mode="offset", offset_param="offset", page_size_param="limit"` | API expects skip/offset. | `state.offset` increments by `page_size`. |
| **Link** | `mode="link", link_path="links.next"` | API returns a full URL. | `state.metadata["next_link"]` holds the URL. |

---

## Collection Strategies

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **Sequential** | Fetches pages one at a time. | Default. Simple, reliable, preserves order. |
| **Concurrent** | Fans out requests. | High throughput. Requires sharding (e.g., by region). |
| **Batch** | Flushes batches periodically. | When downstream needs chunked processing. |
| **Stream** | Emits results immediately. | Real-time processing or low memory footprint. |

---

## Resilience & Performance

### Retry Policy
Handles transient failures (429, 5xx, network errors) with exponential backoff.
```python
RetryPolicy(
    max_attempts=5,
    initial_delay=1,
    multiplier=2,
    retryable_status_codes=(408, 429, 500, 502, 503, 504)
)
```

### Rate Limiting
Token bucket algorithm to respect API limits.
```python
RateLimitPolicy(rate_per_second=5, burst=10)
```

### Circuit Breaker
Prevents request storms when the upstream is unhealthy.
```python
CircuitBreakerPolicy(failure_threshold=5, recovery_timeout=60)
```

---

## Troubleshooting & Diagnostics

CollectorClient includes built-in diagnostic tools to help debug issues.

### Diagnostic Report
Generate a comprehensive report of the last run, including request traces and errors.

```python
# 1. Enable diagnostic mode in blueprint
blueprint.diagnostic_mode = True

# 2. Run collection
try:
    client.collect_events_sync()
except Exception:
    # 3. Get report
    report = client.get_diagnostic_report()
    demisto.debug(f"Diagnostics: {report}")
```

### Error Diagnosis
Get actionable advice for specific exceptions.

```python
try:
    client.collect_events_sync()
except CollectorError as e:
    diagnosis = client.diagnose_error(e)
    demisto.error(f"Issue: {diagnosis['issue']}")
    demisto.error(f"Solution: {diagnosis['solution']}")
```
