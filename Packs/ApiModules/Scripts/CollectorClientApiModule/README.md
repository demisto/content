# CollectorClient API Module

CollectorClient is the canonical API module for XSOAR/XSIAM event collectors. It provides a single blueprint that defines authentication, pagination, retry/rate-limiting, collection strategies, logging, metrics, and resume logic—while exposing both async and sync entry points.

---

## When Should I Use CollectorClient?

- You are polling a remote API for events/logs/assets.
- You need consistent retry/backoff, metrics, and structured logging.
- You must resume from execution timeouts without losing pagination state.
- You want a template that GenAI or junior engineers can follow with minimal edits.

---

## 10-Step Implementation Checklist (Copy & Paste Friendly)

| # | Step | Notes / Snippet |
|---|------|-----------------|
|1|Import CollectorClient module.|`from CollectorClient import *`|
|2|Read integration params.|`params = demisto.params()`|
|3|Pick an `AuthHandler`.|See [Authentication Recipes](#authentication-recipes).|
|4|Describe pagination via `PaginationConfig`.|Cursor/Page/Offset/Link examples below.|
|5|Create a `CollectorRequest` (endpoint, params, `data_path`, pagination).|Set `state_key` if you have multiple feeds.|
|6|Configure `RetryPolicy`, `RateLimitPolicy`, and `TimeoutSettings`.|Start with defaults; adjust as needed.|
|7|Build a `CollectorBlueprint` bundling everything.|`CollectorBlueprint(name="MyCollector", base_url=params["url"], ...)`|
|8|Instantiate `CollectorClient(blueprint)`.|Reuse across commands if possible.|
|9|Call `collect_events_sync(limit=?, strategy=?, resume_state=?)`.|`collect_events` (async) is also available.|
|10|Persist `result.state` and return outputs/metrics.|`demisto.setIntegrationContext({"state": result.state.to_dict()})`|

---

## Boilerplate Template

```python
from CollectorClient import *


def build_client() -> CollectorClient:
    params = demisto.params()

    auth = APIKeyAuthHandler(
        key=params["api_key"],
        header_name="X-API-Key",
    )

    pagination = PaginationConfig(
        mode="cursor",
        cursor_param="cursor",
        next_cursor_path="meta.next_cursor",
        page_size_param="limit",
        page_size=int(params.get("page_size", 200)),
    )

    request = CollectorRequest(
        endpoint="/v1/events",
        params={"limit": pagination.page_size},
        data_path="data.events",
        pagination=pagination,
        state_key="events-default",
    )

    blueprint = CollectorBlueprint(
        name="MyCollector",
        base_url=params["url"],
        request=request,
        auth_handler=auth,
        retry_policy=RetryPolicy(max_attempts=5, initial_delay=1),
        rate_limit=RateLimitPolicy(rate_per_second=5, burst=10),
        timeout=TimeoutSettings(execution=demisto.commandExecutionTime()),
        default_strategy="sequential",
    )

    return CollectorClient(blueprint)


def fetch_events_command():
    client = build_client()
    context = demisto.getIntegrationContext() or {}
    resume_state = CollectorState.from_dict(context.get("state")) if context.get("state") else None

    result = client.collect_events_sync(limit=1000, resume_state=resume_state)

    demisto.setIntegrationContext({"state": result.state.to_dict()})

    return_results(CommandResults(
        readable_output=f"Fetched {len(result.events)} events.",
        outputs_prefix="MyCollector.Event",
        outputs_key_field="id",
        outputs=result.events,
        metrics=result.metrics.metrics,
    ))
```

This template is intentionally verbose so a GenAI assistant (or a human) can follow it step-by-step.

---

## Authentication Recipes

| Scenario | Handler | How to Configure |
|----------|---------|------------------|
|Header API key|`APIKeyAuthHandler`|`APIKeyAuthHandler(key=params["api_key"], header_name="X-Key")`|
|Query param API key|`APIKeyAuthHandler`|`APIKeyAuthHandler(key=params["api_key"], query_param="apikey")`|
|Bearer token|`BearerTokenAuthHandler`|`BearerTokenAuthHandler(token=params["token"])`|
|Basic auth|`BasicAuthHandler`|`BasicAuthHandler(username=params["user"], password=params["password"])`|
|OAuth2 client credentials|`OAuth2ClientCredentialsHandler`|Provide `token_url`, `client_id`, `client_secret`, optional `scope`/`audience`. Tokens auto-refresh and are stored in integration context.|
|Custom flow|Subclass `AuthHandler`|Override `on_request()` to mutate headers/query params, `on_auth_failure()` to refresh credentials and return `True` to retry.|

---

## Pagination Patterns

| Mode | Minimal Config | API Expectations | State Behavior |
|------|----------------|------------------|----------------|
|Cursor|`PaginationConfig(mode="cursor", cursor_param="cursor", next_cursor_path="meta.next")`|Response returns `"meta.next"`.|`state.cursor` stores the next cursor.|
|Page|`mode="page", page_param="page", start_page=1`|API expects page numbers.|`state.page` increments after each request.|
|Offset|`mode="offset", offset_param="offset", page_size_param="limit"`|API expects offsets.|`state.offset` increments by `page_size`.|
|Link|`mode="link", link_path="links.next"`|API returns a next URL.|`state.metadata["next_link"]` holds the URL.|

All pagination metadata (including cursors, offsets, and `has_more` flags) is stored under `collector_client[collector_name][state_key]` in the integration context.

---

## Collection Strategies At a Glance

| Strategy | Description | How to Enable |
|----------|-------------|---------------|
|`sequential`|Default; fetches pages one at a time.|`blueprint.default_strategy = "sequential"` or pass `strategy="sequential"`.|
|`concurrent`|Fans out per shard (e.g., per region/device).|Populate `request.shards = [{"params": {...}, "state_key": "..."}]` and call `collect_events_sync(strategy="concurrent")`. Concurrency equals `CollectorBlueprint.concurrency`.|
|`batch`|Flushes batches (e.g., every 500 events) via `CollectorExecutor.flush_batch`. Use when downstream needs chunking.|`collect_events_sync(strategy=BatchCollectionStrategy(batch_size=500))`.|
|`stream`|Emits results to `CollectorExecutor.stream_batch` immediately (e.g., push to SIEM sink).|`collect_events_sync(strategy=StreamCollectionStrategy())`.|

All strategies enforce `TimeoutSettings`. If time is nearly exhausted, `CollectorTimeoutError` is raised, state is persisted, and partial results are returned.

---

## Rate Limiting, Retry, and Circuit Breaking

```python
RetryPolicy(
    max_attempts=5,
    initial_delay=1,
    multiplier=2,
    retryable_status_codes=(408, 429, 500, 502, 503, 504),
)

RateLimitPolicy(rate_per_second=5, burst=10)

CircuitBreakerPolicy(failure_threshold=5, recovery_timeout=60)
```

- HTTP 429 increments `ExecutionMetrics.quota_error`, honors `Retry-After`, and counts as a retry.
- Network failures (`httpx.ConnectError`, timeouts, etc.) follow exponential backoff with jitter.
- The circuit breaker prevents request storms when the upstream is unhealthy.

---

## Logging & Metrics

- `CollectorLogger.info()` writes to `demisto.info`, while `debug()` logs only when `CollectorBlueprint.diagnostic_mode=True`.
- All sensitive fields are sanitized (headers/params containing *token*, *secret*, *key*).
- `ExecutionMetrics` is automatically incremented: successes, auth/quota/service errors, retries, and timeouts. Pass `result.metrics.metrics` to `CommandResults`.

---

## Testing Guidance

1. Use `pytest` + `respx` to mock HTTP responses.  
2. Cover authentication, pagination, retries, and resume scenarios (see `CollectorClient_test.py`).  
3. Run the module’s tests locally before submitting:

```bash
poetry run pytest Packs/ApiModules/Scripts/CollectorClient/CollectorClient_test.py
```

---

## Operational Notes

- Integration context path: `collector_client[collector_name][state_key]`.
- Docker image: `demisto/python3:3.10.14.92207` (ships with `httpx`, `anyio`, `respx`, etc.).
- Resume support: pass the previous `CollectorState` via `resume_state=result.state`.
- HTTP/2 is automatically preferred. If `h2` is missing, CollectorClient logs an INFO message and continues with HTTP/1.1.

Use this document as a readiness checklist. Every section was crafted to be copy/paste-friendly so GenAI and engineers can implement a collector with minimal guesswork.

