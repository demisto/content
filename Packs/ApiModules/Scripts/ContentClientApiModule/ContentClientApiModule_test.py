"""Tests for ContentClientApiModule - testing ContentClient, auth handlers, policies, and utilities."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import demistomock as demisto
import httpx
import pytest
import respx
from httpx import Response


from ContentClientApiModule import (
    ContentClient,
    AuthHandler,
    APIKeyAuthHandler,
    BearerTokenAuthHandler,
    BasicAuthHandler,
    OAuth2ClientCredentialsHandler,
    ContentClientState,
    RateLimitPolicy,
    RetryPolicy,
    TimeoutSettings,
    CircuitBreakerPolicy,
    CircuitBreaker,
    TokenBucketRateLimiter,
    ContentClientError,
    ContentClientConfigurationError,
    ContentClientAuthenticationError,
    ContentClientRateLimitError,
    ContentClientTimeoutError,
    ContentClientCircuitOpenError,
    ContentClientRetryError,
    ContentClientLogger,
    ContentClientContextStore,
    StructuredLogEntry,
    _extract_list,
    _ensure_dict,
    _parse_retry_after,
    _get_value_by_path,
    _create_rate_limiter,
    _now,
    create_http_request_log,
    create_error_log,
)


@pytest.fixture(autouse=True)
def integration_context(mocker):
    store: dict[str, Any] = {}

    def get_context():
        return json.loads(json.dumps(store))

    def set_context(value: dict[str, Any]):
        store.clear()
        store.update(value)

    mocker.patch.object(demisto, "getIntegrationContext", side_effect=get_context)
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=set_context)
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    return store


# =============================================================================
# Utility Function Tests
# =============================================================================


def test_nested_value_extraction():
    """Test _get_value_by_path utility."""
    data = {"a": {"b": [{"c": 1}]}}
    assert _get_value_by_path(data, "a.b.0.c") == 1
    assert _get_value_by_path(data, "a.b.1.c") is None
    assert _get_value_by_path(data, "x.y.z") is None
    assert _get_value_by_path(data, "") == data


def test_get_value_by_path_with_list_index():
    """Test _get_value_by_path with list indexing."""
    data = {
        "items": [
            {"id": 1, "name": "first"},
            {"id": 2, "name": "second"},
        ]
    }

    # Test valid index
    assert _get_value_by_path(data, "items.0.name") == "first"
    assert _get_value_by_path(data, "items.1.id") == 2

    # Test invalid index
    assert _get_value_by_path(data, "items.5.name") is None

    # Test non-numeric index on list
    assert _get_value_by_path(data, "items.invalid.name") is None


def test_get_value_by_path_edge_cases():
    """Test _get_value_by_path edge cases."""
    # Test with None
    assert _get_value_by_path(None, "path") is None

    # Test with empty path
    data = {"key": "value"}
    assert _get_value_by_path(data, "") == data

    # Test with path through None
    data_with_none = {"a": None}
    assert _get_value_by_path(data_with_none, "a.b.c") is None

    # Test with non-dict, non-list intermediate value
    data_with_scalar = {"a": "string"}
    assert _get_value_by_path(data_with_scalar, "a.b") is None


def test_get_value_by_path_empty_parts():
    """Test _get_value_by_path handles empty parts from consecutive dots."""
    data = {"a": {"b": "value"}}
    # Path with consecutive dots should skip empty parts
    result = _get_value_by_path(data, "a..b")
    assert result == "value"

    # Leading dot
    result = _get_value_by_path(data, ".a.b")
    assert result == "value"

    # Trailing dot
    result = _get_value_by_path(data, "a.b.")
    assert result == "value"


def test_extract_list_utility():
    """Test _extract_list utility function."""
    # List input
    assert _extract_list([1, 2, 3], None) == [1, 2, 3]

    # Dict input (should wrap in list)
    assert _extract_list({"id": 1}, None) == [{"id": 1}]

    # Nested path
    data = {"data": {"events": [1, 2, 3]}}
    assert _extract_list(data, "data.events") == [1, 2, 3]

    # None/missing path
    assert _extract_list(None, "path") == []
    assert _extract_list({}, "missing.path") == []

    # Scalar value (should wrap in list)
    assert _extract_list("value", None) == ["value"]


def test_extract_list_with_dict():
    """Test _extract_list wraps dict in list."""
    result = _extract_list({"id": 1, "name": "test"}, None)
    assert result == [{"id": 1, "name": "test"}]


def test_extract_list_with_scalar():
    """Test _extract_list wraps scalar in list."""
    result = _extract_list("scalar_value", None)
    assert result == ["scalar_value"]

    result = _extract_list(42, None)
    assert result == [42]


def test_extract_list_with_non_standard_types():
    """Test _extract_list with various non-standard types."""
    # Test with boolean
    result = _extract_list(True, None)
    assert result == [True]

    # Test with float
    result = _extract_list(3.14, None)
    assert result == [3.14]


def test_ensure_dict_utility():
    """Test _ensure_dict utility function."""
    # None input
    assert _ensure_dict(None) == {}

    # Dict input
    assert _ensure_dict({"a": 1}) == {"a": 1}

    # MutableMapping input
    from collections import OrderedDict

    assert _ensure_dict(OrderedDict([("a", 1)])) == {"a": 1}


def test_parse_retry_after_with_none_response():
    """Test _parse_retry_after with None response."""
    result = _parse_retry_after(None)
    assert result is None


def test_retry_after_header_parsing():
    """Test Retry-After header parsing."""
    # Test numeric Retry-After
    response = Response(429, headers={"Retry-After": "60"})
    delay = _parse_retry_after(response)
    assert delay == 60.0

    # Test date Retry-After (use timezone-aware datetime)
    future = datetime.now(UTC) + timedelta(seconds=30)
    retry_after_date = future.strftime("%a, %d %b %Y %H:%M:%S GMT")
    response = Response(429, headers={"Retry-After": retry_after_date})
    delay = _parse_retry_after(response)
    assert delay is not None
    assert 25 <= delay <= 35  # Allow some variance

    # Test invalid Retry-After
    response = Response(429, headers={"Retry-After": "invalid"})
    delay = _parse_retry_after(response)
    assert delay is None

    # Test missing Retry-After
    response = Response(429)
    delay = _parse_retry_after(response)
    assert delay is None


# =============================================================================
# Policy Tests
# =============================================================================


def test_retry_policy_validation():
    """Test RetryPolicy validation."""
    from pydantic import ValidationError

    # Valid policy
    policy = RetryPolicy(max_attempts=5, initial_delay=1.0, max_delay=60.0)
    assert policy.max_attempts == 5

    # Invalid: max_attempts < 1 (violates ge=1 constraint)
    with pytest.raises(ValidationError):
        RetryPolicy(max_attempts=0, initial_delay=1.0, max_delay=60.0)


def test_retry_policy_next_delay():
    """Test RetryPolicy.next_delay calculation."""
    policy = RetryPolicy(
        max_attempts=5,
        initial_delay=1.0,
        max_delay=60.0,
        multiplier=2.0,
        jitter=0.0,  # No jitter for predictable testing
    )

    # Test exponential backoff
    delay1 = policy.next_delay(1)
    assert delay1 == 1.0

    delay2 = policy.next_delay(2)
    assert delay2 == 2.0

    delay3 = policy.next_delay(3)
    assert delay3 == 4.0

    # Test max_delay cap
    delay10 = policy.next_delay(10)
    assert delay10 == 60.0

    # Test retry_after override
    delay_with_retry_after = policy.next_delay(1, retry_after=5.0)
    assert delay_with_retry_after == 5.0


def test_timeout_settings_validation():
    """Test TimeoutSettings validation."""
    from pydantic import ValidationError

    # Valid settings
    settings = TimeoutSettings(execution=120.0, safety_buffer=30.0)
    assert settings.execution == 120.0

    # Invalid: connect <= 0 (violates gt=0 constraint)
    with pytest.raises(ValidationError):
        TimeoutSettings(connect=0.0)


def test_timeout_settings_as_httpx():
    """Test TimeoutSettings.as_httpx() method."""
    settings = TimeoutSettings(connect=5.0, read=30.0, write=20.0, pool=15.0)
    httpx_timeout = settings.as_httpx()

    assert httpx_timeout.connect == 5.0
    assert httpx_timeout.read == 30.0
    assert httpx_timeout.write == 20.0
    assert httpx_timeout.pool == 15.0


def test_rate_limit_policy():
    """Test RateLimitPolicy."""
    # Disabled rate limit
    policy = RateLimitPolicy(rate_per_second=0.0)
    assert policy.enabled is False

    # Enabled rate limit
    policy = RateLimitPolicy(rate_per_second=10.0, burst=20)
    assert policy.enabled is True
    assert policy.rate_per_second == 10.0
    assert policy.burst == 20


# =============================================================================
# Circuit Breaker Tests
# =============================================================================


def test_circuit_breaker_success_reset():
    """Test circuit breaker resets failure count on success."""
    policy = CircuitBreakerPolicy(failure_threshold=3, recovery_timeout=1.0)
    breaker = CircuitBreaker(policy)

    # Record some failures
    breaker.record_failure()
    breaker.record_failure()

    # Record success - should reset
    breaker.record_success()

    # Should still be able to execute
    assert breaker.can_execute()

    # Verify failure count was reset (need 3 more failures to open)
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.can_execute()  # Still open after 2 failures


def test_circuit_breaker_recovery():
    """Test circuit breaker recovery after timeout."""
    import time

    policy = CircuitBreakerPolicy(failure_threshold=2, recovery_timeout=0.1)
    breaker = CircuitBreaker(policy)

    # Record failures to open circuit
    breaker.record_failure()
    breaker.record_failure()

    assert not breaker.can_execute()

    # Wait for recovery
    time.sleep(0.15)

    # Should be able to execute again
    assert breaker.can_execute()


# =============================================================================
# Token Bucket Rate Limiter Tests
# =============================================================================


@pytest.mark.asyncio
async def test_token_bucket_refill():
    """Test token bucket rate limiter refill logic."""
    import anyio as anyio_module

    policy = RateLimitPolicy(rate_per_second=10.0, burst=5)
    limiter = TokenBucketRateLimiter(policy)

    # Consume all tokens
    for _ in range(5):
        await limiter.acquire()

    # Wait for refill
    await anyio_module.sleep(0.2)  # Should refill ~2 tokens

    # Should be able to acquire again
    await limiter.acquire()


# =============================================================================
# State Serialization Tests
# =============================================================================


def test_content_client_state_serialization():
    """Test ContentClientState to_dict and from_dict."""
    state = ContentClientState(
        cursor="test_cursor",
        page=5,
        offset=100,
        last_event_id="event_123",
        partial_results=[{"id": 1}],
        metadata={"custom": "data"},
    )

    # Serialize
    state_dict = state.to_dict()
    assert state_dict["cursor"] == "test_cursor"
    assert state_dict["page"] == 5

    # Deserialize
    restored = ContentClientState.from_dict(state_dict)
    assert restored.cursor == "test_cursor"
    assert restored.page == 5
    assert restored.metadata["custom"] == "data"

    # Test empty state
    empty = ContentClientState.from_dict(None)
    assert empty.cursor is None


def test_content_client_state_with_metadata():
    """Test ContentClientState serialization with metadata."""
    state = ContentClientState(
        cursor="test_cursor",
        metadata={"latest_timestamp": "2023-01-01T00:00:00Z", "seen_keys": ["key1"]},
    )

    # Serialize
    state_dict = state.to_dict()
    assert state_dict["metadata"]["latest_timestamp"] == "2023-01-01T00:00:00Z"

    # Deserialize
    restored = ContentClientState.from_dict(state_dict)
    assert restored.metadata is not None
    assert restored.metadata["latest_timestamp"] == "2023-01-01T00:00:00Z"


# =============================================================================
# Auth Handler Tests
# =============================================================================


def test_api_key_auth_both_header_and_query():
    """Test APIKeyAuthHandler with both header and query param."""
    # Should allow both
    auth = APIKeyAuthHandler("secret", header_name="X-API-Key", query_param="api_key")
    assert auth.header_name == "X-API-Key"
    assert auth.query_param == "api_key"


def test_api_key_auth_neither_header_nor_query():
    """Test APIKeyAuthHandler requires at least one of header or query param."""
    with pytest.raises(ContentClientConfigurationError):
        APIKeyAuthHandler("secret")


# =============================================================================
# ContentClient Tests
# =============================================================================


@respx.mock
def test_content_client_direct_usage():
    """Test ContentClient directly."""
    # Mock API endpoint
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=BearerTokenAuthHandler("test_token"),
    )

    response = client.get("/v1/data")

    assert route.called
    assert response.status_code == 200
    sent_headers = route.calls[0].request.headers
    assert sent_headers["Authorization"] == "Bearer test_token"

    client.close()


@respx.mock
def test_content_client_basic_auth_handler():
    """Test ContentClient with BasicAuthHandler."""
    # Mock API endpoint
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=BasicAuthHandler("user", "password"),
    )

    response = client.get("/v1/data")

    assert route.called
    assert response.status_code == 200
    sent_headers = route.calls[0].request.headers
    assert "Authorization" in sent_headers
    assert sent_headers["Authorization"].startswith("Basic ")

    client.close()


@respx.mock
def test_content_client_patch_method():
    """Test ContentClient PATCH method."""
    route = respx.patch("https://api.example.com/v1/data").mock(return_value=Response(200, json={"patched": True}))

    client = ContentClient(base_url="https://api.example.com")

    response = client.patch("/v1/data", json_data={"field": "value"})

    assert route.called
    assert response.status_code == 200

    client.close()


@respx.mock
def test_content_client_with_tuple_auth():
    """Test ContentClient with tuple auth (username, password)."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    # Create client with tuple auth
    client = ContentClient(
        base_url="https://api.example.com",
        auth=("user", "password"),
    )

    response = client.get("/v1/data")

    assert route.called
    assert response.status_code == 200
    # Verify Basic auth header was set
    sent_headers = route.calls[0].request.headers
    assert "Authorization" in sent_headers
    assert sent_headers["Authorization"].startswith("Basic ")

    client.close()


@respx.mock
def test_content_client_with_request_auth_override():
    """Test ContentClient with auth override in request."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    # Pass auth in the request
    client._http_request("GET", "/v1/data", auth=("override_user", "override_pass"))

    assert route.called
    # Verify Basic auth header was set from request auth
    sent_headers = route.calls[0].request.headers
    assert "Authorization" in sent_headers
    assert sent_headers["Authorization"].startswith("Basic ")

    client.close()


@respx.mock
def test_content_client_rate_limiter_enabled():
    """Test ContentClient with rate limiter enabled."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(
        base_url="https://api.example.com",
        rate_limiter=RateLimitPolicy(rate_per_second=100.0, burst=10),
    )

    response = client.get("/v1/data")

    assert route.called
    assert response.status_code == 200

    client.close()


@respx.mock
def test_content_client_diagnostic_mode_with_error():
    """Test ContentClient diagnostic mode captures errors."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(500, json={"error": "Server Error"}))

    client = ContentClient(
        base_url="https://api.example.com",
        diagnostic_mode=True,
        retry_policy=RetryPolicy(max_attempts=1),
    )

    with pytest.raises(ContentClientError):
        client.get("/v1/data")

    # Verify diagnostic report captured the error
    report = client.get_diagnostic_report()
    assert len(report.request_traces) > 0

    client.close()


@respx.mock
def test_content_client_health_check_with_quota_error():
    """Test ContentClient health_check with quota errors."""
    client = ContentClient(base_url="https://api.example.com")

    # Simulate quota error
    client.execution_metrics.quota_error = 3

    health = client.health_check()

    assert health["status"] == "degraded"
    assert any("rate limit" in w.lower() for w in health["warnings"])

    client.close()


@respx.mock
def test_content_client_response_types():
    """Test ContentClient with different response types."""
    # Mock endpoints
    respx.get("https://api.example.com/json").mock(return_value=Response(200, json={"key": "value"}))
    respx.get("https://api.example.com/text").mock(return_value=Response(200, text="plain text response"))
    respx.get("https://api.example.com/content").mock(return_value=Response(200, content=b"binary content"))
    respx.get("https://api.example.com/xml").mock(return_value=Response(200, text="<root><item>value</item></root>"))

    client = ContentClient(base_url="https://api.example.com")

    # Test JSON response
    result = client._http_request("GET", "/json", resp_type="json")
    assert result == {"key": "value"}

    # Test text response
    result = client._http_request("GET", "/text", resp_type="text")
    assert result == "plain text response"

    # Test content response
    result = client._http_request("GET", "/content", resp_type="content")
    assert result == b"binary content"

    # Test XML response (returns text)
    result = client._http_request("GET", "/xml", resp_type="xml")
    assert "<root>" in result

    client.close()


@respx.mock
def test_content_client_empty_response_handling():
    """Test ContentClient handles empty responses correctly."""
    respx.get("https://api.example.com/empty").mock(return_value=Response(204))

    client = ContentClient(base_url="https://api.example.com")

    # Test with return_empty_response and empty_valid_codes
    result = client._http_request(
        "GET",
        "/empty",
        resp_type="json",
        return_empty_response=True,
        empty_valid_codes=[204],
        ok_codes=(204,),
    )
    assert result == {}

    client.close()


@respx.mock
def test_content_client_json_decode_error_empty_content():
    """Test ContentClient handles JSON decode error with empty content."""
    respx.get("https://api.example.com/empty-json").mock(return_value=Response(200, content=b""))

    client = ContentClient(base_url="https://api.example.com")

    # Should return empty dict when content is empty
    result = client._http_request("GET", "/empty-json", resp_type="json")
    assert result == {}

    client.close()


@respx.mock
def test_retryable_exception_handling():
    """Test handling of retryable exceptions (network errors)."""
    # Mock endpoint that fails with network error then succeeds
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[
            httpx.ConnectError("Connection refused"),
            Response(200, json={"result": "success"}),
        ]
    )

    client = ContentClient(
        base_url="https://api.example.com",
        retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02),
        diagnostic_mode=True,
    )

    result = client._http_request("GET", "/v1/data", resp_type="json")

    assert result == {"result": "success"}
    assert client.execution_metrics.retry_error == 1

    client.close()


@respx.mock
def test_content_client_diagnose_error():
    """Test ContentClient.diagnose_error method."""
    client = ContentClient(base_url="https://api.example.com")

    # Test all error types
    auth_error = ContentClientAuthenticationError("Auth failed")
    diagnosis = client.diagnose_error(auth_error)
    assert diagnosis["issue"] == "Authentication failed"

    rate_error = ContentClientRateLimitError("Rate limit")
    diagnosis = client.diagnose_error(rate_error)
    assert diagnosis["issue"] == "Rate limit exceeded"

    timeout_error = ContentClientTimeoutError("Timeout")
    diagnosis = client.diagnose_error(timeout_error)
    assert diagnosis["issue"] == "Execution timeout"

    circuit_error = ContentClientCircuitOpenError("Circuit open")
    diagnosis = client.diagnose_error(circuit_error)
    assert diagnosis["issue"] == "Circuit breaker is open"

    retry_error = ContentClientRetryError("Retries exhausted")
    diagnosis = client.diagnose_error(retry_error)
    assert diagnosis["issue"] == "All retry attempts exhausted"

    config_error = ContentClientConfigurationError("Bad config")
    diagnosis = client.diagnose_error(config_error)
    assert diagnosis["issue"] == "Configuration error"

    generic_error = Exception("Unknown")
    diagnosis = client.diagnose_error(generic_error)
    assert diagnosis["issue"] == "Unexpected error"

    client.close()


# =============================================================================
# OAuth2 Handler Tests
# =============================================================================


@respx.mock
def test_oauth2_token_persistence():
    """Test OAuth2 token persistence to context."""
    # Mock token endpoint
    token_url = "https://api.example.com/oauth/token"
    respx.post(token_url).mock(
        return_value=Response(
            200,
            json={
                "access_token": "test_token",
                "expires_in": 3600,
            },
        )
    )

    # Create OAuth2 handler with context store
    context_store = ContentClientContextStore("TestClient")
    auth = OAuth2ClientCredentialsHandler(
        token_url=token_url,
        client_id="test_client",
        client_secret="test_secret",
        context_store=context_store,
    )

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=auth,
    )

    # Mock API endpoint
    respx.get("https://api.example.com/v1/events").mock(return_value=Response(200, json={"data": []}))

    # Make request to trigger token fetch
    client.get("/v1/events")

    # Verify token was persisted
    stored = context_store.read()
    assert "oauth2_token" in stored
    assert stored["oauth2_token"]["access_token"] == "test_token"

    client.close()


@respx.mock
def test_oauth2_missing_access_token():
    """Test OAuth2 handler when token response is missing access_token."""
    # Mock token endpoint returning response without access_token
    respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"expires_in": 3600})  # Missing access_token
    )

    context_store = ContentClientContextStore("TestClient")
    auth = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="test_client",
        client_secret="test_secret",
        context_store=context_store,
    )

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=auth,
    )

    # Mock API endpoint
    respx.get("https://api.example.com/v1/events").mock(return_value=Response(200, json={"data": {"events": []}}))
    with pytest.raises(ContentClientAuthenticationError, match="access_token"):
        client.get("/v1/events")


@respx.mock
def test_oauth2_network_error():
    """Test OAuth2 handler when token endpoint is unreachable."""
    # Mock token endpoint with network error
    respx.post("https://auth.example.com/token").mock(side_effect=httpx.ConnectError("Connection refused"))

    context_store = ContentClientContextStore("TestClient")
    auth = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="test_client",
        client_secret="test_secret",
        context_store=context_store,
    )

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=auth,
    )

    with pytest.raises(Exception):  # Network error propagates
        client.get("/v1/events")


@respx.mock
def test_oauth2_malformed_json():
    """Test OAuth2 handler when token response is malformed JSON."""
    # Mock token endpoint returning invalid JSON
    respx.post("https://auth.example.com/token").mock(return_value=Response(200, text="not json"))

    context_store = ContentClientContextStore("TestClient")
    auth = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="test_client",
        client_secret="test_secret",
        context_store=context_store,
    )

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=auth,
    )

    with pytest.raises(Exception):  # JSON decode error
        client.get("/v1/events")


@respx.mock
def test_oauth2_with_auth_params():
    """Test OAuth2ClientCredentialsHandler with additional auth_params."""
    # Mock token endpoint
    token_route = respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"access_token": "test_token", "expires_in": 3600})
    )

    # Mock API endpoint
    respx.get("https://api.example.com/v1/events").mock(
        return_value=Response(200, json={"data": {"events": []}, "meta": {"next_cursor": None}})
    )

    context_store = ContentClientContextStore("TestClient")
    auth = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="test_client",
        client_secret="test_secret",
        auth_params={"custom_param": "custom_value"},
        context_store=context_store,
    )

    client = ContentClient(
        base_url="https://api.example.com",
        auth_handler=auth,
    )

    client.get("/v1/events")

    # Verify custom param was sent in token request
    assert token_route.called
    # The request body should contain the custom param
    request_content = token_route.calls[0].request.content.decode()
    assert "custom_param" in request_content


# =============================================================================
# Integration Context Store Tests
# =============================================================================


def test_content_client_context_store_retry_on_failure(mocker):
    """Test ContentClientContextStore retry logic on write failure."""
    store = ContentClientContextStore("TestClient")

    # Mock setIntegrationContext to fail twice then succeed
    call_count = 0

    def mock_set_context(value):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise Exception("Temporary failure")

    mocker.patch.object(demisto, "setIntegrationContext", side_effect=mock_set_context)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})

    # Should retry and eventually succeed
    store.write({"test": "data"})
    assert call_count == 3


def test_content_client_context_store_retry_exhausted(mocker):
    """Test ContentClientContextStore when all retries are exhausted."""
    store = ContentClientContextStore("TestClient")

    # Mock setIntegrationContext to always fail
    mocker.patch.object(demisto, "setIntegrationContext", side_effect=Exception("Persistent failure"))
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})

    # Should raise after exhausting retries
    with pytest.raises(Exception, match="Persistent failure"):
        store.write({"test": "data"})


# =============================================================================
# ContentClient Logger Tests
# =============================================================================


def test_content_client_logger_format_with_extra():
    """Test ContentClientLogger._format with extra data."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=False)

    # Test without extra
    formatted = logger._format("INFO", "Test message", None)
    assert formatted == "[ContentClient:TestClient:INFO] Test message"

    # Test with extra
    extra = {"key": "value", "count": 42}
    formatted = logger._format("ERROR", "Error occurred", extra)
    assert "[ContentClient:TestClient:ERROR] Error occurred" in formatted
    assert "extra=" in formatted
    assert "key" in formatted


def test_content_client_logger_format_with_non_serializable():
    """Test ContentClientLogger._format with non-JSON-serializable extra."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=False)

    # Create a non-serializable object
    class NonSerializable:
        def __repr__(self):
            return "NonSerializable()"

    extra = {"obj": NonSerializable()}
    formatted = logger._format("INFO", "Test message", extra)

    # Should fall back to str() representation
    assert "NonSerializable" in formatted


def test_content_client_logger_trace_error():
    """Test ContentClientLogger trace_error method."""
    from ContentClientApiModule import RequestTrace

    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    trace = RequestTrace(
        method="GET",
        url="https://api.example.com/test",
        headers={},
        params={},
        body=None,
        timestamp=0.0,
    )

    logger.trace_error(trace, "Test error", elapsed_ms=100.0)

    assert trace.error == "Test error"
    assert trace.elapsed_ms == 100.0


def test_content_client_logger_warning():
    """Test ContentClientLogger warning method."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Warning should not raise
    logger.warning("Test warning", extra={"key": "value"})


# =============================================================================
# Diagnostic Report Tests
# =============================================================================


def test_diagnostic_report_recommendations():
    """Test diagnostic report generates appropriate recommendations."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Add various errors
    logger.error("Auth failed", extra={"error_type": "auth"})
    logger.error("Rate limited", extra={"error_type": "rate_limit"})
    logger.error("Timeout", extra={"error_type": "timeout"})
    logger.error("Network error", extra={"error_type": "network"})

    # Add slow request times
    logger._performance["request_times"] = [6000, 7000, 8000]  # > 5000ms

    # Add many retries (need more than 50% to trigger recommendation)
    for i in range(10):
        trace = logger.trace_request("GET", "https://api.example.com/test", {}, {}, retry_attempt=i)
        logger.trace_response(trace, 200, {}, {}, 6000)

    report = logger.get_diagnostic_report({}, [])

    # Verify recommendations exist
    assert len(report.recommendations) > 0
    # Check for specific recommendations based on errors
    rec_text = " ".join(report.recommendations).lower()
    assert "authentication" in rec_text or "auth" in rec_text
    assert "rate" in rec_text
    assert "timeout" in rec_text
    assert "network" in rec_text
    assert "slow" in rec_text or "request" in rec_text


@respx.mock
def test_diagnostic_mode_trace_limit():
    """Test that diagnostic mode limits trace history to 1000 entries."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Add more than 1000 traces
    for i in range(1100):
        trace = logger.trace_request("GET", f"https://api.example.com/test/{i}", {}, {})
        logger.trace_response(trace, 200, {}, {}, 100)

    # Verify trace limit
    report = logger.get_diagnostic_report({}, [])
    assert len(report.request_traces) <= 1000


@respx.mock
def test_diagnostic_mode_non_json_response():
    """Test diagnostic mode handles non-JSON responses."""
    respx.get("https://api.example.com/v1/events").mock(return_value=Response(200, text="<html>Not JSON</html>"))

    client = ContentClient(
        base_url="https://api.example.com",
        diagnostic_mode=True,
    )

    # Make request
    client.get("/v1/events")

    # Get diagnostic report
    report = client.get_diagnostic_report()

    # Verify trace captured response
    assert len(report.request_traces) > 0
    trace = report.request_traces[0]
    assert trace.response_body is not None
    assert "html" in str(trace.response_body).lower()

    client.close()


@respx.mock
def test_close_with_exception(mocker):
    """Test that close() handles exceptions gracefully."""
    # First make a request to initialize the client
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")
    client.get("/v1/data")  # This initializes the async client

    # Now the client should have an async client to close
    # Mock aclose to raise exception
    async def mock_aclose():
        raise Exception("Close failed")

    # Get the actual async client that was created
    async_client = client._get_async_client()
    mocker.patch.object(async_client, "aclose", side_effect=mock_aclose)

    # Should not raise exception
    client.close()


# =============================================================================
# Context Manager Tests
# =============================================================================


@respx.mock
def test_content_client_context_manager():
    """Test ContentClient as a context manager."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    with ContentClient(base_url="https://api.example.com") as client:
        response = client.get("/v1/data")
        assert response.status_code == 200

    assert route.called


@respx.mock
@pytest.mark.asyncio
async def test_content_client_async_context_manager():
    """Test ContentClient as an async context manager."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    async with ContentClient(base_url="https://api.example.com") as client:
        response = await client._request("GET", "/v1/data")
        assert response.status_code == 200

    assert route.called


def test_content_client_double_close():
    """Test that closing a client twice doesn't cause issues."""
    client = ContentClient(base_url="https://api.example.com")

    # Close twice - should not raise
    client.close()
    client.close()


# =============================================================================
# Thread Safety Tests
# =============================================================================


def test_circuit_breaker_thread_safety():
    """Test CircuitBreaker is thread-safe."""
    import threading
    import time

    policy = CircuitBreakerPolicy(failure_threshold=100, recovery_timeout=1.0)
    breaker = CircuitBreaker(policy)

    errors = []

    def record_failures():
        try:
            for _ in range(50):
                breaker.record_failure()
                time.sleep(0.001)
        except Exception as e:
            errors.append(e)

    def record_successes():
        try:
            for _ in range(50):
                breaker.record_success()
                time.sleep(0.001)
        except Exception as e:
            errors.append(e)

    def check_execute():
        try:
            for _ in range(50):
                breaker.can_execute()
                time.sleep(0.001)
        except Exception as e:
            errors.append(e)

    threads = [
        threading.Thread(target=record_failures),
        threading.Thread(target=record_successes),
        threading.Thread(target=check_execute),
        threading.Thread(target=record_failures),
        threading.Thread(target=record_successes),
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # No errors should have occurred
    assert len(errors) == 0


# =============================================================================
# Sensitive Header Redaction Tests
# =============================================================================


def test_trace_request_redacts_sensitive_headers():
    """Test that trace_request redacts sensitive headers."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    headers = {
        "Authorization": "Bearer secret_token",
        "X-API-Key": "api_key_value",
        "Content-Type": "application/json",
        "Api-Key": "another_key",
    }

    trace = logger.trace_request(
        method="GET",
        url="https://api.example.com/test",
        headers=headers,
        params={},
    )

    # Sensitive headers should be redacted
    assert trace.headers["Authorization"] == "***REDACTED***"
    assert trace.headers["X-API-Key"] == "***REDACTED***"
    assert trace.headers["Api-Key"] == "***REDACTED***"

    # Non-sensitive headers should be preserved
    assert trace.headers["Content-Type"] == "application/json"


# =============================================================================
# Instance ok_codes Tests
# =============================================================================


@respx.mock
def test_content_client_uses_instance_ok_codes():
    """Test ContentClient uses instance ok_codes when request ok_codes not provided."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(201, json={"created": True}))

    # Create client with ok_codes that includes 201
    client = ContentClient(
        base_url="https://api.example.com",
        ok_codes=(200, 201, 204),
    )

    # Request without ok_codes should use instance ok_codes
    result = client._http_request("GET", "/v1/data", resp_type="json")

    assert route.called
    assert result == {"created": True}

    client.close()


# =============================================================================
# Additional Coverage Tests
# =============================================================================


def test_extract_list_with_custom_object():
    """Test _extract_list with a custom object type."""

    class CustomObj:
        pass

    obj = CustomObj()
    result = _extract_list(obj, None)
    assert result == [obj]


def test_create_rate_limiter_none_policy():
    """Test _create_rate_limiter with None policy."""
    result = _create_rate_limiter(None)
    assert result is None


def test_create_rate_limiter_disabled_policy():
    """Test _create_rate_limiter with disabled policy."""
    policy = RateLimitPolicy(rate_per_second=0.0)
    result = _create_rate_limiter(policy)
    assert result is None


def test_create_rate_limiter_enabled_policy():
    """Test _create_rate_limiter with enabled policy."""
    policy = RateLimitPolicy(rate_per_second=10.0)
    result = _create_rate_limiter(policy)
    assert result is not None
    assert isinstance(result, TokenBucketRateLimiter)


@pytest.mark.asyncio
async def test_token_bucket_rate_limiter_zero_rate():
    """Test TokenBucketRateLimiter raises error when rate is zero."""
    # Create a policy with rate_per_second > 0 to pass enabled check
    policy = RateLimitPolicy(rate_per_second=0.001, burst=1)
    limiter = TokenBucketRateLimiter(policy)

    # Consume the token
    await limiter.acquire()

    # Now set rate to 0 to trigger the error path
    limiter.policy = RateLimitPolicy(rate_per_second=0.0, burst=1)

    with pytest.raises(ContentClientConfigurationError, match="rate_per_second must be positive"):
        await limiter.acquire()


def test_token_bucket_refill_no_time_elapsed():
    """Test TokenBucketRateLimiter refill when no time has elapsed."""
    import time

    policy = RateLimitPolicy(rate_per_second=10.0, burst=5)
    limiter = TokenBucketRateLimiter(policy)

    # Force the updated time to be in the future to trigger delta <= 0
    limiter._updated = time.monotonic() + 1000

    # This should not add tokens since delta <= 0
    initial_tokens = limiter._tokens
    limiter._refill_locked()  # Now synchronous, no await needed
    assert limiter._tokens == initial_tokens


def test_auth_handler_abstract_methods():
    """Test AuthHandler abstract methods raise NotImplementedError."""
    import asyncio

    handler = AuthHandler()

    # on_request should raise NotImplementedError
    async def test_on_request():
        with pytest.raises(NotImplementedError):
            await handler.on_request(None, None)

    asyncio.run(test_on_request())


@pytest.mark.asyncio
async def test_auth_handler_on_auth_failure_default():
    """Test AuthHandler.on_auth_failure returns False by default."""
    handler = AuthHandler()
    result = await handler.on_auth_failure(None, None)
    assert result is False


def test_api_key_auth_empty_key():
    """Test APIKeyAuthHandler raises error for empty key."""
    with pytest.raises(ContentClientConfigurationError, match="non-empty key"):
        APIKeyAuthHandler("", header_name="X-API-Key")


def test_bearer_token_auth_empty_token():
    """Test BearerTokenAuthHandler raises error for empty token."""
    with pytest.raises(ContentClientConfigurationError, match="non-empty token"):
        BearerTokenAuthHandler("")


def test_basic_auth_empty_username():
    """Test BasicAuthHandler raises error for empty username."""
    with pytest.raises(ContentClientConfigurationError, match="non-empty username"):
        BasicAuthHandler("", "password")


def test_oauth2_empty_token_url():
    """Test OAuth2ClientCredentialsHandler raises error for empty token_url."""
    with pytest.raises(ContentClientConfigurationError, match="non-empty token_url"):
        OAuth2ClientCredentialsHandler(token_url="", client_id="client", client_secret="secret")


def test_oauth2_empty_client_id():
    """Test OAuth2ClientCredentialsHandler raises error for empty client_id."""
    with pytest.raises(ContentClientConfigurationError, match="non-empty client_id"):
        OAuth2ClientCredentialsHandler(token_url="https://auth.example.com/token", client_id="", client_secret="secret")


def test_oauth2_empty_client_secret():
    """Test OAuth2ClientCredentialsHandler raises error for empty client_secret."""
    with pytest.raises(ContentClientConfigurationError, match="non-empty client_secret"):
        OAuth2ClientCredentialsHandler(token_url="https://auth.example.com/token", client_id="client", client_secret="")


def test_oauth2_loads_cached_token(mocker):
    """Test OAuth2ClientCredentialsHandler loads cached token from context store."""
    import time

    # Create a mock context store with a valid cached token
    mock_store = mocker.Mock()
    mock_store.read.return_value = {
        "oauth2_token": {
            "access_token": "cached_token",
            "expires_at": time.monotonic() + 3600,  # Valid for 1 hour
        }
    }

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret", context_store=mock_store
    )

    assert handler._access_token == "cached_token"


def test_oauth2_ignores_expired_cached_token(mocker):
    """Test OAuth2ClientCredentialsHandler ignores expired cached token."""
    import time

    # Create a mock context store with an expired cached token
    mock_store = mocker.Mock()
    mock_store.read.return_value = {
        "oauth2_token": {
            "access_token": "expired_token",
            "expires_at": time.monotonic() - 100,  # Expired
        }
    }

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret", context_store=mock_store
    )

    # Should not load expired token
    assert handler._access_token is None


def test_oauth2_handles_cache_read_error(mocker):
    """Test OAuth2ClientCredentialsHandler handles cache read errors gracefully."""
    # Create a mock context store that raises an error
    mock_store = mocker.Mock()
    mock_store.read.side_effect = Exception("Cache read failed")

    # Should not raise, just log and continue
    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret", context_store=mock_store
    )

    assert handler._access_token is None


@respx.mock
def test_oauth2_with_scope_and_audience():
    """Test OAuth2ClientCredentialsHandler with scope and audience."""
    token_route = respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"access_token": "test_token", "expires_in": 3600})
    )
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token",
        client_id="client",
        client_secret="secret",
        scope="read write",
        audience="https://api.example.com",
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    client.get("/v1/data")

    # Verify scope and audience were sent
    assert token_route.called
    request_content = token_route.calls[0].request.content.decode()
    assert "scope" in request_content
    assert "audience" in request_content

    client.close()


@respx.mock
def test_oauth2_token_persistence_failure(mocker):
    """Test OAuth2 handles token persistence failure gracefully."""
    respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"access_token": "test_token", "expires_in": 3600})
    )
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    # Create a mock context store that fails on write
    mock_store = mocker.Mock()
    mock_store.read.return_value = {}
    mock_store.write.side_effect = Exception("Write failed")

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret", context_store=mock_store
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    # Should not raise even though persistence fails
    result = client.get("/v1/data")
    assert result.status_code == 200

    client.close()


@respx.mock
def test_oauth2_http_status_error():
    """Test OAuth2 handles HTTP status error during token refresh."""
    respx.post("https://auth.example.com/token").mock(return_value=Response(401, json={"error": "invalid_client"}))

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret"
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    with pytest.raises(ContentClientAuthenticationError, match="Token refresh failed"):
        client.get("/v1/data")


@respx.mock
def test_oauth2_timeout_error():
    """Test OAuth2 handles timeout during token refresh."""
    respx.post("https://auth.example.com/token").mock(side_effect=httpx.TimeoutException("Connection timed out"))

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret", token_timeout=0.1
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    with pytest.raises(ContentClientAuthenticationError, match="timed out"):
        client.get("/v1/data")


@respx.mock
def test_api_key_auth_query_param():
    """Test APIKeyAuthHandler adds key to query parameter."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(
        base_url="https://api.example.com", auth_handler=APIKeyAuthHandler(key="secret_key", query_param="api_key")
    )

    client.get("/v1/data")

    assert route.called
    # Check that the query param was added
    request_url = str(route.calls[0].request.url)
    assert "api_key=secret_key" in request_url

    client.close()


@respx.mock
def test_content_client_with_proxy(mocker):
    """Test ContentClient with proxy enabled."""
    mocker.patch("ContentClientApiModule.ensure_proxy_has_http_prefix")

    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com", proxy=True)

    client.get("/v1/data")
    assert route.called

    client.close()


@respx.mock
def test_content_client_without_verify(mocker):
    """Test ContentClient with SSL verification disabled."""
    mocker.patch("ContentClientApiModule.skip_cert_verification")

    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com", verify=False)

    client.get("/v1/data")
    assert route.called

    client.close()


@respx.mock
def test_content_client_post_method():
    """Test ContentClient POST method."""
    route = respx.post("https://api.example.com/v1/data").mock(return_value=Response(201, json={"created": True}))

    client = ContentClient(base_url="https://api.example.com", ok_codes=(201,))

    response = client.post("/v1/data", json_data={"name": "test"})

    assert route.called
    assert response.status_code == 201

    client.close()


@respx.mock
def test_content_client_put_method():
    """Test ContentClient PUT method."""
    route = respx.put("https://api.example.com/v1/data").mock(return_value=Response(200, json={"updated": True}))

    client = ContentClient(base_url="https://api.example.com")

    response = client.put("/v1/data", json_data={"name": "test"})

    assert route.called
    assert response.status_code == 200

    client.close()


@respx.mock
def test_content_client_delete_method():
    """Test ContentClient DELETE method."""
    route = respx.delete("https://api.example.com/v1/data").mock(return_value=Response(204))

    client = ContentClient(base_url="https://api.example.com", ok_codes=(204,))

    response = client.delete("/v1/data")

    assert route.called
    assert response.status_code == 204

    client.close()


@respx.mock
def test_content_client_metrics_property():
    """Test ContentClient metrics property."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    client.get("/v1/data")

    metrics = client.metrics
    assert metrics.success == 1

    client.close()


@respx.mock
def test_content_client_401_with_auth_handler_retry():
    """Test ContentClient retries on 401 when auth handler returns True."""
    # First call returns 401, second returns 200
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[Response(401, json={"error": "Unauthorized"}), Response(200, json={"result": "success"})]
    )
    respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"access_token": "new_token", "expires_in": 3600})
    )

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret"
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    result = client._http_request("GET", "/v1/data", resp_type="json")
    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_circuit_breaker_open():
    """Test ContentClient raises error when circuit breaker is open."""
    client = ContentClient(
        base_url="https://api.example.com", circuit_breaker=CircuitBreakerPolicy(failure_threshold=1, recovery_timeout=60.0)
    )

    # Record a failure to open the circuit
    client._circuit_breaker.record_failure()

    with pytest.raises(ContentClientCircuitOpenError):
        client.get("/v1/data")

    client.close()


@respx.mock
def test_content_client_retryable_status_code():
    """Test ContentClient retries on retryable status codes."""
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[Response(503, text="Service Unavailable"), Response(200, json={"result": "success"})]
    )

    client = ContentClient(
        base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02)
    )

    result = client._http_request("GET", "/v1/data", resp_type="json")
    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_403_error():
    """Test ContentClient handles 403 Forbidden error."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(403, text="Forbidden"))

    client = ContentClient(base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=1))

    with pytest.raises(ContentClientAuthenticationError, match="Authentication failed"):
        client.get("/v1/data")

    client.close()


@respx.mock
def test_content_client_500_error():
    """Test ContentClient handles 500 Internal Server Error."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(500, text="Internal Server Error"))

    client = ContentClient(base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=1))

    with pytest.raises(ContentClientError, match="Request failed"):
        client.get("/v1/data")

    client.close()


@respx.mock
def test_content_client_general_exception():
    """Test ContentClient handles general exceptions."""
    respx.get("https://api.example.com/v1/data").mock(side_effect=Exception("Unexpected error"))

    client = ContentClient(base_url="https://api.example.com", diagnostic_mode=True)

    with pytest.raises(Exception, match="Unexpected error"):
        client.get("/v1/data")

    assert client.execution_metrics.general_error == 1

    client.close()


@respx.mock
def test_content_client_with_full_url():
    """Test ContentClient with full_url parameter."""
    route = respx.get("https://other.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    result = client._http_request("GET", full_url="https://other.example.com/v1/data", resp_type="json")

    assert route.called
    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_with_custom_headers():
    """Test ContentClient with custom headers."""
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com", headers={"X-Custom-Header": "custom_value"})

    client.get("/v1/data", headers={"X-Request-Header": "request_value"})

    assert route.called
    sent_headers = route.calls[0].request.headers
    assert sent_headers.get("X-Custom-Header") == "custom_value"
    assert sent_headers.get("X-Request-Header") == "request_value"

    client.close()


def test_content_client_health_check_with_general_error():
    """Test ContentClient health_check with general errors."""
    client = ContentClient(base_url="https://api.example.com")

    # Simulate general error
    client.execution_metrics.general_error = 1

    health = client.health_check()

    assert health["status"] == "degraded"
    assert any("general" in w.lower() for w in health["warnings"])

    client.close()


def test_content_client_health_check_with_auth_error():
    """Test ContentClient health_check with auth errors."""
    client = ContentClient(base_url="https://api.example.com")

    # Simulate auth error
    client.execution_metrics.auth_error = 1

    health = client.health_check()

    assert health["status"] == "degraded"
    assert any("authentication" in w.lower() for w in health["warnings"])

    client.close()


@respx.mock
def test_content_client_json_decode_error_with_content():
    """Test ContentClient raises JSONDecodeError when content is not valid JSON."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, text="not valid json"))

    client = ContentClient(base_url="https://api.example.com")

    with pytest.raises(json.JSONDecodeError):
        client._http_request("GET", "/v1/data", resp_type="json")

    client.close()


@respx.mock
def test_content_client_default_json_response():
    """Test ContentClient returns JSON by default when resp_type not specified in request_sync."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    # Call request_sync directly without resp_type
    result = client.request_sync(method="GET", url_suffix="/v1/data")

    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_retries_exhausted():
    """Test ContentClient raises ContentClientRetryError when retries are exhausted."""
    respx.get("https://api.example.com/v1/data").mock(side_effect=httpx.ConnectError("Connection refused"))

    client = ContentClient(
        base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=2, initial_delay=0.01, max_delay=0.02)
    )

    with pytest.raises(ContentClientRetryError, match="Exceeded retry attempts"):
        client.get("/v1/data")

    client.close()


@respx.mock
def test_content_client_with_retries_param():
    """Test ContentClient with retries parameter (BaseClient compatibility)."""
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[httpx.ConnectError("Connection refused"), Response(200, json={"result": "success"})]
    )

    client = ContentClient(base_url="https://api.example.com")

    # Use retries param instead of retry_policy
    result = client._http_request("GET", "/v1/data", resp_type="json", retries=2, status_list_to_retry=[503])

    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_429_retry():
    """Test ContentClient retries on 429 rate limit error."""
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[Response(429, text="Rate limited", headers={"Retry-After": "1"}), Response(200, json={"result": "success"})]
    )

    client = ContentClient(
        base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02)
    )

    result = client._http_request("GET", "/v1/data", resp_type="json")
    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_401_retry_with_status_list():
    """Test ContentClient retries on 401 when in status_list_to_retry."""
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[Response(401, text="Unauthorized"), Response(200, json={"result": "success"})]
    )

    client = ContentClient(
        base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02)
    )

    # Include 401 in status_list_to_retry
    result = client._http_request("GET", "/v1/data", resp_type="json", status_list_to_retry=[401, 503])

    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_500_retry_with_status_list():
    """Test ContentClient retries on 500 when in status_list_to_retry."""
    respx.get("https://api.example.com/v1/data").mock(
        side_effect=[Response(500, text="Internal Server Error"), Response(200, json={"result": "success"})]
    )

    client = ContentClient(
        base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02)
    )

    result = client._http_request("GET", "/v1/data", resp_type="json")
    assert result == {"result": "success"}

    client.close()


@respx.mock
def test_content_client_diagnostic_mode_http_error():
    """Test ContentClient diagnostic mode captures HTTP errors."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(400, json={"error": "Bad Request"}))

    client = ContentClient(base_url="https://api.example.com", diagnostic_mode=True, retry_policy=RetryPolicy(max_attempts=1))

    with pytest.raises(ContentClientError):
        client.get("/v1/data")

    # Verify diagnostic report captured the error
    report = client.get_diagnostic_report()
    assert len(report.request_traces) > 0
    trace = report.request_traces[0]
    assert trace.response_status == 400

    client.close()


# =============================================================================
# Sequential Synchronous Request Tests
# =============================================================================


@respx.mock
def test_sequential_sync_requests():
    """Test that multiple sequential synchronous requests work correctly.

    This tests the fix for httpx.AsyncClient reuse across event loops.
    Each call to request_sync creates a new event loop, so the client
    must handle this correctly.
    """
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    # Make multiple sequential synchronous requests
    for _i in range(3):
        result = client._http_request("GET", "/v1/data", resp_type="json")
        assert result == {"result": "success"}

    assert route.call_count == 3
    client.close()


@respx.mock
def test_sequential_sync_requests_with_different_endpoints():
    """Test sequential sync requests to different endpoints."""
    route1 = respx.get("https://api.example.com/v1/users").mock(return_value=Response(200, json={"users": []}))
    route2 = respx.get("https://api.example.com/v1/events").mock(return_value=Response(200, json={"events": []}))
    route3 = respx.post("https://api.example.com/v1/data").mock(return_value=Response(201, json={"created": True}))

    client = ContentClient(base_url="https://api.example.com", ok_codes=(200, 201))

    # Make sequential requests to different endpoints
    result1 = client._http_request("GET", "/v1/users", resp_type="json")
    assert result1 == {"users": []}

    result2 = client._http_request("GET", "/v1/events", resp_type="json")
    assert result2 == {"events": []}

    result3 = client._http_request("POST", "/v1/data", json_data={"key": "value"}, resp_type="json")
    assert result3 == {"created": True}

    assert route1.called
    assert route2.called
    assert route3.called

    client.close()


@respx.mock
def test_sequential_sync_requests_with_auth():
    """Test sequential sync requests with OAuth2 authentication."""
    # Mock token endpoint
    respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"access_token": "test_token", "expires_in": 3600})
    )

    # Mock API endpoint
    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret"
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    # Make multiple sequential requests - token should be reused
    for _ in range(3):
        result = client._http_request("GET", "/v1/data", resp_type="json")
        assert result == {"result": "success"}

    assert route.call_count == 3
    client.close()


@respx.mock
def test_sequential_sync_requests_with_rate_limiter():
    """Test sequential sync requests with rate limiting."""
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com", rate_limiter=RateLimitPolicy(rate_per_second=100.0, burst=10))

    # Make multiple sequential requests
    for _ in range(5):
        result = client._http_request("GET", "/v1/data", resp_type="json")
        assert result == {"result": "success"}

    client.close()


@respx.mock
def test_sequential_sync_requests_with_retries():
    """Test sequential sync requests with retry logic."""
    # First request fails, second succeeds
    route = respx.get("https://api.example.com/v1/data").mock(
        side_effect=[
            httpx.ConnectError("Connection refused"),
            Response(200, json={"result": "success"}),
            Response(200, json={"result": "success"}),
        ]
    )

    client = ContentClient(
        base_url="https://api.example.com", retry_policy=RetryPolicy(max_attempts=3, initial_delay=0.01, max_delay=0.02)
    )

    # First request should retry and succeed
    result1 = client._http_request("GET", "/v1/data", resp_type="json")
    assert result1 == {"result": "success"}

    # Second request should succeed immediately
    result2 = client._http_request("GET", "/v1/data", resp_type="json")
    assert result2 == {"result": "success"}

    # Verify the route was called 3 times (1 failure + 2 successes)
    assert route.call_count == 3

    client.close()


# =============================================================================
# Circuit Breaker Half-Open State Tests
# =============================================================================


def test_circuit_breaker_half_open_state():
    """Test circuit breaker enters half-open state after recovery timeout."""
    import time

    policy = CircuitBreakerPolicy(failure_threshold=2, recovery_timeout=0.1)
    breaker = CircuitBreaker(policy)

    # Record failures to open circuit
    breaker.record_failure()
    breaker.record_failure()

    # Circuit should be open
    assert not breaker.can_execute()

    # Wait for recovery timeout
    time.sleep(0.15)

    # First call should succeed (half-open, probe allowed)
    assert breaker.can_execute()

    # Second call should fail (already in half-open, probe in progress)
    assert not breaker.can_execute()


def test_circuit_breaker_half_open_success_closes():
    """Test circuit breaker closes after successful probe in half-open state."""
    import time

    policy = CircuitBreakerPolicy(failure_threshold=2, recovery_timeout=0.1)
    breaker = CircuitBreaker(policy)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert not breaker.can_execute()

    # Wait for recovery timeout
    time.sleep(0.15)

    # Enter half-open state
    assert breaker.can_execute()

    # Record success - should close the circuit
    breaker.record_success()

    # Circuit should be fully closed now
    assert breaker.can_execute()
    assert breaker.can_execute()  # Multiple calls should work


def test_circuit_breaker_half_open_failure_reopens():
    """Test circuit breaker re-opens after failed probe in half-open state."""
    import time

    policy = CircuitBreakerPolicy(failure_threshold=2, recovery_timeout=0.1)
    breaker = CircuitBreaker(policy)

    # Open the circuit
    breaker.record_failure()
    breaker.record_failure()
    assert not breaker.can_execute()

    # Wait for recovery timeout
    time.sleep(0.15)

    # Enter half-open state
    assert breaker.can_execute()

    # Record failure - should re-open the circuit
    breaker.record_failure()

    # Circuit should be open again
    assert not breaker.can_execute()


# =============================================================================
# Thread Safety Tests for Token Bucket Rate Limiter
# =============================================================================


def test_token_bucket_rate_limiter_thread_safety():
    """Test TokenBucketRateLimiter is thread-safe."""
    import threading
    import asyncio

    policy = RateLimitPolicy(rate_per_second=100.0, burst=50)
    limiter = TokenBucketRateLimiter(policy)

    errors = []
    acquired_count = [0]
    lock = threading.Lock()

    def acquire_tokens():
        try:
            for _ in range(10):
                asyncio.run(limiter.acquire())
                with lock:
                    acquired_count[0] += 1
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=acquire_tokens) for _ in range(5)]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # No errors should have occurred
    assert len(errors) == 0
    # All tokens should have been acquired
    assert acquired_count[0] == 50


# =============================================================================
# OAuth2 Thread Safety Tests
# =============================================================================


@respx.mock
def test_oauth2_concurrent_token_refresh():
    """Test OAuth2 handler handles concurrent token refresh safely."""
    import threading

    # Mock token endpoint - should only be called once due to locking
    respx.post("https://auth.example.com/token").mock(
        return_value=Response(200, json={"access_token": "test_token", "expires_in": 3600})
    )

    # Mock API endpoint
    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    handler = OAuth2ClientCredentialsHandler(
        token_url="https://auth.example.com/token", client_id="client", client_secret="secret"
    )

    client = ContentClient(base_url="https://api.example.com", auth_handler=handler)

    errors = []

    def make_request():
        try:
            client._http_request("GET", "/v1/data", resp_type="json")
        except Exception as e:
            errors.append(e)

    # Start multiple threads that will all try to refresh the token
    threads = [threading.Thread(target=make_request) for _ in range(5)]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # No errors should have occurred
    assert len(errors) == 0

    client.close()


# =============================================================================
# Context Store Thread Safety Tests
# =============================================================================


def test_context_store_thread_safety(mocker):
    """Test ContentClientContextStore is thread-safe."""
    import threading

    store = ContentClientContextStore("TestClient")

    # Track all writes
    writes = []
    write_lock = threading.Lock()

    def mock_set_context(value):
        with write_lock:
            writes.append(value.copy())

    mocker.patch.object(demisto, "setIntegrationContext", side_effect=mock_set_context)
    mocker.patch.object(demisto, "getIntegrationContext", return_value={})

    errors = []

    def write_data(thread_id):
        try:
            for i in range(5):
                store.write({"thread": thread_id, "iteration": i})
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=write_data, args=(i,)) for i in range(3)]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # No errors should have occurred
    assert len(errors) == 0
    # All writes should have completed
    assert len(writes) == 15  # 3 threads * 5 iterations


# =============================================================================
# Additional Test Coverage (PR Review Comment #2)
# =============================================================================


def test_now_utility_function():
    """Test _now() utility function returns monotonic time."""
    import time

    # _now() should return a float representing monotonic time
    t1 = _now()
    time.sleep(0.01)
    t2 = _now()

    assert isinstance(t1, float)
    assert isinstance(t2, float)
    assert t2 > t1  # Time should increase


def test_structured_log_entry_to_dict():
    """Test StructuredLogEntry.to_dict() method."""
    entry = StructuredLogEntry(
        severity="INFO", message="Test message", client_name="TestClient", request_id="abc-123", custom_field="custom_value"
    )

    result = entry.to_dict()

    assert result["severity"] == "INFO"
    assert result["message"] == "Test message"
    assert result["labels"]["client_name"] == "TestClient"
    assert result["labels"]["request_id"] == "abc-123"
    assert result["custom_field"] == "custom_value"
    assert "timestamp" in result


def test_structured_log_entry_with_http_request():
    """Test StructuredLogEntry with http_request field."""
    http_request = {"requestMethod": "GET", "requestUrl": "https://example.com"}
    entry = StructuredLogEntry(severity="INFO", message="HTTP request", client_name="TestClient", http_request=http_request)

    result = entry.to_dict()

    assert result["httpRequest"] == http_request


def test_structured_log_entry_with_error():
    """Test StructuredLogEntry with error field."""
    error_info = {"type": "TestError", "message": "Test error message"}
    entry = StructuredLogEntry(severity="ERROR", message="Error occurred", client_name="TestClient", error=error_info)

    result = entry.to_dict()

    assert result["error"] == error_info


def test_structured_log_entry_with_labels():
    """Test StructuredLogEntry with additional labels."""
    entry = StructuredLogEntry(severity="INFO", message="Test", client_name="TestClient", labels={"custom_label": "value"})

    result = entry.to_dict()

    assert result["labels"]["custom_label"] == "value"
    assert result["labels"]["client_name"] == "TestClient"


def test_create_http_request_log_basic():
    """Test create_http_request_log with basic parameters."""
    result = create_http_request_log(method="GET", url="https://api.example.com/v1/data")

    assert result["requestMethod"] == "GET"
    assert result["requestUrl"] == "https://api.example.com/v1/data"


def test_create_http_request_log_full():
    """Test create_http_request_log with all parameters."""
    result = create_http_request_log(
        method="POST",
        url="https://api.example.com/v1/data",
        status=201,
        latency_ms=150.0,  # Use exact value to avoid floating point issues
        request_size=1024,
        response_size=2048,
        user_agent="TestAgent/1.0",
    )

    assert result["requestMethod"] == "POST"
    assert result["requestUrl"] == "https://api.example.com/v1/data"
    assert result["status"] == 201
    assert result["latency"] == "0.150s"  # 150.0ms / 1000
    assert result["requestSize"] == "1024"
    assert result["responseSize"] == "2048"
    assert result["userAgent"] == "TestAgent/1.0"


def test_create_error_log_basic():
    """Test create_error_log with basic parameters."""
    result = create_error_log(error_type="TestError", error_message="Something went wrong")

    assert result["type"] == "TestError"
    assert result["message"] == "Something went wrong"
    assert "stackTrace" not in result
    assert "code" not in result


def test_create_error_log_full():
    """Test create_error_log with all parameters."""
    result = create_error_log(
        error_type="NetworkError",
        error_message="Connection refused",
        stack_trace="Traceback (most recent call last):\n  File ...",
        error_code="ECONNREFUSED",
    )

    assert result["type"] == "NetworkError"
    assert result["message"] == "Connection refused"
    assert result["stackTrace"] == "Traceback (most recent call last):\n  File ..."
    assert result["code"] == "ECONNREFUSED"


def test_content_client_logger_log_metrics_summary():
    """Test ContentClientLogger.log_metrics_summary() method."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Add some request times
    logger._performance["request_times"] = [100.0, 200.0, 150.0, 300.0, 250.0]

    # Add some traces with retries
    for i in range(3):
        trace = logger.trace_request("GET", "https://api.example.com/test", {}, {}, retry_attempt=i)
        logger.trace_response(trace, 200, {}, {}, 100.0)

    # Should not raise
    logger.log_metrics_summary()


def test_content_client_logger_log_metrics_summary_empty():
    """Test ContentClientLogger.log_metrics_summary() with no data."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Should not raise even with no data
    logger.log_metrics_summary()


def test_content_client_logger_log_metrics_summary_p95():
    """Test ContentClientLogger.log_metrics_summary() with enough data for p95."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Add 25 request times (enough for p95 calculation)
    logger._performance["request_times"] = [float(i * 10) for i in range(25)]

    # Should not raise
    logger.log_metrics_summary()


@respx.mock
def test_content_client_default_is_multithreaded(mocker):
    """Test ContentClient default is_multithreaded=True behavior."""
    mock_support_multithreading = mocker.patch("ContentClientApiModule.support_multithreading")

    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    # Create client with default is_multithreaded=True
    client = ContentClient(base_url="https://api.example.com")

    # Verify support_multithreading was called
    mock_support_multithreading.assert_called_once()

    client.close()


@respx.mock
def test_content_client_is_multithreaded_false(mocker):
    """Test ContentClient with is_multithreaded=False."""
    mock_support_multithreading = mocker.patch("ContentClientApiModule.support_multithreading")

    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    # Create client with is_multithreaded=False
    client = ContentClient(base_url="https://api.example.com", is_multithreaded=False)

    # Verify support_multithreading was NOT called
    mock_support_multithreading.assert_not_called()

    client.close()


@respx.mock
def test_content_client_reuse_client_true(mocker):
    """Test ContentClient with reuse_client=True (default) keeps client open."""
    mocker.patch("ContentClientApiModule.support_multithreading")

    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com", reuse_client=True)

    # Make multiple requests
    client._http_request("GET", "/v1/data", resp_type="json")
    client._http_request("GET", "/v1/data", resp_type="json")

    # Client should still have an async client
    assert hasattr(client._local_storage, "client")

    assert route.call_count == 2
    client.close()


@respx.mock
def test_content_client_reuse_client_false(mocker):
    """Test ContentClient with reuse_client=False closes client after each request."""
    mocker.patch("ContentClientApiModule.support_multithreading")

    route = respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com", reuse_client=False)

    # Make a request
    client._http_request("GET", "/v1/data", resp_type="json")

    # Client should be closed after request
    assert client._local_storage.client is None

    # Make another request - should work fine
    client._http_request("GET", "/v1/data", resp_type="json")

    assert route.call_count == 2
    client.close()


@respx.mock
def test_content_client_get_async_client_event_loop_handling(mocker):
    """Test ContentClient._get_async_client() handles event loop changes."""
    mocker.patch("ContentClientApiModule.support_multithreading")

    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    # Make a request to initialize the client
    client._http_request("GET", "/v1/data", resp_type="json")

    # The client should have been created
    assert hasattr(client._local_storage, "client")

    client.close()


@respx.mock
def test_content_client_close_async_context_warning(mocker):
    """Test ContentClient.close() warns when called from async context."""
    import asyncio

    mocker.patch("ContentClientApiModule.support_multithreading")

    respx.get("https://api.example.com/v1/data").mock(return_value=Response(200, json={"result": "success"}))

    client = ContentClient(base_url="https://api.example.com")

    # Make a request to initialize the client
    client._http_request("GET", "/v1/data", resp_type="json")

    # Mock the logger warning
    mock_warning = mocker.patch.object(client.logger, "warning")

    async def test_async_close():
        # This should trigger the warning
        client.close()

    # Run in async context
    asyncio.run(test_async_close())

    # Verify warning was called
    mock_warning.assert_called_once()
    assert "async context" in mock_warning.call_args[0][0]


def test_content_client_get_async_client_http2_fallback(mocker):
    """Test ContentClient._get_async_client() falls back to HTTP/1.1 when HTTP/2 unavailable."""
    mocker.patch("ContentClientApiModule.support_multithreading")

    # Mock httpx.AsyncClient to raise ImportError on first call with http2=True
    original_async_client = httpx.AsyncClient
    call_count = [0]

    def mock_async_client(*args, **kwargs):
        call_count[0] += 1
        if kwargs.get("http2", False) and call_count[0] == 1:
            raise ImportError("h2 not available")
        return original_async_client(*args, **kwargs)

    mocker.patch.object(httpx, "AsyncClient", side_effect=mock_async_client)

    client = ContentClient(base_url="https://api.example.com")

    # Get the async client - should fall back to HTTP/1.1
    async def get_client():
        return client._get_async_client()

    import asyncio

    asyncio.run(get_client())

    # Verify HTTP/2 is now disabled
    assert client._http2_available is False

    client.close()


def test_structured_log_entry_to_json():
    """Test StructuredLogEntry.to_json() method."""
    entry = StructuredLogEntry(severity="INFO", message="Test message", client_name="TestClient")

    result = entry.to_json()

    # Should be valid JSON
    parsed = json.loads(result)
    assert parsed["severity"] == "INFO"
    assert parsed["message"] == "Test message"


def test_content_client_logger_new_request_id():
    """Test ContentClientLogger.new_request_id() generates unique IDs."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    id1 = logger.new_request_id()
    id2 = logger.new_request_id()

    assert id1 != id2
    assert len(id1) == 8
    assert len(id2) == 8


def test_content_client_logger_get_request_id():
    """Test ContentClientLogger.get_request_id() returns current ID."""
    logger = ContentClientLogger("TestClient", diagnostic_mode=True)

    # Initially None
    assert logger.get_request_id() is None

    # After generating
    new_id = logger.new_request_id()
    assert logger.get_request_id() == new_id
