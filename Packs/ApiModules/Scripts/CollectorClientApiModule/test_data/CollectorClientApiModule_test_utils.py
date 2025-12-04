"""Comprehensive testing utilities for CollectorClient.

This module provides fixtures, helpers, and utilities to make writing tests for
CollectorClient-based integrations easier and more comprehensive.

**Quick Start:**

```python
from CollectorClient_test_utils import *
import respx

@respx.mock
def test_my_collector(collector_fixtures):
    # Use pre-configured fixtures
    client = collector_fixtures.create_client()
    
    # Mock responses
    collector_fixtures.mock_cursor_response(
        events=[{"id": 1}, {"id": 2}],
        next_cursor="abc123"
    )
    
    # Run collection
    result = client.collect_events_sync()
    
    # Assertions
    collector_fixtures.assert_collected_events(result, count=2)
    collector_fixtures.assert_state_persisted("/v1/events")
```

**Features:**

- Pre-configured fixtures for common scenarios
- Response builders for all pagination modes
- State management helpers
- Assertion utilities
- Mock helpers for auth, retries, rate limits
- Performance testing helpers
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Sequence, Union
from unittest.mock import MagicMock, patch

import pytest
import respx
from httpx import Request, Response

try:
    from CollectorClientApiModule import (
        APIKeyAuthHandler,
        BearerTokenAuthHandler,
        BasicAuthHandler,
        CollectorBlueprint,
        CollectorClient,
        CollectorRequest,
        CollectorRunResult,
        CollectorState,
        OAuth2ClientCredentialsHandler,
        PaginationConfig,
        RateLimitPolicy,
        RetryPolicy,
        TimeoutSettings,
    )
except ImportError:
    # For standalone testing
    pass


# ============================================================================
# Response Builders
# ============================================================================


class ResponseBuilder:
    """Builder for creating mock API responses with common patterns."""

    @staticmethod
    def cursor_response(
        events: List[Any],
        next_cursor: Optional[str] = None,
        data_path: str = "data.events",
        cursor_path: str = "meta.next_cursor",
    ) -> Response:
        """Build a cursor-based pagination response.
        
        Args:
            events: List of events to return
            next_cursor: Next cursor value (None if done)
            data_path: Path to events in response (e.g., "data.events")
            cursor_path: Path to cursor in response (e.g., "meta.next_cursor")
            
        Returns:
            httpx.Response with JSON payload
        """
        payload: Dict[str, Any] = {}
        
        # Set events at data_path
        parts = data_path.split(".")
        current = payload
        for part in parts[:-1]:
            current[part] = {}
            current = current[part]
        current[parts[-1]] = events
        
        # Set cursor at cursor_path
        if cursor_path:
            parts = cursor_path.split(".")
            current = payload
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = next_cursor
        
        return Response(200, json=payload)

    @staticmethod
    def page_response(
        events: List[Any],
        page: int,
        has_more: bool = False,
        data_path: str = "data.events",
        page_path: str = "page",
        has_more_path: Optional[str] = None,
    ) -> Response:
        """Build a page-based pagination response.
        
        Args:
            events: List of events to return
            page: Current page number
            has_more: Whether more pages exist
            data_path: Path to events in response
            page_path: Path to page number in response
            has_more_path: Path to has_more boolean (if None, not included)
            
        Returns:
            httpx.Response with JSON payload
        """
        payload: Dict[str, Any] = {}
        
        # Set events
        parts = data_path.split(".")
        current = payload
        for part in parts[:-1]:
            current[part] = {}
            current = current[part]
        current[parts[-1]] = events
        
        # Set page number
        if page_path:
            parts = page_path.split(".")
            current = payload
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = page
        
        # Set has_more
        if has_more_path:
            parts = has_more_path.split(".")
            current = payload
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = has_more
        
        return Response(200, json=payload)

    @staticmethod
    def offset_response(
        events: List[Any],
        offset: int,
        total: Optional[int] = None,
        data_path: str = "data.events",
    ) -> Response:
        """Build an offset-based pagination response.
        
        Args:
            events: List of events to return
            offset: Current offset value
            total: Total number of items (optional)
            data_path: Path to events in response
            
        Returns:
            httpx.Response with JSON payload
        """
        payload: Dict[str, Any] = {}
        
        parts = data_path.split(".")
        current = payload
        for part in parts[:-1]:
            current[part] = {}
            current = current[part]
        current[parts[-1]] = events
        
        if total is not None:
            payload["total"] = total
        
        return Response(200, json=payload)

    @staticmethod
    def link_response(
        events: List[Any],
        next_link: Optional[str] = None,
        data_path: str = "data.events",
        link_path: str = "links.next",
    ) -> Response:
        """Build a link-based pagination response.
        
        Args:
            events: List of events to return
            next_link: Next page URL (None if done)
            data_path: Path to events in response
            link_path: Path to next link in response
            
        Returns:
            httpx.Response with JSON payload
        """
        payload: Dict[str, Any] = {}
        
        # Set events
        parts = data_path.split(".")
        current = payload
        for part in parts[:-1]:
            current[part] = {}
            current = current[part]
        current[parts[-1]] = events
        
        # Set next link
        if link_path:
            parts = link_path.split(".")
            current = payload
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = next_link
        
        return Response(200, json=payload)

    @staticmethod
    def error_response(
        status_code: int,
        error_message: str,
        error_code: Optional[str] = None,
    ) -> Response:
        """Build an error response.
        
        Args:
            status_code: HTTP status code (e.g., 429, 500)
            error_message: Error message
            error_code: Optional error code
            
        Returns:
            httpx.Response with error payload
        """
        payload: Dict[str, Any] = {"error": error_message}
        if error_code:
            payload["error_code"] = error_code
        
        return Response(status_code, json=payload)

    @staticmethod
    def retry_after_response(seconds: float) -> Response:
        """Build a 429 response with Retry-After header.
        
        Args:
            seconds: Seconds to wait (or datetime string)
            
        Returns:
            httpx.Response with 429 status and Retry-After header
        """
        return Response(
            429,
            json={"error": "Too Many Requests"},
            headers={"Retry-After": str(int(seconds))},
        )


# ============================================================================
# Test Fixtures
# ============================================================================


class CollectorTestFixtures:
    """Comprehensive test fixtures for CollectorClient testing.
    
    Provides pre-configured clients, mock helpers, and assertion utilities.
    """

    def __init__(self, integration_context: Dict[str, Any]):
        self.integration_context = integration_context
        self.response_builder = ResponseBuilder()
        self._mock_responses: List[Response] = []

    def create_client(
        self,
        name: str = "TestCollector",
        base_url: str = "https://api.example.com",
        endpoint: str = "/v1/events",
        data_path: str = "data.events",
        auth_handler: Optional[Any] = None,
        pagination: Optional[PaginationConfig] = None,
        retry_policy: Optional[RetryPolicy] = None,
        rate_limit: Optional[RateLimitPolicy] = None,
        timeout: Optional[TimeoutSettings] = None,
        verify: bool = True,
        proxy: bool = False,
    ) -> CollectorClient:
        """Create a pre-configured CollectorClient for testing.
        
        Args:
            name: Collector name
            base_url: Base API URL
            endpoint: API endpoint
            data_path: Path to events in response
            auth_handler: Authentication handler
            pagination: Pagination configuration
            retry_policy: Retry policy (default: fast retries for testing)
            rate_limit: Rate limit policy (default: disabled)
            timeout: Timeout settings (default: 30s execution)
            verify: SSL verification
            proxy: Use proxy
            
        Returns:
            Configured CollectorClient
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
            retry_policy=retry_policy or RetryPolicy(
                max_attempts=3,
                initial_delay=0.01,
                max_delay=0.02,
            ),
            rate_limit=rate_limit or RateLimitPolicy(rate_per_second=0.0),
            timeout=timeout or TimeoutSettings(execution=30.0),
            verify=verify,
            proxy=proxy,
        )
        
        return CollectorClient(blueprint)

    def mock_cursor_response(
        self,
        route: Any,
        events: List[Any],
        next_cursor: Optional[str] = None,
        data_path: str = "data.events",
        cursor_path: str = "meta.next_cursor",
    ) -> None:
        """Mock a cursor-based pagination response.
        
        Args:
            route: respx route to mock
            events: Events to return
            next_cursor: Next cursor value
            data_path: Path to events
            cursor_path: Path to cursor
        """
        response = self.response_builder.cursor_response(
            events=events,
            next_cursor=next_cursor,
            data_path=data_path,
            cursor_path=cursor_path,
        )
        route.mock(return_value=response)

    def mock_page_response(
        self,
        route: Any,
        events: List[Any],
        page: int,
        has_more: bool = False,
        data_path: str = "data.events",
    ) -> None:
        """Mock a page-based pagination response.
        
        Args:
            route: respx route to mock
            events: Events to return
            page: Current page number
            has_more: Whether more pages exist
            data_path: Path to events
        """
        response = self.response_builder.page_response(
            events=events,
            page=page,
            has_more=has_more,
            data_path=data_path,
        )
        route.mock(return_value=response)

    def mock_error_response(
        self,
        route: Any,
        status_code: int,
        error_message: str,
    ) -> None:
        """Mock an error response.
        
        Args:
            route: respx route to mock
            status_code: HTTP status code
            error_message: Error message
        """
        response = self.response_builder.error_response(
            status_code=status_code,
            error_message=error_message,
        )
        route.mock(return_value=response)

    def mock_retry_sequence(
        self,
        route: Any,
        error_count: int,
        success_response: Response,
    ) -> None:
        """Mock a sequence of errors followed by success (for retry testing).
        
        Args:
            route: respx route to mock
            error_count: Number of error responses before success
            success_response: Final success response
        """
        responses = [
            Response(500, json={"error": "Internal Server Error"})
            for _ in range(error_count)
        ]
        responses.append(success_response)
        route.mock(side_effect=responses)

    def assert_collected_events(
        self,
        result: CollectorRunResult,
        count: Optional[int] = None,
        min_count: Optional[int] = None,
        event_ids: Optional[List[Any]] = None,
    ) -> None:
        """Assert collected events match expectations.
        
        Args:
            result: Collection result
            count: Exact number of events expected
            min_count: Minimum number of events expected
            event_ids: Expected event IDs (checks "id" field)
        """
        if count is not None:
            assert len(result.events) == count, f"Expected {count} events, got {len(result.events)}"
        
        if min_count is not None:
            assert len(result.events) >= min_count, f"Expected at least {min_count} events, got {len(result.events)}"
        
        if event_ids:
            actual_ids = [e.get("id") for e in result.events]
            assert set(actual_ids) == set(event_ids), f"Event IDs mismatch: expected {event_ids}, got {actual_ids}"

    def assert_state_persisted(
        self,
        state_key: str,
        collector_name: str = "TestCollector",
        cursor: Optional[str] = None,
        page: Optional[int] = None,
    ) -> None:
        """Assert state was persisted correctly.
        
        Args:
            state_key: State key to check
            collector_name: Collector name
            cursor: Expected cursor value
            page: Expected page number
        """
        namespace = self.integration_context.get("collector_client", {})
        collector_state = namespace.get(collector_name, {})
        state_data = collector_state.get(state_key)
        
        assert state_data is not None, f"State not found for key: {state_key}"
        
        if cursor is not None:
            assert state_data.get("cursor") == cursor, f"Expected cursor {cursor}, got {state_data.get('cursor')}"
        
        if page is not None:
            assert state_data.get("page") == page, f"Expected page {page}, got {state_data.get('page')}"

    def assert_metrics(
        self,
        result: CollectorRunResult,
        success: Optional[int] = None,
        errors: Optional[int] = None,
        retries: Optional[int] = None,
    ) -> None:
        """Assert metrics match expectations.
        
        Args:
            result: Collection result
            success: Expected success count
            errors: Expected error count
            retries: Expected retry count
        """
        if success is not None:
            assert result.metrics.success == success, f"Expected {success} successes, got {result.metrics.success}"
        
        if errors is not None:
            total_errors = (
                result.metrics.general_error
                + result.metrics.auth_error
                + result.metrics.quota_error
                + result.metrics.service_error
            )
            assert total_errors == errors, f"Expected {errors} errors, got {total_errors}"
        
        if retries is not None:
            assert result.metrics.retry_error == retries, f"Expected {retries} retries, got {result.metrics.retry_error}"

    def assert_auth_header(
        self,
        route: Any,
        header_name: str,
        expected_value: str,
    ) -> None:
        """Assert authentication header was sent correctly.
        
        Args:
            route: respx route that was called
            header_name: Header name to check
            expected_value: Expected header value
        """
        assert route.called, "Route was not called"
        sent_headers = route.calls[0].request.headers
        assert header_name in sent_headers, f"Header {header_name} not found in request"
        assert sent_headers[header_name] == expected_value, f"Expected {expected_value}, got {sent_headers[header_name]}"

    def assert_request_count(
        self,
        route: Any,
        count: int,
    ) -> None:
        """Assert route was called a specific number of times.
        
        Args:
            route: respx route to check
            count: Expected call count
        """
        assert route.call_count == count, f"Expected {count} calls, got {route.call_count}"


@pytest.fixture
def collector_fixtures(integration_context):
    """Pytest fixture providing CollectorTestFixtures instance.
    
    Usage:
        @respx.mock
        def test_my_collector(collector_fixtures):
            client = collector_fixtures.create_client()
            # ...
    """
    return CollectorTestFixtures(integration_context)


@pytest.fixture
def integration_context(mocker):
    """Pytest fixture for integration context mocking.
    
    Provides a mock integration context that persists across calls.
    """
    store: Dict[str, Any] = {}

    def get_context():
        return json.loads(json.dumps(store))

    def set_context(value: Dict[str, Any]):
        store.clear()
        store.update(value)

    mocker.patch.object(
        __import__("demistomock", fromlist=["demisto"]).demisto,
        "getIntegrationContext",
        side_effect=get_context,
    )
    mocker.patch.object(
        __import__("demistomock", fromlist=["demisto"]).demisto,
        "setIntegrationContext",
        side_effect=set_context,
    )
    mocker.patch.object(
        __import__("demistomock", fromlist=["demisto"]).demisto,
        "debug",
    )
    mocker.patch.object(
        __import__("demistomock", fromlist=["demisto"]).demisto,
        "error",
    )
    mocker.patch.object(
        __import__("demistomock", fromlist=["demisto"]).demisto,
        "info",
    )
    
    yield store


# ============================================================================
# Example Test Templates
# ============================================================================

"""
Example test using the fixtures:

@respx.mock
def test_cursor_pagination(collector_fixtures):
    # Create client
    client = collector_fixtures.create_client(
        endpoint="/v1/events",
        data_path="data.events",
        pagination=PaginationConfig(
            mode="cursor",
            next_cursor_path="meta.next_cursor",
        ),
    )
    
    # Mock responses
    route = respx.get("https://api.example.com/v1/events")
    collector_fixtures.mock_cursor_response(
        route,
        events=[{"id": 1}],
        next_cursor="abc",
    )
    
    # First page
    result = client.collect_events_sync(limit=1)
    collector_fixtures.assert_collected_events(result, count=1)
    
    # Mock second page
    collector_fixtures.mock_cursor_response(
        route,
        events=[{"id": 2}],
        next_cursor=None,
    )
    
    # Second page
    result = client.collect_events_sync()
    collector_fixtures.assert_collected_events(result, count=1, event_ids=[2])
    collector_fixtures.assert_state_persisted("/v1/events", cursor=None)
"""

