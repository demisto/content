import json
from datetime import UTC, datetime
import pytest
from pytest_mock import MockerFixture
from aiohttp import ClientResponseError, RequestInfo
from unittest.mock import AsyncMock
from CommonServerPython import *
from MimecastEventCollector import (
    ACCESS_TOKEN_KEY,
    TOKEN_TYPE_KEY,
    TOKEN_TTL_KEY,
    TOKEN_VALID_UNTIL_KEY,
    AUDIT_ID_KEY,
    AUDIT_TIME_KEY,
    EVENT_TIME_KEY,
    SOURCE_LOG_TYPE_KEY,
    FILTER_TIME_KEY,
    DEFAULT_BASE_URL,
    AsyncClient,
)

CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def async_client():
    return AsyncClient(
        base_url=DEFAULT_BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        verify=False,
        proxy=False,
    )


def mock_async_session_response(
    response_json: dict | None = None,
    error_status_code: int | None = None,
    error_message: str = "Server error",
) -> AsyncMock | ClientResponseError:
    """Helper function to create mock async session responses."""
    mock_response = AsyncMock()
    mock_response.json = AsyncMock(return_value=response_json)
    if error_status_code:
        return ClientResponseError(
            status=error_status_code,
            history=(),
            request_info=RequestInfo("", "POST", {}),
            message=error_message,
        )
    else:
        mock_response.raise_for_status = AsyncMock()
        mock_response.status = 200
    return AsyncMock(__aenter__=AsyncMock(return_value=mock_response))


@pytest.mark.asyncio
async def test_async_client_generate_new_access_token(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling _generate_new_access_token.
    Then:
     - Ensure the correct HTTP POST request is made to the OAuth token endpoint.
     - Ensure the correct token response is returned.
    """
    mock_token_response = {"access_token": "test_access_token_12345", "token_type": "bearer", "expires_in": 1800}

    mock_response = mock_async_session_response(mock_token_response)

    async with async_client as _client:
        mock_client_post = mocker.patch.object(_client._session, "post", return_value=mock_response)
        token_response = await _client._generate_new_access_token()

    assert token_response == mock_token_response
    assert mock_client_post.call_args.kwargs["url"] == urljoin(DEFAULT_BASE_URL, "/oauth/token")
    assert mock_client_post.call_args.kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert mock_client_post.call_args.kwargs["data"]["grant_type"] == "client_credentials"


@pytest.mark.asyncio
async def test_async_client_generate_new_access_token_error(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling _generate_new_access_token and the response contains an error.
    Then:
     - Ensure a DemistoException is raised with the appropriate error message.
    """
    token_url = urljoin(DEFAULT_BASE_URL, "/oauth/token")
    error_message = "Invalid client credentials"

    mock_response = mock_async_session_response(response_json={"fail": [{"message": error_message}]})

    async with async_client as _client:
        mocker.patch.object(_client._session, "post", return_value=mock_response)
        with pytest.raises(DemistoException, match=f"Request to {token_url} failed. Got error: {error_message}."):
            await _client._generate_new_access_token()


@pytest.mark.parametrize(
    "integration_context, force_generate, expected_generate_call_count, expected_set_context_call_count",
    [
        pytest.param(
            {
                ACCESS_TOKEN_KEY: "existing_token",
                TOKEN_TYPE_KEY: "bearer",
                TOKEN_VALID_UNTIL_KEY: "2025-01-02T12:00:00+00:00",  # Valid until noon (current time is 10:00)
            },
            False,
            0,  # Should not generate new token
            0,  # Should not set context
            id="Valid token in integration context",
        ),
        pytest.param(
            {
                ACCESS_TOKEN_KEY: "expired_token",
                TOKEN_TYPE_KEY: "bearer",
                TOKEN_VALID_UNTIL_KEY: "2025-01-02T09:00:00+00:00",  # Expired (current time is 10:00)
            },
            False,
            1,  # Should generate new token
            1,  # Should set new token in context
            id="Expired token in integration context",
        ),
        pytest.param(
            {},  # Empty context
            False,
            1,  # Should generate new token
            1,  # Should set new token in context
            id="No token in integration context",
        ),
        pytest.param(
            {
                ACCESS_TOKEN_KEY: "existing_token",
                TOKEN_TYPE_KEY: "bearer",
                TOKEN_VALID_UNTIL_KEY: "2025-01-02T12:00:00+00:00",  # Valid token
            },
            True,  # Force generate
            1,  # Should generate new token even though existing is valid
            1,  # Should set new token in context
            id="Force generate new token",
        ),
    ],
)
@pytest.mark.asyncio
async def test_async_client_get_authorization_header(
    async_client: AsyncClient,
    mocker: MockerFixture,
    integration_context: dict,
    force_generate: bool,
    expected_generate_call_count: int,
    expected_set_context_call_count: int,
):
    """
    Given:
     - An AsyncClient instance and various integration context states.
    When:
     - Calling get_authorization_header with different scenarios.
    Then:
     - Ensure the correct behavior for token retrieval/generation.
     - Ensure get_integration_context and set_integration_context are called appropriately.
    """
    mocker.patch("MimecastEventCollector.UTC_NOW", datetime(2025, 1, 2, 10, 0, 0, tzinfo=UTC))
    # Mock integration context functions
    mock_get_context = mocker.patch("MimecastEventCollector.get_integration_context", return_value=integration_context)
    mock_set_context = mocker.patch("MimecastEventCollector.set_integration_context")

    # Mock token generation response
    mock_token_response = {
        ACCESS_TOKEN_KEY: "new_generated_token",
        TOKEN_TYPE_KEY: "bearer",
        TOKEN_TTL_KEY: 1800,
    }

    async with async_client as _client:
        mock_generate = mocker.patch.object(
            _client,
            "_generate_new_access_token",
            return_value=mock_token_response,
        )

        # Call the method
        auth_header = await _client.get_authorization_header(force_generate_new_token=force_generate)

        # Assertions
        assert mock_get_context.call_count == 1
        assert mock_generate.call_count == expected_generate_call_count
        assert mock_set_context.call_count == expected_set_context_call_count

        # Verify the authorization header format
        if expected_generate_call_count > 0:
            # New token was generated
            assert auth_header == "Bearer new_generated_token"
            # Verify set_integration_context was called with correct data
            if expected_set_context_call_count > 0:
                set_context_call_args = mock_set_context.call_args[0][0]
                assert set_context_call_args[ACCESS_TOKEN_KEY] == "new_generated_token"
                assert set_context_call_args[TOKEN_TYPE_KEY] == "bearer"
                assert TOKEN_VALID_UNTIL_KEY in set_context_call_args
        else:
            # Existing token was used
            assert auth_header == "Bearer existing_token"


@pytest.mark.asyncio
async def test_async_client_get_audit_events(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling `get_audit_events` with specific parameters.
    Then:
     - Ensure the correct HTTP POST request is made to the audit events endpoint.
     - Ensure the correct response is returned.
    """
    start_date = "2025-01-01T00:00:00+0000"
    end_date = "2025-01-02T00:00:00+0000"
    page_size = 500

    mock_response_json = util_load_json("test_data/audit_raw_response.json")

    mock_response = mock_async_session_response(response_json=mock_response_json)
    mock_get_auth_header = mocker.patch.object(async_client, "get_authorization_header", return_value="Bearer test_token")

    async with async_client as _client:
        mock_post_request = mocker.patch.object(_client._session, "request", return_value=mock_response)
        response_json = await _client.get_audit_events(
            start_date=start_date,
            end_date=end_date,
            page_size=page_size,
        )

    assert response_json == mock_response_json
    assert mock_get_auth_header.call_count == 1
    assert mock_post_request.call_args.kwargs["url"] == urljoin(DEFAULT_BASE_URL, "/api/audit/get-audit-events")
    assert mock_post_request.call_args.kwargs["json"]["data"][0]["startDateTime"] == start_date
    assert mock_post_request.call_args.kwargs["json"]["data"][0]["endDateTime"] == end_date


@pytest.mark.asyncio
async def test_async_client_get_siem_events(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling get_siem_events with specific parameters.
    Then:
     - Ensure the correct HTTP GET request is made to the SIEM events endpoint.
     - Ensure the correct response is returned.
    """
    event_type = "receipt"
    start_date = "2025-01-01T00:00:00.000Z"
    page_size = 100

    mock_response_json = util_load_json("test_data/siem_raw_response.json")

    mock_response = mock_async_session_response(response_json=mock_response_json)
    mock_get_auth_header = mocker.patch.object(async_client, "get_authorization_header", return_value="Bearer test_token")

    async with async_client as _client:
        mock_get_request = mocker.patch.object(_client._session, "request", return_value=mock_response)
        response_json = await _client.get_siem_events(event_type=event_type, start_date=start_date, page_size=page_size)

    assert response_json == mock_response_json
    assert mock_get_auth_header.call_count == 1
    assert mock_get_request.call_args.kwargs["url"] == urljoin(DEFAULT_BASE_URL, "/siem/v1/events/cg")
    assert mock_get_request.call_args.kwargs["params"]["types"] == event_type


@pytest.mark.parametrize(
    "filter_datetime, expected_audit_format, expected_siem_format",
    [
        pytest.param(
            datetime(2025, 1, 1, 12, 30, 45, tzinfo=UTC),
            "2025-01-01T12:30:45+0000",
            "2025-01-01T12:30:45.000Z",
            id="Datetime conversion with UTC timezone",
        ),
        pytest.param(
            datetime(2025, 1, 1, 13, 35, 55, tzinfo=None),
            "2025-01-01T13:35:55+0000",
            "2025-01-01T13:35:55.000Z",
            id="Datetime conversion with no timezone info",
        ),
    ],
)
def test_convert_to_filter_formats(filter_datetime, expected_audit_format, expected_siem_format):
    """
    Given:
     - A datetime object.
    When:
     - Converting to audit and SIEM filter formats.
    Then:
     - Ensure the correct format strings are returned.
    """
    from MimecastEventCollector import convert_to_audit_filter_format, convert_to_siem_filter_format

    assert convert_to_audit_filter_format(filter_datetime) == expected_audit_format
    assert convert_to_siem_filter_format(filter_datetime) == expected_siem_format


@pytest.mark.parametrize(
    "events, all_fetched_ids, expected_events_count, expected_all_ids_count",
    [
        pytest.param(
            [
                {"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000"},
                {"id": "event-2", "eventTime": "2025-01-01T01:00:00+0000"},
            ],
            set(),
            2,
            2,
            id="No duplicates",
        ),
        pytest.param(
            [
                {"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000"},
                {"id": "event-2", "eventTime": "2025-01-01T01:00:00+0000"},
            ],
            {"event-1"},
            1,
            2,
            id="With duplicates",
        ),
        pytest.param(
            [],
            {"event-1"},
            0,
            1,
            id="Empty events list",
        ),
        pytest.param(
            [{"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000"}],
            {"event-1"},
            0,
            1,
            id="All duplicates",
        ),
    ],
)
def test_deduplicate_and_format_events(
    events: list[dict[str, Any]],
    all_fetched_ids: set[str],
    expected_events_count: int,
    expected_all_ids_count: int,
):
    """
    Given:
     - A list of raw events and a set of already fetched event IDs.
    When:
     - Calling deduplicate_and_format_events.
    Then:
     - Ensure that events are correctly deduplicated and formatted.
     - Ensure that the set of fetched IDs is correctly updated.
    """
    from MimecastEventCollector import deduplicate_and_format_events, convert_to_audit_filter_format

    source_log_type = "Audit"
    new_events = deduplicate_and_format_events(
        events, all_fetched_ids, AUDIT_ID_KEY, AUDIT_TIME_KEY, source_log_type, convert_to_audit_filter_format
    )

    assert len(new_events) == expected_events_count
    assert len(all_fetched_ids) == expected_all_ids_count

    for event in new_events:
        assert EVENT_TIME_KEY in event
        assert event[SOURCE_LOG_TYPE_KEY] == source_log_type
        assert FILTER_TIME_KEY in event


@pytest.mark.asyncio
async def test_get_audit_events_pagination(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit that requires fetching multiple pages of events.
    When:
     - Calling get_audit_events.
    Then:
     - Ensure that multiple API calls are made and events are aggregated.
    """
    from MimecastEventCollector import get_audit_events

    start_date = "2025-01-01T00:00:00+0000"
    end_date = "2025-01-02T00:00:00+0000"
    limit = 600

    mock_response_jsons = [
        {  # Page 1
            "data": [{"id": f"event-A{i}", "eventTime": "2025-01-01T00:00:00+0000"} for i in range(500)],
            "meta": {"pagination": {"next": "page2_token"}},
        },
        {  # Page 2
            "data": [{"id": f"event-B{i}", "eventTime": "2025-01-01T01:00:00+0000"} for i in range(500)],
            "meta": {"pagination": {"next": None}},
        },
    ]

    async with async_client as _client:
        mock_get_audit_events = mocker.patch.object(_client, "get_audit_events", side_effect=mock_response_jsons)
        events = await get_audit_events(
            client=_client,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
        )

    assert len(events) == limit
    assert mock_get_audit_events.call_count == 2  # 500 from first page, 100 from second page


@pytest.mark.asyncio
async def test_get_audit_events_with_deduplication(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit and a list of previously fetched event IDs.
    When:
     - Calling get_audit_events.
    Then:
     - Ensure that duplicate events are filtered out.
    """
    from MimecastEventCollector import get_audit_events

    start_date = "2025-01-01T00:00:00+0000"
    end_date = "2025-01-02T00:00:00+0000"
    limit = 500
    last_fetched_ids = ["event-A0", "event-A1"]

    mock_response_json = {
        "data": [
            {"id": "event-A0", "eventTime": "2025-01-01T00:00:00+0000"},  # Duplicate
            {"id": "event-A1", "eventTime": "2025-01-01T00:00:00+0000"},  # Duplicate
            {"id": "event-A2", "eventTime": "2025-01-01T00:00:00+0000"},  # New
        ],
        "meta": {"pagination": {"next": None}},
    }

    async with async_client as _client:
        mocker.patch.object(_client, "get_audit_events", return_value=mock_response_json)
        events = await get_audit_events(
            client=_client,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            last_fetched_ids=last_fetched_ids,
        )

    assert len(events) == 1  # Only one new event after deduplication
    assert events[0]["id"] == "event-A2"


@pytest.mark.asyncio
async def test_get_siem_events_pagination(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit that requires fetching multiple pages of SIEM events.
    When:
     - Calling get_siem_events.
    Then:
     - Ensure that multiple API calls are made and events are aggregated.
    """
    from MimecastEventCollector import get_siem_events

    event_type = "receipt"
    start_date = "2025-01-01T00:00:00.000Z"
    limit = 150

    mock_response_jsons = [
        {  # Page 1
            "value": [{"aCode": f"event-A{i}", "timestamp": 1704067200000} for i in range(100)],
            "@nextPage": "page2_token",
        },
        {  # Page 2
            "value": [{"aCode": f"event-B{i}", "timestamp": 1704070800000} for i in range(100)],
            "@nextPage": None,
        },
    ]

    async with async_client as _client:
        mock_get_siem_events = mocker.patch.object(_client, "get_siem_events", side_effect=mock_response_jsons)
        events = await get_siem_events(
            client=_client,
            event_type=event_type,
            start_date=start_date,
            limit=limit,
        )

    assert len(events) == limit
    assert mock_get_siem_events.call_count == 2


@pytest.mark.asyncio
async def test_get_events_command(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient and command arguments.
    When:
     - Calling get_events_command.
    Then:
     - Ensure get_audit_events and get_siem_events are called with the correct arguments.
     - Ensure tableToMarkdown is called with the correct arguments.
    """
    from MimecastEventCollector import get_events_command

    mock_audit_events = [{"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000", "_time": "2025-01-01T00:00:00Z"}]
    mock_siem_events = [{"aCode": "event-2", "timestamp": 1704067200000, "_time": "2025-01-01T00:00:00Z"}]

    mocker.patch("MimecastEventCollector.UTC_NOW", datetime(2025, 1, 2, 10, 0, 0, tzinfo=UTC))
    mock_get_audit_events = mocker.patch("MimecastEventCollector.get_audit_events", return_value=mock_audit_events)
    mock_get_siem_events = mocker.patch("MimecastEventCollector.get_siem_events", return_value=mock_siem_events)
    mock_table_to_markdown = mocker.patch("MimecastEventCollector.tableToMarkdown")

    args = {"event_types": "audit,receipt", "limit": "10", "start_date": "1 hour ago"}

    events, _ = await get_events_command(async_client, args)

    assert len(events) == 2
    assert mock_get_audit_events.call_count == 1
    assert mock_get_siem_events.call_count == 1
    assert mock_table_to_markdown.call_count == 2


@pytest.mark.parametrize(
    "last_run, max_fetch, mock_audit_events, expected_next_run",
    [
        pytest.param(
            {},
            100,
            [
                {"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000", "_filter_time": "2025-01-01T00:00:00+0000"},
                {"id": "event-2", "eventTime": "2025-01-01T01:00:00+0000", "_filter_time": "2025-01-01T01:00:00+0000"},
            ],
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2"]},
            id="Initial run with audit events",
        ),
        pytest.param(
            {"start_date": "2025-01-01T00:00:00+0000", "last_fetched_ids": ["event-1"]},
            50,
            [
                {"id": "event-2", "eventTime": "2025-01-01T01:00:00+0000", "_filter_time": "2025-01-01T01:00:00+0000"},
                {"id": "event-3", "eventTime": "2025-01-01T01:00:00+0000", "_filter_time": "2025-01-01T01:00:00+0000"},
            ],
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2", "event-3"]},
            id="Subsequent run with events at same timestamp",
        ),
        pytest.param(
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2"]},
            100,
            [],
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2"]},
            id="No new events",
        ),
    ],
)
@pytest.mark.asyncio
async def test_fetch_audit_events(
    async_client: AsyncClient,
    mocker: MockerFixture,
    last_run: dict,
    max_fetch: int,
    mock_audit_events: list,
    expected_next_run: dict,
):
    """
    Given:
     - An AsyncClient, last_run, and max_fetch parameters.
    When:
     - Calling fetch_audit_events.
    Then:
     - Ensure that get_audit_events is called.
     - Ensure that the next_run object and events are returned correctly.
    """
    from MimecastEventCollector import fetch_audit_events

    mocker.patch("MimecastEventCollector.get_audit_events", return_value=mock_audit_events)

    next_run, events = await fetch_audit_events(async_client, last_run, max_fetch)

    assert next_run == expected_next_run
    assert len(events) == len(mock_audit_events)


@pytest.mark.asyncio
async def test_fetch_siem_events_service_failure_isolation(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - Multiple SIEM event types to fetch.
    When:
     - One event type fails but others succeed.
    Then:
     - Ensure that successful event types' events are still returned.
     - Ensure that the failure is logged but doesn't stop other event types.
    """
    from MimecastEventCollector import fetch_siem_events

    event_types = ["receipt", "delivery", "spam"]
    last_run = {}
    max_fetch = 100

    async def mock_get_siem_events(client, event_type, start_date, limit, last_fetched_ids=None, end_date=None):
        if event_type == "delivery":
            raise Exception("Service error")
        return [{"aCode": f"{event_type}-event-1", "timestamp": 1704067200000, "_filter_time": "2025-01-01T00:00:00.000Z"}]

    mocker.patch("MimecastEventCollector.get_siem_events", side_effect=mock_get_siem_events)
    mock_demisto_error = mocker.patch.object(demisto, "error")

    next_run, events = await fetch_siem_events(async_client, last_run, max_fetch, event_types)

    # Should have events from 2 successful event types
    assert len(events) == 2
    assert mock_demisto_error.call_count == 1
    assert "delivery" in mock_demisto_error.call_args[0][0]


@pytest.mark.asyncio
async def test_fetch_events_command(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient, last_run, max_fetch, and event_types.
    When:
     - Calling fetch_events_command.
    Then:
     - Ensure that fetch_audit_events and fetch_siem_events are called.
     - Ensure that the next_run object and events are returned correctly.
    """
    from MimecastEventCollector import fetch_events_command

    last_run = {}
    max_fetch = 100
    event_types = ["audit", "receipt"]

    mock_audit_events = [{"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000"}]
    mock_siem_events = [{"aCode": "event-2", "timestamp": 1704067200000}]

    mocker.patch(
        "MimecastEventCollector.fetch_audit_events", return_value=({"start_date": "2025-01-01T00:00:00+0000"}, mock_audit_events)
    )
    mocker.patch(
        "MimecastEventCollector.fetch_siem_events",
        return_value=({"receipt": {"start_date": "2025-01-01T00:00:00.000Z"}}, mock_siem_events),
    )

    next_run, events = await fetch_events_command(async_client, last_run, max_fetch, event_types)

    assert "audit" in next_run
    assert "siem" in next_run
    assert len(events) == 2


@pytest.mark.asyncio
async def test_test_module(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient and event types.
    When:
     - Calling `test_module`.
    Then:
     - Ensure that get_audit_events and get_siem_events are called.
     - Ensure "ok" is returned.
    """
    from MimecastEventCollector import test_module

    event_types = ["audit", "receipt"]

    mock_get_audit_events = mocker.patch("MimecastEventCollector.get_audit_events", return_value=[])
    mock_get_siem_events = mocker.patch("MimecastEventCollector.get_siem_events", return_value=[])

    result = await test_module(async_client, event_types)

    assert mock_get_audit_events.call_count == 1
    assert mock_get_siem_events.call_count == 1
    assert result == "ok"
