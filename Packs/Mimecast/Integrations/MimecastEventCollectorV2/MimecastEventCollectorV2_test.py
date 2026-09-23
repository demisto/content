from copy import deepcopy
from datetime import UTC, datetime
import pytest
from pytest_mock import MockerFixture
from aiohttp import ClientResponseError, RequestInfo
from unittest.mock import AsyncMock, Mock
from CommonServerPython import *
from MimecastEventCollectorV2 import (
    ACCESS_TOKEN_KEY,
    TOKEN_TYPE_KEY,
    TOKEN_TTL_KEY,
    TOKEN_VALID_UNTIL_KEY,
    EVENT_TIME_KEY,
    SOURCE_LOG_TYPE_KEY,
    FILTER_TIME_KEY,
    DEFAULT_BASE_URL,
    NEXT_PAGE_KEY,
    START_DATE_KEY,
    LAST_FETCHED_IDS_KEY,
    EventTypes,
    AsyncClient,
)
from test_data.data import AUDIT_RAW_RESPONSE, SIEM_RAW_RESPONSE

# A "bad" SIEM cursor: all event types have offset 0-0 (base64 of
# "[attachment_protect=0-0, av=0-0, ...]:0:null")
BAD_SIEM_CURSOR = (
    "W2F0dGFjaG1lbnRfcHJvdGVjdD0wLTAsIGF2PTAtMCwgZGVsaXZlcnk9MC0wLCBpbXBlcnNvbmF0aW9uX3Byb3RlY3Q9MC0wLCBpbnRlcm5hbF9lb"
    "WFpbF9wcm90ZWN0PTAtMCwgam91cm5hbD0wLTAsIHByb2Nlc3M9MC0wLCByZWNlaXB0PTAtMCwgc3BhbT0wLTAsIHVybF9wcm90ZWN0PTAtMF06MDpudWxs"
)
# A "good" SIEM cursor: at least one event type has a non 0-0 offset
# (base64 of "[attachment_protect=5-100, av=0-0, delivery=0-0]:1:token")
GOOD_SIEM_CURSOR = base64.b64encode(b"[attachment_protect=5-100, av=0-0, delivery=0-0]:1:token").decode()

CLIENT_ID = "test_client_id"
CLIENT_SECRET = "test_client_secret"


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
        # raise_for_status is a synchronous method in aiohttp, not async
        mock_response.raise_for_status = Mock()
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
    mocker.patch("MimecastEventCollectorV2.UTC_NOW", datetime(2025, 1, 2, 10, 0, 0, tzinfo=UTC))
    # Mock integration context functions
    mock_get_context = mocker.patch("MimecastEventCollectorV2.get_integration_context", return_value=integration_context)
    mock_set_context = mocker.patch("MimecastEventCollectorV2.set_integration_context")

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
            new=AsyncMock(return_value=mock_token_response),
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

    mock_response = mock_async_session_response(response_json=AUDIT_RAW_RESPONSE)
    mock_get_auth_header = mocker.patch.object(
        async_client, "get_authorization_header", new=AsyncMock(return_value="Bearer test_token")
    )

    async with async_client as _client:
        mock_post_request = mocker.patch.object(_client._session, "request", return_value=mock_response)
        response_json = await _client.get_audit_events(
            start_date=start_date,
            end_date=end_date,
            page_size=page_size,
        )

    assert response_json == AUDIT_RAW_RESPONSE
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
    start_date = "2025-01-01T00:00:00.000Z"
    page_size = 100

    mock_response = mock_async_session_response(response_json=SIEM_RAW_RESPONSE)
    mock_get_auth_header = mocker.patch.object(
        async_client, "get_authorization_header", new=AsyncMock(return_value="Bearer test_token")
    )

    async with async_client as _client:
        mock_get_request = mocker.patch.object(_client._session, "request", return_value=mock_response)
        response_json = await _client.get_siem_events(start_date=start_date, page_size=page_size)

    assert response_json == SIEM_RAW_RESPONSE
    assert mock_get_auth_header.call_count == 1
    assert mock_get_request.call_args.kwargs["url"] == urljoin(DEFAULT_BASE_URL, "/siem/v1/events/cg")


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
    from MimecastEventCollectorV2 import convert_to_audit_filter_format, convert_to_siem_filter_format

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
    from MimecastEventCollectorV2 import deduplicate_and_format_events

    event_type = EventTypes.AUDIT
    new_events = deduplicate_and_format_events(
        events=events,
        all_fetched_ids=all_fetched_ids,
        event_type=event_type,
    )

    assert len(new_events) == expected_events_count
    assert len(all_fetched_ids) == expected_all_ids_count

    for event in new_events:
        assert EVENT_TIME_KEY in event
        assert event[SOURCE_LOG_TYPE_KEY] == event_type.source_log_type
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
    from MimecastEventCollectorV2 import get_audit_events

    start_date = "2025-01-01T00:00:00+0000"
    end_date = "2025-01-02T00:00:00+0000"
    limit = 600

    mock_response_jsons = [
        {  # Page 1
            "data": [{"id": f"event-A{i}", "eventTime": "2025-01-01T00:00:00+0000"} for i in range(500)],
            "meta": {"pagination": {"next": "page2_token"}},
        },
        {  # Page 2
            "data": [{"id": f"event-B{i}", "eventTime": "2025-01-01T01:00:00+0000"} for i in range(100)],
            "meta": {"pagination": {"next": "page3_token"}},
        },
    ]

    async with async_client as _client:
        mock_get_audit_events = mocker.patch.object(_client, "get_audit_events", new=AsyncMock(side_effect=mock_response_jsons))
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
    from MimecastEventCollectorV2 import get_audit_events

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
        mocker.patch.object(_client, "get_audit_events", new=AsyncMock(return_value=mock_response_json))
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
    from MimecastEventCollectorV2 import get_siem_events

    start_date = "2025-01-01T00:00:00.000Z"
    limit = 150

    # Both pages return valid cursors (at least one non 0-0 offset) so pagination continues
    page2_cursor = base64.b64encode(b"[av=100-200, delivery=0-0]:1:token2").decode()
    page3_cursor = base64.b64encode(b"[av=200-300, delivery=0-0]:2:token3").decode()
    mock_response_jsons = [
        {  # Page 1
            "value": [{"id": f"event-A{i}", "timestamp": 1704067200000} for i in range(100)],
            "@nextPage": page2_cursor,
        },
        {  # Page 2
            "value": [{"id": f"event-B{i}", "timestamp": 1704070800000} for i in range(50)],
            "@nextPage": page3_cursor,
        },
    ]

    async with async_client as _client:
        mock_get_siem_events = mocker.patch.object(_client, "get_siem_events", new=AsyncMock(side_effect=mock_response_jsons))
        events, next_page = await get_siem_events(
            client=_client,
            start_date=start_date,
            limit=limit,
        )

    assert len(events) == limit
    assert next_page == page3_cursor
    assert mock_get_siem_events.call_count == 2


@pytest.mark.parametrize(
    "cursor, expected",
    [
        pytest.param(None, False, id="None is not a valid cursor"),
        pytest.param("", False, id="Empty string is not a valid cursor"),
        pytest.param("not-base64-!!!", False, id="Non-decodable string is not a valid cursor"),
        pytest.param(
            base64.b64encode(b"no brackets here").decode(),
            False,
            id="Decodable cursor without an offsets block is not valid",
        ),
        pytest.param(
            base64.b64encode(b"[no offsets inside]:0:null").decode(),
            False,
            id="Decodable cursor with a block but no parsable offsets is not valid",
        ),
        # A cursor with all event types at offset 0-0 points to the very beginning for every type and is the
        # degenerate cursor that caused the zero-ingestion bug. We cannot know whether such a cursor - even one
        # that carries a page/token in its ":<page>:<token>" suffix - is genuinely usable, so we deliberately
        # treat every all 0-0 cursor as invalid. Dropping it is always safe: the fetch simply falls back to the
        # start date instead of risking a request with an invalid cursor.
        pytest.param(BAD_SIEM_CURSOR, False, id="All event types with 0-0 offset is not a valid cursor"),
        pytest.param(
            base64.b64encode(b"[attachment_protect=0-0, av=0-0, url_protect=0-1]:1:token").decode(),
            True,
            id="A single non 0-0 offset makes the cursor valid",
        ),
        pytest.param(GOOD_SIEM_CURSOR, True, id="At least one non 0-0 offset is a valid cursor"),
        # Malformed cursor with a missing ":<page>:<token>" suffix must not raise; the offsets alone decide validity.
        pytest.param(
            base64.b64encode(b"[av=5-100]").decode(),
            True,
            id="Malformed cursor missing the suffix segments does not crash (offsets still decide validity)",
        ),
        pytest.param(
            base64.b64encode(b"[av=0-0]").decode(),
            False,
            id="Malformed all 0-0 cursor missing the suffix segments does not crash and stays invalid",
        ),
    ],
)
def test_is_valid_cursor(cursor, expected):
    """
    Given:
     - A base64-encoded SIEM cursor string (or an invalid/empty value).
    When:
     - Calling is_valid_cursor.
    Then:
     - Ensure a cursor with all event types at offset 0-0 (or undecodable/empty) is invalid.
       We cannot reliably tell whether an all 0-0 cursor is usable, so it is treated as invalid on purpose:
       dropping it just falls back to the start date, which is always safe.
     - Ensure a cursor with at least one non 0-0 offset is valid.
     - Ensure malformed cursors (missing suffix segments) are handled without raising.
    """
    from MimecastEventCollectorV2 import is_valid_cursor

    assert is_valid_cursor(cursor) is expected


@pytest.mark.asyncio
async def test_get_siem_events_stops_on_invalid_cursor(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A first page response whose returned @nextPage cursor is an invalid (all 0-0) cursor.
    When:
     - Calling get_siem_events with a limit that would otherwise require more pages.
    Then:
     - Ensure pagination stops after the first page (the invalid cursor is not used for another request).
     - Ensure the returned next_page is None (a cursor proven invalid is discarded, never surfaced to the caller).
    """
    from MimecastEventCollectorV2 import get_siem_events

    mock_response_jsons = [
        {  # Page 1 returns a full page but an invalid cursor -> must not paginate further
            "value": [{"id": f"event-A{i}", "timestamp": 1704067200000} for i in range(100)],
            "@nextPage": BAD_SIEM_CURSOR,
        },
    ]

    async with async_client as _client:
        mock_get_siem_events = mocker.patch.object(_client, "get_siem_events", new=AsyncMock(side_effect=mock_response_jsons))
        events, next_page = await get_siem_events(client=_client, start_date="2025-01-01T00:00:00.000Z", limit=150)

    assert len(events) == 100
    # The invalid cursor is discarded (set to None) so the caller can never mistakenly persist or reuse it.
    assert next_page is None
    assert mock_get_siem_events.call_count == 1


@pytest.mark.asyncio
async def test_get_siem_events_stops_on_invalid_cursor_mid_run(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A first page returning a valid cursor and a second page returning an invalid (all 0-0) cursor.
    When:
     - Calling get_siem_events with a limit that would otherwise require more pages.
    Then:
     - Ensure pagination stops after page 2 (the invalid cursor is not used for a third request).
     - Ensure events already collected from both pages are still returned, sorted by _filter_time.
     - Ensure the returned next_page is None so the caller cannot persist the invalid mid-run cursor.
    """
    from MimecastEventCollectorV2 import get_siem_events

    page2_cursor = base64.b64encode(b"[av=100-200, delivery=0-0]:1:token2").decode()
    mock_response_jsons = [
        {  # Page 1: full page + valid cursor -> paginate
            "value": [{"id": f"event-A{i}", "timestamp": 1704070800000} for i in range(100)],
            "@nextPage": page2_cursor,
        },
        {  # Page 2: full page but an invalid cursor -> stop, discard cursor
            "value": [{"id": f"event-B{i}", "timestamp": 1704067200000} for i in range(50)],
            "@nextPage": BAD_SIEM_CURSOR,
        },
    ]

    async with async_client as _client:
        mock_get_siem_events = mocker.patch.object(_client, "get_siem_events", new=AsyncMock(side_effect=mock_response_jsons))
        events, next_page = await get_siem_events(client=_client, start_date="2025-01-01T00:00:00.000Z", limit=300)

    # Both pages' events are returned even though pagination stopped early on the invalid page-2 cursor.
    assert len(events) == 150
    assert mock_get_siem_events.call_count == 2
    # Events are sorted by _filter_time (page-B timestamp is earlier, so those events come first).
    filter_times = [event[FILTER_TIME_KEY] for event in events]
    assert filter_times == sorted(filter_times)
    # The invalid mid-run cursor must not be surfaced to the caller.
    assert next_page is None


@pytest.mark.asyncio
async def test_get_siem_events_ignores_invalid_incoming_cursor(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An invalid (all 0-0) cursor passed to get_siem_events as the initial next_page.
    When:
     - Calling get_siem_events.
    Then:
     - Ensure the first request is made using the start_date only (invalid cursor is not sent to the API).
    """
    from MimecastEventCollectorV2 import get_siem_events

    mock_response_jsons = [
        {"value": [{"id": "event-1", "timestamp": 1704067200000}], "@nextPage": None},
    ]

    async with async_client as _client:
        mock_get_siem_events = mocker.patch.object(_client, "get_siem_events", new=AsyncMock(side_effect=mock_response_jsons))
        events, _ = await get_siem_events(
            client=_client,
            start_date="2025-01-01T00:00:00.000Z",
            limit=100,
            next_page=BAD_SIEM_CURSOR,
        )

    assert len(events) == 1
    assert mock_get_siem_events.call_count == 1
    # The invalid cursor must not be forwarded to the API request
    assert mock_get_siem_events.call_args.kwargs.get("next_page") is None


@pytest.mark.asyncio
async def test_get_siem_events_uses_valid_incoming_cursor(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A valid cursor passed to get_siem_events as the initial next_page.
    When:
     - Calling get_siem_events.
    Then:
     - Ensure the valid cursor is forwarded as-is to the first API request.
    """
    from MimecastEventCollectorV2 import get_siem_events

    mock_response_jsons = [
        {"value": [{"id": "event-1", "timestamp": 1704067200000}], "@nextPage": None},
    ]

    async with async_client as _client:
        mock_get_siem_events = mocker.patch.object(_client, "get_siem_events", new=AsyncMock(side_effect=mock_response_jsons))
        events, _ = await get_siem_events(
            client=_client,
            start_date="2025-01-01T00:00:00.000Z",
            limit=100,
            next_page=GOOD_SIEM_CURSOR,
        )

    assert len(events) == 1
    assert mock_get_siem_events.call_count == 1
    assert mock_get_siem_events.call_args.kwargs.get("next_page") == GOOD_SIEM_CURSOR


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
    from MimecastEventCollectorV2 import get_events_command

    mock_audit_events = [{"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000", "_time": "2025-01-01T00:00:00Z"}]
    mock_siem_events = [{"id": "event-2", "timestamp": 1704067200000, "_time": "2025-01-01T00:00:00Z"}]

    mocker.patch("MimecastEventCollectorV2.UTC_NOW", datetime(2025, 1, 2, 10, 0, 0, tzinfo=UTC))
    mock_get_audit_events = mocker.patch(
        "MimecastEventCollectorV2.get_audit_events", new=AsyncMock(return_value=mock_audit_events)
    )
    mock_get_siem_events = mocker.patch(
        "MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=(mock_siem_events, "next_page"))
    )
    mock_table_to_markdown = mocker.patch("MimecastEventCollectorV2.tableToMarkdown")

    args = {"event_types": "audit,siem", "limit": "10", "start_date": "1 hour ago"}

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
            id="First fetch with audit events",
        ),
        pytest.param(
            {"start_date": "2025-01-01T00:00:00+0000", "last_fetched_ids": ["event-1"]},
            50,
            [
                {"id": "event-2", "eventTime": "2025-01-01T01:00:00+0000", "_filter_time": "2025-01-01T01:00:00+0000"},
                {"id": "event-3", "eventTime": "2025-01-01T01:00:00+0000", "_filter_time": "2025-01-01T01:00:00+0000"},
            ],
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2", "event-3"]},
            id="Subsequent run with events at same timestamp (uses last _filter_time IDs)",
        ),
        pytest.param(
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2"]},
            100,
            [],
            {"start_date": "2025-01-01T01:00:00+0000", "last_fetched_ids": ["event-2"]},
            id="No new events (keeps last run)",
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
    from MimecastEventCollectorV2 import fetch_audit_events

    mocker.patch("MimecastEventCollectorV2.get_audit_events", new=AsyncMock(return_value=mock_audit_events))

    first_fetch = datetime.now() - timedelta(days=7)
    next_run, events = await fetch_audit_events(async_client, last_run, max_fetch, first_fetch)

    assert next_run == expected_next_run
    assert len(events) == len(mock_audit_events)


@pytest.mark.parametrize(
    "last_run, max_fetch, mock_siem_events, mock_next_page, expected_next_run",
    [
        pytest.param(
            {},
            100,
            [
                {
                    "id": "event-1",
                    "aggregateId": "code-1",
                    "timestamp": 1704067200000,
                    "_filter_time": "2025-01-01T00:00:00.000Z",
                },
                {
                    "id": "event-2",
                    "aggregateId": "code-2",
                    "timestamp": 1704070800000,
                    "_filter_time": "2025-01-01T01:01:00.000Z",
                },
            ],
            "next_page_token_1",
            {
                "start_date": "2025-01-01T01:01:00.000Z",
                "last_fetched_ids": ["event-1", "event-2"],
            },
            id="First fetch with SIEM events (next_page is not persisted)",
        ),
        pytest.param(
            {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-1"]},
            50,
            [
                {
                    "id": "event-2",
                    "aggregateId": "code-2",
                    "timestamp": 1704070800000,
                    "_filter_time": "2025-01-01T01:00:00.000Z",
                },
                {
                    "id": "event-3",
                    "aggregateId": "code-3",
                    "timestamp": 1704070800000,
                    "_filter_time": "2025-01-01T01:00:02.000Z",
                },
            ],
            "next_page_token_2",
            {
                "start_date": "2025-01-01T01:00:02.000Z",
                "last_fetched_ids": ["event-2", "event-3"],
            },
            id="Subsequent run with two events on page (use last page IDs, no next_page persisted)",
        ),
        pytest.param(
            {"start_date": "2025-01-01T01:00:00.000Z", "last_fetched_ids": ["event-2"]},
            100,
            [],
            None,
            {"start_date": "2025-01-01T01:00:00.000Z", "last_fetched_ids": ["event-2"]},
            id="No new events (keeps last run)",
        ),
        pytest.param(
            {},
            200,
            [
                {
                    "id": f"event-{i}",
                    "aggregateId": f"code-{i}",
                    "timestamp": 1704067200000,
                    "_filter_time": "2025-01-01T00:00:00.000Z",
                }
                for i in range(150)
            ],
            "next_page_token_3",
            {
                "start_date": "2025-01-01T00:00:00.000Z",
                "last_fetched_ids": [f"event-{i}" for i in range(150)],
            },
            # Sometimes, even when using passing `next_page` to endpoint, we may get events from previous page on the next page
            # So save IDs from the last page (default 100) or all IDs with the latest _filter_time (whichever is greater)
            id="More than 100 events with same timestamp (uses last _filter_time IDs)",
        ),
    ],
)
@pytest.mark.asyncio
async def test_fetch_siem_events(
    async_client: AsyncClient,
    mocker: MockerFixture,
    last_run: dict,
    max_fetch: int,
    mock_siem_events: list,
    mock_next_page: str | None,
    expected_next_run: dict,
):
    """
    Given:
     - An AsyncClient, last_run (without a persisted next_page), and max_fetch parameters.
    When:
     - Calling fetch_siem_events.
    Then:
     - Ensure that get_siem_events is called using the start_date only (no cursor persisted from a previous run).
     - Ensure the next_run object never persists a next_page (cursor is only used within a single fetch cycle).
    """
    from MimecastEventCollectorV2 import fetch_siem_events, convert_to_siem_filter_format

    mock_siem_first_fetch = datetime(2025, 1, 2, 10, 0, 0, tzinfo=UTC)
    mocker.patch("MimecastEventCollectorV2.UTC_MINUTE_AGO", mock_siem_first_fetch)
    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=True)
    mock_get_siem_events = mocker.patch(
        "MimecastEventCollectorV2.get_siem_events",
        new=AsyncMock(return_value=(mock_siem_events, mock_next_page)),
    )

    next_run, events = await fetch_siem_events(async_client, last_run, max_fetch)

    assert mock_get_siem_events.call_count == 1
    assert mock_get_siem_events.call_args.kwargs == {
        "start_date": last_run.get("start_date") or convert_to_siem_filter_format(mock_siem_first_fetch),
        "limit": max_fetch,
        "last_fetched_ids": last_run.get("last_fetched_ids", []),
        "next_page": None,
    }
    assert next_run == expected_next_run
    assert NEXT_PAGE_KEY not in next_run
    assert len(events) == len(mock_siem_events)


@pytest.mark.asyncio
async def test_fetch_siem_events_no_events_persists_clamped_start_date(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A last run whose start_date is older than 24 hours and an API call that returns NO events
       (e.g. the cursor/date returned nothing).
    When:
     - Calling fetch_siem_events.
    Then:
     - Ensure the next run still persists the clamped (now-23h) start_date so the date is not lost.
     - Ensure the next run keeps the existing last_fetched_ids and does not persist a cursor.
    """
    from MimecastEventCollectorV2 import fetch_siem_events, convert_to_siem_filter_format

    mock_now = datetime(2025, 1, 10, 12, 0, 0, tzinfo=UTC)
    mocker.patch("MimecastEventCollectorV2.UTC_NOW", mock_now)
    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=False)
    mocker.patch("MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=([], None)))

    last_run = {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-1"], "next_page": GOOD_SIEM_CURSOR}
    next_run, events = await fetch_siem_events(async_client, last_run, 100)

    expected_start_date = convert_to_siem_filter_format(mock_now - timedelta(hours=23))
    assert events == []
    assert next_run[START_DATE_KEY] == expected_start_date
    assert next_run[LAST_FETCHED_IDS_KEY] == ["event-1"]
    assert NEXT_PAGE_KEY not in next_run


@pytest.mark.asyncio
async def test_fetch_siem_events_clamps_start_date_beyond_24h(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A last run whose start_date is older than 24 hours.
    When:
     - Calling fetch_siem_events.
    Then:
     - Ensure the start_date used for the request is clamped to now-23h.
    """
    from MimecastEventCollectorV2 import fetch_siem_events, convert_to_siem_filter_format

    mock_now = datetime(2025, 1, 10, 12, 0, 0, tzinfo=UTC)
    mocker.patch("MimecastEventCollectorV2.UTC_NOW", mock_now)
    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=False)
    mock_get_siem_events = mocker.patch("MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=([], None)))

    last_run = {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-1"]}
    await fetch_siem_events(async_client, last_run, 100)

    expected_start_date = convert_to_siem_filter_format(mock_now - timedelta(hours=23))
    assert mock_get_siem_events.call_args.kwargs["start_date"] == expected_start_date
    assert mock_get_siem_events.call_args.kwargs["next_page"] is None


@pytest.mark.asyncio
async def test_fetch_siem_events_migration_valid_persisted_cursor(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A last run that still persists a VALID next_page cursor (from the previous integration version).
    When:
     - Calling fetch_siem_events (migration path).
    Then:
     - Ensure the valid persisted cursor is used for this cycle's first request.
     - Ensure the resulting next_run no longer persists next_page.
    """
    from MimecastEventCollectorV2 import fetch_siem_events

    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=True)
    mock_events = [
        {"id": "event-1", "aggregateId": "code-1", "timestamp": 1704067200000, "_filter_time": "2025-01-01T00:00:00.000Z"},
    ]
    mock_get_siem_events = mocker.patch(
        "MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=(mock_events, "new_cursor"))
    )

    last_run = {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-0"], "next_page": GOOD_SIEM_CURSOR}
    next_run, _ = await fetch_siem_events(async_client, last_run, 100)

    assert mock_get_siem_events.call_args.kwargs["next_page"] == GOOD_SIEM_CURSOR
    assert NEXT_PAGE_KEY not in next_run


@pytest.mark.asyncio
async def test_fetch_siem_events_migration_invalid_persisted_cursor(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A last run that persists an INVALID (all 0-0) next_page cursor from the previous integration version.
    When:
     - Calling fetch_siem_events (migration path).
    Then:
     - Ensure the invalid persisted cursor is NOT used and the request falls back to the start_date.
     - Ensure the resulting next_run no longer persists next_page.
    """
    from MimecastEventCollectorV2 import fetch_siem_events

    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=True)
    mock_events = [
        {"id": "event-1", "aggregateId": "code-1", "timestamp": 1704067200000, "_filter_time": "2025-01-01T00:00:00.000Z"},
    ]
    mock_get_siem_events = mocker.patch(
        "MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=(mock_events, None))
    )

    last_run = {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-0"], "next_page": BAD_SIEM_CURSOR}
    next_run, _ = await fetch_siem_events(async_client, last_run, 100)

    assert mock_get_siem_events.call_args.kwargs["next_page"] is None
    assert mock_get_siem_events.call_args.kwargs["start_date"] == "2025-01-01T00:00:00.000Z"
    assert NEXT_PAGE_KEY not in next_run


@pytest.mark.asyncio
async def test_fetch_siem_events_removes_filter_time_and_keeps_time(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An API call that returns SIEM events already formatted with both _time (for the dataset)
       and _filter_time (internal, for deduplication/last-run only).
    When:
     - Calling fetch_siem_events.
    Then:
     - Ensure every returned event still carries _time (needed by the dataset).
     - Ensure the internal _filter_time key is stripped from every returned event before ingestion.
    """
    from MimecastEventCollectorV2 import fetch_siem_events

    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=True)
    mock_events = [
        {
            "id": "event-1",
            "aggregateId": "code-1",
            "timestamp": 1704067200000,
            "_time": "2025-01-01T00:00:00Z",
            "_filter_time": "2025-01-01T00:00:00.000Z",
        },
        {
            "id": "event-2",
            "aggregateId": "code-2",
            "timestamp": 1704070800000,
            "_time": "2025-01-01T01:00:00Z",
            "_filter_time": "2025-01-01T01:00:00.000Z",
        },
    ]
    mocker.patch("MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=(mock_events, None)))

    last_run = {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": []}
    _, events = await fetch_siem_events(async_client, last_run, 100)

    assert len(events) == 2
    for event in events:
        assert EVENT_TIME_KEY in event, "Returned events must keep _time for the dataset."
        assert FILTER_TIME_KEY not in event, "Internal _filter_time must be stripped before ingestion."


@pytest.mark.parametrize(
    "raised_exception",
    [
        pytest.param(DemistoException("SIEM API call failed"), id="DemistoException (error key branch)"),
        pytest.param(
            ClientResponseError(
                status=500,
                history=(),
                request_info=RequestInfo("", "POST", {}),
                message="Server error",
            ),
            id="ClientResponseError (transport failure)",
        ),
    ],
)
@pytest.mark.asyncio
async def test_fetch_siem_events_propagates_errors_without_corrupting_last_run(
    async_client: AsyncClient,
    mocker: MockerFixture,
    raised_exception: Exception,
):
    """
    Given:
     - A previous last_run with a start_date and last_fetched_ids.
     - An API call (get_siem_events) that raises (either a DemistoException or a ClientResponseError).
    When:
     - Calling fetch_siem_events.
    Then:
     - Ensure the exception propagates (the caller does not silently swallow it).
     - Ensure no partial/corrupted next_run is produced - the original last_run is left untouched so the
       next fetch cycle resumes from the exact same state (setLastRun is only called on success in main()).
    """
    from MimecastEventCollectorV2 import fetch_siem_events

    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=True)
    mocker.patch("MimecastEventCollectorV2.get_siem_events", new=AsyncMock(side_effect=raised_exception))

    last_run = {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-1"]}
    original_last_run = deepcopy(last_run)

    with pytest.raises(type(raised_exception)):
        await fetch_siem_events(async_client, last_run, 100)

    # The input last_run must not be mutated on failure so the next cycle resumes from the same cursor/date.
    assert last_run == original_last_run


@pytest.mark.asyncio
async def test_fetch_events_command_persists_corrected_siem_next_run(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A fetch cycle where fetch_siem_events returns a corrected next_run (no persisted cursor).
    When:
     - Calling fetch_events_command end-to-end (the layer where the original persistence bug lived).
    Then:
     - Ensure the SIEM next_run is nested correctly under the "siem" key.
     - Ensure the persisted SIEM state carries start_date and last_fetched_ids and does NOT persist a cursor.
    """
    from MimecastEventCollectorV2 import fetch_events_command

    mocker.patch("MimecastEventCollectorV2.is_within_last_24_hours", return_value=True)
    siem_events = [
        {"id": "event-1", "aggregateId": "code-1", "timestamp": 1704067200000, "_filter_time": "2025-01-01T00:00:00.000Z"},
    ]
    # get_siem_events returns a non-None cursor; fetch_siem_events must NOT persist it in next_run.
    mocker.patch("MimecastEventCollectorV2.get_siem_events", new=AsyncMock(return_value=(siem_events, "some_cursor")))

    last_run = {"siem": {"start_date": "2025-01-01T00:00:00.000Z", "last_fetched_ids": ["event-0"]}}
    next_run, _ = await fetch_events_command(
        async_client,
        last_run=last_run,
        max_fetch=100,
        event_types=[EventTypes.SIEM.value],
        audit_first_fetch=datetime.now() - timedelta(days=1),
    )

    assert "siem" in next_run
    siem_next_run = next_run["siem"]
    assert START_DATE_KEY in siem_next_run
    assert LAST_FETCHED_IDS_KEY in siem_next_run
    assert NEXT_PAGE_KEY not in siem_next_run


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
    from MimecastEventCollectorV2 import fetch_events_command

    last_run = {}
    max_fetch = 100
    event_types = EventTypes.all_values()

    mock_audit_events = [{"id": "event-1", "eventTime": "2025-01-01T00:00:00+0000"}]
    mock_siem_events = [{"id": "event-2", "timestamp": 1704067200000}]

    mocker.patch(
        "MimecastEventCollectorV2.fetch_audit_events",
        new=AsyncMock(return_value=({"start_date": "2025-01-01T00:00:00+0000"}, mock_audit_events)),
    )
    mocker.patch(
        "MimecastEventCollectorV2.fetch_siem_events",
        new=AsyncMock(return_value=({"start_date": "2025-01-01T00:00:00.000Z"}, mock_siem_events)),
    )
    audit_first_fetch = datetime.now() - timedelta(days=4)
    next_run, events = await fetch_events_command(
        async_client, last_run, max_fetch, event_types, audit_first_fetch=audit_first_fetch
    )

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
    from MimecastEventCollectorV2 import test_module

    event_types = EventTypes.all_values()

    mock_audit_first_fetch = datetime(2025, 1, 2, 10, 0, 0, tzinfo=UTC)
    mocker.patch("MimecastEventCollectorV2.UTC_MINUTE_AGO", mock_audit_first_fetch)
    mock_fetch_events_command = mocker.patch(
        "MimecastEventCollectorV2.fetch_events_command", new=AsyncMock(return_value=({}, []))
    )

    result = await test_module(async_client, event_types)

    assert mock_fetch_events_command.call_count == 1
    assert mock_fetch_events_command.call_args.kwargs == {
        "last_run": {},
        "max_fetch": 1,
        "event_types": event_types,
        "audit_first_fetch": mock_audit_first_fetch,
    }
    assert result == "ok"
