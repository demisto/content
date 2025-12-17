import json
from datetime import UTC
import pytest
from pytest_mock import MockerFixture
from aiohttp import ClientResponseError, RequestInfo
from unittest.mock import AsyncMock
from freezegun import freeze_time
from CommonServerPython import *
from GenesysCloud import (
    ACCESS_TOKEN_KEY,
    TOKEN_TYPE_KEY,
    TOKEN_TTL_KEY,
    TOKEN_VALID_UNTIL_KEY,
    DATE_FORMAT,
    DEFAULT_SERVER_URL,
    AsyncClient,
    deduplicate_and_format_events,
    get_audit_events_for_service,
    get_events_command,
    fetch_events_command,
)

SERVER_URL = DEFAULT_SERVER_URL


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture()
def async_client():
    return AsyncClient(
        base_url=SERVER_URL,
        client_id="test_client_id",
        client_secret="test_client_secret",
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
    mock_token_response = {
        "access_token": "test_access_token_12345",
        "token_type": "bearer",
        "expires_in": 86400,
    }

    mock_response = mock_async_session_response(mock_token_response)

    async with async_client as _client:
        mocker.patch.object(_client._session, "post", return_value=mock_response)
        token_response = await _client._generate_new_access_token()

    assert token_response == mock_token_response
    assert _client._session.post.call_args.kwargs["url"] == "https://login.mypurecloud.com/oauth/token"
    assert _client._session.post.call_args.kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"
    assert _client._session.post.call_args.kwargs["params"]["grant_type"] == "client_credentials"


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
    token_url = urljoin(SERVER_URL.replace("api.", "login."), "/oauth/token")
    error_message = "Invalid client credentials"

    mock_response = mock_async_session_response(response_json={"error": error_message})

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
@freeze_time("2025-01-02T10:00:00Z")
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
    # Mock integration context functions
    mock_get_context = mocker.patch("GenesysCloud.get_integration_context", return_value=integration_context)
    mock_set_context = mocker.patch("GenesysCloud.set_integration_context")

    # Mock token generation response
    mock_token_response = {
        ACCESS_TOKEN_KEY: "new_generated_token",
        TOKEN_TYPE_KEY: "bearer",
        TOKEN_TTL_KEY: 86400,
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
                # Verify token validity is set correctly (86400 - 300 = 86100 seconds from now)
                expected_valid_until = datetime(2025, 1, 3, 9, 55, 0, tzinfo=UTC)  # 10:00 + 86100 seconds
                actual_valid_until = arg_to_datetime(set_context_call_args[TOKEN_VALID_UNTIL_KEY])
                assert actual_valid_until == expected_valid_until
        else:
            # Existing token was used
            assert auth_header == "Bearer existing_token"


@pytest.mark.asyncio
async def test_async_client_get_realtime_audits(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling get_realtime_audits with specific parameters.
    Then:
     - Ensure the correct HTTP POST request is made to the audits endpoint.
     - Ensure the correct response is returned.
    """
    from_date = "2025-01-01T00:00:00Z"
    to_date = "2025-01-02T00:00:00Z"
    service_name = "Architect"
    page_number = 1
    page_size = 500

    mock_response_json = {
        "entities": [
            {"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"},
            {"id": "event-2", "eventDate": "2025-01-01T01:00:00Z"},
        ],
        "pageNumber": 1,
        "pageSize": 500,
    }

    mock_response = mock_async_session_response(response_json=mock_response_json)
    mock_get_auth_header = mocker.patch.object(async_client, "get_authorization_header", return_value="Bearer test_token")

    async with async_client as _client:
        mock_post_request = mocker.patch.object(_client._session, "post", return_value=mock_response)
        response_json = await _client.get_realtime_audits(
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            page_number=page_number,
            page_size=page_size,
        )

    assert response_json == mock_response_json
    assert mock_get_auth_header.call_count == 1
    assert mock_post_request.call_args.kwargs["url"] == f"{SERVER_URL}/api/v2/audits/query/realtime"
    assert mock_post_request.call_args.kwargs["json"]["serviceName"] == service_name
    assert mock_post_request.call_args.kwargs["json"]["pageNumber"] == page_number


@pytest.mark.asyncio
async def test_async_client_get_realtime_audits_401_retry(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling get_realtime_audits and receiving a 401 Unauthorized error.
    Then:
     - Ensure the client forces a new token generation and retries the request.
    """
    from_date = "2025-01-01T00:00:00Z"
    to_date = "2025-01-02T00:00:00Z"
    service_name = "Architect"
    page_number = 1

    mock_response_json = {"entities": [{"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"}]}

    mock_responses = [
        mock_async_session_response(error_status_code=401, error_message="Unauthorized"),  # 1st call: expired token error
        mock_async_session_response(mock_response_json),  # 2nd call (after token refresh): new events
    ]

    mock_get_auth_header = mocker.patch.object(async_client, "get_authorization_header", return_value="Bearer test_token")

    async with async_client as _client:
        mock_post_request = mocker.patch.object(_client._session, "post", side_effect=mock_responses)
        response_json = await _client.get_realtime_audits(
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            page_number=page_number,
        )

    assert response_json == mock_response_json
    assert mock_get_auth_header.call_count == 2  # First call + retry with `force_generate_new_token=True`
    assert mock_post_request.call_count == 2


@pytest.mark.asyncio
async def test_async_client_get_realtime_audits_429_retry(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient instance.
    When:
     - Calling get_realtime_audits and receiving a 429 Too many requests error.
    Then:
     - Ensure the client waits for a few seconds and retries the request.
    """
    from_date = "2025-01-01T00:00:00Z"
    to_date = "2025-01-02T00:00:00Z"
    service_name = "Outbound"
    page_number = 1

    mock_response_json = {"entities": [{"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"}]}

    mock_responses = [
        mock_async_session_response(error_status_code=429, error_message="Too many requests"),  # 1st call -> rate limit
        mock_async_session_response(error_status_code=429, error_message="Too many requests"),  # 2nd call (after 1s): rate limit
        mock_async_session_response(mock_response_json),  # Second call (after 2s) -> new events
    ]

    mocker.patch.object(async_client, "get_authorization_header", return_value="Bearer test_token")

    async with async_client as _client:
        mock_post_request = mocker.patch.object(_client._session, "post", side_effect=mock_responses)
        response_json = await _client.get_realtime_audits(
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            page_number=page_number,
        )

    assert response_json == mock_response_json
    assert mock_post_request.call_count == 3


@pytest.mark.parametrize(
    "raw_response, all_fetched_ids, expected_events_count, expected_all_ids_count",
    [
        pytest.param(
            {
                "entities": [
                    {"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"},
                    {"id": "event-2", "eventDate": "2025-01-01T01:00:00Z"},
                ]
            },
            set(),
            2,
            2,
            id="No duplicates",
        ),
        pytest.param(
            {
                "entities": [
                    {"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"},
                    {"id": "event-2", "eventDate": "2025-01-01T01:00:00Z"},
                ]
            },
            {"event-1"},
            1,
            2,
            id="With duplicates",
        ),
        pytest.param(
            {"entities": []},
            {"event-1"},
            0,
            1,
            id="Empty raw response",
        ),
        pytest.param(
            {"entities": [{"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"}]},
            {"event-1"},
            0,
            1,
            id="All duplicates",
        ),
    ],
)
def test_deduplicate_and_format_events(
    raw_response: dict[str, Any],
    all_fetched_ids: set[str],
    expected_events_count: int,
    expected_all_ids_count: int,
):
    """
    Given:
     - A raw API response and a set of already fetched event IDs.
    When:
     - Calling deduplicate_and_format_events.
    Then:
     - Ensure that events are correctly deduplicated and formatted.
     - Ensure that the set of fetched IDs is correctly updated.
    """
    service_name = "Integrations"
    new_events = deduplicate_and_format_events(raw_response, all_fetched_ids, service_name)

    assert len(new_events) == expected_events_count
    assert len(all_fetched_ids) == expected_all_ids_count

    for event in new_events:
        assert event["_time"] == arg_to_datetime(event["eventDate"]).strftime(DATE_FORMAT)
        assert event["source_log_type"] == service_name


@pytest.mark.asyncio
async def test_get_audit_events_for_service_pagination(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit that requires fetching multiple pages of events.
    When:
     - Calling get_audit_events_for_service.
    Then:
     - Ensure that multiple API calls are made concurrently and events are aggregated.
    """
    from_date = "2025-01-01T00:00:00Z"
    to_date = "2025-01-02T00:00:00Z"
    service_name = "Architect"
    limit = 1000  # Requires 2 pages (500 each)

    mock_response_jsons = [
        {  # Page 0
            "entities": [{"id": f"event-A{i}", "eventDate": "2025-01-01T00:00:00Z"} for i in range(500)],
        },
        {  # Page 1
            "entities": [{"id": f"event-B{i}", "eventDate": "2025-01-01T01:00:00Z"} for i in range(500)],
        },
    ]

    async with async_client as _client:
        # Mock get_realtime_audits to return the actual JSON responses
        mock_get_realtime_audits = mocker.patch.object(_client, "get_realtime_audits", side_effect=mock_response_jsons)
        events = await get_audit_events_for_service(
            client=_client,
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            limit=limit,
        )

    assert len(events) == limit
    assert mock_get_realtime_audits.call_count == 2  # Two pages fetched concurrently


@pytest.mark.asyncio
async def test_get_audit_events_for_service_with_deduplication(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - A limit and a list of previously fetched event IDs.
    When:
     - Calling get_audit_events_for_service.
    Then:
     - Ensure that duplicate events are filtered out.
    """
    from_date = "2025-01-01T00:00:00Z"
    to_date = "2025-01-02T00:00:00Z"
    service_name = "Architect"
    limit = 500
    last_fetched_ids = ["event-A0", "event-A1"]

    mock_response_json = {
        "entities": [
            {"id": "event-A0", "eventDate": "2025-01-01T00:00:00Z"},  # Duplicate
            {"id": "event-A1", "eventDate": "2025-01-01T00:00:00Z"},  # Duplicate
            {"id": "event-A2", "eventDate": "2025-01-01T00:00:00Z"},  # New
        ],
    }

    async with async_client as _client:
        # Mock get_realtime_audits to return the actual JSON response
        mocker.patch.object(_client, "get_realtime_audits", return_value=mock_response_json)
        events = await get_audit_events_for_service(
            client=_client,
            from_date=from_date,
            to_date=to_date,
            service_name=service_name,
            limit=limit,
            last_fetched_ids=last_fetched_ids,
        )

    assert len(events) == 1  # Only one new event after deduplication
    assert events[0]["id"] == "event-A2"


@freeze_time("2025-01-02T00:00:00Z")
@pytest.mark.asyncio
async def test_get_events_command(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - An AsyncClient and command arguments.
    When:
     - Calling get_events_command.
    Then:
     - Ensure get_audit_events_for_service is called with the correct arguments.
     - Ensure tableToMarkdown is called with the correct arguments.
    """
    mock_events = [{"id": "event-1", "eventDate": "2025-01-01T00:00:00Z", "_time": "2025-01-01T00:00:00Z"}]

    mock_get_audit_events = mocker.patch("GenesysCloud.get_audit_events_for_service", return_value=mock_events)
    mock_table_to_markdown = mocker.patch("GenesysCloud.tableToMarkdown")

    args = {"service_name": "Architect", "limit": "10", "from_date": "1 day ago"}

    events, _ = await get_events_command(async_client, args)

    assert events == mock_events
    assert mock_get_audit_events.call_args.kwargs["service_name"] == "Architect"
    assert mock_get_audit_events.call_args.kwargs["limit"] == 10
    assert mock_table_to_markdown.call_args.kwargs["name"] == "Genesys Cloud Audit Events from Service: Architect"
    assert mock_table_to_markdown.call_args.kwargs["t"] == mock_events


@pytest.mark.parametrize(
    "last_run, max_fetch, mock_events_per_service, expected_next_run",
    [
        pytest.param(
            {},
            100,
            {
                "Architect": [
                    {"id": "event-1", "eventDate": "2025-01-01T00:00:00Z"},
                    {"id": "event-2", "eventDate": "2025-01-01T01:00:00Z"},
                ],
                "PeoplePermissions": [
                    {"id": "event-3", "eventDate": "2025-01-01T00:30:00Z"},
                ],
            },
            {
                "Architect": {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2"]},
                "PeoplePermissions": {"from_date": "2025-01-01T00:30:00Z", "last_fetched_ids": ["event-3"]},
            },
            id="Initial run with multiple services",
        ),
        pytest.param(
            {
                "Architect": {"from_date": "2025-01-01T00:00:00Z", "last_fetched_ids": ["event-1"]},
            },
            50,
            {
                "Architect": [
                    {"id": "event-2", "eventDate": "2025-01-01T01:00:00Z"},
                    {"id": "event-3", "eventDate": "2025-01-01T01:00:00Z"},
                ],
            },
            {
                "Architect": {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2", "event-3"]},
            },
            id="Subsequent run with events at same timestamp",
        ),
        pytest.param(
            {
                "Architect": {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2"]},
            },
            100,
            {"Architect": []},
            {
                "Architect": {"from_date": "2025-01-01T01:00:00Z", "last_fetched_ids": ["event-2"]},
            },
            id="No new events",
        ),
    ],
)
@pytest.mark.asyncio
async def test_fetch_events_command(
    async_client: AsyncClient,
    mocker: MockerFixture,
    last_run: dict,
    max_fetch: int,
    mock_events_per_service: dict,
    expected_next_run: dict,
):
    """
    Given:
     - An AsyncClient, last_run, and max_fetch parameters.
    When:
     - Calling fetch_events_command.
    Then:
     - Ensure that get_audit_events_for_service is called for each service.
     - Ensure that the next_run object and events are returned correctly.
    """
    service_names = list(mock_events_per_service.keys())

    async def mock_get_audit_events(client, from_date, to_date, service_name, limit, last_fetched_ids=None):
        return mock_events_per_service.get(service_name, [])

    mocker.patch("GenesysCloud.get_audit_events_for_service", side_effect=mock_get_audit_events)

    next_run, events = await fetch_events_command(async_client, last_run, max_fetch, service_names)

    assert next_run == expected_next_run
    total_expected_events = sum(len(evts) for evts in mock_events_per_service.values())
    assert len(events) == total_expected_events


@pytest.mark.asyncio
async def test_fetch_events_command_service_failure_isolation(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - Multiple services to fetch events from.
    When:
     - One service fails but others succeed.
    Then:
     - Ensure that successful services' events are still returned.
     - Ensure that the failure is logged but doesn't stop other services.
    """
    service_names = ["Architect", "PeoplePermissions", "ContactCenter"]
    last_run = {}
    max_fetch = 100

    async def mock_get_audit_events(client, from_date, to_date, service_name, limit, last_fetched_ids=None):
        if service_name == "PeoplePermissions":
            raise Exception("Service error")
        return [{"id": f"{service_name}-event-1", "eventDate": "2025-01-01T00:00:00Z"}]

    mocker.patch("GenesysCloud.get_audit_events_for_service", side_effect=mock_get_audit_events)
    mock_demisto_error = mocker.patch.object(demisto, "error")

    next_run, events = await fetch_events_command(async_client, last_run, max_fetch, service_names)

    # Should have events from 2 successful services
    assert len(events) == 2
    assert mock_demisto_error.call_count == 1
    assert "PeoplePermissions" in mock_demisto_error.call_args[0][0]


@pytest.mark.asyncio
async def test_fetch_events_command_all_services_fail(async_client: AsyncClient, mocker: MockerFixture):
    """
    Given:
     - Multiple services to fetch events from.
    When:
     - All services fail.
    Then:
     - Ensure a DemistoException is raised.
    """
    service_names = ["Architect", "PeoplePermissions"]
    last_run = {}
    max_fetch = 100

    async def mock_get_audit_events(client, from_date, to_date, service_name, limit, last_fetched_ids=None):
        raise Exception("Service error")

    mocker.patch("GenesysCloud.get_audit_events_for_service", side_effect=mock_get_audit_events)
    mocker.patch.object(demisto, "error")

    with pytest.raises(DemistoException, match="Fetching events failed from all services"):
        await fetch_events_command(async_client, last_run, max_fetch, service_names)
