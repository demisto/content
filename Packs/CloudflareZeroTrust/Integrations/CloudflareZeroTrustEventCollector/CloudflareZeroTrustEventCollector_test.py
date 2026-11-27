import datetime
import re

import dateparser
import demistomock as demisto
import pytest
from CloudflareZeroTrustEventCollector import (
    ACCOUNT_AUDIT_TYPE,
    ACCESS_AUTHENTICATION_TYPE,
    AuthTypes,
    Client,
    calculate_fetch_dates,
    DATE_FORMAT,
    DemistoException,
    fetch_events,
    format_events,
    get_events_command,
    generate_event_id_if_not_exists,
    handle_duplicates,
    prepare_next_run,
    SignalTimeoutError,
)
from freezegun import freeze_time

MOCK_BASE_URL = "https://api.cloudflare.com"
MOCK_ACCOUNT_ID = "mock_account_id"

MOCK_API_TOKEN = "test_token_123"
MOCK_GLOBAL_API_KEY = "mock_api_key"
MOCK_EMAIL = "test@example.com"

MOCK_API_TOKEN_HEADERS = {"Authorization": f"Bearer {MOCK_API_TOKEN}"}
MOCK_GLOBAL_API_KEY_HEADERS = {"X-Auth-Email": MOCK_EMAIL, "X-Auth-Key": MOCK_GLOBAL_API_KEY}

MOCK_TIME_UTC_NOW = "2024-01-01T00:00:00.000000Z"


# Sample event data for testing
SAMPLE_EVENTS = [
    {"id": "4", "created_at": "2024-01-01T11:59:58Z"},
    {"id": "3", "when": "2024-01-01T11:59:59Z"},
    {"id": "2", "when": "2024-01-01T12:00:00Z"},
    {"id": "1", "when": "2024-01-01T12:00:00Z"},
]


@pytest.fixture
def mock_client() -> Client:
    """Fixture to create a mock client for testing."""
    return Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        headers=MOCK_GLOBAL_API_KEY_HEADERS,
        account_id=MOCK_ACCOUNT_ID,
    )


@freeze_time(MOCK_TIME_UTC_NOW)
def test_test_module(mock_client: Client, mocker):
    """Test the test_module function."""
    from CloudflareZeroTrustEventCollector import test_module

    mocker.patch("CloudflareZeroTrustEventCollector.fetch_events", return_value=({}, []))
    events_types = ["Account Audit Logs", "User Audit Logs", "Access Authentication Logs"]
    result = test_module(mock_client, events_types)
    assert result == "ok"


@freeze_time(MOCK_TIME_UTC_NOW)
def test_fetch_events_completes(mock_client: Client, mocker):
    """
    Given: Event types to fetch with their `max_fetch` limits.
    When: Calling `fetch_events` and the `fetch_events_for_type` function completes in time.
    Then: Ensure the `next_run` has the right `last_fetch` timestamp and the events are returned.
    """
    mocker.patch(
        "CloudflareZeroTrustEventCollector.Client.get_events",
        return_value={"result": [{"id": "event1", "created_at": "2024-01-01T00:00:00Z"}]},
    )

    last_run = {}
    max_fetch_account_audit = 5
    max_fetch_user_audit = 5
    max_fetch_authentication = 5
    event_types_to_fetch = ["Account Audit Logs", "User Audit Logs"]

    next_run, events = fetch_events(
        client=mock_client,
        last_run=last_run,
        max_fetch_account_audit=max_fetch_account_audit,
        max_fetch_user_audit=max_fetch_user_audit,
        max_fetch_authentication=max_fetch_authentication,
        event_types_to_fetch=event_types_to_fetch,
    )

    assert len(events) == 2  # one for each type, since the len(result) < page_size: break condition.
    assert events[0]["id"] == "event1"
    assert events[0].get("SOURCE_LOG_TYPE")
    assert next_run["Account Audit Logs"]["last_fetch"] == "2024-01-01T00:00:00Z"


def test_fetch_events_times_out(mock_client: Client, mocker):
    """
    Given: Event types to fetch with their `max_fetch` limits.
    When: Calling `fetch_events` and the `fetch_events_for_type` function times out.
    Then: Ensure the timeout logic is executed; the `next_run` has the right `max_fetch` value and no events are returned.
    """
    from CloudflareZeroTrustEventCollector import ACCOUNT_AUDIT_TYPE

    max_fetch_account_audit = 20
    max_fetch_user_audit = 5
    max_fetch_authentication = 5
    last_run = {ACCOUNT_AUDIT_TYPE: {"last_fetch": "2024-01-01T00:00:00Z"}}
    event_types_to_fetch = [ACCOUNT_AUDIT_TYPE]

    mocker.patch("CloudflareZeroTrustEventCollector.fetch_events_for_type", side_effect=SignalTimeoutError)

    next_run, events = fetch_events(
        client=mock_client,
        last_run=last_run,
        max_fetch_account_audit=max_fetch_account_audit,
        max_fetch_user_audit=max_fetch_user_audit,
        max_fetch_authentication=max_fetch_authentication,
        event_types_to_fetch=event_types_to_fetch,
    )

    # Timeout handler should have been called,
    assert next_run[ACCOUNT_AUDIT_TYPE]["max_fetch"] == max_fetch_account_audit // 2  # Reduce max_fetch limit
    assert "nextTrigger" not in next_run  # Do not set nextTrigger since all event types timed out
    assert events == []  # No events returned on timeout


@freeze_time(MOCK_TIME_UTC_NOW)
def test_get_events_command(mock_client: Client, mocker):
    """Test the get_events_command function."""
    mocker.patch(
        "CloudflareZeroTrustEventCollector.Client.get_events",
        return_value={
            "result": [
                {"id": "event1", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "event2", "created_at": "2024-01-01T00:00:01Z"},
            ]
        },
    )

    args = {"limit": "2", "event_types_to_fetch": "Account Audit Logs", "start_date": "2024-01-01T00:00:00Z"}

    events, command_results = get_events_command(mock_client, args)

    assert len(events) == 2
    assert events[0]["id"] == "event1"
    assert events[1]["id"] == "event2"
    assert len(command_results) == 1
    assert "Cloudflare Zero Trust Account Audit Logs Events" in command_results[0].readable_output


@freeze_time(MOCK_TIME_UTC_NOW)
def test_calculate_fetch_dates_with_last_run():
    """
    Given: A mock Cloudflare API client and last run key.
    When: Running CalculateFetchDates with last run.
    Then: Ensure the returned start date is the last fetch time, and the end date is the current time.
    """
    last_fetch_time = (dateparser.parse(MOCK_TIME_UTC_NOW) - datetime.timedelta(minutes=1)).strftime(DATE_FORMAT)
    next_run = {"last_fetch": last_fetch_time, "events_ids": "event1"}
    start_date = calculate_fetch_dates(next_run=next_run)

    assert start_date == last_fetch_time


@freeze_time(MOCK_TIME_UTC_NOW)
def test_calculate_fetch_dates_without_arguments():
    """
    Given: A mock Cloudflare API client.
    When: Running CalculateFetchDates with no arguments.
    Then: Ensure the returned start date is 1 minute before the current time, and the end date is the current time.
    """
    start_date = calculate_fetch_dates(next_run={})
    assert start_date == (dateparser.parse(MOCK_TIME_UTC_NOW) - datetime.timedelta(minutes=1)).strftime(DATE_FORMAT)


def test_prepare_next_run():
    """Test the prepare_next_run function."""
    latest_time, latest_ids = prepare_next_run(SAMPLE_EVENTS)

    assert latest_time == "2024-01-01T12:00:00Z"
    assert latest_ids == ["2", "1"]


def test_generate_event_id_if_not_exists():
    """
    Given: Two events (one with an `id` field and one without).
    When: Calling `generate_event_id_if_not_exists`.
    Then: Ensure the `id` is preserved for the first event and generated for the second.
    """
    original_event_id = "187d944c61940c77"

    test_events = [
        {  # With ID
            "id": original_event_id,
            "when": "2025-01-01T05:20:00.12345Z",
            "ip_address": "1.2.3.4",
            "user_email": "user@example.com",
            "action": "logout",
        },
        {  # Without ID
            "action": "login",
            "allowed": True,
            "connection": "saml",
            "user_email": "user@example.com",
            "created_at": "2025-01-01T05:20:00.12345Z",
        },
    ]
    generate_event_id_if_not_exists(test_events)

    assert test_events[0]["id"] == original_event_id
    assert test_events[1]["id"] == "ffc4ff957a3d1a39ebc27580b26e7b135d0b2b511f0d786da257ed9a607d7b57"


@pytest.mark.parametrize(
    "event, event_type, expected_time",
    [
        pytest.param(
            {"id": "A", "created_at": "2025-01-01T05:20:24.12345Z"},
            ACCOUNT_AUDIT_TYPE,
            "2025-01-01T05:20:24Z",
            id="Account audit event with `created_id` field",
        ),
        pytest.param(
            {"when": "2025-01-01T23:03:12.12345Z"},
            ACCESS_AUTHENTICATION_TYPE,
            "2025-01-01T23:03:12Z",
            id="Access authentication event with `when` field",
        ),
    ],
)
def test_format_events(event: dict, event_type: str, expected_time: str):
    """
    Given: An event of a specific type.
    When: Calling `format_events`.
    Then: Ensure the event has the correct `_time` and `SOURCE_LOG_TYPE` values.
    """
    events = [event]
    format_events(event_type, events)

    assert events[0]["_time"] == expected_time
    assert events[0]["SOURCE_LOG_TYPE"] == event_type


def test_handle_duplicates():
    """Test the handle_duplicates function."""
    previous_ids = ["1", "3"]
    filtered_events = handle_duplicates(SAMPLE_EVENTS, previous_ids)

    assert len(filtered_events) == 2  # IDs "2" and "4" remain
    assert filtered_events[0]["id"] == "4"
    assert filtered_events[1]["id"] == "2"


@pytest.mark.parametrize(
    "params, expected_headers",
    [
        pytest.param(
            {
                "auth_type": AuthTypes.API_TOKEN.value,
                "token_credentials": {"password": MOCK_API_TOKEN},
            },
            MOCK_API_TOKEN_HEADERS,
            id="API token headers",
        ),
        pytest.param(
            {
                "auth_type": AuthTypes.GLOBAL_API_KEY.value,
                "credentials": {"identifier": MOCK_EMAIL, "password": MOCK_GLOBAL_API_KEY},
            },
            MOCK_GLOBAL_API_KEY_HEADERS,
            id="Global API key headers",
        ),
    ],
)
def test_validate_headers_returns_correct_headers(params: dict, expected_headers: dict):
    """
    Given: Valid configuration parameters of an integration instance.
    When: Calling validate_headers.
    Then: Ensure the returned authorization headers are as expected.
    """
    from CloudflareZeroTrustEventCollector import validate_headers

    assert validate_headers(params) == expected_headers


@pytest.mark.parametrize(
    "params, expected_error_message",
    [
        pytest.param(
            {
                "auth_type": AuthTypes.API_TOKEN.value,
                "token_credentials": {},
            },
            f"API Token is required for the {AuthTypes.API_TOKEN.value} authorization type.",
            id="API Token type chosen with empty token credentials",
        ),
        pytest.param(
            {
                "auth_type": AuthTypes.GLOBAL_API_KEY.value,
                "credentials": {"identifier": MOCK_EMAIL},
            },
            f"API Email and Global API Key are required for the {AuthTypes.GLOBAL_API_KEY.value} authorization type.",
            id="Global API Key type chosen with partial credentials",
        ),
        pytest.param(
            {
                "auth_type": AuthTypes.GLOBAL_API_KEY.value,
                "credentials": {"identifier": MOCK_EMAIL, "password": MOCK_GLOBAL_API_KEY},
                "token_credentials": {"password": MOCK_API_TOKEN},
            },
            f"API Token should be left blank for the {AuthTypes.GLOBAL_API_KEY.value} authorization type.",
            id="Global API Key type chosen with API Token credentials",
        ),
        pytest.param(
            {"auth_type": "Hello!"},
            "Invalid authorization type: 'Hello!'.",
            id="Invalid authorization type",
        ),
    ],
)
def test_validate_headers_raises_exception(params: dict, expected_error_message: str):
    """
    Given: Invalid configuration parameters of an integration instance.
    When: Calling `validate_headers`.
    Then: Ensure the correct exception is raised with the expected error message.
    """
    from CloudflareZeroTrustEventCollector import validate_headers

    with pytest.raises(DemistoException, match=re.escape(expected_error_message)):
        validate_headers(params)


@pytest.mark.parametrize("max_fetch, previous_ids", [(625, 19), (625, 23), (1, 0), (5000, 0)])
def test_fetch_events_for_type_uses_fixed_page_size(mock_client: Client, mocker, max_fetch: int, previous_ids: int):
    """
    Given: Any `max_fetch` limit (including a reduced one after timeouts) and any number of deduplication IDs.
    When: Calling `fetch_events_for_type`.
    Then: Ensure the request always uses the fixed page size, never a value derived from `max_fetch` + IDs.

    Regression for XSUP-77377: a derived page size such as 644 made the Access Authentication Logs endpoint
    return HTTP 400 with error code 12091, which stopped event collection.
    """
    from CloudflareZeroTrustEventCollector import ACCESS_AUTHENTICATION_PAGE_SIZE, fetch_events_for_type

    get_events = mocker.patch.object(Client, "get_events", return_value={"result": []})
    last_run = {"last_fetch": "2024-01-01T00:00:00Z", "events_ids": [str(i) for i in range(previous_ids)]}

    fetch_events_for_type(
        client=mock_client,
        last_run=last_run,
        max_fetch=max_fetch,
        max_page_size=ACCESS_AUTHENTICATION_PAGE_SIZE,
        event_type=ACCESS_AUTHENTICATION_TYPE,
    )

    assert get_events.call_args.args[1] == ACCESS_AUTHENTICATION_PAGE_SIZE


def test_fetch_events_for_type_trims_to_max_fetch(mock_client: Client, mocker):
    """
    Given: A full page of events larger than `max_fetch`.
    When: Calling `fetch_events_for_type`.
    Then: Ensure only `max_fetch` events are returned, even though a full page was requested.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    page = [{"id": str(i), "created_at": "2024-01-01T00:00:00Z"} for i in range(10)]
    mocker.patch.object(Client, "get_events", return_value={"result": page})

    events, _ = fetch_events_for_type(
        client=mock_client, last_run={}, max_fetch=3, max_page_size=10, event_type=ACCESS_AUTHENTICATION_TYPE
    )

    assert [event["id"] for event in events] == ["0", "1", "2"]


def test_fetch_events_for_type_advances_since_instead_of_paging(mock_client: Client, mocker):
    """
    Given: A full page of events followed by a short page.
    When: Calling `fetch_events_for_type`.
    Then: Ensure the second request moves `since` to the last event of the first page and asks for page 1 again,
          and that events repeated at the boundary second are deduplicated.

    Regression for XSUP-77377: paging deep into an old window (page=2, 3, ...) made Cloudflare return HTTP 504.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    first_page = [
        {"id": "a", "created_at": "2024-01-01T00:00:00Z"},
        {"id": "b", "created_at": "2024-01-01T00:00:01Z"},
        {"id": "c", "created_at": "2024-01-01T00:00:02Z"},
    ]
    # Cloudflare returns the boundary-second event "c" again, because `since` is inclusive.
    second_page = [{"id": "c", "created_at": "2024-01-01T00:00:02Z"}, {"id": "d", "created_at": "2024-01-01T00:00:03Z"}]
    get_events = mocker.patch.object(Client, "get_events", side_effect=[{"result": first_page}, {"result": second_page}])

    events, next_run = fetch_events_for_type(
        client=mock_client,
        last_run={"last_fetch": "2024-01-01T00:00:00Z", "events_ids": []},
        max_fetch=10,
        max_page_size=3,
        event_type=ACCESS_AUTHENTICATION_TYPE,
    )

    assert [call.args[0] for call in get_events.call_args_list] == ["2024-01-01T00:00:00Z", "2024-01-01T00:00:02Z"]
    assert [call.args[2] for call in get_events.call_args_list] == [1, 1]  # always page 1, never deeper
    assert [event["id"] for event in events] == ["a", "b", "c", "d"]
    assert next_run == {"last_fetch": "2024-01-01T00:00:03Z", "events_ids": ["d"]}


def test_fetch_events_for_type_pages_when_whole_page_shares_one_second(mock_client: Client, mocker):
    """
    Given: A full page where every event has the same timestamp, so `since` cannot move forward.
    When: Calling `fetch_events_for_type`.
    Then: Ensure it falls back to requesting the next page with the same `since`, instead of repeating the same request.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    same_second = [{"id": str(i), "created_at": "2024-01-01T00:00:00Z"} for i in range(3)]
    next_second = [{"id": "x", "created_at": "2024-01-01T00:00:01Z"}]
    get_events = mocker.patch.object(Client, "get_events", side_effect=[{"result": same_second}, {"result": next_second}])

    events, _ = fetch_events_for_type(
        client=mock_client,
        last_run={"last_fetch": "2024-01-01T00:00:00Z", "events_ids": []},
        max_fetch=10,
        max_page_size=3,
        event_type=ACCESS_AUTHENTICATION_TYPE,
    )

    assert [(call.args[0], call.args[2]) for call in get_events.call_args_list] == [
        ("2024-01-01T00:00:00Z", 1),
        ("2024-01-01T00:00:00Z", 2),
    ]
    assert [event["id"] for event in events] == ["0", "1", "2", "x"]


def test_fetch_events_for_type_stops_on_full_page_without_new_events(mock_client: Client, mocker):
    """
    Given: A full page that contains only events that were already fetched.
    When: Calling `fetch_events_for_type`.
    Then: Ensure the loop stops instead of requesting the same data forever.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    page = [{"id": str(i), "created_at": f"2024-01-01T00:00:0{i}Z"} for i in range(3)]
    get_events = mocker.patch.object(Client, "get_events", return_value={"result": page})

    events, _ = fetch_events_for_type(
        client=mock_client,
        last_run={"last_fetch": "2024-01-01T00:00:00Z", "events_ids": ["0", "1", "2"]},
        max_fetch=10,
        max_page_size=3,
        event_type=ACCESS_AUTHENTICATION_TYPE,
    )

    assert events == []
    assert get_events.call_count == 1


def test_get_events_retries_server_errors(mock_client: Client, mocker):
    """
    Given: A request to any Cloudflare endpoint.
    When: Calling `get_events`.
    Then: Ensure transient server errors (including HTTP 504) are retried with backoff.
    """
    from CloudflareZeroTrustEventCollector import RETRY_COUNT, RETRY_STATUS_CODES

    http_request = mocker.patch.object(Client, "_http_request", return_value={"result": []})

    mock_client.get_events("2024-01-01T00:00:00Z", 1000, 1, ACCESS_AUTHENTICATION_TYPE)

    kwargs = http_request.call_args.kwargs
    assert kwargs["retries"] == RETRY_COUNT > 0
    assert 504 in kwargs["status_list_to_retry"] == RETRY_STATUS_CODES


def test_generate_event_id_logs_once_per_batch(mocker):
    """
    Given: Many events without an `id` field.
    When: Calling `generate_event_id_if_not_exists`.
    Then: Ensure a single debug line is written for the whole batch, not one per event.

    A debug line per event cost about 17 seconds per 1000 events, which made high-volume fetches time out.
    """
    debug = mocker.patch.object(demisto, "debug")
    events = [{"created_at": "2024-01-01T00:00:00Z", "n": i} for i in range(50)]

    generate_event_id_if_not_exists(events)

    assert all("id" in event for event in events)
    assert debug.call_count == 1


@freeze_time(MOCK_TIME_UTC_NOW)
def test_fetch_events_isolates_failing_event_type(mock_client: Client, mocker):
    """
    Given: One event type raises an API error while the other succeeds.
    When: Calling `fetch_events`.
    Then: Ensure the successful event type's events and last run are returned, and the failing type keeps its last run.

    Regression for XSUP-77377: an error in one event type used to abort the whole fetch, so the last run was never
    saved and the events of every other event type were discarded.
    """
    from CloudflareZeroTrustEventCollector import USER_AUDIT_TYPE

    mocker.patch.object(demisto, "error")
    failing_last_run = {"last_fetch": "2024-01-01T00:00:00Z", "events_ids": ["x"]}

    def side_effect(client, last_run, max_fetch, max_page_size, event_type, start_fetch_date=""):
        if event_type == ACCESS_AUTHENTICATION_TYPE:
            raise DemistoException("Error in API call [400] - Bad Request")
        return [{"id": "a"}], {"last_fetch": "2024-01-02T00:00:00Z", "events_ids": ["a"]}

    mocker.patch("CloudflareZeroTrustEventCollector.fetch_events_for_type", side_effect=side_effect)

    next_run, events = fetch_events(
        client=mock_client,
        last_run={ACCESS_AUTHENTICATION_TYPE: dict(failing_last_run, max_fetch=625)},
        max_fetch_account_audit=5,
        max_fetch_user_audit=5,
        max_fetch_authentication=5,
        event_types_to_fetch=[USER_AUDIT_TYPE, ACCESS_AUTHENTICATION_TYPE],
    )

    assert events == [{"id": "a"}]
    assert next_run[USER_AUDIT_TYPE] == {"last_fetch": "2024-01-02T00:00:00Z", "events_ids": ["a"]}
    assert next_run[ACCESS_AUTHENTICATION_TYPE] == dict(failing_last_run, max_fetch=625)
    assert "nextTrigger" not in next_run


def test_fetch_events_for_type_keeps_events_when_later_page_fails(mock_client: Client, mocker):
    """
    Given: The first page succeeds and a later page fails with a server error.
    When: Calling `fetch_events_for_type`.
    Then: Ensure the first page's events are returned and the last run advances past them.

    Regression for XSUP-77377: a 500/504 on page 2 discarded page 1, so the last run never advanced and the same
    window failed on every fetch.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    mocker.patch.object(demisto, "error")
    first_page = [{"id": str(i), "created_at": f"2024-01-01T00:00:{i:02d}Z"} for i in range(3)]
    mocker.patch.object(
        Client,
        "get_events",
        side_effect=[{"result": first_page}, DemistoException("Error in API call [504] - Gateway Timeout")],
    )

    events, next_run = fetch_events_for_type(
        client=mock_client,
        last_run={"last_fetch": "2024-01-01T00:00:00Z", "events_ids": []},
        max_fetch=10,
        max_page_size=3,
        event_type=ACCESS_AUTHENTICATION_TYPE,
    )

    assert [event["id"] for event in events] == ["0", "1", "2"]
    assert next_run == {"last_fetch": "2024-01-01T00:00:02Z", "events_ids": ["2"]}


def test_fetch_events_for_type_raises_when_first_page_fails(mock_client: Client, mocker):
    """
    Given: The first page fails.
    When: Calling `fetch_events_for_type`.
    Then: Ensure the error is raised, since no progress was made.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    mocker.patch.object(Client, "get_events", side_effect=DemistoException("Error in API call [500] - Internal Server Error"))

    with pytest.raises(DemistoException, match="500"):
        fetch_events_for_type(
            client=mock_client, last_run={}, max_fetch=10, max_page_size=3, event_type=ACCESS_AUTHENTICATION_TYPE
        )


def test_fetch_events_for_type_propagates_timeout_on_later_page(mock_client: Client, mocker):
    """
    Given: The first page succeeds and the execution timeout fires while fetching a later page.
    When: Calling `fetch_events_for_type`.
    Then: Ensure the timeout propagates so `fetch_events` applies its timeout handling.
    """
    from CloudflareZeroTrustEventCollector import fetch_events_for_type

    first_page = [{"id": str(i), "created_at": "2024-01-01T00:00:00Z"} for i in range(3)]
    mocker.patch.object(Client, "get_events", side_effect=[{"result": first_page}, SignalTimeoutError()])

    with pytest.raises(SignalTimeoutError):
        fetch_events_for_type(
            client=mock_client, last_run={}, max_fetch=10, max_page_size=3, event_type=ACCESS_AUTHENTICATION_TYPE
        )


def test_fetch_events_raises_when_all_event_types_fail(mock_client: Client, mocker):
    """
    Given: Every event type raises an API error.
    When: Calling `fetch_events`.
    Then: Ensure an exception is raised instead of silently reporting an empty successful fetch.
    """
    mocker.patch.object(demisto, "error")
    mocker.patch(
        "CloudflareZeroTrustEventCollector.fetch_events_for_type",
        side_effect=DemistoException("Error in API call [400] - Bad Request"),
    )

    with pytest.raises(DemistoException, match="Failed fetching all event types"):
        fetch_events(
            client=mock_client,
            last_run={},
            max_fetch_account_audit=5,
            max_fetch_user_audit=5,
            max_fetch_authentication=5,
            event_types_to_fetch=[ACCOUNT_AUDIT_TYPE, ACCESS_AUTHENTICATION_TYPE],
        )
