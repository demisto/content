import datetime
import re

import dateparser
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
