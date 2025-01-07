import pytest
import dateparser
import datetime
from freezegun import freeze_time
from CloudflareZeroTrustEventCollector import (
    Client,
    fetch_events,
    get_events_command,
    calculate_fetch_dates,
    prepare_next_run,
    handle_duplicates,
    DATE_FORMAT,
)


MOCK_BASE_URL = "https://api.cloudflare.com"
MOCK_ACCOUNT_ID = "mock_account_id"
MOCK_HEADERS = {
    'X-Auth-Email': "test@example.com",
    'X-Auth-Key': "mock_api_key"
}

MOCK_TIME_UTC_NOW = "2024-01-01T00:00:00.000000Z"


# Sample event data for testing
SAMPLE_EVENTS = [
    {"id": "4", "created_at": "2024-01-01T11:59:58Z"},
    {"id": "3", "when": "2024-01-01T11:59:59Z"},
    {"id": "2", "when": "2024-01-01T12:00:00Z"},
    {"id": "1", "when": "2024-01-01T12:00:00Z"}
]


@pytest.fixture
def mock_client() -> Client:
    """Fixture to create a mock client for testing."""
    return Client(
        base_url=MOCK_BASE_URL,
        verify=False,
        proxy=False,
        headers=MOCK_HEADERS,
        account_id=MOCK_ACCOUNT_ID
    )


@freeze_time(MOCK_TIME_UTC_NOW)
def test_test_module(mock_client: Client, mocker):
    """Test the test_module function."""
    from CloudflareZeroTrustEventCollector import test_module
    mocker.patch(
        "CloudflareZeroTrustEventCollector.fetch_events",
        return_value=({}, [])
    )
    events_types = ["Account Audit Logs", "User Audit Logs", "Access Authentication Logs"]
    result = test_module(mock_client, events_types)
    assert result == "ok"


@freeze_time(MOCK_TIME_UTC_NOW)
def test_fetch_events(mock_client: Client, mocker):
    """Test the fetch_events function."""
    mocker.patch(
        "CloudflareZeroTrustEventCollector.Client.get_events",
        return_value={
            "result": [{"id": "event1", "created_at": "2024-01-01T00:00:00Z"}]
        }
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
        event_types_to_fetch=event_types_to_fetch
    )

    assert len(events) == 2  # one for each type, since the len(result) < page_size: break condition.
    assert events[0]["id"] == "event1"
    assert events[0].get("SOURCE_LOG_TYPE")
    assert next_run["Account Audit Logs"]["last_fetch"] == "2024-01-01T00:00:00Z"


@freeze_time(MOCK_TIME_UTC_NOW)
def test_get_events_command(mock_client: Client, mocker):
    """Test the get_events_command function."""
    mocker.patch(
        "CloudflareZeroTrustEventCollector.Client.get_events",
        return_value={
            "result": [
                {"id": "event1", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "event2", "created_at": "2024-01-01T00:00:01Z"}
            ]
        }
    )

    args = {
        "limit": "2",
        "event_types_to_fetch": "Account Audit Logs",
        "start_date": "2024-01-01T00:00:00Z"
    }

    events, command_results = get_events_command(mock_client, args)

    assert len(events) == 2
    assert events[0]["id"] == "event1"
    assert events[1]["id"] == "event2"
    assert len(command_results) == 1
    assert "Cloudflare Zero Trust Account Audit Logs Events" in command_results[0].readable_output


@freeze_time(MOCK_TIME_UTC_NOW)
def test_calculate_fetch_dates_with_last_run():
    """
    Given: A mock JamfProtect client and last run key.
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
    Given: A mock JamfProtect client.
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


def test_handle_duplicates():
    """Test the handle_duplicates function."""
    previous_ids = ["1", "3"]
    filtered_events = handle_duplicates(SAMPLE_EVENTS, previous_ids)

    assert len(filtered_events) == 2  # IDs "2" and "4" remain
    assert filtered_events[0]["id"] == "4"
    assert filtered_events[1]["id"] == "2"
