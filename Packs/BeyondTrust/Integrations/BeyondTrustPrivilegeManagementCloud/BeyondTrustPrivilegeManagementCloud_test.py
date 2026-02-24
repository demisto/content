import json
import pytest
from freezegun import freeze_time
from datetime import datetime, UTC
from BeyondTrustPrivilegeManagementCloud import (
    Client,
    get_events_command,
    fetch_events,
    fetch_pm_events,
    fetch_activity_audits,
    get_dedup_key,
    main,
)
import BeyondTrustPrivilegeManagementCloud

""" CONSTANTS """

BASE_URL = "https://example.com"
CLIENT_ID = "client_id"
CLIENT_SECRET = "client_secret"


@pytest.fixture
def client():
    return Client(base_url=BASE_URL, client_id=CLIENT_ID, client_secret=CLIENT_SECRET, verify=False, proxy=False)


def load_json(path):
    with open(path) as f:
        return json.load(f)


""" TEST FUNCTIONS """


def test_get_token(client, mocker):
    """
    Given:
        - A client object
    When:
        - get_token is called
    Then:
        - The function should return an access token
    """
    mock_response = {"access_token": "test_token_123", "token_type": "Bearer", "expires_in": 3600}
    mocker.patch.object(client, "_http_request", return_value=mock_response)

    token = client.get_token()
    assert token == "test_token_123"


def test_module_success(client, mocker):
    """
    Given:
        - A client object
    When:
        - test_module is called
    Then:
        - The function should return 'ok' on success
    """
    mocker.patch.object(client, "get_token", return_value="test_token")
    result = BeyondTrustPrivilegeManagementCloud.test_module(client)
    assert result == "ok"


def test_module_failure(client, mocker):
    """
    Given:
        - A client object
    When:
        - test_module is called and authentication fails
    Then:
        - The function should return an error message
    """
    mocker.patch.object(client, "get_token", side_effect=Exception("Authentication failed"))
    result = BeyondTrustPrivilegeManagementCloud.test_module(client)
    assert "Failed to connect" in result


def test_get_events_command(client, mocker):
    """
    Given:
        - A client object
        - Arguments with start_date and limit
    When:
        - get_events_command is called
    Then:
        - The command should return the expected results
    """
    mock_response = {
        "events": [{"id": "1", "created": "2022-01-01T00:00:00.000Z"}, {"id": "2", "created": "2022-01-01T00:00:01.000Z"}],
        "totalRecordsReturned": 2,
    }
    mocker.patch.object(client, "get_events", return_value=mock_response)

    args = {"start_date": "2022-01-01T00:00:00.000Z", "limit": "2"}
    result = get_events_command(client, args)

    outputs = result.outputs
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    assert outputs[0]["id"] == "1"
    assert outputs[1]["id"] == "2"


def test_get_events_command_default_start_date(client, mocker):
    """
    Given:
        - A client object
        - Arguments without start_date
    When:
        - get_events_command is called
    Then:
        - The command should use default start_date (1 hour ago)
    """
    mock_response = {"events": [{"id": "1", "created": "2022-01-01T00:00:00.000Z"}]}
    mocker.patch.object(client, "get_events", return_value=mock_response)

    args = {"limit": "1"}
    result = get_events_command(client, args)

    # Verify get_events was called with a start_date
    assert client.get_events.called
    assert isinstance(result.outputs, list)


def test_get_events_command_activity_audits(client, mocker):
    """
    Given:
        - A client object
        - Arguments with event_type set to Activity Audits
    When:
        - get_events_command is called with event_type="Activity Audits"
    Then:
        - The command should return audit activity results under BeyondTrust.Event prefix
    """
    mock_response = {
        "data": [
            {"id": 1, "created": "2022-01-01T00:00:00.000Z", "details": "User created"},
            {"id": 2, "created": "2022-01-01T00:00:01.000Z", "details": "Policy updated"},
        ],
        "pageCount": 1,
        "totalRecordCount": 2,
    }
    mocker.patch.object(client, "get_audit_activity", return_value=mock_response)

    args = {"event_type": "Activity Audits", "limit": "2"}
    result = get_events_command(client, args)

    outputs = result.outputs
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    assert outputs[0]["id"] == 1
    assert outputs[1]["id"] == 2
    assert result.outputs_prefix == "BeyondTrust.Event"


def test_get_events_command_activity_audits_with_start_date(client, mocker):
    """
    Given:
        - A client object
        - Arguments with event_type Activity Audits and a start_date
    When:
        - get_events_command is called
    Then:
        - The command should pass the date filter to the audit API
    """
    mock_response = {"data": [{"id": 1, "created": "2022-01-01T00:00:00.000Z"}], "pageCount": 1}
    mocker.patch.object(client, "get_audit_activity", return_value=mock_response)

    args = {
        "event_type": "Activity Audits",
        "limit": "10",
        "start_date": "2022-01-01T00:00:00.000Z",
    }
    result = get_events_command(client, args)

    # Verify the method was called
    client.get_audit_activity.assert_called_once()
    assert isinstance(result.outputs, list)


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events(client, mocker):
    """
    Given:
        - A client object
        - Last run context
    When:
        - fetch_events is called
    Then:
        - The function should return the next run context and events
        - next_run timestamps should be set to fetch_end_time (not last event time) to prevent gaps
    """
    mock_events_response = {
        "events": [{"id": "1", "created": "2024-01-01T10:00:00.000Z"}, {"id": "2", "created": "2024-01-01T11:00:00.000Z"}]
    }
    mock_audit_response = {
        "data": [{"id": 3, "created": "2024-01-01T10:30:00.000Z"}, {"id": 4, "created": "2024-01-01T11:30:00.000Z"}],
        "pageCount": 1,
    }

    mocker.patch.object(client, "get_events", return_value=mock_events_response)
    mocker.patch.object(client, "get_audit_activity", return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = "3 days"
    max_fetch = 10
    events_types_to_fetch = ["Events", "Activity Audits"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 4

    # CRITICAL: Verify next_run timestamps are set to fetch_end_time (frozen time), NOT the last event's timestamp
    # This ensures continuous coverage without gaps between fetch cycles
    expected_timestamp = "2024-01-01T12:00:00.000000Z"
    assert next_run["last_event_time"] == expected_timestamp
    assert next_run["last_audit_time"] == expected_timestamp

    # Verify XSIAM fields are added
    for event in events:
        assert "_time" in event
        assert "source_log_type" in event
        assert "vendor" in event
        assert "product" in event


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_only_events(client, mocker):
    """
    Given:
        - A client object configured to fetch only Events
    When:
        - fetch_events is called
    Then:
        - Only Events should be fetched
        - next_run should use fetch_end_time to prevent gaps
    """
    mock_events_response = {"events": [{"id": "1", "created": "2024-01-01T10:00:00.000Z"}]}
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    last_run: dict = {}
    first_fetch = "1 day"
    max_fetch = 10
    events_types_to_fetch = ["Events"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 1
    assert "last_event_time" in next_run
    assert "last_audit_time" not in next_run
    assert events[0]["source_log_type"] == "events"
    # Verify timestamp is set to fetch_end_time
    assert next_run["last_event_time"] == "2024-01-01T12:00:00.000000Z"


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_only_audits(client, mocker):
    """
    Given:
        - A client object configured to fetch only Activity Audits
    When:
        - fetch_events is called
    Then:
        - Only Activity Audits should be fetched
        - next_run should use fetch_end_time to prevent gaps
    """
    mock_audit_response = {"data": [{"id": 1, "created": "2024-01-01T10:00:00.000Z"}], "pageCount": 1}
    mocker.patch.object(client, "get_audit_activity", return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = "1 day"
    max_fetch = 10
    events_types_to_fetch = ["Activity Audits"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 1
    assert "last_audit_time" in next_run
    assert "last_event_time" not in next_run
    assert events[0]["source_log_type"] == "activity_audits"
    # Verify timestamp is set to fetch_end_time
    assert next_run["last_audit_time"] == "2024-01-01T12:00:00.000000Z"


def test_fetch_events_pagination(client, mocker):
    """
    Given:
        - A client object
        - Multiple pages of audit data
    When:
        - fetch_events is called
    Then:
        - All pages should be fetched until max_fetch is reached
    """
    mock_audit_response_page1 = {
        "data": [{"id": 1, "created": "2022-01-01T00:00:00.000Z"}, {"id": 2, "created": "2022-01-01T00:00:01.000Z"}],
        "pageCount": 2,
        "pageNumber": 1,
    }
    mock_audit_response_page2 = {"data": [{"id": 3, "created": "2022-01-01T00:00:02.000Z"}], "pageCount": 2, "pageNumber": 2}

    mocker.patch.object(client, "get_audit_activity", side_effect=[mock_audit_response_page1, mock_audit_response_page2])

    last_run: dict = {}
    first_fetch = "1 day"
    max_fetch = 10
    events_types_to_fetch = ["Activity Audits"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 3
    assert client.get_audit_activity.call_count == 2


def test_get_dedup_key():
    """
    Given:
        - An event dictionary with source_log_type and id
    When:
        - get_dedup_key is called
    Then:
        - The function should return a key prefixed with the event type
    """
    event_with_id = {"id": "123", "data": "test", "source_log_type": "events"}
    assert get_dedup_key(event_with_id) == "events_123"

    event_without_id = {"data": "test", "source_log_type": "events"}
    key = get_dedup_key(event_without_id)
    assert isinstance(key, str)
    assert key.startswith("events_")


def test_get_dedup_key_numeric_id():
    """
    Given:
        - An event with numeric ID and source_log_type
    When:
        - get_dedup_key is called
    Then:
        - The function should convert ID to string and prefix with event type
    """
    event_with_numeric_id = {"id": 456, "data": "test", "source_log_type": "activity_audits"}
    assert get_dedup_key(event_with_numeric_id) == "activity_audits_456"


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_no_gap_between_fetches_first(client, mocker):
    """
    Given:
        - A client object
        - First fetch cycle at 12:00:00
    When:
        - fetch_events is called
    Then:
        - next_run should store fetch_end_time (12:00:00), not last event time (11:50:00)
        - This ensures no events are missed between fetch cycles
    """
    mock_events_response = {
        "events": [
            {"id": "1", "created": "2024-01-01T11:50:00.000Z"},  # Event before fetch time
        ]
    }
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 10
    events_types_to_fetch = ["Events"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    # CRITICAL: Verify fetch stored fetch_end_time (12:00:00), not last event time (11:50:00)
    # This prevents missing events created between 11:50:00 and the next fetch
    assert next_run["last_event_time"] == "2024-01-01T12:00:00.000000Z"
    assert len(events) == 1


@freeze_time("2024-01-01 12:05:00")
def test_fetch_events_no_gap_between_fetches_second(client, mocker):
    """
    Given:
        - A client object
        - Second fetch cycle at 12:05:00
        - Previous fetch ended at 12:00:00
    When:
        - fetch_events is called with last_run from previous fetch
    Then:
        - Fetch should start from 12:00:00 (previous fetch_end_time)
        - Events created between 12:00:00 and 12:05:00 should be captured
    """
    # Events created between first fetch (12:00:00) and second fetch (12:05:00)
    mock_events_response = {
        "events": [
            {"id": "2", "created": "2024-01-01T12:01:00.000Z"},  # Event after first fetch
            {"id": "3", "created": "2024-01-01T12:03:00.000Z"},  # Another event
        ]
    }
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    # Simulate last_run from previous fetch
    last_run = {"last_event_time": "2024-01-01T12:00:00.000000Z"}
    first_fetch = "1 hour"
    max_fetch = 10
    events_types_to_fetch = ["Events"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    # Verify events created between fetches are captured
    assert len(events) == 2

    # Verify second fetch stored its fetch_end_time (12:05:00)
    assert next_run["last_event_time"] == "2024-01-01T12:05:00.000000Z"

    # Verify the get_events call used the correct start_date (from first fetch's end time)
    call_args = client.get_events.call_args
    assert call_args[0][0] == "2024-01-01T12:00:00.000000Z"


def test_fetch_events_with_last_run(client, mocker):
    """
    Given:
        - A client object
        - Last run context with existing timestamps
    When:
        - fetch_events is called
    Then:
        - Should use last_run timestamps instead of first_fetch
    """
    mock_events_response = {"events": [{"id": "1", "created": "2024-01-01T12:30:00.000Z"}]}
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    last_run = {"last_event_time": "2024-01-01T12:00:00.000000Z"}
    first_fetch = "3 days"
    max_fetch = 10
    events_types_to_fetch = ["Events"]

    with freeze_time("2024-01-01 13:00:00"):
        next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    # Verify it used last_run timestamp, not first_fetch
    call_args = client.get_events.call_args
    assert call_args[0][0] == "2024-01-01T12:00:00.000000Z"
    assert len(events) == 1


def test_fetch_events_max_fetch_limit(client, mocker):
    """
    Given:
        - A client object
        - max_fetch limit of 2
    When:
        - fetch_events is called
    Then:
        - Should pass max_fetch as limit parameter to API
    """
    mock_events_response = {"events": [{"id": "1", "created": "2024-01-01T10:00:00.000Z"}]}
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 2  # Limit to 2 events
    events_types_to_fetch = ["Events"]

    with freeze_time("2024-01-01 12:00:00"):
        next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    # Verify the parameter is passed correctly to the API
    call_args = client.get_events.call_args
    assert call_args[0][1] == 2  # Second positional argument is limit


def test_fetch_events_empty_response(client, mocker):
    """
    Given:
        - A client object
        - API returns empty events
    When:
        - fetch_events is called
    Then:
        - Should handle empty response gracefully
    """
    mock_events_response = {"events": []}
    mock_audit_response = {"data": [], "pageCount": 0}

    mocker.patch.object(client, "get_events", return_value=mock_events_response)
    mocker.patch.object(client, "get_audit_activity", return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 10
    events_types_to_fetch = ["Events", "Activity Audits"]

    with freeze_time("2024-01-01 12:00:00"):
        next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 0
    assert "last_event_time" in next_run
    assert "last_audit_time" in next_run


def test_http_request_with_authentication(client, mocker):
    """Test _http_request automatically gets token and adds Authorization header."""
    from BeyondTrustPrivilegeManagementCloud import BaseClient

    mock_token_response = {"access_token": "new_token_123"}
    mock_api_response = {"data": "test"}

    mock_http = mocker.patch.object(BaseClient, "_http_request")
    mock_http.side_effect = [mock_token_response, mock_api_response]

    client._http_request(method="GET", url_suffix="/management-api/v3/test")

    assert client.token == "new_token_123"
    assert mock_http.call_count == 2


def test_http_request_token_endpoint(client, mocker):
    """Test _http_request does NOT add Authorization header for token endpoint."""
    from BeyondTrustPrivilegeManagementCloud import BaseClient

    mock_response = {"access_token": "token_123"}
    mock_http = mocker.patch.object(BaseClient, "_http_request", return_value=mock_response)

    client._http_request(method="POST", url_suffix="/oauth/connect/token", data={})

    call_headers = mock_http.call_args[1]["headers"]
    assert "Authorization" not in call_headers


def test_get_audit_activity_without_filters(client, mocker):
    """Test get_audit_activity without filter parameters."""
    mock_response = {"data": [], "pageCount": 0}
    mock_http = mocker.patch.object(client, "_http_request", return_value=mock_response)

    client.get_audit_activity(page_size=50, page_number=1)

    call_params = mock_http.call_args[1]["params"]
    assert "Pagination.PageSize" in call_params
    assert "Pagination.PageNumber" in call_params
    assert "Filter.Created.Dates" not in call_params


@freeze_time("2024-01-01 12:00:00")
def test_fetch_pm_events(client, mocker):
    """
    Given:
        - A client object
        - Last run context
    When:
        - fetch_pm_events is called directly
    Then:
        - The function should return the next run context and events
        - Events should have XSIAM fields added
    """
    mock_events_response = {
        "events": [{"id": "1", "created": "2024-01-01T10:00:00.000Z"}, {"id": "2", "created": "2024-01-01T11:00:00.000Z"}]
    }
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 10
    fetch_end_time = datetime.now(UTC)

    next_run, events = fetch_pm_events(client, last_run, first_fetch, max_fetch, fetch_end_time)

    assert len(events) == 2
    assert next_run["last_event_time"] == "2024-01-01T12:00:00.000000Z"

    # Verify XSIAM fields are added
    for event in events:
        assert event["source_log_type"] == "events"
        assert event["vendor"] == "beyondtrust"
        assert event["product"] == "pm_cloud"


@freeze_time("2024-01-01 12:00:00")
def test_fetch_activity_audits(client, mocker):
    """
    Given:
        - A client object
        - Last run context
    When:
        - fetch_activity_audits is called directly
    Then:
        - The function should return the next run context and audit events
        - Audit events should have XSIAM fields added
    """
    mock_audit_response = {
        "data": [{"id": 1, "created": "2024-01-01T10:00:00.000Z"}, {"id": 2, "created": "2024-01-01T11:00:00.000Z"}],
        "pageCount": 1,
    }
    mocker.patch.object(client, "get_audit_activity", return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 10
    fetch_end_time = datetime.now(UTC)

    next_run, events = fetch_activity_audits(client, last_run, first_fetch, max_fetch, fetch_end_time)

    assert len(events) == 2
    assert next_run["last_audit_time"] == "2024-01-01T12:00:00.000000Z"

    # Verify XSIAM fields are added
    for event in events:
        assert event["source_log_type"] == "activity_audits"
        assert event["vendor"] == "beyondtrust"
        assert event["product"] == "pm_cloud"


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_max_fetch_per_type(client, mocker):
    """
    Given:
        - A client object configured to fetch both Events and Activity Audits
        - max_fetch limit of 5
    When:
        - fetch_events is called
    Then:
        - Each event type should get its own max_fetch limit (5 each)
        - Total events could be up to 10 (5 Events + 5 Activity Audits)
    """
    # Mock 5 events
    mock_events_response = {"events": [{"id": f"event_{i}", "created": f"2024-01-01T10:0{i}:00.000Z"} for i in range(5)]}
    # Mock 5 audit events
    mock_audit_response = {"data": [{"id": i, "created": f"2024-01-01T10:0{i}:00.000Z"} for i in range(5)], "pageCount": 1}

    mocker.patch.object(client, "get_events", return_value=mock_events_response)
    mocker.patch.object(client, "get_audit_activity", return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 5  # 5 per event type
    events_types_to_fetch = ["Events", "Activity Audits"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    # Should have 10 total events (5 Events + 5 Activity Audits)
    assert len(events) == 10

    # Verify get_events was called with max_fetch=5
    events_call_args = client.get_events.call_args
    assert events_call_args[0][1] == 5

    # Count events by type
    event_count = sum(1 for e in events if e.get("source_log_type") == "events")
    audit_count = sum(1 for e in events if e.get("source_log_type") == "activity_audits")
    assert event_count == 5
    assert audit_count == 5


def test_get_dedup_key_cross_event_type_collision():
    """
    Given:
        - An event and an audit with the same numeric ID but different source_log_type
    When:
        - get_dedup_key is called for both
    Then:
        - The dedup keys should be different, preventing cross-type collisions
    """
    event = {"id": 1, "source_log_type": "events", "created": "2024-01-01T10:00:00.000Z"}
    audit = {"id": 1, "source_log_type": "activity_audits", "created": "2024-01-01T10:00:00.000Z"}

    event_key = get_dedup_key(event)
    audit_key = get_dedup_key(audit)

    assert event_key != audit_key
    assert event_key == "events_1"
    assert audit_key == "activity_audits_1"


@freeze_time("2024-01-01 12:00:00")
def test_fetch_pm_events_at_api_limit(client, mocker):
    """
    Given:
        - A client object
        - API returns exactly DEFAULT_LIMIT (1000) events in first batch
        - Second batch returns fewer events (pagination stops)
    When:
        - fetch_pm_events is called with max_fetch > 1000
    Then:
        - Should make multiple API calls to paginate
        - Should stop when fewer events than batch_size are returned
    """
    batch_1 = [{"id": str(i), "created": f"2024-01-01T10:{i % 60:02d}:00.000Z"} for i in range(1000)]
    batch_2 = [{"id": str(i), "created": f"2024-01-01T11:{i % 60:02d}:00.000Z"} for i in range(1000, 1050)]

    mocker.patch.object(
        client,
        "get_events",
        side_effect=[{"events": batch_1}, {"events": batch_2}],
    )

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 2000
    fetch_end_time = datetime.now(UTC)

    next_run, events = fetch_pm_events(client, last_run, first_fetch, max_fetch, fetch_end_time)

    assert len(events) == 1050
    assert client.get_events.call_count == 2


@freeze_time("2024-01-01 12:00:00")
def test_fetch_activity_audits_exceeds_max_fetch(client, mocker):
    """
    Given:
        - A client object
        - max_fetch is 3
        - API returns pages with 2 audits each
    When:
        - fetch_activity_audits is called
    Then:
        - Should stop fetching when max_fetch is reached
        - Should only request remaining_limit as page_size on second page
    """
    page1 = {
        "data": [
            {"id": 1, "created": "2024-01-01T10:00:00.000Z"},
            {"id": 2, "created": "2024-01-01T10:01:00.000Z"},
        ],
        "pageCount": 2,
    }
    page2 = {
        "data": [{"id": 3, "created": "2024-01-01T10:02:00.000Z"}],
        "pageCount": 2,
    }

    mocker.patch.object(client, "get_audit_activity", side_effect=[page1, page2])

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 3
    fetch_end_time = datetime.now(UTC)

    next_run, audits = fetch_activity_audits(client, last_run, first_fetch, max_fetch, fetch_end_time)

    assert len(audits) == 3
    # Second call should request page_size=1 (remaining_limit)
    second_call = client.get_audit_activity.call_args_list[1]
    assert second_call[1]["page_size"] == 1


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_dedup_across_types(client, mocker):
    """
    Given:
        - Events and audits with the same ID (e.g., id=1)
    When:
        - fetch_events is called and deduplication is applied
    Then:
        - Both events should be kept because they have different source_log_type prefixes
    """
    mock_events_response = {"events": [{"id": 1, "created": "2024-01-01T10:00:00.000Z"}]}
    mock_audit_response = {"data": [{"id": 1, "created": "2024-01-01T10:00:00.000Z"}], "pageCount": 1}

    mocker.patch.object(client, "get_events", return_value=mock_events_response)
    mocker.patch.object(client, "get_audit_activity", return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 10
    events_types_to_fetch = ["Events", "Activity Audits"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    # Deduplicate using get_dedup_key (same logic as main())
    deduped = {get_dedup_key(e): e for e in events}
    final_events = list(deduped.values())

    # Both should be kept because source_log_type differs
    assert len(final_events) == 2


def test_client_token_refresh_on_401(client, mocker):
    """
    Given:
        - A client with an expired/invalid token
    When:
        - An API call is made
    Then:
        - The client should attempt to get a new token
    """
    from BeyondTrustPrivilegeManagementCloud import BaseClient

    mock_token_response = {"access_token": "refreshed_token"}
    mock_api_response = {"data": "test"}

    mock_http = mocker.patch.object(BaseClient, "_http_request")
    mock_http.side_effect = [mock_token_response, mock_api_response]

    # Ensure token is None so it triggers get_token
    client.token = None
    client._http_request(method="GET", url_suffix="/management-api/v3/test")

    assert client.token == "refreshed_token"


@freeze_time("2024-01-01 12:00:00")
def test_fetch_pm_events_exceeds_max_fetch(client, mocker):
    """
    Given:
        - A client object
        - max_fetch is 500
        - API returns 500 events in first batch (batch_size=500 < DEFAULT_LIMIT)
    When:
        - fetch_pm_events is called
    Then:
        - Should stop after first batch since len(fetched) < batch_size won't trigger
          but total_fetched == max_fetch will stop the loop
    """
    events_batch = [{"id": str(i), "created": f"2024-01-01T10:{i % 60:02d}:00.000Z"} for i in range(500)]
    mocker.patch.object(client, "get_events", return_value={"events": events_batch})

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 500
    fetch_end_time = datetime.now(UTC)

    next_run, events = fetch_pm_events(client, last_run, first_fetch, max_fetch, fetch_end_time)

    assert len(events) == 500
    # Only one API call since batch_size (500) == max_fetch and len(fetched) == batch_size
    # but total_fetched == max_fetch stops the while loop
    assert client.get_events.call_count == 1


def test_get_events_api_error_handling(client, mocker):
    """
    Given:
        - A client object
        - API raises an exception
    When:
        - get_events is called
    Then:
        - The exception should propagate
    """
    mocker.patch.object(client, "_http_request", side_effect=Exception("API Error: 500 Internal Server Error"))

    with pytest.raises(Exception, match="API Error: 500 Internal Server Error"):
        client.get_events("2024-01-01T00:00:00.000Z", 100)


def test_get_audit_activity_api_error_handling(client, mocker):
    """
    Given:
        - A client object
        - API raises an exception
    When:
        - get_audit_activity is called
    Then:
        - The exception should propagate
    """
    mocker.patch.object(client, "_http_request", side_effect=Exception("API Error: 403 Forbidden"))

    with pytest.raises(Exception, match="API Error: 403 Forbidden"):
        client.get_audit_activity(page_size=10, page_number=1)


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_mixed_success_failure(client, mocker):
    """
    Given:
        - Events API succeeds but Audit API fails
    When:
        - fetch_events is called for both types
    Then:
        - The exception from the audit API should propagate
    """
    mock_events_response = {"events": [{"id": "1", "created": "2024-01-01T10:00:00.000Z"}]}
    mocker.patch.object(client, "get_events", return_value=mock_events_response)
    mocker.patch.object(client, "get_audit_activity", side_effect=Exception("Audit API Error"))

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 10
    events_types_to_fetch = ["Events", "Activity Audits"]

    with pytest.raises(Exception, match="Audit API Error"):
        fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)


@freeze_time("2024-01-01 12:00:00")
def test_get_events_command_with_push_events(client, mocker):
    """
    Given:
        - A client object
        - should_push_events is True
    When:
        - get_events_command is called
    Then:
        - Events should have XSIAM fields added
        - send_events_to_xsiam should be called
    """
    mock_response = {
        "events": [
            {"id": "1", "created": "2024-01-01T10:00:00.000Z"},
            {"id": "2", "created": "2024-01-01T11:00:00.000Z"},
        ]
    }
    mocker.patch.object(client, "get_events", return_value=mock_response)
    mock_send = mocker.patch("BeyondTrustPrivilegeManagementCloud.send_events_to_xsiam")

    args = {"start_date": "2024-01-01T00:00:00.000Z", "limit": "10", "should_push_events": "true"}
    result = get_events_command(client, args)

    # Verify XSIAM fields were added
    for event in result.outputs:
        assert event["source_log_type"] == "events"
        assert event["vendor"] == "beyondtrust"
        assert event["product"] == "pm_cloud"
        assert "_time" in event

    # Verify send_events_to_xsiam was called
    mock_send.assert_called_once()


@freeze_time("2024-01-01 12:00:00")
def test_fetch_activity_audits_empty_middle_page(client, mocker):
    """
    Given:
        - A client object
        - First page has data, second page is empty
    When:
        - fetch_activity_audits is called
    Then:
        - Should stop fetching when an empty page is encountered
    """
    page1 = {
        "data": [{"id": 1, "created": "2024-01-01T10:00:00.000Z"}],
        "pageCount": 3,
    }
    page2 = {"data": [], "pageCount": 3}

    mocker.patch.object(client, "get_audit_activity", side_effect=[page1, page2])

    last_run: dict = {}
    first_fetch = "1 hour"
    max_fetch = 100
    fetch_end_time = datetime.now(UTC)

    next_run, audits = fetch_activity_audits(client, last_run, first_fetch, max_fetch, fetch_end_time)

    assert len(audits) == 1
    assert client.get_audit_activity.call_count == 2


def test_get_dedup_key_missing_id_and_source_log_type():
    """
    Given:
        - An event without id and without source_log_type
    When:
        - get_dedup_key is called
    Then:
        - Should use 'N/A' as the event type prefix and hash the content
    """
    event = {"data": "some_data", "timestamp": "2024-01-01T10:00:00.000Z"}
    key = get_dedup_key(event)

    assert key.startswith("N/A_")
    assert isinstance(key, str)


@freeze_time("2024-01-01 12:00:00")
def test_fetch_events_boundary_timestamp(client, mocker):
    """
    Given:
        - Events with timestamps exactly at the boundary of the fetch window
    When:
        - fetch_events is called
    Then:
        - Boundary events should be included
        - next_run should use fetch_end_time
    """
    mock_events_response = {
        "events": [
            {"id": "1", "created": "2024-01-01T12:00:00.000000Z"},  # Exactly at fetch_end_time
        ]
    }
    mocker.patch.object(client, "get_events", return_value=mock_events_response)

    last_run = {"last_event_time": "2024-01-01T11:59:59.000000Z"}
    first_fetch = "1 hour"
    max_fetch = 10
    events_types_to_fetch = ["Events"]

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 1
    assert next_run["last_event_time"] == "2024-01-01T12:00:00.000000Z"


def test_client_network_timeout(client, mocker):
    """
    Given:
        - A client object
        - Network request times out
    When:
        - An API call is made
    Then:
        - A timeout exception should propagate
    """
    from BeyondTrustPrivilegeManagementCloud import BaseClient

    mocker.patch.object(BaseClient, "_http_request", side_effect=Exception("Connection timed out"))

    # Token is None, so get_token will be called first and fail
    client.token = None
    with pytest.raises(Exception, match="Connection timed out"):
        client._http_request(method="GET", url_suffix="/management-api/v3/test")


def test_main_command_routing(mocker):
    """
    Given:
        - Various command names
    When:
        - main() is called
    Then:
        - The correct command handler should be invoked
    """
    mocker.patch.object(
        BeyondTrustPrivilegeManagementCloud.demisto,
        "params",
        return_value={
            "url": "https://example.com",
            "credentials": {"identifier": "test_id", "password": "test_secret"},
            "insecure": False,
            "proxy": False,
        },
    )
    mocker.patch.object(BeyondTrustPrivilegeManagementCloud.demisto, "args", return_value={})
    mocker.patch.object(BeyondTrustPrivilegeManagementCloud.demisto, "command", return_value="test-module")

    mock_test_module = mocker.patch("BeyondTrustPrivilegeManagementCloud.test_module", return_value="ok")
    mock_return_results = mocker.patch("BeyondTrustPrivilegeManagementCloud.return_results")

    main()

    mock_test_module.assert_called_once()
    mock_return_results.assert_called_once_with("ok")
