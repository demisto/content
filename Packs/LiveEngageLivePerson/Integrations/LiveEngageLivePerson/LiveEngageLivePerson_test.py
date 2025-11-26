import pytest
from requests.exceptions import RequestException  # type: ignore
from requests_mock import Mocker
from datetime import datetime, timedelta, UTC  # type: ignore

# Import the script
import LiveEngageLivePerson
from CommonServerPython import *
# import demistomock as demisto  # type: ignore


# Define constants for testing
PARAMS = {
    "auth_server_url": "sy.sentinel.liveperson.net",
    "account_id": "123456789",
    "credentials": {"identifier": "test_client_id", "password": "test_client_secret"},
    "insecure": False,
    "proxy": False,
    "max_fetch": 1000,
    "first_fetch": "1 days",
}

MOCK_DOMAIN_RESPONSE = {"baseURI": "va.ac.liveperson.net"}
MOCK_AUTH_RESPONSE = {"access_token": "mock_token_123"}

# --- Mock Event Data ---
# Note: Timestamps must be in ISO format and advance
MOCK_TIME_1 = (datetime.now(UTC) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
MOCK_TIME_2 = (datetime.now(UTC) - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
MOCK_TIME_3 = (datetime.now(UTC) - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")

MOCK_EVENT_1 = {"changeDate": MOCK_TIME_1, "accountId": "123456789", "element": "event1"}
MOCK_EVENT_2 = {"changeDate": MOCK_TIME_2, "accountId": "123456789", "element": "event2"}
MOCK_EVENT_3 = {"changeDate": MOCK_TIME_3, "accountId": "123456789", "element": "event3"}

# Page of 2 events
MOCK_EVENTS_PAGE_1: dict[str, list[dict[str, str]]] = {"data": [MOCK_EVENT_1, MOCK_EVENT_2]}
# Page of 1 event
MOCK_EVENTS_PAGE_2: dict[str, list[dict[str, str]]] = {"data": [MOCK_EVENT_3]}
# Empty page
MOCK_EVENTS_EMPTY: dict[str, list[dict[str, str]]] = {"data": []}


@pytest.fixture(autouse=True)
def mock_demisto(mocker):
    """Mock all demisto functions."""
    mocker.patch.object(demisto, "params", return_value=PARAMS)
    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, "args", return_value={})
    mocker.patch.object(demisto, "getLastRun", return_value={})
    mocker.patch.object(demisto, "setLastRun")
    mocker.patch.object(demisto, "info")
    mocker.patch.object(demisto, "debug")
    mocker.patch.object(demisto, "error")
    mocker.patch.object(demisto, "results")
    mocker.patch.object(demisto, "return_error")
    mocker.patch.object(LiveEngageLivePerson, "send_events_to_xsiam")
    mocker.patch.object(LiveEngageLivePerson, "handle_proxy", return_value={})


@pytest.fixture
def client(mocker) -> LiveEngageLivePerson.Client:
    """Fixture to create a Client object with mocked domain/auth calls."""
    # Mock the two static setup methods to simplify testing of instance methods
    mocker.patch.object(LiveEngageLivePerson.Client, "_get_event_domain", return_value="https://va.ac.liveperson.net")
    mocker.patch.object(LiveEngageLivePerson.Client, "_get_access_token", return_value="mock_token_123")

    return LiveEngageLivePerson.Client(
        base_url="https://va.ac.liveperson.net",
        account_id=PARAMS["account_id"],
        auth_server_url=PARAMS["auth_server_url"],
        client_id=PARAMS["credentials"]["identifier"],
        client_secret=PARAMS["credentials"]["password"],
        verify=True,
        proxy=False,
    )


# ==================================
# --- Test Client Static Methods ---
# ==================================


def test_get_event_domain_success(requests_mock: Mocker):
    """Test successful fetching of the event domain."""
    requests_mock.get(LiveEngageLivePerson.DOMAIN_API_URL.format(account_id=PARAMS["account_id"]), json=MOCK_DOMAIN_RESPONSE)
    domain = LiveEngageLivePerson.Client._get_event_domain(PARAMS["account_id"], True, {})
    assert domain == f"https://{MOCK_DOMAIN_RESPONSE['baseURI']}"


@pytest.mark.parametrize("status_code", [404, 500])
def test_get_event_domain_http_error(requests_mock: Mocker, status_code: int):
    """Test HTTP error when fetching event domain."""
    requests_mock.get(
        LiveEngageLivePerson.DOMAIN_API_URL.format(account_id=PARAMS["account_id"]), status_code=status_code, text="Not Found"
    )
    with pytest.raises(DemistoException, match=f"Failed to fetch event domain. Status: {status_code}"):
        LiveEngageLivePerson.Client._get_event_domain(PARAMS["account_id"], True, {})


def test_get_event_domain_network_error(requests_mock: Mocker):
    """Test network error (e.g., timeout) when fetching event domain."""
    requests_mock.get(
        LiveEngageLivePerson.DOMAIN_API_URL.format(account_id=PARAMS["account_id"]), exc=RequestException("Connection timed out")
    )
    with pytest.raises(DemistoException, match="Network error: Connection timed out"):
        LiveEngageLivePerson.Client._get_event_domain(PARAMS["account_id"], True, {})


def test_get_event_domain_json_error(requests_mock: Mocker):
    """Test invalid JSON response from event domain API."""
    requests_mock.get(
        LiveEngageLivePerson.DOMAIN_API_URL.format(account_id=PARAMS["account_id"]), text="<not_json>This is HTML</not_json>"
    )
    with pytest.raises(DemistoException, match="Failed to parse event domain API response as JSON"):
        LiveEngageLivePerson.Client._get_event_domain(PARAMS["account_id"], True, {})


def test_get_event_domain_missing_key(requests_mock: Mocker):
    """Test response from event domain API that is missing the 'baseURI' key."""
    requests_mock.get(
        LiveEngageLivePerson.DOMAIN_API_URL.format(account_id=PARAMS["account_id"]), json={"wrong_key": "some_value"}
    )
    with pytest.raises(DemistoException, match='Event domain API response missing "baseURI" field'):
        LiveEngageLivePerson.Client._get_event_domain(PARAMS["account_id"], True, {})


def test_get_access_token_success(requests_mock: Mocker):
    """Test successful fetching of the auth token."""
    auth_url = f"https://{PARAMS['auth_server_url']}"
    token_path = LiveEngageLivePerson.OAUTH_PATH_SUFFIX.format(account_id=PARAMS["account_id"])
    requests_mock.post(urljoin(auth_url, token_path), json=MOCK_AUTH_RESPONSE)

    token = LiveEngageLivePerson.Client._get_access_token(auth_url, PARAMS["account_id"], "id", "secret", True, {})
    assert token == MOCK_AUTH_RESPONSE["access_token"]


@pytest.mark.parametrize("status_code", [401, 403, 500])
def test_get_access_token_http_error(requests_mock: Mocker, status_code: int):
    """Test HTTP error when fetching auth token."""
    auth_url = f"https://{PARAMS['auth_server_url']}"
    token_path = LiveEngageLivePerson.OAUTH_PATH_SUFFIX.format(account_id=PARAMS["account_id"])
    requests_mock.post(urljoin(auth_url, token_path), status_code=status_code, text="Unauthorized")

    with pytest.raises(DemistoException, match=f"Failed to get access token. Status: {status_code}"):
        LiveEngageLivePerson.Client._get_access_token(auth_url, PARAMS["account_id"], "id", "secret", True, {})


def test_get_access_token_missing_key(requests_mock: Mocker):
    """Test response from auth API that is missing the 'access_token' key."""
    auth_url = f"https://{PARAMS['auth_server_url']}"
    token_path = LiveEngageLivePerson.OAUTH_PATH_SUFFIX.format(account_id=PARAMS["account_id"])
    requests_mock.post(urljoin(auth_url, token_path), json={"wrong_key": "some_value"})

    with pytest.raises(DemistoException, match='Auth response missing "access_token" field'):
        LiveEngageLivePerson.Client._get_access_token(auth_url, PARAMS["account_id"], "id", "secret", True, {})


# ===================================
# --- Test Client Instance Methods ---
# ===================================


def test_http_request_token_refresh(client: LiveEngageLivePerson.Client, mocker, requests_mock: Mocker):
    """
    Test the core resilience:
    1. First call fails with 401.
    2. Client automatically calls _generate_token().
    3. Client retries the original call, which now succeeds.
    """
    # We patch the *instance* method _generate_token to mock success
    mocker.patch.object(client, "_generate_token")

    # Mock the BaseClient._http_request
    # We need to use a list of responses
    base_http_request = mocker.patch.object(
        LiveEngageLivePerson.BaseClient,
        "_http_request",
        side_effect=[
            # 1. First call raises 401
            DemistoException("401 Unauthorized"),
            # 2. Second call (retry) succeeds
            {"data": "success"},
        ],
    )

    # We remove the auth header to simulate the first call
    client._headers.pop("Authorization", None)

    # Make the call
    response = client._http_request(method="POST", url_suffix="/test")

    # Assertions
    assert response == {"data": "success"}
    assert client._generate_token.called_once()  # Token refresh was called
    assert base_http_request.call_count == 2  # Original call + retry


def test_http_request_non_401_error(client: LiveEngageLivePerson.Client, mocker):
    """Test that a 500 error does NOT trigger a token refresh and just fails."""
    mocker.patch.object(client, "_generate_token")
    base_http_request = mocker.patch.object(
        LiveEngageLivePerson.BaseClient, "_http_request", side_effect=DemistoException("500 Server Error")
    )

    client._headers["Authorization"] = "Bearer old_token"  # Simulate existing token

    with pytest.raises(DemistoException, match="500 Server Error"):
        client._http_request(method="POST", url_suffix="/test")

    assert client._generate_token.called is False  # Token refresh was NOT called
    assert base_http_request.call_count == 1  # Only the original call


def test_fetch_events_no_events(client: LiveEngageLivePerson.Client, mocker):
    """Fringe Case: Test fetching when the API returns an empty list."""
    start_time = datetime.now(UTC) - timedelta(days=1)
    mocker.patch.object(client, "_http_request", return_value=MOCK_EVENTS_EMPTY)

    events, new_time = client.fetch_events(max_fetch=1000, last_run_time=start_time)

    assert events == []
    assert new_time == start_time  # Time should not advance


def test_fetch_events_one_page_partial(client: LiveEngageLivePerson.Client, mocker):
    """Fringe Case: Test fetching when API returns one page with < API_PAGE_SIZE events."""
    start_time = datetime.now(UTC) - timedelta(days=1)
    mocker.patch.object(client, "_http_request", return_value=MOCK_EVENTS_PAGE_1)

    events, new_time = client.fetch_events(max_fetch=1000, last_run_time=start_time)

    assert events == [MOCK_EVENT_1, MOCK_EVENT_2]
    # new_time should be the timestamp of the *last* event
    expected_time = datetime.fromisoformat(MOCK_TIME_2.replace("Z", "+00:00"))
    assert new_time == expected_time


def test_fetch_events_multiple_pages(client: LiveEngageLivePerson.Client, mocker):
    """Fringe Case: Test multi-page pagination (Page 1 full, Page 2 partial)."""
    start_time = datetime.now(UTC) - timedelta(days=1)

    # We need to mock _http_request to return different values on subsequent calls
    http_mock = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[
            MOCK_EVENTS_PAGE_1,  # First call (offset 0)
            MOCK_EVENTS_PAGE_2,  # Second call (offset 2)
            MOCK_EVENTS_EMPTY,  # Third call (offset 3)
        ],
    )

    # We use a smaller API_PAGE_SIZE for this test to match mock data
    LiveEngageLivePerson.API_PAGE_SIZE = 2

    events, new_time = client.fetch_events(max_fetch=1000, last_run_time=start_time)

    # Restore global
    LiveEngageLivePerson.API_PAGE_SIZE = 500

    # Assertions
    assert events == [MOCK_EVENT_1, MOCK_EVENT_2, MOCK_EVENT_3]
    assert http_mock.call_count == 3  # Called 3 times before stopping

    # Final time should be from the last event
    expected_time = datetime.fromisoformat(MOCK_TIME_3.replace("Z", "+00:00"))
    assert new_time == expected_time


def test_fetch_events_max_fetch_limit(client: LiveEngageLivePerson.Client, mocker):
    """Fringe Case: Test that fetching stops when max_fetch is hit, even if more pages exist."""
    start_time = datetime.now(UTC) - timedelta(days=1)

    http_mock = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[
            MOCK_EVENTS_PAGE_1,  # Returns 2 events
            MOCK_EVENTS_PAGE_2,  # Returns 1 event
        ],
    )

    # We use a smaller API_PAGE_SIZE for this test
    LiveEngageLivePerson.API_PAGE_SIZE = 2

    # Ask for max_fetch of 2
    events, new_time = client.fetch_events(max_fetch=2, last_run_time=start_time)

    # Restore global
    LiveEngageLivePerson.API_PAGE_SIZE = 500

    assert events == [MOCK_EVENT_1, MOCK_EVENT_2]  # Should only have 2 events
    assert http_mock.call_count == 1  # Should only have called the API once

    # Time should be from the last event *fetched*
    expected_time = datetime.fromisoformat(MOCK_TIME_2.replace("Z", "+00:00"))
    assert new_time == expected_time


def test_fetch_events_api_error_mid_fetch(client: LiveEngageLivePerson.Client, mocker):
    """Fringe Case: Test API error on the *second* page of a multi-page fetch."""
    start_time = datetime.now(UTC) - timedelta(days=1)

    http_mock = mocker.patch.object(
        client,
        "_http_request",
        side_effect=[
            MOCK_EVENTS_PAGE_1,  # First call (offset 0) succeeds
            DemistoException("500 Server Error"),  # Second call fails
        ],
    )

    LiveEngageLivePerson.API_PAGE_SIZE = 2
    events, new_time = client.fetch_events(max_fetch=1000, last_run_time=start_time)
    LiveEngageLivePerson.API_PAGE_SIZE = 500

    # Should gracefully stop and return what it has
    assert events == [MOCK_EVENT_1, MOCK_EVENT_2]
    assert http_mock.call_count == 2

    # Time should be from the last successful event
    expected_time = datetime.fromisoformat(MOCK_TIME_2.replace("Z", "+00:00"))
    assert new_time == expected_time


def test_fetch_events_malformed_timestamp(client: LiveEngageLivePerson.Client, mocker):
    """Fringe Case: Test event with bad timestamp. Should log warning and continue."""
    start_time = datetime.now(UTC) - timedelta(days=1)

    bad_event = {"changeDate": "not-a-real-date", "element": "badevent"}
    good_event = {"changeDate": MOCK_TIME_1, "element": "goodevent"}

    mocker.patch.object(client, "_http_request", return_value={"data": [bad_event, good_event]})

    events, new_time = client.fetch_events(max_fetch=1000, last_run_time=start_time)

    assert events == [bad_event, good_event]
    # Warning was logged
    demisto.info.assert_any_call(
        "[LivePerson] [Warning] Could not parse timestamp: not-a-real-date. " "This event may not update the last_run_time."
    )
    # Time was updated from the *good* event
    expected_time = datetime.fromisoformat(MOCK_TIME_1.replace("Z", "+00:00"))
    assert new_time == expected_time


# ==============================
# --- Test Command Functions ---
# ==============================


def test_fetch_events_command_first_run(client: LiveEngageLivePerson.Client, mocker):
    """Test fetch_events_command on a first run (no last_run)."""
    # Setup
    mocker.patch.object(demisto, "getLastRun", return_value={})
    first_fetch_time = datetime.now(UTC) - timedelta(days=1)

    new_max_time = datetime.fromisoformat(MOCK_TIME_2.replace("Z", "+00:00"))
    mocker.patch.object(client, "fetch_events", return_value=([MOCK_EVENT_1, MOCK_EVENT_2], new_max_time))

    # Execute
    events = LiveEngageLivePerson.fetch_events_command(client, 1000, first_fetch_time)

    # Assert
    assert events == [MOCK_EVENT_1, MOCK_EVENT_2]
    client.fetch_events.assert_called_with(max_fetch=1000, last_run_time=first_fetch_time)

    # Check that last_run was set correctly (+1 second)
    expected_last_run_time = (new_max_time + timedelta(seconds=1)).isoformat()
    demisto.setLastRun.assert_called_with({"last_fetch_time": expected_last_run_time})


def test_fetch_events_command_subsequent_run(client: LiveEngageLivePerson.Client, mocker):
    """Test fetch_events_command on a subsequent run."""
    # Setup
    last_run_str = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    last_run_time = datetime.fromisoformat(last_run_str)
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch_time": last_run_str})

    new_max_time = datetime.fromisoformat(MOCK_TIME_2.replace("Z", "+00:00"))
    mocker.patch.object(client, "fetch_events", return_value=([MOCK_EVENT_1, MOCK_EVENT_2], new_max_time))

    # Execute
    LiveEngageLivePerson.fetch_events_command(client, 1000, datetime.now(UTC) - timedelta(days=30))

    # Assert
    # Called with the *actual* last_run_time, not first_fetch_time
    client.fetch_events.assert_called_with(max_fetch=1000, last_run_time=last_run_time)
    expected_last_run_time = (new_max_time + timedelta(seconds=1)).isoformat()
    demisto.setLastRun.assert_called_with({"last_fetch_time": expected_last_run_time})


def test_fetch_events_command_no_new_events(client: LiveEngageLivePerson.Client, mocker):
    """Test fetch_events_command when no new events are found."""
    last_run_str = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    last_run_time = datetime.fromisoformat(last_run_str)
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch_time": last_run_str})

    mocker.patch.object(
        client,
        "fetch_events",
        return_value=([], last_run_time),  # Returns empty list and original time
    )

    LiveEngageLivePerson.fetch_events_command(client, 1000, datetime.now(UTC) - timedelta(days=30))

    # Assert
    demisto.setLastRun.assert_not_called()  # Last run should NOT be updated


def test_fetch_events_command_infinite_loop_prevention(client: LiveEngageLivePerson.Client, mocker):
    """
    CRITICAL: Test the "infinite loop" fringe case.
    Events are fetched, but the max timestamp is the *same* as the last_run_time.
    We MUST advance the last_run_time by 1s to prevent fetching the same events again.
    """
    # Setup
    last_run_str = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    last_run_time = datetime.fromisoformat(last_run_str)
    mocker.patch.object(demisto, "getLastRun", return_value={"last_fetch_time": last_run_str})

    # fetch_events returns events, but the *same* time
    mocker.patch.object(client, "fetch_events", return_value=([MOCK_EVENT_1], last_run_time))

    # Execute
    LiveEngageLivePerson.fetch_events_command(client, 1000, datetime.now(UTC) - timedelta(days=30))

    # Assert
    # We must have called setLastRun with +1 second to prevent an infinite loop
    expected_last_run_time = (last_run_time + timedelta(seconds=1)).isoformat()
    demisto.setLastRun.assert_called_with({"last_fetch_time": expected_last_run_time})
    demisto.info.assert_any_call(f"[LivePerson] Setting new last run time to {expected_last_run_time} to avoid duplicates.")


# =========================
# --- Test Main Function ---
# =========================


def test_main_missing_params(mocker):
    """Test main function failing on missing required parameters."""
    mocker.patch.object(demisto, "params", return_value={"account_id": "123"})  # Missing auth_url, etc.

    LiveEngageLivePerson.main()

    demisto.return_error.assert_called_once_with(
        "Failed to execute test-module command. "
        "Error: Missing required parameters: Authorization Server URL, Account ID, Client ID, or Client Secret.",
        error=mocker.ANY,
    )


def test_main_invalid_first_fetch(mocker):
    """Test main function failing on invalid 'first_fetch' string."""
    invalid_params = PARAMS.copy()
    invalid_params["first_fetch"] = "not a real date"
    mocker.patch.object(demisto, "params", return_value=invalid_params)

    LiveEngageLivePerson.main()

    demisto.return_error.assert_called_once_with(
        "Failed to execute test-module command. "
        "Error: Invalid 'first_fetch' format: not a real date. "
        "Use phrases like '3 days ago' or '2023-10-25T10:00:00Z'.",
        error=mocker.ANY,
    )


def test_main_domain_lookup_fails(mocker):
    """
    CRITICAL: Test resilience when the *first* network call (domain lookup) fails.
    This must fail gracefully before a Client is ever initialized.
    """
    mocker.patch.object(
        LiveEngageLivePerson.Client,
        "_get_event_domain",
        side_effect=DemistoException("Failed to fetch event domain. Status: 404"),
    )

    LiveEngageLivePerson.main()

    # Assert that main caught this *before* running any command
    demisto.return_error.assert_called_once_with(
        "Failed to execute test-module command. Error: Failed to fetch event domain. Status: 404", error=mocker.ANY
    )


def test_main_fetch_events_success(mocker):
    """Test the full E2E flow for 'fetch-events' command."""
    mocker.patch.object(demisto, "command", return_value="fetch-events")

    # Mock all external calls
    mocker.patch.object(LiveEngageLivePerson.Client, "_get_event_domain", return_value="https://va.ac.liveperson.net")
    mocker.patch.object(LiveEngageLivePerson.Client, "_get_access_token", return_value="mock_token_123")

    new_max_time = datetime.fromisoformat(MOCK_TIME_2.replace("Z", "+00:00"))
    mocker.patch.object(LiveEngageLivePerson.Client, "fetch_events", return_value=([MOCK_EVENT_1, MOCK_EVENT_2], new_max_time))

    # Run main
    LiveEngageLivePerson.main()

    # Assert success
    demisto.return_error.assert_not_called()
    # Assert events were sent
    LiveEngageLivePerson.send_events_to_xsiam.assert_called_once_with(
        [MOCK_EVENT_1, MOCK_EVENT_2], vendor="LivePerson", product="liveperson"
    )
    # Assert last run was set
    expected_last_run_time = (new_max_time + timedelta(seconds=1)).isoformat()
    demisto.setLastRun.assert_called_with({"last_fetch_time": expected_last_run_time})
