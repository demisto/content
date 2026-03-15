import json

import pytest
from BitwardenPasswordManager import Client
from freezegun import freeze_time

from Packs.BitwardenPasswordManager.Integrations.BitwardenPasswordManager import BitwardenPasswordManager

MOCK_BASEURL = "https://mock.api.com"
MOCK_CLIENT_ID = "mock_client_id"
MOCK_CLIENT_SECRET = "mock_secret"


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture(autouse=True)
@freeze_time("2024-04-25 00:00:00")
def mock_client_with_valid_token(mocker) -> Client:
    """
    Establish a connection to the client with a user credentials.
    This client contains a valid token.

    Returns:
        Client: Connection to client.
    """

    mocker.patch(
        "BitwardenPasswordManager.get_integration_context", return_value={"token": "access_token", "expires": "1715032135"}
    )

    return Client(
        base_url=MOCK_BASEURL,
        verify=False,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        proxy=False,
        self_hosted=False,
    )


def test_login_when_token_creation(mocker):
    """
    Given: An empty integration context
    When: Login is called and token not exist or invalid.
    Then: Create a new token and save it to the integration context
    """

    mock_response = util_load_json("test_data/mock_response_login_token_creation.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("BitwardenPasswordManager.get_integration_context", return_value={})

    client = Client(
        base_url=MOCK_BASEURL,
        verify=False,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        proxy=False,
        self_hosted=False,
    )

    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_login_with_valid_token(mock_client_with_valid_token):
    """
    Given: A token in the integration context with a valid expiration time
    When: Login is called with a valid token
    Then: Fetch the token from the integration context and log in
    """

    assert mock_client_with_valid_token.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
@pytest.mark.parametrize(
    "base_url, full_url",
    [
        (MOCK_BASEURL, "https://identity.bitwarden.com/connect/token"),
        ("https://mock.api.eu", "https://identity.bitwarden.eu/connect/token"),
    ],
)
def test_create_new_token(mocker, base_url: str, full_url: str):
    """
    Given: A client and authentication data
    When: create_new_token is called with valid credentials
    Then: A new token is created, stored in context, and returned
    """
    from BitwardenPasswordManager import Client

    # Mock the HTTP response for token creation
    mock_response = util_load_json("test_data/mock_response_login_token_creation.json")
    mock_http_request = mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mock_set_context = mocker.patch("BitwardenPasswordManager.set_integration_context")
    mock_get_current_time = mocker.patch("BitwardenPasswordManager.get_current_time")

    # Set a fixed time for consistent testing
    from datetime import datetime

    fixed_time = datetime(2024, 4, 25, 0, 0, 0)
    mock_get_current_time.return_value = fixed_time

    # Create client instance without calling login (to test create_new_token directly)
    client = Client.__new__(Client)
    client._base_url = base_url
    client._verify = False
    client._proxy = False
    client.self_hosted = False

    # Test data for token creation
    json_data = {
        "client_id": MOCK_CLIENT_ID,
        "client_secret": MOCK_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "api.organization",
    }

    # Call the method under test
    result_token = client.create_new_token(json_data)

    # Verify the HTTP request was made with correct parameters
    mock_http_request.assert_called_once_with(
        method="POST",
        full_url=full_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=json_data,
    )

    # Verify the token was returned correctly
    assert result_token == "access_token"

    # Verify the context was set with the token and expiration
    mock_set_context.assert_called_once()
    context_call_args = mock_set_context.call_args[1]["context"]
    assert context_call_args["token"] == "access_token"
    assert "expires" in context_call_args


@freeze_time("2024-04-25 00:00:00")
@pytest.mark.parametrize(
    "base_url, expected_url",
    [
        ("https://vault.customer.com", "https://vault.customer.com/identity/connect/token"),
        ("https://vault.customer.com/", "https://vault.customer.com/identity/connect/token"),
        ("https://bitwarden.example.org", "https://bitwarden.example.org/identity/connect/token"),
    ],
)
def test_create_new_token_self_hosted(mocker, base_url: str, expected_url: str):
    """
    Given: A client configured for a self-hosted Bitwarden instance
    When: create_new_token is called with self_hosted=True
    Then: The authentication URL is constructed from the base_url
    """
    from BitwardenPasswordManager import Client

    # Mock the HTTP response for token creation
    mock_response = util_load_json("test_data/mock_response_login_token_creation.json")
    mock_http_request = mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mock_set_context = mocker.patch("BitwardenPasswordManager.set_integration_context")
    mock_get_current_time = mocker.patch("BitwardenPasswordManager.get_current_time")

    # Set a fixed time for consistent testing
    from datetime import datetime

    fixed_time = datetime(2024, 4, 25, 0, 0, 0)
    mock_get_current_time.return_value = fixed_time

    # Create client instance with self_hosted=True
    client = Client.__new__(Client)
    client._base_url = base_url
    client._verify = False
    client._proxy = False
    client.self_hosted = True

    # Test data for token creation
    json_data = {
        "client_id": MOCK_CLIENT_ID,
        "client_secret": MOCK_CLIENT_SECRET,
        "grant_type": "client_credentials",
        "scope": "api.organization",
    }

    # Call the method under test
    result_token = client.create_new_token(json_data)

    # Verify the HTTP request was made with the self-hosted URL
    mock_http_request.assert_called_once_with(
        method="POST",
        full_url=expected_url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=json_data,
    )

    # Verify the token was returned correctly
    assert result_token == "access_token"

    # Verify the context was set with the token and expiration
    mock_set_context.assert_called_once()
    context_call_args = mock_set_context.call_args[1]["context"]
    assert context_call_args["token"] == "access_token"
    assert "expires" in context_call_args


@freeze_time("2024-04-25 00:00:00")
def test_client_initialization_with_self_hosted(mocker):
    """
    Given: Configuration parameters for a self-hosted Bitwarden instance
    When: Client is initialized with self_hosted=True
    Then: The client is created with the self_hosted flag set correctly
    """
    from BitwardenPasswordManager import Client

    # Mock the HTTP response for token creation
    mock_response = util_load_json("test_data/mock_response_login_token_creation.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("BitwardenPasswordManager.get_integration_context", return_value={})
    mocker.patch("BitwardenPasswordManager.set_integration_context")

    # Create client with self_hosted=True
    client = Client(
        base_url="https://vault.customer.com",
        verify=False,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        proxy=False,
        self_hosted=True,
    )

    # Verify the self_hosted flag is set
    assert client.self_hosted is True
    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_client_initialization_without_self_hosted(mocker):
    """
    Given: Configuration parameters for a cloud-hosted Bitwarden instance
    When: Client is initialized without self_hosted parameter (defaults to False)
    Then: The client is created with the self_hosted flag set to False (backward compatibility)
    """
    from BitwardenPasswordManager import Client

    # Mock the HTTP response for token creation
    mock_response = util_load_json("test_data/mock_response_login_token_creation.json")
    mocker.patch.object(Client, "_http_request", return_value=mock_response)
    mocker.patch("BitwardenPasswordManager.get_integration_context", return_value={})
    mocker.patch("BitwardenPasswordManager.set_integration_context")

    # Create client without self_hosted parameter (should default to False)
    client = Client(base_url=MOCK_BASEURL, verify=False, client_id=MOCK_CLIENT_ID, client_secret=MOCK_CLIENT_SECRET, proxy=False)

    # Verify the self_hosted flag defaults to False
    assert client.self_hosted is False
    assert client.token == "access_token"


@freeze_time("2024-04-25 00:00:00")
def test_get_events_with_limit(mock_client_with_valid_token, mocker):
    """
    Given: A mock BitwardenPasswordManager client.
    When: Running get-events with a limit of 2, while there are more than 2 events.
    Then: Ensure only two events is returned per type.
    """
    from BitwardenPasswordManager import get_events_command

    limit = 2
    raw_response = util_load_json("test_data/raw_response.json")
    mocker.patch.object(Client, "_http_request", return_value=raw_response)
    events, _ = get_events_command(client=mock_client_with_valid_token, args={"limit": limit})
    assert len(events) == limit


def test_filter_oldest_events():
    """
    Given: A mock events.
    When: Running filter_events when using oldest=True.
    Then: Ensure that return the oldest events from the events list.
    """
    from BitwardenPasswordManager import filter_events

    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get("data")
    filtered_events = filter_events(events, oldest=True)

    assert len(filtered_events) == 2
    for event in filtered_events:
        assert event.get("date") == "2020-10-31T15:01:21.698Z"

    assert filtered_events[0].get("type") == 1000
    assert filtered_events[1].get("type") == 1007


def test_filter_recent_events():
    """
    Given: A mock events.
    When: Running filter_events when using oldest=False.
    Then: Ensure that return the recent events from the events list.
    """
    from BitwardenPasswordManager import filter_events

    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get("data")
    filtered_events = filter_events(events, oldest=False)

    assert len(filtered_events) == 2
    for event in filtered_events:
        assert event.get("date") == "2020-11-04T15:01:21.698Z"

    assert filtered_events[0].get("type") == 1000
    assert filtered_events[1].get("type") == 1002


def test_hash_events():
    """
    Given: A mock events.
    When: Running hash_events.
    Then: Ensure that the return dictionary is structured such that each item's value is the event, and the key is the hash
    value of the event.
    """
    from BitwardenPasswordManager import hash_events

    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get("data")
    hashed_events = hash_events(events)
    hashed_first_event = list(hashed_events.keys())[0]
    assert len(hashed_events) == len(events)
    assert list(hashed_events.values()) == events
    assert hashed_first_event == "b6142853d9719c4c6301a5012e42437cb9c6726fcfa5b930bd3be6b7048a0d53"
    assert len(hashed_first_event) == 64


def test_get_unique_events_with_duplicates():
    """
    Given: A mock events.
    When: Run the function get_unique_events with the condition that the events should include items that appeared
    in the previous last_run.
    Then: Ensure that the return list contain only unique items.
    """
    from BitwardenPasswordManager import get_unique_events

    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get("data")
    mock_last_run = {
        "hashed_recent_events": {
            "e6bff23ab05c63226e4ad2b15a5713589ab59f01a37cec6f731bad7886a77634": {
                "object": "event",
                "type": 1007,
                "itemId": "event_with_the_same_date_as_other_event",
                "collectionId": "string",
                "groupId": "string",
                "policyId": "string",
                "memberId": "string",
                "actingUserId": "string",
                "date": "2020-10-31T15:01:21.698Z",
                "device": 0,
                "ipAddress": "xxx.xx.xxx.x",
            }
        }
    }
    unique_events = get_unique_events(events, mock_last_run)
    assert list(mock_last_run.get("hashed_recent_events").values())[0] not in unique_events
    assert len(unique_events) == len(events) - 1


def test_get_unique_events_without_duplicates():
    """
    Given: A mock events.
    When: Run the function get_unique_events with the condition that the events are new and not
    Then: Ensure that the return list contain only unique items, and it equals to the events list.
    """
    from BitwardenPasswordManager import get_unique_events

    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get("data")
    mock_last_run = {
        "hashed_recent_events": {
            "dddff23ab05c63226e4ad2b15a5713589ab59f01a37cec6f731bad7886a77634": {
                "object": "event",
                "type": 1007,
                "itemId": "event_with_the_same_date_as_other_event",
                "collectionId": "string",
                "groupId": "string",
                "policyId": "string",
                "memberId": "string",
                "actingUserId": "string",
                "date": "2020-10-30T15:01:21.698Z",
                "device": 0,
                "ipAddress": "xxx.xx.xxx.x",
            }
        }
    }
    unique_events = get_unique_events(events, mock_last_run)
    assert unique_events == events


@freeze_time("2024-04-25 00:00:00")
def test_get_events_with_pagination(mock_client_with_valid_token, mocker):
    """
    Given: A mock events.
    When: Execute the 'get_events_with_pagination' function when the events are divided into two lists: the first list contains
    events with a continuation token, and the second list does not include a continuation token.
    Then: Ensure that the return list contain all the events from both lists.
    """
    from BitwardenPasswordManager import get_events_with_pagination

    raw_response_with_continuationToken = util_load_json("test_data/raw_response_with_continuationToken.json")
    raw_response = util_load_json("test_data/raw_response.json")
    mocker.patch.object(Client, "_http_request", side_effect=[raw_response_with_continuationToken, raw_response])
    events, continuation_token = get_events_with_pagination(
        mock_client_with_valid_token, BitwardenPasswordManager.DEFAULT_MAX_FETCH, {}, {}
    )

    assert len(events) == len(raw_response.get("data")) + len(raw_response_with_continuationToken.get("data"))


@freeze_time("2024-04-25 00:00:00")
def test_fetch_events_without_continuation_token(mock_client_with_valid_token, mocker):
    """
    Given: A mock events.
    When: Execute the 'fetch_events' such that the fetch successes in one shot and no need for continuation token.
    Then: Ensure that the return list contain all the events and that the new_last_run object contain the date of the latest
    fetched event.
    """
    from BitwardenPasswordManager import fetch_events

    raw_response = util_load_json("test_data/raw_response.json")
    mocker.patch.object(Client, "_http_request", return_value=raw_response)
    unique_events, new_last_run = fetch_events(mock_client_with_valid_token, BitwardenPasswordManager.DEFAULT_MAX_FETCH, {})
    assert len(unique_events) == len(raw_response.get("data"))
    assert new_last_run.get("last_fetch")[:-3] == raw_response.get("data")[0].get("date")[:-1]
    assert list(new_last_run.get("hashed_recent_events").values())[0] == raw_response.get("data")[0]


@freeze_time("2024-04-25 00:00:00")
def test_fetch_events_with_continuation_token(mock_client_with_valid_token, mocker):
    """
    Given: A mock events.
    When: Execute the 'fetch_events' function with the condition that the number of events exceeds the 'max_fetch' limit,
     triggering the need for a new fetch operation and returning a continuation token.
    Then: Ensure that returned a continuation token and the nextTrigger is set to 0.
    fetched event.
    """
    from BitwardenPasswordManager import fetch_events

    raw_response_with_continuationToken = util_load_json("test_data/raw_response_with_continuationToken.json")
    mocker.patch.object(Client, "_http_request", return_value=raw_response_with_continuationToken)
    unique_events, new_last_run = fetch_events(mock_client_with_valid_token, max_fetch=1, dates={})
    assert new_last_run.get("continuationToken") == "continuation_token"
    assert new_last_run.get("nextTrigger") == "0"
