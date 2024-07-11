import json
import pytest
from freezegun import freeze_time
from BitwardenPasswordManager import Client
from Packs.BitwardenPasswordManager.Integrations.BitwardenPasswordManager import BitwardenPasswordManager

MOCK_BASEURL = "https://mock.api.com"
MOCK_CLIENT_ID = "mock_client_id"
MOCK_CLIENT_SECRET = "mock_secret"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
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

    mocker.patch("BitwardenPasswordManager.get_integration_context", return_value={
        "token": "access_token",
        "expires": "1715032135"
    })

    return Client(
        base_url=MOCK_BASEURL,
        verify=False,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        proxy=False
    )


def test_login_when_token_creation(mocker):
    """
    Given: An empty integration context
    When: Login is called and token not exist or invalid.
    Then: Create a new token and save it to the integration context
    """

    mock_response = util_load_json("test_data/mock_response_login_token_creation.json")
    mocker.patch.object(Client, '_http_request', return_value=mock_response)
    mocker.patch("BitwardenPasswordManager.get_integration_context", return_value={})

    client = Client(
        base_url=MOCK_BASEURL,
        verify=False,
        client_id=MOCK_CLIENT_ID,
        client_secret=MOCK_CLIENT_SECRET,
        proxy=False
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
def test_get_events_with_limit(mock_client_with_valid_token, mocker):
    """
    Given: A mock BitwardenPasswordManager client.
    When: Running get-events with a limit of 2, while there are more than 2 events.
    Then: Ensure only two events is returned per type.
    """
    from BitwardenPasswordManager import get_events_command

    limit = 2
    raw_response = util_load_json("test_data/raw_response.json")
    mocker.patch.object(Client, '_http_request', return_value=raw_response)
    events, _ = get_events_command(client=mock_client_with_valid_token, args={'limit': limit})
    assert len(events) == limit


def test_filter_oldest_events():
    """
    Given: A mock events.
    When: Running filter_events when using oldest=True.
    Then: Ensure that return the oldest events from the events list.
    """
    from BitwardenPasswordManager import filter_events
    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get('data')
    filtered_events = filter_events(events, oldest=True)

    assert len(filtered_events) == 2
    for event in filtered_events:
        assert event.get('date') == '2020-10-31T15:01:21.698Z'

    assert filtered_events[0].get('type') == 1000
    assert filtered_events[1].get('type') == 1007


def test_filter_recent_events():
    """
    Given: A mock events.
    When: Running filter_events when using oldest=False.
    Then: Ensure that return the recent events from the events list.
    """
    from BitwardenPasswordManager import filter_events
    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get('data')
    filtered_events = filter_events(events, oldest=False)

    assert len(filtered_events) == 2
    for event in filtered_events:
        assert event.get('date') == '2020-11-04T15:01:21.698Z'

    assert filtered_events[0].get('type') == 1000
    assert filtered_events[1].get('type') == 1002


def test_hash_events():
    """
    Given: A mock events.
    When: Running hash_events.
    Then: Ensure that the return dictionary is structured such that each item's value is the event, and the key is the hash
    value of the event.
    """
    from BitwardenPasswordManager import hash_events
    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get('data')
    hashed_events = hash_events(events)
    hashed_first_event = list(hashed_events.keys())[0]
    assert len(hashed_events) == len(events)
    assert list(hashed_events.values()) == events
    assert hashed_first_event == 'b6142853d9719c4c6301a5012e42437cb9c6726fcfa5b930bd3be6b7048a0d53'
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
    events = raw_response.get('data')
    mock_last_run = {
        'hashed_recent_events': {
            'e6bff23ab05c63226e4ad2b15a5713589ab59f01a37cec6f731bad7886a77634': {
                'object': 'event', 'type': 1007,
                'itemId': 'event_with_the_same_date_as_other_event',
                'collectionId': 'string', 'groupId': 'string',
                'policyId': 'string', 'memberId': 'string',
                'actingUserId': 'string',
                'date': '2020-10-31T15:01:21.698Z', 'device': 0,
                'ipAddress': 'xxx.xx.xxx.x'}}
    }
    unique_events = get_unique_events(events, mock_last_run)
    assert list(mock_last_run.get('hashed_recent_events').values())[0] not in unique_events
    assert len(unique_events) == len(events) - 1


def test_get_unique_events_without_duplicates():
    """
    Given: A mock events.
    When: Run the function get_unique_events with the condition that the events are new and not
    Then: Ensure that the return list contain only unique items, and it equals to the events list.
    """
    from BitwardenPasswordManager import get_unique_events

    raw_response = util_load_json("test_data/raw_response.json")
    events = raw_response.get('data')
    mock_last_run = {
        'hashed_recent_events': {
            'dddff23ab05c63226e4ad2b15a5713589ab59f01a37cec6f731bad7886a77634': {
                'object': 'event', 'type': 1007,
                'itemId': 'event_with_the_same_date_as_other_event',
                'collectionId': 'string', 'groupId': 'string',
                'policyId': 'string', 'memberId': 'string',
                'actingUserId': 'string',
                'date': '2020-10-30T15:01:21.698Z', 'device': 0,
                'ipAddress': 'xxx.xx.xxx.x'}}
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
    mocker.patch.object(Client, '_http_request', side_effect=[raw_response_with_continuationToken, raw_response])
    events, continuation_token = get_events_with_pagination(mock_client_with_valid_token,
                                                            BitwardenPasswordManager.DEFAULT_MAX_FETCH, {}, {})

    assert len(events) == len(raw_response.get('data')) + len(raw_response_with_continuationToken.get('data'))


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
    mocker.patch.object(Client, '_http_request', return_value=raw_response)
    unique_events, new_last_run = fetch_events(mock_client_with_valid_token, BitwardenPasswordManager.DEFAULT_MAX_FETCH, {})
    assert len(unique_events) == len(raw_response.get('data'))
    assert new_last_run.get('last_fetch')[:-3] == raw_response.get('data')[0].get('date')[:-1]
    assert list(new_last_run.get('hashed_recent_events').values())[0] == raw_response.get('data')[0]


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
    mocker.patch.object(Client, '_http_request', return_value=raw_response_with_continuationToken)
    unique_events, new_last_run = fetch_events(mock_client_with_valid_token, max_fetch=1, dates={})
    assert new_last_run.get('continuationToken') == 'continuation_token'
    assert new_last_run.get('nextTrigger') == '0'
