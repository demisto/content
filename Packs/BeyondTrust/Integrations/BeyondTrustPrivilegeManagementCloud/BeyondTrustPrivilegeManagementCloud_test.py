import json
import pytest
from BeyondTrustPrivilegeManagementCloud import Client, get_events_command, get_audit_activity_command, fetch_events, \
    get_dedup_key

''' CONSTANTS '''

BASE_URL = 'https://example.com'
CLIENT_ID = 'client_id'
CLIENT_SECRET = 'client_secret'


@pytest.fixture
def client():
    return Client(
        base_url=BASE_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        verify=False,
        proxy=False
    )


def load_json(path):
    with open(path) as f:
        return json.load(f)


''' TEST FUNCTIONS '''


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
        'events': [
            {'id': '1', 'created': '2022-01-01T00:00:00.000Z'},
            {'id': '2', 'created': '2022-01-01T00:00:01.000Z'}
        ]
    }
    mocker.patch.object(client, 'get_events', return_value=mock_response)

    args = {'start_date': '2022-01-01T00:00:00.000Z', 'limit': '2'}
    result = get_events_command(client, args)

    outputs = result.outputs
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    assert outputs[0]['id'] == '1'
    assert outputs[1]['id'] == '2'


def test_get_audit_activity_command(client, mocker):
    """
    Given:
        - A client object
        - Arguments with page_size and page_number
    When:
        - get_audit_activity_command is called
    Then:
        - The command should return the expected results
    """
    mock_response = {
        'data': [
            {'id': '1', 'created': '2022-01-01T00:00:00.000Z'},
            {'id': '2', 'created': '2022-01-01T00:00:01.000Z'}
        ]
    }
    mocker.patch.object(client, 'get_audit_activity', return_value=mock_response)

    args = {'page_size': '2', 'page_number': '1'}
    result = get_audit_activity_command(client, args)

    outputs = result.outputs
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    assert outputs[0]['id'] == '1'
    assert outputs[1]['id'] == '2'


def test_fetch_events(client, mocker):
    """
    Given:
        - A client object
        - Last run context
    When:
        - fetch_events is called
    Then:
        - The function should return the next run context and events
    """
    mock_events_response = {
        'events': [
            {'id': '1', 'created': '2022-01-01T00:00:00.000Z'},
            {'id': '2', 'created': '2022-01-01T00:00:01.000Z'}
        ]
    }
    mock_audit_response = {
        'data': [
            {'id': '3', 'created': '2022-01-01T00:00:02.000Z'},
            {'id': '4', 'created': '2022-01-01T00:00:03.000Z'}
        ],
        'pageCount': 1
    }

    mocker.patch.object(client, 'get_events', return_value=mock_events_response)
    mocker.patch.object(client, 'get_audit_activity', return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = '3 days'
    max_fetch = 10
    events_types_to_fetch = ['Events', 'Activity Audits']

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 4
    assert next_run['last_event_time'] == '2022-01-01T00:00:01.000Z'
    assert next_run['last_audit_time'] == '2022-01-01T00:00:03.000Z'


def test_get_dedup_key():
    """
    Given:
        - An event dictionary
    When:
        - get_dedup_key is called
    Then:
        - The function should return the correct deduplication key
    """
    event_with_id = {'id': '123', 'data': 'test'}
    assert get_dedup_key(event_with_id) == '123'

    event_without_id = {'data': 'test'}
    # The hash will vary, but it should be a string
    assert isinstance(get_dedup_key(event_without_id), str)