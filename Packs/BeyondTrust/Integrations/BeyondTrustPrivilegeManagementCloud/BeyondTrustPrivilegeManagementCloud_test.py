import json
import pytest
from freezegun import freeze_time
from BeyondTrustPrivilegeManagementCloud import Client, get_events_command, get_audit_activity_command, fetch_events, \
    get_dedup_key, test_module

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


def test_get_token(client, mocker):
    """
    Given:
        - A client object
    When:
        - get_token is called
    Then:
        - The function should return an access token
    """
    mock_response = {'access_token': 'test_token_123', 'token_type': 'Bearer', 'expires_in': 3600}
    mocker.patch.object(client, '_http_request', return_value=mock_response)

    token = client.get_token()
    assert token == 'test_token_123'


def test_module_success(client, mocker):
    """
    Given:
        - A client object
    When:
        - test_module is called
    Then:
        - The function should return 'ok' on success
    """
    mocker.patch.object(client, 'get_token', return_value='test_token')
    result = test_module(client)
    assert result == 'ok'


def test_module_failure(client, mocker):
    """
    Given:
        - A client object
    When:
        - test_module is called and authentication fails
    Then:
        - The function should return an error message
    """
    mocker.patch.object(client, 'get_token', side_effect=Exception('Authentication failed'))
    result = test_module(client)
    assert 'Failed to connect' in result


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
        ],
        'totalRecordsReturned': 2
    }
    mocker.patch.object(client, 'get_events', return_value=mock_response)

    args = {'start_date': '2022-01-01T00:00:00.000Z', 'limit': '2'}
    result = get_events_command(client, args)

    outputs = result.outputs
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    assert outputs[0]['id'] == '1'
    assert outputs[1]['id'] == '2'


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
    mock_response = {
        'events': [
            {'id': '1', 'created': '2022-01-01T00:00:00.000Z'}
        ]
    }
    mocker.patch.object(client, 'get_events', return_value=mock_response)

    args = {'limit': '1'}
    result = get_events_command(client, args)

    # Verify get_events was called with a start_date
    assert client.get_events.called
    assert isinstance(result.outputs, list)


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
            {'id': 1, 'created': '2022-01-01T00:00:00.000Z', 'details': 'User created'},
            {'id': 2, 'created': '2022-01-01T00:00:01.000Z', 'details': 'Policy updated'}
        ],
        'pageCount': 1,
        'totalRecordCount': 2
    }
    mocker.patch.object(client, 'get_audit_activity', return_value=mock_response)

    args = {'page_size': '2', 'page_number': '1'}
    result = get_audit_activity_command(client, args)

    outputs = result.outputs
    assert isinstance(outputs, list)
    assert len(outputs) == 2
    assert outputs[0]['id'] == 1
    assert outputs[1]['id'] == 2


def test_get_audit_activity_command_with_filters(client, mocker):
    """
    Given:
        - A client object
        - Arguments with date filters
    When:
        - get_audit_activity_command is called
    Then:
        - The command should pass filters to the API
    """
    mock_response = {
        'data': [
            {'id': 1, 'created': '2022-01-01T00:00:00.000Z'}
        ],
        'pageCount': 1
    }
    mocker.patch.object(client, 'get_audit_activity', return_value=mock_response)

    args = {
        'page_size': '10',
        'page_number': '1',
        'filter_created_dates': '2022-01-01,2022-01-02',
        'filter_created_selection_mode': 'Range'
    }
    result = get_audit_activity_command(client, args)

    # Verify the method was called with correct parameters
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
        'events': [
            {'id': '1', 'created': '2024-01-01T10:00:00.000Z'},
            {'id': '2', 'created': '2024-01-01T11:00:00.000Z'}
        ]
    }
    mock_audit_response = {
        'data': [
            {'id': 3, 'created': '2024-01-01T10:30:00.000Z'},
            {'id': 4, 'created': '2024-01-01T11:30:00.000Z'}
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
    
    # CRITICAL: Verify next_run timestamps are set to fetch_end_time (frozen time), NOT the last event's timestamp
    # This ensures continuous coverage without gaps between fetch cycles
    expected_timestamp = '2024-01-01T12:00:00.000000Z'
    assert next_run['last_event_time'] == expected_timestamp
    assert next_run['last_audit_time'] == expected_timestamp
    
    # Verify XSIAM fields are added
    for event in events:
        assert '_time' in event
        assert 'source_log_type' in event
        assert 'vendor' in event
        assert 'product' in event


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
    mock_events_response = {
        'events': [
            {'id': '1', 'created': '2024-01-01T10:00:00.000Z'}
        ]
    }
    mocker.patch.object(client, 'get_events', return_value=mock_events_response)

    last_run: dict = {}
    first_fetch = '1 day'
    max_fetch = 10
    events_types_to_fetch = ['Events']

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 1
    assert 'last_event_time' in next_run
    assert 'last_audit_time' not in next_run
    assert events[0]['source_log_type'] == 'events'
    # Verify timestamp is set to fetch_end_time
    assert next_run['last_event_time'] == '2024-01-01T12:00:00.000000Z'


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
    mock_audit_response = {
        'data': [
            {'id': 1, 'created': '2024-01-01T10:00:00.000Z'}
        ],
        'pageCount': 1
    }
    mocker.patch.object(client, 'get_audit_activity', return_value=mock_audit_response)

    last_run: dict = {}
    first_fetch = '1 day'
    max_fetch = 10
    events_types_to_fetch = ['Activity Audits']

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 1
    assert 'last_audit_time' in next_run
    assert 'last_event_time' not in next_run
    assert events[0]['source_log_type'] == 'activity_audits'
    # Verify timestamp is set to fetch_end_time
    assert next_run['last_audit_time'] == '2024-01-01T12:00:00.000000Z'


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
        'data': [
            {'id': 1, 'created': '2022-01-01T00:00:00.000Z'},
            {'id': 2, 'created': '2022-01-01T00:00:01.000Z'}
        ],
        'pageCount': 2,
        'pageNumber': 1
    }
    mock_audit_response_page2 = {
        'data': [
            {'id': 3, 'created': '2022-01-01T00:00:02.000Z'}
        ],
        'pageCount': 2,
        'pageNumber': 2
    }

    mocker.patch.object(client, 'get_audit_activity', side_effect=[mock_audit_response_page1, mock_audit_response_page2])

    last_run: dict = {}
    first_fetch = '1 day'
    max_fetch = 10
    events_types_to_fetch = ['Activity Audits']

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)

    assert len(events) == 3
    assert client.get_audit_activity.call_count == 2


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


def test_get_dedup_key_numeric_id():
    """
    Given:
        - An event with numeric ID
    When:
        - get_dedup_key is called
    Then:
        - The function should convert ID to string
    """
    event_with_numeric_id = {'id': 456, 'data': 'test'}
    assert get_dedup_key(event_with_numeric_id) == '456'


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
        'events': [
            {'id': '1', 'created': '2024-01-01T11:50:00.000Z'},  # Event before fetch time
        ]
    }
    mocker.patch.object(client, 'get_events', return_value=mock_events_response)

    last_run: dict = {}
    first_fetch = '1 hour'
    max_fetch = 10
    events_types_to_fetch = ['Events']

    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)
    
    # CRITICAL: Verify fetch stored fetch_end_time (12:00:00), not last event time (11:50:00)
    # This prevents missing events created between 11:50:00 and the next fetch
    assert next_run['last_event_time'] == '2024-01-01T12:00:00.000000Z'
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
        'events': [
            {'id': '2', 'created': '2024-01-01T12:01:00.000Z'},  # Event after first fetch
            {'id': '3', 'created': '2024-01-01T12:03:00.000Z'},  # Another event
        ]
    }
    mocker.patch.object(client, 'get_events', return_value=mock_events_response)
    
    # Simulate last_run from previous fetch
    last_run = {'last_event_time': '2024-01-01T12:00:00.000000Z'}
    first_fetch = '1 hour'
    max_fetch = 10
    events_types_to_fetch = ['Events']
    
    next_run, events = fetch_events(client, last_run, first_fetch, max_fetch, events_types_to_fetch)
    
    # Verify events created between fetches are captured
    assert len(events) == 2
    
    # Verify second fetch stored its fetch_end_time (12:05:00)
    assert next_run['last_event_time'] == '2024-01-01T12:05:00.000000Z'
    
    # Verify the get_events call used the correct start_date (from first fetch's end time)
    call_args = client.get_events.call_args
    assert call_args[0][0] == '2024-01-01T12:00:00.000000Z'