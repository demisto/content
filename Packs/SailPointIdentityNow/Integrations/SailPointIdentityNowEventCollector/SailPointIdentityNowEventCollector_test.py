import pytest
from unittest.mock import Mock, patch
from SailPointIdentityNowEventCollector import fetch_events, add_time_and_status_to_events, Client


@pytest.mark.parametrize('expiration_time, expected', [
    (9999999999, 'valid_token'),
    (0, 'new_token')])
def test_get_token(mocker, expiration_time, expected):
    """
    Given:
        - A SailPointIdentityNow client
        - A context with a token and expiration time
            case 1: expiration time is in the future
            case 2: expiration time is in the past
    When:
        - calling get_token
    Then:
        - Ensure the token is returned correctly
            case 1: the token from the context
            case 2: a new token
    """
    mocker.patch.object(Client, '_http_request').return_value = {"access_token": "dummy token",
                                                                 "expires_in": 1}
    client = Client(base_url="https://example.com", client_id="test_id", client_secret="test_secret", verify=False, proxy=False)
                                                               
    mocker.patch('SailPointIdentityNowEventCollector.get_integration_context', return_value={'token': 'valid_token', 'expires': expiration_time})
    mocker.patch.object(Client, 'generate_token', return_value='new_token')
    token = client.get_token()
    assert token == expected


def test_fetch_events(mocker):
    """
    Given:
        - A SailPointIdentityNow client with max of 3 events per call
    When:
        - calling fetch_events with a max_events_per_fetch of 5
    Then:
        - Ensure the pagination is working correctly, and 2 sets of events are fetched to reach the max_events_per_fetch
        - Ensure the next_run object is returned correctly
    """
    client = mocker.patch('SailPointIdentityNowEventCollector.Client')
    last_run = {'prev_id': '0', 'prev_date': '2022-01-01T00:00:00'}
    max_events_per_fetch = 5

    mocker.patch.object(client, 'search_events', return_value=[
        {'id': str(i), 'created': f'2022-01-01T00:0{i}:00'} for i in range(1, 4)
    ])
    next_run, events = fetch_events(client, last_run, max_events_per_fetch)

    assert next_run == {'prev_id': '3', 'prev_date': '2022-01-01T00:03:00'}
    assert len(events) == max_events_per_fetch +1



def test_add_time_and_status_to_events():
    """
    Given:
        - A list of events
            case 1: created and modified are both present and modified > created
            case 2: created and modified are both present and modified < created
            case 3: created is present and modified is None
            case 4: created and modified are both None
    When:
        - calling add_time_and_status_to_events
    Then:
        - Ensure the _ENTRY_STATUS field is added correctly based on the created and modified fields
        - Ensure the _time field is added correctly
            case 1: _ENTRY_STATUS = modified, _time = modified time
            case 2: _ENTRY_STATUS = new, _time = created time
            case 3: _ENTRY_STATUS = new, _time = created time
            case 4: _ENTRY_STATUS = new, _time = None
    """

    events = [
        {'created': '2022-01-01T00:00:00', 'modified': '2022-01-01T00:01:00'},
        {'created': '2022-01-01T00:02:00', 'modified': '2022-01-01T00:01:00'},
        {'created': '2022-01-01T00:03:00', 'modified': None},
        {'created': None, 'modified': None},
    ]

    add_time_and_status_to_events(events)

    assert events[0] == {'created': '2022-01-01T00:00:00', 'modified': '2022-01-01T00:01:00', '_ENTRY_STATUS': 'modified', '_time': '2022-01-01T00:01:00Z'}
    assert events[1]== {'created': '2022-01-01T00:02:00', 'modified': '2022-01-01T00:01:00', '_ENTRY_STATUS': 'new', '_time': '2022-01-01T00:02:00Z'}
    assert events[2] == {'created': '2022-01-01T00:03:00', 'modified': None, '_ENTRY_STATUS': 'new', '_time': '2022-01-01T00:03:00Z'}
    assert events[3] == {'created': None, 'modified': None, '_time': None, '_ENTRY_STATUS': 'new'}