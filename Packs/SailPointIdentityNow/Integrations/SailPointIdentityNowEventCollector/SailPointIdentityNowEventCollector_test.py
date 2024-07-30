import pytest
from Packs.SailPointIdentityNow.Integrations.SailPointIdentityNowEventCollector.SailPointIdentityNowEventCollector import dedup, get_last_fetched_ids, fetch_events, add_time_and_status_to_events, Client


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

    mocker.patch('SailPointIdentityNowEventCollector.get_integration_context',
                 return_value={'token': 'valid_token', 'expires': expiration_time})
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
    next_run, events = fetch_events(client, max_events_per_fetch, last_run)

    assert next_run == {'prev_id': '3', 'prev_date': '2022-01-01T00:03:00', 'last_fetched_ids': ['3']}
    assert len(events) == max_events_per_fetch + 1


def test_add_time_and_status_to_events():
    """
    Given:
        - A list of events
            case 1: created and modified are both present and modified > created
            case 2: created and modified are both present and modified < created
            case 3: created is present and modified is not
    When:
        - calling add_time_and_status_to_events
    Then:
        - Ensure the _ENTRY_STATUS field is added correctly based on the created and modified fields
        - Ensure the _time field is added correctly
            case 1: _ENTRY_STATUS = modified, _time = modified time
            case 2: _ENTRY_STATUS = new, _time = created time
            case 3: _ENTRY_STATUS = new, _time = created time
    """

    events = [
        {'created': '2022-01-01T00:00:00', 'modified': '2022-01-01T00:01:00'},
        {'created': '2022-01-01T00:02:00', 'modified': '2022-01-01T00:01:00'},
        {'created': '2022-01-01T00:03:00'},
    ]

    add_time_and_status_to_events(events)

    assert events[0] == {'created': '2022-01-01T00:00:00', 'modified': '2022-01-01T00:01:00',
                         '_ENTRY_STATUS': 'modified', '_time': '2022-01-01T00:01:00Z'}
    assert events[1] == {'created': '2022-01-01T00:02:00', 'modified': '2022-01-01T00:01:00',
                         '_ENTRY_STATUS': 'new', '_time': '2022-01-01T00:02:00Z'}
    assert events[2] == {'created': '2022-01-01T00:03:00', '_time': '2022-01-01T00:03:00Z', '_ENTRY_STATUS': 'new'}


@pytest.mark.parametrize('prev_id, expected', [
    ("123",
     '{"indices": ["events"], "queryType": "SAILPOINT", "queryVersion": "5.2", "query": {"query": "type:* "}, "sort": ["+id"], "searchAfter": ["123"]}'
    ),
    (None,
    '{"indices": ["events"], "queryType": "SAILPOINT", "queryVersion": "5.2", "query": {"query": "type:* AND created: [2022-01-01T00:00:00 TO now]"}, "timeZone": "GMT", "sort": ["+created"]}'
    )
])
def test_search_events(mocker, prev_id, expected):
    """
    Given:
        - A SailPointIdentityNow client
    When:
        - calling search_events
            case 1: with a prev_id
            case 2: without a prev_id
    Then:
        - Ensure the correct request is sent to the API
    """
    mocker_request = mocker.patch.object(Client, '_http_request')
    mocker.patch.object(Client, 'get_token').return_value = {}
    client = Client(base_url="https://example.com", client_id="test_id", client_secret="test_secret",
                    verify=False, proxy=False, token = 'dummy_token')
    client.search_events(from_date = '2022-01-01T00:00:00',limit = 1, prev_id = prev_id)
    assert mocker_request.call_args.kwargs["data"] == expected


def test_dedup__some_duplicates():
    """
    Given:
        - A list of events with duplicate and unique entries
        - A list of last fetched ids
    When:
        - calling dedup
    Then:
        - Ensure the duplicate events are removed
    """
    events = [
        {'created': '2022-01-01T00:00:00Z', 'id': '1'},
        {'created': '2022-01-01T00:00:00Z', 'id': '2'},
        {'created': '2022-01-01T00:00:00Z', 'id': '3'},
        {'created': '2022-01-02T00:00:00Z', 'id': '4'},
    ]
    deduped_events = dedup(events, ['1', '2'])

    assert deduped_events == [
        {'created': '2022-01-01T00:00:00Z', 'id': '3'},
        {'created': '2022-01-02T00:00:00Z', 'id': '4'},
    ]
    
    
def test_dedup__all_duplicates():
    """
    Given:
        - A list of events  all duplicate
        - A list of last fetched ids
    When:
        - calling dedup
    Then:
        - Ensure the duplicate events are removed and an empty list is returned
    """
    events = [
        {'created': '2022-01-01T00:00:00Z', 'id': '1'},
        {'created': '2022-01-01T00:00:00Z', 'id': '2'},
        {'created': '2022-01-01T00:00:00Z', 'id': '3'},
        {'created': '2022-01-02T00:00:00Z', 'id': '4'},
    ]
    deduped_events = dedup(events, ['1', '2', '3', '4'])

    assert deduped_events == []
    
    
def test_dedup__no_duplicates():
    """
        Given:
            - A list of events with no duplicates
            - A list of last fetched ids
        When:
            - calling dedup
        Then:
            - Ensure the events are returned as is
    """
    events = [
        {'created': '2022-01-01T00:00:00Z', 'id': '1'},
        {'created': '2022-01-01T00:00:00Z', 'id': '2'},
        {'created': '2022-01-01T00:00:00Z', 'id': '3'},
        {'created': '2022-01-02T00:00:00Z', 'id': '4'},
    ]
    deduped_events = dedup(events, ['6', '5'])

    assert deduped_events == events


def test_get_last_fetched_ids():
    """
    Given:
        - A list of events with different creation dates
    When:
        - calling get_last_fetched_ids
    Then:
        - Ensure the function returns the ids of the events that have the same creation date as the last event
    """
    # Define the input events
    events = [
        {'created': '2022-01-01T00:00:00Z', 'id': '1'},
        {'created': '2022-01-01T00:00:00Z', 'id': '2'},
        {'created': '2022-01-02T00:00:00Z', 'id': '3'},
        {'created': '2022-01-02T00:00:00Z', 'id': '4'},
    ]

    assert get_last_fetched_ids(events) == ['4', '3']