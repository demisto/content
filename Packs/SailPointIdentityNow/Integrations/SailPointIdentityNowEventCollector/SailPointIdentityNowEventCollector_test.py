import pytest
import demistomock as demisto
from SailPointIdentityNowEventCollector import fetch_events, add_time_and_status_to_events, Client, \
    dedup_events, get_last_fetched_ids

EVENTS_WITH_THE_SAME_DATE = [
    {'created': '2022-01-01T00:00:00Z', 'id': '1'},
    {'created': '2022-01-01T00:00:00Z', 'id': '2'},
    {'created': '2022-01-01T00:00:00Z', 'id': '3'},
    {'created': '2022-01-01T00:00:00Z', 'id': '4'},
]

EVENTS_WITH_DIFFERENT_DATE = [
    {'created': '2022-01-01T00:00:00Z', 'id': '1'},
    {'created': '2022-01-01T00:00:00Z', 'id': '2'},
    {'created': '2022-01-02T00:00:00Z', 'id': '3'},
    {'created': '2022-01-02T00:00:00Z', 'id': '4'},
]


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


def test_fetch_events__end_to_end_with_affective_dedup(mocker):
    """
    Given:
        - A SailPointIdentityNow client with max of 3 events ro return per call
    When:
        - calling fetch_events with a max_events_per_fetch of 5
    Then:
        - Ensure the pagination is working correctly, and 3 sets of events are fetched to reach
            the max_events_per_fetch or the end of the events
        - Ensure the next_run object is returned correctly
        - ensure the events are deduped correctly.
    """
    mocker.patch.object(demisto, 'debug')
    client = mocker.patch('SailPointIdentityNowEventCollector.Client')
    last_run = {'prev_id': '0', 'prev_date': '2022-01-01T00:00:00'}
    max_events_per_fetch = 5

    mocker.patch.object(client, 'search_events', side_effect=[[
        {'id': str(i), 'created': f'2022-01-01T00:0{i}:00'} for i in range(1, 4)
    ], [
        {'id': str(i), 'created': f'2022-01-01T00:0{i}:00'} for i in range(3, 5)
    ],
        []])

    next_run, events = fetch_events(client, max_events_per_fetch, last_run)

    assert next_run == {'prev_date': '2022-01-01T00:04:00', 'last_fetched_ids': ['4']}
    assert len(events) == 4


def test_fetch_events__no_events(mocker):
    """
    Given:
        - A SailPointIdentityNow client with max of 3 events per call
    When:
        - calling fetch_events with a max_events_per_fetch of 5 and no events to fetch
    Then:
        - Ensure the next_run object is returned correctly and we did not enter an infinite loop
        - Ensure the debug logs are correct

    """
    mock_debug = mocker.patch.object(demisto, 'debug')
    client = mocker.patch('SailPointIdentityNowEventCollector.Client')
    last_run = {'prev_date': '2022-01-01T00:00:00', 'last_fetched_ids': ['0']}
    max_events_per_fetch = 5

    mocker.patch.object(client, 'search_events', return_value=[])
    next_run, _ = fetch_events(client, max_events_per_fetch, last_run)

    assert next_run == last_run
    assert mock_debug.call_args_list[3][0][0] == 'No events fetched. Exiting the loop.'


def test_fetch_events__all_events_are_dedup(mocker):
    """
    Given:
        - A SailPointIdentityNow client with max of 3 events per call
    When:
        - calling fetch_events with a max_events_per_fetch of 5 and all events are duplicates
    Then:
        - Ensure the next_run object is returned correctly
        - Ensure the we are not stuck in an infinite loop
        - Ensure the debug messages are correct
    """
    mock_debug = mocker.patch.object(demisto, 'debug')
    client = mocker.patch('SailPointIdentityNowEventCollector.Client')
    last_run = {'prev_date': '2022-01-01T00:00:00', 'last_fetched_ids': [0]}
    max_events_per_fetch = 5
    mocker.patch('SailPointIdentityNowEventCollector.dedup_events', return_value=[])

    mocker.patch.object(client, 'search_events', return_value=[
        {'id': str(i), 'created': f'2022-01-01T00:0{i}:00'} for i in range(1, 4)
    ])
    next_run, _ = fetch_events(client, max_events_per_fetch, last_run)
    assert next_run == last_run
    assert 'Successfully fetched 3 events in this cycle.' in mock_debug.call_args_list[2][0][0]
    assert "Done fetching. Sum of all events: 0, the next run is" in mock_debug.call_args_list[3][0][0]


def test_add_time_and_status_to_events(mocker):
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
    mocker.patch.object(demisto, 'debug')

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
     '{"indices": ["events"], "queryType": "SAILPOINT", "queryVersion": "5.2", "sort": ["+id"], "query": {"query": "type:* "}, "searchAfter": ["123"]}'  # noqa: E501
     ),
    (None,
     '{"indices": ["events"], "queryType": "SAILPOINT", "queryVersion": "5.2", "sort": ["+created"], "query": {"query": "type:* AND created: [2022-01-01T00:00:00 TO now]"}, "timeZone": "GMT"}'       # noqa: E501
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
                    verify=False, proxy=False, token='dummy_token')
    client.search_events(from_date='2022-01-01T00:00:00', limit=1, prev_id=prev_id)
    assert mocker_request.call_args.kwargs["data"] == expected


def test_get_last_fetched_ids(mocker):
    """
    Given:
        - A list of events with different creation dates
    When:
        - calling get_last_fetched_ids
    Then:
        - Ensure the function returns the ids of the events that have the same creation date as the last event
    """
    mocker.patch.object(demisto, 'debug')

    assert get_last_fetched_ids(EVENTS_WITH_DIFFERENT_DATE) == ['3', '4']


@pytest.mark.parametrize('events, last_fetched_ids, expected, debug_msgs', [
    (EVENTS_WITH_DIFFERENT_DATE, ['1', '2'], [{'created': '2022-01-02T00:00:00Z', 'id': '3'},
                                              {'created': '2022-01-02T00:00:00Z', 'id': '4'}],
     ["Starting deduping. Number of events before deduping: 4, last fetched ids: ['1', '2']",
      'Done deduping. Number of events after deduping: 2']),
    (EVENTS_WITH_THE_SAME_DATE, ['1', '2', '3', '4'], [], []),
    (EVENTS_WITH_THE_SAME_DATE, ['6', '5'], EVENTS_WITH_THE_SAME_DATE, [])
])
def test_dedup_events(mocker, events, last_fetched_ids, expected, debug_msgs):
    """
    Given:
        - A list of events with duplicate and unique entries
        - A list of last fetched ids
        case 1  - some of the new events were fetched in the last fetch.
        case 2  - all of the new events were fetched in the last fetch.
        case 3  - none of the new events were fetched in the last fetch.
    When:
        - calling dedup_events
    Then:
        - Ensure the duplicate events are removed
        - Ensure the log message contains the info of the dropped events.
    """
    debug_msg = mocker.patch.object(demisto, 'debug')
    deduped_events = dedup_events(events, last_fetched_ids=last_fetched_ids)

    assert deduped_events == expected
    for i, msg in enumerate(debug_msgs):
        assert msg in debug_msg.call_args_list[i][0][0]
