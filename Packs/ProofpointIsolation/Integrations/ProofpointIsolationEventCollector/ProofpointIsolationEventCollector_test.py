import json

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MOCK_BASEURL = "https://example.com"
MOCK_API_KEY = "API_KEY"


def create_client():
    from ProofpointIsolationEventCollector import Client
    return Client(
        base_url=MOCK_BASEURL, verify=False,
        api_key=MOCK_API_KEY
    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_get_and_reorganize_events(mocker):
    """
    Given: A mock Proofpoint client with a set of raw events and a set of event IDs.
    When: Reorganizing events based on date and excluding the last event ID.
    Then:
        - Ensure the events are sorted in chronological order.
        - The number of reorganized events matches the expected count.
        - The last event is excluded because it is in ids set.

    """
    from ProofpointIsolationEventCollector import get_and_reorganize_events, hash_user_name_and_url
    mocked_events = util_load_json('test_data/get_events_raw_response.json')
    mocker.patch('ProofpointIsolationEventCollector.Client.get_events', return_value=mocked_events)

    events = mocked_events["data"]
    client = create_client()
    hashed_id_last_event = hash_user_name_and_url(events[-1])
    ids = {hashed_id_last_event}

    organized_events = get_and_reorganize_events(client, "2025-01-01T19:44:35Z", "2025-01-12", ids)

    assert all(
        organized_events[i]['date'] <= organized_events[i + 1]['date']
        for i in range(len(organized_events) - 1)
    )

    assert len(organized_events) == len(events) - 1

    organized_ids = {hash_user_name_and_url(event) for event in organized_events}
    assert hashed_id_last_event not in organized_ids

    assert organized_events[0]['date'] == "2025-01-01T19:44:35.000+0000"
    assert organized_events[-1]['date'] == "2025-01-09T19:44:35.000+0000"


def test_remove_duplicate_events():
    """
    Given: A list of events sorted by date, with a specified start date and event IDs.
    When: Removing duplicate events for a given start date.
    Then: Ensure the number of events is reduced by the expected amount,
     and verify that no event with the same ID and start date remains after duplicates are removed.
    """
    from ProofpointIsolationEventCollector import (remove_duplicate_events, sort_events_by_date,
                                                   hash_user_name_and_url, get_and_parse_date)
    mocked_events = util_load_json('test_data/get_events_raw_response.json')

    events = sort_events_by_date(mocked_events["data"])
    start_date = "2025-01-01T19:44:35Z"

    ids = {
        hash_user_name_and_url(event) for event in events if get_and_parse_date(event) == start_date
    }

    remove_duplicate_events(start_date, ids, events)

    expected_event_count = len(mocked_events["data"]) - 5
    assert len(events) == expected_event_count

    for event in events:
        assert hash_user_name_and_url(event) not in ids or get_and_parse_date(event) != start_date


def test_get_and_parse_date():
    """
    Given: A valid event with a date in a specific format.
    When: Parsing the event's date using the `get_and_parse_date` function.
    Then: Ensure the date is correctly parsed and returned in the expected format.
    """
    from ProofpointIsolationEventCollector import get_and_parse_date

    valid_event = {
        "date": "2025-01-01T19:44:35.000+0000",
        "userName": "user@example.com",
    }

    parsed_date = get_and_parse_date(valid_event)
    assert parsed_date == "2025-01-01T19:44:35Z"


def test_hash_user_name_and_url():
    """
    Given: A dictionary containing event data with 'url' and 'userName' fields.
    When: The function hash_user_name_and_url is called.
    Then: Ensure the output matches the expected '<url>&<userName>' format.
    """
    from ProofpointIsolationEventCollector import hash_user_name_and_url

    event = {'url': 'example.com', 'userName': 'testUser', 'extraField': 'extraValue'}
    result = hash_user_name_and_url(event)
    assert result == 'example.com&testUser'


def test_sort_events_by_date():
    """
    Given: A list of events, each containing a 'date' field in ISO 8601 format.
    When: The function is called to sort the events by their 'date' field.
    Then: Ensure the events are sorted in ascending order by date.
    """
    from ProofpointIsolationEventCollector import sort_events_by_date

    events = [
        {'date': '2025-01-14T12:00:00.000+0000', 'event_id': 1},
        {'date': '2025-01-13T12:00:00.000+0000', 'event_id': 2},
        {'date': '2025-01-15T12:00:00.000+0000', 'event_id': 3},
    ]
    sorted_events = sort_events_by_date(events)
    assert sorted_events[0]['event_id'] == 2
    assert sorted_events[1]['event_id'] == 1
    assert sorted_events[2]['event_id'] == 3

    events = []
    sorted_events = sort_events_by_date(events)
    assert sorted_events == []


def test_no_more_events_after_second_call(mocker):
    """
    Given: A mock Proofpoint client with event data and a last run timestamp.
    When: Fetching events with a specified limit across multiple calls.
    Then: Ensure the correct number of events are fetched on the first call,
     and no events are returned on the second call when there are no more events to fetch.
    """
    from ProofpointIsolationEventCollector import fetch_events

    client = create_client()
    mocked_events = util_load_json('test_data/get_events_raw_response.json')
    last_event = {"data": [mocked_events.get('data')[-2]]}
    mocker.patch('ProofpointIsolationEventCollector.Client.get_events', side_effect=[mocked_events, last_event, {"data": []}])

    last_run_mock = {
        "start_date": "2025-01-09T11:27:08"
    }
    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value=last_run_mock)

    limit = 10

    events, new_last_run = fetch_events(client, limit)

    assert len(events) == limit
    assert new_last_run['ids']

    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value=new_last_run)
    events, new_last_run = fetch_events(client, limit)
    assert len(events) == 1


def test_fetch_events(mocker):
    """
    Given: A mock Proofpoint client with event data and no previous run data.
    When: Fetching events multiple times with a specified limit.
    Then: Ensure correct number of events are fetched, and `lastRun` updates correctly with unique event IDs.
          Also ensure the first fetch initializes `lastRun` properly.
    """
    from ProofpointIsolationEventCollector import fetch_events

    client = create_client()
    mocked_events = util_load_json('test_data/get_events_raw_response.json')
    return_values_events = [
        mocked_events,
        {'data': mocked_events.get('data')[4:]}
    ]

    mocker.patch('ProofpointIsolationEventCollector.Client.get_events', side_effect=return_values_events)

    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value={})
    limit = 5

    events, new_last_run = fetch_events(client, limit)
    assert len(events) == limit
    assert 'ids' in new_last_run
    assert 'https://exmaple.k1.com/&user9@example.com' in new_last_run['ids']
    assert 'https://exmaple.k1.com/&user10@example.com' in new_last_run['ids']
    assert 'https://exmaple.k1.com/&user7@example.com' in new_last_run['ids']
    assert 'https://exmaple.k10.com/&user0@example.com' in new_last_run['ids']
    assert 'https://exmaple.k1.com/&user8@example.com' in new_last_run['ids']
    assert new_last_run.get('start_date') == '2025-01-01T19:44:35Z'

    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value=new_last_run)

    events, new_last_run = fetch_events(client, limit)
    assert len(events) == limit
    assert 'ids' in new_last_run
    assert len(new_last_run.get('ids')) == 1
    assert new_last_run.get('start_date') == '2025-01-06T19:44:35Z'
