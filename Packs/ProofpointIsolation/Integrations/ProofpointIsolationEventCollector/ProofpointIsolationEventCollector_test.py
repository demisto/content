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


def test_initialize_args_to_fetch_events(mocker):
    from ProofpointIsolationEventCollector import initialize_args_to_fetch_events, DATE_FORMAT
    from datetime import datetime

    last_run_mock = {
        'start_date': "2025-01-08T10:27:08",
        'ids': ["hashed_id_1", "hashed_id_2"]
    }
    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value=last_run_mock)

    current_time = datetime(2025, 1, 9, 12, 0, 0)
    mocker.patch('ProofpointIsolationEventCollector.get_current_time', return_value=current_time)

    start, end, ids = initialize_args_to_fetch_events()
    assert start == "2025-01-08T10:27:08"
    assert end == current_time.strftime(DATE_FORMAT)
    assert ids == {"hashed_id_1", "hashed_id_2"}

    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value={})
    start, end, ids = initialize_args_to_fetch_events()
    assert start is None
    assert ids == set()


def test_initialize_args_to_get_events():
    from ProofpointIsolationEventCollector import initialize_args_to_get_events
    args = {
        'start_date': "2025-01-08T10:27:08",
        'end_date': "2025-01-09T10:27:08"
    }
    start, end, ids = initialize_args_to_get_events(args)

    assert start == "2025-01-08T10:27:08"
    assert end == "2025-01-09T10:27:08"
    assert ids == set()

    args = {}
    start, end, ids = initialize_args_to_get_events(args)

    assert start is None
    assert end is None
    assert ids == set()


def test_remove_duplicate_events():
    from ProofpointIsolationEventCollector import remove_duplicate_events,sort_events_by_date, hash_user_name_and_url, get_and_parse_date
    mocked_events = util_load_json('test_data/get_events_raw_response.json')

    events = sort_events_by_date(mocked_events["data"])
    start_date = "2025-01-01T19:44:35Z"

    ids = {
        hash_user_name_and_url(event) for event in events if get_and_parse_date(event) == start_date
    }

    remove_duplicate_events(start_date, ids, events)

    expected_event_count = len(mocked_events["data"]) - 2
    assert len(events) == expected_event_count

    for event in events:
        assert hash_user_name_and_url(event) not in ids or get_and_parse_date(event) != start_date


def test_get_and_parse_date():
    from ProofpointIsolationEventCollector import get_and_parse_date, parse_date_string, DATE_FORMAT

    valid_event = {
        "date": "2025-01-01T19:44:35.000+0000",
        "userName": "user@example.com",
    }

    parsed_date = get_and_parse_date(valid_event)
    assert parsed_date == "2025-01-01T19:44:35Z"


def test_no_more_events_after_second_call(mocker):
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
    assert len(events) == 0


def test_fetch_limit_reached(mocker):
    from ProofpointIsolationEventCollector import fetch_events

    client = create_client()
    mocked_events = util_load_json('test_data/get_events_raw_response.json')
    mocker.patch('ProofpointIsolationEventCollector.Client.get_events', return_value=mocked_events)
    last_run_mock = {
        "start_date": "2025-01-09T11:27:08"
    }
    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value=last_run_mock)

    limit = 3

    events, new_last_run = fetch_events(client, limit)

    assert len(events) == limit
    assert 'ids' in new_last_run


def test_first_time_fetch(mocker):
    from ProofpointIsolationEventCollector import fetch_events

    client = create_client()
    mocked_events = util_load_json('test_data/get_events_raw_response.json')
    mocker.patch('ProofpointIsolationEventCollector.Client.get_events', return_value=mocked_events)

    last_run_mock = {}
    mocker.patch('ProofpointIsolationEventCollector.demisto.getLastRun', return_value=last_run_mock)
    limit = 5

    events, new_last_run = fetch_events(client, limit)

    assert len(events) == 0
    assert 'ids' in new_last_run
    assert new_last_run['ids'] == []
    assert 'start_date' in new_last_run

