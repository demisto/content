import json

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MOCK_BASEURL = "https://example.com"
MOCK_CLIENT_ID = "ID"
MOCK_CLIENT_SECRET = "SECRET"

from CelonisEventCollector import Client


def create_client():
    return Client(
        base_url=MOCK_BASEURL, verify=False,
        client_id=MOCK_CLIENT_ID, client_secret=MOCK_CLIENT_SECRET
    )


def mock_create_access_token_for_audit(client: Client):
    client.token = '321'


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_sort_events_by_timestamp(mocker):
    """
    Given: A mock raw response containing unsorted event logs.
    When: Sorting events based on timestamp.
    Then:
        - Ensure the events are sorted in chronological order.
        - The number of events remains the same after sorting.
    """
    from CelonisEventCollector import sort_events_by_timestamp
    raw_response = util_load_json('test_data/raw_response_audit_logs.json')

    events = raw_response["content"]
    sorted_events = sort_events_by_timestamp(events)

    assert all(
        sorted_events[i]['timestamp'] <= sorted_events[i + 1]['timestamp']
        for i in range(len(sorted_events) - 1)
    )

    assert len(sorted_events) == len(events)


def test_add_millisecond():
    """
    Given: A timestamp in ISO 8601 format.
    When: Adding one millisecond to the timestamp.
    Then: Ensure the millisecond value is incremented correctly.
    """
    from CelonisEventCollector import add_millisecond
    assert add_millisecond("2025-02-05T14:30:00.123Z") == "2025-02-05T14:30:00.124Z"
    assert add_millisecond("2025-02-05T23:59:59.999Z") == "2025-02-06T00:00:00.000Z"
    assert add_millisecond("2025-02-05T23:59:59Z") == "2025-02-05T23:59:59.001Z"


def test_fetch_events_reaching_rate_limit(mocker):
    from CelonisEventCollector import fetch_events
    client = create_client()

    exception = Exception("Rate limit exceeded")
    setattr(exception, "res", "LIMIT_RATE_EXCEEDED")
    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', side_effect=exception)
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)

    output, new_last_run = fetch_events(client, fetch_limit=10)
    assert output == []
    assert new_last_run == last_run_mock


def test_fetch_events_token_expired(mocker):
    from CelonisEventCollector import fetch_events
    client = create_client()

    raw_response_audit_logs = util_load_json('test_data/raw_response_audit_logs.json')

    exception = Exception("Unauthorized access")
    setattr(exception, "message", "Unauthorized")
    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', side_effect=[exception,raw_response_audit_logs])
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)
    mocker.patch('CelonisEventCollector.Client.create_access_token_for_audit')

    output, new_last_run = fetch_events(client, fetch_limit=10)

    assert len(output) == 10
    assert new_last_run.get('start_date') == '2025-02-10T14:52:10.904Z'


def test_fetch_events_reaching_limit(mocker):
    from CelonisEventCollector import fetch_events, sort_events_by_timestamp
    client = create_client()

    raw_response_audit_logs = util_load_json('test_data/raw_response_audit_logs.json')

    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', return_value=raw_response_audit_logs)
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)
    mocker.patch('CelonisEventCollector.Client.create_access_token_for_audit')

    output, new_last_run = fetch_events(client, fetch_limit=5)

    assert len(output) == 5
    assert new_last_run.get('start_date') == '2025-02-05T14:52:10.904Z'

    for i in range(0,len(output)):
        assert output[i]['message']['id'] == f"id{i+1}"


def test_fetch_events_more_than_exist(mocker):
    pass