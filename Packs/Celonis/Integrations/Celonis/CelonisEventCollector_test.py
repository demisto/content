import json

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


def test_fetch_events_reaching_rate_limit(mocker):
    """
    Given: A rate limit exceeded error (HTTP 429).
    When: Fetching events and encountering the rate limit exception.
    Then: Ensure no events are returned, and the last run timestamp remains unchanged.
    """
    from CelonisEventCollector import fetch_events
    client = create_client()

    exception = Exception("Rate limit exceeded")
    setattr(exception, "message", "429")
    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "audit_token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', side_effect=exception)
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)

    output, new_last_run = fetch_events(client, fetch_limit=10)
    assert output == []
    assert new_last_run == last_run_mock


def test_fetch_events_token_expired(mocker):
    """
    Given: An exception error of expired audit token.
    When: Fetching events and encountering an unauthorized access error.
    Then: Ensure the token is refreshed, events are fetched successfully, and the last run timestamp is updated correctly.
    """
    from CelonisEventCollector import fetch_events
    client = create_client()

    raw_response_audit_logs = util_load_json('test_data/raw_response_audit_logs.json')

    exception = Exception("Unauthorized access")
    setattr(exception, "message", "Unauthorized")
    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "audit_token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', side_effect=[exception,raw_response_audit_logs])
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)
    mocker.patch('CelonisEventCollector.Client.create_access_token_for_audit')

    output, new_last_run = fetch_events(client, fetch_limit=10)

    assert len(output) == 10
    assert new_last_run.get('start_date') == '2025-02-10T14:52:10.904Z'


def test_fetch_events_reaching_limit(mocker):
    """
    Given: A mock raw response containing audit logs events.
    When: Fetching events with a fetch limit smaller than the number of available logs.
    Then: Ensure the function returns exactly the requested number of events and updates the last run timestamp correctly.
    """
    from CelonisEventCollector import fetch_events
    client = create_client()

    raw_response_audit_logs = util_load_json('test_data/raw_response_audit_logs.json')

    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "audit_token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', return_value=raw_response_audit_logs)
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)
    mocker.patch('CelonisEventCollector.Client.create_access_token_for_audit')

    output, new_last_run = fetch_events(client, fetch_limit=5)

    assert len(output) == 5
    assert new_last_run.get('start_date') == '2025-02-05T14:52:10.904Z'

    for i in range(0,len(output)):
        assert output[i]['message']['id'] == f"id{i+1}"


def test_fetch_events_more_than_exist(mocker):
    """
    Given: A mock raw response containing audit logs events.
    When: Fetching events with a fetch limit greater than the available logs.
    Then: Ensure the function returns all available events and updates the last run timestamp correctly.
    """
    from CelonisEventCollector import fetch_events
    client = create_client()

    raw_response_audit_logs = util_load_json('test_data/raw_response_audit_logs.json')

    last_run_mock = {"start_date": "2025-02-06T00:00:00.000Z", "audit_token": "123"}
    mocker.patch('CelonisEventCollector.Client.get_audit_logs', side_effect=[raw_response_audit_logs, {}])
    mocker.patch('CelonisEventCollector.demisto.getLastRun', return_value=last_run_mock)
    mocker.patch('CelonisEventCollector.Client.create_access_token_for_audit')

    output, new_last_run = fetch_events(client, fetch_limit=15)

    assert len(output) == 11
    assert new_last_run.get('start_date') == '2025-02-25T14:52:10.904Z'

    for i in range(0, len(output)):
        assert output[i]['message']['id'] == f"id{i + 1}"

