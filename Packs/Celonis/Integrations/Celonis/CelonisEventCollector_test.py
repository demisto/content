import json

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MOCK_BASEURL = "https://example.com"
MOCK_API_KEY = "API_KEY"


def create_client():
    from CelonisEventCollector import Client
    return Client(
        base_url=MOCK_BASEURL, verify=False,
        client_id=MOCK_API_KEY
    )


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
