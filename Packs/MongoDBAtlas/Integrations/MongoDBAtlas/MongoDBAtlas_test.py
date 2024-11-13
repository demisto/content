import copy
import json
import pytest

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

MOCK_BASEURL = "https://example.com"
MOCK_GROUP_ID = "123"
MOCK_PRIVATE_KEY = "private_key"
MOCK_PUBLIC_KEY = "public_key"


def create_client():
    from MongoDBAtlas import Client
    return Client(
        base_url=MOCK_BASEURL, verify=False,
        group_id=MOCK_GROUP_ID, private_key=MOCK_PRIVATE_KEY,
        public_key=MOCK_PUBLIC_KEY
    )


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_add_entry_status_field():
    """
    Given: A list of events with 'created' and 'updated' timestamps.
    When: Calling the `add_entry_status_field` function to add the '_entry_status' field based on whether the event
     has been updated.
    Then: Ensure the '_entry_status' field is correctly added with the value 'new' if the 'created' and 'updated' timestamps
     are the same, or 'updated' if the 'updated' timestamp differs from the 'created' timestamp.
    """
    from MongoDBAtlas import add_entry_status_field
    test_cases = [
        {
            "event": {"created": "2024-10-27T12:07:17Z", "updated": "2024-10-27T12:07:17Z"},
            "expected_status": "new"
        },
        {
            "event": {"created": "2024-10-27T12:07:17Z", "updated": "2024-10-27T12:08:17Z"},
            "expected_status": "updated"
        }
    ]
    for case in test_cases:
        event = case["event"]
        add_entry_status_field(event)
        assert event["_entry_status"] == case["expected_status"]


def test_get_next_url():
    """
    Given: A list of links.
    When: Calling the `get_next_url` function to extract the 'next' URL.
    Then: Ensure the correct 'next' URL is returned if present, or empty string if no 'next' URL is found.
    """
    from MongoDBAtlas import get_next_url
    # Test case where a "next" link is present
    links_with_next = [
        {"rel": "prev", "href": "http://example.com/page/1"},
        {"rel": "next", "href": "http://example.com/page/3"},
        {"rel": "last", "href": "http://example.com/page/4"}
    ]
    assert get_next_url(links_with_next) == "http://example.com/page/3"

    # Test case where no "next" link is present
    links_without_next = [
        {"rel": "prev", "href": "http://example.com/page/1"},
        {"rel": "first", "href": "http://example.com/page/1"},
        {"rel": "last", "href": "http://example.com/page/4"}
    ]
    assert get_next_url(links_without_next) == ""


def test_get_self_url():
    """
    Given: A list of links.
    When: Calling the `get_self_url` function to extract the 'self' URL.
    Then: Ensure the correct 'self' URL is returned if present, or empty string if no 'self' URL is found.
    """
    from MongoDBAtlas import get_self_url
    # Test case where a "self" link is present
    links_with_next = [
        {"rel": "prev", "href": "http://example.com/page/1"},
        {"rel": "self", "href": "http://example.com/page/3"},
        {"rel": "last", "href": "http://example.com/page/4"}
    ]
    assert get_self_url(links_with_next) == "http://example.com/page/3"

    # Test case where no "self" link is present
    links_without_next = [
        {"rel": "prev", "href": "http://example.com/page/1"},
        {"rel": "first", "href": "http://example.com/page/1"},
        {"rel": "last", "href": "http://example.com/page/4"}
    ]
    assert get_self_url(links_without_next) == ""


def test_add_time_field():
    """
    Given: An event with either 'updated' or 'created' timestamp fields.
    When: Calling the `add_time_field` function to add a '_time' field based on the available timestamp.
    Then: Ensure the '_time' field is correctly added, using the 'updated' timestamp if present,
     otherwise using the 'created' timestamp.
    """
    from MongoDBAtlas import add_time_field
    # Case where 'updated' time is present in the event
    event = {
        "created": "2024-10-27T12:07:17Z",
        "updated": "2024-10-27T13:07:17Z"
    }
    add_time_field(event)
    assert event["_time"] == "2024-10-27T13:07:17Z"

    # Case where only 'created' time is present in the event
    event = {
        "created": "2024-10-27T13:07:17Z"
    }
    add_time_field(event)
    assert event["_time"] == "2024-10-27T13:07:17Z"


def test_remove_alerts_by_ids():
    from MongoDBAtlas import remove_alerts_by_ids
    alerts = [
        {"id": 1, "name": "alert1"},
        {"id": 2, "name": "alert2"},
        {"id": 3, "name": "alert3"},
        {"id": 4, "name": "alert4"},
    ]

    ids_to_remove = [2, 4]

    expected_result = [
        {"id": 1, "name": "alert1"},
        {"id": 3, "name": "alert3"}
    ]

    result = remove_alerts_by_ids(alerts, ids_to_remove)

    assert result == expected_result


@pytest.mark.parametrize("fetch_limit, expected_alert_count", [
    (10, 5),  # Case: fetch_limit > available alerts
    (3, 3)  # Case: fetch_limit < available alerts
])
def test_fetch_alert_type(mocker, fetch_limit, expected_alert_count):
    """
    Given: A mock MongoDB Atlas client with a page of alerts and a specified fetch limit.
    When: Fetching alerts from the page with different fetch limits.
    Then: Ensure the correct number of alerts are fetched, the page link is set correctly,
     and the last page alert IDs are correctly recorded and validated.
    """
    from MongoDBAtlas import fetch_alert_type
    mocked_alerts = util_load_json('test_data/raw_alerts_page_1.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)

    client = create_client()

    last_run = {"page_link": None, "last_page_alerts_ids": []}
    output, last_run_new_dict = fetch_alert_type(client, fetch_limit, last_run)

    assert len(output) == expected_alert_count
    assert last_run_new_dict.get('page_link') == 'self1'
    last_page_alerts_ids = last_run_new_dict.get('last_page_alerts_ids')
    assert len(last_page_alerts_ids) == expected_alert_count
    for id in last_page_alerts_ids:
        assert 1 <= int(id) <= expected_alert_count
        last_page_alerts_ids.remove(id)


@pytest.mark.parametrize("fetch_limit, expected_alert_count", [
    (9, 9),  # Each page has 5 alerts
    (8, 8)
])
def test_fetch_alert_type_using_next_page(mocker, fetch_limit, expected_alert_count):
    """
    Given: A mock MongoDB Atlas client with two pages of alert data.
    When: Fetching alerts with a specified fetch limit and processing alerts from the first and second pages.
    Then: Ensure the correct number of alerts are fetched, the next page link is set properly,
     and the last page alert IDs are correctly updated after the fetch.
    """
    from MongoDBAtlas import fetch_alert_type

    mocked_alerts_page_1 = util_load_json('test_data/raw_alerts_page_1.json')
    mocked_alerts_page_2 = util_load_json('test_data/raw_alerts_page_2.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts_page_1)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=True)
    mocker.patch('MongoDBAtlas.Client.get_response_from_page_link', return_value=mocked_alerts_page_2)

    client = create_client()

    last_run = {"page_link": None, "last_page_alerts_ids": []}

    output, last_run_new_dict = fetch_alert_type(client, fetch_limit, last_run)
    expected_ids_page_1 = [str(i) for i in range(1, expected_alert_count + 1)]

    assert len(output) == expected_alert_count
    assert last_run_new_dict.get('page_link') == 'self2'
    last_page_alerts_ids = last_run_new_dict.get('last_page_alerts_ids')
    assert set(last_page_alerts_ids) == set(expected_ids_page_1[5:])

    last_run = {"page_link": None, "last_page_alerts_ids": ["1"]}

    output, last_run_new_dict = fetch_alert_type(client, fetch_limit, last_run)

    assert len(output) == expected_alert_count
    assert last_run_new_dict.get('page_link') == 'self2'

    last_page_alerts_ids = last_run_new_dict.get('last_page_alerts_ids')
    assert len(last_page_alerts_ids) == abs(4 - expected_alert_count)


def test_fetch_alert_type_while_more_alerts_created(mocker):
    """
    Given: A mock MongoDB Atlas client with an initial page of alert data, where more alerts are added after the initial fetch.
    When: Running fetch_alert_type to fetch alerts in two stages – first fetching the initial set,
     and then fetching only the newly added alerts.
    Then: Ensure the correct number of alerts are returned in each fetch, that the last page link is set correctly,
     and that the IDs in last_page_alerts_ids match the expected values after both fetches.
    """
    from MongoDBAtlas import fetch_alert_type

    mocked_alerts_page_1 = util_load_json('test_data/raw_alerts_page_1.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts_page_1)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=False)

    client = create_client()

    last_run = {"page_link": None, "last_page_alerts_ids": []}

    output, last_run_new_dict = fetch_alert_type(
        client, len(mocked_alerts_page_1.get('results')), last_run
    )

    seen_ids = {event.get('id') for event in output}

    assert len(output) == len(mocked_alerts_page_1.get('results'))
    assert last_run_new_dict.get('page_link') == 'self1'

    mocked_alerts_page_1_with_more_alerts = util_load_json('test_data/raw_alerts_page_1_with_more_alerts.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts_page_1_with_more_alerts)

    last_run = copy.deepcopy(last_run_new_dict)
    additional_alerts_amount = (
        len(mocked_alerts_page_1_with_more_alerts.get('results'))
        - len(mocked_alerts_page_1.get('results'))
    )
    output, last_run_new_dict = fetch_alert_type(client, additional_alerts_amount, last_run)
    assert len(output) == additional_alerts_amount

    expected_ids = [str(i) for i in range(1, 9)]
    last_page_alerts_ids = last_run_new_dict.get('last_page_alerts_ids')

    assert set(last_page_alerts_ids) == set(expected_ids)

    # checks for duplicates
    for event in output:
        event_id = event.get("id")
        assert event_id not in seen_ids
        seen_ids.add(event_id)


@pytest.mark.parametrize("fetch_limit, expected_event_count", [
    (12, 11),  # Case: fetch_limit > available events
    (8, 8)  # Case: fetch_limit < available events
])
def test_fetch_event_type(mocker, fetch_limit, expected_event_count):
    """
    Given: A mock MongoDB Atlas client with a single page of event data.
    When: Running fetch_event_type with different fetch limits.
    Then: Ensure that the number of events returned matches the expected count,
     and the min_time in last_run is updated to the lasted creation time.
    """
    from MongoDBAtlas import fetch_event_type

    mocked_events_page_1 = util_load_json('test_data/raw_events_page_1.json')
    mocker.patch('MongoDBAtlas.Client.get_events_with_min_time', return_value=mocked_events_page_1)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)

    client = create_client()

    last_run = {"min_time": "2024-11-05T11:10:01Z", "events_with_created_min_time": []}

    output, last_run_new_dict = fetch_event_type(
        client, fetch_limit, last_run
    )

    assert len(output) == expected_event_count
    assert last_run_new_dict.get('min_time') is output[expected_event_count - 1].get('created')


def test_fetch_event_type_min_time_repeat(mocker):
    """
    Given: A mock MongoDB Atlas client with event data that includes duplicate timestamps for event creation.
    When: Running fetch_event_type with a set fetch limit, where events initially fetched share the same min_time as new events
     in a subsequent fetch.
    Then: Ensure that events are retrieved up to the fetch limit, min_time is updated appropriately after each fetch,
     and no duplicate event IDs are present in the final output.
    """

    from MongoDBAtlas import fetch_event_type
    raw_events_page_duplicated_dates = util_load_json('test_data/raw_events_page_duplicated_dates.json')
    mocker.patch('MongoDBAtlas.Client.get_events_with_min_time', return_value=raw_events_page_duplicated_dates)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)

    client = create_client()

    last_run = {"min_time": "2024-11-05T11:00:01Z", "events_with_created_min_time": []}

    output, last_run_new_dict = fetch_event_type(
        client, 4, last_run
    )

    events_with_created_min_time = last_run_new_dict.get('events_with_created_min_time')
    min_time = last_run_new_dict.get('min_time')

    assert len(output) == 4
    assert min_time == '2024-11-05T11:10:01Z'

    first_fetch_events_with_created_min_time = copy.deepcopy(events_with_created_min_time)

    last_run = {"min_time": min_time, "events_with_created_min_time": events_with_created_min_time}
    output, last_run_new_dict = fetch_event_type(
        client, 10, last_run
    )

    min_time = last_run_new_dict.get('min_time')

    assert len(output) == 10
    assert min_time == "2024-11-10T14:21:28Z"
    for event_id in first_fetch_events_with_created_min_time:
        for event in output:
            assert event_id != event.get('id')


@pytest.mark.parametrize("fetch_limit, expected_event_count", [
    (20, 20),  # Case: fetch_limit < available events
    (25, 22)  # Case: fetch_limit > available events
])
def test_fetch_event_type_using_previous_page(mocker, fetch_limit, expected_event_count):
    """
    Given: A mock MongoDB Atlas client with a fetch limit and paginated event data spread across 2 pages.
    When: Running fetch_event_type with a specified fetch limit and using previous page retrieval.
    Then: Ensure that the total number of events matches the expected count,
     min_time is updated based on the last event's created time, and no duplicate event IDs are present in the output.
    """
    from MongoDBAtlas import fetch_event_type

    raw_events_page_1 = util_load_json('test_data/raw_events_page_1.json')
    raw_events_page_2 = util_load_json('test_data/raw_events_page_2.json')

    mocker.patch('MongoDBAtlas.Client.get_events_with_min_time', return_value=raw_events_page_2)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)
    mocker.patch('MongoDBAtlas.get_previous_page', side_effect=[True, False])
    mocker.patch('MongoDBAtlas.Client.get_response_from_page_link', return_value=raw_events_page_1)

    client = create_client()

    last_run = {"min_time": "2024-01-01T11:10:01Z", "events_with_created_min_time": []}

    output, last_run_new_dict = fetch_event_type(
        client, fetch_limit, last_run
    )

    assert len(output) == expected_event_count
    assert last_run_new_dict.get('min_time') is output[-1].get('created')

    # checks for duplicates
    seen_ids = set()
    for event in output:
        event_id = event.get("id")
        assert event_id not in seen_ids
        seen_ids.add(event_id)


def test_get_events_first_five_pages(mocker):
    from MongoDBAtlas import Client
    mock_get_events_with_page_num = mocker.patch.object(
        Client, 'get_events_with_page_num'
    )

    page1 = {"results": [{"id": i} for i in range(50)]}
    page2 = {"results": [{"id": i} for i in range(50, 100)]}
    page3 = {"results": [{"id": i} for i in range(100, 150)]}
    page4 = {"results": [{"id": i} for i in range(150, 200)]}
    page5 = {"results": [{"id": i} for i in range(200, 250)]}

    client = create_client()

    mock_get_events_with_page_num.side_effect = [
        page1
    ]
    # Case 1: Fetch limit within one page
    fetch_limit = 30
    results = client.get_events_first_five_pages(fetch_limit)
    assert len(results) == fetch_limit
    assert results[-1]["id"] == 29

    mock_get_events_with_page_num.side_effect = [
        page1, page2, page3
    ]
    # Case 2: Fetch limit across multiple pages
    fetch_limit = 120
    results = client.get_events_first_five_pages(fetch_limit)
    assert len(results) == fetch_limit
    assert results[-1]["id"] == 119

    mock_get_events_with_page_num.side_effect = [
        page1, page2, page3, page4, page5
    ]
    # Case 3: Fetch limit exceeds total available events in five pages
    fetch_limit = 300
    results = client.get_events_first_five_pages(fetch_limit)
    assert len(results) == 250
    assert results[-1]["id"] == 249


def test_test_module(mocker):
    from MongoDBAtlas import test_module

    mock_return_error = mocker.patch('MongoDBAtlas.return_error')

    client = create_client()
    fetch_limit = 0

    test_module(client, fetch_limit)
    mock_return_error.assert_called_with('Invalid maximum number of events per fetch, should be between 1 and 2500.')

    fetch_limit = 2501

    test_module(client, fetch_limit)
    mock_return_error.assert_called_with('Invalid maximum number of events per fetch, should be between 1 and 2500.')
