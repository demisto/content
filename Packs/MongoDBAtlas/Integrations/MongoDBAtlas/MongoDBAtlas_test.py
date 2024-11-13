import copy
import json
import unittest
from datetime import datetime
from unittest.mock import patch
import pytest

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"

MOCK_BASEURL = "https://example.com"
MOCK_GROUP_ID = "123"
MOCK_PRIVATE_KEY = "private_key"
MOCK_PUBLIC_KEY = "public_key"


def util_load_json(path):
    with open(path, encoding='utf-8') as f:
        return json.loads(f.read())


def test_add_entry_status_field():
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
    assert get_next_url(links_without_next) is None


def test_get_self_url():
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
    assert get_self_url(links_without_next) is None


def test_add_time_field():
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



@pytest.mark.parametrize("fetch_limit, expected_alert_count", [
    (10, 5),  # Case: fetch_limit > available alerts
    (3, 3)  # Case: fetch_limit < available alerts
])
def test_fetch_alert_type(mocker, fetch_limit, expected_alert_count):
    from MongoDBAtlas import fetch_alert_type, Client
    mocked_alerts = util_load_json('test_data/raw_alerts_page_1.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)

    client = Client(base_url=MOCK_BASEURL, verify=False, group_id=MOCK_GROUP_ID, private_key=MOCK_PRIVATE_KEY,
                    public_key=MOCK_PUBLIC_KEY)
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
    from MongoDBAtlas import fetch_alert_type, Client

    mocked_alerts_page_1 = util_load_json('test_data/raw_alerts_page_1.json')
    mocked_alerts_page_2 = util_load_json('test_data/raw_alerts_page_2.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts_page_1)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=True)
    mocker.patch('MongoDBAtlas.Client.get_response_from_page_link', return_value=mocked_alerts_page_2)

    client = Client(
        base_url=MOCK_BASEURL, verify=False,
        group_id=MOCK_GROUP_ID, private_key=MOCK_PRIVATE_KEY,
        public_key=MOCK_PUBLIC_KEY
    )
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
    from MongoDBAtlas import fetch_alert_type, Client

    mocked_alerts_page_1 = util_load_json('test_data/raw_alerts_page_1.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts_page_1)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=False)

    client = Client(
        base_url=MOCK_BASEURL, verify=False,
        group_id=MOCK_GROUP_ID, private_key=MOCK_PRIVATE_KEY,
        public_key=MOCK_PUBLIC_KEY
    )

    last_run = {"page_link": None, "last_page_alerts_ids": []}

    output, last_run_new_dict = fetch_alert_type(
        client, len(mocked_alerts_page_1.get('results')), last_run
    )

    assert len(output) == len(mocked_alerts_page_1.get('results'))
    assert last_run_new_dict.get('page_link') == 'self1'

    mocked_alerts_page_1_with_more_alerts = util_load_json('test_data/raw_alerts_page_1_with_more_alerts.json')
    mocker.patch('MongoDBAtlas.get_page_from_last_run_for_alerts', return_value=mocked_alerts_page_1_with_more_alerts)

    last_run = copy.deepcopy(last_run_new_dict)
    additional_alerts_amount = (
        len(mocked_alerts_page_1_with_more_alerts.get('results')) -
        len(mocked_alerts_page_1.get('results'))
    )
    output, last_run_new_dict = fetch_alert_type(client, additional_alerts_amount, last_run)
    assert len(output) == additional_alerts_amount

    expected_ids = [str(i) for i in range(1, 9)]
    last_page_alerts_ids = last_run_new_dict.get('last_page_alerts_ids')

    assert set(last_page_alerts_ids) == set(expected_ids)

@pytest.mark.parametrize("fetch_limit, expected_event_count", [
    (12, 11),  # Case: fetch_limit > available alerts
    (8, 8)  # Case: fetch_limit < available alerts
])
def test_fetch_event_type(mocker, fetch_limit, expected_event_count):
    from MongoDBAtlas import fetch_event_type, Client

    mocked_events_page_1 = util_load_json('test_data/raw_events_page_1.json')
    mocker.patch('MongoDBAtlas.Client.get_events_with_min_time', return_value=mocked_events_page_1)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)

    client = Client(
        base_url=MOCK_BASEURL, verify=False,
        group_id=MOCK_GROUP_ID, private_key=MOCK_PRIVATE_KEY,
        public_key=MOCK_PUBLIC_KEY
    )

    last_run = {"min_time": "2024-11-05T11:10:01Z", "events_with_created_min_time": []}

    output, last_run_new_dict = fetch_event_type(
        client, fetch_limit, last_run
    )

    assert len(output) == expected_event_count
    assert last_run_new_dict.get('min_time') is output[expected_event_count-1].get('created')


def test_fetch_event_type_min_time_repeat(mocker):
    """
    Test fetching events with the same min_time across following fetches.

    Verifies that:
    - The first fetch retrieves events up to `min_time`.
    - The second fetch avoids duplicating events from the first.
    - The final `min_time` advances correctly after both fetches.
    """

    from MongoDBAtlas import fetch_event_type, Client
    raw_events_page_duplicated_dates = util_load_json('test_data/raw_events_page_duplicated_dates.json')
    mocker.patch('MongoDBAtlas.Client.get_events_with_min_time', return_value=raw_events_page_duplicated_dates)
    mocker.patch('MongoDBAtlas.get_next_url', return_value=None)

    client = Client(
        base_url=MOCK_BASEURL, verify=False,
        group_id=MOCK_GROUP_ID, private_key=MOCK_PRIVATE_KEY,
        public_key=MOCK_PUBLIC_KEY
    )

    last_run = {"min_time": "2024-11-05T11:10:01Z", "events_with_created_min_time": []}

    output, last_run_new_dict = fetch_event_type(
        client, 4, last_run
    )

    events_with_created_min_time = last_run_new_dict.get('events_with_created_min_time')
    min_time = last_run_new_dict.get('min_time')

    assert len(output) == 4
    assert min_time is "2024-11-05T11:10:01Z"

    first_fetch_events_with_created_min_time = copy.deepcopy(events_with_created_min_time)

    last_run = {"min_time": min_time, "events_with_created_min_time": events_with_created_min_time}
    output, last_run_new_dict = fetch_event_type(
        client, 10, last_run
    )

    events_with_created_min_time = last_run_new_dict.get('events_with_created_min_time')
    min_time = last_run_new_dict.get('min_time')

    assert len(output) == 10
    assert min_time == "2024-11-07T09:32:40Z"
    for event_id in first_fetch_events_with_created_min_time:
        for event in output:
            assert event_id != event.get('id')

