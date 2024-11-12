"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

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
    assert last_run_new_dict.get('page_link') == 'self'
    last_page_alerts_ids = last_run_new_dict.get('last_page_alerts_ids')
    assert len(last_page_alerts_ids) == expected_alert_count
    for id in last_page_alerts_ids:
        assert int(id) <= expected_alert_count
