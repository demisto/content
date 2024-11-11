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

DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


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



