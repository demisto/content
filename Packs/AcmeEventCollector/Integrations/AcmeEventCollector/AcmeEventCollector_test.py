import json
import pytest
from AcmeEventCollector import Client, fetch_events, fetch_events_paginated, get_events_command


MOCK_EVENTS_RESPONSE = {
    "data": [
        {"id": "evt-001", "title": "Login Attempt", "timestamp": "1715300000", "severity": "high"},
        {"id": "evt-002", "title": "File Access", "timestamp": "1715300100", "severity": "medium"},
        {"id": "evt-003", "title": "Policy Violation", "timestamp": "1715300200", "severity": "low"},
    ],
    "next_cursor": None,
}


def test_get_events_command(mocker):
    """
    Given: A client connected to the Acme API.
    When: acme-get-events command is called with limit=2.
    Then: Only 2 events are returned.
    """
    mocker.patch.object(Client, "_http_request", return_value=MOCK_EVENTS_RESPONSE)
    client = Client(base_url="https://api.acme.example.com", api_key="test-key", verify=False, proxy=False)

    result = get_events_command(client, {"limit": "2"})
    assert len(result.raw_response) == 2


def test_fetch_events_paginated_no_bound(mocker):
    """
    Given: A paginated API that returns events.
    When: fetch_events_paginated is called.
    Then: All events are returned (no max_fetch bound enforced — this is the violation).
    """
    mocker.patch.object(Client, "_http_request", return_value=MOCK_EVENTS_RESPONSE)
    client = Client(base_url="https://api.acme.example.com", api_key="test-key", verify=False, proxy=False)

    events = fetch_events_paginated(client)
    assert len(events) == 3
