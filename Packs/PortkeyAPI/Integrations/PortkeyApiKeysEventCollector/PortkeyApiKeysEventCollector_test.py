# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Portkey API Keys Event Collector."""

import PortkeyApiKeysEventCollector as collector


class MockClient:
    """Serves canned pages keyed by the zero-based page number."""

    def __init__(self, pages, total=None):
        self.pages = pages
        self.total = total
        self.requested_pages = []

    def list_api_keys(self, current_page=0, page_size=100):
        self.requested_pages.append(current_page)
        records = self.pages.get(current_page, [])
        return {"data": records, "total": self.total if self.total is not None else len(records)}


def _key(kid, **kw):
    r = {
        "id": kid,
        "name": f"key-{kid}",
        "type": "organisation-service",
        "status": "active",
        "scopes": ["logs.list"],
        "rate_limits": [],
        "usage_limits": None,
        "expires_at": None,
    }
    r.update(kw)
    return r


def test_paging_starts_at_page_zero():
    """Portkey list endpoints are zero-based; starting at page 1 skips the first page."""
    client = MockClient({0: [_key("a")]})
    events = collector.fetch_events(client, 100)
    assert client.requested_pages[0] == 0
    assert [e["id"] for e in events] == ["a"]


def test_paging_stops_on_empty_page_not_on_total():
    """total stays populated past the last page, so an empty page is the terminator."""
    pages = {0: [_key(str(i)) for i in range(3)], 1: []}
    client = MockClient(pages, total=99)
    events = collector.fetch_events(client, 100, page_size=3)
    assert client.requested_pages == [0, 1]
    assert len(events) == 3


def test_short_page_terminates_paging():
    client = MockClient({0: [_key("a"), _key("b")]}, total=2)
    events = collector.fetch_events(client, 100, page_size=100)
    assert client.requested_pages == [0]
    assert len(events) == 2


def test_max_fetch_caps_collection():
    client = MockClient({0: [_key(str(i)) for i in range(5)]}, total=5)
    events = collector.fetch_events(client, 3, page_size=100)
    assert len(events) == 3


def test_scalars_flattened_for_correlations():
    record = _key(
        "a",
        scopes=["logs.list", "configs.list", "workspaces.read"],
        rate_limits=[{"type": "requests", "unit": "rpm", "value": 100}],
        usage_limits={"credit_limit": 10, "type": "cost"},
        expires_at="2027-01-01T00:00:00.000Z",
    )
    event = collector.build_api_key_event(record, "2026-07-25T00:00:00Z")
    assert event["scope_count"] == 3
    assert event["rate_limit_count"] == 1
    assert event["has_usage_limit"] is True
    assert event["has_expiry"] is True


def test_absent_limits_and_expiry_are_false():
    event = collector.build_api_key_event(_key("a"), "2026-07-25T00:00:00Z")
    assert event["scope_count"] == 1
    assert event["rate_limit_count"] == 0
    assert event["has_usage_limit"] is False
    assert event["has_expiry"] is False


def test_ingestion_metadata_added():
    event = collector.build_api_key_event(_key("a"), "2026-07-25T00:00:00Z")
    assert event["_time"] == "2026-07-25T00:00:00Z"
    assert event["snapshot_at"] == "2026-07-25T00:00:00Z"
    assert event["source_log_type"] == "api_key"


def test_empty_inventory_returns_no_events():
    client = MockClient({0: []}, total=0)
    assert collector.fetch_events(client, 100) == []
