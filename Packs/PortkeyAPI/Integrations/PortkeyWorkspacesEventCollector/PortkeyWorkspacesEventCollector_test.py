# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Portkey Workspaces Event Collector."""

import PortkeyWorkspacesEventCollector as collector


class MockClient:
    """Serves canned pages keyed by the zero-based page number."""

    def __init__(self, pages, total=None):
        self.pages = pages
        self.total = total
        self.requested_pages = []

    def list_workspaces(self, current_page=0, page_size=100):
        self.requested_pages.append(current_page)
        records = self.pages.get(current_page, [])
        return {"data": records, "total": self.total if self.total is not None else len(records)}


def _workspace(wid, settings=None, **kw):
    r = {
        "id": wid,
        "slug": f"ws-{wid}",
        "name": f"Workspace {wid}",
        "usage_limits": None,
        "rate_limits": None,
        "security_settings": settings if settings is not None else {"membersWriteApiKeys": False},
    }
    r.update(kw)
    return r


def test_paging_starts_at_page_zero():
    client = MockClient({0: [_workspace("a")]})
    events = collector.fetch_events(client, 100)
    assert client.requested_pages[0] == 0
    assert [e["id"] for e in events] == ["a"]


def test_paging_stops_on_empty_page_not_on_total():
    """total stays populated past the last page, so an empty page is the terminator."""
    pages = {0: [_workspace(str(i)) for i in range(3)], 1: []}
    client = MockClient(pages, total=99)
    events = collector.fetch_events(client, 100, page_size=3)
    assert client.requested_pages == [0, 1]
    assert len(events) == 3


def test_security_settings_flattened_to_top_level():
    settings = {
        "membersWriteApiKeys": True,
        "membersWriteGuardrails": False,
        "membersViewAllData": True,
        "managersWriteConfigs": True,
    }
    event = collector.build_workspace_event(_workspace("a", settings), "2026-07-25T00:00:00Z")
    assert event["membersWriteApiKeys"] is True
    assert event["membersWriteGuardrails"] is False
    assert event["membersViewAllData"] is True
    assert event["managersWriteConfigs"] is True
    # The nested object itself is not re-emitted.
    assert "security_settings" not in event


def test_member_write_permission_count_counts_only_member_writes():
    settings = {
        "membersWriteApiKeys": True,
        "membersWriteConfigs": True,
        "membersWriteGuardrails": False,
        "membersViewAllData": True,
        "managersWriteConfigs": True,
    }
    event = collector.build_workspace_event(_workspace("a", settings), "2026-07-25T00:00:00Z")
    # Two member write permissions are granted; views and manager writes do not count.
    assert event["member_write_permission_count"] == 2


def test_limits_presence_flattened():
    with_limits = _workspace("a", usage_limits={"credit_limit": 5}, rate_limits=[{"value": 10}])
    event = collector.build_workspace_event(with_limits, "2026-07-25T00:00:00Z")
    assert event["has_usage_limits"] is True
    assert event["has_rate_limits"] is True

    event_without = collector.build_workspace_event(_workspace("b"), "2026-07-25T00:00:00Z")
    assert event_without["has_usage_limits"] is False
    assert event_without["has_rate_limits"] is False


def test_ingestion_metadata_added():
    event = collector.build_workspace_event(_workspace("a"), "2026-07-25T00:00:00Z")
    assert event["_time"] == "2026-07-25T00:00:00Z"
    assert event["snapshot_at"] == "2026-07-25T00:00:00Z"
    assert event["source_log_type"] == "workspace_posture"


def test_empty_inventory_returns_no_events():
    client = MockClient({0: []}, total=0)
    assert collector.fetch_events(client, 100) == []
