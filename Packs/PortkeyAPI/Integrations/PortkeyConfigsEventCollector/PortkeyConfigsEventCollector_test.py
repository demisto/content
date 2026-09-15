# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Portkey Configs Event Collector."""

import PortkeyConfigsEventCollector as collector


class MockClient:
    """Returns the full config list on every call, as the real endpoint does."""

    def __init__(self, records, total=None):
        self.records = records
        self.total = total
        self.calls = 0

    def list_configs(self):
        self.calls += 1
        return {"data": self.records, "total": self.total if self.total is not None else len(self.records)}


def _config(cid, **kw):
    r = {
        "id": cid,
        "name": f"config-{cid}",
        "slug": f"pc-{cid}",
        "status": "active",
        "owner_id": "owner-1",
        "updated_by": "owner-1",
        "workspace_id": "ws-1",
    }
    r.update(kw)
    return r


def test_endpoint_is_requested_exactly_once():
    """GET /configs is not paginated and returns the same list for any page.

    Paging it would re-request identical records indefinitely, so the collector
    must issue a single request.
    """
    client = MockClient([_config("a"), _config("b")])
    events = collector.fetch_events(client, 100)
    assert client.calls == 1
    assert [e["id"] for e in events] == ["a", "b"]


def test_max_fetch_caps_collection():
    client = MockClient([_config(str(i)) for i in range(5)])
    events = collector.fetch_events(client, 3)
    assert len(events) == 3


def test_updated_by_owner_true_when_editor_is_owner():
    event = collector.build_config_event(_config("a"), "2026-07-25T00:00:00Z")
    assert event["updated_by_owner"] is True


def test_updated_by_owner_false_when_someone_else_edited():
    record = _config("a", updated_by="someone-else")
    event = collector.build_config_event(record, "2026-07-25T00:00:00Z")
    assert event["updated_by_owner"] is False


def test_updated_by_owner_false_when_owner_absent():
    record = _config("a", owner_id=None, updated_by=None)
    event = collector.build_config_event(record, "2026-07-25T00:00:00Z")
    assert event["updated_by_owner"] is False


def test_ingestion_metadata_added():
    event = collector.build_config_event(_config("a"), "2026-07-25T00:00:00Z")
    assert event["_time"] == "2026-07-25T00:00:00Z"
    assert event["snapshot_at"] == "2026-07-25T00:00:00Z"
    assert event["source_log_type"] == "config"


def test_empty_inventory_returns_no_events():
    client = MockClient([], total=0)
    assert collector.fetch_events(client, 100) == []
