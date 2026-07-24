# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Cloudflare Access Authentication Logs Event Collector."""
import CloudflareAccessAuthLogsEventCollector as collector


class MockClient:
    """Serves canned Access-log pages keyed by the ``since`` cursor."""

    def __init__(self, pages_by_since):
        self.pages = pages_by_since
        self.calls = 0

    def get_access_logs(self, account_id, since, until, limit=1000, direction="asc"):
        self.calls += 1
        return {"result": self.pages.get(since, []), "success": True}


def _rec(ray_id, created_at, **kw):
    r = {"ray_id": ray_id, "created_at": created_at, "user_email": "u@x.com",
         "ip_address": "1.2.3.4", "allowed": True, "app_domain": "app.x.com"}
    r.update(kw)
    return r


def test_dedup_computes_cursor_and_boundary_ids():
    events = [
        _rec("a", "2026-07-20T10:00:00Z"),
        _rec("b", "2026-07-20T11:00:00Z"),
        _rec("c", "2026-07-20T11:00:00Z"),
    ]
    new, ts, ids = collector.dedup_events(events, set())
    assert ts == "2026-07-20T11:00:00Z"
    assert ids == {"b", "c"}
    assert len(new) == 3


def test_dedup_drops_seen_boundary_ray_ids():
    events = [_rec("b", "2026-07-20T11:00:00Z"), _rec("d", "2026-07-20T12:00:00Z")]
    new, ts, ids = collector.dedup_events(events, {"b"})
    assert [e["ray_id"] for e in new] == ["d"]
    assert ts == "2026-07-20T12:00:00Z"
    assert ids == {"d"}


def test_metadata_added():
    pages = {"2026-07-19T00:00:00Z": [_rec("a", "2026-07-20T10:00:00Z")]}
    client = MockClient(pages)
    events, ts, ids = collector.fetch_access_logs_for_account(
        client, "acc-1", "2026-07-19T00:00:00Z", "2026-07-21T00:00:00Z", 100, set())
    e = events[0]
    assert e["_time"] == "2026-07-20T10:00:00Z"
    assert e["source_log_type"] == "access_auth"
    assert e["cloudflare_account_id"] == "acc-1"


def test_single_page_stops_when_below_limit():
    pages = {"s": [_rec(str(i), f"2026-07-20T10:0{i}:00Z") for i in range(3)]}
    client = MockClient(pages)
    events, ts, ids = collector.fetch_access_logs_for_account(client, "a", "s", "u", 100, set())
    assert client.calls == 1  # got 3 < limit -> stop
    assert len(events) == 3


def test_advances_window_when_full_page():
    # first window returns a full page (limit reached), then the newest ts window returns the rest
    pages = {
        "s": [_rec(str(i), f"2026-07-20T10:0{i}:00Z") for i in range(2)],  # 2 == limit
        "2026-07-20T10:01:00Z": [_rec("x", "2026-07-20T10:05:00Z")],
    }
    client = MockClient(pages)
    events, ts, ids = collector.fetch_access_logs_for_account(client, "a", "s", "u", 2, set())
    # capped at max_fetch=2
    assert len(events) == 2


def test_fetch_events_keeps_cursor_when_empty():
    client = MockClient({})
    last_run = {"acc-1": {"last_ts": "2026-07-20T09:00:00Z", "last_ids": ["z"]}}
    events, run = collector.fetch_events(client, ["acc-1"], last_run, "3 days", 100)
    assert events == []
    assert run["acc-1"]["last_ts"] == "2026-07-20T09:00:00Z"
    assert run["acc-1"]["last_ids"] == ["z"]
