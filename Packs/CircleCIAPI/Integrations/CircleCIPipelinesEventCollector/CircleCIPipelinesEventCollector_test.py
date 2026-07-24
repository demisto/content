# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Pipelines Event Collector."""
import CircleCIPipelinesEventCollector as collector


class MockClient:
    """Serves canned newest-first pages keyed by page token."""

    def __init__(self, pages):
        self.pages = pages
        self.calls = 0

    def list_pipelines(self, org_slug, page_token=None):
        self.calls += 1
        return self.pages[page_token or "first"]


def _pipeline(pid, created_at):
    return {"id": pid, "created_at": created_at, "project_slug": "circleci/org/proj", "state": "created"}


def test_first_fetch_collects_within_window():
    pages = {
        "first": {
            "items": [
                _pipeline("c", "2026-07-20T12:00:00.000Z"),
                _pipeline("b", "2026-07-20T11:00:00.000Z"),
                _pipeline("a", "2026-07-01T00:00:00.000Z"),  # outside window
            ],
            "next_page_token": None,
        }
    }
    client = MockClient(pages)
    cutoff = collector._parse_ts("2026-07-19T00:00:00Z")
    events, new_ts, new_ids = collector.fetch_pipelines_for_org(client, "org", cutoff, set(), 100)
    assert [e["id"] for e in events] == ["c", "b"]
    assert new_ts == "2026-07-20T12:00:00.000Z"
    assert new_ids == {"c"}
    assert events[0]["_time"] == "2026-07-20T12:00:00.000Z"
    assert events[0]["source_log_type"] == "pipeline"
    assert events[0]["circleci_org_slug"] == "org"


def test_incremental_fetch_stops_at_high_water_mark():
    pages = {
        "first": {
            "items": [
                _pipeline("d", "2026-07-20T13:00:00.000Z"),
                _pipeline("c", "2026-07-20T12:00:00.000Z"),  # boundary, already seen
                _pipeline("b", "2026-07-20T11:00:00.000Z"),  # below mark
            ],
            "next_page_token": "t2",
        },
        "t2": {"items": [_pipeline("a", "2026-07-01T00:00:00.000Z")], "next_page_token": None},
    }
    client = MockClient(pages)
    cutoff = collector._parse_ts("2026-07-20T12:00:00.000Z")
    events, new_ts, new_ids = collector.fetch_pipelines_for_org(client, "org", cutoff, {"c"}, 100)
    assert [e["id"] for e in events] == ["d"]
    assert new_ts == "2026-07-20T13:00:00.000Z"
    assert new_ids == {"d"}
    assert client.calls == 1  # never paged past the mark


def test_pagination_follows_next_page_token():
    pages = {
        "first": {
            "items": [_pipeline("d", "2026-07-20T13:00:00.000Z")],
            "next_page_token": "t2",
        },
        "t2": {
            "items": [_pipeline("c", "2026-07-20T12:00:00.000Z")],
            "next_page_token": None,
        },
    }
    client = MockClient(pages)
    cutoff = collector._parse_ts("2026-07-19T00:00:00Z")
    events, _, _ = collector.fetch_pipelines_for_org(client, "org", cutoff, set(), 100)
    assert [e["id"] for e in events] == ["d", "c"]
    assert client.calls == 2


def test_max_fetch_caps_collection():
    pages = {
        "first": {
            "items": [
                _pipeline("d", "2026-07-20T13:00:00.000Z"),
                _pipeline("c", "2026-07-20T12:00:00.000Z"),
                _pipeline("b", "2026-07-20T11:00:00.000Z"),
            ],
            "next_page_token": None,
        }
    }
    client = MockClient(pages)
    cutoff = collector._parse_ts("2026-07-19T00:00:00Z")
    events, _, _ = collector.fetch_pipelines_for_org(client, "org", cutoff, set(), 2)
    assert len(events) == 2


def test_fetch_events_keeps_cursor_when_nothing_new():
    pages = {"first": {"items": [], "next_page_token": None}}
    client = MockClient(pages)
    last_run = {"org": {"last_ts": "2026-07-20T13:00:00.000Z", "last_ids": ["d"]}}
    events, next_run = collector.fetch_events(client, ["org"], last_run, "3 days", 100)
    assert events == []
    assert next_run["org"]["last_ts"] == "2026-07-20T13:00:00.000Z"
    assert next_run["org"]["last_ids"] == ["d"]


def test_fetch_events_isolates_per_org_state():
    pages = {
        "first": {
            "items": [_pipeline("x", "2026-07-20T14:00:00.000Z")],
            "next_page_token": None,
        }
    }
    client = MockClient(pages)
    last_run = {"org1": {"last_ts": "2026-07-20T13:00:00.000Z", "last_ids": ["d"]}}
    events, next_run = collector.fetch_events(client, ["org1", "org2"], last_run, "3 days", 100)
    assert len(events) == 2  # one per org
    assert set(next_run.keys()) == {"org1", "org2"}
    assert next_run["org1"]["last_ts"] == "2026-07-20T14:00:00.000Z"
