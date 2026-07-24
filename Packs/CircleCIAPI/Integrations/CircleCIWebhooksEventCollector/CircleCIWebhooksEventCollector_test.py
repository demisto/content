# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Webhooks Event Collector."""
import CircleCIWebhooksEventCollector as collector


class MockClient:
    def __init__(self, pages_by_project):
        self.pages = pages_by_project
        self.calls = 0

    def list_webhooks(self, project_id, page_token=None):
        self.calls += 1
        return self.pages[project_id][page_token or "first"]


def _webhook(wid, name="hook", url="https://example.com/hook"):
    return {
        "id": wid,
        "name": name,
        "url": url,
        "verify_tls": True,
        "events": ["workflow-completed"],
        "created_at": "2026-07-20T10:00:00Z",
        "updated_at": "2026-07-20T10:00:00Z",
    }


def test_snapshot_collects_all_projects_with_metadata():
    pages = {
        "p1": {"first": {"items": [_webhook("w1"), _webhook("w2")], "next_page_token": None}},
        "p2": {"first": {"items": [], "next_page_token": None}},
    }
    client = MockClient(pages)
    events = collector.fetch_events(client, ["p1", "p2"], 100)
    assert len(events) == 2
    assert all(e["source_log_type"] == "webhook" for e in events)
    assert all(e["circleci_project_id"] == "p1" for e in events)
    assert all(e["_time"] == e["snapshot_at"] for e in events)


def test_pagination_follows_next_page_token():
    pages = {
        "p1": {
            "first": {"items": [_webhook("w1")], "next_page_token": "t2"},
            "t2": {"items": [_webhook("w2")], "next_page_token": None},
        }
    }
    client = MockClient(pages)
    events = collector.fetch_events(client, ["p1"], 100)
    assert [e["id"] for e in events] == ["w1", "w2"]
    assert client.calls == 2


def test_max_fetch_caps_collection():
    pages = {
        "p1": {"first": {"items": [_webhook(f"w{i}") for i in range(5)], "next_page_token": None}}
    }
    client = MockClient(pages)
    events = collector.fetch_events(client, ["p1"], 3)
    assert len(events) == 3


def test_empty_inventory_returns_empty_list():
    pages = {"p1": {"first": {"items": [], "next_page_token": None}}}
    client = MockClient(pages)
    assert collector.fetch_events(client, ["p1"], 100) == []


class MockDiscoveryClient:
    """Serves pipeline pages and project lookups for discovery tests."""

    def __init__(self, pipeline_pages, projects):
        self.pipeline_pages = pipeline_pages
        self.projects = projects
        self.project_calls = 0

    def list_pipelines(self, org_slug, page_token=None):
        return self.pipeline_pages[page_token or "first"]

    def get_project(self, project_slug):
        self.project_calls += 1
        return self.projects[project_slug]


def test_discovery_resolves_distinct_project_slugs():
    pipeline_pages = {
        "first": {
            "items": [
                {"id": "1", "project_slug": "org/proj-a"},
                {"id": "2", "project_slug": "org/proj-b"},
                {"id": "3", "project_slug": "org/proj-a"},
            ],
            "next_page_token": None,
        }
    }
    projects = {"org/proj-a": {"id": "uuid-a"}, "org/proj-b": {"id": "uuid-b"}}
    client = MockDiscoveryClient(pipeline_pages, projects)
    ids, cache = collector.discover_project_ids(client, ["org"], {})
    assert sorted(ids) == ["uuid-a", "uuid-b"]
    assert cache == {"org/proj-a": "uuid-a", "org/proj-b": "uuid-b"}
    assert client.project_calls == 2


def test_discovery_uses_slug_cache():
    pipeline_pages = {
        "first": {
            "items": [{"id": "1", "project_slug": "org/proj-a"}],
            "next_page_token": None,
        }
    }
    client = MockDiscoveryClient(pipeline_pages, {})
    ids, _ = collector.discover_project_ids(client, ["org"], {"org/proj-a": "uuid-a"})
    assert ids == ["uuid-a"]
    assert client.project_calls == 0  # cache hit, no /project lookup


def test_resolve_unions_explicit_and_discovered_ids():
    pipeline_pages = {
        "first": {
            "items": [{"id": "1", "project_slug": "org/proj-a"}],
            "next_page_token": None,
        }
    }
    projects = {"org/proj-a": {"id": "uuid-a"}}
    client = MockDiscoveryClient(pipeline_pages, projects)
    ids, _ = collector.resolve_project_ids(client, ["uuid-x", "uuid-a"], ["org"], {})
    assert ids == ["uuid-x", "uuid-a"]  # no duplicate uuid-a
