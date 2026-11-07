# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Checkout Keys Event Collector."""

import CircleCICheckoutKeysEventCollector as collector


class MockClient:
    def __init__(self, key_pages, pipeline_pages=None):
        self.key_pages = key_pages
        self.pipeline_pages = pipeline_pages or {}
        self.calls = 0

    def list_checkout_keys(self, project_slug, page_token=None):
        self.calls += 1
        return self.key_pages[project_slug][page_token or "first"]

    def list_pipelines(self, org_slug, page_token=None):
        return self.pipeline_pages[page_token or "first"]


def _key(fp, ktype="deploy-key"):
    return {
        "public-key": "ssh-rsa AAAA",
        "type": ktype,
        "fingerprint": fp,
        "preferred": True,
        "created-at": "2026-07-23T10:00:00Z",
    }


def test_snapshot_normalises_keys_and_adds_metadata():
    pages = {"org/proj": {"first": {"items": [_key("aa:bb")], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(pages), ["org/proj"], 100)
    assert len(events) == 1
    e = events[0]
    assert e["public_key"] == "ssh-rsa AAAA"
    assert "public-key" not in e
    assert e["created_at"] == "2026-07-23T10:00:00Z"
    assert "created-at" not in e
    assert e["source_log_type"] == "checkout_key"
    assert e["circleci_project_slug"] == "org/proj"
    assert e["_time"] == e["snapshot_at"]


def test_pagination():
    pages = {
        "org/proj": {
            "first": {"items": [_key("a")], "next_page_token": "t2"},
            "t2": {"items": [_key("b")], "next_page_token": None},
        }
    }
    c = MockClient(pages)
    assert [e["fingerprint"] for e in collector.fetch_events(c, ["org/proj"], 100)] == ["a", "b"]
    assert c.calls == 2


def test_max_fetch_caps():
    pages = {"org/proj": {"first": {"items": [_key(f"k{i}") for i in range(5)], "next_page_token": None}}}
    assert len(collector.fetch_events(MockClient(pages), ["org/proj"], 3)) == 3


def test_discovery_distinct_sorted():
    pp = {
        "first": {
            "items": [{"id": "1", "project_slug": "org/b"}, {"id": "2", "project_slug": "org/a"}],
            "next_page_token": None,
        }
    }
    assert collector.discover_project_slugs(MockClient({}, pp), ["org"]) == ["org/a", "org/b"]


def test_resolve_unions():
    pp = {"first": {"items": [{"id": "1", "project_slug": "org/a"}], "next_page_token": None}}
    assert collector.resolve_project_slugs(MockClient({}, pp), ["org/x", "org/a"], ["org"]) == ["org/x", "org/a"]


def test_empty_returns_empty():
    pages = {"org/proj": {"first": {"items": [], "next_page_token": None}}}
    assert collector.fetch_events(MockClient(pages), ["org/proj"], 100) == []
