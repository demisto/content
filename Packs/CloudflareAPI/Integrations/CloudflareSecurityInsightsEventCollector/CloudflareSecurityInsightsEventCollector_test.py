# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the Cloudflare Security Insights Event Collector."""

import copy

import CloudflareSecurityInsightsEventCollector as collector


class MockClient:
    """Serves canned pages of the Security Center insights endpoint.

    Each call returns freshly copied records, as a real HTTP response would,
    so a per-account mutation cannot leak between accounts through a shared
    dictionary.
    """

    def __init__(self, pages, total_pages=None, total_count=None):
        self.pages = pages
        self.total_pages = total_pages
        self.total_count = total_count
        self.requested = []

    def get_logs(self, url_suffix, params):
        self.requested.append((url_suffix, params.get("page"), params.get("per_page")))
        page = params.get("page", 1)
        issues = copy.deepcopy(self.pages.get(page, []))
        info = {}
        if self.total_pages is not None:
            info["total_pages"] = self.total_pages
        if self.total_count is not None:
            info["total_count"] = self.total_count
        return {"result": {"issues": issues}, "result_info": info}


def _issue(iid, **kw):
    r = {"id": iid, "issue_class": "insecure_setting", "severity": "High", "subject": "example.com"}
    r.update(kw)
    return r


def test_insights_are_collected_and_stamped():
    client = MockClient({1: [_issue("a"), _issue("b")]}, total_pages=1)
    events = collector.fetch_events(client, ["acct-1"], 5000)
    assert [e["id"] for e in events] == ["a", "b"]
    for e in events:
        assert e["source_log_type"] == "security_insight"
        assert e["cloudflare_account_id"] == "acct-1"
        # A snapshot source stamps its collection time.
        assert e["snapshot_at"]
        assert e["_time"]


def test_time_prefers_the_finding_timestamp():
    client = MockClient({1: [_issue("a", timestamp="2026-07-20T10:00:00Z")]}, total_pages=1)
    events = collector.fetch_events(client, ["acct-1"], 5000)
    assert events[0]["_time"] == "2026-07-20T10:00:00Z"


def test_time_falls_back_to_collection_time():
    client = MockClient({1: [_issue("a")]}, total_pages=1)
    events = collector.fetch_events(client, ["acct-1"], 5000)
    assert events[0]["_time"] == events[0]["snapshot_at"]


def test_pagination_uses_the_required_page_size():
    """The insights endpoint requires per_page to be a multiple of five."""
    client = MockClient({1: [_issue("a")]}, total_pages=1)
    collector.fetch_events(client, ["acct-1"], 5000)
    assert client.requested[0][2] == collector.INSIGHTS_PER_PAGE
    assert collector.INSIGHTS_PER_PAGE % 5 == 0


def test_paging_stops_at_total_pages():
    pages = {1: [_issue(str(i)) for i in range(25)], 2: [_issue("late")]}
    client = MockClient(pages, total_pages=1)
    events = collector.fetch_events(client, ["acct-1"], 5000)
    assert len(events) == 25
    assert len(client.requested) == 1


def test_multiple_accounts_are_tagged_separately():
    client = MockClient({1: [_issue("a")]}, total_pages=1)
    events = collector.fetch_events(client, ["acct-1", "acct-2"], 5000)
    assert {e["cloudflare_account_id"] for e in events} == {"acct-1", "acct-2"}


def test_empty_result_returns_no_events():
    client = MockClient({1: []}, total_pages=1)
    assert collector.fetch_events(client, ["acct-1"], 5000) == []
