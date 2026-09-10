# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Contexts Event Collector."""

import CircleCIContextsEventCollector as collector


class MockClient:
    def __init__(self, context_pages, envvar_pages, restriction_pages=None):
        self.context_pages = context_pages
        self.envvar_pages = envvar_pages
        # Default to no restrictions, which is both the common real case and the
        # one worth detecting: an unrestricted context is readable by every
        # project in the organisation.
        self.restriction_pages = restriction_pages or {}
        self.calls = 0

    def list_contexts(self, owner_slug, page_token=None):
        self.calls += 1
        return self.context_pages[page_token or "first"]

    def list_context_envvars(self, context_id, page_token=None):
        return self.envvar_pages[context_id][page_token or "first"]

    def list_context_restrictions(self, context_id, page_token=None):
        pages = self.restriction_pages.get(context_id)
        if not pages:
            return {"items": [], "next_page_token": None}
        return pages[page_token or "first"]


def _context(cid, name):
    return {"id": cid, "name": name, "created_at": "2026-07-23T01:00:00Z"}


def _envvar(variable):
    return {"variable": variable, "created_at": "2026-07-23T02:00:00Z", "updated_at": "2026-07-23T02:00:00Z"}


def test_emits_context_and_envvar_records():
    contexts = {"first": {"items": [_context("c1", "deploy")], "next_page_token": None}}
    envvars = {"c1": {"first": {"items": [_envvar("AWS_KEY"), _envvar("AWS_SECRET")], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 100)
    assert len(events) == 4  # 1 context + 2 env vars + 1 unrestricted marker
    ctx = [e for e in events if e["source_log_type"] == "context"]
    var = [e for e in events if e["source_log_type"] == "context_envvar"]
    assert len(ctx) == 1
    assert len(var) == 2
    assert ctx[0]["name"] == "deploy"
    assert all(e["context_name"] == "deploy" for e in var)
    assert all(e["circleci_org_slug"] == "org" for e in events)
    assert all(e["_time"] == e["snapshot_at"] for e in events)
    assert {e["variable"] for e in var} == {"AWS_KEY", "AWS_SECRET"}


def test_empty_context_still_emits_context_record():
    contexts = {"first": {"items": [_context("c1", "empty")], "next_page_token": None}}
    envvars = {"c1": {"first": {"items": [], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 100)
    # A context with no variables still produces its own record, and now also an
    # unrestricted marker, so assert on the record type rather than the total.
    ctx = [e for e in events if e["source_log_type"] == "context"]
    assert len(ctx) == 1
    assert ctx[0]["name"] == "empty"


def test_context_pagination():
    contexts = {
        "first": {"items": [_context("c1", "a")], "next_page_token": "t2"},
        "t2": {"items": [_context("c2", "b")], "next_page_token": None},
    }
    envvars = {
        "c1": {"first": {"items": [], "next_page_token": None}},
        "c2": {"first": {"items": [], "next_page_token": None}},
    }
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 100)
    ctx = [e for e in events if e["source_log_type"] == "context"]
    assert [e["name"] for e in ctx] == ["a", "b"]


def test_envvar_pagination():
    contexts = {"first": {"items": [_context("c1", "deploy")], "next_page_token": None}}
    envvars = {
        "c1": {
            "first": {"items": [_envvar("A")], "next_page_token": "n2"},
            "n2": {"items": [_envvar("B")], "next_page_token": None},
        }
    }
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 100)
    variables = [e["variable"] for e in events if e["source_log_type"] == "context_envvar"]
    assert variables == ["A", "B"]


def test_max_fetch_caps_total_records():
    contexts = {"first": {"items": [_context("c1", "deploy")], "next_page_token": None}}
    envvars = {"c1": {"first": {"items": [_envvar(f"V{i}") for i in range(10)], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 4)
    assert len(events) == 4  # 1 context + 3 env vars, capped


def _restriction(rid, rtype, value):
    return {"id": rid, "restriction_type": rtype, "restriction_value": value, "project_id": "p1"}


def test_a_context_with_no_restrictions_is_recorded_as_unrestricted():
    """The absence of restrictions is the finding, so it must produce a record.

    A context with no restrictions is readable by every project in the
    organisation. If that were represented by simply emitting nothing, no rule
    could detect it, because a rule cannot see rows it never receives.
    """
    contexts = {"first": {"items": [_context("c1", "deploy")], "next_page_token": None}}
    envvars = {"c1": {"first": {"items": [], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 100)

    marker = [e for e in events if e["source_log_type"] == "context_restriction"]
    assert len(marker) == 1
    assert marker[0]["is_restricted"] is False
    assert marker[0]["restriction_type"] == "none"
    assert marker[0]["context_id"] == "c1"
    assert marker[0]["context_name"] == "deploy"


def test_restrictions_are_emitted_one_record_each():
    contexts = {"first": {"items": [_context("c1", "deploy")], "next_page_token": None}}
    envvars = {"c1": {"first": {"items": [], "next_page_token": None}}}
    restrictions = {
        "c1": {
            "first": {
                "items": [
                    _restriction("r1", "project", "proj-a"),
                    _restriction("r2", "project", "proj-b"),
                ],
                "next_page_token": None,
            }
        }
    }
    events = collector.fetch_events(MockClient(contexts, envvars, restrictions), ["org"], 100)

    recs = [e for e in events if e["source_log_type"] == "context_restriction"]
    assert len(recs) == 2
    assert all(e["is_restricted"] is True for e in recs)
    assert {e["restriction_value"] for e in recs} == {"proj-a", "proj-b"}
    assert all(e["context_name"] == "deploy" for e in recs)
    # the unrestricted marker must NOT also be emitted
    assert not any(e.get("restriction_type") == "none" for e in recs)
