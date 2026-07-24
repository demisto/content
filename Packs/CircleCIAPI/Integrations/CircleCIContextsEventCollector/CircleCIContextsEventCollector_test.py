# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Contexts Event Collector."""

import CircleCIContextsEventCollector as collector


class MockClient:
    def __init__(self, context_pages, envvar_pages):
        self.context_pages = context_pages
        self.envvar_pages = envvar_pages
        self.calls = 0

    def list_contexts(self, owner_slug, page_token=None):
        self.calls += 1
        return self.context_pages[page_token or "first"]

    def list_context_envvars(self, context_id, page_token=None):
        return self.envvar_pages[context_id][page_token or "first"]


def _context(cid, name):
    return {"id": cid, "name": name, "created_at": "2026-07-23T01:00:00Z"}


def _envvar(variable):
    return {"variable": variable, "created_at": "2026-07-23T02:00:00Z", "updated_at": "2026-07-23T02:00:00Z"}


def test_emits_context_and_envvar_records():
    contexts = {"first": {"items": [_context("c1", "deploy")], "next_page_token": None}}
    envvars = {"c1": {"first": {"items": [_envvar("AWS_KEY"), _envvar("AWS_SECRET")], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(contexts, envvars), ["org"], 100)
    assert len(events) == 3  # 1 context + 2 env vars
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
    assert len(events) == 1
    assert events[0]["source_log_type"] == "context"


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
    assert [e["name"] for e in events] == ["a", "b"]


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
