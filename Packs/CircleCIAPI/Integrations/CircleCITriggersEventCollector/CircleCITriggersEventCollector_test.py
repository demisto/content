# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Triggers Event Collector."""

import CircleCITriggersEventCollector as collector


class MockClient:
    def __init__(self, definitions_by_project, triggers_by_definition, pipeline_pages=None, projects=None):
        self.definitions = definitions_by_project
        self.triggers = triggers_by_definition
        self.pipeline_pages = pipeline_pages or {}
        self.projects = projects or {}
        self.project_calls = 0

    def list_pipeline_definitions(self, project_id, page_token=None):
        return self.definitions[project_id][page_token or "first"]

    def list_triggers(self, project_id, definition_id, page_token=None):
        return self.triggers[definition_id][page_token or "first"]

    def list_pipelines(self, org_slug, page_token=None):
        return self.pipeline_pages[page_token or "first"]

    def get_project(self, project_slug):
        self.project_calls += 1
        return self.projects[project_slug]


def _trigger(tid, name="push", provider="github_app"):
    return {
        "id": tid,
        "event_name": name,
        "description": name,
        "created_at": "2026-07-23T08:00:00.000Z",
        "event_source": {"provider": provider},
        "disabled": False,
    }


def test_snapshot_walks_definitions_and_stamps_metadata():
    defs = {"p1": {"first": {"items": [{"id": "d1", "name": "main config"}], "next_page_token": None}}}
    trigs = {"d1": {"first": {"items": [_trigger("t1"), _trigger("t2", "sched", "schedule")], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(defs, trigs), ["p1"], 100)
    assert len(events) == 2
    assert all(e["pipeline_definition_id"] == "d1" for e in events)
    assert all(e["pipeline_definition_name"] == "main config" for e in events)
    assert all(e["source_log_type"] == "trigger" for e in events)
    assert all(e["circleci_project_id"] == "p1" for e in events)
    assert all(e["_time"] == e["snapshot_at"] for e in events)


def test_pagination_on_both_levels():
    defs = {
        "p1": {
            "first": {"items": [{"id": "d1", "name": "a"}], "next_page_token": "t2"},
            "t2": {"items": [{"id": "d2", "name": "b"}], "next_page_token": None},
        }
    }
    trigs = {
        "d1": {
            "first": {"items": [_trigger("t1")], "next_page_token": "n2"},
            "n2": {"items": [_trigger("t2")], "next_page_token": None},
        },
        "d2": {"first": {"items": [_trigger("t3")], "next_page_token": None}},
    }
    events = collector.fetch_events(MockClient(defs, trigs), ["p1"], 100)
    assert [e["id"] for e in events] == ["t1", "t2", "t3"]


def test_max_fetch_caps_collection():
    defs = {"p1": {"first": {"items": [{"id": "d1", "name": "a"}], "next_page_token": None}}}
    trigs = {"d1": {"first": {"items": [_trigger(f"t{i}") for i in range(5)], "next_page_token": None}}}
    events = collector.fetch_events(MockClient(defs, trigs), ["p1"], 3)
    assert len(events) == 3


def test_discovery_resolves_and_caches():
    pipeline_pages = {"first": {"items": [{"id": "1", "project_slug": "org/a"}], "next_page_token": None}}
    projects = {"org/a": {"id": "uuid-a"}}
    client = MockClient({}, {}, pipeline_pages, projects)
    ids, cache = collector.discover_project_ids(client, ["org"], {})
    assert ids == ["uuid-a"]
    assert cache == {"org/a": "uuid-a"}
    ids2, _ = collector.discover_project_ids(client, ["org"], cache)
    assert ids2 == ["uuid-a"]
    assert client.project_calls == 1  # second pass cached


def test_empty_inventory_returns_empty_list():
    defs = {"p1": {"first": {"items": [], "next_page_token": None}}}
    assert collector.fetch_events(MockClient(defs, {}), ["p1"], 100) == []
