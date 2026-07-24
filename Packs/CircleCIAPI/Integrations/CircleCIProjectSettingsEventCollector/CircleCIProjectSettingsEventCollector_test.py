# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Unit tests for the CircleCI Project Settings Event Collector."""
import CircleCIProjectSettingsEventCollector as collector


class MockClient:
    def __init__(self, settings_by_slug, pipeline_pages=None):
        self.settings = settings_by_slug
        self.pipeline_pages = pipeline_pages or {}
        self.settings_calls = []

    def get_project_settings(self, project_slug):
        self.settings_calls.append(project_slug)
        return self.settings[project_slug]

    def list_pipelines(self, org_slug, page_token=None):
        return self.pipeline_pages[page_token or "first"]


def _settings(**adv):
    base = {"build_fork_prs": False, "forks_receive_secret_env_vars": False,
            "disable_ssh": False, "oss": False}
    base.update(adv)
    return {"advanced": base}


def test_flatten_advanced_to_top_level():
    settings = {"gh/o/p": _settings(forks_receive_secret_env_vars=True, build_fork_prs=True)}
    events = collector.fetch_events(MockClient(settings), ["gh/o/p"], 100)
    assert len(events) == 1
    e = events[0]
    assert e["forks_receive_secret_env_vars"] is True
    assert e["build_fork_prs"] is True
    assert e["disable_ssh"] is False
    assert e["source_log_type"] == "project_settings"
    assert e["circleci_project_slug"] == "gh/o/p"
    assert e["_time"] == e["snapshot_at"]
    assert "advanced" not in e


def test_slug_split_for_settings_endpoint():
    settings = {"circleci/3sjp/VT3": _settings()}
    c = MockClient(settings)
    collector.fetch_events(c, ["circleci/3sjp/VT3"], 100)
    assert c.settings_calls == ["circleci/3sjp/VT3"]


def test_nested_and_array_settings_skipped():
    settings = {"gh/o/p": {"advanced": {"oss": True, "pr_only_branch_overrides": ["main"],
                                        "nested": {"x": 1}}}}
    events = collector.fetch_events(MockClient(settings), ["gh/o/p"], 100)
    e = events[0]
    assert e["oss"] is True
    assert "pr_only_branch_overrides" not in e
    assert "nested" not in e


def test_discovery_and_max_fetch():
    settings = {f"gh/o/p{i}": _settings() for i in range(5)}
    pp = {"first": {"items": [{"id": str(i), "project_slug": f"gh/o/p{i}"} for i in range(5)], "next_page_token": None}}
    c = MockClient(settings, pp)
    events = collector.fetch_events(c, collector.resolve_project_slugs(c, [], ["gh/o"]), 3)
    assert len(events) == 3


def test_fetch_error_skips_project():
    class ErrClient(MockClient):
        def get_project_settings(self, project_slug):
            if project_slug == "gh/o/bad":
                raise collector.DemistoException("[404] not found")
            return self.settings[project_slug]
    settings = {"gh/o/good": _settings()}
    events = ErrClient(settings).__class__(settings).__init__ if False else None
    c = ErrClient({"gh/o/good": _settings()})
    events = collector.fetch_events(c, ["gh/o/bad", "gh/o/good"], 100)
    assert [e["circleci_project_slug"] for e in events] == ["gh/o/good"]
