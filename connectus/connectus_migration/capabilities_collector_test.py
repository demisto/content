import json
from pathlib import Path

import yaml

from capabilities_collector import collect_capabilities


def _build_yml(
    name: str = "MyIntegration",
    configuration: list | None = None,
    script: dict | None = None,
) -> dict:
    return {
        "name": name,
        "configuration": configuration or [],
        "script": script or {"commands": []},
    }


class TestCollectCapabilities:
    def test_no_capabilities(self):
        """
        Given: A bare integration YML with no fetch flags and no commands.
        When:  collect_capabilities is called.
        Then:  An empty list is returned (general_configurations is never
               included).
        """
        assert collect_capabilities(_build_yml()) == []

    def test_fetch_secrets(self):
        """
        Given: A YML with an 'isFetchCredentials' config param and no commands.
        When:  collect_capabilities is called.
        Then:  Only 'Fetch Secrets' is returned.
        """
        yml = _build_yml(configuration=[{"name": "isFetchCredentials", "type": 8}])
        assert collect_capabilities(yml) == ["Fetch Secrets"]

    def test_fetch_issues(self):
        """
        Given: A YML with isfetch=True and no isfetch:platform override.
        When:  collect_capabilities is called.
        Then:  'Fetch Issues' is in the returned list.
        """
        yml = _build_yml(script={"isfetch": True, "commands": []})
        assert collect_capabilities(yml) == ["Fetch Issues"]

    def test_fetch_issues_skipped_when_platform_false(self):
        """
        Given: A YML with isfetch=True but isfetch:platform=False.
        When:  collect_capabilities is called.
        Then:  'Fetch Issues' is not returned.
        """
        yml = _build_yml(
            script={"isfetch": True, "isfetch:platform": False, "commands": []}
        )
        assert "Fetch Issues" not in collect_capabilities(yml)

    def test_fetch_assets(self):
        """
        Given: A YML with isfetchassets=True.
        When:  collect_capabilities is called.
        Then:  'Fetch Assets and Vulnerabilities' is returned.
        """
        yml = _build_yml(script={"isfetchassets": True, "commands": []})
        assert "Fetch Assets and Vulnerabilities" in collect_capabilities(yml)

    def test_automation_non_event_collector(self):
        """
        Given: A non event-collector YML with a single non-fetch command.
        When:  collect_capabilities is called.
        Then:  'Automation' is returned.
        """
        yml = _build_yml(script={"commands": [{"name": "vendor-do-action"}]})
        assert collect_capabilities(yml) == ["Automation"]

    def test_automation_not_added_for_only_fetch_commands(self):
        """
        Given: A YML whose only command is a fetch command.
        When:  collect_capabilities is called.
        Then:  'Automation' is NOT returned.
        """
        yml = _build_yml(
            script={
                "isfetch": True,
                "commands": [{"name": "fetch-incidents"}],
            }
        )
        result = collect_capabilities(yml)
        assert "Automation" not in result
        assert "Fetch Issues" in result

    def test_event_collector_two_commands_no_automation(self):
        """
        Given: An event collector with two commands (one non-fetch).
        When:  collect_capabilities is called.
        Then:  'Log Collection' is present, 'Automation' is NOT (fewer than 3).
        """
        yml = _build_yml(
            name="SomeSiem",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "siem-do-action"},
                    {"name": "siem-list"},
                ],
            },
        )
        result = collect_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" not in result

    def test_event_collector_three_commands_adds_automation(self):
        """
        Given: An event collector with three commands including non-fetch ones.
        When:  collect_capabilities is called.
        Then:  Both 'Log Collection' and 'Automation' are returned.
        """
        yml = _build_yml(
            name="SomeSiem",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "siem-do-action"},
                    {"name": "siem-list"},
                    {"name": "siem-get-thing"},
                ],
            },
        )
        result = collect_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" in result

    def test_pure_event_collector_short_circuits(self):
        """
        Given: A pure event collector (name has 'event collector', only a
               get-events command).
        When:  collect_capabilities is called.
        Then:  Only 'Log Collection' is returned (early exit).
        """
        yml = _build_yml(
            name="My Event Collector",
            script={
                "isfetchevents": True,
                "commands": [{"name": "vendor-get-events"}],
            },
        )
        assert collect_capabilities(yml) == ["Log Collection"]

    def test_feed_early_exit(self):
        """
        Given: A feed YML whose name contains 'feed' and whose only command is
               a get-indicators command (no other commands).
        When:  collect_capabilities is called.
        Then:  Only 'Threat Intelligence & Enrichment' is returned (early
               exit; no Automation because there is no non-fetch command).
        """
        yml = _build_yml(
            name="MyFeedSource",
            script={"feed": True, "commands": [{"name": "vendor-get-indicators"}]},
        )
        assert collect_capabilities(yml) == ["Threat Intelligence & Enrichment"]

    def test_no_duplicate_capabilities(self):
        """
        Given: A YML triggering several capabilities.
        When:  collect_capabilities is called.
        Then:  Each capability appears exactly once and general_configurations
               is never present.
        """
        yml = _build_yml(
            name="BigIntegration",
            configuration=[{"name": "isFetchCredentials"}],
            script={
                "isfetch": True,
                "isfetchassets": True,
                "commands": [
                    {"name": "big-do-stuff"},
                    {"name": "big-list"},
                ],
            },
        )
        result = collect_capabilities(yml)
        assert "general_configurations" not in result
        assert len(result) == len(set(result))
        assert set(result) == {
            "Fetch Secrets",
            "Fetch Issues",
            "Fetch Assets and Vulnerabilities",
            "Automation",
        }


class TestEndToEnd:
    def test_writes_json_list(self, tmp_path: Path):
        """
        Given: A small integration YML written to disk.
        When:  collect_capabilities runs and the result is JSON-serialised.
        Then:  The JSON round-trips to the same flat list of capabilities.
        """
        yml_content = {
            "name": "TinyIntegration",
            "configuration": [],
            "script": {
                "isfetch": True,
                "commands": [
                    {"name": "fetch-incidents"},
                    {"name": "tiny-do-stuff"},
                ],
            },
        }
        yml_path = tmp_path / "tiny.yml"
        with open(yml_path, "w") as f:
            yaml.safe_dump(yml_content, f)

        result = collect_capabilities(yml_content)
        assert set(result) == {"Fetch Issues", "Automation"}

        out = tmp_path / "out.json"
        out.write_text(json.dumps(result, indent=2))
        loaded = json.loads(out.read_text())
        assert loaded == result
