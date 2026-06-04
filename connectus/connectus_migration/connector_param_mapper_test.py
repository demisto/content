import json
from pathlib import Path

import pytest
import yaml

from connector_param_mapper import (
    _filter_hidden_params,
    decide_capabilities,
    map_params_to_capabilities,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Step 1 - capability decision tests
# ---------------------------------------------------------------------------
class TestDecideCapabilities:
    def test_only_general_configurations(self):
        """
        Given: A bare integration YML with no fetch flags and no commands.
        When:  decide_capabilities is called.
        Then:  Only the empty 'general_configurations' bucket is returned.
        """
        yml = _build_yml()
        assert decide_capabilities(yml) == {"general_configurations": []}

    def test_fetch_secrets_added(self):
        """
        Given: A YML whose configuration includes an 'isFetchCredentials' param
               and no commands.
        When:  decide_capabilities is called.
        Then:  'Fetch Secrets' is added and 'Automation' is NOT added (no
               non-excluded commands exist).
        """
        yml = _build_yml(
            configuration=[{"name": "isFetchCredentials", "type": 8}],
        )
        result = decide_capabilities(yml)
        assert "Fetch Secrets" in result
        assert "Automation" not in result

    def test_log_collection_normal(self):
        """
        Given: A YML with isfetchevents=True, a name that does NOT contain
               'eventcollector', and no 'get-events' style command.
        When:  decide_capabilities is called.
        Then:  Both 'Log Collection' and 'Automation' are present (no early
               exit, because non-excluded commands exist).
        """
        # isfetchevents true but name has no eventcollector and no get-events cmd
        yml = _build_yml(
            name="SomeSiem",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "siem-get-alert"},
                    {"name": "siem-list-cases"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" in result  # has non-excluded commands

    def test_log_collection_early_exit_event_collector_name(self):
        """
        Given: A pure event-collector YML (isfetchevents=True only) whose
               name contains 'event collector' (with a space) AND has at least
               one non-get-events command.
        When:  decide_capabilities is called.
        Then:  Rule 2 short-circuits and returns the minimal mapping
               {general_configurations, Log Collection}.
        """
        yml = _build_yml(
            name="My Event Collector",
            script={
                "isfetchevents": True,
                "commands": [{"name": "do-something"}],
            },
        )
        result = decide_capabilities(yml)
        assert result == {
            "general_configurations": [],
            "Log Collection": [],
            "Automation": [],
        }

    def test_log_collection_no_early_exit_when_only_get_events_commands(self):
        """
        Given: An event-collector YML whose name contains 'event collector'
               but whose ONLY commands are get-events (no regular commands).
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit must NOT fire — the new
               _is_pure_event_collector tail check rejects integrations that
               only have get-events commands. 'Log Collection' is still added.
        """
        yml = _build_yml(
            name="My Event Collector",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "vendor-get-events"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        # Early-exit did NOT fire, so result is the full dict (not just LC + general)
        # Note: there are no non-excluded commands, so no Automation is added either.

    def test_log_collection_no_early_exit_with_two_get_events(self):
        """
        Given: A YML with two distinct 'get-events' commands plus another
               command (so the name has no 'eventcollector' marker).
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit must NOT fire; both 'Log Collection' and
               'Automation' remain in the result.
        """
        # 2 commands matching "get-events" should NOT trigger early exit
        yml = _build_yml(
            name="SomeIntegration",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "vendor-get-events"},
                    {"name": "vendor-other-get-events"},
                    {"name": "vendor-list"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" in result

    def test_fetch_issues_added(self):
        """
        Given: A YML with isfetch=True and no isfetch:platform override.
        When:  decide_capabilities is called.
        Then:  'Fetch Issues' is added to the result.
        """
        yml = _build_yml(script={"isfetch": True, "commands": []})
        result = decide_capabilities(yml)
        assert "Fetch Issues" in result

    def test_fetch_issues_skipped_when_platform_false(self):
        """
        Given: A YML with isfetch=True but isfetch:platform=False.
        When:  decide_capabilities is called.
        Then:  'Fetch Issues' is suppressed (the platform flag blocks it).
        """
        yml = _build_yml(
            script={"isfetch": True, "isfetch:platform": False, "commands": []}
        )
        result = decide_capabilities(yml)
        assert "Fetch Issues" not in result

    def test_threat_intel_added(self):
        """
        Given: A YML with feed=True, a name that does NOT contain 'feed',
               and commands that do NOT match the 'get-indicators' early-exit.
        When:  decide_capabilities is called.
        Then:  Both 'Threat Intelligence & Enrichment' and 'Automation' are
               present.
        """
        yml = _build_yml(
            name="GenericTI",
            script={
                "feed": True,
                "commands": [
                    {"name": "ti-get-something"},
                    {"name": "ti-list"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Threat Intelligence & Enrichment" in result
        assert "Automation" in result

    def test_threat_intel_early_exit_feed_in_name(self):
        """
        Given: A YML with feed=True whose name contains 'feed'.
        When:  decide_capabilities is called.
        Then:  Rule 4 short-circuits and only
               {general_configurations, Threat Intelligence & Enrichment}
               is returned.
        """
        yml = _build_yml(
            name="MyFeedSource",
            script={"feed": True, "commands": [{"name": "ti-action"}]},
        )
        result = decide_capabilities(yml)
        assert result == {
            "general_configurations": [],
            "Threat Intelligence & Enrichment": [],
            "Automation": [],
        }

    def test_threat_intel_early_exit_single_get_indicators(self):
        """
        Given: A YML with feed=True where exactly one command matches
               'get-indicators' (rest leaves command list empty after
               exclusion).
        When:  decide_capabilities is called.
        Then:  Rule 4 short-circuits and only
               {general_configurations, Threat Intelligence & Enrichment,
               Automation} is returned.
        """
        yml = _build_yml(
            name="SomeTI",
            script={
                "feed": True,
                "commands": [
                    {"name": "vendor-get-indicators"},
                    {"name": "vendor-other"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert result == {
            "general_configurations": [],
            "Threat Intelligence & Enrichment": [],
            "Automation": [],
        }

    def test_fetch_assets_added(self):
        """
        Given: A YML with isfetchassets=True and no commands.
        When:  decide_capabilities is called.
        Then:  'Fetch Assets and Vulnerabilities' is added to the result.
        """
        yml = _build_yml(script={"isfetchassets": True, "commands": []})
        result = decide_capabilities(yml)
        assert "Fetch Assets and Vulnerabilities" in result

    def test_combined_capabilities(self):
        """
        Given: A YML that triggers Fetch Secrets (isFetchCredentials param),
               Fetch Issues (isfetch=True), Fetch Assets and Vulnerabilities
               (isfetchassets=True), AND Automation (non-excluded commands).
        When:  decide_capabilities is called.
        Then:  All four capabilities co-exist in the returned mapping.
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
        result = decide_capabilities(yml)
        assert "Fetch Secrets" in result
        assert "Fetch Issues" in result
        assert "Fetch Assets and Vulnerabilities" in result
        assert "Automation" in result

    # ------------------------------------------------------------------
    # Rule 2 early-exit precondition tests (Option B fix)
    # ------------------------------------------------------------------
    def test_event_collector_with_isfetchassets_keeps_both_capabilities(self):
        """
        Given: A multi-purpose collector YML with isfetchevents=True AND
               isfetchassets=True whose name contains 'eventcollector'.
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit must NOT fire — both 'Log Collection' and
               'Fetch Assets and Vulnerabilities' must remain.
        """
        yml = _build_yml(
            name="Jamf Protect Event Collector",
            script={
                "isfetchevents": True,
                "isfetchassets": True,
                "commands": [
                    {"name": "jamf-protect-get-events"},
                    {"name": "jamf-protect-get-computer-assets"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Fetch Assets and Vulnerabilities" in result
        assert "Automation" in result
        assert "general_configurations" in result

    def test_pure_event_collector_still_short_circuits(self):
        """
        Given: A pure event-collector YML where isfetchevents is the only
               fetch flag, the name contains 'event collector' (with space),
               and there is at least one non-get-events command.
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit fires (regression guard for the
               multi-purpose fix above).
        """
        yml = _build_yml(
            name="My Event Collector",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "do-something"},
                    {"name": "vendor-get-events"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert result == {
            "general_configurations": [],
            "Log Collection": [],
            "Automation": [],
        }


# ---------------------------------------------------------------------------
# Step 2 - param mapping tests
# ---------------------------------------------------------------------------
class TestMapParamsToCapabilities:
    def test_test_module_param_without_default_goes_to_general(self):
        """
        Given: A test-module command exposing two params, of which only
               'api_key' has a default in param_defaults.
        When:  map_params_to_capabilities is called.
        Then:  'url' (no default) lands in general_configurations and
               'api_key' (has default) does NOT.
        """
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {"test-module": ["url", "api_key"]},
        }
        param_defaults = {"api_key": "secret"}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert "url" in result["general_configurations"]
        assert "api_key" not in result["general_configurations"]

    def test_test_module_param_with_default_skipped(self):
        """
        Given: A test-module command whose only param has a default in
               param_defaults.
        When:  map_params_to_capabilities is called.
        Then:  The param is NOT added to general_configurations
               (Step 2.1 skips defaulted params).
        """
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {"test-module": ["api_key"]},
        }
        param_defaults = {"api_key": "secret"}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        # general_configurations bucket is dropped by Step 2.7 cleanup when empty
        assert "api_key" not in result.get("general_configurations", [])

    def test_single_capability_shortcut(self):
        """
        Given: A capabilities mapping with exactly 2 keys
               (general_configurations + Log Collection) and several commands
               whose params overlap with test-module.
        When:  map_params_to_capabilities is called.
        Then:  Step 2.2 shortcut fires: all unique command params (minus the
               one already in general_configurations) land in the single
               non-general capability.
        """
        # only 2 keys → all unique command params go into the non-general one
        capabilities = {"general_configurations": [], "Log Collection": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "fetch-events": ["max_fetch", "first_fetch"],
                "vendor-get-events": ["query"],
            },
        }
        param_defaults = {"max_fetch": 30, "first_fetch": "3 days", "query": ""}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["general_configurations"] == ["url"]
        # all unique params (excluding the one already in general_configurations)
        assert sorted(result["Log Collection"]) == sorted(
            ["max_fetch", "first_fetch", "query"]
        )

    def test_multi_capability_fetch_incidents_to_fetch_issues(self):
        """
        Given: Multiple capabilities (Fetch Issues + Automation) plus a
               fetch-incidents command and an unrelated vendor command.
        When:  map_params_to_capabilities is called.
        Then:  Step 2.3 routes 'fetch-incidents' params to 'Fetch Issues'
               (via COMMAND_TO_CAPABILITY) and the vendor command's param
               to 'Automation'.
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": [],
                "fetch-incidents": ["incident_query", "max_incidents"],
                "vendor-do-stuff": ["arg1"],
            },
        }
        param_defaults = {
            "incident_query": "",
            "max_incidents": 50,
            "arg1": "x",
        }
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert sorted(result["Fetch Issues"]) == sorted(
            ["incident_query", "max_incidents"]
        )
        assert result["Automation"] == ["arg1"]

    def test_multi_capability_other_command_to_automation(self):
        """
        Given: A multi-capability mapping (Fetch Issues + Automation) but
               only generic vendor commands that don't match
               COMMAND_TO_CAPABILITY.
        When:  map_params_to_capabilities is called.
        Then:  All vendor params fall back to 'Automation' and 'Fetch Issues'
               remains empty.
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "vendor-action-1": ["a"],
                "vendor-action-2": ["b"],
            },
        }
        param_defaults = {"a": 1, "b": 2}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert sorted(result["Automation"]) == ["a", "b"]
        # Empty 'Fetch Issues' bucket is dropped by Step 2.7 cleanup
        assert "Fetch Issues" not in result

    def test_multi_capability_missing_target_logs_warning(self, caplog):
        """
        Given: A capabilities mapping that does NOT contain 'Fetch Issues'
               while a fetch-incidents command supplies params.
        When:  map_params_to_capabilities is called at WARNING log level.
        Then:  The orphan param is NOT placed anywhere AND a warning naming
               both the param and the missing target capability is logged.
        """
        # Fetch Issues capability is NOT present, but fetch-incidents command provides params
        capabilities = {
            "general_configurations": [],
            "Automation": [],
            "Log Collection": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "fetch-incidents": ["missing_param"],
                "vendor-action": ["a"],
            },
        }
        param_defaults = {"missing_param": 1, "a": 2}
        caplog.set_level("WARNING")
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        # The param should not be placed anywhere; empty buckets are dropped
        # by Step 2.7 cleanup, so use .get() for defensive lookups.
        assert "missing_param" not in result.get("Automation", [])
        assert "missing_param" not in result.get("general_configurations", [])
        # And a warning should have been logged
        assert "missing_param" in caplog.text
        assert "Fetch Issues" in caplog.text

    def test_get_events_command_routes_to_log_collection(self):
        """
        Given: A multi-capability mapping containing 'Log Collection' and a
               command whose name contains 'get-events'.
        When:  map_params_to_capabilities is called.
        Then:  Substring routing places the get-events params in
               'Log Collection' (not the default Automation fallback).
        """
        capabilities = {
            "general_configurations": [],
            "Log Collection": [],
            "Automation": [],
        }
        command_params = {
            "integration": "MyProduct",
            "commands": {
                "myproduct-get-events": ["events_param"],
                "myproduct-do-action": ["action_param"],
            },
        }
        param_defaults = {"events_param": 1, "action_param": 2}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["Log Collection"] == ["events_param"]
        assert result["Automation"] == ["action_param"]

    def test_get_events_command_falls_back_to_automation_without_log_collection(
        self,
    ):
        """
        Given: A capabilities mapping that does NOT contain 'Log Collection'
               and a command whose name contains 'get-events'.
        When:  map_params_to_capabilities is called.
        Then:  With only 2 capabilities, Step 2.2 shortcut fires and the
               get-events param lands in 'Automation' (no special routing).
        """
        capabilities = {
            "general_configurations": [],
            "Automation": [],
        }
        command_params = {
            "integration": "MyProduct",
            "commands": {
                "myproduct-get-events": ["events_param"],
            },
        }
        param_defaults = {"events_param": 1}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        # With only 2 capabilities, Step 2.2 shortcut places everything in
        # the non-general capability (Automation).
        assert result["Automation"] == ["events_param"]

    def test_get_indicators_command_routes_to_threat_intel(self):
        """
        Given: A multi-capability mapping containing
               'Threat Intelligence & Enrichment' and a command whose name
               contains 'get-indicators'.
        When:  map_params_to_capabilities is called.
        Then:  Substring routing places the get-indicators params in
               'Threat Intelligence & Enrichment' (not the default Automation
               fallback).
        """
        capabilities = {
            "general_configurations": [],
            "Threat Intelligence & Enrichment": [],
            "Automation": [],
        }
        command_params = {
            "integration": "MyFeed",
            "commands": {
                "myfeed-get-indicators": ["indicators_param"],
                "myfeed-do-action": ["action_param"],
            },
        }
        param_defaults = {"indicators_param": 1, "action_param": 2}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["Threat Intelligence & Enrichment"] == ["indicators_param"]
        assert result["Automation"] == ["action_param"]

    def test_get_indicators_command_falls_back_to_automation_without_threat_intel(
        self,
    ):
        """
        Given: A capabilities mapping that does NOT contain
               'Threat Intelligence & Enrichment' and a command whose name
               contains 'get-indicators'.
        When:  map_params_to_capabilities is called.
        Then:  The get-indicators params fall back to 'Automation'.
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "MyProduct",
            "commands": {
                "myproduct-get-indicators": ["indicators_param"],
            },
        }
        param_defaults = {"indicators_param": 1}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["Automation"] == ["indicators_param"]
        # Empty 'Fetch Issues' bucket is dropped by Step 2.7 cleanup
        assert "Fetch Issues" not in result

    def test_dedup_param_in_multiple_capabilities_moves_to_general(self):
        """
        Given: A param ('shared') that is referenced by two different
               commands routed to two different capabilities, plus a unique
               param.
        When:  map_params_to_capabilities is called.
        Then:  Step 2.4 dedup moves 'shared' into general_configurations and
               removes it from both capabilities; 'unique' stays in
               'Automation'.
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "fetch-incidents": ["shared"],
                "vendor-action": ["shared", "unique"],
            },
        }
        param_defaults = {"shared": 1, "unique": 2}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert "shared" in result["general_configurations"]
        # After dedup, 'Fetch Issues' has no params left → dropped by Step 2.7
        # cleanup. 'Automation' still has 'unique' so it survives.
        assert "shared" not in result.get("Fetch Issues", [])
        assert "Fetch Issues" not in result
        assert "shared" not in result["Automation"]
        assert "unique" in result["Automation"]

    def test_dedup_param_in_general_and_capability_keeps_general(self):
        """
        Given: A param ('url') that ends up in general_configurations (via
               test-module) AND in another capability (via fetch-incidents).
        When:  map_params_to_capabilities is called.
        Then:  Step 2.4 dedup keeps a single occurrence in
               general_configurations and removes it from 'Fetch Issues'.
        """
        # If a param is in general_configurations AND in another capability,
        # _deduplicate should remove it from the capability and keep it in general.
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "fetch-incidents": ["url"],
            },
        }
        param_defaults = {}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["general_configurations"].count("url") == 1
        # After dedup, 'Fetch Issues' is empty → dropped by Step 2.7 cleanup
        assert "url" not in result.get("Fetch Issues", [])
        assert "Fetch Issues" not in result


# ---------------------------------------------------------------------------
# Step 2.1.5 - manual command-to-capability mapping tests
# ---------------------------------------------------------------------------
class TestManualMapping:
    def test_manual_mapping_empty_dict_preserves_existing_behavior(self):
        """
        Given: A complete command_params + capabilities setup and TWO calls
               to map_params_to_capabilities — one without
               manual_command_to_capability and one with an empty dict.
        When:  The two results are compared.
        Then:  They are identical (an empty manual mapping must be a no-op).
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "fetch-incidents": ["incident_query", "max_incidents"],
                "vendor-do-stuff": ["arg1"],
            },
        }
        param_defaults = {
            "incident_query": "",
            "max_incidents": 50,
            "arg1": "x",
        }
        baseline = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        with_empty_manual = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            manual_command_to_capability={},
        )
        assert baseline == with_empty_manual

    def test_manual_mapping_routes_long_running_to_custom_capability(self):
        """
        Given: An initial capabilities mapping that does NOT contain
               'Connection Health', plus a manual override routing
               'long-running-execution' to a new 'Connection Health'
               capability.
        When:  map_params_to_capabilities is called with the manual mapping.
        Then:  'Connection Health' is created with 'port'; 'filter' lands in
               'Automation'; 'url' (shared by 3 commands) is moved to
               general_configurations by Step 2.4 dedup.
        """
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "long-running-execution": ["url", "port"],
                "my-cmd": ["url", "filter"],
            },
        }
        param_defaults = {"url": None, "port": "8080", "filter": ""}
        manual = {"long-running-execution": ["Connection Health"]}
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            manual_command_to_capability=manual,
        )
        assert "Connection Health" in result
        assert "port" in result["Connection Health"]
        assert "filter" in result["Automation"]
        # 'url' appears in test-module + long-running + my-cmd → dedup → general
        assert "url" in result["general_configurations"]
        assert "url" not in result["Connection Health"]
        assert "url" not in result["Automation"]

    def test_manual_mapping_overrides_command_to_capability_constant(self):
        """
        Given: A capabilities mapping that contains 'Log Collection' (where
               'fetch-events' would normally route via COMMAND_TO_CAPABILITY)
               plus a manual override pointing 'fetch-events' to 'Custom Cap'.
        When:  map_params_to_capabilities is called.
        Then:  Manual mapping wins — 'lookback' lands in 'Custom Cap' and
               NOT in 'Log Collection'.
        """
        capabilities = {
            "general_configurations": [],
            "Log Collection": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "fetch-events": ["url", "lookback"],
                "my-cmd": ["url"],
            },
        }
        param_defaults = {"url": None, "lookback": "1h"}
        manual = {"fetch-events": ["Custom Cap"]}
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            manual_command_to_capability=manual,
        )
        assert "Custom Cap" in result
        assert "lookback" in result["Custom Cap"]
        assert "lookback" not in result["Log Collection"]

    def test_manual_mapping_multi_target_routes_to_all_listed(self):
        """
        Given: A manual override routing 'my-cmd' to BOTH 'Cap A' and
               'Cap B', and 'url' is also referenced by test-module.
        When:  map_params_to_capabilities is called.
        Then:  Both 'Cap A' and 'Cap B' are created; the params placed in
               both then duplicate, so Step 2.4 dedup moves 'shared' and
               'extra' into general_configurations and clears them from the
               capabilities (leaving Cap A and Cap B empty).
        """
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["url", "shared", "extra"],
            },
        }
        param_defaults = {"url": None, "shared": "x", "extra": "y"}
        manual = {"my-cmd": ["Cap A", "Cap B"]}
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            manual_command_to_capability=manual,
        )
        assert "Cap A" in result
        assert "Cap B" in result
        # 'shared' and 'extra' were placed in BOTH Cap A and Cap B → dedup
        # moves them into general_configurations and clears them from the caps.
        assert "shared" in result["general_configurations"]
        assert "extra" in result["general_configurations"]
        assert result["Cap A"] == []
        assert result["Cap B"] == []

    def test_manual_mapping_with_existing_capability_no_duplicate_keys(self):
        """
        Given: A manual override routing 'my-cmd' to 'Automation' (which
               already exists in the initial mapping).
        When:  map_params_to_capabilities is called.
        Then:  No duplicate 'Automation' key is created and 'filter' appears
               exactly once (Step 2.3 must skip the manually-handled command).
        """
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["url", "filter"],
            },
        }
        param_defaults = {"url": None, "filter": ""}
        manual = {"my-cmd": ["Automation"]}
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            manual_command_to_capability=manual,
        )
        # 'Automation' key exists exactly once, with 'filter' present once.
        assert list(result.keys()).count("Automation") == 1
        assert result["Automation"].count("filter") == 1
        assert "filter" in result["Automation"]


# ---------------------------------------------------------------------------
# End-to-end tests
# ---------------------------------------------------------------------------
class TestEndToEnd:
    def test_e2e_simple_integration(self, tmp_path: Path):
        """
        Given: A small fake integration YML (isfetch=True with a vendor
               command) written to a tmp_path, plus matching command_params
               and param_defaults.
        When:  decide_capabilities → map_params_to_capabilities is run, the
               result is JSON-serialised to disk and reloaded.
        Then:  The full end-to-end mapping equals
               {general_configurations:[url], Fetch Issues:[max_fetch],
               Automation:[arg1]} and JSON round-trip preserves it.
        """
        # Build a small fake integration YML
        yml_content = {
            "name": "TinyIntegration",
            "configuration": [{"name": "url", "type": 0}],
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

        capabilities = decide_capabilities(yml_content)
        assert "Fetch Issues" in capabilities
        assert "Automation" in capabilities

        command_params = {
            "integration": "TinyIntegration",
            "commands": {
                "test-module": ["url"],
                "fetch-incidents": ["max_fetch"],
                "tiny-do-stuff": ["arg1"],
            },
        }
        param_defaults = {"max_fetch": 50, "arg1": "x"}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result == {
            "general_configurations": ["url"],
            "Fetch Issues": ["max_fetch"],
            "Automation": ["arg1"],
        }

        # Write out and reload to make sure JSON serialisation works.
        out = tmp_path / "out.json"
        out.write_text(json.dumps(result, indent=2))
        loaded = json.loads(out.read_text())
        assert loaded == result

    def test_e2e_exabeam_yml(self):
        """
        Given: The real ExabeamSecOpsPlatform integration YML (skipped if
               not present locally), which has isfetchevents=True AND
               isfetch=True with isfetch:platform=False.
        When:  decide_capabilities is called on the parsed YML.
        Then:  Rule 2's early-exit must NOT fire (other fetch flags exist),
               so 'Log Collection' and 'Automation' remain, 'Fetch Issues' is
               blocked by the platform flag, and general_configurations is
               empty.
        """
        yml_path = Path(
            "/Users/yhayun/dev/demisto/content/Packs/"
            "ExabeamSecurityOperationsPlatform/Integrations/"
            "ExabeamSecOpsPlatform/ExabeamSecOpsPlatform.yml"
        )
        if not yml_path.exists():
            pytest.skip(f"Exabeam YML not found at {yml_path}")
        with open(yml_path) as f:
            integration_yml = yaml.safe_load(f)

        result = decide_capabilities(integration_yml)
        # ExabeamSecOpsPlatform: isfetchevents=True AND isfetch=True (with
        # isfetch:platform=False so Fetch Issues itself is skipped). Because
        # other fetch flags are present, Rule 2's early-exit must NOT fire —
        # Log Collection remains and Automation is added for non-excluded
        # commands like "exabeam-platform-event-search".
        assert "Log Collection" in result
        assert "Automation" in result
        assert "Fetch Issues" not in result  # isfetch:platform=False blocks it
        assert result["general_configurations"] == []


# ---------------------------------------------------------------------------
# Step 2.6 - hidden param filter tests
# ---------------------------------------------------------------------------
class TestHiddenParamFilter:
    def test_hidden_true_param_removed_from_result(self):
        """
        Given: An integration YML with a param marked ``hidden: true`` and
               another normal param, and command_params that route both into
               capabilities.
        When:  map_params_to_capabilities is called with the YML passed via
               the new ``integration_yml`` kwarg.
        Then:  The hidden=true param is stripped from every capability list,
               while the normal param remains.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "secret", "hidden": True},
                {"name": "url"},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["secret", "url"],
                "my-cmd": ["secret", "url"],
            },
        }
        param_defaults = {"secret": None, "url": "x"}

        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        all_params = [p for params in result.values() for p in params]
        assert "secret" not in all_params
        assert "url" in all_params

    def test_hidden_list_with_platform_param_removed(self):
        """
        Given: An integration YML with a param whose ``hidden`` field is a
               list containing ``"platform"`` (e.g. [marketplacev2, platform]).
        When:  map_params_to_capabilities runs with the YML passed in.
        Then:  That param is stripped from every capability list.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "interval", "hidden": ["marketplacev2", "platform"]},
                {"name": "url"},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["interval", "url"],
            },
        }
        param_defaults = {"interval": 1, "url": "x"}

        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        all_params = [p for params in result.values() for p in params]
        assert "interval" not in all_params
        assert "url" in all_params

    def test_hidden_list_without_platform_param_kept(self):
        """
        Given: An integration YML with a param whose ``hidden`` field is a
               list that does NOT contain ``"platform"`` (e.g. [xsoar]).
        When:  map_params_to_capabilities runs with the YML passed in.
        Then:  That param is preserved in the result (Cortex Platform is
               unaffected by xsoar-only hidden flags).
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "interval", "hidden": ["xsoar"]},
                {"name": "url"},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["interval", "url"],
            },
        }
        param_defaults = {"interval": 1, "url": "x"}

        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        all_params = [p for params in result.values() for p in params]
        assert "interval" in all_params
        assert "url" in all_params

    def test_no_hidden_params_no_log(self, caplog):
        """
        Given: An integration YML whose configuration has no params hidden on
               the platform (no ``hidden: true`` and no list containing
               ``"platform"``).
        When:  map_params_to_capabilities runs at INFO level with the YML
               passed in.
        Then:  No "Removed the following params" INFO message is emitted.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "url"},
                {"name": "interval", "hidden": ["xsoar"]},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["interval", "url"],
            },
        }
        param_defaults = {"interval": 1, "url": "x"}

        caplog.set_level("INFO")
        map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        assert "Removed the following params" not in caplog.text

    def test_hidden_param_in_multiple_capabilities_removed_once_logged_once(
        self, caplog
    ):
        """
        Given: A pre-built result where the same hidden param appears in TWO
               capability lists, and a hidden_params set containing it.
        When:  _filter_hidden_params is invoked directly at INFO level.
        Then:  The param is removed from BOTH capabilities AND the INFO log
               message contains the param name exactly once (the helper
               deduplicates removed names via a set).
        """
        result = {
            "general_configurations": ["url", "secret"],
            "Automation": ["secret", "arg1"],
        }
        hidden_params = {"secret"}

        caplog.set_level("INFO")
        _filter_hidden_params(result, hidden_params, set())

        # Param removed from both capabilities
        assert "secret" not in result["general_configurations"]
        assert "secret" not in result["Automation"]
        assert result["general_configurations"] == ["url"]
        assert result["Automation"] == ["arg1"]

        # The INFO log message lists the param exactly once
        assert "Removed the following params" in caplog.text
        assert caplog.text.count("'secret'") == 1

    def test_hidden_param_kept_when_has_yml_defaultvalue_and_not_in_param_defaults(
        self, caplog
    ):
        """
        Given: An integration YML with a param marked ``hidden: true`` that
               also has a YAML ``defaultvalue`` field, and a ``param_defaults``
               dict that does NOT contain the param's name.
        When:  map_params_to_capabilities runs at INFO level with the YML
               passed in.
        Then:  The hidden param is KEPT in the result by the carve-out, an
               INFO "Kept the following hidden params" message is emitted
               naming it, and no "Removed the following params" message
               mentions the param.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "internal_retries", "hidden": True, "defaultvalue": "3"},
                {"name": "url"},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["internal_retries", "url"],
            },
        }
        # internal_retries is intentionally NOT in param_defaults
        param_defaults = {"url": "x"}

        caplog.set_level("INFO")
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        all_params = [p for params in result.values() for p in params]
        assert "internal_retries" in all_params
        assert "url" in all_params

        assert "Kept the following hidden params" in caplog.text
        assert "internal_retries" in caplog.text
        # No "Removed" message for internal_retries
        if "Removed the following params" in caplog.text:
            assert (
                "internal_retries"
                not in caplog.text.split("Removed the following params")[1].split("\n")[
                    0
                ]
            )

    def test_hidden_param_removed_when_in_param_defaults_even_with_yml_defaultvalue(
        self, caplog
    ):
        """
        Given: An integration YML with a param hidden on the platform (via a
               list containing ``"platform"``) AND a YAML ``defaultvalue``,
               but the param IS present in ``param_defaults``.
        When:  map_params_to_capabilities runs at INFO level with the YML
               passed in.
        Then:  The carve-out does NOT fire (condition #1 fails) — the param is
               removed from the result, and no "Kept the following hidden
               params" log message is emitted.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {
                    "name": "interval",
                    "hidden": ["marketplacev2", "platform"],
                    "defaultvalue": "1",
                },
                {"name": "url"},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["interval", "url"],
            },
        }
        # interval IS in param_defaults — carve-out condition #1 fails
        param_defaults = {"interval": "5", "url": "x"}

        caplog.set_level("INFO")
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        all_params = [p for params in result.values() for p in params]
        assert "interval" not in all_params
        assert "url" in all_params

        assert "Kept the following hidden params" not in caplog.text

    def test_hidden_param_removed_when_no_yml_defaultvalue_even_if_not_in_param_defaults(
        self, caplog
    ):
        """
        Given: An integration YML with a param marked ``hidden: true`` that
               has NO ``defaultvalue`` field at all in the YAML, and a
               ``param_defaults`` dict that does NOT contain the param's
               name.
        When:  map_params_to_capabilities runs at INFO level with the YML
               passed in.
        Then:  The carve-out does NOT fire (condition #3 fails) — the param
               is removed from the result, and no "Kept the following hidden
               params" log message is emitted.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "secret", "hidden": True},
                {"name": "url"},
            ],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "my-cmd": ["secret", "url"],
            },
        }
        # secret is NOT in param_defaults, but YML has no defaultvalue
        param_defaults = {"url": "x"}

        caplog.set_level("INFO")
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )

        all_params = [p for params in result.values() for p in params]
        assert "secret" not in all_params
        assert "url" in all_params

        assert "Kept the following hidden params" not in caplog.text


# ---------------------------------------------------------------------------
# Long-running capability routing tests (INTEGRATION_TO_LONGRUNNING_CAPABILITY)
# ---------------------------------------------------------------------------
class TestLongRunningRouting:
    """Tests for the long-running capability routing feature.

    Verifies that when an integration declares ``script.longRunning: true`` AND
    its ``commonfields.id`` is present in
    ``INTEGRATION_TO_LONGRUNNING_CAPABILITY``:
      - The suggested capability key is created in the result dict (Rule 7).
      - The literal ``longRunningPort`` config param is routed there (Step 2.0).
      - The ``long-running-execution`` command's params are routed there
        (Step 2.3 via ``_resolve_target_capability``).

    Also verifies that integrations NOT in the dict fall through to the existing
    behavior (no change), and that integrations without ``longRunning: true``
    ignore the dict entirely.
    """

    def _build_long_running_yml(
        self,
        integration_id: str,
        long_running: bool = True,
        configuration: list | None = None,
    ) -> dict:
        """Helper that builds a YML with ``commonfields.id`` and a
        ``long-running-execution`` command."""
        return {
            "name": integration_id,
            "commonfields": {"id": integration_id},
            "configuration": configuration or [],
            "script": {
                "longRunning": long_running,
                "commands": [{"name": "long-running-execution"}],
            },
        }

    def test_long_running_id_in_dict_routes_port_and_command(self):
        """
        Given: An integration whose id (``Akamai WAF SIEM``) is in
               ``INTEGRATION_TO_LONGRUNNING_CAPABILITY`` (suggested:
               'Log Collection'), declares ``longRunning: true``, exposes a
               ``longRunningPort`` config param, and has a
               ``long-running-execution`` command with extra params.
        When:  decide_capabilities + map_params_to_capabilities are called.
        Then:  The suggested capability ('Log Collection') exists in the
               result, ``longRunningPort`` is placed in it (Step 2.0), AND the
               ``long-running-execution`` command's params are routed there
               instead of 'Automation'.
        """
        yml = self._build_long_running_yml(
            integration_id="Akamai WAF SIEM",
            configuration=[{"name": "longRunningPort", "type": 0}],
        )
        capabilities = decide_capabilities(yml)
        # Rule 7 must have created the Log Collection bucket
        assert "Log Collection" in capabilities

        command_params = {
            "integration": "Akamai WAF SIEM",
            "commands": {
                "long-running-execution": ["listenerUrl", "certificate"],
            },
        }
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults={},
            integration_yml=yml,
        )

        # Step 2.0 - longRunningPort routed to suggested capability
        assert "longRunningPort" in result["Log Collection"]
        # Step 2.3 - long-running-execution params routed to suggested capability
        assert "listenerUrl" in result["Log Collection"]
        assert "certificate" in result["Log Collection"]
        # And NOT to Automation (which doesn't even exist in this minimal result)
        assert "Automation" not in result or "listenerUrl" not in result.get(
            "Automation", []
        )

    def test_long_running_id_not_in_dict_falls_through_to_automation(self):
        """
        Given: An integration whose id is NOT in
               ``INTEGRATION_TO_LONGRUNNING_CAPABILITY`` but declares
               ``longRunning: true``.
        When:  decide_capabilities + map_params_to_capabilities are called.
        Then:  No suggested-capability key is added (existing behavior). The
               ``long-running-execution`` command's params land in 'Automation'
               via the standard fallback. ``longRunningPort`` is NOT routed by
               Step 2.0 (skipped due to no override).
        """
        yml = self._build_long_running_yml(
            integration_id="SomeUnknownIntegration",
            configuration=[{"name": "longRunningPort", "type": 0}],
        )
        capabilities = decide_capabilities(yml)
        # No long-running-suggested capability added (only general + Automation
        # from Rule 6, since long-running-execution is a non-excluded command).
        assert "general_configurations" in capabilities
        # Rule 6 adds Automation because long-running-execution doesn't match
        # any excluded pattern.
        assert "Automation" in capabilities

        command_params = {
            "integration": "SomeUnknownIntegration",
            "commands": {
                "long-running-execution": ["listenerUrl"],
            },
        }
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults={},
            integration_yml=yml,
        )
        # Existing fallback: long-running-execution params land in Automation
        assert "listenerUrl" in result["Automation"]
        # longRunningPort is NOT auto-routed by Step 2.0 (no override)
        assert "longRunningPort" not in result.get("Automation", [])

    def test_long_running_port_absent_no_error(self):
        """
        Given: An integration in the dict (``Akamai WAF SIEM``) with
               ``longRunning: true`` but NO ``longRunningPort`` config param.
        When:  map_params_to_capabilities is called.
        Then:  No error is raised; the suggested capability still receives the
               ``long-running-execution`` command's params.
        """
        yml = self._build_long_running_yml(
            integration_id="Akamai WAF SIEM",
            configuration=[],  # no longRunningPort
        )
        capabilities = decide_capabilities(yml)
        command_params = {
            "integration": "Akamai WAF SIEM",
            "commands": {"long-running-execution": ["listenerUrl"]},
        }
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults={},
            integration_yml=yml,
        )
        assert "Log Collection" in result
        assert "listenerUrl" in result["Log Collection"]
        # longRunningPort is not in any bucket since it's not in the YML
        assert "longRunningPort" not in result["Log Collection"]

    def test_long_running_port_in_param_defaults_still_routed(self):
        """
        Given: An integration in the dict (``Akamai WAF SIEM``) with
               ``longRunning: true``, exposes ``longRunningPort``, AND
               ``longRunningPort`` is also a key in ``param_defaults``.
        When:  map_params_to_capabilities is called.
        Then:  ``longRunningPort`` IS placed in the suggested long-running
               capability (per the long-running spec — params owned by the
               long-running flow are routed to the suggested capability
               regardless of ``param_defaults``). The command's other params
               are routed there too.
        """
        yml = self._build_long_running_yml(
            integration_id="Akamai WAF SIEM",
            configuration=[{"name": "longRunningPort", "type": 0}],
        )
        capabilities = decide_capabilities(yml)
        command_params = {
            "integration": "Akamai WAF SIEM",
            "commands": {"long-running-execution": ["listenerUrl"]},
        }
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults={"longRunningPort": 8080},  # external default
            integration_yml=yml,
        )
        # longRunningPort is placed in the suggested capability (long-running
        # spec wins over param_defaults override)
        assert "longRunningPort" in result["Log Collection"]
        # The command's other params are also routed there
        assert "listenerUrl" in result["Log Collection"]
        # And longRunningPort is NOT in general_configurations (which is
        # dropped entirely by Step 2.7 cleanup when empty)
        assert "longRunningPort" not in result.get("general_configurations", [])

    def test_no_long_running_flag_dict_ignored(self):
        """
        Given: An integration whose id IS in the dict (``Akamai WAF SIEM``) but
               does NOT declare ``longRunning: true`` (e.g., longRunning
               flag absent or false).
        When:  decide_capabilities + map_params_to_capabilities are called.
        Then:  The dict is ignored entirely. No suggested-capability key added
               by Rule 7; ``longRunningPort`` (if present) is not routed by
               Step 2.0; the ``long-running-execution`` command (if present)
               falls through to Automation.
        """
        yml = self._build_long_running_yml(
            integration_id="Akamai WAF SIEM",
            long_running=False,  # No long-running flag
            configuration=[{"name": "longRunningPort", "type": 0}],
        )
        capabilities = decide_capabilities(yml)
        # Rule 7 must NOT trigger
        assert "Log Collection" not in capabilities

        command_params = {
            "integration": "Akamai WAF SIEM",
            "commands": {"long-running-execution": ["listenerUrl"]},
        }
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults={},
            integration_yml=yml,
        )
        # No Log Collection bucket; long-running-execution falls through to
        # Automation (which Rule 6 added because long-running-execution is a
        # non-excluded command).
        assert "Log Collection" not in result
        assert "Automation" in result
        assert "listenerUrl" in result["Automation"]
        # longRunningPort not auto-routed (longRunning flag is false)
        assert "longRunningPort" not in result["Automation"]

    def test_long_running_param_pinned_to_suggested_capability_only(self):
        """
        Given: An integration in the dict (``Akamai WAF SIEM``) with
               ``longRunning: true``. The ``longRunning`` param name is also
               referenced by ``test-module`` and by another command's params —
               adversarial inputs that try to land it in
               ``general_configurations`` and/or another capability.
        When:  decide_capabilities + map_params_to_capabilities are called.
        Then:  ``longRunning`` ends up ONLY in the suggested long-running
               capability (``Log Collection`` for Akamai WAF SIEM). It is NOT in
               ``general_configurations`` and NOT in ``Automation``.
        """
        yml = self._build_long_running_yml(
            integration_id="Akamai WAF SIEM",
            configuration=[],
        )
        # Force Automation into the result by adding a non-excluded command
        yml["script"]["commands"].append({"name": "akamai-do-something"})

        capabilities = decide_capabilities(yml)
        # Sanity: Rule 7 placed longRunning in Log Collection
        assert "Log Collection" in capabilities
        assert capabilities["Log Collection"] == ["longRunning"]

        # Adversarial command_params: longRunning appears in test-module AND
        # another command (Automation candidate)
        command_params = {
            "integration": "Akamai WAF SIEM",
            "commands": {
                "test-module": ["url", "longRunning"],
                "akamai-do-something": ["longRunning", "someArg"],
                "long-running-execution": ["listenerUrl"],
            },
        }
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults={},
            integration_yml=yml,
        )

        # The hard requirement: longRunning lands ONLY in Log Collection
        assert "longRunning" in result["Log Collection"]
        assert "longRunning" not in result["general_configurations"]
        assert "longRunning" not in result.get("Automation", [])

        # And it appears exactly once across all capabilities
        all_locations = [
            cap for cap, params in result.items() if "longRunning" in params
        ]
        assert all_locations == ["Log Collection"]


# ---------------------------------------------------------------------------
# Step 2.7 — cleanup empty capabilities
# ---------------------------------------------------------------------------
class TestCleanupEmptyCapabilities:
    """Tests for the Step 2.7 cleanup that removes any capability bucket with
    an empty param list, including ``general_configurations``."""

    def test_capability_emptied_by_dedup_is_removed(self):
        """
        Given: A param routed to two capabilities so dedup moves it to
               general_configurations, leaving one of the source capabilities
               empty.
        When:  map_params_to_capabilities is called.
        Then:  The emptied capability is removed from the final result by
               Step 2.7 cleanup.
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                # 'shared' is routed to both Fetch Issues (by fetch-incidents)
                # and Automation (by vendor-action). After dedup it moves to
                # general_configurations, leaving Fetch Issues empty.
                "fetch-incidents": ["shared"],
                "vendor-action": ["shared"],
            },
        }
        param_defaults = {"shared": 1}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert "Fetch Issues" not in result
        assert "Automation" not in result
        assert result["general_configurations"] == ["shared"]

    def test_capability_emptied_by_hidden_filter_is_removed(self):
        """
        Given: A capability that contains only params that are hidden on
               the platform (via integration_yml).
        When:  map_params_to_capabilities is called with the integration_yml.
        Then:  Step 2.6 hidden filter strips all params, then Step 2.7
               cleanup removes the now-empty capability.
        """
        integration_yml = {
            "name": "X",
            "configuration": [
                {"name": "vendor_arg", "hidden": True},
            ],
            "script": {"commands": []},
        }
        capabilities = {
            "general_configurations": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "vendor-action": ["vendor_arg"],
            },
        }
        param_defaults = {"vendor_arg": 1}
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
        )
        # Step 2.6 stripped 'vendor_arg' from Automation; Step 2.7 removed it.
        assert "Automation" not in result
        assert "general_configurations" not in result

    def test_empty_general_configurations_is_also_removed(self):
        """
        Given: A capabilities setup that ends with an empty
               general_configurations bucket (no test-module-without-default
               and no duplicates to demote).
        When:  map_params_to_capabilities is called.
        Then:  Step 2.7 cleanup removes general_configurations too (per the
               Q2=b spec — empty general_configurations is NOT exempt).
        """
        capabilities = {
            "general_configurations": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "vendor-action": ["only_param"],
            },
        }
        param_defaults = {"only_param": 1}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        # Automation has 'only_param' so it stays
        assert result["Automation"] == ["only_param"]
        # general_configurations is empty → removed
        assert "general_configurations" not in result

    def test_non_empty_capabilities_are_preserved(self):
        """
        Given: A capabilities mapping where every bucket ends with at least
               one param.
        When:  map_params_to_capabilities is called.
        Then:  No bucket is removed by Step 2.7 cleanup; all keys present.
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "fetch-incidents": ["incident_query"],
                "vendor-action": ["arg1"],
            },
        }
        # url has no default → goes to general_configurations
        # incident_query → Fetch Issues
        # arg1 → Automation
        param_defaults = {"incident_query": "", "arg1": "x"}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["general_configurations"] == ["url"]
        assert result["Fetch Issues"] == ["incident_query"]
        assert result["Automation"] == ["arg1"]

    def test_cleanup_logs_removed_keys(self, caplog):
        """
        Given: A run that produces at least one empty capability.
        When:  map_params_to_capabilities is called at INFO log level.
        Then:  An INFO log message names the removed capability key(s).
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "vendor-action": ["only_param"],
            },
        }
        param_defaults = {"only_param": 1}
        caplog.set_level("INFO")
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        # Fetch Issues and general_configurations both end up empty
        assert "Removed empty capabilities" in caplog.text
        assert "Fetch Issues" in caplog.text
        assert "general_configurations" in caplog.text
        # Sanity: Automation survives
        assert result["Automation"] == ["only_param"]
