import json
from pathlib import Path

import pytest
import yaml

from connector_param_mapper import (
    _filter_hidden_params,
    _handle_test_module,
    _required_param_names,
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
# Phase 1 - capability decision tests
# ---------------------------------------------------------------------------
class TestDecideCapabilities:

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
               'eventcollector', three commands and no 'get-events' style
               command.
        When:  decide_capabilities is called.
        Then:  Both 'Log Collection' and 'Automation' are present (no early
               exit; event-collector sub-rule is satisfied because there are
               >= 3 commands with non-fetch commands).
        """
        # isfetchevents true but name has no eventcollector and no get-events cmd
        yml = _build_yml(
            name="SomeSiem",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "siem-get-alert"},
                    {"name": "siem-list-cases"},
                    {"name": "siem-do-action"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" in result  # event collector with >= 3 commands

    def test_log_collection_early_exit_event_collector_name(self):
        """
        Given: An event-collector YML (isfetchevents=True only) whose name
               contains 'event collector' (with a space) AND has exactly one
               non-get-events command.
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit does NOT fire (the single command is not a
               get-events command, so _is_pure_event_collector returns False).
               'Log Collection' is present. Because this is an event collector
               with fewer than 3 commands, the event-collector sub-rule
               suppresses 'Automation'.
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
            script={"isfetch": True, "isfetch:platform": False, "isfetchevents": True, "commands": []}
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
               isfetchassets=True whose name contains 'eventcollector', with
               only TWO commands.
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit must NOT fire — both 'Log Collection' and
               'Fetch Assets and Vulnerabilities' must remain. Because the
               integration IS an event collector with fewer than 3 commands,
               the event-collector sub-rule suppresses 'Automation'.
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
        # Event collector with only 2 commands → Automation NOT added.
        assert "Automation" not in result
        assert "general_configurations" in result

    def test_pure_event_collector_still_short_circuits(self):
        """
        Given: A pure event-collector YML where isfetchevents is the only
               fetch flag, the name contains 'event collector' (with space),
               and the ONLY command is a get-events command (no other
               commands).
        When:  decide_capabilities is called.
        Then:  Rule 2's early-exit fires and returns the minimal mapping
               {general_configurations, Log Collection} (regression guard for
               the multi-purpose fix above). 'Automation' is never added
               because the early-exit returns before Rule 6.
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
        assert result == {
            "general_configurations": [],
            "Log Collection": [],
        }


# ---------------------------------------------------------------------------
# Phase 2 - param mapping tests
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
               (Phase 2.1 skips defaulted params).
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
        # Empty buckets are preserved (no cleanup pass), so the key remains.
        assert "general_configurations" in result
        assert "api_key" not in result["general_configurations"]

    def test_single_capability_shortcut(self):
        """
        Given: A capabilities mapping with exactly 2 keys
               (general_configurations + Log Collection) and several commands
               whose params overlap with test-module.
        When:  map_params_to_capabilities is called.
        Then:  Phase 2.2 shortcut fires: all unique command params (minus the
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
        Then:  Phase 2.3 routes 'fetch-incidents' params to 'Fetch Issues'
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

    def test_mirroring_commands_ignored_multi_capability(self):
        """
        Given: A multi-capability mapping (Fetch Issues + Automation) plus
               the mirroring commands (get-remote-data,
               get-modified-remote-data, update-remote-system,
               get-mapping-fields) each carrying mirroring-only params.
        When:  map_params_to_capabilities is called.
        Then:  The mirroring params are NOT routed into any capability
               (Automation stays empty); only the real vendor param lands
               in Automation.
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
                "get-remote-data": ["mirror_direction"],
                "get-modified-remote-data": ["mirror_limit"],
                "update-remote-system": ["mirror_tags"],
                "get-mapping-fields": ["close_incident"],
                "vendor-do-stuff": ["arg1"],
            },
        }
        param_defaults = {
            "mirror_direction": "Both",
            "mirror_limit": 100,
            "mirror_tags": "comments",
            "close_incident": True,
            "arg1": "x",
        }
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["Automation"] == ["arg1"]
        for cap, params in result.items():
            assert "mirror_direction" not in params
            assert "mirror_limit" not in params
            assert "mirror_tags" not in params
            assert "close_incident" not in params

    def test_mirroring_commands_ignored_single_capability_shortcut(self):
        """
        Given: A single non-general capability plus mirroring commands that
               carry mirroring-only params.
        When:  map_params_to_capabilities is called (Phase 2.2 shortcut).
        Then:  The mirroring params are NOT dumped into the single
               capability; only the real command params land there.
        """
        capabilities = {
            "general_configurations": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": [],
                "get-remote-data": ["mirror_direction"],
                "update-remote-system": ["mirror_tags"],
                "vendor-do-stuff": ["arg1"],
            },
        }
        param_defaults = {
            "mirror_direction": "Both",
            "mirror_tags": "comments",
            "arg1": "x",
        }
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["Automation"] == ["arg1"]
        assert "mirror_direction" not in result["Automation"]
        assert "mirror_tags" not in result["Automation"]

    def test_multi_capability_other_command_to_automation(self):
        """
        Given: A multi-capability mapping (Fetch Issues + Automation) but
               only generic vendor commands that don't match
               COMMAND_TO_CAPABILITY.
        When:  map_params_to_capabilities is called.
        Then:  All vendor params fall back to 'Automation' and 'Fetch Issues'
               remains (empty), since empty buckets are preserved.
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
        # Empty buckets are preserved (no cleanup pass).
        assert result["Fetch Issues"] == []

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
        # The param should not be placed anywhere; empty buckets are preserved
        # (no cleanup pass), so look them up directly.
        assert "missing_param" not in result["Automation"]
        assert "missing_param" not in result["general_configurations"]
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
        Then:  With only 2 capabilities, Phase 2.2 shortcut fires and the
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
        # With only 2 capabilities, Phase 2.2 shortcut places everything in
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
        # Empty buckets are preserved (no cleanup pass).
        assert result["Fetch Issues"] == []

    def test_dedup_param_in_multiple_capabilities_moves_to_general(self):
        """
        Given: A param ('shared') that is referenced by two different
               commands routed to two different capabilities, plus a unique
               param.
        When:  map_params_to_capabilities is called.
        Then:  Phase 2.4 dedup moves 'shared' into general_configurations and
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
        # After dedup, 'Fetch Issues' has no params left but is preserved
        # (no cleanup pass). 'Automation' still has 'unique'.
        assert result["Fetch Issues"] == []
        assert "shared" not in result["Automation"]
        assert "unique" in result["Automation"]

    def test_test_module_param_also_in_capability_stays_in_capability(self):
        """
        Given: A non-required param ('url') read by test-module AND by a real
               capability command (fetch-incidents).
        When:  map_params_to_capabilities is called.
        Then:  The param is owned by its capability ('Fetch Issues') and is NOT
               forced into general_configurations. test-module only reads it to
               validate the connection, so its test-module appearance must not
               promote it to general (Correction 3 in _handle_test_module).
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
                "fetch-incidents": ["url"],
            },
        }
        param_defaults = {}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        # Not promoted to general because a real capability command uses it.
        assert "url" not in result["general_configurations"]
        # Owned by the capability that actually consumes it.
        assert result["Fetch Issues"] == ["url"]


# ---------------------------------------------------------------------------
# Phase 2.1.5 - manual command-to-capability mapping tests
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
               general_configurations by Phase 2.4 dedup.
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

    def test_manual_mapping_with_existing_capability_no_duplicate_keys(self):
        """
        Given: A manual override routing 'my-cmd' to 'Automation' (which
               already exists in the initial mapping).
        When:  map_params_to_capabilities is called.
        Then:  No duplicate 'Automation' key is created and 'filter' appears
               exactly once (Phase 2.3 must skip the manually-handled command).
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
# Phase 2.6 - hidden param filter tests
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
      - The literal ``longRunningPort`` config param is routed there (Phase 2.0).
      - The ``long-running-execution`` command's params are routed there
        (Phase 2.3 via ``_resolve_target_capability``).

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
               result, ``longRunningPort`` is placed in it (Phase 2.0), AND the
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

        # Phase 2.0 - longRunningPort routed to suggested capability
        assert "longRunningPort" in result["Log Collection"]
        # Phase 2.3 - long-running-execution params routed to suggested capability
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
               Phase 2.0 (skipped due to no override).
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
        # longRunningPort is NOT auto-routed by Phase 2.0 (no override)
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
        # And longRunningPort is NOT in general_configurations (empty buckets
        # are preserved, so the key still exists but without the param).
        assert "longRunningPort" not in result.get("general_configurations", [])

    def test_no_long_running_flag_dict_ignored(self):
        """
        Given: An integration whose id IS in the dict (``Akamai WAF SIEM``) but
               does NOT declare ``longRunning: true`` (e.g., longRunning
               flag absent or false).
        When:  decide_capabilities + map_params_to_capabilities are called.
        Then:  The dict is ignored entirely. No suggested-capability key added
               by Rule 7; ``longRunningPort`` (if present) is not routed by
               Phase 2.0; the ``long-running-execution`` command (if present)
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
# Empty capabilities are preserved (no cleanup pass)
# ---------------------------------------------------------------------------
class TestEmptyCapabilitiesPreserved:
    """Tests verifying that empty capability buckets (including
    ``general_configurations``) are PRESERVED in the final result — the
    previous Phase 2.7 cleanup pass has been removed."""

    def test_capability_emptied_by_dedup_is_preserved(self):
        """
        Given: A param routed to two capabilities so dedup moves it to
               general_configurations, leaving one of the source capabilities
               empty.
        When:  map_params_to_capabilities is called.
        Then:  The emptied capability remains in the final result (empty);
               no cleanup pass removes it.
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
        assert result["Fetch Issues"] == []
        assert result["Automation"] == []
        assert result["general_configurations"] == ["shared"]

    def test_capability_emptied_by_hidden_filter_is_preserved(self):
        """
        Given: A capability that contains only params that are hidden on
               the platform (via integration_yml).
        When:  map_params_to_capabilities is called with the integration_yml.
        Then:  Phase 2.6 hidden filter strips all params, but the now-empty
               capability is preserved (no cleanup pass).
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
        # Phase 2.6 stripped 'vendor_arg' from Automation; the empty bucket and
        # the empty general_configurations are both preserved.
        assert result["Automation"] == []
        assert result["general_configurations"] == []

    def test_empty_general_configurations_is_preserved(self):
        """
        Given: A capabilities setup that ends with an empty
               general_configurations bucket (no test-module-without-default
               and no duplicates to demote).
        When:  map_params_to_capabilities is called.
        Then:  general_configurations is preserved (empty), even when all
               params landed under another capability.
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
        # general_configurations is empty but preserved
        assert result["general_configurations"] == []

    def test_non_empty_capabilities_are_preserved(self):
        """
        Given: A capabilities mapping where every bucket ends with at least
               one param.
        When:  map_params_to_capabilities is called.
        Then:  All keys are present with their expected params.
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

    def test_all_params_under_general_configurations_keeps_empty_buckets(self):
        """
        Given: A capabilities mapping with extra buckets, where every command
               param has no default and is shared so it collapses into
               general_configurations, leaving the other buckets empty.
        When:  map_params_to_capabilities is called.
        Then:  The empty non-general buckets are still present in the result
               (matching the new "don't clean up empty capabilities" rule).
        """
        capabilities = {
            "general_configurations": [],
            "Fetch Issues": [],
            "Automation": [],
        }
        command_params = {
            "integration": "X",
            "commands": {
                # 'common' is routed to Fetch Issues and Automation, then
                # deduped into general_configurations.
                "fetch-incidents": ["common"],
                "vendor-action": ["common"],
            },
        }
        param_defaults = {"common": 1}
        result = map_params_to_capabilities(
            capabilities, command_params, param_defaults
        )
        assert result["general_configurations"] == ["common"]
        assert result["Fetch Issues"] == []
        assert result["Automation"] == []


# ---------------------------------------------------------------------------
# Rule 6 — Automation for event collectors (command-count threshold)
# ---------------------------------------------------------------------------
class TestAutomationEventCollectorRule:
    """Tests for the event-collector sub-rule of Rule 6: an event collector
    (``script.isfetchevents`` is True) only gets the ``Automation`` capability
    when it has at least one non-fetch command AND a total of >= 3 commands."""

    def test_event_collector_two_commands_no_automation(self):
        """
        Given: An event collector (isfetchevents=True) with only TWO commands,
               at least one of which is a non-fetch command.
        When:  decide_capabilities is called.
        Then:  'Automation' is NOT added (fewer than 3 commands).
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
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" in result

    def test_event_collector_three_commands_adds_automation(self):
        """
        Given: An event collector (isfetchevents=True) with THREE commands,
               including non-fetch commands.
        When:  decide_capabilities is called.
        Then:  'Automation' IS added (>= 3 commands and a non-fetch command
               exists).
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
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" in result

    def test_event_collector_three_fetch_commands_no_automation(self):
        """
        Given: An event collector with THREE commands that are ALL fetch-style
               (matching EXCLUDED_AUTOMATION_PATTERNS), so there is no
               non-fetch command.
        When:  decide_capabilities is called.
        Then:  'Automation' is NOT added — the non-fetch-command requirement
               still applies even when the count is >= 3.
        """
        yml = _build_yml(
            name="SomeSiem",
            script={
                "isfetchevents": True,
                "commands": [
                    {"name": "vendor-get-events"},
                    {"name": "vendor-other-get-events"},
                    {"name": "vendor-get-indicators"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Log Collection" in result
        assert "Automation" not in result

    def test_non_event_collector_one_command_adds_automation(self):
        """
        Given: A NON event-collector integration (isfetchevents not set) with a
               single non-fetch command.
        When:  decide_capabilities is called.
        Then:  'Automation' is added — the >= 3 threshold only applies to event
               collectors.
        """
        yml = _build_yml(
            name="SomeIntegration",
            script={
                "commands": [
                    {"name": "vendor-do-action"},
                ],
            },
        )
        result = decide_capabilities(yml)
        assert "Automation" in result


# ---------------------------------------------------------------------------
# Phase 2.1 — required test-module params elevated to the connection
# (other_connection in Auth Details), non-required keep general_configurations
# ---------------------------------------------------------------------------
class TestRequiredParamNames:
    def test_collects_only_required_true(self):
        yml = {
            "configuration": [
                {"name": "url", "required": True},
                {"name": "proxy", "required": False},
                {"name": "insecure"},  # missing -> not required
                {"name": "token", "required": True},
            ]
        }
        assert _required_param_names(yml) == {"url", "token"}

    def test_none_yml_returns_empty(self):
        assert _required_param_names(None) == set()

    def test_required_string_true_is_not_required(self):
        # Only the JSON boolean True counts; the string "true" does not.
        yml = {"configuration": [{"name": "url", "required": "true"}]}
        assert _required_param_names(yml) == set()


class TestTestModuleElevation:
    def test_required_test_module_param_elevated_not_in_general(self):
        """
        Given: A required test-module param with no default.
        When:  the mapper runs with the YML passed in.
        Then:  it is returned as elevated, kept out of every capability
               bucket (including general_configurations).
        """
        integration_yml = {
            "name": "X",
            "configuration": [{"name": "url", "required": True}],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {"test-module": ["url"], "vendor-action": ["arg1"]},
        }
        param_defaults = {"arg1": "x"}
        elevated: list[str] = []
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
            elevated_out=elevated,
        )
        assert elevated == ["url"]
        all_params = [p for params in result.values() for p in params]
        assert "url" not in all_params

    def test_non_required_test_module_param_goes_to_general(self):
        """
        Given: A NON-required test-module param with no default.
        When:  the mapper runs with the YML passed in.
        Then:  it keeps the historical behavior — lands in
               general_configurations and is NOT elevated.
        """
        integration_yml = {
            "name": "X",
            "configuration": [{"name": "lookback", "required": False}],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {"test-module": ["lookback"]},
        }
        elevated: list[str] = []
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            {},
            integration_yml=integration_yml,
            elevated_out=elevated,
        )
        assert elevated == []
        assert "lookback" in result["general_configurations"]

    def test_required_test_module_param_with_default_not_elevated(self):
        """A required test-module param that HAS a default is not elevated
        (the default already covers the connection-test path)."""
        integration_yml = {
            "name": "X",
            "configuration": [{"name": "first_fetch", "required": True}],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {"test-module": ["first_fetch"]},
        }
        param_defaults = {"first_fetch": "3 days"}
        elevated: list[str] = []
        map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
            elevated_out=elevated,
        )
        assert elevated == []

    def test_elevated_param_stripped_even_when_under_other_command(self):
        """A required test-module param that ALSO appears under a real
        command must still be stripped from capabilities (elevated wins)."""
        integration_yml = {
            "name": "X",
            "configuration": [{"name": "url", "required": True}],
            "script": {"commands": []},
        }
        capabilities = {"general_configurations": [], "Automation": []}
        command_params = {
            "integration": "X",
            "commands": {
                "test-module": ["url"],
                "vendor-action": ["url", "arg1"],
            },
        }
        param_defaults = {"arg1": "x"}
        elevated: list[str] = []
        result = map_params_to_capabilities(
            capabilities,
            command_params,
            param_defaults,
            integration_yml=integration_yml,
            elevated_out=elevated,
        )
        assert elevated == ["url"]
        all_params = [p for params in result.values() for p in params]
        assert "url" not in all_params

    def test_handle_test_module_returns_sorted_elevated(self):
        """_handle_test_module returns the elevated names sorted."""
        integration_yml = {
            "configuration": [
                {"name": "zeta", "required": True},
                {"name": "alpha", "required": True},
            ]
        }
        result = {"general_configurations": []}
        command_params = {"commands": {"test-module": ["zeta", "alpha"]}}
        elevated = _handle_test_module(result, command_params, {}, integration_yml)
        assert elevated == ["alpha", "zeta"]
        assert result["general_configurations"] == []

    def test_no_yml_keeps_legacy_general_behavior(self):
        """Without a YML, required-ness is unknown → nothing is elevated and
        test-module params fall back to general_configurations (legacy)."""
        result = {"general_configurations": []}
        command_params = {"commands": {"test-module": ["url"]}}
        elevated = _handle_test_module(result, command_params, {}, None)
        assert elevated == []
        assert result["general_configurations"] == ["url"]
