import json
from pathlib import Path

import demistomock as demisto  # noqa: F401
import pytest
from CommonServerPython import *  # noqa: F401

import HealthCheckParseResults
from HealthCheckParseResults import (
    THRESHOLDS,
    classify_key,
    handle_agent_policy_assignment,
    handle_edr_disabled_endpoints,
    handle_noisy_issue_categories,
    load_context_data,
    main,
    parse_collect_results,
)

TEST_DATA_DIR = Path(__file__).parent / "test_data"


def load_mock_context() -> dict:
    with open(TEST_DATA_DIR / "results-mock.json") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# classify_key
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_key, expected",
    [
        ("Health Check - Agent and Asset - Agent Policy Assignment xql_1773742279543", "AgentPolicyAssignment"),
        ("Health Check - Agent and Asset-HC-test - EDR Disabled Endpoints xql_1773148595080", "EDRDisabledEndpoints"),
        (
            "Health Check - Ingestion/Integration/Configuration-HC-test - CIE - Ingested Domains xql_1773145541487",
            "CIEIngestedDomains",
        ),
        (
            "Health Check - Ingestion/Integration/Configuration-HC-test - Health Issues - 7d xql_1773664559419",
            "HealthIssues",
        ),
        ("Health Check - Issues/Cases-HC-test - Noisy Issue Categories - 30d xql_1772798270735", "NoisyIssueCategories"),
        ("Health Check - Issues/Cases-HC-test - Non-Prevented Issues xql_1773144919377", "NonPreventedIssues"),
        ("Noisy Issue Categories - 30d", "NoisyIssueCategories"),
        ("Correlation Rules Without Automation", "CorrelationRulesWithoutAutomation"),
        ("Some Unrelated Widget xql_123", None),
    ],
)
def test_classify_key(raw_key, expected):
    """
    Given: Raw widget keys as they appear in HealthCheck.CollectResults, with dashboard prefixes,
           XQL-ID suffixes and time-window suffixes.
    When: classify_key is called.
    Then: The canonical widget name is returned, or None for an unknown widget.
    """
    assert classify_key(raw_key) == expected


# ---------------------------------------------------------------------------
# handle_agent_policy_assignment
# ---------------------------------------------------------------------------


def test_agent_policy_assignment_empty_rows():
    """
    Given: No policy rows.
    When: handle_agent_policy_assignment is called.
    Then: No action items are returned.
    """
    assert handle_agent_policy_assignment([], THRESHOLDS["AgentPolicyAssignment"]) == []


def test_agent_policy_assignment_zero_agents():
    """
    Given: Policy rows whose counts sum to zero.
    When: handle_agent_policy_assignment is called.
    Then: No action items are returned and no division by zero occurs.
    """
    rows = [{"assigned_prevention_policy": "Default", "policy_count": 0}]
    assert handle_agent_policy_assignment(rows, THRESHOLDS["AgentPolicyAssignment"]) == []


def test_agent_policy_assignment_healthy_distribution():
    """
    Given: Agents spread across non-default policies, none small and none dominant.
    When: handle_agent_policy_assignment is called.
    Then: No action items are returned.
    """
    rows = [
        {"assigned_prevention_policy": "Servers", "policy_count": 40},
        {"assigned_prevention_policy": "Workstations", "policy_count": 40},
        {"assigned_prevention_policy": "Executives", "policy_count": 20},
    ]
    assert handle_agent_policy_assignment(rows, THRESHOLDS["AgentPolicyAssignment"]) == []


def test_agent_policy_assignment_default_policy_over_threshold():
    """
    Given: 40% of agents are on a policy whose name contains "default" (threshold is 30%).
    When: handle_agent_policy_assignment is called.
    Then: Exactly one action item is returned, reporting the 40% default-policy share.
    """
    rows = [
        {"assigned_prevention_policy": "Default Policy", "policy_count": 40},
        {"assigned_prevention_policy": "Servers", "policy_count": 30},
        {"assigned_prevention_policy": "Workstations", "policy_count": 30},
    ]
    items = handle_agent_policy_assignment(rows, THRESHOLDS["AgentPolicyAssignment"])

    assert len(items) == 1
    assert items[0]["description"].startswith("40% of endpoints are operating on the Default Policy")
    assert items[0]["category"] == "Agent & Asset"
    assert items[0]["severity"] == "Medium"


def test_agent_policy_assignment_small_policies():
    """
    Given: Two policies with 3 or fewer agents (max_small_policy_agents is 3).
    When: handle_agent_policy_assignment is called.
    Then: One action item reports 2 small policies.
    """
    rows = [
        {"assigned_prevention_policy": "Servers", "policy_count": 50},
        {"assigned_prevention_policy": "Workstations", "policy_count": 45},
        {"assigned_prevention_policy": "Lab", "policy_count": 3},
        {"assigned_prevention_policy": "Test", "policy_count": 2},
    ]
    items = handle_agent_policy_assignment(rows, THRESHOLDS["AgentPolicyAssignment"])

    assert len(items) == 1
    assert items[0]["description"] == "Found 2 policies with \u2264 3 agents assigned."


def test_agent_policy_assignment_dominant_policy():
    """
    Given: One non-default policy holds 95 of 100 agents (max_dominant_policy_pct is 90).
    When: handle_agent_policy_assignment is called.
    Then: A dominant-policy action item naming that policy is returned.
    """
    rows = [
        {"assigned_prevention_policy": "Corp", "policy_count": 95},
        {"assigned_prevention_policy": "Servers", "policy_count": 5},
    ]
    items = handle_agent_policy_assignment(rows, THRESHOLDS["AgentPolicyAssignment"])

    assert len(items) == 1
    assert '95%+ of agents are under one single policy ("Corp")' in items[0]["description"]


# ---------------------------------------------------------------------------
# handle_edr_disabled_endpoints
# ---------------------------------------------------------------------------


def test_edr_disabled_endpoints_reports_names():
    """
    Given: Two endpoints with EDR disabled.
    When: handle_edr_disabled_endpoints is called.
    Then: One action item lists both endpoint names and the count.
    """
    rows = [{"name": "host-a"}, {"name": "host-b"}]
    items = handle_edr_disabled_endpoints(rows, THRESHOLDS["EDRDisabledEndpoints"])

    assert len(items) == 1
    assert items[0]["description"] == "EDR is disabled on 2 endpoints: host-a, host-b"
    assert items[0]["severity"] == "Medium"


def test_edr_disabled_endpoints_no_rows():
    """
    Given: No endpoints with EDR disabled.
    When: handle_edr_disabled_endpoints is called.
    Then: No action items are returned.
    """
    assert handle_edr_disabled_endpoints([], THRESHOLDS["EDRDisabledEndpoints"]) == []


# ---------------------------------------------------------------------------
# handle_noisy_issue_categories
# ---------------------------------------------------------------------------


def test_noisy_issue_categories_empty_rows():
    """
    Given: No issue category rows.
    When: handle_noisy_issue_categories is called.
    Then: No action items are returned.
    """
    assert handle_noisy_issue_categories([], THRESHOLDS["NoisyIssueCategories"]) == []


def test_noisy_issue_categories_single_category_over_threshold():
    """
    Given: One non-correlation category produces 60% of all alerts (threshold is 50%).
    When: handle_noisy_issue_categories is called.
    Then: One action item names that category.
    """
    rows = [
        {"xdm.issue.detection.method": "BIOC", "Alerts": 60},
        {"xdm.issue.detection.method": "ANALYTICS", "Alerts": 40},
    ]
    items = handle_noisy_issue_categories(rows, THRESHOLDS["NoisyIssueCategories"])

    assert len(items) == 1
    assert items[0]["description"].startswith("Category BIOC is generating a disproportionately high")


def test_noisy_issue_categories_correlation_exceeds_multiplier():
    """
    Given: Correlation alerts (45) exceed 2x the non-correlation alerts (20), and no single
           category is over 50%.
    When: handle_noisy_issue_categories is called.
    Then: One correlation-volume action item is returned with the alert counts.
    """
    # Correlation volume is split across two categories so neither crosses the 50% single-category rule.
    rows = [
        {"xdm.issue.detection.method": "CORRELATION", "Alerts": 30},
        {"xdm.issue.detection.method": "CORRELATION_RULE_2", "Alerts": 15},
        {"xdm.issue.detection.method": "BIOC", "Alerts": 20},
    ]
    items = handle_noisy_issue_categories(rows, THRESHOLDS["NoisyIssueCategories"])

    assert len(items) == 1
    assert "(45 vs 20 alerts, 2x threshold)" in items[0]["description"]


def test_noisy_issue_categories_balanced():
    """
    Given: Alerts spread evenly with correlation volume under 2x non-correlation volume.
    When: handle_noisy_issue_categories is called.
    Then: No action items are returned.
    """
    rows = [
        {"xdm.issue.detection.method": "CORRELATION", "Alerts": 30},
        {"xdm.issue.detection.method": "BIOC", "Alerts": 35},
        {"xdm.issue.detection.method": "ANALYTICS", "Alerts": 35},
    ]
    assert handle_noisy_issue_categories(rows, THRESHOLDS["NoisyIssueCategories"]) == []


# ---------------------------------------------------------------------------
# load_context_data
# ---------------------------------------------------------------------------


def test_load_context_data_dict(mocker):
    """
    Given: The incident context holds HealthCheck as a dict.
    When: load_context_data is called.
    Then: The dict is returned as-is.
    """
    mocker.patch.object(demisto, "context", return_value={"HealthCheck": {"CollectResults": {"a": []}}})
    assert load_context_data() == {"CollectResults": {"a": []}}


def test_load_context_data_list_takes_first(mocker):
    """
    Given: The incident context holds HealthCheck as a list of dicts.
    When: load_context_data is called.
    Then: The first element is returned.
    """
    mocker.patch.object(demisto, "context", return_value={"HealthCheck": [{"first": 1}, {"second": 2}]})
    assert load_context_data() == {"first": 1}


@pytest.mark.parametrize(
    "context, message",
    [
        ({}, "HealthCheck key not found in incident context"),
        ({"HealthCheck": "not-a-dict"}, "unexpected type str"),
    ],
)
def test_load_context_data_invalid(mocker, context, message):
    """
    Given: The incident context has no HealthCheck key, or HealthCheck is not a dict.
    When: load_context_data is called.
    Then: A ValueError with a descriptive message is raised.
    """
    mocker.patch.object(demisto, "context", return_value=context)
    with pytest.raises(ValueError, match=message):
        load_context_data()


# ---------------------------------------------------------------------------
# parse_collect_results
# ---------------------------------------------------------------------------


def test_parse_collect_results_skips_duplicates_and_unknown(mocker):
    """
    Given: Collect results containing the same widget under two dashboard prefixes plus an
           unknown widget.
    When: parse_collect_results is called.
    Then: The duplicate widget is evaluated only once and the unknown widget is ignored.
    """
    edr_rows = [{"name": "host-a"}]
    collect_results = {
        "Health Check - Agent and Asset - EDR Disabled Endpoints xql_1": edr_rows,
        "Health Check - Agent and Asset-HC-test - EDR Disabled Endpoints xql_1": edr_rows,
        "Totally Unknown Widget": [{"x": 1}],
    }
    items = parse_collect_results(collect_results)

    assert len(items) == 1
    assert items[0]["description"] == "EDR is disabled on 1 endpoints: host-a"


def test_parse_collect_results_skips_non_list_rows():
    """
    Given: A recognised widget whose rows are not a list.
    When: parse_collect_results is called.
    Then: The widget is skipped without raising.
    """
    assert parse_collect_results({"EDR Disabled Endpoints": {"name": "host-a"}}) == []


def test_parse_collect_results_handler_failure_is_logged_with_traceback(mocker):
    """
    Given: A widget handler that raises an exception.
    When: parse_collect_results is called.
    Then: The error is logged with the full traceback and parsing continues.
    """

    def broken_handler(rows, cfg):
        raise RuntimeError("boom")

    mocker.patch.dict(HealthCheckParseResults.WIDGET_HANDLERS, {"EDRDisabledEndpoints": broken_handler})
    error_log = mocker.patch.object(demisto, "error")

    assert parse_collect_results({"EDR Disabled Endpoints": [{"name": "host-a"}]}) == []

    logged = error_log.call_args[0][0]
    assert "handler for 'EDRDisabledEndpoints' raised boom" in logged
    assert "Traceback (most recent call last)" in logged


def test_parse_collect_results_with_mock_data():
    """
    Given: The real CollectResults from test_data/results-mock.json.
    When: parse_collect_results is called.
    Then: The Agent Policy Assignment, EDR Disabled Endpoints and Noisy Issue Categories
          widgets produce action items, each evaluated only once despite duplicate keys.
    """
    collect_results = load_mock_context()["HealthCheck"]["CollectResults"]

    items = parse_collect_results(collect_results)
    descriptions = [item["description"] for item in items]

    edr_items = [d for d in descriptions if d.startswith("EDR is disabled on")]
    assert edr_items == ["EDR is disabled on 1 endpoints: emre-win3-client"]
    assert any("policies with" in d for d in descriptions)
    assert all(set(item) == {"category", "description", "resolution", "severity"} for item in items)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def test_main_returns_action_items(mocker):
    """
    Given: The incident context from test_data/results-mock.json.
    When: main is called.
    Then: return_results receives CommandResults with HealthCheck.ActionableItems and a
          markdown table.
    """
    mocker.patch.object(demisto, "context", return_value=load_mock_context())
    return_results_mock = mocker.patch.object(HealthCheckParseResults, "return_results")

    main()

    command_results = return_results_mock.call_args[0][0]
    assert command_results.outputs_prefix == "HealthCheck"
    assert command_results.outputs["ActionableItems"]
    assert "HealthCheck Actionable Items" in command_results.readable_output


def test_main_empty_collect_results_warns(mocker):
    """
    Given: HealthCheck exists in context but CollectResults is empty.
    When: main is called.
    Then: A warning is returned and no results are produced.
    """
    mocker.patch.object(demisto, "context", return_value={"HealthCheck": {"CollectResults": {}}})
    warning_mock = mocker.patch.object(HealthCheckParseResults, "return_warning")
    return_results_mock = mocker.patch.object(HealthCheckParseResults, "return_results")

    main()

    warning_mock.assert_called_once_with("HealthCheck.CollectResults is empty — nothing to parse")
    return_results_mock.assert_not_called()


def test_main_missing_context_calls_return_error(mocker):
    """
    Given: The incident context has no HealthCheck key.
    When: main is called.
    Then: return_error is called with the failure message and the original exception,
          and the traceback is logged.
    """
    mocker.patch.object(demisto, "context", return_value={})
    error_log = mocker.patch.object(demisto, "error")
    return_error_mock = mocker.patch.object(HealthCheckParseResults, "return_error")

    main()

    message = return_error_mock.call_args[0][0]
    assert "Failed to execute HealthCheckParseResults" in message
    assert "HealthCheck key not found in incident context" in message
    assert isinstance(return_error_mock.call_args.kwargs["error"], ValueError)
    assert "Traceback (most recent call last)" in error_log.call_args[0][0]
