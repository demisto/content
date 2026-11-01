import importlib
import sys

import demistomock as demisto

MODULE_NAME = "HealthCheckCustomScripts"


def run_script(mocker, scripts):
    """Import the script fresh with demisto calls mocked and return recorded calls."""
    recorded_calls = []
    api_response = [{"Type": 1, "Contents": {"response": {"scripts": scripts}}}]

    def fake_execute_command(command, args=None):
        recorded_calls.append((command, args))
        if command == "core-api-post":
            return api_response
        return []

    mocker.patch.object(demisto, "executeCommand", side_effect=fake_execute_command)
    mocker.patch.object(demisto, "results")
    sys.modules.pop(MODULE_NAME, None)
    importlib.import_module(MODULE_NAME)
    return recorded_calls


def get_health_details(calls):
    """Return the health details list passed to setIncident as a field->value mapping."""
    for command, args in calls:
        if command == "setIncident":
            return {entry["field"]: entry["value"] for entry in args["healthcheckcustomscriptdetails"]}
    raise AssertionError("setIncident was never called")


def test_custom_and_detached_scripts_are_counted(mocker):
    """
    Given: Four scripts, one custom and one detached.
    When: The script runs.
    Then: Totals and percentages reflect the custom and detached counts.
    """
    scripts = [
        {"system": True, "detached": False},
        {"system": False, "detached": False},
        {"system": True, "detached": True},
        {"system": True, "detached": False},
    ]

    details = get_health_details(run_script(mocker, scripts))

    assert details["Total Automation Scripts"] == 4
    assert details["Custom Scripts Count"] == 1
    assert details["Custom Scripts Percentage"] == "25.0%"
    assert details["Detached Scripts Count"] == 1
    assert details["Detached Scripts Percentage"] == "25.0%"


def test_empty_script_list_avoids_division_by_zero(mocker):
    """
    Given: The search endpoint returns no scripts.
    When: The script runs.
    Then: Counts are zero and percentages render as 0% rather than raising.
    """
    details = get_health_details(run_script(mocker, []))

    assert details["Total Automation Scripts"] == 0
    assert details["Custom Scripts Count"] == 0
    assert details["Custom Scripts Percentage"] == "0%"
    assert details["Detached Scripts Percentage"] == "0%"


def test_missing_keys_default_to_system_and_detached(mocker):
    """
    Given: A script entry with no system or detached keys.
    When: The script runs.
    Then: It is treated as a system script that is detached, per the defaults.
    """
    details = get_health_details(run_script(mocker, [{}]))

    assert details["Custom Scripts Count"] == 0
    assert details["Detached Scripts Count"] == 1
