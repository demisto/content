import importlib
import sys

import demistomock as demisto

MODULE_NAME = "HealthCheckCustomLayouts"


def run_script(mocker, layouts):
    """Import the script fresh with demisto calls mocked and return recorded calls."""
    recorded_calls = []
    api_response = [{"Type": 1, "Contents": {"response": layouts}}]

    def fake_execute_command(command, args=None):
        recorded_calls.append((command, args))
        if command == "core-api-get":
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
            return {entry["field"]: entry["value"] for entry in args["healthcheckcustomlayoutdetails"]}
    raise AssertionError("setIncident was never called")


def test_custom_issue_and_case_layouts_are_counted(mocker):
    """
    Given: Incident and case layouts, some custom (no pack, not system).
    When: The script runs.
    Then: Custom counts and percentages are reported per group.
    """
    layouts = [
        {"group": "incident", "system": True, "packID": "SomePack"},
        {"group": "incident", "system": False, "packID": ""},
        {"group": "case", "system": False, "packID": ""},
        {"group": "case", "system": True, "packID": "SomePack"},
    ]

    details = get_health_details(run_script(mocker, layouts))

    assert details["Total Issue Layouts"] == 2
    assert details["Custom Issue Layouts Count"] == 1
    assert details["Custom Issue Layouts Percentage"] == "50.0%"
    assert details["Total Case Layouts"] == 2
    assert details["Custom Case Layouts Count"] == 1
    assert details["Custom Case Layouts Percentage"] == "50.0%"


def test_indicator_layouts_are_ignored(mocker):
    """
    Given: Only indicator-group layouts.
    When: The script runs.
    Then: Neither issue nor case totals are incremented.
    """
    layouts = [
        {"group": "indicator", "system": False, "packID": ""},
        {"group": "indicator", "system": False, "packID": ""},
    ]

    details = get_health_details(run_script(mocker, layouts))

    assert details["Total Issue Layouts"] == 0
    assert details["Total Case Layouts"] == 0


def test_empty_layout_list_avoids_division_by_zero(mocker):
    """
    Given: The layouts endpoint returns no layouts.
    When: The script runs.
    Then: Percentages render as 0% rather than raising.
    """
    details = get_health_details(run_script(mocker, []))

    assert details["Custom Issue Layouts Percentage"] == "0%"
    assert details["Custom Case Layouts Percentage"] == "0%"


def test_layouts_endpoint_is_queried(mocker):
    """
    Given: A valid layouts response.
    When: The script runs.
    Then: The sessionDataSync layouts endpoint is called.
    """
    calls = run_script(mocker, [])

    get_calls = [args for command, args in calls if command == "core-api-get"]
    assert get_calls == [{"uri": "/sessionDataSync/layouts", "body": {}}]
