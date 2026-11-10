import importlib
import sys

import demistomock as demisto

MODULE_NAME = "HealthCheckCustomFields"


def run_script(mocker, fields):
    """Import the script fresh with demisto calls mocked and return recorded calls."""
    recorded_calls = []
    api_response = [{"Type": 1, "Contents": {"response": fields}}]

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
            return {entry["field"]: entry["value"] for entry in args["healthcheckcustomfielddetails"]}
    raise AssertionError("setIncident was never called")


def custom_field(field_id):
    """Build a field entry that qualifies as custom."""
    return {"id": field_id, "system": False, "XDRBuiltInField": False, "content": False}


def system_field(field_id):
    """Build a field entry that qualifies as system-owned."""
    return {"id": field_id, "system": True, "XDRBuiltInField": False, "content": False}


def test_custom_issue_and_case_fields_are_counted(mocker):
    """
    Given: Issue and case fields, one custom in each group.
    When: The script runs.
    Then: Custom counts and percentages are reported per group.
    """
    fields = [
        system_field("incident_one"),
        custom_field("incident_two"),
        system_field("case_one"),
        custom_field("case_two"),
    ]

    details = get_health_details(run_script(mocker, fields))

    assert details["Total Issue Fields"] == 2
    assert details["Custom Issue Fields Count"] == 1
    assert details["Custom Issue Fields Percentage"] == "50.0%"
    assert details["Total Case Fields"] == 2
    assert details["Custom Case Fields Count"] == 1
    assert details["Custom Case Fields Percentage"] == "50.0%"


def test_indicator_fields_are_ignored(mocker):
    """
    Given: Only indicator-prefixed fields.
    When: The script runs.
    Then: Neither issue nor case totals are incremented.
    """
    fields = [custom_field("indicator_one"), custom_field("indicator_two")]

    details = get_health_details(run_script(mocker, fields))

    assert details["Total Issue Fields"] == 0
    assert details["Total Case Fields"] == 0


def test_fields_with_trigger_scripts_are_counted(mocker):
    """
    Given: Fields where some declare a change-trigger script.
    When: The script runs.
    Then: Only fields with a non-empty script are counted.
    """
    with_script = system_field("incident_scripted")
    with_script["script"] = "SomeAutomation"
    without_script = system_field("incident_plain")
    without_script["script"] = ""

    details = get_health_details(run_script(mocker, [with_script, without_script]))

    assert details["Issue and Case Fields with Trigger Scripts"] == 1


def test_empty_field_list_avoids_division_by_zero(mocker):
    """
    Given: The incident fields endpoint returns no fields.
    When: The script runs.
    Then: Percentages render as 0% rather than raising.
    """
    details = get_health_details(run_script(mocker, []))

    assert details["Custom Issue Fields Percentage"] == "0%"
    assert details["Custom Case Fields Percentage"] == "0%"


def test_incident_fields_endpoint_is_queried(mocker):
    """
    Given: A valid incident fields response.
    When: The script runs.
    Then: The sessionDataSync incidentFields endpoint is called.
    """
    calls = run_script(mocker, [])

    get_calls = [args for command, args in calls if command == "core-api-get"]
    assert get_calls == [{"uri": "/sessionDataSync/incidentFields", "body": {}}]
