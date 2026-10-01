import importlib
import sys

import demistomock as demisto

MODULE_NAME = "HealthCheckCustomDashboards"


def run_script(mocker, api_response):
    """Import the script fresh with demisto calls mocked and return recorded calls."""
    recorded_calls = []

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


def test_dashboard_count_is_written_to_incident(mocker):
    """
    Given: The dashboards API returns an objects_count value.
    When: The script runs.
    Then: The count is stored on the incident via setIncident.
    """
    api_response = [{"Type": 1, "Contents": {"response": {"objects_count": 7}}}]

    calls = run_script(mocker, api_response)

    set_incident_calls = [args for command, args in calls if command == "setIncident"]
    assert set_incident_calls == [{"healthcheckcustomdashboardcount": 7}]


def test_dashboards_endpoint_is_queried(mocker):
    """
    Given: A valid dashboards API response.
    When: The script runs.
    Then: The dashboards get endpoint is called with an empty request_data body.
    """
    api_response = [{"Type": 1, "Contents": {"response": {"objects_count": 0}}}]

    calls = run_script(mocker, api_response)

    post_calls = [args for command, args in calls if command == "core-api-post"]
    assert post_calls == [{"uri": "/public_api/v1/dashboards/get", "body": {"request_data": {}}}]
