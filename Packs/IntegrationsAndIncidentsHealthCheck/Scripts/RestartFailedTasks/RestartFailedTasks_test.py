import pytest
from RestartFailedTasks import *
from CommonServerPython import *

GET_INCIDENTS_RESPONSE = [{"id": "123"}]
GET_CONTEXT_RESPONSE_NO_FAILED_TASKS = [{"Contents": {"context": {}}}]
GET_CONTEXT_RESPONSE_WITH_FAILED_TASKS = [{"Contents": {"context": {"GetFailedTasks": [1, 2]}}}]
FAILED_TASKS = [
    {"Task ID": "1", "Incident ID": "1", "Playbook Name": "playbook1", "Task Name": "task1"},
    {"Task ID": "2", "Incident ID": "2", "Playbook Name": "playbook2", "Task Name": "task2"},
]
RESTARTED_TASKS = [
    {"IncidentID": "1", "TaskID": "1", "PlaybookName": "playbook1", "TaskName": "task1"},
    {"IncidentID": "2", "TaskID": "2", "PlaybookName": "playbook2", "TaskName": "task2"},
]


@pytest.mark.parametrize(
    "incidents, error, context",
    [
        (None, True, None),
        (GET_INCIDENTS_RESPONSE, True, None),
        (GET_INCIDENTS_RESPONSE, False, GET_CONTEXT_RESPONSE_NO_FAILED_TASKS),
    ],
)
def test_get_context_no_incidents_or_context(mocker, incidents, error, context):
    """
    Given: No incidents in XSOAR were created or the context data is empty or the key 'GetFailedTasks' is not
        in the context
    When: When running the script from the war-room or running from an incident without running !GetFailesTasks priorly
    Then: Return an error

    """
    import RestartFailedTasks as rft

    rft.is_error = lambda x: error
    rft.get_error = lambda x: "error"
    mocker.patch.object(demisto, "incidents", return_value=incidents)
    mocker.patch.object(demisto, "executeCommand", return_value=context)
    with pytest.raises(DemistoException) as e:
        check_context()
        if not e:
            pytest.fail()


@pytest.mark.parametrize("incidents, context", [(GET_INCIDENTS_RESPONSE, GET_CONTEXT_RESPONSE_WITH_FAILED_TASKS)])
def test_get_context(mocker, incidents, context):
    """
    Given: Context after running 'GetFailedTasks'
    When: Running this script after running 'GetFailedTasks'
    Then: Return failed tasks

    """
    import RestartFailedTasks as rft

    rft.is_error = lambda x: False
    rft.get_error = lambda x: "error"
    mocker.patch.object(demisto, "incidents", return_value=incidents)
    mocker.patch.object(demisto, "executeCommand", return_value=context)
    assert check_context() == context[0].get("Contents", {}).get("context", {}).get("GetFailedTasks")


@pytest.mark.parametrize("is_above_6_2", [True, False])
def test_restart_tasks(mocker, is_above_6_2):
    """
    Given: Failed tasks generated from GetFailedTasks command
    When: When running the script
    Then: restart the Failed tasks

    """
    mocker.patch("CommonServerPython.is_demisto_version_ge", return_value=is_above_6_2)
    mocker.patch.object(demisto, "executeCommand", return_value="")
    assert restart_tasks(FAILED_TASKS, 0, 10) == (2, RESTARTED_TASKS)
