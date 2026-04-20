import json

import demistomock as demisto
import pytest
from CommonServerPython import DemistoException
from TroubleshootRestartFailedPlaybooks import (
    _extract_failed_tasks,
    filter_playbook_failures,
    get_alerts_with_errors,
    get_failed_tasks_for_alert,
    main,
    restart_all_failed_tasks,
    restart_task,
)

MOCK_ALERTS = [
    {"id": "1", "name": "Alert 1", "status": 1},
    {"id": "2", "name": "Alert 2", "status": 1},
    {"id": "3", "name": "Alert 3", "status": 1},
]

MOCK_FAILED_TASKS = [
    {
        "id": "task-101",
        "type": "regular",
        "state": "Error",
        "task": {"name": "Send Email", "scriptId": "|||send-mail"},
        "ancestors": ["Phishing Investigation"],
        "entries": ["entry-1"],
    },
    {
        "id": "task-102",
        "type": "regular",
        "state": "Error",
        "task": {"name": "IP Enrichment", "scriptId": "|||ip"},
        "ancestors": ["Phishing Investigation"],
        "entries": ["entry-2", "entry-3"],
    },
]

MOCK_FAILED_TASKS_WITH_PLAYBOOK_DUPLICATE = [
    {
        "id": "task-201",
        "type": "playbook",
        "state": "Error",
        "task": {"name": "Phishing Investigation"},
        "ancestors": ["Main Playbook"],
        "entries": ["entry-4"],
    },
    {
        "id": "task-202",
        "type": "regular",
        "state": "Error",
        "task": {"name": "Send Email", "scriptId": "|||send-mail"},
        "ancestors": ["Phishing Investigation"],
        "entries": ["entry-5"],
    },
]

MOCK_PLAYBOOK_RESPONSE = {
    "id": "1",
    "name": "Test Playbook",
    "tasks": {
        "0": {
            "id": "0",
            "type": "start",
            "state": "Completed",
            "task": {"name": "Start"},
            "ancestors": [],
        },
        "1": {
            "id": "task-101",
            "type": "regular",
            "state": "Error",
            "task": {"name": "Send Email", "scriptId": "|||send-mail"},
            "ancestors": ["Phishing Investigation"],
        },
        "2": {
            "id": "task-102",
            "type": "regular",
            "state": "Error",
            "task": {"name": "IP Enrichment", "scriptId": "|||ip"},
            "ancestors": ["Phishing Investigation"],
        },
        "3": {
            "id": "task-103",
            "type": "regular",
            "state": "Completed",
            "task": {"name": "Close Alert"},
            "ancestors": [],
        },
    },
}


class TestFilterPlaybookFailures:
    def test_filters_duplicate_playbook_tasks(self):
        """
        GIVEN:
            A list of failed tasks where a playbook-type task's name appears in the ancestors of another task.

        WHEN:
            filter_playbook_failures is called.

        THEN:
            The playbook-type task should be filtered out, keeping only the inner task.
        """
        result = filter_playbook_failures(MOCK_FAILED_TASKS_WITH_PLAYBOOK_DUPLICATE)
        assert len(result) == 1
        assert result[0]["id"] == "task-202"

    def test_keeps_all_regular_tasks(self):
        """
        GIVEN:
            A list of failed tasks with only regular-type tasks.

        WHEN:
            filter_playbook_failures is called.

        THEN:
            All tasks should be kept.
        """
        result = filter_playbook_failures(MOCK_FAILED_TASKS)
        assert len(result) == 2

    def test_empty_list(self):
        """
        GIVEN:
            An empty list.

        WHEN:
            filter_playbook_failures is called.

        THEN:
            An empty list should be returned.
        """
        assert filter_playbook_failures([]) == []


class TestExtractFailedTasks:
    def test_extracts_error_tasks(self):
        """
        GIVEN:
            A playbook response with tasks in various states.

        WHEN:
            _extract_failed_tasks is called with allowed_types {"regular"}.

        THEN:
            Only tasks in Error state with type "regular" should be returned.
        """
        result = _extract_failed_tasks(MOCK_PLAYBOOK_RESPONSE, {"regular"})
        assert len(result) == 2
        assert all(t.get("state") == "Error" for t in result)

    def test_filters_by_type(self):
        """
        GIVEN:
            A playbook response with tasks of different types.

        WHEN:
            _extract_failed_tasks is called with allowed_types {"condition"}.

        THEN:
            No tasks should be returned since none match the type.
        """
        result = _extract_failed_tasks(MOCK_PLAYBOOK_RESPONSE, {"condition"})
        assert result == []

    def test_returns_empty_for_none_playbook(self):
        """
        GIVEN:
            None as playbook input.

        WHEN:
            _extract_failed_tasks is called.

        THEN:
            An empty list should be returned.
        """
        result = _extract_failed_tasks(None, {"regular"})
        assert result == []

    def test_returns_empty_for_empty_playbook(self):
        """
        GIVEN:
            An empty dict as playbook input.

        WHEN:
            _extract_failed_tasks is called.

        THEN:
            An empty list should be returned.
        """
        result = _extract_failed_tasks({}, {"regular"})
        assert result == []

    def test_returns_empty_when_no_error_tasks(self):
        """
        GIVEN:
            A playbook with no tasks in Error state.

        WHEN:
            _extract_failed_tasks is called.

        THEN:
            An empty list should be returned.
        """
        playbook = {
            "tasks": {
                "0": {"id": "0", "type": "regular", "state": "Completed", "task": {"name": "Done"}},
            }
        }
        result = _extract_failed_tasks(playbook, {"regular"})
        assert result == []


class TestGetAlertsWithErrors:
    def test_returns_alerts(self, mocker):
        """
        GIVEN:
            A successful getIncidents response with alerts.

        WHEN:
            get_alerts_with_errors is called.

        THEN:
            The alerts should be returned.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": {"data": MOCK_ALERTS}, "Type": 1}],
        )
        result = get_alerts_with_errors(500)
        assert len(result) == 3

    def test_returns_empty_when_no_alerts(self, mocker):
        """
        GIVEN:
            A getIncidents response with no data.

        WHEN:
            get_alerts_with_errors is called.

        THEN:
            An empty list should be returned.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": {"data": None}, "Type": 1}],
        )
        result = get_alerts_with_errors(500)
        assert result == []

    def test_raises_on_error(self, mocker):
        """
        GIVEN:
            An error response from getIncidents.

        WHEN:
            get_alerts_with_errors is called.

        THEN:
            A DemistoException should be raised.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Type": 4, "Contents": "Error occurred"}],
        )
        with pytest.raises(DemistoException, match="Failed to query alerts"):
            get_alerts_with_errors(500)


class TestGetFailedTasksForAlert:
    def test_returns_tasks_via_internal_request(self, mocker):
        """
        GIVEN:
            A successful internal HTTP request returning a playbook with failed tasks.

        WHEN:
            get_failed_tasks_for_alert is called.

        THEN:
            The failed tasks should be returned.
        """
        mocker.patch.object(
            demisto,
            "internalHttpRequest",
            return_value={"statusCode": 200, "body": json.dumps(MOCK_PLAYBOOK_RESPONSE)},
        )
        result = get_failed_tasks_for_alert("1")
        assert len(result) == 2

    def test_falls_back_to_api_on_value_error(self, mocker):
        """
        GIVEN:
            An internal HTTP request that raises a ValueError.

        WHEN:
            get_failed_tasks_for_alert is called.

        THEN:
            It should fall back to core-api-get and return tasks.
        """
        mocker.patch.object(
            demisto,
            "internalHttpRequest",
            side_effect=ValueError("connection refused"),
        )
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": {"response": MOCK_PLAYBOOK_RESPONSE}, "Type": 1}],
        )
        result = get_failed_tasks_for_alert("1")
        assert len(result) == 2

    def test_returns_empty_on_failed_internal_request(self, mocker):
        """
        GIVEN:
            An internal HTTP request that returns a non-200 status.

        WHEN:
            get_failed_tasks_for_alert is called.

        THEN:
            An empty list should be returned.
        """
        mocker.patch.object(
            demisto,
            "internalHttpRequest",
            return_value={"statusCode": 500, "body": "Internal Server Error"},
        )
        result = get_failed_tasks_for_alert("1")
        assert result == []


class TestRestartTask:
    def test_successful_restart(self, mocker):
        """
        GIVEN:
            Successful taskReopen and internalHttpRequest responses.

        WHEN:
            restart_task is called.

        THEN:
            It should return success=True.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": "ok", "Type": 1}],
        )
        mocker.patch.object(
            demisto,
            "internalHttpRequest",
            return_value={"statusCode": 200, "body": "{}"},
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.is_demisto_version_ge",
            return_value=True,
        )
        result = restart_task("task-101", "1")
        assert result["success"] is True

    def test_failed_reopen(self, mocker):
        """
        GIVEN:
            A failed taskReopen response.

        WHEN:
            restart_task is called.

        THEN:
            It should return success=False with an error message.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Type": 4, "Contents": "Task not found"}],
        )
        result = restart_task("task-999", "1")
        assert result["success"] is False
        assert "Failed to reopen" in result["error"]

    def test_failed_execute(self, mocker):
        """
        GIVEN:
            A successful taskReopen but failed internalHttpRequest execute.

        WHEN:
            restart_task is called.

        THEN:
            It should return success=False with an error message about execution.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": "ok", "Type": 1}],
        )
        mocker.patch.object(
            demisto,
            "internalHttpRequest",
            return_value={"statusCode": 500, "body": "Execution failed"},
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.is_demisto_version_ge",
            return_value=True,
        )
        result = restart_task("task-101", "1")
        assert result["success"] is False
        assert "Failed to execute" in result["error"]

    def test_failed_execute_exception(self, mocker):
        """
        GIVEN:
            A successful taskReopen but internalHttpRequest raises an exception.

        WHEN:
            restart_task is called.

        THEN:
            It should return success=False with an error message.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": "ok", "Type": 1}],
        )
        mocker.patch.object(
            demisto,
            "internalHttpRequest",
            side_effect=Exception("Connection error"),
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.is_demisto_version_ge",
            return_value=True,
        )
        result = restart_task("task-101", "1")
        assert result["success"] is False
        assert "Failed to execute" in result["error"]

    def test_uses_legacy_body_format_pre_6_2(self, mocker):
        """
        GIVEN:
            XSOAR version < 6.2.

        WHEN:
            restart_task is called.

        THEN:
            The body should use the legacy format without 'taskinfo' wrapper.
        """
        mocker.patch.object(
            demisto,
            "executeCommand",
            return_value=[{"Contents": "ok", "Type": 1}],
        )
        mock_internal = mocker.patch.object(
            demisto,
            "internalHttpRequest",
            return_value={"statusCode": 200, "body": "{}"},
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.is_demisto_version_ge",
            return_value=False,
        )
        restart_task("task-101", "1")

        call_body = json.loads(mock_internal.call_args[1]["body"])
        assert "taskinfo" not in call_body
        assert call_body["invId"] == "1"
        assert call_body["inTaskID"] == "task-101"


class TestRestartAllFailedTasks:
    def test_restarts_tasks_across_alerts(self, mocker):
        """
        GIVEN:
            Multiple alerts with failed tasks.

        WHEN:
            restart_all_failed_tasks is called.

        THEN:
            All failed tasks should be restarted and tracked.
        """
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_failed_tasks_for_alert",
            return_value=MOCK_FAILED_TASKS,
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.restart_task",
            return_value={"success": True, "error": ""},
        )

        restarted, failed = restart_all_failed_tasks(MOCK_ALERTS[:1], group_size=10, sleep_time=0)
        assert len(restarted) == 2
        assert len(failed) == 0

    def test_tracks_failed_restarts(self, mocker):
        """
        GIVEN:
            Alerts with failed tasks where restart fails.

        WHEN:
            restart_all_failed_tasks is called.

        THEN:
            Failed restarts should be tracked in the failed_to_restart list.
        """
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_failed_tasks_for_alert",
            return_value=MOCK_FAILED_TASKS[:1],
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.restart_task",
            return_value={"success": False, "error": "Permission denied"},
        )

        restarted, failed = restart_all_failed_tasks(MOCK_ALERTS[:1], group_size=10, sleep_time=0)
        assert len(restarted) == 0
        assert len(failed) == 1
        assert failed[0]["Error"] == "Permission denied"

    def test_skips_alerts_without_failed_tasks(self, mocker):
        """
        GIVEN:
            Alerts where no failed tasks are found.

        WHEN:
            restart_all_failed_tasks is called.

        THEN:
            No tasks should be restarted.
        """
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_failed_tasks_for_alert",
            return_value=[],
        )

        restarted, failed = restart_all_failed_tasks(MOCK_ALERTS, group_size=10, sleep_time=0)
        assert len(restarted) == 0
        assert len(failed) == 0

    def test_throttling_with_group_size(self, mocker):
        """
        GIVEN:
            Multiple failed tasks and a group_size of 1.

        WHEN:
            restart_all_failed_tasks is called.

        THEN:
            time.sleep should be called after each task.
        """
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_failed_tasks_for_alert",
            return_value=MOCK_FAILED_TASKS,
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.restart_task",
            return_value={"success": True, "error": ""},
        )
        mock_sleep = mocker.patch("TroubleshootRestartFailedPlaybooks.time.sleep")

        restart_all_failed_tasks(MOCK_ALERTS[:1], group_size=1, sleep_time=5)
        assert mock_sleep.call_count == 2
        mock_sleep.assert_called_with(5)


class TestMain:
    def test_no_alerts_found(self, mocker):
        """
        GIVEN:
            No non-closed alerts exist.

        WHEN:
            main is called.

        THEN:
            A message indicating no alerts were found should be returned.
        """
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_alerts_with_errors",
            return_value=[],
        )
        mock_return = mocker.patch("TroubleshootRestartFailedPlaybooks.return_results")

        main()

        mock_return.assert_called_once_with("No non-closed alerts were found.")

    def test_no_failed_tasks_found(self, mocker):
        """
        GIVEN:
            Alerts exist but none have failed tasks.

        WHEN:
            main is called.

        THEN:
            A message indicating no failed tasks were found should be returned.
        """
        mocker.patch.object(demisto, "args", return_value={})
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_alerts_with_errors",
            return_value=MOCK_ALERTS,
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.restart_all_failed_tasks",
            return_value=([], []),
        )
        mock_return = mocker.patch("TroubleshootRestartFailedPlaybooks.return_results")

        main()

        mock_return.assert_called_once_with("No failed tasks were found across the queried alerts.")

    def test_successful_run_with_results(self, mocker):
        """
        GIVEN:
            Alerts with failed tasks that are successfully restarted.

        WHEN:
            main is called.

        THEN:
            CommandResults should be returned with the restarted tasks.
        """
        restarted = [
            {"IncidentID": "1", "TaskID": "task-101", "TaskName": "Send Email", "PlaybookName": "Phishing Investigation"}
        ]
        mocker.patch.object(demisto, "args", return_value={"max_alerts": "100"})
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.get_alerts_with_errors",
            return_value=MOCK_ALERTS,
        )
        mocker.patch(
            "TroubleshootRestartFailedPlaybooks.restart_all_failed_tasks",
            return_value=(restarted, []),
        )
        mock_return = mocker.patch("TroubleshootRestartFailedPlaybooks.return_results")

        main()

        call_args = mock_return.call_args[0][0]
        assert call_args.outputs["TotalRestarted"] == 1
        assert call_args.outputs["TotalFailed"] == 0
        assert call_args.outputs_prefix == "TroubleshootRestartFailedPlaybooks"

    def test_invalid_group_size(self, mocker):
        """
        GIVEN:
            A group_size of 0.

        WHEN:
            main is called.

        THEN:
            return_error should be called with an appropriate message.
        """
        mocker.patch.object(demisto, "args", return_value={"group_size": "0"})
        mock_error = mocker.patch("TroubleshootRestartFailedPlaybooks.return_error")

        main()

        mock_error.assert_called_once()
        assert "group_size" in mock_error.call_args[0][0]
