from IbmUpdateTask import update_task
import demistomock as demisto


def test_update_task_success(mocker):
    args = {"task_id": "123", "status": "Completed", "phase": "Initial", "due_date": "2020-02-02T19:00:00Z"}
    mock_results = [{"HumanReadable": "Task updated successfully"}]
    mocker.patch.object(demisto, "executeCommand", return_value=mock_results)

    result = update_task(args)

    assert result.readable_output == "Task updated successfully"
    demisto.executeCommand.assert_called_once_with('rs-update-task', args=args)
