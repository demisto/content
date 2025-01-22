from CommonServerPython import *
import demistomock as demisto
from TroubleshootCloseAlertsByQuery import main


def test_main_success(mocker):
    """
    GIVEN:
        A list of alert IDs to close.

    WHEN:
        The 'main' function is called and the execute command returns a successful response.

    THEN:
        It should execute the command to close investigations for each alert ID
        and return a message indicating the closure results.
    """
    alert_ids = ["1", "2", "3"]
    mock_closure_results = [
        [{"Contents": f"Alert {alert_id} closed successfully."}] for alert_id in alert_ids
    ]

    # Mock the demisto module methods
    mock_args = mocker.patch.object(demisto, 'args')
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_demisto_return_results = mocker.patch('TroubleshootCloseAlertsByQuery.return_results')
    mock_args.return_value = {"alert_ids": ",".join(alert_ids)}
    mock_execute_command.side_effect = mock_closure_results

    # Call the main function
    main()

    # Check that executeCommand was called for each alert ID
    for alert_id in alert_ids:
        mock_execute_command.assert_any_call(
            "closeInvestigation", {"id": alert_id, "close_reason": "Resolved - Auto Resolve"}
        )

    # Check that return_results was called with the expected final message
    expected_message = "\n".join(f"Alert {alert_id} closed successfully." for alert_id in alert_ids) + "\n"
    assert expected_message in mock_demisto_return_results.call_args[0]
    # mock_demisto_return_results.assert_called_once_with(expected_message)


def test_main_exception_handling(mocker):
    """
    GIVEN:
        A list of alert IDs and an exception occurs during the execution of the main function.

    WHEN:
        The 'main' function is called and an exception is raised.

    THEN:
        It should call return_error with the exception message.
    """
    mock_args = mocker.patch.object(demisto, 'args')
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_execute_command.side_effect = Exception("Test exception")
    mock_demisto_return_error = mocker.patch('TroubleshootCloseAlertsByQuery.return_error')
    mock_args.return_value = {"alert_ids": "1,2,3"}

    main()

    assert "Test exception" in mock_demisto_return_error.call_args[0]
