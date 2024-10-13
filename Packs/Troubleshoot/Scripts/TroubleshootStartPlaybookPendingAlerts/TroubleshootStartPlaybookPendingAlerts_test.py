import pytest
from CommonServerPython import *
import demistomock as demisto
from TroubleshootStartPlaybookPendingAlerts import *


PLAYBOOKS_DICT = {
    "123": "Test Playbook 1",
    "456": "Test Playbook 2"
}
PLAYBOOK_ID = "123"
ALERT_IDS = [1, 2, 3, 4]
INCIDENTS = [
    {"id": "1", "closeReason": "Resolved"},
    {"id": "2", "closeReason": ""},
    {"id": "3", "closeReason": "Closed"},
    {"id": "4", "closeReason": ""}
]
LIMIT = 4
REOPEN_CLOSED_INV = True
INCIDENTS_FOR_SPLIT = [
    {"id": "1", "playbookId": "123"},
    {"id": "2", "playbookId": "456"},
    {"id": "3", "playbookId": ""},
    {"id": "4", "playbookId": "123"},
    {"id": "5", "playbookId": ""}
]
LIMIT_FOR_SPLIT = 5


def test_get_playbook_id_by_name():
    # Test when playbook_name is provided and found
    playbook_name = "Test Playbook 1"
    result = get_playbook_id(playbook_id="", playbook_name=playbook_name, playbooks_dict=PLAYBOOKS_DICT)
    assert result == "123"


def test_get_playbook_id_by_id():
    # Test when playbook_id is provided and found
    playbook_id = "456"
    result = get_playbook_id(playbook_id=playbook_id, playbook_name="", playbooks_dict=PLAYBOOKS_DICT)
    assert result == "456"


def test_get_playbook_id_both_id_and_name():
    # Test when both playbook_id and playbook_name are provided
    with pytest.raises(DemistoException) as e:
        get_playbook_id(playbook_id="123", playbook_name="Test Playbook 1", playbooks_dict=PLAYBOOKS_DICT)
    assert "Please provide only a playbook ID or a playbook name, not both." in str(e)


def test_get_playbook_id_name_not_found():
    # Test when playbook_name is not found
    with pytest.raises(DemistoException) as e:
        get_playbook_id(playbook_id="", playbook_name="Non-existent Playbook", playbooks_dict=PLAYBOOKS_DICT)
    assert "Playbook 'Non-existent Playbook' wasn't found. Please check the name and try again." in str(e)


def test_get_playbook_id_id_not_found():
    # Test when playbook_id is not found
    with pytest.raises(DemistoException) as e:
        get_playbook_id(playbook_id="999", playbook_name="", playbooks_dict=PLAYBOOKS_DICT)
    assert "Playbook '999' wasn't found. Please check the name and try again." in str(e)


def test_no_results():
    # Test when no command results are found
    command_results = {}
    result = handle_results(command_results, PLAYBOOK_ID, ALERT_IDS)
    assert result == "No results found for this query."


def test_all_successful():
    # Test when all playbook executions are successful
    command_results = [{
        "Contents": {
            "response": {}
        }
    }]
    result = handle_results(command_results, PLAYBOOK_ID, ALERT_IDS)
    assert result == f"Playbook ID '123' was set successfully for alerts: {ALERT_IDS}."


def test_some_failed():
    # Test when some alerts failed, and some succeeded
    command_results = [{
        "Contents": {
            "response": {
                2: "Error creating investigation playbook",
                4: "Error creating investigation playbook"
            }
        }
    }]
    result = handle_results(command_results, PLAYBOOK_ID, ALERT_IDS)
    expected_message = (
        "Playbook ID '123' could not be executed for alerts [2, 4] due to failure in creating an investigation playbook.\n"
        "Playbook ID '123' was set successfully for alerts: [1, 3]."
    )
    assert result == expected_message


def test_all_failed():
    # Test when all alerts failed
    command_results = [{
        "Contents": {
            "response": {
                1: "Error creating investigation playbook",
                2: "Error creating investigation playbook",
                3: "Error creating investigation playbook",
                4: "Error creating investigation playbook"
            }
        }
    }]
    result = handle_results(command_results, PLAYBOOK_ID, ALERT_IDS)
    expected_message = (
        "Playbook ID '123' could not be executed for alerts [1, 2, 3, 4] "
        "due to failure in creating an investigation playbook."
    )
    assert result == expected_message


def test_unexpected_error_handle_results():
    # Test when an unexpected error occurs
    command_results = [{
        "Contents": None  # Simulate an invalid response structure
    }]
    result = handle_results(command_results, PLAYBOOK_ID, ALERT_IDS)
    assert result.startswith("Unexpected error occurred")


def test_playbook_id_not_found_set_playbook_on_alerts(mocker):
    # Test when playbook ID is not found in the playbooks_dict
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    playbook_id = "999"
    result = set_playbook_on_alerts(playbook_id, ALERT_IDS, PLAYBOOKS_DICT)
    assert result == f"Playbook ID '{playbook_id}' was not found for alerts {ALERT_IDS}."
    mock_execute_command.assert_not_called()  # Ensure API is not called if playbook is not found


def test_successful_execution_set_playbook_on_alerts(mocker):
    # Test when the playbook execution is successful
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_command_result = [{
        "Contents": {
            "response": {}
        }
    }]
    mock_execute_command.return_value = mock_command_result

    result = set_playbook_on_alerts(PLAYBOOK_ID, ALERT_IDS, PLAYBOOKS_DICT)

    # Expected result from successful execution
    expected_message = f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: {ALERT_IDS}."
    assert result == expected_message
    mock_execute_command.assert_called_once_with("core-api-post", {
        "uri": "/xsoar/inv-playbook/new",
        "body": {"playbookId": PLAYBOOK_ID, "alertIds": ALERT_IDS, "version": -1}
    })


def test_failed_execution_set_playbook_on_alerts(mocker):
    # Test when some playbook executions fail
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_command_result = [{
        "Contents": {
            "response": {
                2: "Error creating investigation playbook"
            }
        }
    }]
    mock_execute_command.return_value = mock_command_result

    result = set_playbook_on_alerts(PLAYBOOK_ID, ALERT_IDS, PLAYBOOKS_DICT)

    expected_message = (
        f"Playbook ID '{PLAYBOOK_ID}' could not be executed for alerts [2] "
        "due to failure in creating an investigation playbook.\n"
        f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: [1, 3, 4]."
    )
    assert result == expected_message
    mock_execute_command.assert_called_once_with("core-api-post", {
        "uri": "/xsoar/inv-playbook/new",
        "body": {"playbookId": PLAYBOOK_ID, "alertIds": ALERT_IDS, "version": -1}
    })


def test_unexpected_error_set_playbook_on_alerts(mocker):
    # Test for an unexpected error in the command result
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_command_result = [{
        "Contents": None  # Simulate an invalid or unexpected response
    }]
    mock_execute_command.return_value = mock_command_result

    result = set_playbook_on_alerts(PLAYBOOK_ID, ALERT_IDS, PLAYBOOKS_DICT)
    assert result.startswith("Unexpected error occurred")
    mock_execute_command.assert_called_once_with("core-api-post", {
        "uri": "/xsoar/inv-playbook/new",
        "body": {"playbookId": PLAYBOOK_ID, "alertIds": ALERT_IDS, "version": -1}
    })


def test_no_incidents_loop_on_alerts(mocker):
    # Test when no incidents are provided
    mocker.patch.object(demisto, 'executeCommand')
    mock_open_investigation = mocker.patch("TroubleshootStartPlaybookPendingAlerts.open_investigation")
    mock_set_playbook = mocker.patch("TroubleshootStartPlaybookPendingAlerts.set_playbook_on_alerts")
    result = loop_on_alerts([], PLAYBOOK_ID, LIMIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    assert result == "Couldn't find any alerts"
    mock_open_investigation.assert_not_called()
    mock_set_playbook.assert_not_called()


def test_reopen_closed_investigations_loop_on_alerts(mocker):
    # Test reopening closed alerts and applying playbooks to all alerts
    mocker.patch.object(demisto, 'executeCommand')
    mock_open_investigation = mocker.patch("TroubleshootStartPlaybookPendingAlerts.open_investigation")
    mock_set_playbook = mocker.patch("TroubleshootStartPlaybookPendingAlerts.set_playbook_on_alerts")
    mock_set_playbook.return_value = f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: ['4', '3', '2', '1']."

    result = loop_on_alerts(INCIDENTS, PLAYBOOK_ID, LIMIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    expected_message = (
        f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: ['4', '3', '2', '1'].\n"
        "Alerts ['1', '3'] have been reopened."
    )
    assert result == expected_message

    # Ensure closed investigations are reopened
    mock_open_investigation.assert_called_once_with(alert_ids=["1", "3"])
    # Ensure playbooks are applied to all alerts
    mock_set_playbook.assert_called()


def test_apply_playbook_without_reopen_loop_on_alerts(mocker):
    # Test applying playbook without reopening closed alerts
    mocker.patch.object(demisto, 'executeCommand')
    mock_open_investigation = mocker.patch("TroubleshootStartPlaybookPendingAlerts.open_investigation")
    mock_set_playbook = mocker.patch("TroubleshootStartPlaybookPendingAlerts.set_playbook_on_alerts")
    mock_set_playbook.return_value = f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: ['4', '2']."
    REOPEN_CLOSED_INV = False

    result = loop_on_alerts(INCIDENTS, PLAYBOOK_ID, LIMIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    expected_message = f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: ['4', '2']."
    assert result == expected_message

    # Ensure closed investigations are not reopened
    mock_open_investigation.assert_not_called()
    # Ensure playbooks are applied to open alerts only
    mock_set_playbook.assert_called()


def test_no_closed_investigations_loop_on_alerts(mocker):
    # Test with no closed alerts to reopen
    mocker.patch.object(demisto, 'executeCommand')
    mock_open_investigation = mocker.patch("TroubleshootStartPlaybookPendingAlerts.open_investigation")
    mock_set_playbook = mocker.patch("TroubleshootStartPlaybookPendingAlerts.set_playbook_on_alerts")
    incidents = [{"id": "1", "closeReason": ""}]
    mock_set_playbook.return_value = f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: ['1']."

    result = loop_on_alerts(incidents, PLAYBOOK_ID, LIMIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    expected_message = f"Playbook ID '{PLAYBOOK_ID}' was set successfully for alerts: ['1']."
    assert result == expected_message

    # Ensure no closed investigations are reopened
    mock_open_investigation.assert_not_called()
    # Ensure playbooks are applied to open alerts only
    mock_set_playbook.assert_called()


def test_loop_on_alerts_respects_limit(mocker):
    """
    Test that loop_on_alerts respects the limit and only processes the specified number of incidents.
    """
    # Set up the incidents with some having close reasons and some without
    playbook_id = "123"
    playbooks_dict = {
        "123": "Playbook 123"
    }
    limit = 2
    mocker.patch.object(demisto, 'executeCommand')
    mock_open_investigation = mocker.patch("TroubleshootStartPlaybookPendingAlerts.open_investigation")
    mock_set_playbook = mocker.patch("TroubleshootStartPlaybookPendingAlerts.set_playbook_on_alerts")
    incidents = [
        {"id": "1", "playbookId": "123", "closeReason": ""},
        {"id": "2", "playbookId": "123", "closeReason": ""},
        {"id": "3", "playbookId": "123", "closeReason": "Closed"},  # This should not be processed due to limit
    ]

    # Mock the response for set_playbook_on_alerts
    mock_set_playbook.return_value = "Playbook set for alerts"

    # Call loop_on_alerts
    result = loop_on_alerts(incidents, playbook_id, limit, REOPEN_CLOSED_INV, playbooks_dict)

    # Assert that only 2 incidents are processed (as per the limit)
    expected_result = "Playbook set for alerts"
    assert expected_result in result

    # Check that set_playbook_on_alerts was called only with the first 2 incidents (due to the limit)
    mock_set_playbook.assert_called_with(playbook_id='123', alert_ids=['1', '2'], playbooks_dict={'123': 'Playbook 123'})

    # Assert that open_investigation was never called since none of the incidents were closed and reopen_closed_inv is False
    mock_open_investigation.assert_not_called()


def test_process_by_playbook_split_by_playbooks(mocker):
    # Test processing incidents by playbook ID
    mock_loop_on_alerts = mocker.patch("TroubleshootStartPlaybookPendingAlerts.loop_on_alerts")
    mock_loop_on_alerts.side_effect = [
        "Processed playbook 123",
        "Processed playbook 456"
    ]

    result = split_by_playbooks(INCIDENTS_FOR_SPLIT, LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    expected_result = (
        "Could not find an attached playbook for alerts ['3', '5'].\n"
        "Processed playbook 123\n"
        "Processed playbook 456"
    )
    assert result == expected_result

    # Ensure loop_on_alerts was called with correct playbook IDs and incidents
    mock_loop_on_alerts.assert_any_call([{"id": "1", "playbookId": "123"}, {"id": "4", "playbookId": "123"}],
                                        "123", LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    mock_loop_on_alerts.assert_any_call([{"id": "2", "playbookId": "456"}],
                                        "456", LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)


def test_no_playbook_attached_split_by_playbooks(mocker):
    # Test when no incidents have a playbook ID
    mock_loop_on_alerts = mocker.patch("TroubleshootStartPlaybookPendingAlerts.loop_on_alerts")
    incidents = [{"id": "1", "playbookId": ""}, {"id": "2", "playbookId": ""}]
    result = split_by_playbooks(incidents, LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    assert result == "Could not find an attached playbook for alerts ['1', '2']."
    mock_loop_on_alerts.assert_not_called()


def test_playbook_attached_split_by_playbooks(mocker):
    # Test when all incidents have a playbook ID
    mock_loop_on_alerts = mocker.patch("TroubleshootStartPlaybookPendingAlerts.loop_on_alerts")
    incidents = [
        {"id": "1", "playbookId": "123"},
        {"id": "2", "playbookId": "456"}
    ]
    mock_loop_on_alerts.side_effect = [
        "Processed playbook 123",
        "Processed playbook 456"
    ]

    result = split_by_playbooks(incidents, LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    expected_result = (
        "Processed playbook 123\n"
        "Processed playbook 456"
    )
    assert result == expected_result

    # Ensure loop_on_alerts was called with correct playbook IDs and incidents
    mock_loop_on_alerts.assert_any_call([{"id": "1", "playbookId": "123"}],
                                        "123", LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    mock_loop_on_alerts.assert_any_call([{"id": "2", "playbookId": "456"}],
                                        "456", LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)


def test_empty_incidents_split_by_playbooks(mocker):
    # Test when no incidents are passed
    mock_loop_on_alerts = mocker.patch("TroubleshootStartPlaybookPendingAlerts.loop_on_alerts")
    result = split_by_playbooks([], LIMIT_FOR_SPLIT, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    assert result == ""
    mock_loop_on_alerts.assert_not_called()


def test_split_by_playbooks_limit_cut(mocker):
    """
    Test that split_by_playbooks respects the limit and only processes the specified number of incidents.
    """
    # Setup incidents
    mock_loop_on_alerts = mocker.patch("TroubleshootStartPlaybookPendingAlerts.loop_on_alerts")
    incidents = [
        {"id": "1", "playbookId": "123"},
        {"id": "2", "playbookId": "123"},
        {"id": "3", "playbookId": "123"},  # Should not be processed due to the limit
        {"id": "4", "playbookId": "456"},  # Should not be processed due to the limit
        {"id": "5", "playbookId": "456"}   # Should not be processed due to the limit
    ]

    # Set the limit to 2 (only the first 2 incidents should be processed)
    limit = 2

    # Mock the return value for loop_on_alerts calls
    mock_loop_on_alerts.side_effect = [
        "Processed playbook 123",
        "Processed playbook 456"
    ]

    # Call split_by_playbooks with the limit
    result = split_by_playbooks(incidents, limit, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    # Expected result after processing only the first two incidents
    expected_result = "Processed playbook 123"
    assert result == expected_result

    # Assert that loop_on_alerts is called with the correct incidents respecting the limit
    mock_loop_on_alerts.assert_any_call([{"id": "1", "playbookId": "123"}, {'id': '2', 'playbookId': '123'}],
                                        "123", limit, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    calls = mock_loop_on_alerts.call_args_list
    processed_ids = [call[0][0] for call in calls]
    for ids in processed_ids:
        assert {'id': '3', 'playbookId': '123'} not in ids
        assert {"id": "4", "playbookId": "456"} not in ids
        assert {"id": "5", "playbookId": "456"} not in ids


def test_split_by_playbooks_limit_cut_two_calls(mocker):
    """
    Test that split_by_playbooks respects the limit and only processes the specified number of incidents.
    """
    # Setup incidents
    mock_loop_on_alerts = mocker.patch("TroubleshootStartPlaybookPendingAlerts.loop_on_alerts")
    incidents = [
        {"id": "1", "playbookId": "123"},
        {"id": "4", "playbookId": "456"},
        {"id": "2", "playbookId": "123"},  # Should not be processed due to the limit
        {"id": "3", "playbookId": "123"},  # Should not be processed due to the limit
        {"id": "5", "playbookId": "456"}   # Should not be processed due to the limit
    ]

    # Set the limit to 2 (only the first 2 incidents should be processed)
    limit = 2

    # Mock the return value for loop_on_alerts calls
    mock_loop_on_alerts.side_effect = [
        "Processed playbook 123",
        "Processed playbook 456"
    ]

    # Call split_by_playbooks with the limit
    result = split_by_playbooks(incidents, limit, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)

    # Expected result after processing only the first two incidents
    expected_result = "Processed playbook 123\nProcessed playbook 456"
    assert result == expected_result

    # Assert that loop_on_alerts is called with the correct incidents respecting the limit
    mock_loop_on_alerts.assert_any_call([{"id": "1", "playbookId": "123"}],
                                        "123", limit, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    mock_loop_on_alerts.assert_any_call([{"id": "4", "playbookId": "456"}],
                                        "456", limit, REOPEN_CLOSED_INV, PLAYBOOKS_DICT)
    calls = mock_loop_on_alerts.call_args_list
    processed_ids = [call[0][0] for call in calls]
    for ids in processed_ids:
        assert {"id": "3", "playbookId": "123"} not in ids
        assert {"id": "2", "playbookId": "123"} not in ids
        assert {"id": "5", "playbookId": "456"} not in ids
