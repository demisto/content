import pytest
import demistomock as demisto
from TroubleshootExecutePlaybookByAlertQuery import *


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
    """
    GIVEN:
        A playbook name and a playbooks dictionary.

    WHEN:
        The 'get_playbook_id' function is called with an empty playbook ID and the specified playbook name.

    THEN:
        It should return the corresponding playbook ID from the playbooks dictionary.
    """
    playbook_name = "Test Playbook 1"
    result = get_playbook_id(playbook_id="", playbook_name=playbook_name, playbooks_dict=PLAYBOOKS_DICT)
    assert result == "123"


def test_get_playbook_id_by_id():
    """
    GIVEN:
        A playbook ID and a playbooks dictionary.

    WHEN:
        The 'get_playbook_id' function is called with the specified playbook ID and an empty playbook name.

    THEN:
        It should return the provided playbook ID.
    """
    playbook_id = "456"
    result = get_playbook_id(playbook_id=playbook_id, playbook_name="", playbooks_dict=PLAYBOOKS_DICT)
    assert result == "456"


def test_get_playbook_id_both_id_and_name():
    """
    GIVEN:
        A scenario where both a playbook ID and a playbook name are provided.

    WHEN:
        The 'get_playbook_id' function is called with both parameters.

    THEN:
        It should raise a DemistoException indicating that only one of the parameters should be provided.
    """
    with pytest.raises(DemistoException) as e:
        get_playbook_id(playbook_id="123", playbook_name="Test Playbook 1", playbooks_dict=PLAYBOOKS_DICT)
    assert "Please provide only a playbook ID or a playbook name, not both." in str(e)


def test_get_playbook_id_name_not_found():
    """
    GIVEN:
        A playbook name that does not exist in the playbooks dictionary.

    WHEN:
        The 'get_playbook_id' function is called with an empty playbook ID and the non-existent playbook name.

    THEN:
        It should raise a DemistoException indicating that the playbook was not found.
    """
    with pytest.raises(DemistoException) as e:
        get_playbook_id(playbook_id="", playbook_name="Non-existent Playbook", playbooks_dict=PLAYBOOKS_DICT)
    assert "Playbook 'Non-existent Playbook' wasn't found. Please check the name and try again." in str(e)


def test_get_playbook_id_id_not_found():
    """
    GIVEN:
        A playbook ID that does not exist in the playbooks dictionary.

    WHEN:
        The 'get_playbook_id' function is called with the specified non-existent playbook ID and an empty playbook name.

    THEN:
        It should raise a DemistoException indicating that the playbook ID was not found.
    """
    with pytest.raises(DemistoException) as e:
        get_playbook_id(playbook_id="999", playbook_name="", playbooks_dict=PLAYBOOKS_DICT)
    assert "Playbook '999' wasn't found. Please check the name and try again." in str(e)


def test_handle_results_insufficient_permissions(mocker):
    mock_return_error = mocker.patch('TroubleshootExecutePlaybookByAlertQuery.return_error')
    command_results = [{'Contents': "The request requires the right permissions"}]
    playbook_id = "test_playbook_id"
    alert_ids = ["alert1", "alert2"]

    # WHEN: Calling handle_results with insufficient permissions
    handle_results(command_results, playbook_id, alert_ids, results_summary=ResultsSummary({}))

    # THEN: return_error is called with the expected message
    mock_return_error.assert_called_once_with(
        "Request Failed: Insufficient permissions. Ensure the API key has the appropriate access rights."
    )


def test_handle_results_no_response():
    """
    GIVEN:
        Command results that do not contain a valid response.

    WHEN:
        The 'handle_results' function is called with the provided command results, playbook ID, and alert IDs.

    THEN:
        It should update the results summary to reflect the success of the operation for the given playbook ID.
    """
    command_results = [{'Contents': {}}]
    playbook_id = "playbook_123"
    alert_ids = ["alert1", "alert2"]
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)

    handle_results(command_results, playbook_id, alert_ids, results_summary_instance)

    assert playbook_id in results_summary_instance.results_summary["success"]
    assert results_summary_instance.results_summary["success"][playbook_id] == alert_ids


def test_handle_results_success():
    """
    GIVEN:
        Command results that indicate a successful operation with valid alert IDs.

    WHEN:
        The 'handle_results' function is called with the provided command results, playbook ID, and alert IDs.

    THEN:
        It should update the results summary to reflect the success of the operation for the given playbook ID,
        associating it with the provided alert IDs.
    """
    command_results = [{'Contents': {'response': {}}}]
    playbook_id = "playbook_123"
    alert_ids = ["alert1", "alert2", "alert3"]
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)

    handle_results(command_results, playbook_id, alert_ids, results_summary_instance)

    assert playbook_id in results_summary_instance.results_summary["success"]
    assert results_summary_instance.results_summary["success"][playbook_id] == alert_ids


def test_handle_results_failure_and_success():
    """
    GIVEN:
        Command results indicating some alert IDs have failed while others succeeded.

    WHEN:
        The 'handle_results' function is called with the provided command results, playbook ID, and alert IDs.

    THEN:
        It should update the results summary to reflect the failures and successes for the given playbook ID,
        categorizing the alert IDs accordingly.
    """
    command_results = [{'Contents': {'response': {'alert2': 'failed', 'alert3': 'failed'}}}]
    playbook_id = "playbook_123"
    alert_ids = ["alert1", "alert2", "alert3"]
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)

    handle_results(command_results, playbook_id, alert_ids, results_summary_instance)

    assert playbook_id in results_summary_instance.results_summary["failure_create"]
    assert results_summary_instance.results_summary["failure_create"][playbook_id] == ["alert2", "alert3"]

    assert playbook_id in results_summary_instance.results_summary["success"]
    assert results_summary_instance.results_summary["success"][playbook_id] == ["alert1"]


def test_handle_results_failure():
    """
    GIVEN:
        Command results indicating that all provided alert IDs have failed.

    WHEN:
        The 'handle_results' function is called with the command results, playbook ID, and alert IDs.

    THEN:
        It should update the results summary to reflect that all alert IDs are categorized as failures
        for the specified playbook ID.
    """
    command_results = [{'Contents': {'response': {'alert2': 'failed', 'alert3': 'failed'}}}]
    playbook_id = "playbook_123"
    alert_ids = ["alert2", "alert3"]
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)

    handle_results(command_results, playbook_id, alert_ids, results_summary_instance)

    assert playbook_id in results_summary_instance.results_summary["failure_create"]
    assert results_summary_instance.results_summary["failure_create"][playbook_id] == ["alert2", "alert3"]


def test_handle_results_empty_command_results():
    """
    GIVEN:
        An empty list of command results.

    WHEN:
        The 'handle_results' function is called with the empty command results, a playbook ID, and alert IDs.

    THEN:
        It should not update the results summary, and the return value should be None, indicating no actions were taken.
    """
    command_results = []
    playbook_id = "playbook_123"
    alert_ids = ["alert1", "alert2"]
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)

    result = handle_results(command_results, playbook_id, alert_ids, results_summary_instance)

    assert result is None
    assert playbook_id not in results_summary_instance.results_summary["success"]
    assert playbook_id not in results_summary_instance.results_summary["failure_create"]


def test_unexpected_error_handle_results():
    """
    GIVEN:
        A list of command results containing a None value for 'Contents'.

    WHEN:
        The 'handle_results' function is called with the provided command results and a results summary instance.

    THEN:
        It should return a message indicating that an unexpected error occurred, demonstrating the function's
        ability to handle unexpected input gracefully.
    """
    command_results = [{
        "Contents": None
    }]
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)

    result = handle_results(command_results, PLAYBOOK_ID, ALERT_IDS, results_summary_instance)
    assert result.startswith("Unexpected error occurred")


def test_set_playbook_on_alerts_flag_pending_idle_true_success(mocker):
    """
    GIVEN:
        A playbook ID, a list of alert IDs, and a playbooks dictionary.

    WHEN:
        The 'set_playbook_on_alerts' function is called with the specified parameters,
        and the execute command returns a successful response.

    THEN:
        It should execute the command to set the playbook on alerts and update the results
        summary to reflect the successful execution.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "playbook_123"
    alert_ids = ["alert1", "alert2"]
    playbooks_dict = {playbook_id: "name of playbook"}

    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_execute_command.return_value = [{'Contents': {'response': {}}}]

    set_playbook_on_alerts(playbook_id, alert_ids, playbooks_dict, results_summary_instance, True)

    mock_execute_command.assert_called_once_with(
        "core-api-post",
        {"uri": "/xsoar/inv-playbook/new", "body": {"playbookId": playbook_id, "alertIds": alert_ids, "version": -1}}
    )

    assert playbook_id in results_summary_instance.results_summary["success"]
    assert alert_ids == results_summary_instance.results_summary["success"][playbook_id]


def test_set_playbook_on_alerts_invalid_playbook():
    """
    GIVEN:
        An invalid playbook ID and a list of alert IDs.

    WHEN:
        The 'set_playbook_on_alerts' function is called with the invalid playbook ID.

    THEN:
        It should update the results summary to reflect the failure in setting the playbook on alerts.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "invalid_playbook"
    alert_ids = ["alert1", "alert2"]
    playbooks_dict = {"playbook_123": "name of playbook"}

    set_playbook_on_alerts(playbook_id, alert_ids, playbooks_dict, results_summary_instance, False)

    assert playbook_id in results_summary_instance.results_summary["failure_set"]
    assert results_summary_instance.results_summary["failure_set"][playbook_id] == alert_ids


def test_set_playbook_on_alerts_flag_pending_idle_false_success(mocker):
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    playbook_id = "test_playbook"
    alert_ids = ["alert1", "alert2"]
    playbooks_dict = {"test_playbook": "playbook_info"}
    results_summary = mocker
    flag_pending_idle = False

    mock_execute_command.return_value = [{'Contents': {'response': {}}}]

    set_playbook_on_alerts(
        playbook_id, alert_ids, playbooks_dict,
        results_summary, flag_pending_idle
    )

    for alert_id in alert_ids:
        mock_execute_command.assert_any_call(
            "core-api-post",
            {"uri": f"/xsoar/inv-playbook/new/{playbook_id}/{alert_id}"}
        )


def test_loop_on_alerts_success(mocker):
    """
    GIVEN:
        A list of incidents with no closed alerts, a playbook ID, and a results summary instance.

    WHEN:
        The 'loop_on_alerts' function is called with the specified incidents and parameters.

    THEN:
        It should successfully loop through the alerts and apply the playbook, calling the
        'set_playbook_on_alerts' function the expected number of times.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "playbook_123"
    incidents = [{"id": f"alert{i}", "closeReason": ""} for i in range(15)]
    playbooks_dict = {playbook_id: "name of playbook"}

    mocker.patch("TroubleshootExecutePlaybookByAlertQuery.open_investigation")
    mock_set_playbook_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.set_playbook_on_alerts")

    loop_on_alerts(incidents, playbook_id, limit=15, reopen_closed_inv=False,
                   playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    mock_set_playbook_on_alerts.assert_called()
    assert len(mock_set_playbook_on_alerts.call_args_list) == 2


def test_loop_on_alerts_with_closed_investigations(mocker):
    """
    GIVEN:
        A list of incidents containing both closed and open investigations, a playbook ID,
        and a results summary instance, with the option to reopen closed investigations set to True.

    WHEN:
        The 'loop_on_alerts' function is called with the specified incidents and parameters.

    THEN:
        It should successfully open closed investigations, call the appropriate functions for both
        closed and open alerts, and update the results summary with the reopened alerts.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "playbook_123"
    incidents = [
        {"id": "alert1", "closeReason": "Closed"},
        {"id": "alert2", "closeReason": "Closed"},
        {"id": "alert3", "closeReason": ""},
        {"id": "alert4", "closeReason": ""}
    ]
    playbooks_dict = {playbook_id: "name of playbook"}

    mock_open_investigation = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.open_investigation")
    mock_set_playbook_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.set_playbook_on_alerts")

    loop_on_alerts(incidents, playbook_id, limit=4, reopen_closed_inv=True,
                   playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    assert mock_open_investigation.call_count == 1

    assert len(mock_set_playbook_on_alerts.call_args_list) == 1


def test_loop_on_alerts_empty_incidents(mocker):
    """
    GIVEN:
        An empty list of incidents, a playbook ID, and a results summary instance.

    WHEN:
        The 'loop_on_alerts' function is called with the empty incident list.

    THEN:
        It should not call any functions to open investigations or set playbooks,
        indicating that no actions were taken due to the absence of incidents.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "playbook_123"
    incidents = []
    playbooks_dict = {playbook_id: "name of playbook"}

    mock_open_investigation = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.open_investigation")
    mock_set_playbook_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.set_playbook_on_alerts")

    loop_on_alerts(incidents, playbook_id, limit=10, reopen_closed_inv=False,
                   playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    mock_open_investigation.assert_not_called()
    mock_set_playbook_on_alerts.assert_not_called()


def test_loop_on_alerts_with_limit(mocker):
    """
    GIVEN:
        A list of incidents exceeding the specified limit, a playbook ID, and a results summary instance.

    WHEN:
        The 'loop_on_alerts' function is called with the limit parameter set to a specific value.

    THEN:
        It should restrict the processing of incidents to the specified limit,
        and the 'set_playbook_on_alerts' function should be called only once for the limited number of alerts.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "playbook_123"
    incidents = [{"id": f"alert{i}", "closeReason": ""} for i in range(20)]
    playbooks_dict = {playbook_id: "name of playbook"}

    mocker.patch("TroubleshootExecutePlaybookByAlertQuery.open_investigation")
    mock_set_playbook_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.set_playbook_on_alerts")

    loop_on_alerts(incidents, playbook_id, limit=10, reopen_closed_inv=False,
                   playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    assert mock_set_playbook_on_alerts.call_count == 1


def test_loop_on_alerts_with_closed_investigations_not_reopening(mocker):
    """
    GIVEN:
        A list of incidents including closed investigations, a playbook ID, and a results summary instance,
        with the reopen_closed_inv flag set to False.

    WHEN:
        The 'loop_on_alerts' function is called with the provided incidents.

    THEN:
        It should not attempt to reopen any closed investigations,
        and the 'set_playbook_on_alerts' function should only be called for open alerts.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    playbook_id = "playbook_123"
    incidents = [
        {"id": "alert1", "closeReason": "Closed"},
        {"id": "alert2", "closeReason": "Closed"},
        {"id": "alert3", "closeReason": ""},
        {"id": "alert4", "closeReason": ""}
    ]
    playbooks_dict = {playbook_id: "name of playbook"}

    mock_open_investigation = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.open_investigation")
    mock_set_playbook_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.set_playbook_on_alerts")

    loop_on_alerts(incidents, playbook_id, limit=4, reopen_closed_inv=False,
                   playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    mock_open_investigation.assert_not_called()

    assert mock_set_playbook_on_alerts.call_count == 1


def test_split_by_playbooks_success(mocker):
    """
    GIVEN:
        A list of incidents with associated playbook IDs and a results summary instance.

    WHEN:
        The 'split_by_playbooks' function is called with the provided incidents.

    THEN:
        It should successfully split the incidents by their playbook IDs,
        call the 'loop_on_alerts' function for each unique playbook,
        and log any incidents without an attached playbook in the results summary.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    incidents = [
        {"id": "alert1", "playbookId": "playbook_123"},
        {"id": "alert2", "playbookId": "playbook_456"},
        {"id": "alert3", "playbookId": "playbook_123"},
        {"id": "alert4", "playbookId": ""},
    ]
    playbooks_dict = {'playbook_123': 'First Playbook', 'playbook_456': 'Second Playbook'}

    mock_loop_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.loop_on_alerts")

    split_by_playbooks(incidents, limit=4, reopen_closed_inv=False,
                       playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    assert mock_loop_on_alerts.call_count == 2
    mock_loop_on_alerts.assert_any_call(
        [{'id': 'alert1', 'playbookId': 'playbook_123'}, {'id': 'alert3', 'playbookId': 'playbook_123'}],
        'playbook_123',
        4,
        False,
        playbooks_dict,
        results_summary_instance,
        False
    )
    mock_loop_on_alerts.assert_any_call(
        [{"id": "alert2", "playbookId": "playbook_456"}],
        "playbook_456",
        4,
        False,
        playbooks_dict,
        results_summary_instance,
        False
    )
    assert "Could not find an attached playbook for alerts: ['alert4']." in results_summary_instance.results_summary["others"]


def test_split_by_playbooks_missing_playbook(mocker):
    """
    GIVEN:
        A list of incidents with some missing playbook IDs and a results summary instance.

    WHEN:
        The 'split_by_playbooks' function is called with the provided incidents.

    THEN:
        It should successfully split the incidents by their available playbook IDs,
        call the 'loop_on_alerts' function for each unique playbook,
        and log any incidents without an attached playbook in the results summary.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    incidents = [
        {"id": "alert1", "playbookId": "playbook_123"},
        {"id": "alert2", "playbookId": ""},
        {"id": "alert3", "playbookId": "playbook_456"},
        {"id": "alert4", "playbookId": ""}
    ]
    playbooks_dict = {'playbook_123': 'First Playbook', 'playbook_456': 'Second Playbook'}

    mock_loop_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.loop_on_alerts")

    split_by_playbooks(incidents, limit=4, reopen_closed_inv=False,
                       playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    assert mock_loop_on_alerts.call_count == 2
    mock_loop_on_alerts.assert_any_call(
        [{'id': 'alert1', 'playbookId': 'playbook_123'}],
        'playbook_123',
        4,
        False,
        playbooks_dict,
        results_summary_instance,
        False
    )
    mock_loop_on_alerts.assert_any_call(
        [{"id": "alert3", "playbookId": "playbook_456"}],
        "playbook_456",
        4,
        False,
        playbooks_dict,
        results_summary_instance,
        False
    )

    assert "Could not find an attached playbook for alerts: ['alert2', 'alert4']." in \
        results_summary_instance.results_summary["others"]


def test_split_by_playbooks_all_missing_playbooks(mocker):
    """
    GIVEN:
        A list of incidents where all have missing playbook IDs and a results summary instance.

    WHEN:
        The 'split_by_playbooks' function is called with the provided incidents.

    THEN:
        It should not call the 'loop_on_alerts' function, as there are no valid playbook IDs,
        and it should log all incidents without an attached playbook in the results summary.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    incidents = [
        {"id": "alert1", "playbookId": ""},
        {"id": "alert2", "playbookId": ""},
        {"id": "alert3", "playbookId": ""},
    ]
    playbooks_dict = {'playbook_123': 'First Playbook', 'playbook_456': 'Second Playbook'}

    mock_loop_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.loop_on_alerts")

    split_by_playbooks(incidents, limit=4, reopen_closed_inv=False,
                       playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    assert mock_loop_on_alerts.call_count == 0

    assert "Could not find an attached playbook for alerts: ['alert1', 'alert2', 'alert3']." in \
        results_summary_instance.results_summary["others"]


def test_split_by_playbooks_limit(mocker):
    """
    GIVEN:
        A list of incidents with varying playbook IDs and a specified limit on the number of incidents.

    WHEN:
        The 'split_by_playbooks' function is called with the provided incidents and a limit of 3.

    THEN:
        It should call the 'loop_on_alerts' function for each unique playbook,
        processing only up to the specified limit of incidents per playbook,
        and correctly handle incidents exceeding the limit.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    incidents = [
        {"id": "alert1", "playbookId": "playbook_123"},
        {"id": "alert2", "playbookId": "playbook_123"},
        {"id": "alert3", "playbookId": "playbook_456"},
        {"id": "alert4", "playbookId": "playbook_123"},
        {"id": "alert5", "playbookId": "playbook_456"},
    ]
    playbooks_dict = {'playbook_123': 'First Playbook', 'playbook_456': 'Second Playbook'}

    mock_loop_on_alerts = mocker.patch("TroubleshootExecutePlaybookByAlertQuery.loop_on_alerts")

    split_by_playbooks(incidents, limit=3, reopen_closed_inv=False,
                       playbooks_dict=playbooks_dict, results_summary=results_summary_instance, flag_pending_idle=False)

    assert mock_loop_on_alerts.call_count == 2
    mock_loop_on_alerts.assert_any_call(
        [{'id': 'alert1', 'playbookId': 'playbook_123'}, {'id': 'alert2', 'playbookId': 'playbook_123'}],
        'playbook_123',
        3,
        False,
        playbooks_dict,
        results_summary_instance,
        False
    )
    mock_loop_on_alerts.assert_any_call(
        [{'id': 'alert3', 'playbookId': 'playbook_456'}],
        'playbook_456',
        3,
        False,
        playbooks_dict,
        results_summary_instance,
        False
    )


def test_get_playbooks_dict_success(mocker):
    """
    GIVEN:
        A mocked execution of the 'executeCommand' function that simulates the retrieval of playbook data.

    WHEN:
        The 'get_playbooks_dict' function is called, which internally invokes 'executeCommand' to fetch playbook information.

    THEN:
        It should return a dictionary mapping playbook IDs to their respective names, matching the expected structure.
    """
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_execute_command.return_value = [{
        "Contents": {
            "response": {
                "playbook_id_1": "Playbook Name 1",
                "playbook_id_2": "Playbook Name 2"
            }
        }
    }]

    result = get_playbooks_dict()

    expected_result = {
        "playbook_id_1": "Playbook Name 1",
        "playbook_id_2": "Playbook Name 2"
    }
    assert result == expected_result


def test_get_playbooks_dict_invalid_response_format(mocker):
    """
    GIVEN:
        A mocked execution of the 'executeCommand' function that simulates an empty response.

    WHEN:
        The 'get_playbooks_dict' function is called, which attempts to retrieve playbook information.

    THEN:
        It should raise a DemistoException indicating that the response format is invalid, as the response is empty.
    """
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_execute_command.return_value = []

    with pytest.raises(DemistoException) as e:
        get_playbooks_dict()

    assert "Invalid response format while searching for playbooks." in str(e)


def test_get_playbooks_dict_no_playbooks_found(mocker):
    """
    GIVEN:
        A mocked execution of the 'executeCommand' function that simulates a response with no playbooks.

    WHEN:
        The 'get_playbooks_dict' function is called, which attempts to retrieve playbook information.

    THEN:
        It should raise a DemistoException indicating that no playbooks were found in the response.
    """
    mock_execute_command = mocker.patch.object(demisto, 'executeCommand')
    mock_execute_command.return_value = [{
        "Contents": {
            "response": {}
        }
    }]

    with pytest.raises(DemistoException) as e:
        get_playbooks_dict()

    assert "No playbooks found. Please ensure that playbooks are available and try again." in str(e)


def test_generate_summary():
    """
    GIVEN:
        A ResultsSummary instance with predefined success, failure, reopened, and other messages.
    WHEN:
        The generate_summary method is called.
    THEN:
        It should return a summary message that includes:
            - Alerts that had a successful playbook set.
            - Alerts where playbook creation failed.
            - Alerts where playbook setting failed.
            - Alerts that were reopened.
            - Any additional messages in the 'others' field.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {
        "success": {
            "123": ["alert1", "alert2"],
            "456": ["alert3"]
        },
        "failure_create": {
            "789": ["alert4"]
        },
        "failure_set": {
            "999": ["alert5", "alert6"]
        },
        "reopened": ["alert7", "alert8"],
        "others": ["Some other information here."]
    }

    summary = results_summary_instance.generate_summary()

    expected_summary = (
        "Playbook Test Playbook 1 with ID 123 was set successfully for alerts: ['alert1', 'alert2'].\n"
        "Playbook Test Playbook 2 with ID 456 was set successfully for alerts: ['alert3'].\n"
        "Playbook with ID 789 could not be executed for alerts: ['alert4'].\n"
        "Playbook with ID 999 was not found for alerts: ['alert5', 'alert6'].\n"
        "Alerts ['alert7', 'alert8'] have been reopened.\n"
        "Some other information here."
    )

    assert summary == expected_summary


def test_update_success_with_string_alert_id():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'success' dictionary.
    WHEN:
        update_success is called with a playbook ID and a single alert ID as a string.
    THEN:
        The 'success' dictionary should be updated with the alert ID for the given playbook ID.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"success": {}}

    results_summary_instance.update_success("playbook_123", "alert1")
    assert results_summary_instance.results_summary["success"]["playbook_123"] == ["alert1"]

    results_summary_instance.update_success("playbook_123", "alert2")
    assert results_summary_instance.results_summary["success"]["playbook_123"] == ["alert1", "alert2"]


def test_update_success_with_list_alert_ids():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'success' dictionary.
    WHEN:
        update_success is called with a playbook ID and a list of alert IDs.
    THEN:
        The 'success' dictionary should be updated with all the alert IDs for the given playbook ID.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"success": {}}

    results_summary_instance.update_success("playbook_123", ["alert1", "alert2"])
    assert results_summary_instance.results_summary["success"]["playbook_123"] == ["alert1", "alert2"]

    results_summary_instance.update_success("playbook_123", ["alert3", "alert4"])
    assert results_summary_instance.results_summary["success"]["playbook_123"] == ["alert1", "alert2", "alert3", "alert4"]


def test_update_failure_create_with_string_failed_id():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'failure_create' dictionary.
    WHEN:
        update_failure_create is called with a playbook ID and a single failed ID as a string.
    THEN:
        The 'failure_create' dictionary should be updated with the failed ID for the given playbook ID.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"failure_create": {}}

    results_summary_instance.update_failure_create("playbook_789", "alert4")
    assert results_summary_instance.results_summary["failure_create"]["playbook_789"] == ["alert4"]

    results_summary_instance.update_failure_create("playbook_789", "alert5")
    assert results_summary_instance.results_summary["failure_create"]["playbook_789"] == ["alert4", "alert5"]


def test_update_failure_create_with_list_failed_ids():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'failure_create' dictionary.
    WHEN:
        update_failure_create is called with a playbook ID and a list of failed IDs.
    THEN:
        The 'failure_create' dictionary should be updated with all the failed IDs for the given playbook ID.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"failure_create": {}}

    results_summary_instance.update_failure_create("playbook_789", ["alert4", "alert5"])
    assert results_summary_instance.results_summary["failure_create"]["playbook_789"] == ["alert4", "alert5"]

    results_summary_instance.update_failure_create("playbook_789", ["alert6", "alert7"])
    assert results_summary_instance.results_summary["failure_create"]["playbook_789"] == ["alert4", "alert5", "alert6", "alert7"]


def test_update_failure_set():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'failure_set' dictionary.
    WHEN:
        update_failure_set is called with a playbook ID and a list of alert IDs.
    THEN:
        The 'failure_set' dictionary should be updated with the alert IDs for the given playbook ID.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"failure_set": {}}

    results_summary_instance.update_failure_set("playbook_456", ["alert7", "alert8"])

    assert results_summary_instance.results_summary["failure_set"] == {"playbook_456": ["alert7", "alert8"]}

    results_summary_instance.update_failure_set("playbook_456", ["alert9"])
    assert results_summary_instance.results_summary["failure_set"]["playbook_456"] == ["alert7", "alert8", "alert9"]


def test_update_reopened():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'reopened' list.
    WHEN:
        update_reopened is called with a list of reopened alerts.
    THEN:
        The 'reopened' list should be updated with the provided alerts.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"reopened": []}

    results_summary_instance.update_reopened(["alert10", "alert11"])

    assert results_summary_instance.results_summary["reopened"] == ["alert10", "alert11"]


def test_append_to_others():
    """
    GIVEN:
        A ResultsSummary instance with an empty 'others' list.
    WHEN:
        append_to_others is called with a message.
    THEN:
        The 'others' list should be updated with the provided message.
    """
    results_summary_instance = ResultsSummary(PLAYBOOKS_DICT)
    results_summary_instance.results_summary = {"others": []}

    results_summary_instance.append_to_others("Test message")

    assert results_summary_instance.results_summary["others"] == ["Test message"]


def test_get_playbook_info():
    """
    GIVEN:
        A playbook ID and a dictionary mapping playbook IDs to names.
    WHEN:
        The get_playbook_info function is called.
    THEN:
        It should return the correct playbook information string based on whether the ID exists in the dictionary.
    """
    playbook_dict = {
        "123": "Test Playbook 1",
        "456": "Test Playbook 2",
        "789": "Test Playbook 3"
    }

    playbook_info_123 = get_playbook_info("123", playbook_dict)
    expected_info_123 = "Test Playbook 1 with ID 123"
    assert playbook_info_123 == expected_info_123

    playbook_info_999 = get_playbook_info("999", playbook_dict)
    expected_info_999 = "with ID 999"
    assert playbook_info_999 == expected_info_999

    playbook_info_456 = get_playbook_info("456", playbook_dict)
    expected_info_456 = "Test Playbook 2 with ID 456"
    assert playbook_info_456 == expected_info_456

    playbook_info_789 = get_playbook_info("789", playbook_dict)
    expected_info_789 = "Test Playbook 3 with ID 789"
    assert playbook_info_789 == expected_info_789
