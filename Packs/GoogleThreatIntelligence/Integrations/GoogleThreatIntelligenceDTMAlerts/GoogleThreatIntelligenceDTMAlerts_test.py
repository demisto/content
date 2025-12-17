from GoogleThreatIntelligenceDTMAlerts import (
    MAX_FETCH,
    Client,
    BASE_URL,
    ENDPOINTS,
    MESSAGES,
    ERROR_MESSAGES,
    ALERTS_ALERT_TYPE_LIST,
    ALERTS_STATUS_HUMAN_READABLE,
    ALERTS_SEVERITY_HUMAN_READABLE,
    ALERTS_ORDER_HR_LIST,
    ALERTS_SORT_HR_LIST,
)
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
import json
import pytest


# Helper Functions
def util_load_json(path):
    """Load JSON data from file."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client(mocker):
    """Create a mocked client for testing."""
    return Client(verify_certificate=False, proxy=False, api_key="test_api_key")


def test_client_initialization():
    """Test Client class initialization."""
    client = Client(verify_certificate=True, proxy=False, api_key="test_key_123")

    # Verify client is properly initialized
    assert client._base_url == BASE_URL
    assert client._headers["x-apikey"] == "test_key_123"
    assert client._headers["x-tool"] == "CortexGTI"
    assert client._headers["Accept"] == "application/json"
    assert client._headers["Content-Type"] == "application/json"


def test_test_module_success(mock_client, requests_mock):
    """Test test_module function returns 'ok' when API call succeeds."""
    from GoogleThreatIntelligenceDTMAlerts import test_module

    requests_mock.get(f'{BASE_URL}/{ENDPOINTS["alert_list"]}', json={}, status_code=200)
    result = test_module(client=mock_client)

    # Verify the function returns "ok"
    assert result == "ok"


def test_test_module_invalid_api_key(mock_client, requests_mock):
    """Test test_module function returns 'ok' when API call succeeds."""
    from GoogleThreatIntelligenceDTMAlerts import test_module

    requests_mock.get(
        f'{BASE_URL}/{ENDPOINTS["alert_list"]}',
        json={"error": {"code": "WrongCredentialsError", "message": "Wrong API key"}},
        status_code=401,
    )
    with pytest.raises(DemistoException) as e:
        test_module(client=mock_client)

    assert (
        str(e.value) == "401 Unauthorized request: Invalid API key provided "
        "{'error': {'code': 'WrongCredentialsError', 'message': 'Wrong API key'}}."
    )


def test_main_test_module_success(mocker, requests_mock):
    """
    Given:
    - Valid parameters and test-module command.

    When:
    - Running the main function.

    Then:
    - Validate that test_module is called and returns 'ok'.
    """
    from GoogleThreatIntelligenceDTMAlerts import main

    # Mock demisto functions
    mock_params = {"credentials": {"password": "test_api_key"}, "insecure": False, "proxy": False}
    mock_demisto = mocker.patch("GoogleThreatIntelligenceDTMAlerts.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = "test-module"
    mock_demisto.args.return_value = {}
    mock_demisto.debug = mocker.Mock()

    # Mock return_results and return_error
    mock_return_results = mocker.patch("GoogleThreatIntelligenceDTMAlerts.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceDTMAlerts.return_error")

    # Mock the API call for test_module
    requests_mock.get(f'{BASE_URL}/{ENDPOINTS["alert_list"]}', json={}, status_code=200)

    # Call main
    main()

    # Assertions
    mock_demisto.command.assert_called_once()
    mock_return_results.assert_called_once_with("ok")
    mock_return_error.assert_not_called()


@pytest.mark.parametrize(
    "command, args, mock_api_response, expected_result_type",
    [("test-module", {}, {}, str), ("gti-dtm-alert-get", {"alert_id": "test_123"}, "dtm_alert_get.json", type(None))],
)
def test_main_try_block_success_paths(mocker, requests_mock, command, args, mock_api_response, expected_result_type):
    """
    Given:
    - Valid parameters and different commands.

    When:
    - Running the main function try block.

    Then:
    - Validate that the appropriate command is executed and return_results is called.
    """
    from GoogleThreatIntelligenceDTMAlerts import main

    # Mock demisto functions
    mock_params = {"credentials": {"password": "test_api_key"}, "insecure": False, "proxy": False}
    mock_demisto = mocker.patch("GoogleThreatIntelligenceDTMAlerts.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = command
    mock_demisto.args.return_value = args
    mock_demisto.debug = mocker.Mock()

    # Mock return_results and return_error
    mock_return_results = mocker.patch("GoogleThreatIntelligenceDTMAlerts.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceDTMAlerts.return_error")

    # Mock API responses based on command
    if command == "test-module":
        requests_mock.get(f'{BASE_URL}/{ENDPOINTS["alert_list"]}', json=mock_api_response, status_code=200)
    elif command == "gti-dtm-alert-get":
        mock_response = util_load_json(f"test_data/{mock_api_response}")
        requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_get'].format(args['alert_id'])}", json=mock_response)

    # Call main
    main()

    # Assertions
    mock_return_results.assert_called_once()
    mock_return_error.assert_not_called()

    # Verify the result type if needed
    if command == "test-module":
        mock_return_results.assert_called_with("ok")


def test_main_try_block_unknown_command_exception(mocker):
    """
    Given:
    - An unknown command that raises NotImplementedError.

    When:
    - Running the main function with unknown command.

    Then:
    - Validate that NotImplementedError is caught and return_error is called.
    """
    from GoogleThreatIntelligenceDTMAlerts import main

    # Mock demisto functions
    mock_params = {"credentials": {"password": "test_api_key"}, "insecure": False, "proxy": False}
    mock_demisto = mocker.patch("GoogleThreatIntelligenceDTMAlerts.demisto")
    mock_demisto.params.return_value = mock_params
    mock_demisto.command.return_value = "unknown-command"
    mock_demisto.args.return_value = {}

    # Mock return functions
    mock_return_results = mocker.patch("GoogleThreatIntelligenceDTMAlerts.return_results")
    mock_return_error = mocker.patch("GoogleThreatIntelligenceDTMAlerts.return_error")

    # Call main
    main()

    # Verify exception handling
    mock_return_error.assert_called_once()
    error_message = mock_return_error.call_args[0][0]

    # Verify error message contains expected content
    assert "Failed to execute unknown-command command" in error_message
    assert "Command unknown-command is not implemented" in error_message

    mock_return_results.assert_not_called()


def test_gti_alert_get_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid alert ID.

    When:
    - Running the !gti-alert-get command.

    Then:
    - Validate the command results are valid.
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_get_command

    mock_response = util_load_json("test_data/dtm_alert_get.json")
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/dtm_alert_get_human_readable.md")) as f:
        dtm_alert_list_hr = f.read()

    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['alert_get'].format('dummy_0000')}?sanitize=true&refs=true&truncate=1000", json=mock_response
    )

    test_args = {
        "alert_id": "dummy_0000",
        "truncate": "1000",
        "sanitize": "Yes",
        "include_more_details": "Yes",
    }

    results = gti_dtm_alert_get_command(client=mock_client, args=test_args)

    assert results.raw_response == mock_response
    assert results.readable_output == dtm_alert_list_hr
    assert results.outputs == [mock_response]


def test_gti_alert_get_command_no_record_found(mock_client, requests_mock):
    """
    Given:
    - An invalid alert ID.

    When:
    - Running the !gti-alert-get command.

    Then:
    - Validate the command results are valid.
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_get_command

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_get'].format('dummy_0000')}?sanitize=true&refs=true&truncate=1000", json={})

    test_args = {
        "alert_id": "dummy_0000",
        "truncate": "1000",
        "sanitize": "Yes",
        "include_more_details": "Yes",
    }

    results = gti_dtm_alert_get_command(client=mock_client, args=test_args)

    assert results.readable_output == "No DTM Alert was found for the given argument(s)."
    assert results.outputs is None
    assert results.raw_response is None


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"alert_id": ""}, ValueError, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"alert_id": "dummy123", "truncate": "-1"}, ValueError, ERROR_MESSAGES["INVALID_DTM_ALERT_TRUNCATE"].format("-1")),
    ],
)
def test_gti_dtm_alert_get_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input.

    When:
    - Running the !gti-dtm-alert-get command.

    Then:
    - Validate the command results are valid.
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_get_command

    with pytest.raises(exception) as e:
        gti_dtm_alert_get_command(client=mock_client, args=args)

    assert str(e.value) == error


def test_gti_dtm_alerts_list_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid query

    When:
    - Running the !gti-dtm-alerts-list command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_list_command

    mock_response = util_load_json("test_data/dtm_alerts_lists.json")

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/dtm_alerts_list_human_readable.md")) as f:
        dtm_alerts_list_hr = f.read()

    test_args = {
        "page_size": "1",
        "order": "desc",
        "sort": "created_at",
        "start_date": "2025-05-20T12:19:22.824000Z",
        "end_date": "2025-05-20T12:19:27.824000Z",
        "monitor_id": "dummy_monitor",
        "tags": "attempt",
        "status": "read",
        "alert_type": "Message",
        "severity": "low",
        "mscore_gte": "11",
        "include_more_details": "Yes",
        "include_monitor_name": "Yes",
        "has_analysis": "True",
        "search": "social",
        "match_value": "access",
    }

    # Mock the API call without params in requests_mock
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_list']}", json=mock_response)

    results = gti_dtm_alert_list_command(client=mock_client, args=test_args)

    assert results.readable_output == dtm_alerts_list_hr
    assert results.outputs == mock_response["alerts"]


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"page_size": "-1"}, ValueError, ERROR_MESSAGES["INVALID_PAGE_SIZE"].format("-1", MAX_FETCH)),
        ({"page_size": "26"}, ValueError, ERROR_MESSAGES["INVALID_PAGE_SIZE"].format("26", MAX_FETCH)),
        ({"order": "test"}, ValueError, ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "order", ALERTS_ORDER_HR_LIST)),
        ({"sort": "test"}, ValueError, ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "sort", ALERTS_SORT_HR_LIST)),
        (
            {"severity": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "severity", ALERTS_SEVERITY_HUMAN_READABLE),
        ),
        ({"mscore_gte": "-1"}, ValueError, ERROR_MESSAGES["INVALID_MSCORE_GTE"].format("-1")),
        ({"mscore_gte": "101"}, ValueError, ERROR_MESSAGES["INVALID_MSCORE_GTE"].format("101")),
        (
            {"alert_type": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "type", ALERTS_ALERT_TYPE_LIST),
        ),
        (
            {"status": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "status", ALERTS_STATUS_HUMAN_READABLE),
        ),
    ],
)
def test_gti_dtm_alerts_list_command_when_invalid_input(args, mocker, exception, error):
    """
    Given:
    - An invalid input

    When:
    - Running the !gti-dtm-alerts-list command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_list_command

    with pytest.raises(exception) as e:
        gti_dtm_alert_list_command(mock_client, args)

    assert str(e.value) == error


def test_gti_dtm_alerts_list_no_records_found(mock_client, requests_mock):
    """
    Given:
    - No records found

    When:
    - Running the !gti-dtm-alerts-list command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_list_command

    test_args = {
        "page_size": "1",
        "order": "desc",
        "sort": "created_at",
        "start_time": "2025-05-20T12:19:22.824000Z",
        "end_time": "2025-05-20T12:19:27.824000Z",
        "monitor_id": "dummymonitor",
        "tags": "attempt ,test",
        "status": "read ,New",
        "alert_type": "Message ",
        "severity": "low ,High",
        "mscore_gte": "11",
        "include_more_details": "Yes",
        "include_monitor_name": "Yes",
        "has_analysis": "True",
        "search": "surgesocialmarket",
        "match_value": "access",
    }
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_list']}", json={})

    results = gti_dtm_alert_list_command(mock_client, test_args)

    assert results.readable_output == "No DTM Alerts were found for the given argument(s)."
    assert results.outputs is None


def test_gti_update_dtm_alert_status_command_success(mock_client, requests_mock):
    """
    Given:
    - A valid alert ID and status

    When:
    - Running the !gti-update-dtm-alert-status command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_status_update_command

    mock_response = util_load_json("test_data/dtm_alert_status_update.json")
    with open(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/dtm_alert_status_update_human_readable.md")
    ) as f:
        dtm_alert_list_hr = f.read()

    test_args = {
        "alert_id": "dummy_alert_id",
        "status": "read",
    }
    requests_mock.patch(f"{BASE_URL}/dtm/alerts/dummy_alert_id", json=mock_response)

    results = gti_dtm_alert_status_update_command(mock_client, test_args)

    assert results.readable_output == dtm_alert_list_hr
    assert results.outputs == [mock_response]


@pytest.mark.parametrize(
    "args, exception, error",
    [
        ({"alert_id": ""}, ValueError, MESSAGES["REQUIRED_ARGUMENT"].format("alert_id")),
        ({"alert_id": "dummy123", "status": ""}, ValueError, MESSAGES["REQUIRED_ARGUMENT"].format("status")),
        (
            {"alert_id": "dummy123", "status": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "status", ALERTS_STATUS_HUMAN_READABLE),
        ),
    ],
)
def test_gti_update_dtm_alert_status_command_when_invalid_input(args, mock_client, exception, error):
    """
    Given:
    - An invalid input

    When:
    - Running the !gti-update-dtm-alert-status command

    Then:
    - Validate the command results are valid
    """
    from GoogleThreatIntelligenceDTMAlerts import gti_dtm_alert_status_update_command

    with pytest.raises(exception) as e:
        gti_dtm_alert_status_update_command(mock_client, args)

    assert str(e.value) == error


def test_fetch_incidents_test_connectivity_dtm_alerts(mock_client, requests_mock, mocker):
    """Test test_module function when fetch is enabled."""
    from GoogleThreatIntelligenceDTMAlerts import test_module

    params = {"isFetch": True, "max_fetch": "10", "first_fetch": "1 days", "mirror_direction": "Outgoing"}

    # Mock demisto.params() to return our test parameters
    mocker.patch.object(demisto, "params", return_value=params)

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_list']}", json={}, status_code=200)

    result = test_module(client=mock_client)

    assert result == "ok"


def test_fetch_incidents_dtm_alerts_success(mock_client, requests_mock, mocker):
    from GoogleThreatIntelligenceDTMAlerts import fetch_incidents

    mock_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents_dtm_alerts_success.json")
    )

    incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_dtm_alerts_success_incidents.json")
    )
    alert_ids = [alert["id"] for alert in mock_response["alerts"]]

    requests_mock.get(
        f"{BASE_URL}/{ENDPOINTS['alert_list']}",
        json=mock_response,
        headers={"link": f'<{BASE_URL}/{ENDPOINTS["alert_list"]}?page=next_page_token>'},
    )

    params = {
        "isFetch": False,
        "alert_match_value": ["attempt"],
        "alert_monitor_ids": ["monitor_id_000"],
        "alert_severity": ["Low", "Medium"],
        "alert_status": ["New"],
        "alert_tags": ["intrustion", "network"],
        "alert_type": ["Message"],
        "first_fetch": "1 days",
        "max_fetch": 3,
        "mirror_direction": "Outgoing",
    }
    mocker.patch.object(demisto, "params", return_value=params)

    alert_incidents, next_run_params = fetch_incidents(client=mock_client, params=params, last_run={})

    assert next_run_params["alert_ids"] == alert_ids
    assert next_run_params["last_alert_created_at"] == "2025-08-19T14:30:45.97Z"
    assert alert_incidents == incidents


def test_fetch_incidents_dtm_alerts_success_with_last_run(mock_client, requests_mock, mocker):
    from GoogleThreatIntelligenceDTMAlerts import fetch_incidents

    params = {
        "isFetch": False,
        "alert_match_value": ["attempt"],
        "alert_monitor_ids": ["monitor_id_000"],
        "alert_severity": ["Low", "Medium"],
        "alert_status": ["New"],
        "alert_tags": ["intrustion", "network"],
        "alert_type": ["Message"],
        "first_fetch": "1 days",
        "max_fetch": 3,
        "mirror_direction": "Outgoing",
    }
    mocker.patch.object(demisto, "params", return_value=params)
    last_run = {
        "alert_ids": ["dummy_001"],
        "last_alert_created_at": "2025-01-01T14:26:37Z",
        "next_page_link": "dummy_next_page_link",
    }

    mock_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents_dtm_alerts_success.json")
    )

    incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_dtm_alerts_success_incidents.json")
    )
    alert_ids = [alert["id"] for alert in mock_response["alerts"]]

    alert_ids_list = last_run["alert_ids"] + alert_ids

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_list']}", json=mock_response)

    alert_incidents, next_run_params = fetch_incidents(client=mock_client, params=params, last_run=last_run)

    assert next_run_params["alert_ids"] == alert_ids_list
    assert next_run_params["last_alert_created_at"] == "2025-08-19T14:30:45.97Z"
    assert alert_incidents == incidents


def test_fetch_incidents_dtm_alerts_skip_duplicate_alerts(mock_client, requests_mock, mocker):
    from GoogleThreatIntelligenceDTMAlerts import fetch_incidents

    params = {
        "isFetch": False,
        "alert_match_value": ["attempt"],
        "alert_monitor_ids": ["monitor_id_000"],
        "alert_severity": ["Low", "Medium"],
        "alert_status": ["New"],
        "alert_tags": ["intrustion", "network"],
        "alert_type": ["Message"],
        "first_fetch": "1 days",
        "max_fetch": 25,
        "mirror_direction": "Outgoing",
    }
    mocker.patch.object(demisto, "params", return_value=params)

    last_run = {
        "alert_ids": ["dummy_00"],
        "last_alert_created_at": "2025-08-10T14:26:37Z",
    }

    mock_response = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents_dtm_alerts_success.json")
    )

    alert_skip_dup_incidents = util_load_json(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_dtm_alerts_incidents_with_skip_duplicate.json"
        )
    )
    alert_ids = [alert["id"] for alert in mock_response["alerts"]]

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_list']}", json=mock_response)

    alert_incidents, next_run_params = fetch_incidents(client=mock_client, params=params, last_run=last_run)

    assert next_run_params["alert_ids"] == alert_ids
    assert next_run_params["last_alert_created_at"] == "2025-08-19T14:30:45.97Z"
    assert alert_incidents == alert_skip_dup_incidents


@pytest.mark.parametrize(
    "params, exception, error",
    [
        ({"max_fetch": "-1"}, ValueError, ERROR_MESSAGES["INVALID_MAX_FETCH"].format("-1")),
        ({"max_fetch": "0"}, ValueError, ERROR_MESSAGES["INVALID_MAX_FETCH"].format("0")),
        ({"max_fetch": "26"}, ValueError, ERROR_MESSAGES["INVALID_MAX_FETCH"].format("26")),
        ({"alert_mscore_gte": "-1"}, ValueError, ERROR_MESSAGES["INVALID_MSCORE_GTE"].format("-1")),
        ({"alert_mscore_gte": "101"}, ValueError, ERROR_MESSAGES["INVALID_MSCORE_GTE"].format("101")),
        (
            {"alert_type": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "type", ALERTS_ALERT_TYPE_LIST),
        ),
        (
            {"alert_status": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "status", ALERTS_STATUS_HUMAN_READABLE),
        ),
        (
            {"alert_severity": "test"},
            ValueError,
            ERROR_MESSAGES["INVALID_ARGUMENT"].format("test", "severity", ALERTS_SEVERITY_HUMAN_READABLE),
        ),
    ],
)
def test_validate_configuration_params_invalid(params, exception, error, mock_client, requests_mock):
    from GoogleThreatIntelligenceDTMAlerts import fetch_incidents

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_list']}", json={})

    with pytest.raises(exception) as error_message:
        fetch_incidents(client=mock_client, params=params, last_run={})

    assert str(error_message.value) == error


def test_update_remote_system_command_status_update_incident_closed(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status DONE and incident changed

    When:
    - Running update_remote_system_command

    Then:
    - Status should be updated to 'closed' via a PATCH request.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 2  # IncidentStatus.DONE
    mock_args.delta = {}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock the API endpoint
    requests_mock.patch(f"{BASE_URL}/{ENDPOINTS['alert_update'].format('alert_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 2,  # IncidentStatus.DONE
        "delta": {},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify the PATCH request was made with the correct payload
    history = requests_mock.request_history
    assert len(history) == 1
    assert history[0].method == "PATCH"
    assert history[0].json() == {"status": "closed"}


def test_update_remote_system_command_incident_active_with_no_delta(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status ACTIVE, no delta, and incident changed

    When:
    - Running update_remote_system_command

    Then:
    - Status should be updated to 'in_progress' via a PATCH request.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock the API endpoint
    requests_mock.patch(f"{BASE_URL}/{ENDPOINTS['alert_update'].format('alert_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify the PATCH request was made with the correct payload
    history = requests_mock.request_history
    assert len(history) == 1
    assert history[0].method == "PATCH"
    assert history[0].json() == {"status": "in_progress"}


def test_update_remote_system_command_tags_update_with_platform_tags_exist(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with tags in delta and incident changed
    - GTI platform has existing tags

    When:
    - Running update_remote_system_command

    Then:
    - Tags should be updated with platform case-sensitive matching via a PATCH request.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {"tags": ["test", "malware", "newtag"]}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoints
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_stat']}", json={"tag": [{"tag": "Test"}, {"tag": "Malware"}]})
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_get'].format('alert_456')}", json={"tags": ["ExistingTag"]})
    requests_mock.patch(f"{BASE_URL}/{ENDPOINTS['alert_update'].format('alert_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {"tags": ["test", "malware", "newtag"]},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify the PATCH request was made with the correct payload
    history = requests_mock.request_history
    assert len(history) == 3
    assert history[2].method == "PATCH"
    expected_tags = ["ExistingTag", "Test", "Malware", "newtag"]
    assert history[2].json() == {"tags": expected_tags}


def test_update_remote_system_command_tags_update_with_no_duplicate_tags_update(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with tags in delta that already exist in current tags

    When:
    - Running update_remote_system_command

    Then:
    - No duplicate tags should be added and no PATCH request should be sent.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {"tags": ["test", "ExistingTag"]}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoints
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_stat']}", json={"tag": [{"tag": "Test"}]})
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_get'].format('alert_456')}", json={"tags": ["Test", "ExistingTag"]})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {"tags": ["test", "ExistingTag"]},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify no PATCH request was made
    assert not any(req.method == "PATCH" for req in requests_mock.request_history)


def test_update_remote_system_command_incident_closed_and_tags_update(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status DONE and tags in delta

    When:
    - Running update_remote_system_command

    Then:
    - Both status and tags should be updated in a single PATCH request.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 2  # IncidentStatus.DONE
    mock_args.delta = {"tags": ["urgent"]}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoints
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_stat']}", json={"tag": [{"tag": "Urgent"}]})
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_get'].format('alert_456')}", json={"tags": []})
    requests_mock.patch(f"{BASE_URL}/{ENDPOINTS['alert_update'].format('alert_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 2,  # IncidentStatus.DONE
        "delta": {"tags": ["urgent"]},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify the PATCH request was made with the correct payload
    history = requests_mock.request_history
    assert len(history) == 3
    assert history[2].method == "PATCH"
    expected_update = {"status": "closed", "tags": ["Urgent"]}
    assert history[2].json() == expected_update


def test_update_remote_system_command_no_mirror_alert_id(mocker, requests_mock, mock_client):
    """
    Given:
    - Arguments with missing mirror alert ID

    When:
    - Running update_remote_system_command

    Then:
    - No update should be made and no API calls should be sent.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {}  # No alertid
    mock_args.inc_status = 2
    mock_args.delta = {"tags": ["test"]}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    args = {
        "remote_incident_id": "remote_123",
        "data": {},  # No alertid
        "inc_status": 2,
        "delta": {"tags": ["test"]},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify no API calls were made
    assert requests_mock.call_count == 0


def test_update_remote_system_command_incident_not_changed(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments but incident_changed is False

    When:
    - Running update_remote_system_command

    Then:
    - No update should be made and no API calls should be sent.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.incident_changed = False

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    args = {"remote_incident_id": "remote_123", "data": {"alertid": "alert_456"}, "incident_changed": False}

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify no API calls were made
    assert requests_mock.call_count == 0
    assert len(requests_mock.request_history) == 0


def test_update_remote_system_command_incident_active_and_tags_update(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status ACTIVE and delta present

    When:
    - Running update_remote_system_command

    Then:
    - Status should not be updated (only tags if present) via a PATCH request.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {"tags": ["test"]}  # Delta present
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock API endpoints
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_stat']}", json={"tag": [{"tag": "Test"}]})
    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['alert_get'].format('alert_456')}", json={"tags": []})
    requests_mock.patch(f"{BASE_URL}/{ENDPOINTS['alert_update'].format('alert_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {"tags": ["test"]},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify only tags were updated, not status
    history = requests_mock.request_history
    assert len(history) == 3
    assert history[2].method == "PATCH"
    expected_update = {"tags": ["Test"]}
    assert history[2].json() == expected_update


def test_update_remote_system_command_incident_reopen(mocker, requests_mock, mock_client):
    """
    Given:
    - Valid arguments with incident status ACTIVE and delta present

    When:
    - Running update_remote_system_command

    Then:
    - Status should not be updated (only tags if present) via a PATCH request.
    """
    from GoogleThreatIntelligenceDTMAlerts import update_remote_system_command

    # Mock UpdateRemoteSystemArgs
    mock_args = mocker.Mock()
    mock_args.remote_incident_id = "remote_123"
    mock_args.data = {"alertid": "alert_456"}
    mock_args.inc_status = 1  # IncidentStatus.ACTIVE
    mock_args.delta = {"closingUserId": "", "runStatus": ""}
    mock_args.incident_changed = True

    mocker.patch("GoogleThreatIntelligenceDTMAlerts.UpdateRemoteSystemArgs", return_value=mock_args)

    # Mock the API endpoint
    requests_mock.patch(f"{BASE_URL}/{ENDPOINTS['alert_update'].format('alert_456')}", json={"success": True})

    args = {
        "remote_incident_id": "remote_123",
        "data": {"alertid": "alert_456"},
        "inc_status": 1,  # IncidentStatus.ACTIVE
        "delta": {"closingUserId": "", "runStatus": ""},
        "incident_changed": True,
    }

    result = update_remote_system_command(mock_client, args)

    # Verify the result
    assert result == "remote_123"

    # Verify the PATCH request was made with the correct payload
    history = requests_mock.request_history
    assert len(history) == 1
    assert history[0].method == "PATCH"
    assert history[0].json() == {"status": "in_progress"}
