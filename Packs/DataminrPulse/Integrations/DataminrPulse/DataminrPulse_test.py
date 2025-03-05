"""Dataminr Pulse Integration for Cortex XSOAR - Unit Tests file."""

import io
import json
import os

import pytest

from DataminrPulse import (
    BASE_URL,
    ENDPOINTS,
    ERRORS,
    timezone,
    datetime,
    DemistoException,
    OUTPUT_PREFIX_WATCHLISTS,
    OUTPUT_PREFIX_ALERTS,
    OUTPUT_PREFIX_CURSOR,
    remove_empty_elements,
    MAX_NUMBER_OF_ALERTS_TO_RETRIEVE,
)


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with io.open(path, mode="r", encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    from DataminrPulse import DataminrPulseClient

    client = DataminrPulseClient(client_id="client_id", client_secret="client_secret", proxy=False, verify=False)
    return client


@pytest.fixture
def mock_client_with_valid_token(requests_mock):
    """Mock a client object with required data to mock."""
    from DataminrPulse import DataminrPulseClient

    client = DataminrPulseClient(client_id="client_id", client_secret="client_secret", proxy=False, verify=False)
    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 + 40000})
    requests_mock.post(f'{BASE_URL}{ENDPOINTS["AUTH_ENDPOINT"]}', json=token_response, status_code=200)
    return client


def test_test_module_invalid_credentials(requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module with invalid credentials.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from DataminrPulse import test_module

    unauthorized_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_401.json")
    )
    requests_mock.post(f'{BASE_URL}{ENDPOINTS["AUTH_ENDPOINT"]}', json=unauthorized_response, status_code=401)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == ERRORS["GENERAL_AUTH_ERROR"].format(unauthorized_response)


def test_test_module(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for successful execution of test_module.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns an ok message
    """
    from DataminrPulse import test_module

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_success.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["ALERTS_ENDPOINT"]}', json=mock_response_alerts, status_code=200)
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)
    assert test_module(mock_client_with_valid_token) == "ok"


def test_test_module_auth_failure_before_expire(requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module when auth token fails before expire time.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from DataminrPulse import test_module

    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 + 40000})
    requests_mock.post(f'{BASE_URL}{ENDPOINTS["AUTH_ENDPOINT"]}', json=token_response, status_code=200)

    watchlist_response_401: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_401.json")
    )
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=watchlist_response_401, status_code=401)
    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == ERRORS["UNAUTHORIZED_REQUEST"].format(watchlist_response_401)


def test_test_module_auth_failure_after_expire(requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module when auth token fails after expire time.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from DataminrPulse import test_module

    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 - 40000})
    requests_mock.post(f'{BASE_URL}{ENDPOINTS["AUTH_ENDPOINT"]}', json=token_response, status_code=200)

    watchlist_response_401: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_401.json")
    )
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=watchlist_response_401, status_code=401)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == ERRORS["UNAUTHORIZED_REQUEST"].format(watchlist_response_401)


@pytest.mark.parametrize(
    "args, err_msg", [({"max_fetch": "-1", "use_configured_watchlist_names": "false"}, ERRORS["INVALID_MAX_FETCH"].format(-1))]
)
def test_fetch_incident_when_invalid_arguments_provided(args, err_msg, mock_client_with_valid_token, requests_mock, capfd):
    """
    Test case scenario for execution of fetch_incidents when invalid arguments are provided.

    Given:
        - command arguments for fetch_incidents
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid error message.
    """
    from DataminrPulse import fetch_incidents

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)

    with pytest.raises(ValueError) as err:
        capfd.close()
        fetch_incidents(mock_client_with_valid_token, {}, args)

    assert str(err.value) == err_msg


def test_fetch_incident_when_watchlist_name_not_matched(requests_mock, mock_client_with_valid_token, capfd):
    """
    Test case scenario for execution of fetch_incidents when watchlist_names is not matched.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulse import fetch_incidents

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)

    with pytest.raises(ValueError) as err:
        capfd.close()
        fetch_incidents(mock_client_with_valid_token, {}, {"watchlist_names": "my_name"})
    assert str(err.value) == ERRORS["NOT_MATCHED_WATCHLIST_NAMES"]


def test_fetch_incident_success_with_last_run(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for execution of fetch_incident when last_run is given.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from DataminrPulse import fetch_incidents

    _from = "H4sIAAAAAAAAAFWQ3UdDcRyHz2d+JjNJkiRJkqSSSZKkUkeSJEmSNDYzZss6f0Cmi6nVRXqhdOqiRKb4nmQya6ayVqaL1MzMVGaxLCl76fXcdvPcPo9HwRoFrcGg13Wa9FZhun5KaxWMgtFi1usm31KEkcAXoda9n0V+dFVCqdMhoWn9kzAQfiSUny1sMlXEt8m4xQyhzbVLGLUHCB2eWBbq8AqhO+cljB3vELqSeyJj7vksCrxpQuvBM6Ex6smg+DVJGLr+IAwGZDQHIwSeZNTNxQkNkRdCjS+VQZH/hFARuiJUv8dFlhf3S+hdPiKM/+QIVbc+wvD+OaEvt5tBofOSUHZxQ6jcdhHaE3JVS3hNZApbgqCZDRL63TaRKcUlCSUPsmOC0/xbYbaYe3RGwWI1ak3qua0sn/cU+uVVO8k0zxz2H17hv4ttgJtxfPNKjovdH/pOtX8DCr1xTwEAAA=="  # noqa: E501
    last_run = {"from": _from, "last_watchlist_names": ["Data Security"], "last_query": None, "found_alert_ids": []}

    incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents.json")
    )

    alert_ids = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_alert_ids.json")
    )

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_with_parent_success.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["ALERTS_ENDPOINT"]}', json=mock_response_alerts, status_code=200)
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)

    next_run, actual_incidents = fetch_incidents(
        mock_client_with_valid_token, last_run, {"max_fetch": 201, "watchlist_names": "Data Security", "alert_type": "Alert"}
    )

    assert next_run == {
        "found_alert_ids": alert_ids,
        "from": _from,
        "last_query": None,
        "last_watchlist_names": ["Data Security"],
    }
    assert actual_incidents == incidents


def test_fetch_incident_success(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for execution of fetch_incident.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from DataminrPulse import fetch_incidents

    incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents.json")
    )

    alert_ids = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_alert_ids.json")
    )

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_success.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["ALERTS_ENDPOINT"]}', json=mock_response_alerts, status_code=200)
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)

    next_run, actual_incidents = fetch_incidents(mock_client_with_valid_token, {}, {"max_fetch": 40})

    _from = "H4sIAAAAAAAAAFWQ3UdDcRyHz2d+JjNJkiRJkqSSSZKkUkeSJEmSNDYzZss6f0Cmi6nVRXqhdOqiRKb4nmQya6ayVqaL1MzMVGaxLCl76fXcdvPcPo9HwRoFrcGg13Wa9FZhun5KaxWMgtFi1usm31KEkcAXoda9n0V+dFVCqdMhoWn9kzAQfiSUny1sMlXEt8m4xQyhzbVLGLUHCB2eWBbq8AqhO+cljB3vELqSeyJj7vksCrxpQuvBM6Ex6smg+DVJGLr+IAwGZDQHIwSeZNTNxQkNkRdCjS+VQZH/hFARuiJUv8dFlhf3S+hdPiKM/+QIVbc+wvD+OaEvt5tBofOSUHZxQ6jcdhHaE3JVS3hNZApbgqCZDRL63TaRKcUlCSUPsmOC0/xbYbaYe3RGwWI1ak3qua0sn/cU+uVVO8k0zxz2H17hv4ttgJtxfPNKjovdH/pOtX8DCr1xTwEAAA=="  # noqa: E501

    assert next_run == {"found_alert_ids": alert_ids, "from": _from, "last_query": None, "last_watchlist_names": []}
    assert actual_incidents == incidents


def test_dataminr_watchlists_get_command_for_success(requests_mock, mock_client_with_valid_token):
    """Test case scenario for successful execution of dataminrpulse-watchlists-get-command.
    Given:
        - dataminrpulse-watchlists-get-command function and mock_client to call the function.
    When:
        - Valid arguments are provided to the command.
    Then:
        - Should return proper human-readable string and context data.
    """
    from DataminrPulse import dataminrpulse_watchlists_get_command

    watchlists_get_for_success_raw_resp = util_load_json(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data/dataminr_watchlists_get_command_for_success_response.json"
        )
    )
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=watchlists_get_for_success_raw_resp)
    resp = dataminrpulse_watchlists_get_command(mock_client_with_valid_token, {})

    watchlists_get_for_success_outputs_resp = util_load_json(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data/dataminr_watchlists_get_command_for_success_output.json"
        )
    )
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/dataminr_watchlist_get.md")) as f:
        dataminr_watchlists_get_hr = f.read()

    assert resp.outputs == remove_empty_elements(watchlists_get_for_success_outputs_resp)
    assert resp.raw_response == watchlists_get_for_success_raw_resp
    assert resp.readable_output == dataminr_watchlists_get_hr
    assert resp.outputs_key_field == "id"
    assert resp.outputs_prefix == OUTPUT_PREFIX_WATCHLISTS


def test_alerts_get_command_success(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_alerts_get function.

    Given:
        - command arguments for dataminrpulse_alerts_get
    When:
        - Calling `dataminrpulse_alerts_get` function
    Then:
        - Returns a valid output
    """
    from DataminrPulse import dataminrpulse_alerts_get

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_success.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["ALERTS_ENDPOINT"]}', json=mock_response_alerts, status_code=200)

    actual = dataminrpulse_alerts_get(
        mock_client_with_valid_token,
        args={
            "query": "linux",
            "watchlist_ids": "3320155",
            "to": "H4sIAAAAAAAAAFWQ3StDcRyHz2f90lpLkiRJkiShJUmSECdJkiR",
            "num": "2",
            "use_configured_watchlist_names": "false",
        },
    )

    raw_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_raw_response.json")
    )

    raw_response_cursor = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_cursor_raw_response.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_success_hr.md")) as file:
        hr_output_for_alerts = file.read()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_cursor_success_hr.md")) as file:
        hr_output_for_cursor = file.read()

    assert actual[0].outputs_prefix == OUTPUT_PREFIX_ALERTS
    assert actual[0].outputs_key_field == "alertId"
    assert actual[0].raw_response == raw_response_alerts
    assert actual[0].outputs == remove_empty_elements(raw_response_alerts)
    assert actual[0].readable_output == hr_output_for_alerts

    assert actual[1].outputs_prefix == OUTPUT_PREFIX_CURSOR
    assert actual[1].outputs_key_field == ["from", "to"]
    assert actual[1].raw_response == raw_response_cursor
    assert actual[1].outputs == remove_empty_elements(raw_response_cursor)
    assert actual[1].readable_output == hr_output_for_cursor


def test_alerts_get_command_success_with_watchlist_names(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_alerts_get function.

    Given:
        - command arguments for dataminrpulse_alerts_get
    When:
        - Calling `dataminrpulse_alerts_get` function
    Then:
        - Returns a valid output
    """
    from DataminrPulse import dataminrpulse_alerts_get

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_success.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["ALERTS_ENDPOINT"]}', json=mock_response_alerts, status_code=200)
    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)

    actual = dataminrpulse_alerts_get(
        mock_client_with_valid_token,
        args={
            "watchlist_names": "Data Security",
            "query": "linux",
            "from": "H4sIAAAAAAAAAFWQ3StDcRyHz2f90lpLkiRJkiShJUmSECdJkiR",
            "num": "2",
        },
    )

    raw_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_raw_response.json")
    )

    raw_response_cursor = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_cursor_raw_response.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_success_hr.md")) as file:
        hr_output_for_alerts = file.read()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_cursor_success_hr.md")) as file:
        hr_output_for_cursor = file.read()

    assert actual[0].outputs_prefix == OUTPUT_PREFIX_ALERTS
    assert actual[0].outputs_key_field == "alertId"
    assert actual[0].raw_response == raw_response_alerts
    assert actual[0].outputs == remove_empty_elements(raw_response_alerts)
    assert actual[0].readable_output == hr_output_for_alerts

    assert actual[1].outputs_prefix == OUTPUT_PREFIX_CURSOR
    assert actual[1].outputs_key_field == ["from", "to"]
    assert actual[1].raw_response == raw_response_cursor
    assert actual[1].outputs == remove_empty_elements(raw_response_cursor)
    assert actual[1].readable_output == hr_output_for_cursor


@pytest.mark.parametrize(
    "args, err_msg",
    [
        ({"num": "-1", "use_configured_watchlist_names": "false"}, ERRORS["INVALID_MAX_NUM"].format("-1", "3333")),
        (
            {"num": "{}".format(MAX_NUMBER_OF_ALERTS_TO_RETRIEVE + 1), "use_configured_watchlist_names": "false"},
            ERRORS["INVALID_MAX_NUM"].format(MAX_NUMBER_OF_ALERTS_TO_RETRIEVE + 1, 3333),
        ),
        ({"use_configured_watchlist_names": "false"}, ERRORS["AT_LEAST_ONE_REQUIRED"].format("query", "watchlist_ids")),
        (
            {"use_configured_watchlist_names": "false", "query": "linux", "from": "from", "to": "to"},
            ERRORS["EITHER_ONE_REQUIRED"].format("from", "to"),
        ),
    ],
)
def test_dataminrpulse_alerts_get_when_invalid_argument_provided(args, err_msg, mock_client_with_valid_token):
    """
    Test case scenario for execution of dataminrpulse_alerts_get when invalid argument provided.

    Given:
        - command arguments for dataminrpulse_alerts_get
    When:
        - Calling `dataminrpulse_alerts_get` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulse import dataminrpulse_alerts_get

    with pytest.raises(ValueError) as err:
        dataminrpulse_alerts_get(mock_client_with_valid_token, args)
    assert str(err.value) == err_msg


def test_dataminrpulse_alerts_get_when_watchlist_name_not_matched(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for execution of dataminrpulse_alerts_get when watchlist_names is not matched.

    Given:
        - command arguments for dataminrpulse_alerts_get
    When:
        - Calling `dataminrpulse_alerts_get` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulse import dataminrpulse_alerts_get

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_for_get_alerts.json")
    )

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json=mock_response_watchlists, status_code=200)

    with pytest.raises(ValueError) as err:
        dataminrpulse_alerts_get(
            mock_client_with_valid_token, {"use_configured_watchlist_names": "true", "watchlist_names": "my_name"}
        )
    assert str(err.value) == ERRORS["NOT_MATCHED_WATCHLIST_NAMES"]


def test_dataminrpulse_alerts_get_when_watchlist_data_is_empty(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for execution of dataminrpulse_alerts_get when watchlist data is empty list.

    Given:
        - command arguments for dataminrpulse_alerts_get
    When:
        - Calling `dataminrpulse_alerts_get` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulse import dataminrpulse_alerts_get

    requests_mock.get(f'{BASE_URL}{ENDPOINTS["WATCHLISTS_ENDPOINT"]}', json={"watchlists": {"xyz": []}}, status_code=200)

    with pytest.raises(ValueError) as err:
        dataminrpulse_alerts_get(mock_client_with_valid_token, {"use_configured_watchlist_names": "true", "watchlist_names": ""})
    assert str(err.value) == ERRORS["AT_LEAST_ONE_REQUIRED"].format("query", "watchlist_names configured in integration")


def test_dataminr_related_alert_get_command_for_success(requests_mock, mock_client_with_valid_token):
    """Test case scenario for successful execution of dataminrpulse-related-alerts-get command.

    Given:
        - dataminrpulse-related-alerts-get command function and mock_client to call the function.
    When:
        - Valid arguments are provided to the command.
    Then:
        - Should return proper human-readable string and context data.
    """
    from DataminrPulse import dataminrpulse_related_alerts_get_command

    related_alert_get_for_success_raw_resp = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/dataminr_related_alert_success_response.json")
    )

    requests_mock.get(f"{BASE_URL}/{ENDPOINTS['RELATED_ALERTS_ENDPOINT']}", json=related_alert_get_for_success_raw_resp)

    resp = dataminrpulse_related_alerts_get_command(
        mock_client_with_valid_token, args={"alert_id": "10970294382677847841669364079567-1669364079599-1", "include_root": False}
    )

    dataminr_related_get_for_success_outputs_resp = util_load_json(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "test_data/dataminr_related_alert_get_command_for_success_output.json"
        )
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/dataminr_related_alert.md")) as f:
        dataminr_related_alert_hr = f.read()

    assert resp.outputs == remove_empty_elements(dataminr_related_get_for_success_outputs_resp)
    assert resp.raw_response == related_alert_get_for_success_raw_resp
    assert resp.readable_output == dataminr_related_alert_hr
    assert resp.outputs_key_field == "alertId"
    assert resp.outputs_prefix == OUTPUT_PREFIX_ALERTS


def test_related_alert_get_with_invalid_parameters(mock_client_with_valid_token):
    """Test case scenario for unsuccessful execution of dataminrpulse-related-alert-get-command.

    Given:
        - dataminrpulse-related-alert-get-command function and mock_client to call the function.
    When:
        - Invalid arguments are provided to the command.
    Then:
        - Should raise exception for required parameter if it is missing.
    """
    from DataminrPulse import dataminrpulse_related_alerts_get_command

    with pytest.raises(ValueError) as exc:
        dataminrpulse_related_alerts_get_command(mock_client_with_valid_token, args={"alert_id": "", "include_root": False})
    assert str(exc.value) == ERRORS["INVALID_REQUIRED_PARAMETER"].format("alert_id")
