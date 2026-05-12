"""Dataminr Pulse - ReGenAI Integration for Cortex XSOAR - Unit Tests file."""

import json
import os

import pytest
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import

from DataminrPulseReGenAI import (
    BASE_URL,
    ENDPOINTS,
    ERRORS,
    MAX_NUMBER_OF_ALERTS_TO_RETRIEVE,
    timezone,
    datetime,
    DemistoException,
    demisto,
    OUTPUT_PREFIX_WATCHLISTS,
    remove_empty_elements,
    OUTPUT_PREFIX_ALERTS,
    OUTPUT_PREFIX_CURSOR,
    CUSTOM_OUTPUT_PREFIX,
    VENDOR_NAME,
    DEFAULT_RELIABILITY,
)


def util_load_json(path):
    """Load a JSON file to python dictionary."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    from DataminrPulseReGenAI import DataminrPulseReGenAIClient

    client = DataminrPulseReGenAIClient(client_id="client_id", client_secret="client_secret", proxy=False, verify=False)
    return client


@pytest.fixture
def mock_client_with_valid_token(requests_mock):
    """Mock a client object with required data to mock."""
    from DataminrPulseReGenAI import DataminrPulseReGenAIClient

    client = DataminrPulseReGenAIClient(client_id="client_id", client_secret="client_secret", proxy=False, verify=False)
    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 + 40000})
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=token_response, status_code=200)
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
    from DataminrPulseReGenAI import test_module

    unauthorized_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_401.json")
    )
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=unauthorized_response, status_code=401)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == ERRORS["GENERAL_AUTH_ERROR"].format(401, unauthorized_response)


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
    from DataminrPulseReGenAI import test_module

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)
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
    from DataminrPulseReGenAI import test_module

    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 + 40000})
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=token_response, status_code=200)

    alert_response_401: dict = {"error": "Token has been revoked."}
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=alert_response_401, status_code=401)
    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == ERRORS["UNAUTHORIZED_REQUEST"].format(401, alert_response_401)


def test_test_module_internal_retries_due_to_invalid_token(mocker, requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module when integration token is invalid.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from DataminrPulseReGenAI import test_module
    import DataminrPulseReGenAI

    integration_context = {"token": {"dmaToken": "token", "expire": 0}}
    mocker.patch.object(DataminrPulseReGenAI, "get_integration_context", return_value=integration_context)

    # first time request fails with 401
    alert_response_401: dict = {"error": "Token has been revoked."}
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=alert_response_401, status_code=401)

    # second time go for new token generation
    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 + 40000})
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=token_response, status_code=200)

    # third time request should be successful
    alert_response_200: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=alert_response_200, status_code=200)

    assert test_module(mock_client) == "ok"


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
    from DataminrPulseReGenAI import test_module

    token_response: dict = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_auth_token_200.json")
    )
    token_response.update({"expire": datetime.now(timezone.utc).timestamp() * 1000 - 40000})
    requests_mock.post(f"{BASE_URL}{ENDPOINTS['AUTH_ENDPOINT']}", json=token_response, status_code=200)

    alert_response_401: dict = {"error": "Token has been revoked."}
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=alert_response_401, status_code=401)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert str(err.value) == ERRORS["UNAUTHORIZED_REQUEST"].format(401, alert_response_401)


@pytest.mark.parametrize(
    "params",
    [
        {"max_fetch": "-1", "isFetch": "true"},
        {"max_fetch": "101", "isFetch": "true"},
    ],
)
def test_test_module_when_fetch_is_true_when_invalid_arguments_provided(
    mocker, params, mock_client_with_valid_token, requests_mock, capfd
):
    """
    Test case scenario for execution of test_module when invalid params are provided.

    Given:
        - mocked client
        - params for test_module
    When:
        - Calling `test_module` function
    Then:
        - Returns a valid error message.
    """
    from DataminrPulseReGenAI import test_module

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    with pytest.raises(ValueError) as err:
        capfd.close()
        test_module(mock_client_with_valid_token)

    assert str(err.value) == ERRORS["INVALID_NUM"].format(params["max_fetch"], "Max Fetch", MAX_NUMBER_OF_ALERTS_TO_RETRIEVE)


def test_test_module_when_fetch_is_true_success(mocker, mock_client_with_valid_token, requests_mock):
    """
    Test case scenario for execution of test_module when valid params are provided.

    Given:
        - mocked client
        - params for test_module
    When:
        - Calling `test_module` function
    Then:
        - Returns an ok message
    """
    from DataminrPulseReGenAI import test_module

    params = {"max_fetch": "1", "isFetch": "true"}

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    mocker.patch.object(demisto, "params", return_value=params)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )
    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)

    assert test_module(mock_client_with_valid_token) == "ok"


def test_test_module_fetch_is_true_when_watchlist_name_not_matched(mocker, requests_mock, mock_client_with_valid_token, capfd):
    """
    Test case scenario for execution of test_module when watchlist_names is not matched.

    Given:
        - command arguments for test_module
    When:
        - Calling `test_module` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import test_module

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    params = {"max_fetch": "1", "isFetch": "true", "watchlist_names": ["My Name"]}

    mocker.patch.object(demisto, "params", return_value=params)
    with pytest.raises(ValueError) as err:
        capfd.close()
        test_module(mock_client_with_valid_token)
    assert str(err.value) == ERRORS["NOT_MATCHED_WATCHLIST_NAMES"].format(params["watchlist_names"])


def test_fetch_incident_when_invalid_arguments_provided(mock_client_with_valid_token, requests_mock, capfd):
    """
    Test case scenario for execution of fetch_incidents when invalid arguments are provided.

    Given:
        - command arguments for fetch_incidents
    When:
        - Calling `fetch_incidents` function
    Then:
        - Returns a valid error message.
    """
    from DataminrPulseReGenAI import fetch_incidents

    params = {"max_fetch": "-1"}

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    with pytest.raises(ValueError) as err:
        capfd.close()
        fetch_incidents(mock_client_with_valid_token, {}, params)

    assert str(err.value) == ERRORS["INVALID_NUM"].format(-1, "Max Fetch", MAX_NUMBER_OF_ALERTS_TO_RETRIEVE)


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
    from DataminrPulseReGenAI import fetch_incidents

    last_run = {
        "from": "DUMMY_CURSOR02",
        "last_watchlist_names": ["Data Security"],
        "last_query": None,
        "found_alert_ids": ["DUMMY_ALERT_ID"],
    }

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    next_run, actual_incidents = fetch_incidents(
        mock_client_with_valid_token, last_run, {"max_fetch": 1, "watchlist_names": "Data Security", "alert_type": "Alert"}
    )

    assert next_run == {
        "found_alert_ids": ["DUMMY_ALERT_ID"],
        "from": "DUMMY_CURSOR01",
        "last_query": None,
        "last_watchlist_names": ["Data Security"],
    }
    assert actual_incidents == []


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
    from DataminrPulseReGenAI import fetch_incidents

    incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents.json")
    )

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    params = {"max_fetch": "101", "query": "  CVE-2025-0001  "}

    next_run, actual_incidents = fetch_incidents(mock_client_with_valid_token, {}, params)

    assert next_run == {
        "found_alert_ids": ["DUMMY_ALERT_ID", "DUMMY_ALERT_ID01"],
        "from": "DUMMY_CURSOR01",
        "last_query": "CVE-2025-0001",
        "last_watchlist_names": [],
    }
    assert actual_incidents == incidents


def test_fetch_incident_success_with_lower_watchlist_names(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for execution of fetch_incident.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import fetch_incidents

    incidents = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/fetch_incident_incidents.json")
    )

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    params = {"max_fetch": "101", "query": "  CVE-2025-0001  ", "watchlist_names": "data security"}

    next_run, actual_incidents = fetch_incidents(mock_client_with_valid_token, {}, params)

    assert next_run == {
        "found_alert_ids": ["DUMMY_ALERT_ID", "DUMMY_ALERT_ID01"],
        "from": "DUMMY_CURSOR01",
        "last_query": "CVE-2025-0001",
        "last_watchlist_names": ["data security"],
    }
    assert actual_incidents == incidents


def test_fetch_incident_success_when_no_alert_type_match(requests_mock, mock_client_with_valid_token):
    """
    Test case scenario for execution of fetch_incident when no alert for given type.

    Given:
        - command arguments for fetch_incident
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import fetch_incidents

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    next_run, actual_incidents = fetch_incidents(mock_client_with_valid_token, {}, {"max_fetch": 1, "alert_type": "Flash"})

    assert next_run == {
        "found_alert_ids": [],
        "from": "DUMMY_CURSOR01",
        "last_query": None,
        "last_watchlist_names": [],
    }
    assert actual_incidents == []


def test_dataminr_watchlists_get_command_for_success(requests_mock, mock_client_with_valid_token):
    """Test case scenario for successful execution of dataminrpulse-watchlists-get-command.
    Given:
        - dataminrpulse-watchlists-get-command function and mock_client to call the function.
    When:
        - Valid arguments are provided to the command.
    Then:
        - Should return proper human-readable string and context data.
    """
    from DataminrPulseReGenAI import dataminrpulse_watchlists_get_command

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.md")) as f:
        dataminr_watchlists_get_hr = f.read()

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"))
    resp = dataminrpulse_watchlists_get_command(mock_client_with_valid_token, {})

    assert resp.outputs == remove_empty_elements(mock_response_watchlists.get("outputs"))
    assert resp.raw_response == mock_response_watchlists.get("raw_response")
    assert resp.readable_output == dataminr_watchlists_get_hr
    assert resp.outputs_key_field == "id"
    assert resp.outputs_prefix == OUTPUT_PREFIX_WATCHLISTS


def test_test_module_using_main(mocker, requests_mock):
    """
    Test case scenario for successful execution of test_module using main.

    Given:
        - command arguments for test_module
    When:
        - Calling `test_module` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import main

    mocker.patch.object(demisto, "params", return_value={"api_key": "DUMMY_API_KEY  ", "api_secret": "DUMMY_API_SECRET"})
    mocker.patch.object(demisto, "command", return_value="test-module")

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)

    main()


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
    from DataminrPulseReGenAI import dataminrpulse_alerts_get

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)

    actual = dataminrpulse_alerts_get(
        mock_client_with_valid_token,
        args={
            "query": "linux",
            "watchlist_ids": "3320155",
            "to": "DUMMY_CURSOR",
            "num": "2",
            "use_configured_watchlist_names": "false",
        },
    )

    raw_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    raw_response_cursor = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_cursor_200.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_200.md")) as f:
        hr_output_for_alerts = f.read()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_cursor_200.md")) as f:
        hr_output_for_cursor = f.read()

    assert actual[0].outputs_prefix == OUTPUT_PREFIX_ALERTS
    assert actual[0].outputs_key_field == "alertId"
    assert actual[0].raw_response == raw_response_alerts.get("raw_response")
    assert actual[0].outputs == remove_empty_elements(raw_response_alerts.get("outputs"))
    assert actual[0].readable_output == hr_output_for_alerts

    assert actual[1].outputs_prefix == OUTPUT_PREFIX_CURSOR
    assert actual[1].outputs_key_field == ["from", "to"]
    assert actual[1].raw_response == raw_response_cursor.get("raw_response")
    assert actual[1].outputs == remove_empty_elements(raw_response_cursor.get("outputs"))
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
    from DataminrPulseReGenAI import dataminrpulse_alerts_get

    mock_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(f"{BASE_URL}{ENDPOINTS['ALERTS_ENDPOINT']}", json=mock_response_alerts.get("raw_response"), status_code=200)
    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    actual = dataminrpulse_alerts_get(
        mock_client_with_valid_token,
        args={
            "watchlist_names": "Data Security",
            "query": "linux",
            "from": "DUMMY_CURSOR",
            "num": "2",
        },
    )

    raw_response_alerts = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_200.json")
    )

    raw_response_cursor = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_alerts_cursor_200.json")
    )

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_200.md")) as f:
        hr_output_for_alerts = f.read()

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/get_alerts_cursor_200.md")) as f:
        hr_output_for_cursor = f.read()

    assert actual[0].outputs_prefix == OUTPUT_PREFIX_ALERTS
    assert actual[0].outputs_key_field == "alertId"
    assert actual[0].raw_response == raw_response_alerts.get("raw_response")
    assert actual[0].outputs == remove_empty_elements(raw_response_alerts.get("outputs"))
    assert actual[0].readable_output == hr_output_for_alerts

    assert actual[1].outputs_prefix == OUTPUT_PREFIX_CURSOR
    assert actual[1].outputs_key_field == ["from", "to"]
    assert actual[1].raw_response == raw_response_cursor.get("raw_response")
    assert actual[1].outputs == remove_empty_elements(raw_response_cursor.get("outputs"))
    assert actual[1].readable_output == hr_output_for_cursor


@pytest.mark.parametrize(
    "args, err_msg",
    [
        (
            {"num": "-1", "use_configured_watchlist_names": "false"},
            ERRORS["INVALID_NUM"].format("-1", "num", MAX_NUMBER_OF_ALERTS_TO_RETRIEVE),
        ),
        (
            {"num": f"{MAX_NUMBER_OF_ALERTS_TO_RETRIEVE + 1}", "use_configured_watchlist_names": "false"},
            ERRORS["INVALID_NUM"].format(MAX_NUMBER_OF_ALERTS_TO_RETRIEVE + 1, "num", MAX_NUMBER_OF_ALERTS_TO_RETRIEVE),
        ),
        (
            {"from": "from", "to": "to", "use_configured_watchlist_names": "false"},
            ERRORS["ATMOST_ONE_ALLOWED"].format("from", "to"),
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
    from DataminrPulseReGenAI import dataminrpulse_alerts_get

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
    from DataminrPulseReGenAI import dataminrpulse_alerts_get

    mock_response_watchlists = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/get_watchlist_200.json")
    )

    requests_mock.get(
        f"{BASE_URL}{ENDPOINTS['WATCHLISTS_ENDPOINT']}", json=mock_response_watchlists.get("raw_response"), status_code=200
    )

    with pytest.raises(ValueError) as err:
        dataminrpulse_alerts_get(
            mock_client_with_valid_token, {"use_configured_watchlist_names": "true", "watchlist_names": "my_name"}
        )
    assert str(err.value) == ERRORS["NOT_MATCHED_WATCHLIST_NAMES"].format("['my_name']")


def test_dataminrpulse_vulnerability_enrich_command_success(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_vulnerability_enrich_command function.

    Given:
        - command arguments for dataminrpulse_vulnerability_enrich_command
    When:
        - Calling `dataminrpulse_vulnerability_enrich_command` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import dataminrpulse_vulnerability_enrich_command

    mock_vulnerability_data = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/enrich_vulnerability_indicator.json")
    )

    args = {
        "vulnerability_json_data": json.dumps(mock_vulnerability_data.get("input")),
    }

    actual = dataminrpulse_vulnerability_enrich_command(mock_client_with_valid_token, args)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/enrich_vulnerability_indicator.md")) as f:
        hr_output_for_enrich_vulneribility = f.read()

    expected_indicator = Common.CustomIndicator(
        value=mock_vulnerability_data.get("outputs")[0].get("id"),
        indicator_type="Dataminr Pulse Vulnerability Indicator",
        data=remove_empty_elements(mock_vulnerability_data.get("outputs")[0]),
        context_prefix="DataminrPulseVulnerabilityIndicator",
        dbot_score=Common.DBotScore(
            indicator=mock_vulnerability_data.get("outputs")[0].get("id"),
            indicator_type="custom",
            integration_name=VENDOR_NAME,
            score=2,
            reliability=DEFAULT_RELIABILITY,
        ),
    )

    assert actual[0].outputs_prefix == CUSTOM_OUTPUT_PREFIX.format("Vulnerability")
    assert actual[0].outputs_key_field == "id"
    assert actual[0].raw_response == mock_vulnerability_data.get("input")[0]
    assert actual[0].outputs == remove_empty_elements(mock_vulnerability_data.get("outputs")[0])
    assert actual[0].readable_output == hr_output_for_enrich_vulneribility
    assert actual[0].indicator.to_context() == expected_indicator.to_context()  # type: ignore


def test_dataminrpulse_vulnerability_enrich_command_when_no_data_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_vulnerability_enrich_command function wneh no data present.

    Given:
        - command arguments for dataminrpulse_vulnerability_enrich_command
    When:
        - Calling `dataminrpulse_vulnerability_enrich_command` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import dataminrpulse_vulnerability_enrich_command

    args = {
        "vulnerability_json_data": "[]",
    }

    actual = dataminrpulse_vulnerability_enrich_command(mock_client_with_valid_token, args)

    assert actual.readable_output == "No vulnerabilities found."  # type: ignore


def test_dataminrpulse_vulnerability_enrich_command_when_invalid_json_data_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_vulnerability_enrich_command function
    wneh invalid json data present.

    Given:
        - command arguments for dataminrpulse_vulnerability_enrich_command
    When:
        - Calling `dataminrpulse_vulnerability_enrich_command` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import dataminrpulse_vulnerability_enrich_command

    args = {
        "vulnerability_json_data": "[",
    }

    with pytest.raises(ValueError) as err:
        dataminrpulse_vulnerability_enrich_command(mock_client_with_valid_token, args)

    assert str(err.value) == ERRORS["JSON_DECODE"].format("vulnerability_json_data")


def test_dataminrpulse_vulnerability_enrich_command_when_no_arg_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_vulnerability_enrich_command function
    wneh no arg present.

    Given:
        - command arguments for dataminrpulse_vulnerability_enrich_command
    When:
        - Calling `dataminrpulse_vulnerability_enrich_command` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import dataminrpulse_vulnerability_enrich_command

    args = {
        "vulnerability_json_data": "",
    }

    with pytest.raises(ValueError) as err:
        dataminrpulse_vulnerability_enrich_command(mock_client_with_valid_token, args)

    assert str(err.value) == ERRORS["REQUIRED_ARG"].format("vulnerability_json_data")


def test_dataminrpulse_malware_enrich_command_success(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_malware_enrich_command function.

    Given:
        - command arguments for dataminrpulse_malware_enrich_command
    When:
        - Calling `dataminrpulse_malware_enrich_command` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import dataminrpulse_malware_enrich_command

    mock_malware_data = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/enrich_malware_indicator.json")
    )

    args = {
        "malware_json_data": json.dumps(mock_malware_data.get("input")),
    }

    actual = dataminrpulse_malware_enrich_command(mock_client_with_valid_token, args)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/enrich_malware_indicator.md")) as f:
        hr_output_for_enrich_malware = f.read()

    expected_indicator = Common.CustomIndicator(
        value=mock_malware_data.get("outputs")[0].get("name"),
        indicator_type="Dataminr Pulse Malware Indicator",
        data=remove_empty_elements(mock_malware_data.get("outputs")[0]),
        context_prefix="DataminrPulseMalwareIndicator",
        dbot_score=Common.DBotScore(
            indicator=mock_malware_data.get("outputs")[0].get("name"),
            indicator_type="custom",
            integration_name=VENDOR_NAME,
            score=3,
            reliability=DEFAULT_RELIABILITY,
        ),
    )

    assert actual[0].outputs_prefix == CUSTOM_OUTPUT_PREFIX.format("Malware")
    assert actual[0].outputs_key_field == "name"
    assert actual[0].raw_response == mock_malware_data.get("input")[0]
    assert actual[0].outputs == remove_empty_elements(mock_malware_data.get("outputs")[0])
    assert actual[0].readable_output == hr_output_for_enrich_malware
    assert actual[0].indicator.to_context() == expected_indicator.to_context()  # type: ignore


def test_dataminrpulse_malware_enrich_command_when_no_data_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_malware_enrich_command function wneh no data present.

    Given:
        - command arguments for dataminrpulse_malware_enrich_command
    When:
        - Calling `dataminrpulse_malware_enrich_command` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import dataminrpulse_malware_enrich_command

    args = {
        "malware_json_data": "[]",
    }

    actual = dataminrpulse_malware_enrich_command(mock_client_with_valid_token, args)

    assert actual.readable_output == "No malware found."  # type: ignore


def test_dataminrpulse_malware_enrich_command_when_invalid_json_data_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_malware_enrich_command function wneh invalid json data present.

    Given:
        - command arguments for dataminrpulse_malware_enrich_command
    When:
        - Calling `dataminrpulse_malware_enrich_command` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import dataminrpulse_malware_enrich_command

    args = {
        "malware_json_data": "[",
    }

    with pytest.raises(ValueError) as err:
        dataminrpulse_malware_enrich_command(mock_client_with_valid_token, args)

    assert str(err.value) == ERRORS["JSON_DECODE"].format("malware_json_data")


def test_dataminrpulse_malware_enrich_command_when_no_arg_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_malware_enrich_command function
    wneh no arg present.

    Given:
        - command arguments for dataminrpulse_vulnerability_enrich_command
    When:
        - Calling `dataminrpulse_malware_enrich_command` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import dataminrpulse_malware_enrich_command

    args = {
        "malware_json_data": "",
    }

    with pytest.raises(ValueError) as err:
        dataminrpulse_malware_enrich_command(mock_client_with_valid_token, args)

    assert str(err.value) == ERRORS["REQUIRED_ARG"].format("malware_json_data")


def test_dataminrpulse_threat_actor_enrich_command_success(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_threat_actor_enrich_command function.

    Given:
        - command arguments for dataminrpulse_threat_actor_enrich_command
    When:
        - Calling `dataminrpulse_threat_actor_enrich_command` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import dataminrpulse_threat_actor_enrich_command

    mock_threat_actor_data = util_load_json(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "test_data/enrich_threat_actor_indicator.json")
    )

    args = {
        "threat_actor_json_data": json.dumps(mock_threat_actor_data.get("input")),
    }

    actual = dataminrpulse_threat_actor_enrich_command(mock_client_with_valid_token, args)

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "./test_data/enrich_threat_actor_indicator.md")) as f:
        hr_output_for_enrich_threat_actor = f.read()

    expected_indicator = Common.CustomIndicator(
        value=mock_threat_actor_data.get("outputs")[0].get("name"),
        indicator_type="Dataminr Pulse Threat Actor Indicator",
        data=remove_empty_elements(mock_threat_actor_data.get("outputs")[0]),
        context_prefix="DataminrPulseThreatActorIndicator",
        dbot_score=Common.DBotScore(
            indicator=mock_threat_actor_data.get("outputs")[0].get("name"),
            indicator_type="custom",
            integration_name=VENDOR_NAME,
            score=3,
            reliability=DEFAULT_RELIABILITY,
        ),
    )

    assert actual[0].outputs_prefix == CUSTOM_OUTPUT_PREFIX.format("ThreatActor")
    assert actual[0].outputs_key_field == "name"
    assert actual[0].raw_response == mock_threat_actor_data.get("input")[0]
    assert actual[0].outputs == remove_empty_elements(mock_threat_actor_data.get("outputs")[0])
    assert actual[0].readable_output == hr_output_for_enrich_threat_actor
    assert actual[0].indicator.to_context() == expected_indicator.to_context()  # type: ignore


def test_dataminrpulse_threat_actor_enrich_command_when_no_data_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_threat_actor_enrich_command function wneh no data present.

    Given:
        - command arguments for dataminrpulse_threat_actor_enrich_command
    When:
        - Calling `dataminrpulse_threat_actor_enrich_command` function
    Then:
        - Returns a valid output
    """
    from DataminrPulseReGenAI import dataminrpulse_threat_actor_enrich_command

    args = {
        "threat_actor_json_data": "[]",
    }

    actual = dataminrpulse_threat_actor_enrich_command(mock_client_with_valid_token, args)

    assert actual.readable_output == "No threat actors found."  # type: ignore


def test_dataminrpulse_threat_actor_enrich_command_when_invalid_json_data_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_threat_actor_enrich_command function
    wneh invalid json data present.

    Given:
        - command arguments for dataminrpulse_threat_actor_enrich_command
    When:
        - Calling `dataminrpulse_threat_actor_enrich_command` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import dataminrpulse_threat_actor_enrich_command

    args = {
        "threat_actor_json_data": "[",
    }

    with pytest.raises(ValueError) as err:
        dataminrpulse_threat_actor_enrich_command(mock_client_with_valid_token, args)

    assert str(err.value) == ERRORS["JSON_DECODE"].format("threat_actor_json_data")


def test_dataminrpulse_threat_actor_enrich_command_when_no_arg_present(mock_client_with_valid_token):
    """
    Test case scenario for successful execution of dataminrpulse_threat_actor_enrich_command function
    wneh no arg present.

    Given:
        - command arguments for dataminrpulse_threat_actor_enrich_command
    When:
        - Calling `dataminrpulse_threat_actor_enrich_command` function
    Then:
        - Returns a valid error message
    """
    from DataminrPulseReGenAI import dataminrpulse_threat_actor_enrich_command

    args = {
        "threat_actor_json_data": "",
    }

    with pytest.raises(ValueError) as err:
        dataminrpulse_threat_actor_enrich_command(mock_client_with_valid_token, args)

    assert str(err.value) == ERRORS["REQUIRED_ARG"].format("threat_actor_json_data")
