"""Ignite Test File."""

import json
import os.path
import re
from datetime import timedelta
from unittest.mock import patch

import Ignite
import pytest
from CommonServerPython import DemistoException, get_current_time
from Ignite import (
    DATE_FORMAT,
    LIBRARY_AND_PACKAGE_SORT_VALUES,
    MESSAGES,
    URL_SUFFIX,
    Client,
    demisto,
    main,
    remove_space_from_args,
    OUTPUT_PREFIX,
    MAX_PRODUCT,
    MAX_PAGE_SIZE,
    SORT_DATE_VALUES,
    SORT_ORDER_VALUES,
    FILTER_DATE_VALUES,
    IS_FRESH_VALUES,
    MAX_FETCH_LIMIT,
    MAX_ALERTS_LIMIT,
    ALERT_STATUS_VALUES,
    ALERT_ORIGIN_VALUES,
    OUTPUT_KEY_FIELD,
    VULNERABILITY_SORT_MAPPING,
    vulnerability_get_command,
    vendor_list_command,
    product_list_command,
    vulnerability_list_command,
    cve_command,
    DEFAULT_REPUTATION_CONTEXT_LIMIT,
    create_relationships_list_for_community_search,
    ip_lookup_command,
)

""" CONSTANTS """

API_KEY = "api_key"
MOCK_URL = "https://mock_dummy.com"
BASIC_PARAMS = {"url": MOCK_URL, "credentials": {"password": API_KEY}}
CURRENT_TIME = get_current_time()
CURRENT_TIME_STRING = CURRENT_TIME.strftime(DATE_FORMAT)
CURRENT_TIME_PLUS_ONE = CURRENT_TIME + timedelta(days=1)
CURRENT_TIME_PLUS_ONE_STRING = CURRENT_TIME_PLUS_ONE.strftime(DATE_FORMAT)

MESSAGES.update(
    {
        "NO_SERVER_URL_PROVIDED": "Please provide the Server URL.",
        "NO_CREDENTIALS_PROVIDED": "Please provide the API Key.",
    }
)

""" UTILITY FUNCTIONS AND FIXTURES """


def util_load_json(path: str) -> dict:
    """Load a json to python dict."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def util_load_text_data(path: str) -> str:
    """Load a text file."""
    with open(path, encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def mock_client():
    """Mock a client object with required data to mock."""
    client = Client(MOCK_URL, {}, False, None, True)
    return client


""" TEST CASES """


def test_test_module(mock_client, requests_mock):
    """Test test_module."""
    from Ignite import test_module

    response = util_load_json("test_data/ip_lookup_reputation.json")
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}?size=1', json=response, status_code=200)

    assert test_module(client=mock_client) == "ok"


@patch("Ignite.return_results")
def test_test_module_using_main_function(mock_return, requests_mock, mocker):
    """
    Test case scenario for successful execution of test_module through main function.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns an ok message
    """
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json={}, status_code=200)

    params = {**BASIC_PARAMS, "isFetch": True}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="test-module")

    main()
    assert mock_return.call_args.args[0] == "ok"


@pytest.mark.parametrize(
    "params, err_msg",
    [
        ({}, MESSAGES["NO_SERVER_URL_PROVIDED"]),
        ({"url": " "}, MESSAGES["NO_SERVER_URL_PROVIDED"]),
        ({"url": " url ", "cluster_id": " cluster_id "}, MESSAGES["NO_CREDENTIALS_PROVIDED"]),
        ({"url": " url ", "cluster_id": " cluster_id ", "credentials": {}}, MESSAGES["NO_CREDENTIALS_PROVIDED"]),
        ({"url": " url ", "cluster_id": " cluster_id ", "credentials": {"password": " "}}, MESSAGES["NO_CREDENTIALS_PROVIDED"]),
        (
            {**BASIC_PARAMS.copy(), "isFetch": True, "first_fetch": CURRENT_TIME_PLUS_ONE_STRING},
            MESSAGES["INVALID_FETCH_TIME"].format(CURRENT_TIME_PLUS_ONE_STRING),
        ),
        (
            {**BASIC_PARAMS.copy(), "isFetch": True, "max_fetch": MAX_FETCH_LIMIT + 1},
            MESSAGES["INVALID_MAX_FETCH"].format(MAX_FETCH_LIMIT + 1),
        ),
        (
            {**BASIC_PARAMS.copy(), "isFetch": True, "fetch_type": "Alerts", "max_fetch": MAX_FETCH_LIMIT + 1},
            MESSAGES["INVALID_MAX_FETCH"].format(MAX_FETCH_LIMIT + 1),
        ),
    ],
)
def test_test_module_when_invalid_params_provided(params, err_msg, mocker, capfd):
    """
    Test case scenario for execution of test_module when invalid argument provided.

    Given:
        - Params for test_module.
    When:
        - Calling `test_module` function.
    Then:
        - Returns a valid error message.
    """
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "exit", return_value=None)
    mocker.patch.object(demisto, "command", return_value="test-module")

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert err_msg in return_error.call_args[0][0]


@pytest.mark.parametrize(
    "status_code, err_msg",
    [
        (400, MESSAGES["INVALID_ARGUMENT_RESPONSE"]),
        (401, MESSAGES["INVALID_API_KEY"]),
        (521, MESSAGES["TEST_CONNECTIVITY_FAILED"]),
        (403, MESSAGES["TEST_CONNECTIVITY_FAILED"]),
        (404, MESSAGES["NO_RECORD_FOUND"]),
    ],
)
def test_test_module_invalid_response(requests_mock, mock_client, status_code, err_msg):
    """
    Test case scenario for the execution of test_module with invalid response with the different status code.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from Ignite import test_module

    response = {"message": "invalid_response"}
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}?size=1', json=response, status_code=status_code)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    err_msg = err_msg + response.get("message") if status_code == 400 else err_msg
    if status_code in (403, 521):
        err_msg += json.dumps(response)
    assert MESSAGES["STATUS_CODE"].format(status_code, err_msg) == str(err.value)


def test_test_module_invalid_json_response(requests_mock, mock_client):
    """
    Test case scenario for the execution of test_module with invalid json response.

    Given:
       - mocked client
    When:
       - Calling `test_module` function
    Then:
       - Returns exception
    """
    from Ignite import test_module

    response = "invalid_response"
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}?size=1', text=response, status_code=200)

    with pytest.raises(DemistoException) as err:
        test_module(mock_client)

    assert MESSAGES["STATUS_CODE"].format(200, MESSAGES["INVALID_JSON_OBJECT"].format(response)) == str(err.value)


def test_fetch_incidents_when_valid_incidents_return(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {}

    mock_response: dict = util_load_json("test_data/fetch_compromised_credentials.json")

    incidents_response = util_load_json("test_data/incidents_compromised_credentials.json")

    params: dict = {
        "fetch_type": "",
        "first_fetch": "2024-05-16T10:22:38Z",
        "is_fresh_compromised_credentials": "true",
        "password_has_lowercase": "true",
        "password_has_number": "true",
        "max_fetch": 1,
    }
    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    END_TIME = next_run.get("end_time")
    expected_next_run = {
        "fetch_count": 1,
        "fetch_sum": 1,
        "total": 31,
        "end_time": END_TIME,
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1"],
        "last_timestamp": 1617219725,
        "start_time": "2024-05-16T10:22:38Z",
    }

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_when_params_not_provided_and_last_run_provided(mocker, mock_client, requests_mock):
    """
    Test case scenario of fetch_incidents for fetch compromised credentials when params not provided and last run is provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "fetch_count": 1,
        "start_time": "2024-05-16T10:22:38Z",
        "total": 31,
        "fetch_sum": 30,
        "end_time": "2024-05-30T19:42:05Z",
        "last_timestamp": 1617219726,
    }

    expected_next_run = {
        "fetch_count": 0,
        "start_time": "2021-03-31T19:42:05Z",
        "total": None,
        "fetch_sum": 0,
        "end_time": "2024-05-30T19:42:05Z",
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1"],
        "last_timestamp": 1617219725,
    }

    mock_response: dict = util_load_json("test_data/fetch_compromised_credentials.json")

    incidents_response = util_load_json("test_data/incidents_compromised_credentials.json")

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={"max_fetch": 201})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials when invalid arguments provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Raise error message.
    """
    from Ignite import fetch_incidents

    error_message = MESSAGES["INVALID_MAX_FETCH"].format("0")
    with pytest.raises(DemistoException) as error:
        fetch_incidents(client=mock_client, last_run={}, params={"max_fetch": 0})

    assert str(error.value) == error_message


def test_fetch_incidents_when_max_product_exceed_total_limit(mock_client, requests_mock):
    from Ignite import fetch_incidents

    mock_response: dict = util_load_json("test_data/fetch_incidents_with_check_max_product.json")

    error_message = MESSAGES["TIME_RANGE_ERROR"].format("10005")
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)

    with pytest.raises(ValueError) as error:
        fetch_incidents(client=mock_client, last_run={"total": 10005}, params={})

    assert str(error.value) == error_message


def test_fetch_incidents_to_check_duplicates_compromised_credentials(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials to check duplicate records in response.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "fetch_count": 1,
        "start_time": "2024-05-16T10:22:38Z",
        "total": 31,
        "fetch_sum": 30,
        "end_time": "2024-05-30T19:42:05Z",
        "hit_ids": ["sample_id_2"],
    }

    expected_next_run = {
        "fetch_count": 0,
        "start_time": "2021-03-31T19:42:05Z",
        "total": None,
        "fetch_sum": 0,
        "end_time": "2024-05-30T19:42:05Z",
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1", "sample_id_2"],
        "last_timestamp": 1617219725,
    }

    mock_response: dict = util_load_json("test_data/fetch_incidents_compromised_credentials_check_duplicate.json")

    incidents_response = util_load_json("test_data/incidents_compromised_credentials.json")

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_compromised_credentials_when_email_not_present(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials when email not provided in response.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "fetch_count": 1,
        "start_time": "2024-05-16T10:22:38Z",
        "total": 31,
        "fetch_sum": 30,
        "end_time": "2024-05-30T19:42:05Z",
        "last_timestamp": 1617219725,
        "hit_ids": [],
    }

    expected_next_run = {
        "fetch_count": 0,
        "start_time": "2021-03-31T19:42:05Z",
        "total": None,
        "fetch_sum": 0,
        "end_time": "2024-05-30T19:42:05Z",
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1"],
        "last_timestamp": 1617219725,
    }

    mock_response: dict = util_load_json("test_data/fetch_compromised_credentials.json")

    del mock_response["hits"]["hits"][0]["_source"]["email"]
    incidents_response = util_load_json("test_data/incidents_compromised_credentials_when_email_not_present.json")

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_compromised_credentials_when_email_and_username_not_present(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for compromised credentials when email and username not present.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "fetch_count": 1,
        "start_time": "2024-05-16T10:22:38Z",
        "total": 31,
        "fetch_sum": 30,
        "end_time": "2024-05-30T19:42:05Z",
        "last_timestamp": 1617219725,
        "hit_ids": [],
    }

    expected_next_run = {
        "fetch_count": 0,
        "start_time": "2021-03-31T19:42:05Z",
        "total": None,
        "fetch_sum": 0,
        "end_time": "2024-05-30T19:42:05Z",
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1"],
        "last_timestamp": 1617219725,
    }

    mock_response: dict = util_load_json("test_data/fetch_compromised_credentials.json")

    del mock_response["hits"]["hits"][0]["_source"]["email"]
    del mock_response["hits"]["hits"][0]["_source"]["username"]
    incidents_response = util_load_json("test_data/incidents_compromised_credentials_when_email_username_not_present.json")

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_compromised_credentials_when_fpid_not_present(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials when fpid not provided in response.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "fetch_count": 1,
        "start_time": "2024-05-16T10:22:38Z",
        "total": 31,
        "fetch_sum": 30,
        "end_time": "2024-05-30T19:42:05Z",
    }

    expected_next_run = {
        "fetch_count": 0,
        "start_time": "2021-03-31T19:42:05Z",
        "total": None,
        "fetch_sum": 0,
        "end_time": "2024-05-30T19:42:05Z",
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1"],
        "last_timestamp": 1617219725,
    }

    mock_response: dict = util_load_json("test_data/fetch_compromised_credentials.json")

    del mock_response["hits"]["hits"][0]["_source"]["email"]
    del mock_response["hits"]["hits"][0]["_source"]["username"]
    del mock_response["hits"]["hits"][0]["_source"]["fpid"]

    incidents_response = util_load_json("test_data/incidents_compromised_credentials_when_fpid_not_present.json")

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={})

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_get_reports_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-search command.

    Given:
       - command arguments for get_reports_command
    When:
       - Calling `get_reports_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_reports_command

    get_reports = util_load_json("test_data/get_reports_success.json")
    get_reports_context = util_load_json("test_data/get_reports_success_context.json")
    with open("test_data/get_reports_success_hr.md") as file:
        hr_output_for_reports = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["REPORT_SEARCH"]}?query=report_search&limit=5', json=get_reports, status_code=200)

    resp = get_reports_command(mock_client, {"report_search": "report_search"})

    assert resp.outputs_prefix == OUTPUT_PREFIX["REPORT"]
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD["REPORT_ID"]
    assert resp.readable_output == hr_output_for_reports
    assert resp.outputs == get_reports_context
    assert resp.raw_response == get_reports


def test_get_reports_command_success_when_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-search command with empty response.

    Given:
       - command arguments for get_reports_command
    When:
       - Calling `get_reports_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_reports_command

    get_reports_empty_data = util_load_json("test_data/get_reports_success_empty_response.json")
    with open("test_data/get_reports_success_empty_response_hr.md") as file:
        hr_output_for_reports = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["REPORT_SEARCH"]}?query=report_search&limit=5', json=get_reports_empty_data, status_code=200
    )

    resp = get_reports_command(mock_client, {"report_search": "report_search"})

    assert resp.readable_output == hr_output_for_reports
    assert resp.raw_response == get_reports_empty_data


def test_get_reports_command_when_invalid_argument(mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-search command
    when invalid argument provided.
    Given:
       - command arguments for get_reports_command
    When:
       - Calling `get_reports_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_reports_command

    args = {"report_search": " "}
    with pytest.raises(ValueError) as err:
        get_reports_command(mock_client, remove_space_from_args(args))

    assert str(err.value) == MESSAGES["MISSING_REQUIRED_ARGS"].format("report_search")


def test_event_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of event_list_command function.

    Given:
        - command arguments for event_list_command
    When:
        - Calling `event_list_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_list_command

    mock_response_events = util_load_json("test_data/event_list_2_response.json")

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["EVENT_LIST"]}', json=mock_response_events, status_code=200)

    resp = event_list_command(
        mock_client, args={"time_period": "1 month", "limit": 2, "attack_ids": "T1001", "report_fpid": "0000000000000000000001"}
    )

    output_list_events = util_load_json("test_data/event_list_2_output.json")

    hr_output_for_events = util_load_text_data("test_data/event_list_2_hr.md")

    assert resp.outputs_prefix == OUTPUT_PREFIX["EVENT"]
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD["EVENT_ID"]
    assert resp.readable_output == hr_output_for_events
    assert resp.outputs == output_list_events
    assert resp.raw_response == mock_response_events


def test_event_list_command_no_result(requests_mock, mock_client):
    """
    Test case scenario with no results execution of event_list_command function.

    Given:
        - command arguments for event_list_command
    When:
        - Calling `event_list_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_list_command

    mock_response_events = []

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["EVENT_LIST"]}', json=mock_response_events, status_code=200)

    resp = event_list_command(mock_client, args={})

    assert resp.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("events")
    assert resp.raw_response == mock_response_events


@pytest.mark.parametrize(
    "args,error_message",
    [
        ({"limit": "10001"}, MESSAGES["LIMIT_ERROR"].format("10001", MAX_PRODUCT)),
        ({"limit": "-1"}, MESSAGES["LIMIT_ERROR"].format("-1", MAX_PRODUCT)),
        ({"limit": "0"}, MESSAGES["LIMIT_ERROR"].format("0", MAX_PRODUCT)),
    ],
)
def test_event_list_command_with_invalid_args(args, error_message, mock_client):
    """
    Test case scenario for execution of event_list_command with invalid arguments provided.

    Given:
        - arguments for event_list_command.
    When:
        - Calling `event_list_command` function.
    Then:
        - Returns a valid error message.
    """
    from Ignite import event_list_command

    with pytest.raises(DemistoException) as error:
        event_list_command(mock_client, args=args)

    assert str(error.value) == error_message


def test_event_get_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of event_get_command function.

    Given:
        - command arguments for event_get_command
    When:
        - Calling `event_get_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_get_command

    mock_response_events = util_load_json("test_data/event_get_response.json")

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["EVENT_GET"].format("1")}', json=mock_response_events, status_code=200)

    resp = event_get_command(mock_client, args={"event_id": "1"})

    output_list_events = util_load_json("test_data/event_get_output.json")

    hr_output_for_events = util_load_text_data("test_data/event_get_hr.md")

    assert resp.outputs_prefix == OUTPUT_PREFIX["EVENT"]
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD["EVENT_ID"]
    assert resp.readable_output == hr_output_for_events
    assert resp.outputs == output_list_events
    assert resp.raw_response == mock_response_events


def test_event_get_command_no_result(requests_mock, mock_client):
    """
    Test case scenario with no results execution of event_get_command function.

    Given:
        - command arguments for event_get_command
    When:
        - Calling `event_get_command` function
    Then:
        - Returns a valid output
    """
    from Ignite import event_get_command

    mock_response_events = []

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["EVENT_GET"].format("1")}', json=mock_response_events, status_code=200)

    resp = event_get_command(mock_client, args={"event_id": "1"})

    assert resp.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("event")
    assert resp.raw_response == mock_response_events


def test_event_get_command_with_empty_argument(mock_client):
    """
    Test case scenario for the execution of event_get_command with empty argument.

    Given:
       - mocked client
    When:
       - Calling `event_get_command` function
    Then:
       - Returns exception
    """
    from Ignite import event_get_command

    with pytest.raises(DemistoException) as err:
        event_get_command(mock_client, args={})

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("event_id") in str(err.value)


def test_flashpoint_ignite_compromised_credentials_command_with_arguments(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-compromised-credentials-list with arguments provided.

    Given:
        - mocked client
    When:
        - Calling `flashpoint_ignite_compromised_credentials_list_command` function.
    Then:
        - Returns valid command output
    """
    from Ignite import flashpoint_ignite_compromised_credentials_list_command

    args = {
        "end_date": "now",
        "filter_date": "first_observed_at",
        "is_fresh": "true",
        "page_number": "1",
        "page_size": "1",
        "sort_date": "created_at",
        "sort_order": "asc",
        "start_date": "3 years",
    }

    mock_response: dict = util_load_json(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_data/get_compromised_credentials_list.json",
        )
    )

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "test_data/get_compromised_credentials_hr_output.md",
        )
    ) as file:
        hr_output = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response["raw_response"], status_code=200)
    response = flashpoint_ignite_compromised_credentials_list_command(client=mock_client, args=args)

    assert response.raw_response == mock_response["raw_response"]
    assert response.outputs_prefix == OUTPUT_PREFIX["COMPROMISED_CREDENTIALS"]
    assert response.outputs_key_field == "_id"
    assert response.outputs == mock_response["outputs"]
    assert response.readable_output == hr_output


def test_flashpoint_ignite_compromised_credentials_with_no_response(mock_client, requests_mock):
    """
    Test case scenario for execution of flashpoint-ignite-compromised-credentials-list with no response.

    Given:
        - mocked client
    When:
        - Calling `flashpoint_ignite_compromised_credentials_list_command` function.
    Then:
        - Returns valid command output
    """
    from Ignite import flashpoint_ignite_compromised_credentials_list_command

    mock_response: dict = {}

    args = {
        "end_date": "now",
        "filter_date": "created_at",
        "is_fresh": "false",
        "page_number": "1",
        "page_size": "1",
        "sort_date": "first_observed_at",
        "sort_order": "asc",
        "start_date": "now",
    }

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    response = flashpoint_ignite_compromised_credentials_list_command(client=mock_client, args=args)

    assert response.readable_output == "No compromised credentials were found for the given argument(s)."
    assert response.raw_response == mock_response


@pytest.mark.parametrize(
    "args,error_message",
    [
        ({"page_size": "1001"}, MESSAGES["PAGE_SIZE_ERROR"].format("1001", MAX_PAGE_SIZE)),
        ({"page_size": "-1"}, MESSAGES["PAGE_SIZE_ERROR"].format("-1", MAX_PAGE_SIZE)),
        ({"page_number": "-1"}, MESSAGES["PAGE_NUMBER_ERROR"].format("-1")),
        ({"sort_order": "abc"}, MESSAGES["SORT_ORDER_ERROR"].format("abc", SORT_ORDER_VALUES)),
        ({"page_size": "1000", "page_number": "100"}, MESSAGES["PRODUCT_ERROR"].format(MAX_PRODUCT, 100000)),
        ({"end_date": "2 days"}, MESSAGES["START_DATE_ERROR"]),
        ({"sort_date": "updated_at"}, MESSAGES["SORT_DATE_ERROR"].format("updated_at", SORT_DATE_VALUES)),
        ({"start_date": "2 days"}, MESSAGES["MISSING_FILTER_DATE_ERROR"]),
        ({"is_fresh": "wrong", "sort_date": "created_at"}, MESSAGES["IS_FRESH_ERROR"].format("wrong", IS_FRESH_VALUES)),
        ({"filter_date": "updated_at"}, MESSAGES["FILTER_DATE_ERROR"].format("updated_at", FILTER_DATE_VALUES)),
        ({"sort_order": "asc"}, MESSAGES["MISSING_SORT_DATE_ERROR"]),
    ],
)
def test_flashpoint_ignite_compromised_credentials_with_invalid_args(args, error_message, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-compromised-credentials-list with invalid arguments provided.

    Given:
        - arguments for flashpoint_ignite_compromised_credentials_list_command.
    When:
        - Calling `flashpoint_ignite_compromised_credentials_list_command` function.
    Then:
        - Returns a valid error message.
    """
    from Ignite import flashpoint_ignite_compromised_credentials_list_command

    with pytest.raises(ValueError) as error:
        flashpoint_ignite_compromised_credentials_list_command(mock_client, args=args)

    assert str(error.value) == error_message


def test_get_report_by_id_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-get command.

    Given:
       - command arguments for  get_report_by_id_command
    When:
       - Calling ` get_report_by_id_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_report_by_id_command

    get_report = util_load_json("test_data/get_report_by_id_success.json")
    get_report_context = util_load_json("test_data/get_report_by_id_success_context.json")
    with open("test_data/get_report_by_id_success_hr.md") as file:
        hr_output_for_report = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["GET_REPORT_BY_ID"].format("0000000000000000000001")}', json=get_report, status_code=200
    )

    resp = get_report_by_id_command(mock_client, {"report_id": "0000000000000000000001"})

    assert resp.outputs_prefix == OUTPUT_PREFIX["REPORT"]
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD["REPORT_ID"]
    assert resp.readable_output == hr_output_for_report
    assert resp.outputs == get_report_context
    assert resp.raw_response == get_report


def test_get_report_by_id_command_when_report_not_found(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-get command when report not found.

    Given:
       - command arguments for  get_report_by_id_command
    When:
       - Calling ` get_report_by_id_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_report_by_id_command

    get_report_invalid_id = util_load_json("test_data/get_report_by_id_when_report_not_found.json")

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["GET_REPORT_BY_ID"].format("0000000000000000000001")}',
        json=get_report_invalid_id,
        status_code=404,
    )

    with pytest.raises(DemistoException) as err:
        get_report_by_id_command(mock_client, {"report_id": "0000000000000000000001"})

    assert str(err.value) == MESSAGES["STATUS_CODE"].format(404, MESSAGES["NO_RECORD_FOUND"])


def test_get_report_by_id_command_when_invalid_argument(mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-report-get command
    when invalid argument provided.
    Given:
       - command arguments for get_report_by_id_command
    When:
       - Calling `get_report_by_id_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import get_report_by_id_command

    args = {"report_id": " "}
    with pytest.raises(ValueError) as err:
        get_report_by_id_command(mock_client, remove_space_from_args(args))

    assert str(err.value) == MESSAGES["MISSING_REQUIRED_ARGS"].format("report_id")


def test_related_report_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list command.

    Given:
       - command arguments for related_report_list_command
    When:
       - Calling `related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    related_report_lists = util_load_json("test_data/related_report_list_success.json")
    related_report_lists_context = util_load_json("test_data/related_report_list_success_context.json")
    with open("test_data/hr_output_for_related_report_list_success.md") as file:
        hr_output_for_related_reports = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["RELATED_REPORT_LIST"].format("0000000000000000000001")}?limit=5',
        json=related_report_lists,
        status_code=200,
    )

    resp = related_report_list_command(mock_client, {"report_id": "0000000000000000000001"})

    assert resp.outputs_prefix == OUTPUT_PREFIX["REPORT"]
    assert resp.outputs_key_field == OUTPUT_KEY_FIELD["REPORT_ID"]
    assert resp.readable_output == hr_output_for_related_reports
    assert resp.outputs == related_report_lists_context
    assert resp.raw_response == related_report_lists


def test_related_report_list_command_success_when_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list command with empty response.

    Given:
       - command arguments for related_report_list_command
    When:
       - Calling `related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    related_report_lists_empty_data = util_load_json("test_data/related_report_list_success_empty_response.json")
    with open("test_data/hr_output_for_related_report_list_success_empty_response.md") as file:
        hr_output_for_related_reports = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["RELATED_REPORT_LIST"].format("0000000000000000000001")}?limit=5',
        json=related_report_lists_empty_data,
        status_code=200,
    )

    resp = related_report_list_command(mock_client, {"report_id": "0000000000000000000001"})

    assert resp.readable_output == hr_output_for_related_reports
    assert resp.raw_response == related_report_lists_empty_data


def test_related_report_list_command_when_report_not_found(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list
    command when report not found.

    Given:
       - command arguments for  related_report_list_command
    When:
       - Calling ` related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    report_invalid_id = util_load_json("test_data/get_report_by_id_when_report_not_found.json")

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["RELATED_REPORT_LIST"].format("0000000000000000000001")}?limit=5',
        json=report_invalid_id,
        status_code=404,
    )

    with pytest.raises(DemistoException) as err:
        related_report_list_command(mock_client, {"report_id": "0000000000000000000001"})

    assert str(err.value) == MESSAGES["STATUS_CODE"].format(404, MESSAGES["NO_RECORD_FOUND"])


def test_related_report_list_command_when_invalid_argument(mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-intelligence-related-report-list command
    when invalid argument provided.
    Given:
       - command arguments for related_report_list_command
    When:
       - Calling `related_report_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import related_report_list_command

    args = {"report_id": " "}
    with pytest.raises(ValueError) as err:
        related_report_list_command(mock_client, remove_space_from_args(args))

    assert str(err.value) == MESSAGES["MISSING_REQUIRED_ARGS"].format("report_id")


@patch("demistomock.results")
def test_email(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of email command through main function
    when it returns reputation about given email address.

    Given:
       - mocked client
    When:
       - Calling `email_lookup_command` function
    Then:
       - Returns list of command results.
    """

    email_reputation = util_load_json("test_data/email_reputation.json")
    email_reputation_context = util_load_json("test_data/email_reputation_context.json")
    with open("test_data/hr_output_for_email_reputation.md") as file:
        hr_output_for_email_reputation = file.read()
    requests_mock.get(
        f"{MOCK_URL}/technical-intelligence/v1/simple?query=%2Btype%3A%28%22email-dst%22%2C%20"
        f"%22email-src%22%2C%20%22email-src-display-name%22%2C%20%22email-subject%22%2C%20"
        f"%22email%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy%40dummy.com%22",
        json=email_reputation,
        status_code=200,
    )
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"email": "dummy@dummy.com"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="email")
    mocker.patch.object(demisto, "args", return_value=args)

    main()
    assert hr_output_for_email_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert email_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert email_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_email_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of email command through main function
    when Ignite do not have data about that email address.

    Given:
       - mocked client
    When:
       - Calling `email_lookup_command` function
    Then:
       - Returns list of command results.
    """

    email_reputation = util_load_json("test_data/email_reputation_empty.json")
    email_reputation_context = util_load_json("test_data/email_reputation_context_empty.json")
    with open("test_data/hr_output_for_email_reputation_empty.md") as file:
        hr_output_for_email_reputation = file.read()

    requests_mock.get(
        f"{MOCK_URL}/technical-intelligence/v1/simple?query=%2Btype%3A%28%22email-dst%22%2C%20"
        f"%22email-src%22%2C%20%22email-src-display-name%22%2C%20%22email-subject%22%2C%20"
        f"%22email%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy2%40dummy.com%22",
        json=email_reputation,
        status_code=200,
    )

    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"email": "dummy2@dummy.com"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="email")
    mocker.patch.object(demisto, "args", return_value=args)

    main()
    assert hr_output_for_email_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert email_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert email_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_filename(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of filename command through main function
    when it returns reputation about given filename.

    Given:
       - mocked client
    When:
       - Calling `filename_lookup_command` function
    Then:
       - Returns list of command results.
    """

    filename_reputation = util_load_json("test_data/filename_reputation.json")
    filename_reputation_context = util_load_json("test_data/filename_reputation_context.json")
    with open("test_data/filename_reputation_hr.md") as file:
        filename_reputation_hr = file.read()

    requests_mock.get(
        f"{MOCK_URL}/technical-intelligence/v1/simple?query="
        f"%2Btype%3A%28%22filename%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy.log%22",
        json=filename_reputation,
        status_code=200,
    )
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"filename": "dummy.log"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="filename")
    mocker.patch.object(demisto, "args", return_value=args)

    main()
    assert filename_reputation_hr == mock_return.call_args.args[0].get("HumanReadable")
    assert filename_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert filename_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_filename_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of filename command through main function
    when Ignite do not have data about that filename.

    Given:
       - mocked client
    When:
       - Calling `filename_lookup_command` function
    Then:
       - Returns list of command results.
    """
    filename_reputation = util_load_json("test_data/filename_reputation_empty.json")
    filename_reputation_context = util_load_json("test_data/filename_reputation_context_empty.json")
    with open("test_data/filename_reputation_empty_hr.md") as file:
        filename_reputation_empty_hr = file.read()

    requests_mock.get(
        f"{MOCK_URL}/technical-intelligence/v1/simple?query="
        f"%2Btype%3A%28%22filename%22%29%20%2Bvalue.%5C%2A.keyword%3A%22dummy2.log%22",
        json=filename_reputation,
        status_code=200,
    )

    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"filename": "dummy2.log"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="filename")
    mocker.patch.object(demisto, "args", return_value=args)

    main()
    assert filename_reputation_empty_hr == mock_return.call_args.args[0].get("HumanReadable")
    assert filename_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert filename_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
@pytest.mark.parametrize("exact_match", [True, False])
def test_domain_lookup_command_success(mock_return, requests_mock, mocker, exact_match):
    """
    Test case for successful execution of domain look up command through main function
    when it returns reputation about given domain indicator.

    Given:
       - mocked client
    When:
       - Calling `domain_lookup_command` function
    Then:
       - Returns list of command results.
    """

    domain_lookup_reputation = util_load_json("test_data/domain_lookup_reputation.json")
    domain_lookup_reputation_context = util_load_json("test_data/domain_lookup_reputation_context.json")
    with open("test_data/hr_output_for_domain_lookup_reputation.md") as file:
        hr_output_for_domain_lookup_reputation = file.read()

    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'

    requests_mock.get(url, json=domain_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    domain_value = "dummy_domain.com"
    args = {"domain": domain_value, "exact_match": exact_match}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="domain")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    last_request = requests_mock.last_request
    domain_value = f'"{domain_value}"' if exact_match else domain_value
    assert last_request.qs["ioc_value"] == [domain_value]

    assert hr_output_for_domain_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert domain_lookup_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert domain_lookup_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_domain_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of domain look up command through main function
    when it returns empty reputation about given domain indicator.

    Given:
       - mocked client
    When:
       - Calling `domain_lookup_command` function
    Then:
       - Returns list of command results.
    """

    domain_lookup_empty_reputation_context = util_load_json("test_data/domain_lookup_empty_reputation_context.json")
    with open("test_data/hr_output_for_domain_lookup_empty_reputation.md") as file:
        hr_output_for_domain_lookup_reputation = file.read()

    response = util_load_json("test_data/domain_lookup_v2_empty_response.json")
    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'

    requests_mock.get(url, json=response, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"domain": "dummy_domain.com"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="domain")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_domain_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert domain_lookup_empty_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert mock_return.call_args.args[0].get("Contents") == response


def test_domain_lookup_command_when_invalid_value_is_provided(mocker):
    """
    Test case for successful execution of domain look up command through main function
    when domain indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `domain_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"domain": " "}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="domain")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("domain") in return_error.call_args[0][0]


@patch("demistomock.results")
@pytest.mark.parametrize("exact_match", [True, False])
def test_ip_lookup_command_success(mock_return, requests_mock, mocker, exact_match):
    """
    Test case for successful execution of ip look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """

    ip_lookup_reputation = util_load_json("test_data/ip_lookup_reputation.json")
    ip_lookup_reputation_context = util_load_json("test_data/ip_lookup_reputation_context.json")
    with open("test_data/hr_output_for_ip_lookup_reputation.md") as file:
        hr_output_for_ip_lookup_reputation = file.read()

    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'
    requests_mock.get(url, json=ip_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    ip_value = "0.0.0.1"
    args = {"ip": ip_value, "exact_match": exact_match}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch("Ignite.is_ip_address_internal", return_value=False)
    main()

    last_request = requests_mock.last_request
    ip_value = f'"{ip_value}"' if exact_match else ip_value
    assert last_request.qs["ioc_value"] == [ip_value]

    assert hr_output_for_ip_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert ip_lookup_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert ip_lookup_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_ip_lookup_command_community_search_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of ip look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """

    empty_response = util_load_json("test_data/ip_lookup_reputation_v2_empty_response.json")
    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'
    requests_mock.get(url, json=empty_response, status_code=200)

    ip_lookup_community_search_reputation = util_load_json("test_data/ip_lookup_community_search_reputation.json")
    ip_lookup_community_search_reputation_context = util_load_json("test_data/ip_lookup_community_search_reputation_context.json")
    with open("test_data/hr_output_for_ip_lookup_community_search_reputation.md") as file:
        hr_output_for_ip_lookup_community_search_reputation = file.read()

    community_search_url = f'{MOCK_URL}{URL_SUFFIX["COMMUNITY_SEARCH"]}'
    requests_mock.post(community_search_url, json=ip_lookup_community_search_reputation, status_code=200)
    mocker.patch("Ignite.is_ip_address_internal", return_value=False)

    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"ip": "0.0.0.1"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_ip_lookup_community_search_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert ip_lookup_community_search_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert ip_lookup_community_search_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_ip_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of ip look up command through main function
    when it returns empty reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """

    ip_lookup_empty_reputation_context = util_load_json("test_data/ip_lookup_empty_reputation_context.json")
    with open("test_data/hr_output_for_ip_lookup_empty_reputation.md") as file:
        hr_output_for_ip_lookup_reputation = file.read()

    empty_response = util_load_json("test_data/ip_lookup_reputation_v2_empty_response.json")
    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'
    requests_mock.get(url, json=empty_response, status_code=200)

    ip_lookup_community_search_empty_reputation = util_load_json("test_data/ip_lookup_community_search_empty_reputation.json")
    community_search_url = f'{MOCK_URL}{URL_SUFFIX["COMMUNITY_SEARCH"]}'
    requests_mock.post(community_search_url, json=ip_lookup_community_search_empty_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"ip": "0.0.0.1"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(demisto, "args", return_value=args)
    mocker.patch("Ignite.is_ip_address_internal", return_value=False)

    main()

    assert hr_output_for_ip_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert ip_lookup_empty_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert mock_return.call_args.args[0].get("Contents") == empty_response


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"ip": "dummy.com"}, MESSAGES["INVALID_IP_ADDRESS"].format("dummy.com")),
        ({"ip": " "}, MESSAGES["MISSING_REQUIRED_ARGS"].format("ip")),
    ],
)
def test_ip_lookup_command_when_invalid_value_is_provided(mocker, args, error_msg, capfd):
    """
    Test case for successful execution of ip look up command through main function
    when ip indicator's value is invalid.

    Given:
       - mocked client
    When:
       - Calling `ip_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}

    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="ip")
    mocker.patch.object(demisto, "args", return_value=args)
    return_error = mocker.patch.object(Ignite, "return_error")

    capfd.close()
    main()

    assert error_msg in return_error.call_args[0][0]


@patch("demistomock.results")
def test_common_lookup_command_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json("test_data/common_lookup_reputation.json")
    common_lookup_reputation_context = util_load_json("test_data/common_lookup_reputation_context.json")
    with open("test_data/hr_output_for_common_lookup_reputation.md") as file:
        hr_output_for_common_lookup_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator": "00000000000000000000000000000001"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-common-lookup")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_common_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert common_lookup_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_common_lookup_command_success_when_indicator_type_is_ipv4(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json("test_data/common_lookup_ipv4_reputation.json")
    common_lookup_reputation_context = util_load_json("test_data/common_lookup_ipv4_reputation_context.json")
    with open("test_data/hr_output_for_common_lookup_ipv4_reputation.md") as file:
        hr_output_for_common_lookup_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator": "0.0.0.0"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-common-lookup")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_common_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert common_lookup_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_common_lookup_command_success_when_indicator_type_is_ipv6(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns reputation about given ip indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json("test_data/common_lookup_ipv6_reputation.json")
    common_lookup_reputation_context = util_load_json("test_data/common_lookup_ipv6_reputation_context.json")
    with open("test_data/hr_output_for_common_lookup_ipv6_reputation.md") as file:
        hr_output_for_common_lookup_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator": "0:0:0:0:0:0:0:0"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-common-lookup")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_common_lookup_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert common_lookup_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_common_lookup_command_when_custom_indicator_provided(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of flashpoint-ignite-common-lookup command through main function
    when it returns reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    indicator_reputation = util_load_json("test_data/common_lookup_custom_indicator_reputation.json")
    indicator_reputation_context = util_load_json("test_data/common_lookup_custom_indicator_reputation_context.json")
    with open("test_data/hr_output_for_common_lookup_custom_indicator_reputation.md") as file:
        hr_output_for_indicator_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=indicator_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator": "dummy_value"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-common-lookup")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_indicator_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert indicator_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert indicator_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_common_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of common look up command through main function
    when it returns empty reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """

    common_lookup_reputation = util_load_json("test_data/common_lookup_reputation_empty.json")
    common_lookup_reputation_context = util_load_json("test_data/common_lookup_reputation_context_empty.json")
    with open("test_data/hr_output_for_common_lookup_empty_response.md") as file:
        hr_output_for_common_lookup_empty_response = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=common_lookup_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator": "dummy@dummy.com"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-common-lookup")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_common_lookup_empty_response == mock_return.call_args.args[0].get("HumanReadable")
    assert common_lookup_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert common_lookup_reputation == mock_return.call_args.args[0].get("Contents")


def test_common_lookup_command_when_invalid_value_is_provided(mocker):
    """
    Test case for successful execution of common look up command through main function
    when indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `common_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator": " "}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-common-lookup")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("indicator") in return_error.call_args[0][0]


@patch("demistomock.results")
def test_indicator_get_command_success(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of flashpoint-ignite-indicator-get command through main function
    when it returns reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `indicator_get_command` function
    Then:
       - Returns list of command results.
    """

    indicator_reputation = util_load_json("test_data/indicator_reputation.json")
    indicator_reputation_context = util_load_json("test_data/indicator_reputation_context.json")
    with open("test_data/hr_output_for_indicator_reputation.md") as file:
        hr_output_for_indicator_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}/dummy_id', json=indicator_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator_id": "dummy_id"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-indicator-get")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_indicator_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert indicator_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert indicator_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_indicator_get_command_when_custom_indicator_provided(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of flashpoint-ignite-indicator-get command through main function
    when it returns reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `indicator_get_command` function
    Then:
       - Returns list of command results.
    """

    indicator_reputation = util_load_json("test_data/custom_indicator_reputation.json")
    indicator_reputation_context = util_load_json("test_data/custom_indicator_reputation_context.json")
    with open("test_data/hr_output_for_custom_indicator_reputation.md") as file:
        hr_output_for_indicator_reputation = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}/dummy_id', json=indicator_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator_id": "dummy_id"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-indicator-get")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert hr_output_for_indicator_reputation == mock_return.call_args.args[0].get("HumanReadable")
    assert indicator_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert indicator_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_indicator_get_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of flashpoint-ignite-indicator-get command through main function
    when it returns empty reputation about given indicator.

    Given:
       - mocked client
    When:
       - Calling `indicator_get_command` function
    Then:
       - Returns list of command results.
    """

    with open("test_data/hr_output_for_indicator_empty_response.md") as file:
        hr_output_for_indicator_empty_response = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}/dummy_id', json={}, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator_id": "dummy_id"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-indicator-get")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert mock_return.call_args.args[0].get("HumanReadable") == hr_output_for_indicator_empty_response
    assert mock_return.call_args.args[0].get("EntryContext") == {}
    assert mock_return.call_args.args[0].get("Contents") == {}


def test_indicator_get_command_when_invalid_value_is_provided(mocker):
    """
    Test case for  execution of flashpoint-ignite-indicator-get command through main function
    when indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `indicator_get_command` function
    Then:
       - raises error.
    """
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"indicator_id": " "}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-indicator-get")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("indicator_id") in return_error.call_args[0][0]


@patch("demistomock.results")
@pytest.mark.parametrize("exact_match", [True, False])
def test_url_lookup_command_success(mock_return, requests_mock, mocker, exact_match):
    """
    Test case for successful execution of url lookup command through main function
    when it returns reputation about given url.

    Given:
       - mocked client
    When:
       - Calling `url_lookup_command` function
    Then:
       - Returns list of command results.
    """

    url_reputation = util_load_json("test_data/url_reputation.json")
    url_reputation_context = util_load_json("test_data/url_reputation_context.json")
    with open("test_data/url_reputation_hr.md") as file:
        url_reputation_hr = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=url_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    url_value = "http://dummy.com"
    args = {"url": url_value, "exact_match": exact_match}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="url")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    last_request = requests_mock.last_request
    url_value = f'"{url_value}"' if exact_match else url_value
    assert last_request.qs["ioc_value"] == [url_value]

    assert url_reputation_hr == mock_return.call_args.args[0].get("HumanReadable")
    assert url_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert url_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_url_lookup_command_success_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of url lookup command through main function
    when Ignite do not have data about that url.

    Given:
       - mocked client
    When:
       - Calling `url_lookup_command` function
    Then:
       - Returns list of command results.
    """

    url_reputation = util_load_json("test_data/url_reputation_empty.json")
    url_reputation_context = util_load_json("test_data/url_reputation_context_empty.json")
    with open("test_data/url_reputation_hr_empty.md") as file:
        url_reputation_hr = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=url_reputation, status_code=200)

    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"url": "http://dummy2.com"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="url")
    mocker.patch.object(demisto, "args", return_value=args)

    main()
    assert url_reputation_hr == mock_return.call_args.args[0].get("HumanReadable")
    assert url_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert url_reputation == mock_return.call_args.args[0].get("Contents")


def test_url_lookup_command_when_invalid_value_is_provided(mocker):
    """
    Test case for successful execution of url lookup command through main function
    when url indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `url_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"url": " "}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="url")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("url") in return_error.call_args[0][0]


@patch("demistomock.results")
@pytest.mark.parametrize("exact_match", [True, False])
def test_file_lookup_command_success(mock_return, requests_mock, mocker, exact_match):
    """
    Test case for successful execution of file command through main function
    when it returns reputation about given file.

    Given:
       - mocked client
    When:
       - Calling `file_lookup_command` function
    Then:
       - Returns list of command results.
    """

    file_reputation = util_load_json("test_data/file_reputation.json")
    file_reputation_context = util_load_json("test_data/file_reputation_context.json")
    with open("test_data/file_reputation_hr.md") as file:
        file_reputation_hr = file.read()

    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'
    requests_mock.get(url, json=file_reputation, status_code=200)
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    file_value = "00000000000000000000000000000001"
    args = {"file": file_value, "exact_match": exact_match}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="file")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    last_request = requests_mock.last_request
    file_value = f'"{file_value}"' if exact_match else file_value
    assert last_request.qs["ioc_value"] == [file_value]

    assert file_reputation_hr == mock_return.call_args.args[0].get("HumanReadable")
    assert file_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert file_reputation == mock_return.call_args.args[0].get("Contents")


@patch("demistomock.results")
def test_file_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of file command through main function
    when Ignite do not have data about that file.

    Given:
       - mocked client
    When:
       - Calling `file_lookup_command` function
    Then:
       - Returns list of command results.
    """
    file_reputation = util_load_json("test_data/file_reputation_empty.json")
    file_reputation_context = util_load_json("test_data/file_reputation_context_empty.json")
    with open("test_data/file_reputation_empty_hr.md") as file:
        file_reputation_empty_hr = file.read()

    url = f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}'
    requests_mock.get(url, json=file_reputation, status_code=200)

    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"file": "10000000000000000000000000000000"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="file")
    mocker.patch.object(demisto, "args", return_value=args)

    main()
    assert file_reputation_empty_hr == mock_return.call_args.args[0].get("HumanReadable")
    assert file_reputation_context == mock_return.call_args.args[0].get("EntryContext")
    assert file_reputation == mock_return.call_args.args[0].get("Contents")


def test_file_lookup_command_when_invalid_value_is_provided(mocker):
    """
    Test case for unsuccessful execution of file look up command through main function
    when file indicator's value is blank.

    Given:
       - mocked client
    When:
       - Calling `file_lookup_command` function
    Then:
       - Returns list of command results.
    """
    params = {**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"}
    args = {"file": " "}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="file")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("file") in return_error.call_args[0][0]


def test_fetch_incidents_alerts_success(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch alerts.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {}

    mock_response: dict = util_load_json("test_data/fetch_alerts.json")

    incidents_response = util_load_json("test_data/incidents_alerts.json")

    params: dict = {"fetch_type": "Alerts", "first_fetch": "2024-06-14T06:17:17Z", "max_fetch": 4}

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    END_TIME = next_run.get("before_time")

    expected_next_run = {
        "after_time": "2024-06-14T06:17:17Z",
        "before_time": END_TIME,
        "cursor": "1718788282.118454",
        "alert_ids": [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000004",
            "00000000-0000-0000-0000-000000000005",
        ],
    }

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_alerts_when_params_not_provided_and_last_run_provided(mocker, mock_client, requests_mock):
    """
    Test case scenario of fetch_incidents for fetch alerts when params not provided and last run is provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "after_time": "2024-06-14T06:17:17Z",
        "before_time": "2024-06-17T06:17:17Z",
        "alert_ids": ["00000000-0000-0000-0000-000000000000"],
    }

    mock_response: dict = util_load_json("test_data/fetch_alerts.json")

    incidents_response = util_load_json("test_data/incidents_alerts.json")

    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)
    mocker.patch.object(demisto, "command", return_value="fetch-incidents")
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(
        client=mock_client, last_run=last_run, params={"max_fetch": 201, "fetch_type": "Alerts"}
    )

    END_TIME = next_run.get("before_time")

    expected_next_run = {
        "after_time": "2024-06-14T06:17:17Z",
        "before_time": END_TIME,
        "cursor": "1718788282.118454",
        "alert_ids": [
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000004",
            "00000000-0000-0000-0000-000000000005",
        ],
    }
    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_alerts_to_check_duplicates_incidents(mock_client, requests_mock):
    """
    Test case scenario of fetch_incidents for fetch alerts to check duplicate records in response. .

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid command output.
    """
    from Ignite import fetch_incidents

    last_run = {
        "after_time": "2024-06-14T06:17:17Z",
        "before_time": "2024-06-17T06:17:17Z",
        "alert_ids": [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000004",
            "00000000-0000-0000-0000-000000000005",
        ],
    }

    mock_response: dict = util_load_json("test_data/fetch_alerts.json")

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params={"max_fetch": 1, "fetch_type": "Alerts"})

    END_TIME = next_run.get("before_time")

    expected_next_run = {
        "after_time": "2024-06-14T06:17:17Z",
        "before_time": END_TIME,
        "cursor": "1718788282.118454",
        "alert_ids": [
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000004",
            "00000000-0000-0000-0000-000000000005",
        ],
    }
    assert incidents == []
    assert next_run == expected_next_run


def test_fetch_incidents_alerts_when_invalid_arguments_provided(mock_client):
    """
    Test case scenario for execution of fetch_incidents for fetch alerts when invalid arguments provided.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Raise error message.
    """
    from Ignite import fetch_incidents

    error_message = MESSAGES["INVALID_MAX_FETCH"].format("0")
    with pytest.raises(DemistoException) as error:
        fetch_incidents(client=mock_client, last_run={}, params={"max_fetch": 0, "fetch_type": "Alerts"})

    assert str(error.value) == error_message


def test_test_module_with_fetch_incidents_alerts(requests_mock, mock_client):
    """
    Test case scenario for execution of fetch_incident when is_test is true.

    Given:
        - mock client
    When:
        - Calling `fetch_incident` function
    Then:
        - Returns a valid output
    """
    from Ignite import fetch_incidents

    mock_response: dict = util_load_json("test_data/fetch_alerts.json")

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=mock_response, status_code=200)

    next_run, incidents = fetch_incidents(
        client=mock_client, last_run={}, params={"max_fetch": 2, "fetch_type": "Alerts"}, is_test=True
    )

    assert next_run == {}
    assert incidents == []


def test_alert_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import alert_list_command

    alerts = util_load_json("test_data/alert_list_success.json")
    alert_list_context = util_load_json("test_data/alert_list_success_context.json")
    with open("test_data/alert_list_success_hr.md") as file:
        hr_output_for_alerts = file.read()

    token_context = util_load_json("test_data/token_success_context.json")
    with open("test_data/token_success_hr.md") as file:
        hr_output_for_token = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=alerts, status_code=200)

    args = {"size": "4", "created_at": "2024-06-11T05:54:25Z", "created_before": "2024-06-12T05:54:25Z"}
    actual_response = alert_list_command(mock_client, args)

    assert actual_response[0].outputs_prefix == OUTPUT_PREFIX["ALERT"]
    assert actual_response[0].outputs_key_field == "id"
    assert actual_response[0].readable_output == hr_output_for_alerts
    assert actual_response[0].outputs == alert_list_context
    assert actual_response[0].raw_response == alerts

    assert actual_response[1].outputs_prefix == OUTPUT_PREFIX["TOKEN"]
    assert actual_response[1].outputs_key_field == "name"
    assert actual_response[1].readable_output == hr_output_for_token
    assert actual_response[1].outputs == token_context


def test_alert_list_command_success_when_next_is_null(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command when next is null.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import alert_list_command

    alerts = util_load_json("test_data/alert_list_success_next_is_null.json")
    alert_list_context = util_load_json("test_data/alert_list_success_context_next_is_null.json")
    with open("test_data/alert_list_success_next_is_null_hr.md") as file:
        hr_output_for_alerts = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=alerts, status_code=200)

    args = {
        "cursor": "0",
        "tags": "tags1,tags2",
        "sources": "source1,source2",
        "asset_ids": "asset1,asset2",
        "query_ids": "query1,query2",
        "asset_type": "assert_type",
    }
    actual_response = alert_list_command(mock_client, args)

    assert actual_response[0].outputs_prefix == OUTPUT_PREFIX["ALERT"]
    assert actual_response[0].outputs_key_field == "id"
    assert actual_response[0].readable_output == hr_output_for_alerts
    assert actual_response[0].outputs == alert_list_context
    assert actual_response[0].raw_response == alerts


def test_alert_list_command_success_when_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command when empty response.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import alert_list_command

    alerts = util_load_json("test_data/alert_list_success_empty_response.json")
    with open("test_data/alert_list_success_empty_response_hr.md") as file:
        hr_output_for_alerts = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["ALERTS"]}', json=alerts, status_code=200)

    actual_response = alert_list_command(mock_client, {"size": "1"})

    assert actual_response[0].readable_output == hr_output_for_alerts
    assert actual_response[0].raw_response == alerts


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"size": "0"}, MESSAGES["SIZE_ERROR"].format("0", MAX_ALERTS_LIMIT)),
        ({"size": "501"}, MESSAGES["SIZE_ERROR"].format("501", MAX_ALERTS_LIMIT)),
        (
            {"created_after": "2024-06-11T05:54:25Z", "created_before": "2024-06-11T05:54:25Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "created_after", "created_before", "2024-06-11T05:54:25Z", "2024-06-11T05:54:25Z"
            ),
        ),
        ({"status": "tmpStatus"}, MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format("tmpstatus", "status", ALERT_STATUS_VALUES)),
        ({"origin": "tmpOrigin"}, MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format("tmporigin", "origin", ALERT_ORIGIN_VALUES)),
        ({"asset_ip": "abc.com"}, MESSAGES["INVALID_IP_ADDRESS"].format("abc.com")),
    ],
)
def test_alert_list_command_success_when_invalid_argument_provided(mock_client, args, error_msg):
    """
    Test case scenario for successful execution of flashpoint-ignite-alert-list command when invalid argument provided.

    Given:
       - command arguments for alert_list_command
    When:
       - Calling `alert_list_command` function
    Then:
       - Returns a valid error message.
    """
    from Ignite import alert_list_command

    with pytest.raises(ValueError) as err:
        alert_list_command(mock_client, args)

    assert str(err.value) == error_msg


def test_module_fetch_incidents_when_max_product_exceed_total_limit(mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incident compromised credentials when is_test is true.

    Given:
       - mocked client.
    When:
       - Calling `fetch_incidents` function
    Then:
       - Returns a valid error message.
    """
    from Ignite import fetch_incidents

    mock_response: dict = util_load_json("test_data/fetch_incidents_with_check_max_product.json")

    error_message = MESSAGES["TIME_RANGE_ERROR"].format("10005")
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)

    with pytest.raises(ValueError) as error:
        fetch_incidents(client=mock_client, last_run={}, params={}, is_test=True)

    assert str(error.value) == error_message


def test_fetch_incidents_when_empty_password_complexity_filter_params_passed(mocker, mock_client, requests_mock):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - Returns a valid output.
    """
    from Ignite import fetch_incidents

    last_run: dict = {}

    mock_response: dict = util_load_json("test_data/fetch_compromised_credentials.json")

    incidents_response = util_load_json("test_data/incidents_compromised_credentials.json")

    params: dict = {
        "fetch_type": "",
        "first_fetch": "2024-05-16T10:22:38Z",
        "is_fresh_compromised_credentials": "true",
        "password_min_length": "",
        "password_has_symbol": "",
        "password_has_uppercase": "",
        "password_has_lowercase": "",
        "password_has_number": "",
        "max_fetch": 1,
    }
    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["COMPROMISED_CREDENTIALS"]}', json=mock_response, status_code=200)
    next_run, incidents = fetch_incidents(client=mock_client, last_run=last_run, params=params)

    END_TIME = next_run.get("end_time")
    expected_next_run = {
        "fetch_count": 1,
        "fetch_sum": 1,
        "total": 31,
        "end_time": END_TIME,
        "last_time": "2021-03-31T19:42:05Z",
        "hit_ids": ["sample_id_1"],
        "last_timestamp": 1617219725,
        "start_time": "2024-05-16T10:22:38Z",
    }

    assert incidents == incidents_response
    assert next_run == expected_next_run


def test_fetch_incidents_when_invalid_password_complexity_filter_params_passed(mocker, mock_client):
    """
    Test case scenario for execution of fetch_incidents for fetch compromised credentials.

    Given:
        - mock client
    When:
        - Calling `fetch_incidents` function.
    Then:
        - raise value error.
    """
    from Ignite import fetch_incidents

    params: dict = {
        "fetch_type": "",
        "first_fetch": "2025-05-10T10:22:38Z",
        "is_fresh_compromised_credentials": "true",
        "password_min_length": "-1",
        "max_fetch": 1,
    }
    demisto_params = {**BASIC_PARAMS, "severity": "Medium"}
    mocker.patch.object(demisto, "params", return_value=demisto_params)

    with pytest.raises(ValueError) as error:
        fetch_incidents(client=mock_client, last_run={}, params=params)

    assert str(error.value) == MESSAGES["INVALID_PASSWORD_LENGTH"]


def test_vulnerability_get_command_success(mock_client, requests_mock):
    """
    Test case for successful execution of flashpoint-ignite-vulnerability-get command
    when it returns vulnerability details for given ID.

    Given:
       - mocked client
    When:
       - Calling `vulnerability_get_command` function
    Then:
       - Returns command results with vulnerability details and indicator results.
    """
    vulnerability_response = util_load_json("test_data/vulnerability_response.json")
    vulnerability_context = util_load_json("test_data/vulnerability_context.json")
    with open("test_data/hr_output_for_vulnerability.md") as file:
        hr_output_for_vulnerability = file.read()

    requests_mock.get(f"{MOCK_URL}{URL_SUFFIX['VULNERABILITY_GET']}/123456", json=vulnerability_response, status_code=200)
    args = {"id": "123456"}

    results = vulnerability_get_command(mock_client, args)

    # Verify we got multiple results (main result + indicator results)
    assert len(results) >= 1

    # First result should contain vulnerability outputs
    assert results[0].readable_output == hr_output_for_vulnerability
    assert results[0].outputs == vulnerability_context
    assert results[0].raw_response == vulnerability_response

    # Additional results should be indicator results for CVEs
    if len(results) > 1:
        for i in range(1, len(results)):
            assert results[i].indicator is not None
            assert "Created Indicator for" in results[i].readable_output  # type: ignore


@patch("demistomock.results")
def test_vulnerability_get_command_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of flashpoint-ignite-vulnerability-get command through main function
    when it returns empty response for given ID.

    Given:
       - mocked client
    When:
       - Calling `vulnerability_get_command` function with non-existent ID
    Then:
       - Returns no records found message.
    """

    requests_mock.get(f"{MOCK_URL}{URL_SUFFIX['VULNERABILITY_GET']}/999999", json={}, status_code=200)
    params = {**BASIC_PARAMS}
    args = {"id": "999999"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-vulnerability-get")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert mock_return.call_args.args[0].get("HumanReadable") == MESSAGES["NO_RECORDS_FOUND"].format("vulnerability")
    assert mock_return.call_args.args[0].get("EntryContext") == {}
    assert mock_return.call_args.args[0].get("Contents") == {}


def test_vulnerability_get_command_when_id_not_provided(mocker):
    """
    Test case for execution of flashpoint-ignite-vulnerability-get command through main function
    when vulnerability ID is not provided.

    Given:
       - mocked client
    When:
       - Calling `vulnerability_get_command` function without ID
    Then:
       - Raises error for missing required argument.
    """
    params = {**BASIC_PARAMS}
    args: dict = {}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-vulnerability-get")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("id") in return_error.call_args[0][0]


def test_vulnerability_get_command_when_blank_id_provided(mocker):
    """
    Test case for execution of flashpoint-ignite-vulnerability-get command through main function
    when vulnerability ID is blank.

    Given:
       - mocked client
    When:
       - Calling `vulnerability_get_command` function with blank ID
    Then:
       - Raises error for missing required argument.
    """
    params = {**BASIC_PARAMS}
    args = {"id": ""}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="flashpoint-ignite-vulnerability-get")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("id") in return_error.call_args[0][0]


def test_vulnerability_list_command_success(mock_client, requests_mock):
    """
    Test case scenario for successful execution of flashpoint-ignite-vulnerability-list command with filters.

    Given:
       - command arguments including severities, size, from, sort_by, sort_order
    When:
       - Calling `vulnerability_list_command` function
    Then:
       - Returns a valid output and verifies request parameters are sent correctly.
    """
    mock_response = util_load_json("test_data/vulnurability_list_response.json")

    hr_output = open("test_data/vulnerability_list_hr.md").read()
    expected_outputs = util_load_json("test_data/vulnerability_list_context.json")

    requests_mock.post(f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_LIST"]}', json=mock_response, status_code=200)

    args = {
        "severities": "high,medium",
        "size": "2",
        "from": "0",
        "sort_by": "published at",
        "sort_order": "desc",
        "tags": "oss",
        "products": "dummy product",
        "vendors": "dummy vendor",
    }

    results = vulnerability_list_command(mock_client, args=args)

    assert results[0].outputs_prefix == OUTPUT_PREFIX["VULNERABILITY"]
    assert results[0].raw_response == mock_response
    assert results[0].readable_output == hr_output
    assert results[0].outputs == expected_outputs


def test_vulnerability_list_command_with_pagination(mock_client, requests_mock):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-list command with pagination hint.

    Given:
       - command arguments with size=2 and from=0, total=4 (next_index=2 < 4)
    When:
       - Calling `vulnerability_list_command` function
    Then:
       - Returns a valid output that includes a pagination hint in the human-readable output.
    """
    mock_response = util_load_json("test_data/vulnurability_list_response.json")

    requests_mock.post(f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_LIST"]}', json=mock_response, status_code=200)

    results = vulnerability_list_command(mock_client, args={"size": "2", "from": "1"})

    assert len(results) == 1
    assert results[0].outputs_prefix == OUTPUT_PREFIX["VULNERABILITY"]
    assert "#### To retrieve the next set of result use," in results[0].readable_output
    assert "from = 3, size = 2" in results[0].readable_output


def test_vulnerability_list_command_when_empty_response(mock_client, requests_mock):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-list command when no results are returned.

    Given:
       - mocked client returning empty results
    When:
       - Calling `vulnerability_list_command` function
    Then:
       - Returns no records found message.
    """
    mock_response = {"total": 0, "results": []}

    requests_mock.post(f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_LIST"]}', json=mock_response, status_code=200)

    results = vulnerability_list_command(mock_client, args={})

    assert len(results) == 1
    assert results[0].readable_output == MESSAGES["NO_RECORDS_FOUND"].format("vulnerabilities")
    assert results[0].raw_response == mock_response


@pytest.mark.parametrize(
    "args, error_message",
    [
        (
            {"size": "0"},
            MESSAGES["INVALID_LIMIT_PROVIDED"].format("0", MAX_PAGE_SIZE),
        ),
        (
            {"size": "1001"},
            MESSAGES["INVALID_LIMIT_PROVIDED"].format("1001", MAX_PAGE_SIZE),
        ),
        (
            {"from": "-1"},
            MESSAGES["INVALID_FROM_PROVIDED"].format("-1"),
        ),
        (
            {"sort_by": "invalid_sort"},
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format("invalid_sort", "sort_by", VULNERABILITY_SORT_MAPPING.keys()),
        ),
        (
            {"sort_order": "invalid_order"},
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format("invalid_order", "sort_order", SORT_ORDER_VALUES),
        ),
        (
            {"severities": "invalid_severity"},
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                ["invalid_severity"], "Severity", ["Critical", "High", "Medium", "Low", "Informational"]
            ),
        ),
        (
            {"ransomware_scores": "invalid_score"},
            MESSAGES["INVALID_MULTI_PARAMS_PROVIDED"].format(
                ["invalid_score"], "Ransomware Scores", ["Critical", "High", "Medium", "Low"]
            ),
        ),
        (
            {"cwe_ids": "abc"},
            MESSAGES["INVALID_INT_PARAMS_PROVIDED"].format(["abc"], "CWE IDs"),
        ),
        (
            {"updated_after": "2024-06-01T00:00:00Z", "updated_before": "2024-05-01T00:00:00Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "updated_after", "updated_before", "2024-06-01T00:00:00Z", "2024-05-01T00:00:00Z"
            ),
        ),
        (
            {"disclosed_after": "2024-06-01T00:00:00Z", "disclosed_before": "2024-05-01T00:00:00Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "disclosed_after", "disclosed_before", "2024-06-01T00:00:00Z", "2024-05-01T00:00:00Z"
            ),
        ),
        (
            {"published_after": "2024-06-01T00:00:00Z", "published_before": "2024-05-01T00:00:00Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "published_after", "published_before", "2024-06-01T00:00:00Z", "2024-05-01T00:00:00Z"
            ),
        ),
        (
            {"last_touched_after": "2024-06-01T00:00:00Z", "last_touched_before": "2024-05-01T00:00:00Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "last_touched_after", "last_touched_before", "2024-06-01T00:00:00Z", "2024-05-01T00:00:00Z"
            ),
        ),
        (
            {"min_cvssv3_score": "-1"},
            MESSAGES["INVALID_CVSS_SCORE"].format("Minimum CVSS v3 Score"),
        ),
        (
            {"max_cvssv3_score": "11"},
            MESSAGES["INVALID_CVSS_SCORE"].format("Maximum CVSS v3 Score"),
        ),
        (
            {"min_cvssv3_score": "5", "max_cvssv3_score": "3"},
            MESSAGES["INVALID_SCORE_RANGE"].format("Minimum CVSS v3 Score", "Maximum CVSS v3 Score"),
        ),
        (
            {"min_epss_score": "-0.1"},
            MESSAGES["INVALID_EPSS_SCORE"].format("Minimum EPSS Score"),
        ),
        (
            {"max_epss_score": "1.1"},
            MESSAGES["INVALID_EPSS_SCORE"].format("Maximum EPSS Score"),
        ),
        (
            {"min_epss_score": "0.8", "max_epss_score": "0.2"},
            MESSAGES["INVALID_SCORE_RANGE"].format("Minimum EPSS Score", "Maximum EPSS Score"),
        ),
    ],
)
def test_vulnerability_list_command_with_invalid_args(mock_client, args, error_message):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-list command with invalid arguments.

    Given:
       - Invalid command arguments for vulnerability_list_command
    When:
       - Calling `vulnerability_list_command` function
    Then:
       - Raises a DemistoException with the appropriate error message.
    """
    from CommonServerPython import DemistoException

    with pytest.raises(DemistoException) as error:
        vulnerability_list_command(mock_client, args=args)

    assert str(error.value) == error_message


def test_cve_command_success(mock_client, requests_mock):
    """
    Test case for successful execution of cve command through main function
    when it returns vulnerability details for given CVE.

    Given:
       - mocked client
    When:
       - Calling `cve_command` function with valid CVE
    Then:
       - Returns command results with vulnerability details.
    """
    vulnerability_response = util_load_json("test_data/vulnerability_response.json")
    cve_response = {"results": [vulnerability_response]}
    cve_context = util_load_json("test_data/cve_context.json")
    with open("test_data/hr_output_for_cve.md") as file:
        hr_output_for_cve = file.read()

    requests_mock.get(f"{MOCK_URL}{URL_SUFFIX['VULNERABILITY_GET']}", json=cve_response, status_code=200)
    args = {"cve": "CVE-2024-0001"}

    results = cve_command(mock_client, args)

    # Verify we got multiple results (main result + indicator results)
    assert len(results) >= 1

    # First result should contain vulnerability outputs
    assert results[0].readable_output == hr_output_for_cve
    assert results[0].outputs == cve_context
    assert results[0].raw_response == cve_response

    # Additional results should be indicator results for CVEs
    if len(results) > 1:
        for i in range(1, len(results)):
            assert results[i].indicator is not None
            assert "Created Indicator for" in results[i].readable_output  # type: ignore


@patch("demistomock.results")
def test_cve_command_when_empty_response(mock_return, requests_mock, mocker):
    """
    Test case for successful execution of cve command through main function
    when it returns empty response for given CVE.

    Given:
       - mocked client
    When:
       - Calling `cve_command` function with non-existent CVE
    Then:
       - Returns no records found message.
    """
    requests_mock.get(f"{MOCK_URL}{URL_SUFFIX['VULNERABILITY_GET']}", json={"results": []}, status_code=200)
    params = {**BASIC_PARAMS}
    args = {"cve": "CVE-9999-9999"}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="cve")
    mocker.patch.object(demisto, "args", return_value=args)

    main()

    assert mock_return.call_args.args[0].get("HumanReadable") == MESSAGES["NO_RECORDS_FOUND"].format("cve")


def test_cve_command_when_cve_not_provided(mocker):
    """
    Test case for execution of cve command through main function
    when CVE is not provided.

    Given:
       - mocked client
    When:
       - Calling `cve_command` function without CVE
    Then:
       - Raises error for missing required argument.
    """
    params = {**BASIC_PARAMS}
    args: dict = {}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="cve")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("cve") in return_error.call_args[0][0]


def test_cve_command_when_blank_cve_provided(mocker):
    """
    Test case for execution of cve command through main function
    when CVE is blank.

    Given:
       - mocked client
    When:
       - Calling `cve_command` function with blank CVE
    Then:
       - Raises error for missing required argument.
    """
    params = {**BASIC_PARAMS}
    args = {"cve": ""}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "command", return_value="cve")
    mocker.patch.object(demisto, "args", return_value=args)

    return_error = mocker.patch.object(Ignite, "return_error")
    main()

    assert MESSAGES["MISSING_REQUIRED_ARGS"].format("cve") in return_error.call_args[0][0]


def test_cve_command_with_multiple_cves(mock_client, requests_mock):
    """
    Test case for successful execution of cve command through main function
    when multiple CVEs are provided.

    Given:
       - mocked client
    When:
       - Calling `cve_command` function with multiple CVEs
    Then:
       - Returns command results with vulnerability details for each CVE.
    """
    vulnerability_response = util_load_json("test_data/vulnerability_response.json")
    cve_response = {"results": [vulnerability_response]}
    cve_context = util_load_json("test_data/cve_context.json")
    with open("test_data/hr_output_for_cve.md") as file:
        hr_output_for_cve = file.read()

    requests_mock.get(f"{MOCK_URL}{URL_SUFFIX['VULNERABILITY_GET']}", json=cve_response, status_code=200)
    args = {"cve": "CVE-2024-0001,CVE-2024-0002"}

    results = cve_command(mock_client, args)

    # Verify we got multiple results (main result + indicator results)
    assert len(results) >= 1

    # First result should contain vulnerability outputs
    assert results[0].readable_output == hr_output_for_cve
    assert results[0].outputs == cve_context
    assert results[0].raw_response == cve_response

    # Additional results should be indicator results for CVEs
    if len(results) > 1:
        for i in range(1, len(results)):
            assert results[i].indicator is not None
            assert "Created Indicator for" in results[i].readable_output  # type: ignore


def test_cve_command_with_invalid_cve_format(mock_client, mocker):
    """
    Test case for execution of cve command when all provided CVEs have invalid format.

    Given:
    - An invalid CVE format (INVALID-CVE-FORMAT)

    When:
    - Running the !cve command

    Then:
    - Display warning message and exit when all CVEs are invalid
    """
    cve = {"cve": "INVALID-CVE-FORMAT"}

    # Mock return_warning to raise SystemExit when exit=True (simulating actual behavior)
    def mock_return_warning_side_effect(message, exit=False):
        if exit:
            raise SystemExit(0)

    mock_return_warning = mocker.patch("Ignite.return_warning", side_effect=mock_return_warning_side_effect)

    # Expect SystemExit to be raised when all CVEs are invalid
    with pytest.raises(SystemExit):
        cve_command(mock_client, args=cve)

    # Verify warning was called with correct message and exit=True
    mock_return_warning.assert_called_once_with("The following CVEs were found invalid: INVALID-CVE-FORMAT", exit=True)


def test_vulnerability_library_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-vulnerability-library-list command.

    Given:
       - command arguments for vulnerability_library_list_command
    When:
       - Calling `vulnerability_library_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import vulnerability_library_list_command

    response = util_load_json("test_data/vulnerability_libraries.json")

    with open("test_data/vulnerability_libraries_hr.md") as file:
        vulnerability_libraries_hr = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_LIBRARIES"].format("101010")}',
        json=response,
        status_code=200,
    )

    args = {
        "vulnerability_id": "101010",
        "size": "2",
        "sort_by": "Name",
        "sort_order": "asc",
        "from": "2",
        "library_name": "dummy_name",
    }
    actual_response = vulnerability_library_list_command(mock_client, args)

    assert actual_response.outputs_prefix == OUTPUT_PREFIX["VULNERABILITY_LIBRARY"]
    assert actual_response.outputs_key_field == "id"
    assert actual_response.raw_response == response
    assert len(actual_response.outputs) == 2
    assert actual_response.outputs[0]["id"] == 1010
    assert actual_response.outputs[1]["id"] == 101010
    assert actual_response.readable_output == vulnerability_libraries_hr


def test_vulnerability_library_list_command_empty_response(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-library-list command when empty response.

    Given:
       - command arguments for vulnerability_library_list_command
    When:
       - Calling `vulnerability_library_list_command` function
    Then:
       - Returns no records found message.
    """
    from Ignite import vulnerability_library_list_command

    response = {"total": 0, "next": None, "previous": None, "size": 25, "from": 0, "results": []}

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_LIBRARIES"].format("999999")}',
        json=response,
        status_code=200,
    )

    args = {"vulnerability_id": "999999"}
    actual_response = vulnerability_library_list_command(mock_client, args)

    assert actual_response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("vulnerability libraries")


def test_vulnerability_library_list_command_with_pagination(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-library-list command with pagination.

    Given:
       - command arguments with from and size for vulnerability_library_list_command
    When:
       - Calling `vulnerability_library_list_command` function
    Then:
       - Returns a valid output with pagination hint.
    """
    from Ignite import PAGINATION_HR, vulnerability_library_list_command

    response = util_load_json("test_data/vulnerability_libraries.json")

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_LIBRARIES"].format("101010")}',
        json=response,
        status_code=200,
    )

    args = {"vulnerability_id": "101010", "from": "0", "size": "2"}
    actual_response = vulnerability_library_list_command(mock_client, args)

    assert f"{PAGINATION_HR} from = 4, size = 2" in actual_response.readable_output


@pytest.mark.parametrize(
    "args, error_msg",
    [
        (
            {"vulnerability_id": ""},
            MESSAGES["MISSING_REQUIRED_ARGS"].format("vulnerability_id"),
        ),
        (
            {"vulnerability_id": "101010", "size": "0"},
            MESSAGES["SIZE_ERROR"].format(0, MAX_PAGE_SIZE),
        ),
        (
            {"vulnerability_id": "101010", "size": "1001"},
            MESSAGES["SIZE_ERROR"].format(1001, MAX_PAGE_SIZE),
        ),
        (
            {"vulnerability_id": "101010", "sort_by": "invalid_sort"},
            MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format("invalid_sort", "sort_by", LIBRARY_AND_PACKAGE_SORT_VALUES),
        ),
        (
            {"vulnerability_id": "101010", "sort_order": "invalid_order"},
            MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format("invalid_order", "sort_order", SORT_ORDER_VALUES),
        ),
    ],
)
def test_vulnerability_library_list_command_invalid_args(mock_client, args, error_msg):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-library-list command when invalid argument provided.

    Given:
       - command arguments for vulnerability_library_list_command
    When:
       - Calling `vulnerability_library_list_command` function
    Then:
       - Returns a valid error message.
    """
    from Ignite import vulnerability_library_list_command

    with pytest.raises(ValueError) as error:
        vulnerability_library_list_command(mock_client, args)

    assert str(error.value) == error_msg


def test_vulnerability_package_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-vulnerability-package-list command.

    Given:
       - command arguments for vulnerability_package_list_command
    When:
       - Calling `vulnerability_package_list_command` function
    Then:
       - Returns a valid output.
    """
    from Ignite import vulnerability_package_list_command

    response = util_load_json("test_data/vulnerability_packages.json")

    with open("test_data/vulnerability_packages_hr.md") as file:
        vulnerability_packages_hr = file.read()

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_PACKAGES"].format("101010")}',
        json=response,
        status_code=200,
    )

    args = {
        "vulnerability_id": "101010",
        "size": "2",
        "sort_by": "Name",
        "sort_order": "asc",
        "from": "0",
        "package_name": "dummy_package_1",
    }
    actual_response = vulnerability_package_list_command(mock_client, args)

    assert actual_response.outputs_prefix == OUTPUT_PREFIX["VULNERABILITY_PACKAGE"]
    assert actual_response.outputs_key_field == "id"
    assert actual_response.raw_response == response
    assert len(actual_response.outputs) == 2
    assert actual_response.outputs[0]["id"] == 10000
    assert actual_response.outputs[1]["id"] == 10001
    assert actual_response.readable_output == vulnerability_packages_hr


def test_vulnerability_package_list_command_empty_response(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-package-list command when empty response.

    Given:
       - command arguments for vulnerability_package_list_command
    When:
       - Calling `vulnerability_package_list_command` function
    Then:
       - Returns no records found message.
    """
    from Ignite import vulnerability_package_list_command

    response = {"total": 0, "next": None, "previous": None, "size": 25, "from": 0, "results": []}

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_PACKAGES"].format("999999")}',
        json=response,
        status_code=200,
    )

    args = {"vulnerability_id": "999999"}
    actual_response = vulnerability_package_list_command(mock_client, args)

    assert actual_response.readable_output == MESSAGES["NO_RECORDS_FOUND"].format("vulnerability packages")


def test_vulnerability_package_list_command_with_pagination(requests_mock, mock_client):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-package-list command with pagination.

    Given:
       - command arguments with from and size for vulnerability_package_list_command
    When:
       - Calling `vulnerability_package_list_command` function
    Then:
       - Returns a valid output with pagination hint.
    """
    from Ignite import PAGINATION_HR, vulnerability_package_list_command

    response = util_load_json("test_data/vulnerability_packages.json")

    requests_mock.get(
        f'{MOCK_URL}{URL_SUFFIX["VULNERABILITY_PACKAGES"].format("101010")}',
        json=response,
        status_code=200,
    )

    args = {"vulnerability_id": "101010", "from": "0", "size": "2"}
    actual_response = vulnerability_package_list_command(mock_client, args)

    assert f"{PAGINATION_HR} from = 2, size = 2" in actual_response.readable_output


@pytest.mark.parametrize(
    "args, error_msg",
    [
        (
            {"vulnerability_id": ""},
            MESSAGES["MISSING_REQUIRED_ARGS"].format("vulnerability_id"),
        ),
        (
            {"vulnerability_id": "101010", "size": "0"},
            MESSAGES["SIZE_ERROR"].format(0, MAX_PAGE_SIZE),
        ),
        (
            {"vulnerability_id": "101010", "size": "1001"},
            MESSAGES["SIZE_ERROR"].format(1001, MAX_PAGE_SIZE),
        ),
        (
            {"vulnerability_id": "101010", "sort_by": "invalid_sort"},
            MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format("invalid_sort", "sort_by", LIBRARY_AND_PACKAGE_SORT_VALUES),
        ),
        (
            {"vulnerability_id": "101010", "sort_order": "invalid_order"},
            MESSAGES["INVALID_SINGLE_SELECT_PARAM"].format("invalid_order", "sort_order", SORT_ORDER_VALUES),
        ),
    ],
)
def test_vulnerability_package_list_command_invalid_args(mock_client, args, error_msg):
    """
    Test case scenario for execution of flashpoint-ignite-vulnerability-package-list command when invalid argument provided.

    Given:
       - command arguments for vulnerability_package_list_command
    When:
       - Calling `vulnerability_package_list_command` function
    Then:
       - Returns a valid error message.
    """
    from Ignite import vulnerability_package_list_command

    with pytest.raises(ValueError) as error:
        vulnerability_package_list_command(mock_client, args)

    assert str(error.value) == error_msg


def test_vendor_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-vendor-list command.

    Given:
       - command arguments with size=2 and from=0, total=5 (pagination expected)
    When:
       - Calling `vendor_list_command` function
    Then:
       - Returns valid output with vendors and pagination HR.
    """
    vendors = util_load_json("test_data/vendor_list_success.json")
    with open("test_data/vendor_list_success_hr.md") as file:
        expected_hr = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["VENDORS"]}', json=vendors, status_code=200)

    args = {"size": "2", "from": "0"}
    actual_response = vendor_list_command(mock_client, args)

    assert len(actual_response) == 1
    assert actual_response[0].outputs_prefix == OUTPUT_PREFIX["VENDOR"]
    assert actual_response[0].outputs_key_field == "id"
    assert actual_response[0].readable_output == expected_hr
    assert actual_response[0].outputs == vendors["results"]
    assert actual_response[0].raw_response == vendors


def test_vendor_list_command_empty_response(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-vendor-list command
    when no vendors are returned.

    Given:
       - command arguments for vendor_list_command
    When:
       - Calling `vendor_list_command` function and API returns empty results
    Then:
       - Returns no records found message.
    """
    result = {"total": "0", "next": "null", "previous": "null", "size": "25", "from": "0", "results": []}
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["VENDORS"]}', json=result, status_code=200)

    actual_response = vendor_list_command(mock_client, {})

    assert len(actual_response) == 1
    assert actual_response[0].readable_output == "No vendors were found for the given argument(s)."


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"size": "0"}, MESSAGES["SIZE_ERROR"].format("0", MAX_PAGE_SIZE)),
        ({"size": "1001"}, MESSAGES["SIZE_ERROR"].format("1001", MAX_PAGE_SIZE)),
        ({"from": "-1"}, MESSAGES["INVALID_FROM_PROVIDED"].format(-1)),
        (
            {"updated_after": "2024-06-01T00:00:00Z", "updated_before": "2024-05-01T00:00:00Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "updated_after", "updated_before", "2024-06-01T00:00:00Z", "2024-05-01T00:00:00Z"
            ),
        ),
    ],
)
def test_vendor_list_command_invalid_args(mock_client, args, error_msg):
    """
    Test case scenario for flashpoint-ignite-vendor-list command when invalid arguments are provided.

    Given:
       - Invalid command arguments
    When:
       - Calling `vendor_list_command` function
    Then:
       - Raises ValueError with appropriate error message.
    """
    with pytest.raises(ValueError, match=re.escape(error_msg)):
        vendor_list_command(mock_client, args)


def test_vendor_list_command_with_invalid_vendor_ids(requests_mock, mock_client, mocker):
    """
    Test case scenario for flashpoint-ignite-vendor-list command when non-integer vendor_ids are provided.

    Given:
       - command arguments with a mix of valid and non-integer vendor_ids
    When:
       - Calling `vendor_list_command` function
    Then:
       - A warning is issued for invalid IDs and the command still returns results.
    """
    vendors = util_load_json("test_data/vendor_list_success.json")
    return_warning_mock = mocker.patch.object(Ignite, "return_warning")

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["VENDORS"]}', json=vendors, status_code=200)

    args = {"vendor_ids": "1001,abc,1002"}
    actual_response = vendor_list_command(mock_client, args)

    assert return_warning_mock.called
    warning_msg = return_warning_mock.call_args[0][0]
    assert "abc" in warning_msg
    assert len(actual_response) == 1


def test_product_list_command_success(requests_mock, mock_client):
    """
    Test case scenario for successful execution of flashpoint-ignite-product-list command.

    Given:
       - command arguments with size=2 and from=0, total=5 (pagination expected)
    When:
       - Calling `product_list_command` function
    Then:
       - Returns valid output with products and pagination HR.
    """
    products = util_load_json("test_data/product_list_success.json")
    with open("test_data/product_list_success_hr.md") as file:
        expected_hr = file.read()

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["PRODUCTS"]}', json=products, status_code=200)

    args = {"size": "2", "from": "0"}
    actual_response = product_list_command(mock_client, args)

    assert len(actual_response) == 1
    assert actual_response[0].outputs_prefix == OUTPUT_PREFIX["PRODUCT"]
    assert actual_response[0].outputs_key_field == "id"
    assert actual_response[0].readable_output == expected_hr
    assert actual_response[0].outputs == products["results"]
    assert actual_response[0].raw_response == products


def test_product_list_command_empty_response(requests_mock, mock_client):
    """
    Test case scenario for flashpoint-ignite-product-list command when no results are returned.

    Given:
       - mocked client returning empty results
    When:
       - Calling `product_list_command` function
    Then:
       - Returns no records found message.
    """
    result = {"total": 0, "next": None, "previous": None, "size": 10, "from": 0, "results": []}
    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["PRODUCTS"]}', json=result, status_code=200)

    actual_response = product_list_command(mock_client, {})

    assert len(actual_response) == 1
    assert actual_response[0].readable_output == MESSAGES["NO_RECORDS_FOUND"].format("products")


@pytest.mark.parametrize(
    "args, error_msg",
    [
        ({"size": "0"}, MESSAGES["SIZE_ERROR"].format("0", MAX_PAGE_SIZE)),
        ({"size": "1001"}, MESSAGES["SIZE_ERROR"].format("1001", MAX_PAGE_SIZE)),
        ({"from": "-1"}, MESSAGES["INVALID_FROM_PROVIDED"].format(-1)),
        (
            {"updated_after": "2024-06-01T00:00:00Z", "updated_before": "2024-05-01T00:00:00Z"},
            MESSAGES["INVALID_TIME_INTERVAL"].format(
                "updated_after", "updated_before", "2024-06-01T00:00:00Z", "2024-05-01T00:00:00Z"
            ),
        ),
    ],
)
def test_product_list_command_invalid_args(mock_client, args, error_msg):
    """
    Test case scenario for flashpoint-ignite-product-list command when invalid arguments are provided.

    Given:
       - Invalid command arguments
    When:
       - Calling `product_list_command` function
    Then:
       - Raises ValueError with appropriate error message.
    """
    with pytest.raises(ValueError, match=re.escape(error_msg)):
        product_list_command(mock_client, args)


@pytest.mark.parametrize(
    "args, invalid_id",
    [
        ({"product_ids": "10001,invalid_id,10002"}, "invalid_id"),
        ({"vendor_ids": "1,bad_id"}, "bad_id"),
    ],
)
def test_product_list_command_with_invalid_ids(requests_mock, mock_client, mocker, args, invalid_id):
    """
    Test case scenario for flashpoint-ignite-product-list command when non-integer IDs are provided.

    Given:
       - command arguments with a mix of valid and non-integer product_ids or vendor_ids
    When:
       - Calling `product_list_command` function
    Then:
       - A warning is issued for invalid IDs and the command still returns results.
    """
    products = util_load_json("test_data/product_list_success.json")
    return_warning_mock = mocker.patch.object(Ignite, "return_warning")

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["PRODUCTS"]}', json=products, status_code=200)

    actual_response = product_list_command(mock_client, args)

    assert return_warning_mock.called
    warning_msg = return_warning_mock.call_args[0][0]
    assert invalid_id in warning_msg
    assert len(actual_response) == 1


def test_community_search_relationships_truncated_when_over_limit(mock_client):
    """
    Test that relationships are capped at DEFAULT_REPUTATION_CONTEXT_LIMIT.

    Given:
        - A community search indicator with url_domains list longer than the limit.
    When:
        - Calling `create_relationships_list_for_community_search`.
    Then:
        - Relationships are capped at DEFAULT_REPUTATION_CONTEXT_LIMIT.
    """
    oversized_domains = [f"domain{i}.com" for i in range(DEFAULT_REPUTATION_CONTEXT_LIMIT + 10)]
    indicator = {"enrichments": {"url_domains": oversized_domains}}
    relationships = create_relationships_list_for_community_search(mock_client, indicator, "1.2.3.4")
    assert len(relationships) == DEFAULT_REPUTATION_CONTEXT_LIMIT


def test_community_search_relationships_not_truncated_when_within_limit(mock_client):
    """
    Test that enrichment lists within the limit produce all relationships.

    Given:
        - A community search indicator with url_domains list shorter than the limit.
    When:
        - Calling `create_relationships_list_for_community_search`.
    Then:
        - All entries produce relationships.
    """
    indicator = {"enrichments": {"url_domains": ["example.com", "test.com"]}}
    relationships = create_relationships_list_for_community_search(mock_client, indicator, "9.9.9.9")
    assert len(relationships) == 2


def test_ip_lookup_enrichments_truncated_to_param_limit(requests_mock, mocker):
    """
    Test that community-search enrichment lists are truncated to the configured
    `reputation_enrichments_limit` parameter value, not the hardcoded constant.

    Given:
        - A client with reputation_enrichments_limit set to 3.
        - A community search response containing an enrichment list with 10 entries.
    When:
        - Calling `ip_lookup_command`.
    Then:
        - The outputs stored in context contain at most 3 enrichment entries per list.
    """
    custom_limit = 3
    client = Client(MOCK_URL, {}, False, None, False, reputation_enrichments_limit=custom_limit)

    empty_ioc_response = {"items": []}
    oversized_enrichments = [f"domain{i}.com" for i in range(10)]
    community_response = {
        "items": [
            {
                "id": "test-id",
                "date": "2024-01-01T00:00:00Z",
                "first_observed_at": "2024-01-01T00:00:00Z",
                "last_observed_at": "2024-01-01T00:00:00Z",
                "author": "test-author",
                "title": "test-title",
                "site": "test-site",
                "enrichments": {
                    "url_domains": oversized_enrichments,
                },
            }
        ]
    }

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=empty_ioc_response, status_code=200)
    requests_mock.post(f'{MOCK_URL}{URL_SUFFIX["COMMUNITY_SEARCH"]}', json=community_response, status_code=200)
    mocker.patch("Ignite.is_ip_address_internal", return_value=False)
    mocker.patch.object(demisto, "params", return_value={**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"})

    result = ip_lookup_command(client, "1.2.3.4")

    outputs = result.outputs  # type: ignore[union-attr]
    assert isinstance(outputs, list)
    stored_domains = outputs[0].get("enrichments", {}).get("url_domains", [])
    assert len(stored_domains) == custom_limit


def test_ip_lookup_enrichments_not_truncated_when_within_param_limit(requests_mock, mocker):
    """
    Test that enrichment lists within the configured limit are stored in full.

    Given:
        - A client with reputation_enrichments_limit set to 10.
        - A community search response containing an enrichment list with 3 entries.
    When:
        - Calling `ip_lookup_command`.
    Then:
        - All 3 enrichment entries are preserved in the outputs.
    """
    custom_limit = 10
    client = Client(MOCK_URL, {}, False, None, False, reputation_enrichments_limit=custom_limit)

    empty_ioc_response = {"items": []}
    small_enrichments = ["a.com", "b.com", "c.com"]
    community_response = {
        "items": [
            {
                "id": "test-id",
                "date": "2024-01-01T00:00:00Z",
                "first_observed_at": "2024-01-01T00:00:00Z",
                "last_observed_at": "2024-01-01T00:00:00Z",
                "author": "test-author",
                "title": "test-title",
                "site": "test-site",
                "enrichments": {
                    "url_domains": small_enrichments,
                },
            }
        ]
    }

    requests_mock.get(f'{MOCK_URL}{URL_SUFFIX["LIST_INDICATORS"]}', json=empty_ioc_response, status_code=200)
    requests_mock.post(f'{MOCK_URL}{URL_SUFFIX["COMMUNITY_SEARCH"]}', json=community_response, status_code=200)
    mocker.patch("Ignite.is_ip_address_internal", return_value=False)
    mocker.patch.object(demisto, "params", return_value={**BASIC_PARAMS, "integrationReliability": "B - Usually reliable"})

    result = ip_lookup_command(client, "1.2.3.4")

    outputs = result.outputs  # type: ignore[union-attr]
    assert isinstance(outputs, list)
    stored_domains = outputs[0].get("enrichments", {}).get("url_domains", [])
    assert len(stored_domains) == len(small_enrichments)


def test_client_default_reputation_enrichments_limit():
    """
    Test that Client uses DEFAULT_REPUTATION_CONTEXT_LIMIT as the default when
    reputation_enrichments_limit is not provided.

    Given:
        - A Client instantiated without the reputation_enrichments_limit argument.
    When:
        - Accessing client.reputation_enrichments_limit.
    Then:
        - The value equals DEFAULT_REPUTATION_CONTEXT_LIMIT.
    """
    client = Client(MOCK_URL, {}, False, None, False)
    assert client.reputation_enrichments_limit == DEFAULT_REPUTATION_CONTEXT_LIMIT
