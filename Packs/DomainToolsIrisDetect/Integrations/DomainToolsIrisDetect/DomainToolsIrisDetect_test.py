"""
DomainTools Iris Detect Test Cases
"""
import hmac
import json
import time
from hashlib import sha256
from typing import Any

import pytest
import requests

from CommonServerPython import DemistoException
from DomainToolsIrisDetect import (
    DEFAULT_LIMIT, DEFAULT_OFFSET, DEFAULT_PAGE_SIZE,
    DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT, DOMAINTOOLS_WATCHED_DOMAINS_HEADER,
    INCLUDE_COUNTS_LIMIT, INCLUDE_DOMAIN_DATA_LIMIT, INTEGRATION_CONTEXT_NAME,
    LIMIT_ERROR_MSG, MAX_DAYS_BACK, MONITOR_DOMAINS_LIMIT,
    PAGE_NUMBER_ERROR_MSG, PAGE_SIZE_ERROR_MSG, Client, DTSigner,
    create_common_api_arguments, create_escalated_api_arguments,
    domaintools_iris_detect_blocklist_domains_command,
    domaintools_iris_detect_escalate_domains_command,
    domaintools_iris_detect_get_blocklist_domains_command,
    domaintools_iris_detect_get_escalated_domains_command,
    domaintools_iris_detect_get_ignored_domains_command,
    domaintools_iris_detect_get_monitors_list_command,
    domaintools_iris_detect_get_new_domains_command,
    domaintools_iris_detect_get_watched_domains_command,
    domaintools_iris_detect_ignore_domains_command,
    domaintools_iris_detect_watch_domains_command, dt_error_handler,
    fetch_domain_tools_api_results, fetch_domains, flatten_nested_dict,
    format_blocklist_fields, format_common_fields, format_data, format_monitor_fields,
    format_risk_score_components, format_watchlist_fields,
    get_command_title_string, get_last_run, get_max_limit, get_results_helper,
    handle_domain_action, join_dict_values_for_keys, module_test, pagination,
    validate_first_fetch)

client = Client(
    username="test_user",
    api_key="test_key",
    new_domains="test_new",
    changed_domains="test_changed",
    blocked_domains="test_blocked",
    risk_score_ranges=["100-100"],
    include_domain_data=True,
    verify=False,
    proxy=False,
)

FORMAT_WATCHLIST_OUTPUT = {
    "dt_domain": "christinadianedummystore.com",
    "dt_state": "watched",
    "dt_discovered_date": "2022-12-27T11:40:16.241000+00:00",
    "dt_changed_date": "2022-12-27T12:03:05.000000+00:00",
    "dt_domain_id": "KW3yJOyKDE",
}
FORMAT_BLOCKLIST_FIELDS_OUTPUT = {
    "dt_watchlist_domain_id": "Va778eAexa",
    "dt_escalation_type": "blocked",
    "dt_id": "PBbe0Rvgw2",
    "dt_created_date_result": "2023-01-08T06:07:33.641498+00:00",
    "dt_updated_date": "2023-01-08T06:07:33.641498+00:00",
    "dt_created_by": "user@example.com",
}
FORMAT_MONITOR_FIELDS_OUTPUT = {
    "dt_monitor_id": "QEMba8wmxo",
    "dt_term": "dummyexpress",
    "dt_state": "active",
    "dt_match_substring_variations": False,
    "dt_nameserver_exclusions": [],
    "dt_text_exclusions": [],
    "dt_created_date": "2022-09-20T06:01:56.760955+00:00",
    "dt_updated_date": "2022-09-20T06:02:33.358799+00:00",
    "dt_status": "completed",
    "dt_created_by": "user@example.com",
}
FORMAT_RISK_SCORE_COMPONENTS_OUTPUT = {
    "dt_proximity_score": 22,
    "dt_threat_profile_malware": 54,
    "dt_threat_profile_phishing": 74,
    "dt_threat_profile_spam": 32,
    "dt_threat_profile_evidence": ["domain name", "name server", "registrant"],
}
FORMAT_COMMON_FIELDS_OUTPUT = {
    "dt_domain": "dummy.com",
    "dt_state": "new",
    "dt_status": "active",
    "dt_discovered_date": "2023-01-07T03:18:40.704000+00:00",
    "dt_changed_date": "2023-01-07T03:20:16.000000+00:00",
    "dt_escalations": [],
    "dt_risk_score": 74,
    "dt_risk_status": "full",
    "dt_mx_exists": False,
    "dt_tld": "com",
    "dt_domain_id": "MWpVbD0x5E",
    "dt_monitor_ids": ["rA7bn46jQ3"],
    "dt_create_date": 20230106,
    "dt_registrar": "dummy Technology Co., Ltd.",
    "dt_registrant_contact_email": None,
}

CREATE_INDICATOR_FROM_DETECT_DOMAIN_OUTPUT = {
    "name": "DomainTools Iris Detect",
    "value": "dummy.com",
    "occurred": "2023-01-07T03:18:40.704000+00:00",
    "type": "DomainTools Iris Detect",
    "rawJSON": {
        "state": "new",
        "domain": "dummy.com",
        "monitor_term": "dummy",
        "status": "active",
        "discovered_date": "2023-01-07T03:18:40.704000+00:00",
        "changed_date": "2023-01-07T03:20:16.000000+00:00",
        "risk_score": 74,
        "risk_score_status": "full",
        "risk_score_components": {
            "proximity": 22,
            "threat_profile": {
                "phishing": 74,
                "malware": 54,
                "spam": 32,
                "evidence": ["domain name", "name server", "registrant"],
            },
        },
        "mx_exists": False,
        "tld": "com",
        "id": "MWpVbD0x5E",
        "escalations": [],
        "monitor_ids": ["rA7bn46jQ3"],
        "registrar": "dummy Technology Co., Ltd.",
        "create_date": 20230106,
    },
    "fields": {
        "irisdetectterm": "dummy",
        "domainname": "dummy.com",
        "creation_date": "2023-01-07T03:18:40.704000+00:00",
        "updated_date": "2023-01-07T03:20:16.000000+00:00",
        "domain_status": "active",
        "irisdetectdiscovereddate": "2023-01-07T03:18:40.704000+00:00",
        "irisdetectchangeddate": "2023-01-07T03:20:16.000000+00:00",
        "irisdetectdomainstatus": "active",
        "irisdetectdomainstate": "new",
        "domaintoolsriskscore": 74,
        "domaintoolsriskscorestatus": "full",
        "irisdetectdomainid": "MWpVbD0x5E",
        "irisdetectescalations": [],
        "irisdetecthostingipdetails": [],
        "registrant_name": "dummy Technology Co., Ltd.",
        "registrant_email": "",
        "name_servers": "",
        "irisdetectmailserversexists": False,
        "irisdetectmailserverdetails": [],
        "domaintoolsriskscorecomponents": {
            "proximity": 22,
            "phishing": 74,
            "malware": 54,
            "spam": 32,
            "evidence": ["domain name", "name server", "registrant"],
        },
        "last_seen_by_source": "2023-01-07T03:20:16.000000+00:00",
        "first_seen_by_source": "2023-01-07T03:18:40.704000+00:00",
    },
}
CREATE_COMMON_API_ARGUMENTS = {
    "monitor_id": "rA7bn46jQ3",
    "tlds[]": [],
    "include_domain_data": False,
    "risk_score_ranges[]": [],
    "sort[]": [],
    "order": None,
    "mx_exists": False,
    "preview": False,
    "search": None,
    "limit": 5,
    "page": None,
    "page_size": None

}


def test_dt_signer():
    """
    Tests the DTSigner class by creating an instance with a sample API username and key, and then
    generates a signature for a given timestamp and URI. The test verifies that the generated
    signature matches the expected signature calculated using the HMAC SHA-256 algorithm.
    """
    api_username = "my_username"
    api_key = "my_key"
    signer = DTSigner(api_username, api_key)
    timestamp = str(int(time.time()))
    uri = "/v2/whois/example.com"
    expected_signature = hmac.new(
        api_key.encode("utf-8"), (api_username + timestamp + uri).encode("utf-8"), sha256
    ).hexdigest()

    signature = signer.sign(timestamp, uri)
    assert signature == expected_signature


def load_json(path):
    """
    Loads a JSON file from the specified path.

    Args:
        path (str): The path of the JSON file to load.

    Returns:
        dict: A dictionary representation of the loaded JSON file.

    Raises:
        IOError: If the file at the specified path cannot be found or read.
        JSONDecodeError: If the file at the specified path contains invalid JSON.

    """
    with open(path, encoding="utf-8") as file:
        return json.loads(file.read())


INDICATOR_LIST = load_json("test_data/indicator.json")
DT_API_INPUT = load_json("test_data/dt_api.json")
INDICATOR_LIST_MONITOR = load_json("test_data/format_monitor_list_input.json")
INDICATOR_LIST_BLOCK = load_json("test_data/format_block_list_input.json")
INDICATOR_LIST_WATCH = load_json("test_data/format_watched_list_input.json")
MONITOR_INPUT_LIST = load_json("test_data/monitor_input_list.json")
POST_BLOCKED_LIST = load_json("test_data/post_blocked_list.json")
POST_ESCALATED_LIST = load_json("test_data/post_escalated_list.json")
POST_WATCHED_LIST = load_json("test_data/post_watched_list.json")
POST_IGNORED_LIST = load_json("test_data/post_ignored_list.json")
GET_NEW_DOMAIN_LIST = load_json("test_data/get_new_domain_list.json")
GET_WATCHED_DOMAIN_LIST = load_json("test_data/get_watched_domain_list.json")
GET_BLOCKED_DOMAIN_LIST = load_json("test_data/get_blocked_domain_list.json")
GET_IGNORED_DOMAIN_LIST = load_json("test_data/get_ignored_domain_list.json")
GET_ESCALATED_DOMAIN_LIST = load_json("test_data/get_escalated_domain_list.json")
DT_API_OUTPUT = load_json("test_data/dt_api_output.json")
DT_HANDLE_DOMAIN_ACTION_OUTPUT = [
    {
        "dt_changed_date": "2022-12-27T12:03:05.000000+00:00",
        "dt_discovered_date": "2022-12-27T11:40:16.241000+00:00",
        "dt_domain": "christinadianedummystore.com",
        "dt_domain_id": "KW3yJOyKDE",
        "dt_state": "watched",
    }
]


def test_test_module(mocker):
    """
    Test module_test function.

    Given:
        - Mocker object.

    When:
        - Running the 'module_test'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    mocker.patch.object(client, "query_dt_api", autospec=True)
    response = module_test(client)
    assert response == "ok"


@pytest.mark.parametrize(
    "nested_dict, expected_output",
    [
        # Test case 1: Nested dict with primitive values.
        ({"proximity": 22, "threat_profile": {"phishing": 74, "malware": 54, "spam": 32}},
         {"proximity": 22, "phishing": 74, "malware": 54, "spam": 32}
         ),
        # Test case 2: Nested dict with list values.
        ({"proximity": 22, "threat_profile": {"phishing": 74,
                                              "evidence": ["domain name", "name server", "registrant"]}},
         {"proximity": 22, "phishing": 74, "evidence": ["domain name", "name server", "registrant"]}),
        # Test case 3: Empty nested dict.
        ({}, {}),
        # Test case 4: Nested dict with nested empty dict.
        ({"proximity": 22, "threat_profile": {}}, {"proximity": 22}),
    ],
)
def test_flatten_nested_dict(nested_dict, expected_output):
    """
    Test flatten_nested_dict function.

    Given:
        - Nested dict.
        - Expected output.

    When:
        - Running the 'flatten_nested_dict'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    assert flatten_nested_dict(nested_dict) == expected_output


def test_get_last_run():
    """
    Test get_last_run function.

    Given:
        - Mocker object.

    When:
        - Running the 'get_last_run'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = get_last_run("test")
    assert response is None


@pytest.mark.parametrize(
    "expected_output", [CREATE_INDICATOR_FROM_DETECT_DOMAIN_OUTPUT]
)
def test_create_indicator_from_detect_domain(expected_output):
    """
    Test create_indicator_from_detect_domain function.

    Given:
        - Expected output.

    When:
        - Running the 'create_indicator_from_detect_domain'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = client.create_indicator_from_detect_domain(
        item=INDICATOR_LIST, term={"rA7bn46jQ3": "dummy"}
    )
    assert response == expected_output


@pytest.mark.parametrize("expected_output", [FORMAT_COMMON_FIELDS_OUTPUT])
def test_format_common_fields(expected_output):
    """
    Test format_common_fields function.

    Given:
        - Expected output.

    When:
        - Running the 'format_common_fields'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = format_common_fields(result=INDICATOR_LIST)
    assert response == expected_output


@pytest.mark.parametrize("expected_output", [FORMAT_MONITOR_FIELDS_OUTPUT])
def test_format_monitor_fields(expected_output):
    """
    Test format_monitor_fields function.

    Given:
        - Expected output.

    When:
        - Running the 'format_monitor_fields'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = format_monitor_fields(result=INDICATOR_LIST_MONITOR)
    assert response == expected_output


@pytest.mark.parametrize("expected_output", [FORMAT_BLOCKLIST_FIELDS_OUTPUT])
def test_format_blocklist_fields(expected_output):
    """
    Test format_blocklist_fields function.

    Given:
        - Expected output.

    When:
        - Running the 'format_blocklist_fields'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = format_blocklist_fields(result=INDICATOR_LIST_BLOCK)
    assert response == expected_output


@pytest.mark.parametrize("expected_output", [FORMAT_WATCHLIST_OUTPUT])
def test_format_watchlist_fields(expected_output):
    """
    Test format_watchlist_fields function.

    Given:
        - Expected output.

    When:
        - Running the 'format_watchlist_fields'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = format_watchlist_fields(result=INDICATOR_LIST_WATCH)
    assert response == expected_output


@pytest.mark.parametrize("expected_output", [FORMAT_RISK_SCORE_COMPONENTS_OUTPUT])
def test_format_risk_score_components(expected_output):
    """
    Test format_risk_score_components function.

    Given:
        - Expected output.

    When:
        - Running the 'format_risk_score_components'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    response = format_risk_score_components(result=INDICATOR_LIST)
    assert response == expected_output


@pytest.mark.parametrize("expected_output", [CREATE_COMMON_API_ARGUMENTS])
def test_create_common_api_arguments(expected_output):
    """
    Test create_common_api_arguments function.

    Given:
        - Expected output.

    When:
        - Running the 'create_common_api_arguments'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    args = {
        "monitor_id": "rA7bn46jQ3",
        "tlds": None,
        "include_domain_data": "False",
        "risk_score_ranges": None,
        "sort": None,
        "order": None,
        "mx_exists": "False",
        "preview": "False",
        "search": None,
        "limit": 5,
        "offset": 0,
        "page": None,
        "page_size": None
    }
    response = create_common_api_arguments(args=args)
    assert expected_output == response


def test_domaintools_iris_detect_get_escalated_domains_command(mocker):
    """
    Test domaintools_iris_detect_get_escalated_domains_command function.

    Given:
        - Mocker object.

    When:
        - Running the 'domaintools_iris_detect_get_escalated_domains_command'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    mocker.patch.object(client, "query_dt_api", return_value=GET_ESCALATED_DOMAIN_LIST)
    args = {"include_domain_data": "True"}
    response = domaintools_iris_detect_get_escalated_domains_command(client, args=args)
    assert response.outputs == GET_ESCALATED_DOMAIN_LIST.get("watchlist_domains", [])
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.Escalated"


def test_domaintools_iris_detect_get_blocklist_domains_command(mocker):
    """
    Test domaintools_iris_detect_get_blocklist_domains_command function.

    Given:
        - Mocker object.

    When:
        - Running the 'domaintools_iris_detect_get_blocklist_domains_command'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    mocker.patch.object(client, "query_dt_api", return_value=GET_BLOCKED_DOMAIN_LIST)
    args = {"include_domain_data": "True"}
    response = domaintools_iris_detect_get_blocklist_domains_command(client, args=args)
    assert response.outputs == GET_BLOCKED_DOMAIN_LIST.get("watchlist_domains", [])
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.Blocked"


def test_domaintools_iris_detect_get_ignored_domains_command(mocker):
    """
    Test domaintools_iris_detect_get_ignored_domains_command function.

    Given:
        - Mocker object.

    When:
        - Running the 'domaintools_iris_detect_get_ignored_domains_command'.

    Then:
        -  Checks the output of the command function with the expected output.
    """
    mocker.patch.object(client, "query_dt_api", return_value=GET_IGNORED_DOMAIN_LIST)
    args = {"include_domain_data": "True"}
    response = domaintools_iris_detect_get_ignored_domains_command(client, args=args)
    assert response.outputs == GET_IGNORED_DOMAIN_LIST.get("watchlist_domains", [])
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.Ignored"


def test_domaintools_iris_detect_get_watched_domains_command(mocker):
    """
    Given:
        - DomainTools API client object
    When:
        - Running the 'domaintools_iris_detect_get_watched_domains_command' function.
    Then:
        - Ensure that the command function output is as expected.
    """
    mocker.patch.object(client, "query_dt_api", return_value=GET_WATCHED_DOMAIN_LIST)
    args = {"include_domain_data": "True"}
    response = domaintools_iris_detect_get_watched_domains_command(client, args=args)
    assert response.outputs == GET_WATCHED_DOMAIN_LIST.get("watchlist_domains", [])
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.Watched"


def test_domaintools_iris_detect_get_new_domains_command(mocker):
    """
    Given:
        - DomainTools API client object
    When:
        - Running the 'domaintools_iris_detect_get_new_domains_command' function.
    Then:
        - Ensure that the command function output is as expected.
    """
    mocker.patch.object(client, "query_dt_api", return_value=GET_NEW_DOMAIN_LIST)
    args = {"include_domain_data": "True"}
    response = domaintools_iris_detect_get_new_domains_command(client, args=args)
    assert response.outputs == GET_NEW_DOMAIN_LIST.get("watchlist_domains", [])
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.New"


def test_fetch_domains(mocker):
    """
    Given:
        - DomainTools API client object
    When:
        - Running the 'fetch_and_process_domains' function.
    Then:
        - Ensure that the function returns True as expected.
    """
    mocker.patch.object(
        client, "fetch_and_process_domains", side_effect=[INDICATOR_LIST]
    )
    response = fetch_domains(client)
    assert str(response) == str(True)


def test_domaintools_iris_detect_get_monitors_list_command(mocker):
    """
    Test domaintools_iris_detect_get_monitors_list_command function.
    Given:
    - requests_mock object.
    When:
    - Running the 'domaintools_iris_detect_get_monitors_list_command' function.
    Then:
    - Ensure the function returns the expected results.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[MONITOR_INPUT_LIST])
    response = domaintools_iris_detect_get_monitors_list_command(client, {})
    assert len(response.outputs) == 3
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.Monitor"


def test_domaintools_iris_detect_blocklist_domains_command(mocker):
    """
    Test domaintools_iris_detect_blocklist_domains_command function.
    Given:
    - requests_mock object.
    When:
    - Running the 'domaintools_iris_detect_blocklist_domains_command' function.
    Then:
    - Ensure the function returns the expected results.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[POST_BLOCKED_LIST])
    response = domaintools_iris_detect_blocklist_domains_command(client, {})
    assert len(response.outputs) == 1
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.BlockedDomain"


def test_domaintools_iris_detect_escalate_domains_command(mocker):
    """
    Test domaintools_iris_detect_escalate_domains_command function.
    Given:
    - requests_mock object.
    When:
    - Running the 'domaintools_iris_detect_escalate_domains_command' function.
    Then:
    - Ensure the function returns the expected results.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[POST_ESCALATED_LIST])
    response = domaintools_iris_detect_escalate_domains_command(client, {})
    assert len(response.outputs) == 1
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.EscalatedDomain"


def test_domaintools_iris_detect_watch_domains_command(mocker):
    """
    Test domaintools_iris_detect_watch_domains_command function.
    Given:
    - requests_mock object.
    When:
    - Running the 'domaintools_iris_detect_watch_domains_command' function.
    Then:
    - Ensure the function returns the expected results.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[POST_WATCHED_LIST])
    response = domaintools_iris_detect_watch_domains_command(client, {})
    assert len(response.outputs) == 1
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.WatchedDomain"


def test_domaintools_iris_detect_ignore_domains_command(mocker):
    """
    Test domaintools_iris_detect_ignore_domains_command function.
    Given:
    - requests_mock object.
    When:
    - Running the 'domaintools_iris_detect_ignore_domains_command' function.
    Then:
    - Ensure the function returns the expected results.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[POST_IGNORED_LIST])
    response = domaintools_iris_detect_ignore_domains_command(client, {})
    assert len(response.outputs) == 1
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.IgnoredDomain"


def test_fetch_domain_tools_api_results(mocker):
    """
    Given:
        - A mocked Client.
    When:
        - Calling fetch_domain_tools_api_results.
    Then:
        - Ensures the output is as expected.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[GET_NEW_DOMAIN_LIST])
    args = {"include_domain_data": "True"}
    response = fetch_domain_tools_api_results(
        client, "/v1/iris-detect/domains/new/", "New Domains", dt_args=args
    )
    assert response.outputs == GET_NEW_DOMAIN_LIST.get("watchlist_domains", [])
    assert response.outputs_prefix == f"{INTEGRATION_CONTEXT_NAME}.New"


def test_process_dt_domains_into_xsoar():
    """
    Given:
        - An empty domains_list.
        - An incident_name.
        - A last_run value.
        - A term dict.
        - enable_incidents=False.
    When:
        - Calling dt_domains_into_xsoar.
    Then:
        - Ensures the result is as expected.
    """
    domains_list = []
    incident_name = "DomainTools Iris Detect Changed Domains Since"
    last_run = "changed_domain_last_run"
    term = {"MWpVbD0x5E": "dummy"}
    res = client.process_dt_domains_into_xsoar(
        domains_list, incident_name, last_run, term, enable_incidents=False
    )
    assert not res


def test_fetch_dt_domains_from_api(mocker):
    """
    Given:
        - A mocked Client.
        - A last_run value.
        - An endpoint.
    When:
        - Calling fetch_dt_domains_from_api.
    Then:
        - Ensures the output is as expected.
    """
    mocker.patch.object(client, "query_dt_api", return_value=DT_API_INPUT)
    last_run = "changed_domain_last_run"
    endpoint = "/v1/iris-detect/domains/watched/"
    res, _ = client.fetch_dt_domains_from_api(endpoint, last_run)
    assert res == DT_API_OUTPUT


def test_get_results_helper(mocker):
    """
    Tests the get_results_helper function.
        Given:
            - mocker object.
        When:
            - Running the 'get_results_helper' function.
        Then:
            -  Checks the output of the command function with the expected output.
    """
    mocker.patch.object(client, "query_dt_api", return_value=DT_API_INPUT)
    endpoint = "/v1/iris-detect/domains/watched/"
    response = get_results_helper(client, endpoint, {}, "watchlist_domains", DOMAINTOOLS_WATCHED_DOMAINS_HEADER)
    assert response == (DT_API_OUTPUT, "Watched Domains \nCurrent page size: 50\nShowing page 1 out of 1")


def test_handle_domain_action(mocker):
    """
    Test the handle_domain_action function.

    Given:
    - mocker object.
    - Arguments for the function call.
    - The action to be performed.

    When:
    - Running the 'handle_domain_action' function.

    Then:
    - Checks the output of the command function with the expected output.
    """
    mocker.patch.object(client, "query_dt_api", side_effect=[POST_WATCHED_LIST])
    args = {"watchlist_domain_ids": "KW3yJOyKDE"}
    response = handle_domain_action(client, args, "watched")
    assert response.to_context()["Contents"] == DT_HANDLE_DOMAIN_ACTION_OUTPUT


@pytest.mark.parametrize("expected_output", ["dummy"])
def test_get_iris_detect_term(expected_output):
    """
    Tests the get_iris_detect_term function.
        Given:
            - An item from a DomainTools Iris Detect response.
            - A dictionary containing the mapping of Iris Detect monitor IDs to terms.
        When:
            - Running the 'get_iris_detect_term' function.
        Then:
            -  Checks the output of the function with the expected output.
    """
    term = {"rA7bn46jQ3": "dummy"}
    item = {
        "state": "new",
        "domain": "dummy.com",
        "status": "active",
        "discovered_date": "2023-01-07T03:18:40.704000+00:00",
        "changed_date": "2023-01-07T03:20:16.000000+00:00",
        "risk_score": 74,
        "risk_score_status": "full",
        "risk_score_components": {
            "proximity": 22,
            "threat_profile": {
                "phishing": 74,
                "malware": 54,
                "spam": 32,
                "evidence": ["domain name", "name server", "registrant"],
            },
        },
        "mx_exists": False,
        "tld": "com",
        "id": "MWpVbD0x5E",
        "escalations": [],
        "monitor_ids": ["rA7bn46jQ3"],
        "registrar": "dummy Technology Co., Ltd.",
        "create_date": 20230106,
    }
    response = join_dict_values_for_keys(item.get("monitor_ids"), term)
    assert response == expected_output


def test_dt_error_handler():
    """
    Test the dt_error_handler function.

    Given:
        - A requests.Response object.

    When:
        - The dt_error_handler function is called with the response object.

    Then:
        - If the response status code is 200, the function should return None.
        - If the response status code is 404 and the response contains a JSON error message,
          the function should raise a DemistoException with the error message.
        - If the response status code is 500 and the response contains a non-JSON error message,
          the function should raise a DemistoException with the default error message.

    """
    response = requests.Response()
    response.status_code = 200
    assert dt_error_handler(response) is None

    # Test an error response with a JSON error message
    response.status_code = 404
    response._content = b'{"error": {"message": "Not Found: The requested resource could not be found."}}'
    with pytest.raises(DemistoException) as exc_info:
        dt_error_handler(response)
    assert str(exc_info.value) == "Not Found: The requested resource could not be found."

    # Test an error response with a non-JSON error message
    response.status_code = 500
    response._content = b"Internal Server Error: An error occurred on the server side."
    with pytest.raises(DemistoException) as exc_info:
        dt_error_handler(response)
    assert str(exc_info.value) == "Internal Server Error: An error occurred on the server side."


FORMAT_INPUT_DATA = {
    "field1": [
        {"key1": "value1"},
        {"key1": "value2"},
        {"key1": "value3"},
        {"key1": "value4"},
    ],
    "field2": [],
}


def test_format_data_with_data():
    """
    Test the format_data function with non-empty data.

    Given:
        - A dictionary containing non-empty data.
        - A field key that exists in the dictionary.
        - An output prefix to use for the formatted output.
        - A key to use for extracting data from each item in the field.

    When:
        - The format_data function is called with the given inputs.

    Then:
        - The function should return a dictionary with the expected keys and values.
        - The value of the output_prefix_1 key should match the value of the data_key in the first item of the field
         list.
        - The value of the output_prefix_2 key should match the value of the data_key in the second item of the
        field list.
    """
    result = format_data(FORMAT_INPUT_DATA, "field1", "output_prefix", "key1")
    assert result["output_prefix_1"] == "value1"
    assert result["output_prefix_2"] == "value2"


def test_format_data_with_empty_field():
    """
    Test the format_data function with an empty field.

    Given:
        - A dictionary containing an empty field.
        - A field key that does not exist in the dictionary.
        - An output prefix to use for the formatted output.
        - A key to use for extracting data from each item in the field.

    When:
        - The format_data function is called with the given inputs.

    Then:
        - The function should return a dictionary with the expected keys and None values.
    """
    result = format_data(FORMAT_INPUT_DATA, "field2", "output_prefix", "key1")

    assert result["output_prefix_raw"] is None
    assert len(result) == 1  # only the output_prefix_raw key should exist


def test_format_data_with_missing_field():
    """
    Test the format_data function with a missing field.

    Given:
        - A dictionary containing a missing field.
        - A field key that does not exist in the dictionary.
        - An output prefix to use for the formatted output.
        - A key to use for extracting data from each item in the field.

    When:
        - The format_data function is called with the given inputs.

    Then:
        - The function should return a dictionary with the expected keys and None values.
    """
    result = format_data(FORMAT_INPUT_DATA, "field3", "output_prefix", "key1")

    assert result["output_prefix_raw"] is None
    assert len(result) == 1  # only the output_prefix_raw key should exist


def test_create_escalated_api_arguments():
    """
    Test the create_escalated_api_arguments function to ensure it returns the
    correct dictionary based on the input arguments dictionary.

    Given:
        - A dictionary containing various API argument fields.
        - Two test cases with different input dictionaries, one with all fields and
          another with some missing fields.

    When:
        - The create_escalated_api_arguments function is called with the given inputs.

    Then:
        - The function should return a dictionary with the expected keys and corresponding
          values from the input dictionary for each test case.
    """
    args = {
        "escalated_since": "2023-01-01",
        "escalation_types": ["type1", "type2"],
        "changed_since": "2023-02-01"
    }

    expected_output = {
        "escalated_since": "2023-01-01",
        "escalation_types[]": ["type1", "type2"],
        "changed_since": "2023-02-01"
    }

    assert create_escalated_api_arguments(args) == expected_output

    # Test with missing keys in the input dictionary
    args = {
        "escalated_since": "2023-01-01",
        "escalation_types": ["type1", "type2"],
    }

    expected_output = {
        "escalated_since": "2023-01-01",
        "escalation_types[]": ["type1", "type2"],
        "changed_since": None
    }

    assert create_escalated_api_arguments(args) == expected_output


def test_validate_first_fetch():
    """
`   Test the validate_first_fetch function with various input cases, including valid input, input with extra spaces,
    input with negative value, non-integer input, empty input, input with only spaces, and input exceeding
    the MAX_DAYS_BACK limit.
    """

    # Test valid input
    assert validate_first_fetch("5 days") == 5
    assert validate_first_fetch("1 day") == 1

    # Test input with extra spaces
    assert validate_first_fetch("   3 days   ") == 3

    # Test input with negative value
    assert validate_first_fetch("-2 days") == MAX_DAYS_BACK

    # Test input with non-integer value
    assert validate_first_fetch("invalid days") == MAX_DAYS_BACK

    # Test input with no value
    assert validate_first_fetch("") == MAX_DAYS_BACK

    # Test input with only spaces
    assert validate_first_fetch("   ") == MAX_DAYS_BACK

    # Test input exceeding MAX_DAYS_BACK
    assert validate_first_fetch(f"{MAX_DAYS_BACK + 5} days") == MAX_DAYS_BACK


@pytest.mark.parametrize("value, expected", [
    ("5 days", 5),
    ("1 day", 1),
    ("   3 days   ", 3),
    ("-2 days", MAX_DAYS_BACK),
    ("invalid days", MAX_DAYS_BACK),
    ("", MAX_DAYS_BACK),
    ("   ", MAX_DAYS_BACK),
    (f"{MAX_DAYS_BACK + 5} days", MAX_DAYS_BACK)
])
def test_validate_first_fetch_parametrized(value, expected):
    """
    Test the validate_first_fetch function with parameterized input cases, including valid input, input with extra
    spaces, input with negative value, non-integer input, empty input, input with only spaces, and input exceeding
    the MAX_DAYS_BACK limit.

    Args:
        value (str): The input value for validate_first_fetch.
        expected (int): The expected output value.
    """

    assert validate_first_fetch(value) == expected


# Test the pagination function with various inputs
@pytest.mark.parametrize(
    "page, page_size, limit, expected",
    [
        (None, None, None, (DEFAULT_PAGE_SIZE, DEFAULT_OFFSET)),
        (2, None, None, (DEFAULT_PAGE_SIZE, DEFAULT_PAGE_SIZE)),
        (3, 20, None, (20, 40)),
        (4, 15, 30, (15, 45)),
        (1, 10, 10, (10, 0)),
    ],
)
def test_pagination(page: int | None, page_size: int | None, limit: int | None, expected: tuple[int, int]):
    """
    Test the pagination function with various input cases, including when page, page_size, and limit are None,
    when only page is provided, when page and page_size are provided, and when all parameters are provided.

    Args:
        page (Optional[int]): The input page number.
        page_size (Optional[int]): The input page size.
        limit (Optional[int]): The input limit.
        expected (Tuple[int, int]): The expected output value as a tuple of page size and offset.
    """
    assert pagination(page, page_size, limit) == expected


# Test the pagination function with invalid inputs that should raise exceptions
@pytest.mark.parametrize(
    "page, page_size, limit, error_msg",
    [
        (-1, None, None, PAGE_NUMBER_ERROR_MSG),
        (0, None, None, PAGE_NUMBER_ERROR_MSG),
        (1, -1, None, PAGE_SIZE_ERROR_MSG),
        (1, 0, None, PAGE_SIZE_ERROR_MSG),
        (1, 10, -1, LIMIT_ERROR_MSG),
        (1, 10, 0, LIMIT_ERROR_MSG),
    ],
)
def test_pagination_errors(page: int | None, page_size: int | None, limit: int | None, error_msg: str):
    """
    Test the pagination function with invalid input cases that should raise exceptions.

    Args:
        page (Optional[int]): The input page number.
        page_size (Optional[int]): The input page size.
        limit (Optional[int]): The input limit.
        error_msg (str): The error message to match in the exception.
    """
    with pytest.raises(DemistoException, match=error_msg):
        pagination(page, page_size, limit)


@pytest.mark.parametrize(
    "sub_context, page, page_size, hits, expected_output",
    [
        ("Test Context", 1, 10, 50, "Test Context \nCurrent page size: 10\nShowing page 1 out of 5"),
        ("Test Context", None, None, None, "Test Context"),
        ("Test Context", 3, 20, 100, "Test Context \nCurrent page size: 20\nShowing page 3 out of 5"),
        ("Test Context", 1, 10, 0, "Test Context \nCurrent page size: 10\nShowing page 1 out of 1"),
    ],
)
def test_get_command_title_string(sub_context: str, page: int | None, page_size: int | None, hits: int | None,
                                  expected_output: str):
    """
    Test the get_command_title_string function with various input cases.

    Args:
        sub_context (str): The input sub_context.
        page (Optional[int]): The input page number.
        page_size (Optional[int]): The input page size.
        hits (Optional[int]): The input hits value.
        expected_output (str): The expected output string.
    """
    assert get_command_title_string(sub_context, page, page_size, hits) == expected_output


@pytest.mark.parametrize(
    "end_point, dt_args, expected_max_limit",
    [
        (DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT, {"include_counts": False}, MONITOR_DOMAINS_LIMIT),
        (DOMAINTOOLS_MONITOR_DOMAINS_ENDPOINT, {"include_counts": True}, INCLUDE_COUNTS_LIMIT),
        ("some_other_endpoint", {"include_counts": True}, INCLUDE_COUNTS_LIMIT),
        ("some_other_endpoint", {"include_domain_data": True}, INCLUDE_DOMAIN_DATA_LIMIT),
        ("some_other_endpoint", {"include_counts": False, "include_domain_data": False}, DEFAULT_LIMIT),
    ],
)
def test_get_max_limit(end_point: str, dt_args: dict[str, Any], expected_max_limit: int):
    """
    Test the get_max_limit function with various input cases, including different endpoints and argument combinations.

    Args:
        end_point (str): The input API endpoint.
        dt_args (Dict[str, Any]): The input dictionary of arguments required for the API query.
        expected_max_limit (int): The expected output value for the maximum limit.
    """
    assert get_max_limit(end_point, dt_args) == expected_max_limit
