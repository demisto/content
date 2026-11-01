import logging
from datetime import datetime
from unittest.mock import patch

import pytest
from CommonServerPython import DemistoException, IncidentSeverity, IncidentStatus
from dateparser import parse
from HackerView import (
    ABSOLUTE_MAX_FETCH,
    HV_DEEPSCAN_FIELDS,
    HV_INCOMING_DATE_FORMAT,
    HV_LIGHTSCAN_FIELDS,
    HV_OUTGOING_DATE_FORMAT,
    LOGGING_PREFIX,
)

"""CONSTANTS"""  # pylint: disable="pointless-string-statement”
BASE_URL = "https://example.com:443"

MODULES = [
    ("lightscan", HV_LIGHTSCAN_FIELDS),
    ("deepscan", HV_DEEPSCAN_FIELDS),
]


def load_mock_response(file_name: str) -> dict | list:
    """
    Given:
        - Name of json file inside `test-data` directory. Load mock file that simulates an API response.
    When:
        - load_mock_response is called.
    Then:
        - Read the file requested into a dictionary and return it.
    """
    import json
    import os

    base = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_data")
    with open(os.path.join(base, file_name), encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


DEEPSCAN_INCIDENT_DETAILS_EXPECTED = load_mock_response("incident_details_response_deepscan_valid.json")[0]


""" MOCK CLIENT"""  # pylint: disable="pointless-string-statement”


@pytest.fixture()
def mock_client():
    """
    Given: Nothing
    When:
        - mock_client is called.
    Then:
        - Return a new mock HackerView Client.
    """
    from HackerView import Client

    return Client(
        base_url="https://example.com",
        verify=False,
        headers={"api-key": "some_mock_api_key"},
    )


""" HELPER FUNCTION TESTS"""  # pylint: disable="pointless-string-statement”


@pytest.mark.parametrize(
    "hackerview_severity, expected_xsoar_severity",
    [
        ("fyi", 0),
        ("info", 0.5),
        ("informational", 0.5),
        ("low", 1),
        ("medium", 2),
        ("high", 3),
        ("critical", 4),
    ],
)
def test_convert_to_demisto_severity(hackerview_severity, expected_xsoar_severity):
    """
    Given:
        - A string represents a HackerView severity.
    When:
        - convert_to_demisto_severity is called.
    Then:
        - Verify that the severity was correctly translated to a Cortex XSOAR severity.
    """
    from HackerView import convert_to_demisto_severity

    assert convert_to_demisto_severity(hackerview_severity) == expected_xsoar_severity


@pytest.mark.parametrize(
    "mock_log_type,mock_log_function,mock_message,mock_asserts",
    [
        (
            [logging.INFO, "INFO"],
            "log",
            "This is a log message at debug level",
            f"{LOGGING_PREFIX} This is a log message at debug level",
        ),
        (
            [logging.INFO, "INFO"],
            "log",
            "This is a log message at info level",
            f"{LOGGING_PREFIX} This is a log message at info level",
        ),
        (
            [logging.INFO, "INFO"],
            "log",
            "This is a log message at error level",
            f"{LOGGING_PREFIX} This is a log message at error level",
        ),
    ],
)
def test_log(mock_log_type, mock_log_function, mock_message, mock_asserts, caplog):
    """
    Given:
        - Demisto log level.
        - Message to log.
    When:
        - helper function log is called.
    Then:
        - Ensure logged message is as expected.
    """
    from HackerView import log

    logging.getLogger().propagate = True
    with caplog.at_level(mock_log_type[0]):
        log(mock_log_type[1], mock_message)
    assert mock_asserts in caplog.text


@pytest.mark.parametrize(
    "mock_input,mock_args,mock_asserts",
    [
        (
            "",
            {"timestamp": False, "input_format_string": "", "output_format": "", "kwargs": {}},
            parse("", [""]),
        ),
        (
            "",
            {"timestamp": False, "input_format_string": "NOT_VALID", "output_format": "", "kwargs": {}},
            "",
        ),
        (
            "05-12-2022 23:03:34",
            {"timestamp": False, "input_format_string": HV_INCOMING_DATE_FORMAT, "output_format": "", "kwargs": {}},
            datetime(2022, 12, 5, 23, 3, 34),
        ),
        (
            "05-12-2022 23:03:34",
            {
                "timestamp": True,
                "input_format_string": HV_INCOMING_DATE_FORMAT,
                "output_format": "",
                "kwargs": {"settings": {"TIMEZONE": "UTC+3", "TO_TIMEZONE": "UTC"}},
            },
            1670270614000,
        ),
        (
            "05-12-2022 23:03:34",
            {
                "timestamp": False,
                "input_format_string": HV_INCOMING_DATE_FORMAT,
                "output_format": "",
                "kwargs": {"settings": {"TIMEZONE": "UTC", "TO_TIMEZONE": "UTC"}},
            },
            datetime(2022, 12, 5, 23, 3, 34),
        ),
        (
            "05-12-2022 23:03:34",
            {
                "timestamp": False,
                "input_format_string": HV_INCOMING_DATE_FORMAT,
                "output_format": HV_OUTGOING_DATE_FORMAT,
                "kwargs": {"settings": {"TIMEZONE": "UTC", "TO_TIMEZONE": "UTC"}},
            },
            "05-12-2022 23:03",
        ),
    ],
)
def test_convert_time_string(mock_input, mock_args, mock_asserts, capfd, caplog):
    """
    Given:
        - Input time string.
        - Input format string.
        - (Optional) Output format string.
        - (Optional) Timestamp switch
    When:
        - convert_time_string is called.
    Then:
        - Return time as either: another time format, [datetime] object, or timestamp in milliseconds
    """
    from HackerView import convert_time_string

    with capfd.disabled():
        result = convert_time_string(
            mock_input,
            mock_args["input_format_string"],
            mock_args["output_format"],
            mock_args["timestamp"],
            **mock_args["kwargs"],
        )
        caplog.set_level(logging.INFO)
        assert result == mock_asserts
        if caplog.text:
            assert (
                f"{LOGGING_PREFIX} An error was encountered at `convert_time_string()` \
                err=ValueError('The passed date string and/or format string is not valid')"
                in caplog.text
            )


@pytest.mark.parametrize(
    "mock_input_file,mock_assert_file,module",
    [
        ("fetch_incidents_response_valid.json", "incident_list_cmd_result_valid.json", "lightscan"),
        ("fetch_incidents_response_deepscan_valid.json", "map_and_create_deepscan_expected.json", "deepscan"),
    ],
)
def test_map_and_create_incident(mock_input_file, mock_assert_file, module):
    """
    Given:
        - A dictionary of an unmapped incident.
    When:
        - map_and_create_incident is called.
    Then:
        - Create a new incident dictionary that is in XSOAR-appropriate structure and return it.
    """
    from HackerView import Instance, map_and_create_incident

    mock_fetched_incident = dict(load_mock_response(mock_input_file)[0])
    expected_raw = load_mock_response(mock_assert_file)
    mock_assert = dict(expected_raw[0] if isinstance(expected_raw, list) else expected_raw)
    mock_assert.pop("rawJson", None)
    with patch("HackerView.INSTANCE", Instance(module=module)):
        result = map_and_create_incident(mock_fetched_incident)
    result.pop("rawJson", None)
    assert result == mock_assert


@pytest.mark.parametrize(
    "input_file_name,last_run_ids,expected_num_ids,expected_num_unique",
    [
        ("", [], 0, 0),
        ("fetch_incidents_response_valid.json", [], 3, 3),
        ("fetch_incidents_response_valid.json", ["HVI-98944790"], 3, 2),
        ("fetch_incidents_response_deepscan_valid.json", [], 3, 3),
        ("fetch_incidents_response_deepscan_valid.json", ["HVI-23813230"], 3, 2),
        ("fetch_incidents_response_deepscan_valid.json", ["HVI-99912344"], 3, 2),
    ],
)
def test_deduplicate_and_create_incidents(input_file_name, last_run_ids, expected_num_ids, expected_num_unique, capfd, caplog):
    """
    Given:
        - List of fetched incidents.
        - List of last run's calculated ids.
    When:
        - deduplicate_and_create_incidents is called.
    Then:
        - Calculate ids for the passed list of incidents.
        - Create a new list of XSOAR-ready incidents only for incidents not found in the last run.
    """
    from HackerView import deduplicate_and_create_incidents

    with capfd.disabled():
        caplog.set_level(logging.DEBUG)
        fetched = load_mock_response(input_file_name) if input_file_name else []
        new_ids, unique_incidents = deduplicate_and_create_incidents(fetched, last_run_ids)
        assert len(new_ids) == expected_num_ids
        assert len(unique_incidents) == expected_num_unique


@pytest.mark.parametrize(
    "mock_input,mock_assert",
    [
        ("PascalCaseTest", "pascal_case_test"),
        ("camelCaseTest", "camel_case_test"),
    ],
)
def test_to_snake_case(mock_input, mock_assert):
    """
    Given:
        - String in a case other than snake case
    When:
        - to_snake_case is called
    Then:
        - Convert the input to snake case and return it
    """
    from HackerView import to_snake_case

    assert to_snake_case(mock_input) == mock_assert


""" COMMAND TESTS """  # pylint: disable="pointless-string-statement”


@pytest.mark.parametrize(
    "mock_params,mock_side_effect",
    [
        (
            {
                "mirror_direction": "",
            },
            DemistoException('Invalid "Mirroring Direction" Value'),
        ),
        (
            {
                "mirror_direction": "None",
                "first_fetch": "wrong",
            },
            DemistoException('Invalid "First Fetch" Value'),
        ),
        (
            {
                "mirror_direction": "None",
                "max_fetch": "-1",
            },
            DemistoException(f'Invalid "Max Fetch" Value. Should be between 1 to {ABSOLUTE_MAX_FETCH}'),
        ),
        (
            {
                "mirror_direction": "None",
                "date_from": "wrong",
            },
            DemistoException('Invalid "Date From" Value (Does not match format "%d-%m-%Y %H:%M")'),
        ),
        (
            {
                "mirror_direction": "None",
                "date_to": "wrong",
            },
            DemistoException('Invalid "Date To" Value (Does not match format "%d-%m-%Y %H:%M")'),
        ),
        ({"mirror_direction": "None", "api_key": {"password": ""}}, DemistoException('Invalid "API Key" Value')),
    ],
)
def test_test_module(mock_params, mock_side_effect, mock_client, mocker):
    """
    Given:
        - HackerView Client.
        - Client arguments.
    When:
        - test-module is called.
    Then:
        - The key is checked against known valid keys.
        - If invalid, an exception is raised with a clear message.
    """
    from HackerView import test_module

    mocker.patch.object(
        mock_client,
        "test_configuration",
        side_effect=mock_side_effect,
    )
    with pytest.raises(DemistoException) as e:
        test_module(mock_client, mock_params)
    assert str(e.value) == mock_side_effect.message


def test_test_module_ok_when_module_to_use_missing(mock_client, mocker):
    """Upgraded instances without module_to_use should still test and fetch as Light Scan."""
    from HackerView import test_module

    mock_test = mocker.patch.object(mock_client, "test_configuration", return_value=[])
    result = test_module(
        mock_client,
        {"mirror_direction": "None", "api_key": {"password": "test"}},
    )
    assert result == "ok"
    assert mock_test.call_args[0][0]["module_type"] == "lightscan"


@pytest.mark.parametrize("mock_module,module_fields", MODULES)
def test_get_mapping_fields_command(mock_module, module_fields):
    """
    Given: Nothing.
    When:
        - User schema in the application contains the fields 'field1' and 'field2'.
        - Calling function get_mapping_fields_command.
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the application fields is returned.
    """
    from HackerView import Instance, get_mapping_fields_command

    mock_instance = Instance(module=mock_module)
    with patch("HackerView.INSTANCE", new=mock_instance):
        mappings = get_mapping_fields_command()

    expected_mappings = {"HackerView Incident": {field["name"]: field["description"] for field in module_fields}}
    assert mappings.extract_mapping() == expected_mappings


# Both modules use three incidents in `fetch_incidents_response_*_valid.json` so fetch/dedup tests stay parallel.
FETCH_INCIDENTS_CASES = [
    {
        "module": "lightscan",
        "last_fetch_ids": ["HVI-75466160", "HVI-11136324", "HVI-98944790"],
        "dup_prefix": 1,
        "after_dup_incidents": 2,
        "after_dup_ids_len": 3,
        "first_incident_name": "SSL Expiring in 30 days",
        "expect_issue_category": ["Web Communication"],
        "mirror_id_if_dup": "HVI-11136324",
        "nodup_incidents": 3,
        "second_incident_name": "SSL Expiring in 30 days",
    },
    {
        "module": "deepscan",
        "last_fetch_ids": ["HVI-23813230", "HVI-56431595", "HVI-99912344"],
        "dup_prefix": 1,
        "after_dup_incidents": 2,
        "after_dup_ids_len": 3,
        "first_incident_name": "robots.txt file",
        "expect_issue_category": None,
        "mirror_id_if_dup": "HVI-56431595",
        "nodup_incidents": 3,
        "second_incident_name": "robots.txt file",
        "nodup_ids_match_remote": {"HVI-23813230", "HVI-56431595", "HVI-99912344"},
    },
]


@pytest.mark.parametrize(
    "response_files_names,mock_params,fetch_case",
    [
        (
            ["fetch_incidents_response_valid.json", "fetch_incidents_response_invalid.json"],
            {
                "max_hits": "3",
            },
            FETCH_INCIDENTS_CASES[0],
        ),
        (
            ["fetch_incidents_response_deepscan_valid.json", "fetch_incidents_response_invalid.json"],
            {
                "max_hits": "3",
            },
            FETCH_INCIDENTS_CASES[1],
        ),
    ],
)
def test_fetch_incidents_command(response_files_names, mock_params, fetch_case, mock_client, mocker):
    """
    Given:
        - HackerView Client
        - Client arguments
        # Case 1:
            - User has provided valid pagination params.
            - First run with no new incidents yet, so an empty list will be returned.
        # Case 2:
            - User has provided valid pagination params.
            - Not first run with 1 duplicate incidents, so 3 ids are calculated and 2 unique incidents are returned.
        # Case 3:
            - User has provided valid pagination params.
            - Not first run with no duplicate incidents, so 3 ids are calculated and 3 unique incidents are returned.
        # Case 4:
            - User has provided invalid pagination params.
    When:
        - fetch-incidents command is called.
    Then:
        - Ensure response has correct number of records
        # Case 1:
            - An empty list will be returned.
        # Case 2:
            - 3 ids are calculated and 2 unique incidents are returned.
        # Case 3:
            - 3 ids are calculated and 3 unique incidents are returned.
        # Case 4:
            - DemistoException is raised.
    """
    from HackerView import Instance, fetch_incidents

    last_fetch_ids = fetch_case["last_fetch_ids"]
    # `main()` merges `module_type` into fetch params before calling this helper.
    fetch_params = {**mock_params, "module_type": fetch_case["module"]}

    with patch("HackerView.INSTANCE", Instance(module=fetch_case["module"])):
        # First run with no incidents returned
        mocker.patch.object(mock_client, "fetch_incidents", return_value=[])
        next_run, incidents = fetch_incidents(mock_client, [], fetch_params, {})
        assert next_run == {}
        assert incidents == []

        # Not first run with 1 duplicate in the returned incidents
        mocker.patch.object(mock_client, "fetch_incidents", return_value=load_mock_response(response_files_names[0]))
        next_run, incidents = fetch_incidents(
            mock_client, last_fetch_ids[: fetch_case["dup_prefix"]], fetch_params, {"not_empty": ""}
        )
        assert mock_client.fetch_incidents.call_args[0][0].get("module_type") == fetch_case["module"]
        assert len(incidents) == fetch_case["after_dup_incidents"]
        assert len(next_run.get("last_fetch_ids", [])) == fetch_case["after_dup_ids_len"]
        if incidents and incidents[0].get("xsoar_mirroring", {}).get("mirror_direction"):
            assert incidents[0].get("xsoar_mirroring", {}).get("mirror_id") == fetch_case["mirror_id_if_dup"]
        assert incidents[0].get("name") == fetch_case["first_incident_name"]
        if fetch_case["expect_issue_category"]:
            assert incidents[0].get("CustomFields", {}).get("issue_category") == fetch_case["expect_issue_category"]

        # Not first run with no duplicates in the returned incidents

        mocker.patch.object(mock_client, "fetch_incidents", return_value=load_mock_response(response_files_names[0]))
        next_run, incidents = fetch_incidents(mock_client, [], fetch_params, {"not_empty": ""})
        assert len(incidents) == fetch_case["nodup_incidents"]
        assert next_run.get("last_fetch_ids") == last_fetch_ids
        if incidents and incidents[0].get("xsoar_mirroring", {}).get("mirror_direction"):
            assert incidents[0].get("xsoar_mirroring", {}).get("mirror_id") != ""
        if fetch_case["module"] == "lightscan":
            assert incidents[1].get("name") == fetch_case["second_incident_name"]
            assert incidents[1].get("CustomFields", {}).get("issue_category") == ["Web Communication"]
        elif fetch_case.get("nodup_ids_match_remote"):
            assert {inc.get("CustomFields", {}).get("id") for inc in incidents} == fetch_case["nodup_ids_match_remote"]
            if fetch_case.get("second_incident_name"):
                assert incidents[1].get("name") == fetch_case["second_incident_name"]

        # Run with bad params

        fetch_exception = DemistoException("Error received: Please contact Threat Manager Team")
        mocker.patch.object(mock_client, "fetch_incidents", side_effect=fetch_exception)
        bad_mock_params = {**fetch_params, "date_from": "abcdefg123"}
        with pytest.raises(DemistoException) as e:
            fetch_incidents(mock_client, [], bad_mock_params, {"not_empty": ""})
        assert str(e.value) == "Error received: Please contact Threat Manager Team"


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts_file,module",
    [
        (
            "fetch_incidents_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "incident_list_cmd_result_valid.json",
            "lightscan",
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            "lightscan",
        ),
        (
            "fetch_incidents_response_deepscan_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "deepscan_incident_list_cmd_result_valid.json",
            "deepscan",
        ),
    ],
)
def test_ctm360_hv_incident_list_command(response_file_name, mock_args, mock_asserts_file, module, mock_client, mocker):
    """
    Given:
        - HackerView Client.
        - Client arguments.
    When:
        - fetch_incidents is called.
    Then:
        - Fetch the list of incidents from the remote server.
    """
    from HackerView import Instance, ctm360_hv_incident_list_command

    patched_response = load_mock_response(response_file_name) if response_file_name else []
    mocker.patch.object(mock_client, "fetch_incidents", return_value=patched_response)
    with patch("HackerView.INSTANCE", Instance(module=module)):
        cmd_results = ctm360_hv_incident_list_command(mock_client, mock_args)
    expected_results = load_mock_response(mock_asserts_file) if mock_asserts_file else []
    cmd_results = cmd_results.to_context().get("Contents")
    called_params = mock_client.fetch_incidents.call_args[0][0]
    assert called_params.get("module_type") == module
    if cmd_results and expected_results:
        cmd_results = [{k: v for k, v in item.items() if k != "rawJson"} for item in cmd_results]
        expected_results = [{k: v for k, v in item.items() if k != "rawJson"} for item in expected_results]
    assert cmd_results == expected_results


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts,module",
    [
        (
            "incident_details_response_valid.json",
            {"ticketId": "HVI-11145070"},
            {
                "id": "HVI-11145070",
                "timestamp": 1725453245000,
                "confidence": "confirmed",
                "cve_id": "CVE-2022-1292",
                "cwe": ["CWE-78"],
                "issue_category": ["Common Vulnerabilities"],
                "issue_id": 20221292,
                "issue_name": "Openssl 3.0.2 Vulnerability detected",
                "status": "active",
                "progress_status": "New",
                "severity": "critical",
                "first_seen": "04-09-2024 12:34:03",
                "last_seen": "26-10-2024 12:30:30",
                "environments": ["Web Server", "Library"],
                "ip": "10.161.216.126",
                "ticket_id": "HVI-11145070",
                "ip_type": "dedicated",
                "technologies": ["OpenSSL", "Apache"],
                "port": 443,
                "asset_type": "ip",
                "asset": "10.161.216.126",
                "brand": "REPERSEA",
                "last_updated": 1733839847270,
            },
            "lightscan",
        ),
        (
            False,
            {"ticketId": "HVI-NOTFOUND"},
            {},
            "lightscan",
        ),
        (
            "incident_details_response_deepscan_valid.json",
            {"ticketId": "HVI-99912344"},
            DEEPSCAN_INCIDENT_DETAILS_EXPECTED,
            "deepscan",
        ),
    ],
)
def test_ctm360_hv_incident_details_command(response_file_name, mock_args, mock_asserts, module, mock_client, mocker):
    """
    Given:
        - Ticket ID of incident.
    When:
        - ctm360-hv-incident-details command is called.
    Then:
        - Ensure result is as expected.
    """
    from HackerView import Instance, ctm360_hv_incident_details_command

    patched_response = load_mock_response(response_file_name)[0] if response_file_name else {}
    mocker.patch.object(mock_client, "fetch_incident", return_value=patched_response)
    with patch("HackerView.INSTANCE", Instance(module=module)):
        cmd_results = ctm360_hv_incident_details_command(mock_client, mock_args)
    called_params = mock_client.fetch_incident.call_args[0][0]
    assert called_params.get("module_type") == module
    assert cmd_results.to_context().get("Contents") == mock_asserts


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts",
    [
        (
            "incident_status_change_response_valid.json",
            {"ticketId": "HVI-TEST", "ticketStatus": "investigating", "comment": "test"},
            "Status updated successfully",
        ),
        (
            "incident_status_change_response_invalid_id.json",
            {"ticketId": "HVI-TEST"},
            "Issue not found in the system",
        ),
        (
            "incident_status_change_response_invalid_status.json",
            {"ticketId": "HVI-TEST"},
            "Issue status not valid. Please provide a value from "
            "new,investigating,in_progress,fixed,acceptable_risk,false_positive",
        ),
    ],
)
def test_ctm360_hv_incident_status_change_command(response_file_name, mock_args, mock_asserts, mock_client, mocker):
    """
    Given:
        - Issue ID of incident.
    When:
        - ctm360-hv-incident-change-status command is called.
    Then:
        - Ensure result is as expected.
    """
    from HackerView import ctm360_hv_incident_status_change_command

    mocker.patch.object(mock_client, "change_incident_status", return_value=load_mock_response(response_file_name))
    cmd_results = ctm360_hv_incident_status_change_command(mock_client, mock_args)
    assert cmd_results.to_context().get("HumanReadable") == mock_asserts


@pytest.mark.parametrize(
    "mock_last_seen,mock_last_updated,mock_status",
    [
        ("11-12-2024 11:24:47", 1733905487769, "active"),
        ("11-12-2024 11:24:47", 1733905487768, "active"),
        ("11-12-2024 11:24:45", 1733905487769, "active"),
        ("11-12-2024 11:24:45", 1733905487768, "active"),
        ("11-12-2024 11:24:47", 1733905487769, "inactive"),
        ("11-12-2024 11:24:47", 1733905487768, "inactive"),
        ("11-12-2024 11:24:45", 1733905487769, "inactive"),
        ("11-12-2024 11:24:45", 1733905487768, "inactive"),
    ],
)
def test_get_remote_data(mock_last_seen, mock_last_updated, mock_status, mock_client, mocker):
    """
    Given:
        - HackerView Client.
        - Client arguments.
    When:
        -  get-remote-data command is called.
    Then:
        - Ensure result is as expected.
    """
    from copy import deepcopy

    from HackerView import (
        convert_time_string,
        get_remote_data_command,
        map_and_create_incident,
    )

    mock_args = {"id": "HVI-11145070", "lastUpdate": "2024-10-26T12:34:03.172707565Z"}
    mock_result = load_mock_response("incident_details_response_valid.json")[0]
    mock_result["status"] = mock_status
    mock_result["last_updated"] = mock_last_updated

    progress_statuses = [
        ("Investigating", "Your team is actively investigating and examining this particular issue."),
        ("In Progress", "Your team has concluded its investigation and has shifted its focus to resolution."),
        (
            "Fixed",
            "Your team has implemented all necessary changes and fixes to address this issue."
            + " Our system will automatically label issues as resolved once they are no longer present.",
        ),
        ("False Positive", "The identified problem was incorrectly tagged and may not be relevant."),
        (
            "Acceptable Risk",
            "your organization deems any risk(s) linked to a particular issue as acceptable."
            + " This categorization is intended for internal classification purposes.",
        ),
    ]

    for mock_progress in progress_statuses:
        mock_result["progress_status"] = mock_progress[0]
        mocker.patch.object(mock_client, "fetch_incident", return_value=deepcopy(mock_result))
        mock_result2 = map_and_create_incident(deepcopy(mock_result)) if mock_status and isinstance(mock_result, dict) else []
        if isinstance(mock_result2, dict):
            del mock_result2["rawJson"]
        result = get_remote_data_command(mock_client, mock_args)
        called_params = mock_client.fetch_incident.call_args[0][0]
        assert called_params.get("module_type") == "lightscan"
        entry = result.entries[0] if len(result.entries) >= 1 else []

        if isinstance(result.mirrored_object, dict):
            del result.mirrored_object["rawJson"]

        if (
            convert_time_string(mock_last_seen, HV_INCOMING_DATE_FORMAT, in_iso_format=True, is_utc=True, timestamp=True)
            == mock_last_updated
        ):
            if mock_status == "active":
                assert entry == {"Type": 1, "ContentsFormat": "json", "Contents": {"dbotIncidentReopen": True}}
            else:
                close_reason = f'Incident was {"resolved" if mock_progress[0].lower() == "fixed" else "closed"}.'
                assert entry == {
                    "Type": 1,
                    "ContentsFormat": "json",
                    "Contents": {"dbotIncidentClose": True, "closeReason": close_reason},
                }

            assert result.mirrored_object == mock_result2

        elif mock_status != "inactive":
            assert entry == {"Type": 1, "ContentsFormat": "text", "Contents": mock_progress[1]}
            assert result.mirrored_object == mock_result2
        else:
            assert result.mirrored_object == []
            assert entry == []


@pytest.mark.parametrize(
    "mock_input_file,module",
    [
        ("fetch_incidents_response_valid.json", "lightscan"),
        ("fetch_incidents_response_deepscan_valid.json", "deepscan"),
    ],
)
def test_get_modified_remote_data(mock_input_file, module, mock_client, mocker):
    """
    Given:
        - HackerView Client.
        - Client arguments.
    When:
        - get-modified-remote-data command is called
    Then:
        - Ensure result is as expected
    """
    from HackerView import Instance, get_modified_remote_data_command

    mock_args = {
        "date_field": "last_updated",
        "order": "asc",
        "date_from": "1704183134",
        "max_hits": 50,
        "lastUpdate": "2024-01-02T13:30:21.172707565Z",
    }
    mock_result = load_mock_response(mock_input_file)
    mocker.patch.object(mock_client, "fetch_incidents", return_value=mock_result)
    with patch("HackerView.INSTANCE", Instance(module=module)):
        result = get_modified_remote_data_command(mock_client, mock_args)
    called_params = mock_client.fetch_incidents.call_args[0][0]
    assert called_params.get("module_type") == module
    mock_assert = [str(item["id"]) for item in mock_result]
    assert result.modified_incident_ids == mock_assert


@pytest.mark.parametrize(
    "mock_response_file,mock_args,mock_log_asserts",
    [
        (
            "",
            {
                "remoteId": "1",
                "data": {},
                "entries": [],
                "status": IncidentStatus.ACTIVE,
                "incidentChanged": False,
                "delta": {"not_empty": "value"},
            },
            f"{LOGGING_PREFIX} Incident 1 was not modified locally..",
        ),
        (
            "",
            {
                "remoteId": "2",
                "data": {},
                "entries": [],
                "status": IncidentStatus.ARCHIVE,
                "incidentChanged": True,
                "delta": {"not_empty": "value"},
            },
            f"{LOGGING_PREFIX} Modification to 2 is not configured for outgoing mirroring..",
        ),
        (
            "incident_status_change_response_valid.json",
            {
                "remoteId": "3",
                "data": {},
                "entries": [],
                "status": IncidentStatus.DONE,
                "incidentChanged": True,
                "delta": {"not_empty": "value"},
            },
            f"{LOGGING_PREFIX} Closing incident 3",
        ),
    ],
)
def test_update_remote_system(mock_response_file, mock_args, mock_log_asserts, mock_client, mocker, caplog):
    """
    Given:
        - HackerView Client.
        - Client arguments.
    When:
        - update-remote-system command is called.
    Then:
        - Ensure result is as expected.
    """
    from HackerView import update_remote_system_command

    with caplog.at_level(logging.INFO):
        if mock_response_file:
            mocker.patch.object(mock_client, "change_incident_status", return_value=load_mock_response(mock_response_file))
        result = update_remote_system_command(mock_client, mock_args)
        assert result == mock_args["remoteId"]
        assert mock_log_asserts in caplog.text


@pytest.mark.parametrize(
    "module_to_use,expected",
    [
        (None, "lightscan"),
        ("", "lightscan"),
        ("Light Scan", "lightscan"),
        ("Deep Scan", "deepscan"),
        ("legacy-unknown", "lightscan"),
    ],
)
def test_resolve_hv_module_defaults_to_lightscan(module_to_use, expected):
    """Missing or blank module_to_use must keep pre-DeepScan behavior (Light Scan)."""
    from HackerView import resolve_hv_module

    assert resolve_hv_module(module_to_use) == expected


@pytest.mark.parametrize(
    "is_xsiam_platform, expected_severity",
    [
        (True, IncidentSeverity.MEDIUM),
        (False, IncidentSeverity.MEDIUM),
    ],
)
def test_map_and_create_incident_severity_by_platform(is_xsiam_platform, expected_severity, mocker):
    """Incident fetch maps API severity to numeric Demisto severity on all platforms."""
    from HackerView import Instance, map_and_create_incident

    mocker.patch("HackerView.is_xsiam", return_value=is_xsiam_platform)
    issue = {
        "issue_name": "Test Issue",
        "first_seen": "05-07-2024 06:28:28",
        "last_seen": "26-10-2024 12:15:24",
        "status": "active",
        "severity": "medium",
        "id": "HVI-1",
        "timestamp": 1720161042000,
    }
    with patch("HackerView.INSTANCE", Instance(module="lightscan")):
        result = map_and_create_incident(issue)

    assert result["severity"] == expected_severity
