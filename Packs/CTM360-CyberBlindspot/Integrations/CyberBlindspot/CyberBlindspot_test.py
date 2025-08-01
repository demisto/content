import pytest
import logging
from datetime import datetime
from dateparser import parse
from unittest.mock import patch
from CommonServerPython import DemistoException, IncidentStatus, EntryType, CommandResults
from CyberBlindspot import (
    LOGGING_PREFIX,
    CBS_INCOMING_DATE_FORMAT,
    CBS_OUTGOING_DATE_FORMAT,
    ABSOLUTE_MAX_FETCH,
    CBS_INCIDENT_FIELDS,
    CBS_CARD_FIELDS,
    CBS_CRED_FIELDS,
    CBS_DOMAIN_INFRINGE_FIELDS,
    CBS_MALWARE_LOG_FIELDS,
)

"""CONSTANTS"""
BASE_URL = "https://example.com:443"


STATUS_ENTRIES = {
    "wip": "Incident is undergoing a process on CyberBlindspot. Actions will be unavailable until processing is done.",
    "closed": "Incident was closed on CyberBlindspot.",
    "monitoring": "Incident is being monitored on CyberBlindspot. Actions will be unavailable until monitoring is done.",
    "resolved": "Incident was resolved by response team on CyberBlindspot. Not closed yet.",
    "disregarded": "Incident was disregarded on CyberBlindspot. Not closed yet.",
    "unconfirmed": "Incident was unconfirmed on CyberBlindspot. Not closed yet.",
    "auto_resolved": "Incident was resolved through monitoring on CyberBlindspot. Not closed yet.",
}

MODULES = [
    (
        "incidents",
        "CyberBlindspot.IncidentList",
        "CyberBlindspot.RemoteIncident",
        CBS_INCIDENT_FIELDS,
    ),
    (
        "compromised_cards",
        "CyberBlindspot.IncidentList",
        "CyberBlindspot.RemoteIncident",
        CBS_CARD_FIELDS,
    ),
    (
        "breached_credentials",
        "CyberBlindspot.IncidentList",
        "CyberBlindspot.RemoteIncident",
        CBS_CRED_FIELDS,
    ),
    (
        "domain_infringement",
        "CyberBlindspot.IncidentList",
        "CyberBlindspot.RemoteIncident",
        CBS_DOMAIN_INFRINGE_FIELDS,
    ),
    (
        "subdomain_infringement",
        "CyberBlindspot.IncidentList",
        "CyberBlindspot.RemoteIncident",
        CBS_DOMAIN_INFRINGE_FIELDS,
    ),
    (
        "malware_logs",
        "CyberBlindspot.IncidentList",
        "CyberBlindspot.RemoteIncident",
        CBS_MALWARE_LOG_FIELDS,
    ),
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

    with open(os.path.join("test_data", file_name), encoding="utf-8") as mock_file:
        return json.loads(mock_file.read())


""" MOCK CLIENT"""


@pytest.fixture()
def mock_client():
    """
    Given: Nothing
    When:
        - mock_client is called.
    Then:
        - Return a new mock CyberBlindspot Client.
    """
    from CyberBlindspot import Client

    return Client(
        base_url="https://example.com",
        verify=False,
        headers={"api-key": "some_mock_api_key"},
    )


""" MOCK HASHES"""


@pytest.fixture()
def mock_last_fetch_ids():
    """
    Given: Nothing
    When:
        - mock_last_fetch_ids is called.
    Then:
        - Return a list of ids.
    """

    def mock_ids(module_type: str):
        match module_type:
            case "compromised_cards":
                return [
                    "LC-A1E202F49",
                    "LC-A1R252F49",
                    "LC-A1CV42F49",
                ]
            case "breached_credentials":
                return [
                    "BC-7FPF679C6",
                    "BC-2EL85279F",
                    "BC-1EF22EW64",
                ]
            case "domain_infringement":
                return [
                    "RD-D7A4ABBC5",
                    "RD-E4F5B5E7E",
                    "RD-9F1AF54E4",
                ]
            case "subdomain_infringement":
                return [
                    "RD-FA144D66C",
                    "RD-5049BCA31",
                    "RD-FBD354127",
                ]
            case "malware_logs":
                return [
                    "ML-904CE0968",
                    "ML-DEAF1ABD5",
                    "ML-919AE2387",
                ]
            case _:
                return [
                    "COMX123456123456",
                    "COMX123456654321",
                    "COMX987654",
                ]

    return mock_ids


""" HELPER FUNCTION TESTS"""


@pytest.mark.parametrize(
    "cyberblindspot_severity, expected_xsoar_severity",
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
def test_convert_to_demisto_severity(cyberblindspot_severity, expected_xsoar_severity):
    """
    Given:
        - A string represents a CyberBlindspot severity.
    When:
        - convert_to_demisto_severity is called.
    Then:
        - Verify that the severity was correctly translated to a Cortex XSOAR severity.
    """
    from CyberBlindspot import convert_to_demisto_severity

    assert convert_to_demisto_severity(cyberblindspot_severity) == expected_xsoar_severity


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
    from CyberBlindspot import log

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
            "05-12-2022 11:03:34 PM",
            {"timestamp": False, "input_format_string": CBS_INCOMING_DATE_FORMAT, "output_format": "", "kwargs": {}},
            datetime(2022, 12, 5, 23, 3, 34),
        ),
        (
            "05-12-2022 11:03:34 PM",
            {
                "timestamp": True,
                "input_format_string": CBS_INCOMING_DATE_FORMAT,
                "output_format": "",
                "kwargs": {"settings": {"TIMEZONE": "UTC+3", "TO_TIMEZONE": "UTC"}},
            },
            1670270614000,
        ),
        (
            "05-12-2022 11:03:34 PM",
            {
                "timestamp": False,
                "input_format_string": CBS_INCOMING_DATE_FORMAT,
                "output_format": "",
                "kwargs": {"settings": {"TIMEZONE": "UTC", "TO_TIMEZONE": "UTC"}},
            },
            datetime(2022, 12, 5, 23, 3, 34),
        ),
        (
            "05-12-2022 11:03:34 PM",
            {
                "timestamp": False,
                "input_format_string": CBS_INCOMING_DATE_FORMAT,
                "output_format": CBS_OUTGOING_DATE_FORMAT,
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
        - Return time as either: another time format, <datetime> object, or timestamp in milliseconds
    """
    from CyberBlindspot import convert_time_string

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
    "mock_input_file,mock_assert_file,mock_module",
    [
        ("fetch_incidents_response_valid.json", "incident_list_cmd_result_valid.json", MODULES[0][0]),
        ("fetch_cards_response_valid.json", "card_list_cmd_result_valid.json", MODULES[1][0]),
        ("fetch_creds_response_valid.json", "cred_list_cmd_result_valid.json", MODULES[2][0]),
        ("fetch_domains_response_valid.json", "domain_list_cmd_result_valid.json", MODULES[3][0]),
        ("fetch_subdomains_response_valid.json", "subdomain_list_cmd_result_valid.json", MODULES[4][0]),
        ("fetch_malware_logs_response_valid.json", "malware_logs_list_cmd_result_valid.json", MODULES[5][0]),
    ],
)
def test_map_and_create_incident(mock_input_file, mock_assert_file, mock_module):
    """
    Given:
        - A dictionary of an unmapped incident.
    When:
        - map_and_create_incident is called.
    Then:
        - Create a new incident dictionary that is in XSOAR-appropriate structure and return it.
    """
    from CyberBlindspot import map_and_create_incident

    mock_fetched_incident = load_mock_response(mock_input_file)[0]
    mock_assert = load_mock_response(mock_assert_file)[0]
    del mock_assert["rawJson"]

    with patch("CyberBlindspot.INSTANCE.module", new=mock_module):
        result = map_and_create_incident(mock_fetched_incident)
        del result["rawJson"]
        logging.debug(result)
        logging.debug(mock_assert)
        assert result == mock_assert


@pytest.mark.parametrize(
    "input_file_name,mock_input,mock_asserts,mock_module",
    [
        ("", ([], []), ([], []), MODULES[0][0]),
        ("fetch_incidents_response_valid.json", 2, ([], []), MODULES[0][0]),
        ("fetch_incidents_response_valid.json", -2, ([], []), MODULES[0][0]),
        ("", ([], []), ([], []), MODULES[1][0]),
        ("fetch_cards_response_valid.json", 2, ([], []), MODULES[1][0]),
        ("fetch_cards_response_valid.json", -2, ([], []), MODULES[1][0]),
        ("", ([], []), ([], []), MODULES[2][0]),
        ("fetch_creds_response_valid.json", 2, ([], []), MODULES[2][0]),
        ("fetch_creds_response_valid.json", -2, ([], []), MODULES[2][0]),
        ("", ([], []), ([], []), MODULES[3][0]),
        ("fetch_domains_response_valid.json", 2, ([], []), MODULES[3][0]),
        ("fetch_domains_response_valid.json", -2, ([], []), MODULES[3][0]),
        ("", ([], []), ([], []), MODULES[4][0]),
        ("fetch_subdomains_response_valid.json", 2, ([], []), MODULES[4][0]),
        ("fetch_subdomains_response_valid.json", -2, ([], []), MODULES[4][0]),
        ("", ([], []), ([], []), MODULES[5][0]),
        ("fetch_malware_logs_response_valid.json", 2, ([], []), MODULES[5][0]),
        ("fetch_malware_logs_response_valid.json", -2, ([], []), MODULES[5][0]),
    ],
)
def test_deduplicate_and_create_incidents(
    input_file_name, mock_input, mock_asserts, mock_module, mock_last_fetch_ids, capfd, caplog
):
    """
    Given:
        - List of fetched incidents.
        - List of last run's calculated hashes.
    When:
        - deduplicate_and_create_incidents is called.
    Then:
        - Calculate hashes for the passed list of incidents.
        - Create a new list of XSOAR-ready incidents only for incidents not found in the last run.
    """
    from CyberBlindspot import deduplicate_and_create_incidents

    with capfd.disabled():
        caplog.set_level(logging.DEBUG)
        if input_file_name:
            mock_input = [
                load_mock_response(input_file_name),
                mock_last_fetch_ids(mock_module)[mock_input:] if mock_input != -2 else [],
            ]
        new_hashes, unique_incidents = deduplicate_and_create_incidents(mock_input[1], mock_input[0])
        assert new_hashes == mock_asserts[0]
        assert unique_incidents == mock_asserts[1]


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
    from CyberBlindspot import to_snake_case

    assert to_snake_case(mock_input) == mock_assert


@pytest.mark.parametrize(
    "mock_response",
    [
        {"hits": [{"testkey": "testval"}], "statusCode": 200},
        {"statusCode": 200},
        {"errors": "Invalid API-KEY", "statusCode": 400},
        {"statusCode": 500},
    ],
)
def test_test_configuration(mock_response, mock_client, mocker):
    """
    Given:
        - CyberBlindspot Client.
    When:
        - test_configuration is called.
    Then:
        - The returned value must be a list.
    """

    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)

    if mock_response.get("statusCode") > 200:
        # Expecting an exception
        with pytest.raises(DemistoException) as e:
            incidents = mock_client.test_configuration({})
            if type(e) is DemistoException:
                assert e == mock_response.get("errors", "request was not successful")
    else:
        incidents = mock_client.test_configuration({})
        assert type(incidents) is list


""" COMMAND TESTS """


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
        (
            {"mirror_direction": "None", "api_key": {"password": "test"}, "module_to_use": ""},
            DemistoException('Invalid "Module" Value'),
        ),
    ],
)
def test_test_module(mock_params, mock_side_effect, mock_client, mocker):
    """
    Given:
        - CyberBlindspot Client.
        - Client arguments.
    When:
        - test-module is called.
    Then:
        - The key is checked against known valid keys.
        - If invalid, an exception is raised with a clear message.
    """
    from CyberBlindspot import test_module

    mocker.patch.object(
        mock_client,
        "test_configuration",
        side_effect=mock_side_effect,
    )
    with pytest.raises(DemistoException) as e:
        test_module(mock_client, mock_params)
    assert str(e.value) == mock_side_effect.message


@pytest.mark.parametrize(
    "mock_module,expected_mappings",
    [
        (
            MODULES[0][0],
            {
                "CyberBlindspot Incident": {
                    "id": "Unique ID for the incident record",
                    "subject": "Asset or title of incident",
                    "severity": "The severity of the incident",
                    "type": "Incident type",
                    "class": "Subject class",
                    "status": "Incident's current state of affairs",
                    "coa": "The possible course of action",
                    "remarks": "Remarks about the incident",
                    "first_seen": "The creation date of the incident",
                    "last_seen": "The date the incident got last updated",
                    "screenshots": "The screenshot evidence if available",
                    "brand": "The organization the incident belongs to",
                    "timestamp": "The timestamp of when the record was created",
                    "external_link": "External link to the remote platform",
                }
            },
        ),
        (
            MODULES[1][0],
            {
                "CyberBlindspot Incident": {
                    "first_seen": "The creation date of the incident",
                    "last_seen": "The date the incident got last updated",
                    "timestamp": "The timestamp of when the record was created",
                    "brand": "The organization the incident belongs to",
                    "status": "Incident's current state of affairs",
                    "severity": "The severity of the incident",
                    "remarks": "Remarks about the incident",
                    "type": "Incident type",
                    "id": "Unique ID for the incident record",
                    "external_link": "External link to the remote platform",
                    "card_number": "The compromised card's number.",
                    "cvv": "The compromised card's Card Verification Value (CVV).",
                    "expiry_month": "The compromised card's expiration month.",
                    "expiry_year": "The compromised card's expiration year.",
                }
            },
        ),
        (
            MODULES[2][0],
            {
                "CyberBlindspot Incident": {
                    "first_seen": "The creation date of the incident",
                    "last_seen": "The date the incident got last updated",
                    "timestamp": "The timestamp of when the record was created",
                    "brand": "The organization the incident belongs to",
                    "status": "Incident's current state of affairs",
                    "severity": "The severity of the incident",
                    "remarks": "Remarks about the incident",
                    "type": "Incident type",
                    "id": "Unique ID for the incident record",
                    "external_link": "External link to the remote platform",
                    "breach_source": "The source of breached data.",
                    "domain": "The domain related to the breached data.",
                    "email": "Email found in the breached data.",
                    "username": "Username found in the breached data.",
                    "executive_name": "Executive member's name related to the breached data.",
                    "password": "Password found in the breached data.",
                }
            },
        ),
        (
            MODULES[3][0],
            {
                "CyberBlindspot Incident": {
                    "first_seen": "The creation date of the incident",
                    "last_seen": "The date the incident got last updated",
                    "timestamp": "The timestamp of when the record was created",
                    "brand": "The organization the incident belongs to",
                    "status": "Incident's current state of affairs",
                    "severity": "The severity of the incident",
                    "remarks": "Remarks about the incident",
                    "type": "Incident type",
                    "id": "Unique ID for the incident record",
                    "external_link": "External link to the remote platform",
                    "confirmation_time": "The time of infringement confirmation.",
                    "risks": "The potential difficulties carried by the infringement.",
                    "incident_status": "The status of the infringement incident.",
                }
            },
        ),
        (
            MODULES[4][0],
            {
                "CyberBlindspot Incident": {
                    "first_seen": "The creation date of the incident",
                    "last_seen": "The date the incident got last updated",
                    "timestamp": "The timestamp of when the record was created",
                    "brand": "The organization the incident belongs to",
                    "status": "Incident's current state of affairs",
                    "severity": "The severity of the incident",
                    "remarks": "Remarks about the incident",
                    "type": "Incident type",
                    "id": "Unique ID for the incident record",
                    "external_link": "External link to the remote platform",
                    "confirmation_time": "The time of infringement confirmation.",
                    "risks": "The potential difficulties carried by the infringement.",
                    "incident_status": "The status of the infringement incident.",
                }
            },
        ),
        (
            MODULES[5][0],
            {
                "CyberBlindspot Incident": {
                    "first_seen": "The creation date of the incident",
                    "last_seen": "The date the incident got last updated",
                    "timestamp": "The timestamp of when the record was created",
                    "brand": "The organization the incident belongs to",
                    "status": "Incident's current state of affairs",
                    "severity": "The severity of the incident",
                    "remarks": "Remarks about the incident",
                    "type": "Incident type",
                    "id": "Unique ID for the incident record",
                    "external_link": "External link to the remote platform",
                    "masked_password": "The masked password related to the breached data.",
                    "password": "Password found in the breached data or compromised account.",
                    "software": "The software related to the breached data.",
                    "user": "The user related to the breached data.",
                    "user_domain": "The domain of the user related to the breached data.",
                    "website": "The website related to the breached data.",
                    "sources": "The sources related to the breached data.",
                    "source_uri": "The source URI related to the breached data.",
                    "domain": "The domain related to the breached data or compromised device.",
                    "hostname": "The hostname related to the breached data.",
                    "stealer_family": "The family of the malware.",
                    "compromise_details": "The details of the compromise.",
                    "date_compromised": "The date the malware was compromised.",
                    "computer_name": "The name of the computer that was compromised.",
                    "operating_system": "The operating system of the computer that was compromised.",
                    "malware_path": "The path of the malware.",
                    "url_path": "The URL path of the malware.",
                }
            },
        ),
    ],
)
def test_get_mapping_fields_command(mock_module, expected_mappings):
    """
    Given: Nothing.
    When:
        - User schema in the application contains the fields 'field1' and 'field2'.
        - Calling function get_mapping_fields_command.
    Then:
        - Ensure a GetMappingFieldsResponse object that contains the application fields is returned.
    """
    from CyberBlindspot import get_mapping_fields_command, Instance

    mock_instance = Instance(module=mock_module)

    with patch("CyberBlindspot.INSTANCE", new=mock_instance):
        mappings = get_mapping_fields_command()
        assert mappings.extract_mapping() == expected_mappings


@pytest.mark.parametrize(
    "response_files_names,mock_params,mock_module",
    [
        (
            ["fetch_incidents_response_valid.json", "fetch_incidents_response_invalid.json"],
            {
                "max_hits": "3",
            },
            "incidents",
        ),
    ],
)
def test_fetch_incidents_command(response_files_names, mock_params, mock_module, mock_last_fetch_ids, mock_client, mocker):
    """
    Given:
        - CyberBlindspot Client
        - Client arguments
        # Case 1:
            - User has provided valid pagination params.
            - First run with no new incidents yet, so an empty list will be returned.
        # Case 2:
            - User has provided valid pagination params.
            - Not first run with 1 duplicate incidents, so 3 hashes are calculated and 2 unique incidents are returned.
        # Case 3:
            - User has provided valid pagination params.
            - Not first run with no duplicate incidents, so 3 hashes are calculated and 3 unique incidents are returned.
        # Case 4:
            - User has provided invalid pagination params.
    When:
        - fetch-incidents command is called.
    Then:
        - Ensure response has correct number of records
        # Case 1:
            - An empty list will be returned.
        # Case 2:
            - 3 hashes are calculated and 2 unique incidents are returned.
        # Case 3:
            - 3 hashes are calculated and 3 unique incidents are returned.
        # Case 4:
            - DemistoException is raised.
    """
    from CyberBlindspot import fetch_incidents

    # First run with no incidents returned
    mocker.patch.object(mock_client, "fetch_incidents", return_value=[])
    next_run, incidents = fetch_incidents(mock_client, [], mock_params, {})
    assert next_run == {}
    assert incidents == []

    # Not first run with 1 duplicate in the returned incidents
    mocker.patch.object(mock_client, "fetch_incidents", return_value=load_mock_response(response_files_names[0]))
    next_run, incidents = fetch_incidents(mock_client, mock_last_fetch_ids(mock_module)[:1], mock_params, {"not_empty": ""})
    assert len(incidents) == 2
    assert len(next_run.get("last_fetch_ids", [])) == 3
    if incidents and incidents[0].get("xsoar_mirroring", {}).get("mirror_direction"):
        assert incidents[0].get("xsoar_mirroring", {}).get("mirror_id") == "COMX123456654321"
    assert incidents[0].get("name") == "New leaked_credential with severity High found"
    assert incidents[0].get("CustomFields", {}).get("cbs_type") == "Leaked Credential"

    # Not first run with no duplicates in the returned incidents

    mocker.patch.object(mock_client, "fetch_incidents", return_value=load_mock_response(response_files_names[0]))
    next_run, incidents = fetch_incidents(mock_client, [], mock_params, {"not_empty": ""})
    assert len(incidents) == 3
    assert next_run.get("last_fetch_ids") == mock_last_fetch_ids(mock_module)
    if incidents and incidents[0].get("xsoar_mirroring", {}).get("mirror_direction"):
        assert incidents[0].get("xsoar_mirroring", {}).get("mirror_id") != ""
    assert incidents[1].get("name") == "New leaked_credential with severity High found"
    assert incidents[1].get("CustomFields", {}).get("cbs_type") == "Leaked Credential"

    # Run with bad params

    fetch_exception = DemistoException("Error received: Please contact Threat Manager Team")
    mocker.patch.object(mock_client, "fetch_incidents", side_effect=fetch_exception)
    bad_mock_params = {**mock_params, "date_from": "abcdefg123"}
    with pytest.raises(DemistoException) as e:
        fetch_incidents(mock_client, [], bad_mock_params, {"not_empty": ""})
    assert str(e.value) == "Error received: Please contact Threat Manager Team"


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts_file,mock_module,mock_module_prefix",
    [
        (
            "fetch_incidents_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "incident_list_cmd_result_valid.json",
            MODULES[0][0],
            MODULES[0][1],
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            MODULES[0][0],
            MODULES[0][1],
        ),
        (
            "fetch_cards_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "card_list_cmd_result_valid.json",
            MODULES[1][0],
            MODULES[1][1],
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            MODULES[1][0],
            MODULES[1][1],
        ),
        (
            "fetch_creds_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "cred_list_cmd_result_valid.json",
            MODULES[2][0],
            MODULES[2][1],
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            MODULES[2][0],
            MODULES[2][1],
        ),
        (
            "fetch_domains_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "domain_list_cmd_result_valid.json",
            MODULES[3][0],
            MODULES[3][1],
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            MODULES[3][0],
            MODULES[3][1],
        ),
        (
            "fetch_subdomains_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "subdomain_list_cmd_result_valid.json",
            MODULES[4][0],
            MODULES[4][1],
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            MODULES[4][0],
            MODULES[4][1],
        ),
        (
            "fetch_malware_logs_response_valid.json",
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            "malware_logs_list_cmd_result_valid.json",
            MODULES[5][0],
            MODULES[5][1],
        ),
        (
            False,
            {"maxHits": "3", "order": "asc", "dateFrom": "23-10-2023 07:00", "dateTo": "23-10-2023 23:00"},
            False,
            MODULES[5][0],
            MODULES[5][1],
        ),
    ],
)
def test_ctm360_cbs_incident_list_command(
    response_file_name, mock_args, mock_asserts_file, mock_module, mock_module_prefix, mock_client, mocker, capfd, caplog
):
    """
    Given:
        - CyberBlindspot Client.
        - Client arguments.
    When:
        - fetch_incidents is called.
    Then:
        - Fetch the list of incidents from the remote server.
    """
    from CyberBlindspot import ctm360_cbs_list_command, Instance

    patched_response = load_mock_response(response_file_name) if response_file_name else []
    mocker.patch.object(mock_client, "fetch_incidents", return_value=patched_response)
    mock_instance = Instance(module=mock_module)
    with capfd.disabled():
        caplog.set_level(logging.DEBUG)
        with patch("CyberBlindspot.INSTANCE", new=mock_instance):
            cmd_results = ctm360_cbs_list_command(mock_client, mock_args)
            expected_results = load_mock_response(mock_asserts_file) if mock_asserts_file else []
            cmd_results = cmd_results.to_context().get("Contents")
            if cmd_results and expected_results:
                cmd_results = [{k: v for k, v in item.items() if k != "rawJson"} for item in cmd_results]
                expected_results = [{k: v for k, v in item.items() if k != "rawJson"} for item in expected_results]
            logging.debug(cmd_results)
            logging.debug(expected_results)
            assert cmd_results == expected_results


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts,mock_module",
    [
        (
            "incident_details_response_valid.json",
            {"ticketId": "COMX584598490058"},
            {
                "id": "COMX584598490058",
                "subject": "1 customer credentials compromised (6vd6e97)",
                "severity": "High",
                "type": "Leaked Credential",
                "class": "Link",
                "status": "Member Feedback",
                "coa": "Member Side Action",
                "remarks": "New leaked_credential with severity High found",
                "external_link": "https://platform.ctm360.com/cbs/threat_manager/incidents/COMX584598490058",
                "first_seen": "27-12-2023 05:42:18 AM",
                "last_seen": "27-12-2023 05:42:18 AM",
                "screenshots": [{"filename": "screenshot1.png", "filepath": "29207a3d7f2ce17cd6309d1fc0f5ad7e"}],
                "brand": "Mock Brand",
                "timestamp": "1703655740964",
            },
            MODULES[0],
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            {},
            MODULES[0],
        ),
        (
            "cred_details_response_valid.json",
            {"ticketId": "BC-0D7FDA777"},
            {
                "first_seen": "24-11-2024 09:23:11 PM",
                "last_seen": "24-11-2024 09:23:11 PM",
                "breach_source": ["Pure Incubation"],
                "domain": "example.local",
                "type": "",
                "remarks": "Pure Incubation Breach - yash.abc@example.local",
                "external_link": "https://platform.ctm360.com/cbs/leaks/breached_credentials?filters=[]&searchQuery=BC-0D7FDA777&selectedSearchField=leak_id",
                "email": "yash.abc@example.local",
                "username": "yser",
                "password": "ypass123!",
                "brand": "RiskAssess Demo",
                "id": "BC-0D7FDA777",
                "status": "new",
            },
            MODULES[1],
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            {},
            MODULES[1],
        ),
        (
            "card_details_response_valid.json",
            {"ticketId": "LC-A1E4B2F49"},
            {
                "first_seen": "25-12-2024 09:16:59 AM",
                "last_seen": "25-12-2024 09:16:59 AM",
                "card_number": "0123456789012345",
                "cvv": "123",
                "expiry_month": 4,
                "expiry_year": 2026,
                "brand": "Demo Bank",
                "id": "LC-A1E4B2F49",
                "external_link": "https://platform.ctm360.com/cbs/leaks/compromised_cards?filters=[]&searchQuery=LC-A1E4B2F49&selectedSearchField=leak_id",
                "status": "new",
                "timestamp": "1735107419000",
                "severity": "Low",
                "type": "Compromised Cards",
                "remarks": "Compromised Card 0123456789012345",
            },
            MODULES[2],
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            {},
            MODULES[2],
        ),
        (
            "domain_details_response_valid.json",
            {"ticketId": "RD-0285ED4LA"},
            {
                "first_seen": "29-10-2024 09:58:25 PM",
                "last_seen": "31-12-2024 03:51:58 AM",
                "id": "RD-0285ED4LA",
                "subject": "trybackme.xyz",
                "severity": "High",
                "type": "Domain Infringement",
                "risks": ["Has A Record", "Has MX Record", "Newly registered when detected", "Has NS Record", "Has DNS Record"],
                "external_link": "https://platform.ctm360.com/cbs/domains/registered/uYa30ZYB_inRxraHlAO4",
                "status": "monitoring",
                "incident_status": "member_feedback",
                "brand": "RiskAssess Demo",
                "timestamp": "1730239105000",
            },
            MODULES[3],
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            {},
            MODULES[3],
        ),
        (
            "subdomain_details_response_valid.json",
            {"ticketId": "RD-C4G04E22B"},
            {
                "first_seen": "26-10-2024 01:06:43 AM",
                "last_seen": "26-10-2024 01:09:07 AM",
                "id": "RD-C4G04E22B",
                "subject": "sse.host-master.trybackme.wo",
                "severity": "High",
                "type": "Subdomain Infringement",
                "risks": ["SSL issued on domain", "Has DNS Record", "Has NS Record"],
                "external_link": "https://platform.ctm360.com/cbs/domains/registered/uYa30ZYB_inRxraHlAO4",
                "status": "monitoring",
                "brand": "RiskAssess Demo",
                "timestamp": "1729904803311",
            },
            MODULES[4],
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            {},
            MODULES[4],
        ),
        (
            "malware_logs_details_response_valid.json",
            {"ticketId": "ML-919AE2387"},
            {
                "brand": "RiskAssess Demo",
                "compromise_details": [
                    {
                        "antiviruses": ["Windows Defender"],
                        "clientAt": ["trybackme.io"],
                        "computer_name": "DESKTOP-KPLOECB (DELL)",
                        "date_compromised": "2025-05-23T03:48:49.000Z",
                        "date_uploaded": "2025-05-23T08:51:12.080Z",
                        "employeeAt": ["sit.edu.lb"],
                        "employee_session_cookies": [
                            {
                                "domain": "trybackme.io",
                                "expiry": "2025-07-25T23:04:06.000Z",
                                "name": "SNID",
                                "url": "trybackme.io",
                                "value": "AILqd3Wz3s_6iqTeieieLAII1KgBAAQOBFY3RDT6ncttjkiZ4SJgKF00Gq3kHD07-D95EwhPEoflTkPv0PFXiUM"
                                "adqwSnwNE4e",
                            }
                        ],
                        "installed_software": None,
                        "ip": "154.134.143.229",
                        "malware_path": " C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\maxerste.exe",
                        "operating_system": "Windows 10 Professionnel (10.0.19045) x64",
                        "stealer": "[MA]154.134.143.229",
                        "stealer_family": "Lumma",
                        "type": "client",
                    }
                ],
                "computer_name": "DESKTOP-KPLOECB (DELL)",
                "date_compromised": "23-05-2025 03:48:49 AM",
                "domain": "trybackme.io",
                "external_link": "https://platform.ctm360.com/cbs/leaks/malware_logs/user_credentials_web_app?filters=[]&searchQuery=ML-919AE2387&selectedSearchField=leak_id",
                "first_seen": "23-05-2025 09:35:21 PM",
                "hostname": "trybackme.io",
                "id": "ML-919AE2387",
                "last_seen": "23-05-2025 09:35:21 PM",
                "malware_path": " C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\maxerste.exe",
                "masked_password": "***pezz753",
                "operating_system": "Windows 10 Professionnel (10.0.19045) x64",
                "password": "Suppezz753",
                "remarks": "ML-919AE2387",
                "source_uri": ["leak/malware_logs?path=eaf75fb8f9431fe403b9"],
                "sources": ["Chr log files"],
                "status": "new",
                "stealer_family": ["Lumma"],
                "timestamp": "1748036121189",
                "type": "User Credentials Web App",
                "user": "otronerfinn",
                "user_domain": "",
                "website": "trybackme.io",
            },
            MODULES[5],
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            {},
            MODULES[5],
        ),
    ],
)
def test_ctm360_cbs_incident_details_command(response_file_name, mock_args, mock_asserts, mock_module, mock_client, mocker):
    """
    Given:
        - Ticket ID of incident.
    When:
        - ctm360-cbs-incident-details command is called.
    Then:
        - Ensure result is as expected.
    """
    from CyberBlindspot import ctm360_cbs_details_command, Instance

    mock_instance = Instance(module=mock_module)

    with patch("CyberBlindspot.INSTANCE", new=mock_instance):
        patched_response = load_mock_response(response_file_name) if response_file_name else {}
        mocker.patch.object(mock_client, "fetch_incident", return_value=patched_response)
        cmd_results = ctm360_cbs_details_command(mock_client, mock_args)
        assert cmd_results.to_context().get("Contents") == mock_asserts


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts",
    [
        (
            "close_incident_response_valid.json",
            {"ticketId": "COMX165756654321"},
            "Incident closed successfully",
        ),
        (
            "close_incident_response_invalid.json",
            {"ticketId": "COMX165756654321"},
            "Incident should be under Member Feedback or Monitoring to Close",
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            None,
        ),
    ],
)
def test_ctm360_cbs_incident_close_command(response_file_name, mock_args, mock_asserts, mock_client, mocker):
    """
    Given:
        - Ticket ID of incident.
    When:
        - ctm360-cbs-incident-close command is called.
    Then:
        - Ensure result is as expected.
    """
    from CyberBlindspot import ctm360_cbs_incident_close_command

    mock_response = load_mock_response(response_file_name) if response_file_name else {}
    mocker.patch.object(mock_client, "close_incident", return_value=mock_response)
    cmd_results = ctm360_cbs_incident_close_command(mock_client, mock_args)
    assert cmd_results.to_context().get("HumanReadable") == mock_asserts


@pytest.mark.parametrize(
    "response_file_name,mock_args,mock_asserts",
    [
        (
            "request_takedown_response_valid.json",
            {"ticketId": "COMX165756654321"},
            "Takedown request executed successfully",
        ),
        (
            "request_takedown_response_invalid.json",
            {"ticketId": "COMX165756654321"},
            "Incident should be under Member Feedback for Takedown",
        ),
        (
            False,
            {"ticketId": "COMX165756654321"},
            None,
        ),
    ],
)
def test_ctm360_cbs_incident_request_takedown_command(response_file_name, mock_args, mock_asserts, mock_client, mocker):
    """
    Given:
        - Ticket ID of incident.
    When:
        - ctm360-cbs-incident-request-takedown command is called.
    Then:
        - Ensure result is as expected.
    """
    from CyberBlindspot import ctm360_cbs_incident_request_takedown_command

    mock_response = load_mock_response(response_file_name) if response_file_name else {}
    mocker.patch.object(mock_client, "request_takedown", return_value=mock_response)
    cmd_results = ctm360_cbs_incident_request_takedown_command(mock_client, mock_args)
    assert cmd_results.to_context().get("HumanReadable") == mock_asserts


@pytest.mark.parametrize(
    "mock_module,mock_response,mock_entry,mock_status",
    [
        (MODULES[0][0], "incident_details_response_valid.json", "", ""),
        (MODULES[0][0], "incident_details_response_valid.json", STATUS_ENTRIES["wip"], "wip"),
        (MODULES[0][0], "incident_details_response_valid.json", STATUS_ENTRIES["closed"], "closed"),
        (MODULES[0][0], "incident_details_response_valid.json", STATUS_ENTRIES["resolved"], "resolved"),
        (MODULES[0][0], "incident_details_response_valid.json", STATUS_ENTRIES["disregarded"], "disregarded"),
        (MODULES[0][0], "incident_details_response_valid.json", STATUS_ENTRIES["unconfirmed"], "unconfirmed"),
        (MODULES[1][0], "card_details_response_valid.json", "", ""),
        (MODULES[1][0], "card_details_response_valid.json", STATUS_ENTRIES["wip"], "wip"),
        (MODULES[1][0], "card_details_response_valid.json", STATUS_ENTRIES["closed"], "closed"),
        (MODULES[1][0], "card_details_response_valid.json", STATUS_ENTRIES["resolved"], "resolved"),
        (MODULES[1][0], "card_details_response_valid.json", STATUS_ENTRIES["disregarded"], "disregarded"),
        (MODULES[1][0], "card_details_response_valid.json", STATUS_ENTRIES["unconfirmed"], "unconfirmed"),
        (MODULES[2][0], "cred_details_response_valid.json", "", ""),
        (MODULES[2][0], "cred_details_response_valid.json", STATUS_ENTRIES["wip"], "wip"),
        (MODULES[2][0], "cred_details_response_valid.json", STATUS_ENTRIES["closed"], "closed"),
        (MODULES[2][0], "cred_details_response_valid.json", STATUS_ENTRIES["resolved"], "resolved"),
        (MODULES[2][0], "cred_details_response_valid.json", STATUS_ENTRIES["disregarded"], "disregarded"),
        (MODULES[2][0], "cred_details_response_valid.json", STATUS_ENTRIES["unconfirmed"], "unconfirmed"),
        (MODULES[3][0], "domain_details_response_valid.json", "", ""),
        (MODULES[3][0], "domain_details_response_valid.json", STATUS_ENTRIES["wip"], "wip"),
        (MODULES[3][0], "domain_details_response_valid.json", STATUS_ENTRIES["closed"], "closed"),
        (MODULES[3][0], "domain_details_response_valid.json", STATUS_ENTRIES["resolved"], "resolved"),
        (MODULES[3][0], "domain_details_response_valid.json", STATUS_ENTRIES["disregarded"], "disregarded"),
        (MODULES[3][0], "domain_details_response_valid.json", STATUS_ENTRIES["unconfirmed"], "unconfirmed"),
        (MODULES[4][0], "subdomain_details_response_valid.json", "", ""),
        (MODULES[4][0], "subdomain_details_response_valid.json", STATUS_ENTRIES["wip"], "wip"),
        (MODULES[4][0], "subdomain_details_response_valid.json", STATUS_ENTRIES["closed"], "closed"),
        (MODULES[4][0], "subdomain_details_response_valid.json", STATUS_ENTRIES["resolved"], "resolved"),
        (MODULES[4][0], "subdomain_details_response_valid.json", STATUS_ENTRIES["disregarded"], "disregarded"),
        (MODULES[4][0], "subdomain_details_response_valid.json", STATUS_ENTRIES["unconfirmed"], "unconfirmed"),
        (MODULES[5][0], "malware_logs_details_response_valid.json", "", ""),
        (MODULES[5][0], "malware_logs_details_response_valid.json", STATUS_ENTRIES["wip"], "wip"),
        (MODULES[5][0], "malware_logs_details_response_valid.json", STATUS_ENTRIES["closed"], "closed"),
        (MODULES[5][0], "malware_logs_details_response_valid.json", STATUS_ENTRIES["resolved"], "resolved"),
        (MODULES[5][0], "malware_logs_details_response_valid.json", STATUS_ENTRIES["disregarded"], "disregarded"),
        (MODULES[5][0], "malware_logs_details_response_valid.json", STATUS_ENTRIES["unconfirmed"], "unconfirmed"),
    ],
)
def test_get_remote_data(mock_module, mock_response, mock_entry, mock_status, mock_client, mocker):
    """
    Given:
        - CyberBlindspot Client.
        - Client arguments.
    When:
        -  get-remote-data command is called.
    Then:
        - Ensure result is as expected.
    """
    from copy import deepcopy
    from CyberBlindspot import get_remote_data_command, map_and_create_incident, Instance

    mock_args = {"id": "COMX165756654321", "lastUpdate": "2024-01-02T13:30:21.172707565Z"}
    mock_result = load_mock_response(mock_response)
    if type(mock_result) is dict:
        mock_result["status"] = mock_status

    if type(mock_result) is dict:
        mock_result2 = deepcopy(mock_result)
    mocker.patch.object(mock_client, "fetch_incident", return_value=mock_result)

    mock_instance = Instance(module=mock_module)
    with patch("CyberBlindspot.INSTANCE", new=mock_instance):
        result = get_remote_data_command(mock_client, mock_args)
        mock_result = map_and_create_incident(mock_result2) if mock_status else []
        if isinstance(mock_result, dict):
            del mock_result["rawJson"]
        if isinstance(result.mirrored_object, dict):
            del result.mirrored_object["rawJson"]
        assert result.mirrored_object == mock_result
        if mock_status == "":
            assert result.entries == []
        elif mock_status == "closed":
            assert result.entries[0].get("Contents", {}).get("closeReason", "") == mock_entry
        else:
            assert result.entries[0].get("Contents", "") == mock_entry


@pytest.mark.parametrize(
    "mock_input_file",
    [
        ("fetch_incidents_response_valid.json"),
    ],
)
def test_get_modified_remote_data(mock_input_file, mock_client, mocker):
    """
    Given:
        - CyberBlindspot Client.
        - Client arguments.
    When:
        - get-modified-remote-data command is called
    Then:
        - Ensure result is as expected
    """
    from CyberBlindspot import get_modified_remote_data_command

    mock_args = {
        "date_field": "last_seen",
        "order": "asc",
        "date_from": "1704183134",
        "max_hits": 50,
        "lastUpdate": "2024-01-02T13:30:21.172707565Z",
    }
    mock_result = load_mock_response(mock_input_file)
    mocker.patch.object(mock_client, "fetch_incidents", return_value=mock_result)
    result = get_modified_remote_data_command(mock_client, mock_args)
    mock_assert = [item["id"] for item in mock_result]
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
            "close_incident_response_valid.json",
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
        - CyberBlindspot Client.
        - Client arguments.
    When:
        - update-remote-system command is called.
    Then:
        - Ensure result is as expected.
    """
    from CyberBlindspot import update_remote_system_command

    with caplog.at_level(logging.INFO):
        if mock_response_file:
            mocker.patch.object(mock_client, "close_incident", return_value=load_mock_response(mock_response_file))
        result = update_remote_system_command(mock_client, mock_args)
        assert result == mock_args["remoteId"]
        assert mock_log_asserts in caplog.text


@pytest.mark.parametrize(
    "mock_response,mock_params,expected_result",
    [
        (
            {"results": [{"filename": "screenshot1.png", "filedata": {"data": b"test_data"}}]},
            {"ticket_id": "COMX123456"},
            [{"filename": "screenshot1.png", "filedata": {"data": b"test_data"}}],
        ),
        ({"results": []}, {"ticket_id": "COMX123456"}, []),
        ({"results": None}, {"ticket_id": "COMX123456"}, []),
    ],
)
def test_get_screenshot_files(mock_response, mock_params, expected_result, mock_client, mocker):
    """
    Given:
        - CyberBlindspot Client
        - Parameters for the screenshot request
        - Mock API response
    When:
        - get_screenshot_files is called
    Then:
        - Ensure the correct response is returned
    """
    mocker.patch.object(mock_client, "_http_request", return_value=mock_response)
    result = mock_client.get_screenshot_files(mock_params)
    assert result == expected_result


@pytest.mark.parametrize(
    "mock_conf,mock_response,mock_args,existing_files,api_error,expected_result",
    [
        # Test when screenshot retrieval is disabled
        (
            False,
            {"results": [{"filename": "screenshot1.png", "filedata": {"data": b"test_data1"}}]},
            {"ticket_id": "COMX123456"},
            [],
            None,
            CommandResults(readable_output="Screenshot Evidence Retrieval is Disabled in Instance Configuration."),
        ),
        # Test with single screenshot
        (
            True,
            {"results": [{"filename": "screenshot1.png", "filedata": {"data": b"test_data1"}}]},
            {"ticket_id": "COMX123456"},
            [],
            None,
            [{"File": "screenshot1.png", "FileID": "mock_file_id", "Type": EntryType.IMAGE}],
        ),
        # Test with multiple screenshots
        (
            True,
            {
                "results": [
                    {"filename": "screenshot1.png", "filedata": {"data": b"test_data1"}},
                    {"filename": "screenshot2.png", "filedata": {"data": b"test_data2"}},
                ]
            },
            {"ticket_id": "COMX123456"},
            [],
            None,
            [
                {"File": "screenshot1.png", "FileID": "mock_file_id", "Type": EntryType.IMAGE},
                {"File": "screenshot2.png", "FileID": "mock_file_id", "Type": EntryType.IMAGE},
            ],
        ),
        # Test with no results
        (
            True,
            {"results": []},
            {"ticket_id": "COMX123456"},
            [],
            None,
            CommandResults(readable_output="No new screenshots to fetch"),
        ),
        # Test with filtered files (no files to fetch after filtering)
        (
            True,
            {"results": []},
            {"files": [{"filename": "screenshot1.png", "filepath": "/path/to/file"}]},
            [],
            None,
            CommandResults(readable_output="No new screenshots to fetch"),
        ),
        # Test with empty files list
        (
            True,
            {"results": []},
            {"ticket_id": "COMX123456", "files": []},
            [],
            None,
            CommandResults(readable_output="No new screenshots to fetch"),
        ),
        # Test with all files already existing in context
        (
            True,
            {"results": []},
            {"files": [{"filename": "existing.png", "filepath": "/path/to/file"}]},
            [{"Name": "existing.png"}],
            None,
            CommandResults(readable_output="All requested screenshots already exist in context"),
        ),
        # Test with invalid type in files list (should be filtered out)
        (
            True,
            {"results": [{"filename": "screenshot1.png", "filedata": {"data": b"test_data1"}}]},
            {"files": [{"filename": "screenshot1.png"}, "not_a_dict"]},
            [],
            None,
            [{"File": "screenshot1.png", "FileID": "mock_file_id", "Type": EntryType.IMAGE}],
        ),
        # Test with API error
        (
            True,
            {"results": []},
            {"ticket_id": "COMX123456"},
            [],
            Exception("API connection error"),
            CommandResults(readable_output="Failed to fetch screenshots from API: API connection error"),
        ),
        # Test with non-dictionary in results
        (
            True,
            {"results": ["not_a_dict", {"filename": "screenshot1.png", "filedata": {"data": b"test_data1"}}]},
            {"ticket_id": "COMX123456"},
            [],
            None,
            [{"File": "screenshot1.png", "FileID": "mock_file_id", "Type": EntryType.IMAGE}],
        ),
        # Test with non-list InfoFile
        (
            True,
            {"results": [{"filename": "screenshot1.png", "filedata": {"data": b"test_data1"}}]},
            {"ticket_id": "COMX123456"},
            {"Name": "other_file.png"},  # Not a list
            None,
            [{"File": "screenshot1.png", "FileID": "mock_file_id", "Type": EntryType.IMAGE}],
        ),
    ],
)
def test_ctm360_cbs_incident_retrieve_screenshots_command(
    mock_conf, mock_response, mock_args, existing_files, api_error, expected_result, mock_client, mocker, capfd
):
    """
    Given:
        - CyberBlindspot Client
        - Command arguments
        - Mock API response
        - Existing files in context
        - Optional API error to simulate
    When:
        - ctm360_cbs_incident_retrieve_screenshots_command is called
    Then:
        - Ensure the correct file results or command results are returned
        - Verify error handling works as expected
        - Verify critical logs are generated
    """
    from CyberBlindspot import ctm360_cbs_incident_retrieve_screenshots_command

    # Mock fileResult to avoid writing to disk
    def mock_file_result(filename, data, file_type=None):
        return {"File": filename, "FileID": "mock_file_id", "Type": file_type}

    # Create a mock for demisto context
    mock_context = mocker.MagicMock(return_value={"InfoFile": existing_files})

    # Mock log function but keep track of calls
    mock_log = mocker.patch("CyberBlindspot.log")

    # Patch everything with mocker
    mocker.patch("CyberBlindspot.demisto.context", mock_context)
    mocker.patch("CyberBlindspot.RETRIEVE_SCREENSHOTS", new=mock_conf)
    mocker.patch("CyberBlindspot.fileResult", side_effect=mock_file_result)
    mocker.patch("CommonServerPython.fileResult", side_effect=mock_file_result)

    # Configure get_screenshot_files based on whether we want to simulate an error
    if api_error:
        mocker.patch.object(mock_client, "get_screenshot_files", side_effect=api_error)
    else:
        mocker.patch.object(mock_client, "get_screenshot_files", return_value=mock_response.get("results", []))

    # Run the function with capfd disabled to prevent stdout issues
    with capfd.disabled():
        result = ctm360_cbs_incident_retrieve_screenshots_command(mock_client, mock_args)

    # Verify results
    if isinstance(result, list):
        assert len(result) == len(expected_result)
        for r, e in zip(result, expected_result):
            assert r["File"] == e["File"]
            assert r["Type"] == e["Type"]
    elif isinstance(result, CommandResults):
        assert isinstance(expected_result, CommandResults)
        assert result.readable_output == expected_result.readable_output

    # Verify critical logging behavior only
    if api_error:
        # For API errors, verify error is logged
        mock_log.assert_any_call("error", f"Error calling get_screenshot_files: {str(api_error)}")
    elif not mock_conf:
        # For disabled screenshots, verify info message
        mock_log.assert_any_call("info", "Screenshot Evidence Retrieval is Disabled in Instance Configuration.")
    elif result and isinstance(result, list):
        # For successful file retrieval, verify success message
        mock_log.assert_any_call("info", f"Added {len(result)} new screenshot(s) to context")
