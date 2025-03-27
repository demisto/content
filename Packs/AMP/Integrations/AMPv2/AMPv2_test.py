"""
Unit testing for CiscoAMP (Advanced Malware Protection)
"""
import json
import io
import os
from typing import Any
import pytest
from AMPv2 import Client
from CommonServerPython import DemistoException

API_KEY = "API_Key"
CLIENT_ID = "Client_ID"
SERVER_URL = "https://api.eu.amp.cisco.com"
BASE_URL = f"{SERVER_URL}/{Client.API_VERSION}"


def assert_output_has_no_links(outputs: list[dict]):
    """
    Check that there are no 'links' keys in the outputs.

    Args:
        outputs (List[Dict, str]): output to loop through.
    """
    for output in outputs:
        assert "links" not in output


def load_mock_response(file_name: str) -> str | io.TextIOWrapper:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    path = os.path.join("test_data", file_name)

    with open(path, encoding="utf-8") as mock_file:
        if os.path.splitext(file_name)[1] == ".json":
            return json.loads(mock_file.read())

        return mock_file


@pytest.fixture(autouse=True)
def mock_client() -> Client:
    """
    Establish a connection to the client with a URL and API key.

    Returns:
        Client: Connection to client.
    """
    from CommonServerPython import DBotScoreReliability

    return Client(
        server_url=SERVER_URL,
        api_key=API_KEY,
        client_id=CLIENT_ID,
        reliability=DBotScoreReliability.C,
    )


@pytest.mark.parametrize(
    "args, suffix, file, expected_readable_output, expected_output",
    [
        (
            {"limit": "34"},
            "",
            "computer_list_response.json",
            "### Results\n"
            "|Current Item Count|Index|Items Per Page|Total|\n"
            "|---|---|---|---|\n"
            "| metadata_results_current_item_count | metadata_results_index | metadata_results_current_item_count "
            "| metadata_results_total |\n"
            "### Computer Information\n"
            "|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|\n"
            "|---|---|---|---|---|---|\n"
            "| data[0]_hostname | data[0]_connector_guid | data[0]_operating_system (Build data[0]_os_version) "
            "| data[0]_external_ip | data[0]_group_guid | data[0]_policy_guid |\n"
            "| data[1]_hostname | data[1]_connector_guid | data[1]_operating_system (Build data[1]_os_version) "
            "| data[1]_external_ip | data[1]_group_guid | data[1]_policy_guid |\n"
            "| data[2]_hostname | data[2]_connector_guid | data[2]_operating_system (Build data[2]_os_version) "
            "| data[2]_external_ip | data[2]_group_guid | data[2]_policy_guid |\n"
            "| data[3]_hostname | data[3]_connector_guid | data[3]_operating_system (Build data[3]_os_version) "
            "| data[3]_external_ip | data[3]_group_guid | data[3]_policy_guid |\n"
            "| data[4]_hostname | data[4]_connector_guid | data[4]_operating_system (Build data[4]_os_version) "
            "| data[4]_external_ip | data[4]_group_guid | data[4]_policy_guid |\n"
            "| data[5]_hostname | data[5]_connector_guid | data[5]_operating_system (Build data[5]_os_version) "
            "| data[5]_external_ip | data[5]_group_guid | data[5]_policy_guid |\n"
            "| data[6]_hostname | data[6]_connector_guid | data[6]_operating_system (Build data[6]_os_version) "
            "| data[6]_external_ip | data[6]_group_guid | data[6]_policy_guid |\n"
            "| data[7]_hostname | data[7]_connector_guid | data[7]_operating_system (Build data[7]_os_version) "
            "| data[7]_external_ip | data[7]_group_guid | data[7]_policy_guid |\n"
            "| data[8]_hostname | data[8]_connector_guid | data[8]_operating_system (Build data[8]_os_version) "
            "| data[8]_external_ip | data[8]_group_guid | data[8]_policy_guid |\n"
            "| data[9]_hostname | data[9]_connector_guid | data[9]_operating_system (Build data[9]_os_version) "
            "| data[9]_external_ip | data[9]_group_guid | data[9]_policy_guid |\n"
            "| data[10]_hostname | data[10]_connector_guid | data[10]_operating_system (Build data[10]_os_version) "
            "| data[10]_external_ip | data[10]_group_guid | data[10]_policy_guid |\n"
            "| data[11]_hostname | data[11]_connector_guid | data[11]_operating_system (Build data[11]_os_version) "
            "| data[11]_external_ip | data[11]_group_guid | data[11]_policy_guid |\n"
            "| data[12]_hostname | data[12]_connector_guid | data[12]_operating_system (Build data[12]_os_version) "
            "| data[12]_external_ip | data[12]_group_guid | data[12]_policy_guid |\n"
            "| data[13]_hostname | data[13]_connector_guid | data[13]_operating_system (Build data[13]_os_version) "
            "| data[13]_external_ip | data[13]_group_guid | data[13]_policy_guid |\n"
            "| data[14]_hostname | data[14]_connector_guid | data[14]_operating_system (Build data[14]_os_version) "
            "| data[14]_external_ip | data[14]_group_guid | data[14]_policy_guid |\n"
            "| data[15]_hostname | data[15]_connector_guid | data[15]_operating_system (Build data[15]_os_version) "
            "| data[15]_external_ip | data[15]_group_guid | data[15]_policy_guid |\n"
            "| data[16]_hostname | data[16]_connector_guid | data[16]_operating_system (Build data[16]_os_version) "
            "| data[16]_external_ip | data[16]_group_guid | data[16]_policy_guid |\n"
            "| data[17]_hostname | data[17]_connector_guid | data[17]_operating_system (Build data[17]_os_version) "
            "| data[17]_external_ip | data[17]_group_guid | data[17]_policy_guid |\n"
            "| data[18]_hostname | data[18]_connector_guid | data[18]_operating_system (Build data[18]_os_version) "
            "| data[18]_external_ip | data[18]_group_guid | data[18]_policy_guid |\n"
            "| data[19]_hostname | data[19]_connector_guid | data[19]_operating_system (Build data[19]_os_version) "
            "| data[19]_external_ip | data[19]_group_guid | data[19]_policy_guid |\n"
            "| data[20]_hostname | data[20]_connector_guid | data[20]_operating_system (Build data[20]_os_version) "
            "| data[20]_external_ip | data[20]_group_guid | data[20]_policy_guid |\n"
            "| data[21]_hostname | data[21]_connector_guid | data[21]_operating_system (Build data[21]_os_version) "
            "| data[21]_external_ip | data[21]_group_guid | data[21]_policy_guid |\n"
            "| data[22]_hostname | data[22]_connector_guid | data[22]_operating_system (Build data[22]_os_version) "
            "| data[22]_external_ip | data[22]_group_guid | data[22]_policy_guid |\n"
            "| data[23]_hostname | data[23]_connector_guid | data[23]_operating_system (Build data[23]_os_version) "
            "| data[23]_external_ip | data[23]_group_guid | data[23]_policy_guid |\n"
            "| data[24]_hostname | data[24]_connector_guid | data[24]_operating_system (Build data[24]_os_version) "
            "| data[24]_external_ip | data[24]_group_guid | data[24]_policy_guid |\n"
            "| data[25]_hostname | data[25]_connector_guid | data[25]_operating_system (Build data[25]_os_version) "
            "| data[25]_external_ip | data[25]_group_guid | data[25]_policy_guid |\n"
            "| data[26]_hostname | data[26]_connector_guid | data[26]_operating_system (Build data[26]_os_version) "
            "| data[26]_external_ip | data[26]_group_guid | data[26]_policy_guid |\n"
            "| data[27]_hostname | data[27]_connector_guid | data[27]_operating_system (Build data[27]_os_version) "
            "| data[27]_external_ip | data[27]_group_guid | data[27]_policy_guid |\n"
            "| data[28]_hostname | data[28]_connector_guid | data[28]_operating_system (Build data[28]_os_version) "
            "| data[28]_external_ip | data[28]_group_guid | data[28]_policy_guid |\n"
            "| data[29]_hostname | data[29]_connector_guid | data[29]_operating_system (Build data[29]_os_version) "
            "| data[29]_external_ip | data[29]_group_guid | data[29]_policy_guid |\n"
            "| data[30]_hostname | data[30]_connector_guid | data[30]_operating_system (Build data[30]_os_version) "
            "| data[30]_external_ip | data[30]_group_guid | data[30]_policy_guid |\n"
            "| data[31]_hostname | data[31]_connector_guid | data[31]_operating_system (Build data[31]_os_version) "
            "| data[31]_external_ip | data[31]_group_guid | data[31]_policy_guid |\n"
            "| data[32]_hostname | data[32]_connector_guid | data[32]_operating_system (Build data[32]_os_version) "
            "| data[32]_external_ip | data[32]_group_guid | data[32]_policy_guid |\n"
            "| data[33]_hostname | data[33]_connector_guid | data[33]_operating_system (Build data[33]_os_version) "
            "| data[33]_external_ip | data[33]_group_guid | data[33]_policy_guid |\n",
            {
                "connector_guid": "data[33]_connector_guid",
                "hostname": "data[33]_hostname",
                "windows_processor_id": "data[33]_windows_processor_id",
                "active": "data[33]_active",
                "connector_version": "data[33]_connector_version",
                "operating_system": "data[33]_operating_system",
                "os_version": "data[33]_os_version",
                "internal_ips": ["data[33]_internal_ips_0"],
                "external_ip": "data[33]_external_ip",
                "group_guid": "data[33]_group_guid",
                "install_date": "data[33]_install_date",
                "is_compromised": "data[33]_is_compromised",
                "demo": "data[33]_demo",
                "windows_machine_guid": "data[33]_windows_machine_guid",
                "network_addresses": [
                    {
                        "mac": "data[33]_network_addresses[0]_mac",
                        "ip": "data[33]_network_addresses[0]_ip",
                    }
                ],
                "policy": {
                    "guid": "data[33]_policy_guid",
                    "name": "data[33]_policy_name",
                },
                "groups": [
                    {
                        "guid": "data[33]_groups[0]_guid",
                        "name": "data[33]_groups[0]_name",
                    }
                ],
                "last_seen": "data[33]_last_seen",
                "av_update_definitions": {
                    "status": "data[33]_av_update_definitions_status",
                    "detection_engine": "data[33]_av_update_definitions_detection_engine",
                    "version": "data[33]_av_update_definitions_version",
                    "updated_at": "data[33]_av_update_definitions_updated_at",
                },
                "faults": [],
                "isolation": {
                    "available": "data[33]_isolation_available",
                    "status": "data[33]_isolation_status",
                },
                "orbital": {"status": "data[33]_orbital_status"},
            },
        ),
        (
            {"connector_guid": "1"},
            "/1",
            "computer_get_response.json",
            "### Computer Information\n"
            "|Host Name|Connector GUID|Operating System|External IP|Group GUID|Policy GUID|\n"
            "|---|---|---|---|---|---|\n"
            "| data_hostname | data_connector_guid | data_operating_system (Build data_os_version) |"
            " data_external_ip | data_group_guid | data_policy_guid |\n",
            {
                "connector_guid": "data_connector_guid",
                "hostname": "data_hostname",
                "windows_processor_id": "data_windows_processor_id",
                "active": "data_active",
                "connector_version": "data_connector_version",
                "operating_system": "data_operating_system",
                "os_version": "data_os_version",
                "internal_ips": ["data_internal_ips_0"],
                "external_ip": "data_external_ip",
                "group_guid": "data_group_guid",
                "install_date": "data_install_date",
                "is_compromised": "data_is_compromised",
                "demo": "data_demo",
                "network_addresses": [
                    {
                        "mac": "data_network_addresses[0]_mac",
                        "ip": "data_network_addresses[0]_ip",
                    }
                ],
                "policy": {"guid": "data_policy_guid", "name": "data_policy_name"},
                "groups": [
                    {"guid": "data_groups[0]_guid", "name": "data_groups[0]_name"}
                ],
                "last_seen": "data_last_seen",
                "faults": [],
                "isolation": {
                    "available": "data_isolation_available",
                    "status": "data_isolation_status",
                },
                "orbital": {"status": "data_orbital_status"},
            },
        ),
    ],
)
def test_computer_list_command(
    requests_mock,
    mock_client,
    args,
    suffix,
    file,
    expected_readable_output,
    expected_output,
):
    """
    Scenario:
    -   Get a list of 34 computers.
    -   Get a single computer.
    Given:
    -   The user has entered a limit.
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure links don't exist.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/computers{suffix}", json=mock_response)

    from AMPv2 import computer_list_command

    responses = computer_list_command(mock_client, args)

    for response in responses[:-1]:
        assert response.outputs_prefix == "CiscoAMP.Computer"
        assert "links" not in response.outputs
        assert response.indicator.id == response.outputs["connector_guid"]
        assert (
            response.indicator.mac_address
            == response.outputs["network_addresses"][0]["mac"]
        )
        assert (
            response.indicator.status == "Online"
            if response.outputs["active"]
            else "Offline"
        )
        assert response.indicator.vendor == "CiscoAMP Response"

    assert response.outputs == expected_output
    assert responses[-1].readable_output == expected_readable_output


def test_computer_list_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Search for a specific computer and get a list of computers in a group.
    Given:
    -   The user has entered a connector_guid and a group_guid.
    When:
    -    cisco-amp-computer-list is called.
    Then:
    -   Ensure an exception has been raised.
    """
    args = {"connector_guid": "1", "group_guid": "2"}

    requests_mock.get(f'{BASE_URL}/computers/{args["connector_guid"]}')

    from AMPv2 import computer_list_command

    with pytest.raises(ValueError) as ve:
        computer_list_command(mock_client, args)

        assert (
            str(ve)
            == "connector_guid must be the only input, when fetching a specific computer."
        )


def test_computer_trajectory_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get a computer's trajectory with pagination.
    Given:
    -   The user has entered a connector_guid, page and page_size.
    When:
    -    cisco-amp-computer-trajectory-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure length of the events in context output is correct.
    -   Ensure connector_guid is in the events.
    -   Ensure pagination worked.
    """
    args = {"connector_guid": "1", "page": 2, "page_size": 2}

    mock_response = load_mock_response("computer_trajectory_response.json")
    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/trajectory', json=mock_response
    )

    from AMPv2 import computer_trajectory_list_command

    response = computer_trajectory_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerTrajectory"
    assert len(response.outputs) == args["page_size"]
    assert response.outputs == [
        {
            "timestamp": "data_events[2]_timestamp",
            "timestamp_nanoseconds": "data_events[2]_timestamp_nanoseconds",
            "date": "data_events[2]_date",
            "event_type": "data_events[2]_event_type",
            "group_guids": ["data_events[2]_group_guids_0"],
            "file": {
                "disposition": "data_events[2]_file_disposition",
                "file_name": "data_events[2]_file_file_name",
                "file_path": "data_events[2]_file_file_path",
                "file_type": "data_events[2]_file_file_type",
                "identity": {"sha256": "data_events[2]_file_identity_sha256"},
                "parent": {
                    "disposition": "data_events[2]_file_parent_disposition",
                    "identity": {
                        "sha256": "data_events[2]_file_parent_identity_sha256"
                    },
                },
            },
            "connector_guid": "data_computer_connector_guid",
        },
        {
            "timestamp": "data_events[3]_timestamp",
            "timestamp_nanoseconds": "data_events[3]_timestamp_nanoseconds",
            "date": "data_events[3]_date",
            "event_type": "data_events[3]_event_type",
            "group_guids": ["data_events[3]_group_guids_0"],
            "file": {
                "disposition": "data_events[3]_file_disposition",
                "file_name": "data_events[3]_file_file_name",
                "file_path": "data_events[3]_file_file_path",
                "file_type": "data_events[3]_file_file_type",
                "identity": {"sha256": "data_events[3]_file_identity_sha256"},
                "parent": {
                    "disposition": "data_events[3]_file_parent_disposition",
                    "identity": {
                        "sha256": "data_events[3]_file_parent_identity_sha256"
                    },
                },
            },
            "connector_guid": "data_computer_connector_guid",
        },
    ]
    assert_output_has_no_links(response.outputs)


def test_computer_trajectory_list_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get a computer's trajectory and filter it by a false query.
    Given:
    -   The user has entered a connector_guid and a query_string.
    When:
    -    cisco-amp-computer-trajectory-get is called.
    Then:
    -   Ensure an exception has been raised.
    """
    args = {"connector_guid": "1", "query_string": '"'}

    with pytest.raises(ValueError) as ve:
        from AMPv2 import computer_trajectory_list_command

        computer_trajectory_list_command(mock_client, args)

        assert str(ve) == "query_string must be: SHA-256/IPv4/URL"


def test_computer_user_activity_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get user activity on computers.
    Given:
    -   The user has entered a username.
    When:
    -    cisco-amp-computer-user-activity-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure isn't in the outputs.
    """
    mock_response = load_mock_response("computer_user_activity_response.json")
    requests_mock.get(f"{BASE_URL}/computers/user_activity", json=mock_response)

    args = {"username": "johndoe"}

    from AMPv2 import computer_user_activity_list_command

    response = computer_user_activity_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerUserActivity"
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)
        assert output == mock_output


def test_computer_user_trajectory_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get a computer's trajectory with pagination.
    Given:
    -   The user has entered a connector_guid, page and page_size.
    When:
    -    cisco-amp-computer-user-trajectory-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure length of the outputs is correct.
    -   Ensure connector_guid is in the outputs.
    """
    args = {"connector_guid": "1", "page": "1", "page_size": "1"}

    mock_response = load_mock_response("computer_user_trajectory_response.json")
    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/user_trajectory',
        json=mock_response,
    )

    from AMPv2 import computer_user_trajectory_list_command

    response = computer_user_trajectory_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerUserTrajectory"
    assert len(response.outputs) == 1
    assert response.outputs == [
        {
            "id": "data_events[0]_id",
            "timestamp": "data_events[0]_timestamp",
            "timestamp_nanoseconds": "data_events[0]_timestamp_nanoseconds",
            "date": "data_events[0]_date",
            "event_type": "data_events[0]_event_type",
            "event_type_id": "data_events[0]_event_type_id",
            "detection_id": "data_events[0]_detection_id",
            "group_guids": ["data_events[0]_group_guids_0"],
            "severity": "data_events[0]_severity",
            "file": {
                "disposition": "data_events[0]_file_disposition",
                "file_name": "data_events[0]_file_file_name",
                "file_path": "data_events[0]_file_file_path",
                "identity": {
                    "sha256": "data_events[0]_file_identity_sha256",
                    "sha1": "data_events[0]_file_identity_sha1",
                    "md5": "data_events[0]_file_identity_md5",
                },
                "attack_details": {
                    "application": "data_events[0]_file_attack_details_application",
                    "attacked_module": "data_events[0]_file_attack_details_attacked_module",
                    "base_address": "data_events[0]_file_attack_details_base_address",
                    "suspicious_files": [
                        "data_events[0]_file_attack_details_suspicious_files_0"
                    ],
                    "indicators": [
                        {
                            "tactics": [
                                "data_events[0]_file_attack_details_indicators[0]_tactics_0"
                            ],
                            "severity": "data_events[0]_file_attack_details_indicators[0]_severity",
                            "description": "data_events[0]_file_attack_details_indicators[0]_description",
                            "short_description": "data_events[0]_file_attack_details_indicators[0]_short_description",
                            "id": "data_events[0]_file_attack_details_indicators[0]_id",
                            "techniques": [
                                "data_events[0]_file_attack_details_indicators[0]_techniques_0"
                            ],
                        }
                    ],
                },
            },
            "user_name": "data_events[0]_user_name",
            "tactics": ["data_events[0]_tactics_0"],
            "techniques": ["data_events[0]_techniques_0"],
            "connector_guid": "data_computer_connector_guid",
        }
    ]


def test_computer_vulnerabilities_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get vulnerabilities of a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-vulnerabilities-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure length of the outputs is correct.
    -   Ensure connector_guid is in the outputs.
    """
    args = {"connector_guid": "12345"}

    mock_response = load_mock_response("computer_vulnerabilities_response.json")
    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/vulnerabilities',
        json=mock_response,
    )

    from AMPv2 import computer_vulnerabilities_list_command

    response = computer_vulnerabilities_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerVulnerability"
    assert len(response.outputs) == 1
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(
        response.outputs, mock_response["data"]["vulnerabilities"]
    ):
        assert output["connector_guid"] == mock_response["data"]["connector_guid"]

        output.pop("connector_guid", None)
        mock_output.pop("links", None)
        assert output == mock_output


def test_computer_move_command(requests_mock, mock_client):
    """
    Scenario:
    -   Move a computer to another group.
    Given:
    -   The user has entered a connector_guid and a group_guid.
    When:
    -    cisco-amp-computer-move is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure a links doesn't exist in outputs.
    """
    args: dict[str, Any] = {"connector_guid": 1, "group_guid": 2}

    mock_response = load_mock_response("computer_move_response.json")
    requests_mock.patch(
        f'{BASE_URL}/computers/{args["connector_guid"]}', json=mock_response
    )

    from AMPv2 import computer_move_command

    response = computer_move_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Computer"
    assert "links" not in response.outputs
    mock_response["data"].pop("links", None)
    assert response.outputs[0] == mock_response["data"]


def test_computer_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -   cisco-amp-computer-delete is called.
    Then:
    -   Ensure the computer has been deleted.
    """
    args: dict[str, Any] = {"connector_guid": 1}

    mock_response = load_mock_response("computer_delete_response.json")
    requests_mock.delete(
        f'{BASE_URL}/computers/{args["connector_guid"]}', json=mock_response
    )

    from AMPv2 import computer_delete_command

    response = computer_delete_command(mock_client, args)

    assert response.raw_response["data"]["deleted"] is True


def test_computer_delete_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -   cisco-amp-computer-delete is called.
    Then:
    -   Ensure a value error has been raised.
    """
    args: dict[str, Any] = {"connector_guid": 1}

    mock_response = load_mock_response("computer_delete_fail_response.json")
    requests_mock.delete(
        f'{BASE_URL}/computers/{args["connector_guid"]}', json=mock_response
    )

    with pytest.raises(DemistoException) as de:
        from AMPv2 import computer_delete_command

        computer_delete_command(mock_client, args)

        assert de.message.startswith("Failed to delete Connector GUID:")


def test_computer_activity_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get activity on computers by query.
    Given:
    -   The user has entered a url to query.
    When:
    -    cisco-amp-computer-activity-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure a links doesn't exist in outputs.
    """
    args = {"query_string": "8.8.8.8"}

    mock_response = load_mock_response("computer_activity_response.json")
    requests_mock.get(f"{BASE_URL}/computers/activity", json=mock_response)

    from AMPv2 import computer_activity_list_command

    response = computer_activity_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerActivity"
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)
        assert output == mock_output


def test_computer_activity_list_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get activity on computers by query.
    Given:
    -   The user has entered a false query.
    When:
    -    cisco-amp-computer-activity-list is called.
    Then:
    -   Ensure a value has been raised.
    """
    args = {"query_string": '"'}

    requests_mock.get(f"{BASE_URL}/computers/activity")

    with pytest.raises(ValueError) as ve:
        from AMPv2 import computer_activity_list_command

        computer_activity_list_command(mock_client, args)

        assert str(ve) == "query_string must be: SHA-256/IPv4/URL/Filename"


def test_computer_isolation_feature_availability_get_command(
    requests_mock, mock_client
):
    """
    Scenario:
    -   Get available features on a computer.
    When:
    -    cisco-amp-computer_isolation_feature_availability_get is called.
    Then:
    -   Ensure readable_output is correct.
    """
    args: dict[str, Any] = {"connector_guid": 1}

    requests_mock.options(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation',
        headers={"Allow": "GET, PUT, DELETE"},
    )

    from AMPv2 import computers_isolation_feature_availability_get_command

    response = computers_isolation_feature_availability_get_command(mock_client, args)

    assert (
        response.readable_output
        == "Can get information about an isolation with computer-isolation-get\n"
        + "Can request to create a new isolation with computer-isolation-create\n"
        + "Can request to stop the isolation with computer-isolation-delete\n"
    )


def test_computer_isolation_get_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get isolation status on a computer.
    Given:
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-isolation-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure comment is set in readable_output.
    """
    args: dict[str, Any] = {"connector_guid": 1}
    mock_response = load_mock_response("isolation_response.json")

    requests_mock.get(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation', json=mock_response
    )

    from AMPv2 import computer_isolation_get_command

    response = computer_isolation_get_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerIsolation"
    assert response.outputs["connector_guid"] == args["connector_guid"]
    response.outputs.pop("connector_guid", None)
    assert response.outputs == mock_response["data"]


def test_computer_isolation_create_command(requests_mock, mock_client):
    """
    Scenario:
    -   Put a computer in isolation.
    Given:
    -   The user has entered a connector_guid, comment adn unlock_code.
    When:
    -    cisco-amp-computer-isolation-create is called.
    Then:
    -   Ensure outputs_prefix is correct.
    """
    args: dict[str, Any] = {
        "connector_guid": "1",
        "comment": "Hello",
        "unlock_code": "Goodbye",
    }

    mock_response = load_mock_response("isolation_response.json")
    requests_mock.put(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation', json=mock_response
    )

    from AMPv2 import computer_isolation_create_command

    response = computer_isolation_create_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerIsolation"
    assert response.outputs["connector_guid"] == args["connector_guid"]
    response.outputs.pop("connector_guid", None)
    assert response.outputs == mock_response["data"]


def test_computer_isolation_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a computer in isolation.
    Given:
    -   The user has entered a connector_guid.
    When:
    -    cisco-amp-computer-isolation-delete is called.
    Then:
    -   Ensure outputs_prefix is correct.
    """
    args: dict[str, Any] = {
        "connector_guid": "1",
    }

    mock_response = load_mock_response("isolation_response.json")
    requests_mock.delete(
        f'{BASE_URL}/computers/{args["connector_guid"]}/isolation', json=mock_response
    )

    from AMPv2 import computer_isolation_delete_command

    response = computer_isolation_delete_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.ComputerIsolation"
    assert response.outputs[0]["available"] == mock_response["data"]["available"]
    assert response.outputs[0]["status"] == mock_response["data"]["status"]
    assert response.outputs[0]["unlock_code"] == mock_response["data"]["unlock_code"]


def test_event_list_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get list of events.
    Given:
    -   The user has entered no arguments.
    When:
    -    cisco-amp-event-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response("event_list_response.json")
    requests_mock.get(f"{BASE_URL}/events", json=mock_response)

    args: dict[str, Any] = {}

    from AMPv2 import event_list_command

    responses = event_list_command(mock_client, args)

    for response in responses[:-1]:
        assert response.outputs_prefix == "CiscoAMP.Event"

        if "file" in response.outputs:
            assert (
                response.indicator.sha256
                == response.outputs["file"]["identity"]["sha256"]
            )
            assert response.indicator.path == response.outputs["file"]["file_path"]
            assert response.indicator.name == response.outputs["file"]["file_name"]
            if "parent" in response.outputs["file"]:
                assert (
                    response.indicator.relationships[0].to_context()["EntityB"]
                    == response.outputs["file"]["parent"]["identity"]["sha256"]
                )

        if computer := response.outputs.get("computer"):
            assert "links" not in computer

    assert (
        responses[-1].readable_output
        == "### Results\n"
        + "|Current Item Count|Index|Items Per Page|Total|\n"
        + "|---|---|---|---|\n"
        + "| metadata_results_current_item_count | metadata_results_index | "
        + "metadata_results_items_per_page | metadata_results_total |\n"
        + "### Event Information\n"
        + "|ID|Date|Event Type|Detection|Connector GUID|Severity|\n"
        + "|---|---|---|---|---|---|\n"
        + "| data[0]_id | data[0]_date | data[0]_event_type |  | data[0]_connector_guid |  |\n"
        + "| data[1]_id | data[1]_date | data[1]_event_type |  | data[1]_connector_guid |  |\n"
        + "| data[2]_id | data[2]_date | data[2]_event_type |  | data[2]_connector_guid |  |\n"
        + "| data[3]_id | data[3]_date | data[3]_event_type |  | data[3]_connector_guid |  |\n"
        + "| data[4]_id | data[4]_date | data[4]_event_type |  | data[4]_connector_guid |  |\n"
        + "| data[5]_id | data[5]_date | data[5]_event_type |  | data[5]_connector_guid |  |\n"
        + "| data[6]_id | data[6]_date | data[6]_event_type |  | data[6]_connector_guid |  |\n"
        + "| data[7]_id | data[7]_date | data[7]_event_type |  | data[7]_connector_guid |  |\n"
        + "| data[8]_id | data[8]_date | data[8]_event_type |  | data[8]_connector_guid |  |\n"
        + "| data[9]_id | data[9]_date | data[9]_event_type |  | data[9]_connector_guid |  |\n"
        + "| data[10]_id | data[10]_date | data[10]_event_type |  | data[10]_connector_guid |  |\n"
        + "| data[11]_id | data[11]_date | data[11]_event_type |  | data[11]_connector_guid |  |\n"
        + "| data[12]_id | data[12]_date | data[12]_event_type |  | data[12]_connector_guid |  |\n"
        + "| data[13]_id | data[13]_date | data[13]_event_type |  |  |  |\n"
        + "| data[14]_id | data[14]_date | data[14]_event_type | "
        + "data[14]_detection | data[14]_connector_guid | data[14]_severity |\n"
    )


def test_file_command(requests_mock, mock_client):
    """
    Given:
        - a file (sha256)
    When:
        - executing file_command function
    Then:
        - Ensure raw_response is an empty dict.
        - Ensure readable_output is correct and contains an informative message.
    """
    mock_response = {
        "version": "version",
        "metadata": {
            "links": {
                "self": "metadata_links_self",
                "next": "metadata_links_next"
            },
            "results": {
                "total": "metadata_results_total",
                "current_item_count": "metadata_results_current_item_count",
                "index": "metadata_results_index",
                "items_per_page": "metadata_results_items_per_page"
            }
        },
        "data": []
    }
    requests_mock.get(f"{BASE_URL}/events", json=mock_response)
    file_sha_256 = "e" * 64
    args: dict[str, Any] = {"file": file_sha_256}

    from AMPv2 import file_command

    response = file_command(mock_client, args)

    assert response[0].readable_output == f'Cisco AMP: {file_sha_256} not found in Cisco AMP v2.'
    assert response[0].raw_response == {}


@pytest.mark.parametrize(
    "args, expected_number_of_results, start, end",
    [
        ({}, 100, 0, 100),
        ({"limit": "50"}, 50, 0, 50),
        ({"page": "7", "page_size": "5"}, 5, 30, 35),
    ],
)
def test_event_types_list_command(
    requests_mock, mock_client, args, expected_number_of_results, start, end
):
    """
    Scenario:
    -   Get list of event types.
    Given:
    -   The user has entered no arguments.
    -   The user has entered automatic pagination.
    -   The user has entered manual pagination.
    When:
    -    cisco-amp-event-type-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure pagination has worked.
    """
    mock_response = load_mock_response("event_type_list_response.json")
    requests_mock.get(f"{BASE_URL}/event_types", json=mock_response)

    from AMPv2 import event_type_list_command

    response = event_type_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.EventType"
    assert len(response.outputs) == expected_number_of_results

    for output, mock_output in zip(response.outputs, mock_response["data"][start:end]):
        mock_output.pop("links", None)
        assert output == mock_output


@pytest.mark.parametrize(
    "file, suffix, args, expected_file_list_type",
    [
        (
            "file_list_list_response.json",
            "file_lists/1",
            {"file_list_guid": "1"},
            "application_blocking",
        ),
        (
            "file_list_application_blocking_response.json",
            "file_lists/application_blocking",
            {},
            "application_blocking",
        ),
        (
            "file_list_simple_custom_detections_response.json",
            "file_lists/simple_custom_detections",
            {"file_list_type": "Simple Custom Detection"},
            "simple_custom_detections",
        ),
    ],
)
def test_file_list_list_command(
    requests_mock, mock_client, file, suffix, args, expected_file_list_type
):
    """
    Scenario:
    -   Get a specific file list.
    -   Get an application_blocking list.
    -   Get a simple_custom_detections list.
    Given:
    -   The user has entered a file_list_guid.
    -   The user has entered no arguments.
    -   The user has entered a file_list_type.
    When:
    -    cisco-amp-file-list-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    -   Ensure the correct file list type has been returned.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/{suffix}", json=mock_response)

    from AMPv2 import file_list_list_command

    response = file_list_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.FileList"

    if not isinstance(response.outputs, list):
        response.outputs = [response.outputs]

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output in response.outputs:
        assert "links" not in output
        assert output["type"] == expected_file_list_type

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)
        assert output == mock_output


@pytest.mark.parametrize(
    "file, suffix, args",
    [
        (
            "file_list_item_list_response.json",
            "file_lists/1/files",
            {"file_list_guid": "1"},
        ),
        (
            "file_list_item_get_response.json",
            "file_lists/1/files/1",
            {"file_list_guid": "1", "sha256": "1"},
        ),
    ],
)
def test_file_list_item_list_command(requests_mock, mock_client, file, suffix, args):
    """
    Scenario:
    -   Get a file item list.
    -   Get a specific file item list item.
    Given:
    -   The user has entered a file_list_guid.
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/{suffix}", json=mock_response)

    from AMPv2 import file_list_item_list_command

    response = file_list_item_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.FileListItem"
    assert "links" not in response.outputs

    if policies := response.outputs[0].get("policies"):
        assert_output_has_no_links(policies)

        for policy, mock_policy in zip(policies, mock_response["data"]["policies"]):
            mock_policy.pop("links", None)
            assert policy == mock_policy

    if items := response.outputs[0].get("items"):
        assert_output_has_no_links(items)

        for item, mock_item in zip(items, mock_response["data"]["items"]):
            mock_item.pop("links", None)
            assert item == mock_item


def test_file_list_item_create_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create an item for a file item list
    Given:
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-create is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args: dict[str, Any] = {"file_list_guid": "1", "sha256": "1"}

    mock_response = load_mock_response("file_list_item_create_response.json")
    requests_mock.post(
        f'{BASE_URL}/file_lists/{args["file_list_guid"]}/files/{args["sha256"]}',
        json=mock_response,
    )

    from AMPv2 import file_list_item_create_command

    response = file_list_item_create_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.FileListItem"
    assert "links" not in response.outputs
    mock_response["data"].pop("links", None)
    assert response.outputs[0] == mock_response["data"]


def test_file_list_item_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a file item from a file item list.
    Given:
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-delete is called.
    Then:
    -   Ensure the deletion succeeded.
    """
    args = {"file_list_guid": "1", "sha256": "1"}

    mock_response = load_mock_response("file_list_item_delete_response.json")
    requests_mock.delete(
        f'{BASE_URL}/file_lists/{args["file_list_guid"]}/files/{args["sha256"]}',
        json=mock_response,
    )

    from AMPv2 import file_list_item_delete_command

    response = file_list_item_delete_command(mock_client, args)

    assert (
        response.readable_output
        == f'SHA-256: "{args["sha256"]}" Successfully deleted from File List GUID: "{args["file_list_guid"]}".'
    )


def test_file_list_item_delete_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a file item from a file item list.
    Given:
    -   The user has entered a file_list_guid and a sha256.
    When:
    -    cisco-amp-file-list-item-delete is called.
    Then:
    -   Ensure the deletion failed.
    """
    args = {"file_list_guid": "1", "sha256": "1"}

    mock_response = load_mock_response("file_list_item_delete_fail_response.json")
    requests_mock.delete(
        f'{BASE_URL}/file_lists/{args["file_list_guid"]}/files/{args["sha256"]}',
        json=mock_response,
    )

    with pytest.raises(DemistoException) as de:
        from AMPv2 import file_list_item_delete_command

        file_list_item_delete_command(mock_client, args)

        assert (
            de.message
            == f'Failed to delete-\nFile List GUID: "{args["file_list_guid"]}"\nSHA-256: "{args["sha256"]}" not found.'
        )


@pytest.mark.parametrize(
    "file, args, suffix",
    [
        ("group_list_response.json", {}, ""),
        ("group_response.json", {"group_guid": "1"}, "/1"),
    ],
)
def test_group_list_command(requests_mock, mock_client, file, args, suffix):
    """
    Scenario:
    -   Get a group list.
    -   Get a specific group.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered a group_guid.
    When:
    -    cisco-amp-group-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/groups{suffix}", json=mock_response)

    from AMPv2 import group_list_command

    response = group_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Group"

    assert_output_has_no_links(response.outputs)

    if policies := response.outputs[0].get("policies"):
        assert_output_has_no_links(policies)

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)

        for policy in mock_output.get("policies", []):
            policy.pop("links", None)

        assert output == mock_output


def test_group_policy_update_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update a group policy.
    Given:
    -   The user hasn't entered any policy arguments.
    -   The user has entered a group_guid and a policy argument.
    When:
    -    cisco-amp-group-policy-update is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args = {"group_guid": "1", "windows_policy_guid": "1"}

    mock_response = load_mock_response("group_response.json")
    requests_mock.patch(f'{BASE_URL}/groups/{args["group_guid"]}', json=mock_response)

    from AMPv2 import group_policy_update_command

    response = group_policy_update_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Group"

    if policies := response.outputs[0].get("policies"):
        assert_output_has_no_links(policies)

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)

        for policy in mock_output.get("policies", []):
            policy.pop("links", None)

        assert output == mock_output


def test_group_policy_update_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Update a group policy.
    Given:
    -   The user hasn't entered any policy arguments.
    When:
    -    cisco-amp-group-policy-update is called.
    Then:
    -   Ensure an error has been raised
    """
    args = {"group_guid": "1"}

    requests_mock.patch(f'{BASE_URL}/groups/{args["group_guid"]}')

    with pytest.raises(ValueError) as ve:
        from AMPv2 import group_policy_update_command

        group_policy_update_command(mock_client, args)

        assert str(ve) == "At least one Policy GUID must be entered."


@pytest.mark.parametrize("file", [("group_response.json"), ("group_response.json")])
def test_group_parent_update_command(requests_mock, mock_client, file):
    """
    Scenario:
    -   Update a group policy.
    Given:
    -   The user has entered a child_guid.
    When:
    -    cisco-amp-group-parent-update is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args: dict[str, Any] = {"child_guid": "1"}

    mock_response = load_mock_response(file)
    requests_mock.patch(
        f'{BASE_URL}/groups/{args["child_guid"]}/parent', json=mock_response
    )

    from AMPv2 import group_parent_update_command

    response = group_parent_update_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Group"

    if policies := response.outputs[0].get("policies"):
        assert_output_has_no_links(policies)

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)

        for policy in mock_output.get("policies", []):
            policy.pop("links", None)

        assert output == mock_output


def test_group_create_command(requests_mock, mock_client):
    """
    Scenario:
    -   Create a new group.
    Given:
    -   The user has entered a name and description.
    When:
    -    cisco-amp-group-create is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    args: dict[str, Any] = {
        "name": "Til",
        "description": "Tamar",
    }

    mock_response = load_mock_response("group_response.json")
    requests_mock.post(f"{BASE_URL}/groups", json=mock_response)

    from AMPv2 import group_create_command

    response = group_create_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Group"

    if policies := response.outputs[0].get("policies"):
        assert_output_has_no_links(policies)

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)

        for policy in mock_output.get("policies", []):
            policy.pop("links", None)

        assert output == mock_output


def test_group_delete_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a group.
    Given:
    -   The user has entered a group_guid.
    When:
    -    cisco-amp-groups-delete is called.
    Then:
    -   Ensure the deletion succeeded.
    """
    args: dict[str, Any] = {
        "group_guid": "1",
    }

    mock_response = load_mock_response("group_delete_response.json")
    requests_mock.delete(f'{BASE_URL}/groups/{args["group_guid"]}', json=mock_response)

    from AMPv2 import groups_delete_command

    response = groups_delete_command(mock_client, args)

    assert (
        response.readable_output
        == f'Group GUID: "{args["group_guid"]}"\nSuccessfully deleted.'
    )


def test_group_delete_error_command(requests_mock, mock_client):
    """
    Scenario:
    -   Delete a group.
    Given:
    -   The user has entered a group_guid.
    When:
    -    cisco-amp-groups-delete is called.
    Then:
    -   Ensure the deletion failed.
    """
    args: dict[str, Any] = {
        "group_guid": "1",
    }

    mock_response = load_mock_response("group_delete_fail_response.json")
    requests_mock.delete(f'{BASE_URL}/groups/{args["group_guid"]}', json=mock_response)

    with pytest.raises(DemistoException) as de:
        from AMPv2 import groups_delete_command

        groups_delete_command(mock_client, args)

        assert de.message == f'Failed to delete Group GUID: "{args["group_guid"]}".'


@pytest.mark.parametrize(
    "file, args, suffix",
    [
        ("indicator_list_response.json", {}, ""),
        ("indicator_get_response.json", {"indicator_guid": "1"}, "/1"),
    ],
)
def test_indicator_list_command(requests_mock, mock_client, file, args, suffix):
    """
    Scenario:
    -   Get an indicator list.
    -   Get a specific indicator.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered an indicator_guid.
    When:
    -    cisco-amp-indicator-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/indicators{suffix}", json=mock_response)

    from AMPv2 import indicator_list_command

    response = indicator_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Indicator"
    assert_output_has_no_links(response.outputs)

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)
        assert output == mock_output


@pytest.mark.parametrize(
    "file, args, suffix",
    [
        ("policy_list_response.json", {}, ""),
        ("policy_get_response.json", {"policy_guid": "1"}, "/1"),
    ],
)
def test_policy_list_command(requests_mock, mock_client, file, args, suffix):
    """
    Scenario:
    -   Get a policy list.
    -   Get a specific policy.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered an policy_guid.
    When:
    -    cisco-amp-policy-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/policies{suffix}", json=mock_response)

    from AMPv2 import policy_list_command

    response = policy_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Policy"
    assert_output_has_no_links(response.outputs)

    if isinstance(mock_response["data"], dict):
        mock_response["data"] = [mock_response["data"]]

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)
        assert output == mock_output


@pytest.mark.parametrize(
    "args, expected_number_of_results, start, end",
    [
        ({"ios_bid": "Gotta"}, 100, 0, 100),
        ({"ios_bid": "Catch-em", "limit": "50"}, 50, 0, 50),
        ({"ios_bid": "All", "page": "7", "page_size": "5"}, 5, 30, 35),
    ],
)
def test_app_trajectory_query_list_command(
    requests_mock,
    mock_client,
    args,
    expected_number_of_results,
    start,
    end,
):
    """
    Scenario:
    -   Get an app trajectory.
    Given:
    -   The user has entered an ios_bid.
    -   The user has entered an ios_bid and automatic pagination.
    -   The user has entered an ios_bid and manual pagination.
    When:
    -    cisco-amp-app-trajectory-query-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure pagination has worked.
    """
    mock_response = load_mock_response("app_trajectory_query_response.json")
    requests_mock.get(f"{BASE_URL}/app_trajectory/queries", json=mock_response)

    from AMPv2 import app_trajectory_query_list_command

    response = app_trajectory_query_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.AppTrajectoryQuery"
    assert len(response.outputs) == expected_number_of_results

    for output, mock_output in zip(response.outputs, mock_response["data"][start:end]):
        mock_output.pop("links", None)
        assert output == mock_output


def test_version_get_command(requests_mock, mock_client):
    """
    Scenario:
    -   Get current version of API.
    When:
    -    cisco-amp-version-get is called.
    Then:
    -   Ensure outputs_prefix is correct.
    """
    arg: dict[str, Any] = {}

    mock_response = load_mock_response("version_get_response.json")
    requests_mock.get(f"{BASE_URL}/version", json=mock_response)

    from AMPv2 import version_get_command

    response = version_get_command(mock_client, arg)

    assert response.outputs_prefix == "CiscoAMP.Version"


@pytest.mark.parametrize(
    "file, args, suffix, is_list",
    [
        ("vulnerability_list_response.json", {}, "", True),
        ("vulnerability_get_response.json", {"sha256": "1"}, "/1/computers", False),
    ],
)
def test_vulnerability_list_command(
    requests_mock, mock_client, file, args, suffix, is_list
):
    """
    Scenario:
    -   Get a vulnerability list.
    -   Get a vulnerable item trajectory.
    Given:
    -   The user hasn't entered any arguments.
    -   The user has entered a sha256.
    When:
    -    cisco-amp-vulnerability-list is called.
    Then:
    -   Ensure outputs_prefix is correct.
    -   Ensure there are no links in the outputs.
    """
    mock_response = load_mock_response(file)
    requests_mock.get(f"{BASE_URL}/vulnerabilities{suffix}", json=mock_response)

    from AMPv2 import vulnerability_list_command

    response = vulnerability_list_command(mock_client, args)

    assert response.outputs_prefix == "CiscoAMP.Vulnerability"
    assert_output_has_no_links(response.outputs)

    for output, mock_output in zip(response.outputs, mock_response["data"]):
        mock_output.pop("links", None)

        for computer in mock_output.get("computers", []):
            computer.pop("links", None)

        assert output == mock_output


@pytest.mark.parametrize(
    "last_run, limit, expeted_previous_ids",
    [
        (
            {
                "last_fetch": "2022-07-18T00:00:00.000Z",
                "previous_ids": ["6159258594551267593", "6159258594551267594", "6159258594551267595"]
            },
            3,
            ["6159258594551267597"]
        ),
        (
            {},
            2,
            ["6159258594551267592", "6159258594551267593"]
        ),
        (
            {
                "last_fetch": "test",
                "previous_ids": ["6159258594551267592"]
            },
            1,
            ["6159258594551267592", "6159258594551267593"]
        )
    ]
)
def test_fetch_incidents(
    mock_client,
    mocker,
    last_run: dict[str, str | list[str]],
    limit: int,
    expeted_previous_ids: list[str],
):
    """
    Given:
        - args: last_run, limit.
    When:
        - run `fetch_incidents` function.
    Then:
        - Ensure in case previous_ids is provided it does not fetch
          the incidents with ids already fetched.
        - Ensure that when there are two incidents with the same time
          the previous_ids returned contains both ids.
        - Ensure that when the last incident retrieved has the same time
          as the incident with the id provided in previous_ids
          then it returns both ids.
    """
    mock_response_1 = load_mock_response("incidents_response_1.json")
    mock_response_2 = load_mock_response("incidents_response_2.json")

    mocker.patch.object(Client, "event_list_request", side_effect=[mock_response_1, mock_response_2])
    mocker.patch("AMPv2.date_to_timestamp", return_value=1699360451000)

    from AMPv2 import fetch_incidents

    next_run, incidents = fetch_incidents(mock_client,
                                          last_run=last_run,
                                          first_fetch_time="2023-11-01T23:17:39.000Z",
                                          incident_severities=["Low", "Medium", "High", "Critical"],
                                          max_incidents_to_fetch=limit)

    # Validate response
    for previous_id in expeted_previous_ids:
        assert previous_id in next_run["previous_ids"]
    assert len(incidents) == limit


def test_fetch_incidents_with_no_new_incidents(
    mock_client,
    mocker,
):
    """
    Given:
        - args with last_run that has previous_ids
          (Simulates a given situation where there are no new incidents).
    When:
        - run `fetch_incidents` function.
    Then:
        - Ensure the no incidents returned.
        - Ensure the `previous_ids` does not change and stays with the provided id.
    """
    mock_response = load_mock_response("incidents_response_3.json")

    mocker.patch.object(Client, "event_list_request", return_value=mock_response)

    from AMPv2 import fetch_incidents

    next_run, incidents = fetch_incidents(mock_client,
                                          last_run={
                                              "last_fatch": "2023-11-15T00:00:00.000Z",
                                              "previous_ids": ["6159258594551267595"]
                                          },
                                          first_fetch_time="2023-11-01T23:17:39.000Z",
                                          incident_severities=["Low", "Medium", "High", "Critical"],
                                          max_incidents_to_fetch=100)

    # Validate response
    assert "6159258594551267595" in next_run["previous_ids"]
    assert len(incidents) == 0


def test_fetch_incidents_for_incident_severities(
    mock_client,
    mocker,
):
    """
    Given:
        - the last_run empty and incident_severities without "Medium" severity.
    When:
        - run `fetch_incidents` function.
    Then:
        - Ensure the incidents returned only contain "Low", "High" and "Critical" severities.
    """
    mock_response = load_mock_response("incidents_response_4.json")

    mocker.patch.object(Client, "event_list_request", return_value=mock_response)

    from AMPv2 import fetch_incidents

    _, incidents = fetch_incidents(mock_client,
                                   last_run={},
                                   first_fetch_time="2023-11-01T23:17:39.000Z",
                                   incident_severities=["Low", "High", "Critical"],
                                   max_incidents_to_fetch=100)

    # Validate response
    assert len(incidents) == 3
