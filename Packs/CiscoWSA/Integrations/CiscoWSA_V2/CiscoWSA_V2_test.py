import json
import os
import pytest
from unittest.mock import patch


"""CONSTANTS"""
BASE_URL = "https://example.com/wsa/api"
USERNAME = "MOCK_USER"
PASSWORD = "XXX"
TOKEN = "XXX-XXXX"
V2_PREFIX = "v2.0"
V3_PREFIX = "v3.0"


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(
        os.path.join("test_data/outputs", file_name), mode="r", encoding="utf-8"
    ) as mock_file:
        return json.loads(mock_file.read())


def mock_access_token(client):
    return TOKEN


@pytest.fixture(autouse=True)
@patch("CiscoWSA_V2.Client.handle_request_headers", mock_access_token)
def mock_client():
    """
    Mock client
    """
    from CiscoWSA_V2 import Client

    return Client(BASE_URL, USERNAME, PASSWORD, verify=False, proxy=False)


""" TESTING INTEGRATION COMMANDS"""


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len",
    [
        (
            "domain_map_list.json",
            {
                "domain_names": "test.com",
                "ip_addresses": "8.8.8.8",
            },
            2,
        ),
        (
            "domain_map_list.json",
            {
                "page": 1,
                "page_size": 3,
            },
            3,
        ),
        (
            "domain_map_list.json",
            {
                "limit": 5,
            },
            5,
        ),
    ],
)
def test_domain_map_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    requests_mock,
    mock_client,
):
    """
    Scenario: Domain map list.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-domain-map-list command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSA_V2 import domain_map_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/{V2_PREFIX}/configure/web_security/domain_map"
    requests_mock.get(url=url, json=mock_response)

    result = domain_map_list_command(mock_client, command_arguments)

    assert result.outputs_prefix == "CiscoWSA.DomainMap"
    assert len(result.outputs) == expected_outputs_len


def test_domain_map_create_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Domain map create.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-domain-map-create command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSA_V2 import domain_map_create_command

    mock_response = load_mock_response("domain_map_create.json")
    url = f"{BASE_URL}/{V2_PREFIX}/configure/web_security/domain_map"
    requests_mock.post(url=url, json=mock_response)

    result = domain_map_create_command(
        mock_client,
        {
            "domain_name": "test.com",
            "ip_addresses": "1.1.1.1",
            "order": 1,
        },
    )

    assert result.readable_output == 'Domain "test.com" mapping created successfully.'
    assert result.raw_response["res_code"] == 201


def test_domain_map_update_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Domain map update.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-domain-map-update command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSA_V2 import domain_map_update_command

    mock_response = load_mock_response("domain_map_update.json")
    url = f"{BASE_URL}/{V2_PREFIX}/configure/web_security/domain_map"
    requests_mock.put(url=url, json=mock_response)

    result = domain_map_update_command(
        mock_client,
        {
            "domain_name": "test.com",
            "new_domain_name": "test.com",
            "ip_addresses": "1.1.1.1",
            "order": 1,
        },
    )

    assert result.readable_output == 'Domain "test.com" mapping updated successfully.'
    assert result.raw_response["res_code"] == 200


def test_domain_map_delete_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Domain map delete.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-domain-map-delete command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSA_V2 import domain_map_delete_command

    mock_response = load_mock_response("domain_map_delete.json")
    url = f"{BASE_URL}/{V2_PREFIX}/configure/web_security/domain_map"
    requests_mock.delete(url=url, json=mock_response)

    result = domain_map_delete_command(
        mock_client,
        {"domain_names": "test.com"},
    )

    assert result.readable_output == 'Domain "test.com" deleted successfully.'
    assert result.raw_response["res_code"] == 200


""" TESTING HELPER FUNCTIONS"""


@pytest.mark.parametrize(
    "response,arguments,paginated_response",
    [
        (
            ['test.com', 'test1.com', 'test2.com', 'test3.com', 'test4.com'],
            {
                "page": 2,
                "page_size": 2,
            },
            ['test2.com', 'test3.com']
        ),
            (
            ['test.com', 'test1.com', 'test2.com', 'test3.com', 'test4.com'],
            {
                "limit": 3,
            },
            ['test.com', 'test1.com', 'test2.com']
        )
    ],
)
def test_pagination_function(response, arguments, paginated_response):
    """
    Scenario: Paginate response.
    Given:
    - User has provided pagination arguments.
    When:
    - pagination function called.
    Then:
    - Ensure result is correct.
    """
    from CiscoWSA_V2 import pagination

    result = pagination(response, arguments)

    assert result == paginated_response
