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
@patch("CiscoWSAV2.Client.handle_request_headers", mock_access_token)
def mock_client():
    """
    Mock client
    """
    from CiscoWSAV2 import Client

    return Client(BASE_URL, USERNAME, PASSWORD, verify=False, proxy=False)


""" TESTING INTEGRATION COMMANDS"""


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len",
    [
        (
            "access_policy_list.json",
            {
                "policy_names": "test,test2",
            },
            2,
        ),
        (
            "access_policy_list.json",
            {
                "page": 1,
                "page_size": 2,
            },
            2,
        ),
        (
            "access_policy_list.json",
            {
                "limit": 2,
            },
            2,
        ),
    ],
)
def test_access_policy_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    requests_mock,
    mock_client,
):
    """
    Scenario: Access policies list.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-access-policy-list command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSAV2 import access_policy_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/{V3_PREFIX}/web_security/access_policies"
    requests_mock.get(url=url, json=mock_response)

    result = access_policy_list_command(mock_client, command_arguments)

    assert result.outputs_prefix == "CiscoWSA.AccessPolicy"
    assert len(result.outputs) == expected_outputs_len


def test_access_policy_create_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Access policies create.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-access-policy-create command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSAV2 import access_policy_create_command

    url = f"{BASE_URL}/{V3_PREFIX}/web_security/access_policies"
    requests_mock.post(url=url, status_code=204)
    result = access_policy_create_command(
        mock_client,
        {
            "policy_name": "test",
            "policy_status": "enable",
            "identification_profile_name": "global_identification_profile",
            "policy_order": "1",
            "policy_description": "test",
        },
    )

    assert result.readable_output == 'Created "test" access policy successfully.'


def test_access_policy_update_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Access policies update.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-access-policy-update command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSAV2 import access_policy_update_command

    url = f"{BASE_URL}/{V3_PREFIX}/web_security/access_policies"
    requests_mock.put(url=url, status_code=204)
    result = access_policy_update_command(
        mock_client,
        {
            "policy_name": "test",
            "new_policy_name": "test",
            "policy_status": "enable",
            "identification_profile_name": "global_identification_profile",
            "policy_order": "2",
            "policy_description": "test description",
        },
    )

    assert result.readable_output == 'Updated "test" access policy successfully.'


def test_access_policy_delete_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Access policies delete.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-access-policy-delete command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSAV2 import access_policy_delete_command

    url = f"{BASE_URL}/{V3_PREFIX}/web_security/access_policies"
    requests_mock.delete(url=url, status_code=204)
    result = access_policy_delete_command(
        mock_client,
        {
            "policy_names": "test,test2",
        },
    )

    assert (
        result.readable_output == 'Access policies "test, test2" deleted successfully.'
    )


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
    from CiscoWSAV2 import domain_map_list_command

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
    - Ensure readable output is correct.
    - Ensure response code is correct.
    """
    from CiscoWSAV2 import domain_map_create_command

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
    - Ensure readable output is correct.
    - Ensure response code is correct.
    """
    from CiscoWSAV2 import domain_map_update_command

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
    - Ensure readable output is correct.
    - Ensure response code is correct.
    """
    from CiscoWSAV2 import domain_map_delete_command

    mock_response = load_mock_response("domain_map_delete.json")
    url = f"{BASE_URL}/{V2_PREFIX}/configure/web_security/domain_map"
    requests_mock.delete(url=url, json=mock_response)

    result = domain_map_delete_command(
        mock_client,
        {"domain_names": "test.com"},
    )

    assert result.readable_output == 'Domain "test.com" deleted successfully.'
    assert result.raw_response["res_code"] == 200


@pytest.mark.parametrize(
    "response_file_name,command_arguments,expected_outputs_len",
    [
        (
            "identification_profiles_list.json",
            {
                "page": 1,
                "page_size": 3,
            },
            3,
        ),
        (
            "identification_profiles_list.json",
            {
                "limit": 5,
            },
            5,
        ),
    ],
)
def test_identification_profiles_list_command(
    response_file_name,
    command_arguments,
    expected_outputs_len,
    requests_mock,
    mock_client,
):
    """
    Scenario: Identification profiles list.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-identification-profiles-list command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSAV2 import identification_profiles_list_command

    mock_response = load_mock_response(response_file_name)
    url = f"{BASE_URL}/{V3_PREFIX}/web_security/identification_profiles"
    requests_mock.get(url=url, json=mock_response)

    result = identification_profiles_list_command(mock_client, command_arguments)

    assert result.outputs_prefix == "CiscoWSA.IdentificationProfile"
    assert len(result.outputs) == expected_outputs_len


def test_identification_profiles_create_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Identification profile create.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-identification-profiles-create command called.
    Then:
    - Ensure readable output is correct.
    """
    from CiscoWSAV2 import identification_profiles_create_command

    url = f"{BASE_URL}/{V3_PREFIX}/web_security/identification_profiles"
    requests_mock.post(url=url, status_code=204)

    result = identification_profiles_create_command(
        mock_client,
        {
            "profile_name": "test",
            "status": "enable",
            "order": 1,
            "description": "test",
            "protocols": "HTTPS",
        },
    )

    assert (
        result.readable_output == 'Created identification profile "test" successfully.'
    )


def test_identification_profiles_update_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Identification profile update.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-identification-profiles-update command called.
    Then:
    - Ensure readable output is correct.
    """
    from CiscoWSAV2 import identification_profiles_update_command

    url = f"{BASE_URL}/{V3_PREFIX}/web_security/identification_profiles"
    requests_mock.put(url=url, status_code=204)

    result = identification_profiles_update_command(
        mock_client,
        {
            "profile_name": "test",
            "new_profile_name": "test1",
            "order": 2,
            "description": "test description",
            "protocols": "SOCKS",
        },
    )

    assert (
        result.readable_output == 'Updated identification profile "test" successfully.'
    )


def test_identification_profiles_delete_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: Identification profile delete.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-identification-profiles-delete command called.
    Then:
    - Ensure readable output is correct.
    """
    from CiscoWSAV2 import identification_profiles_delete_command

    url = f"{BASE_URL}/{V3_PREFIX}/web_security/identification_profiles"
    requests_mock.delete(url=url, status_code=204)

    result = identification_profiles_delete_command(
        mock_client,
        {
            "profile_names": "test",
        },
    )

    assert result.readable_output == "Deleted identification profiles successfully."


def test_url_categories_list_command(
    requests_mock,
    mock_client,
):
    """
    Scenario: URL categories list.
    Given:
    - User has provided valid credentials.
    - User may provided pagination args.
    - User may Provided filtering arguments.
    When:
    - cisco-wsa-url-categories-list command called.
    Then:
    - Ensure outputs prefix is correct.
    - Ensure number of items is correct.
    - Validate outputs' fields.
    """
    from CiscoWSAV2 import url_categories_list_command

    mock_response = load_mock_response("url_categories_list.json")
    url = f"{BASE_URL}/{V3_PREFIX}/generic_resources/url_categories"
    requests_mock.get(url=url, json=mock_response)

    result = url_categories_list_command(mock_client, {})

    assert result.outputs_prefix == "CiscoWSA.UrlCategory"
    assert len(result.outputs["predefined"]) == 106
    assert len(result.outputs["custom"]) == 1


""" TESTING HELPER FUNCTIONS"""


@pytest.mark.parametrize(
    "response,arguments,paginated_response",
    [
        (
            ["test.com", "test1.com", "test2.com", "test3.com", "test4.com"],
            {
                "page": 2,
                "page_size": 2,
            },
            ["test2.com", "test3.com"],
        ),
        (
            ["test.com", "test1.com", "test2.com", "test3.com", "test4.com"],
            {
                "limit": 3,
            },
            ["test.com", "test1.com", "test2.com"],
        ),
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
    from CiscoWSAV2 import pagination

    result = pagination(response, arguments)

    assert result == paginated_response
