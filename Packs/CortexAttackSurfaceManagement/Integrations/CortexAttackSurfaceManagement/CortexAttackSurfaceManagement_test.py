import pytest
from test_data.raw_response import (
    EXTERNAL_EXPOSURES_RESPONSE,
    EXTERNAL_EXPOSURE_RESPONSE,
    EXTERNAL_RANGES_RESPONSE,
    EXTERNAL_RANGE_RESPONSE,
    EXTERNAL_SERVICES_RESPONSE,
    EXTERNAL_SERVICE_RESPONSE,
    GENERAL_500_WAITRESS_ERROR,
    INTERNET_EXPOSURE_PRE_FORMAT,
    RCS_FAILURE_RESPONSE_100,
    RCS_SUCCESSFUL_RESPONSE_200,
    RCS_SUCCESSFUL_RESPONSE_201,
    REMEDIATION_RULES_RESPONSE,
)
from test_data.expected_results import (
    EXTERNAL_EXPOSURES_RESULTS,
    EXTERNAL_EXPOSURE_RESULTS,
    EXTERNAL_RANGES_RESULTS,
    EXTERNAL_RANGE_RESULTS,
    EXTERNAL_SERVICES_RESULTS,
    EXTERNAL_SERVICE_RESULTS,
    INTERNET_EXPOSURE_POST_FORMAT,
    RCS_SUCCESSFUL_RESULTS_200,
    RCS_SUCCESSFUL_RESULTS_201,
    REMEDIATION_RULES_RESULTS,
)

"""Fixtures for the test cases"""


@pytest.fixture(scope="module")
def client():
    from CortexAttackSurfaceManagement import Client

    client = Client(base_url="https://test.com/api/webapp/public_api/v1", verify=True, headers={"HOST": "test.com", "Authorizatio": "THISISAFAKEKEY", "Content-Type": "application/json"}, proxy=False)
    return client


"""Test cases"""

def test_format_asm_id_func():
    """Tests format_asm_id helper function.

    Given:
        - Mock JSON pre-formatting from the list_asset_internet_exposure_command function
    When:
        - Sending JSON to format_asm_id function.
    Then:
        - Checks the output of the helper function with the expected output.
    """
    from CortexAttackSurfaceManagement import format_asm_id

    response = format_asm_id(INTERNET_EXPOSURE_PRE_FORMAT)

    assert response == INTERNET_EXPOSURE_POST_FORMAT


def test_list_external_service_command(client, requests_mock):
    """Tests list_external_service_command command function.

    Given:
        - requests_mock instance to generate the appropriate list_external_service_command API response,
          loaded from a local JSON file.
    When:
        - Running the 'list_external_service_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import list_external_service_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/assets/get_external_services/", json=EXTERNAL_SERVICES_RESPONSE)

    args = {
        "domain": "testdomain.com",
    }

    response = list_external_service_command(client, args)

    assert response.outputs == EXTERNAL_SERVICES_RESULTS
    assert response.outputs_prefix == "ASM.ExternalService"
    assert response.outputs_key_field == "service_id"


def test_get_external_service_command(client, requests_mock):
    """Tests get_external_service_command command function.

    Given:
        - requests_mock instance to generate the appropriate get_external_service_command API response,
          loaded from a local JSON file.
    When:
        - Running the 'get_external_service_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import get_external_service_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/assets/get_external_service", json=EXTERNAL_SERVICE_RESPONSE)

    args = {"service_id": "94232f8a-f001-3292-aa65-63fa9d981427"}

    response = get_external_service_command(client, args)

    assert response.outputs == EXTERNAL_SERVICE_RESULTS
    assert response.outputs_prefix == "ASM.ExternalService"
    assert response.outputs_key_field == "service_id"


def test_list_external_ip_address_range_command(client, requests_mock):
    """Tests list_external_ip_address_range_command function.

    Given:
        - requests_mock instance to generate the appropriate list_external_ip_address_range_command( API response,
          loaded from a local JSON file.
    When:
        - Running the 'list_external_ip_address_range_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import list_external_ip_address_range_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_ranges/", json=EXTERNAL_RANGES_RESPONSE)

    args = {}

    response = list_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGES_RESULTS
    assert response.outputs_prefix == "ASM.ExternalIpAddressRange"
    assert response.outputs_key_field == "range_id"


def test_get_external_ip_address_range_command(client, requests_mock):
    """Tests get_external_ip_address_range_command function.

    Given:
        - requests_mock instance to generate the appropriate get_external_ip_address_range_command( API response,
          loaded from a local JSON file.
    When:
        - Running the 'get_external_ip_address_range_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import get_external_ip_address_range_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_range/", json=EXTERNAL_RANGE_RESPONSE)

    args = {"range_id": "1093124c-ce26-33ba-8fb8-937fecb4c7b6"}

    response = get_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGE_RESULTS
    assert response.outputs_prefix == "ASM.ExternalIpAddressRange"
    assert response.outputs_key_field == "range_id"


def test_list_asset_internet_exposure_command(client, requests_mock):
    """Tests list_asset_internet_exposure_command function.

    Given:
        - requests_mock instance to generate the appropriate list_asset_internet_exposure_command( API response,
          loaded from a local JSON file.
    When:
        - Running the 'list_asset_internet_exposure_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import list_asset_internet_exposure_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/assets/get_assets_internet_exposure/", json=EXTERNAL_EXPOSURES_RESPONSE)

    args = {"name": "testdomain.com"}

    response = list_asset_internet_exposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response.outputs_prefix == "ASM.AssetInternetExposure"
    assert response.outputs_key_field == "asm_ids"


def test_get_asset_internet_exposure_command(client, requests_mock):
    """Tests get_asset_internet_exposure_command function.

    Given:
        - requests_mock instance to generate the appropriate get_asset_internet_exposure_command( API response,
          loaded from a local JSON file.
    When:
        - Running the 'get_asset_internet_exposure_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import get_asset_internet_exposure_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/assets/get_asset_internet_exposure/", json=EXTERNAL_EXPOSURE_RESPONSE)

    args = {"asm_id": "testdomain.com"}

    response = get_asset_internet_exposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURE_RESULTS
    assert response.outputs_prefix == "ASM.AssetInternetExposure"
    assert response.outputs_key_field == "asm_ids"


def test_list_remediation_rule_command(client, requests_mock):
    """Tests list_remediation_rule_command function.

    Given:
        - requests_mock instance to generate the appropriate list_remediation_rule_command( API response,
          loaded from a local JSON file.
    When:
        - Running the 'list_remediation_rule_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import list_remediation_rule_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/xpanse_remediation_rules/rules/", json=REMEDIATION_RULES_RESPONSE)

    args = {"asm_rule_id": "RdpServer"}

    response = list_remediation_rule_command(client, args)

    assert response.outputs == REMEDIATION_RULES_RESULTS
    assert response.outputs_prefix == "ASM.RemediationRule"
    assert response.outputs_key_field == "rule_id"


@pytest.mark.parametrize(
    "alert_internal_id, service_id, attack_surface_rule_id, expected_results, raw_response, status_code",
    [
        (123, "12345abc-123a-1234-a123-efgh12345678", "RdpServer", RCS_SUCCESSFUL_RESULTS_201, RCS_SUCCESSFUL_RESPONSE_201, 201),
        (123, "12345abc-123a-1234-a123-efgh12345678", "RdpServer", RCS_SUCCESSFUL_RESULTS_200, RCS_SUCCESSFUL_RESPONSE_200, 200),
    ],
)
def test_start_remediation_confirmation_scan_successful_codes(client, alert_internal_id, service_id, attack_surface_rule_id,
                                                              expected_results, raw_response, status_code, requests_mock):
    from CortexAttackSurfaceManagement import start_remediation_confirmation_scan_command

    requests_mock.post("https://test.com/api/webapp/public_api/v1/remediation_confirmation_scanning/requests/get_or_create/",
                       json=raw_response, status_code=status_code)

    args = {"alert_internal_id": alert_internal_id, "service_id": service_id, "attack_surface_rule_id": attack_surface_rule_id}

    response = start_remediation_confirmation_scan_command(client=client, args=args)

    assert response.outputs == expected_results
    assert response.outputs_prefix == "ASM.RemediationScan"
    assert response.outputs_key_field == ""
