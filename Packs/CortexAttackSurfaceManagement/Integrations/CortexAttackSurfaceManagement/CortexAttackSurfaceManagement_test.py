import pytest
import requests
import demistomock as demisto
from CortexAttackSurfaceManagement import NotFoundError, ProcessingError, Client
from test_data.raw_response import (
    EXTERNAL_EXPOSURES_RESPONSE,
    EXTERNAL_EXPOSURE_RESPONSE,
    EXTERNAL_RANGES_RESPONSE,
    EXTERNAL_RANGE_RESPONSE,
    EXTERNAL_SERVICES_RESPONSE,
    EXTERNAL_SERVICE_RESPONSE,
    INTERNET_EXPOSURE_PRE_FORMAT,
    RCS_START_SCAN_FAILURE_RESPONSE_100,
    RCS_GET_SCAN_FAILURE_RESPONSE_404,
    GENERAL_API_FAILURE_RESPONSE_400,
    GENERAL_500_WAITRESS_ERROR,
    RCS_START_SCAN_SUCCESSFUL_RESPONSE_200,
    RCS_START_SCAN_SUCCESSFUL_RESPONSE_201,
    REMEDIATION_RULES_RESPONSE,
    RCS_GET_SCAN_STATUS_SUCCESS_REMEDIATED_RESPONSE_200,
    RCS_GET_SCAN_STATUS_SUCCESS_UNREMEDIATED_RESPONSE_200,
    RCS_GET_SCAN_STATUS_IN_PROGRESS_RESPONSE_200,
    RCS_GET_SCAN_STATUS_FAILED_ERROR_RESPONSE_200,
    RCS_GET_SCAN_STATUS_FAILED_TIMEOUT_RESPONSE_200,
    RCS_GET_SCAN_STATUS_OTHER_RESPONSE_200,
    ASM_GET_ATTACK_SURFACE_RULE_RESPONSE
)
from test_data.expected_results import (
    EXTERNAL_EXPOSURES_RESULTS,
    EXTERNAL_EXPOSURE_RESULTS,
    EXTERNAL_RANGES_RESULTS,
    EXTERNAL_RANGE_RESULTS,
    EXTERNAL_SERVICES_RESULTS,
    EXTERNAL_SERVICE_RESULTS,
    INTERNET_EXPOSURE_POST_FORMAT,
    RCS_START_SCAN_SUCCESSFUL_RESULTS_200,
    RCS_START_SCAN_SUCCESSFUL_RESULTS_201,
    REMEDIATION_RULES_RESULTS,
    RCS_GET_SCAN_STATUS_SUCCESS_REMEDIATED_RESULTS_200,
    RCS_GET_SCAN_STATUS_SUCCESS_UNREMEDIATED_RESULTS_200,
    RCS_GET_SCAN_STATUS_FAILED_ERROR_RESULTS_200,
    RCS_GET_SCAN_STATUS_FAILED_TIMEOUT_RESULTS_200,
    RCS_GET_SCAN_STATUS_OTHER_RESULTS_200,
    ASM_GET_ATTACK_SURFACE_RULE_RESULTS
)

client = Client(
    base_url="https://test.com/api/webapp/public_api/v1",
    verify=False,
    headers={
        "HOST": "test.com",
        "Authorization": "THISISAFAKEKEY",
        "Content-Type": "application/json",
    },
    proxy=False,
)

"""Helper classes for test cases"""


class MockResponse(requests.Response):
    def __init__(self, json_data, status_code):
        super().__init__()
        self._json_data = json_data
        self.status_code = status_code

    def json(self):
        return self._json_data


"""Test cases"""


def test_main(mocker):
    """
    When:
        - Running the 'main' function.
    Then:
        Checks that the 'demisto.results' function was called once with the value 'ok'.
    """
    from CortexAttackSurfaceManagement import main

    params = {
        "url": "https://api-test.com",
        "credentials": {"identifier": "test_id", "password": "test_secret"},
    }
    args = {}
    mocker.patch.object(demisto, "params", return_value=params)
    mocker.patch.object(demisto, "args", return_value=args)

    mocker.patch.object(demisto, "command", return_value="test-module")
    mocker.patch.object(demisto, 'results')
    mocker.patch('CortexAttackSurfaceManagement.Client.list_external_service_request',
                 return_value=EXTERNAL_SERVICE_RESPONSE)
    mocker.patch('CortexAttackSurfaceManagement.Client.get_attack_surface_rule_request',
                 return_value=ASM_GET_ATTACK_SURFACE_RULE_RESPONSE)

    main()
    assert demisto.results.call_count == 1
    assert demisto.results.call_args[0][0] == 'ok'


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


def test_general_500_error(requests_mock, mocker):
    """
    Uses any one endpoint that returns a 500 error for when a response for waitress error is received.

    Given:
        - Mock request for /assets/get_external_services/ that returns a 500 error and text/plain content type.
    When:
        - Running the 'start_remediation_confirmation_scan'.
    Then:
        - Checks that a NotFoundError exception is raised
    """

    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.8.0", "buildNumber": "12345"},
    )

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_external_services/",
        json=GENERAL_500_WAITRESS_ERROR,
        status_code=400
    )

    with pytest.raises(NotFoundError) as err:
        client.list_external_service_request(search_params=["test"])

    assert type(err.value) is NotFoundError


def test_list_external_service_command(requests_mock):
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

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_external_services/",
        json=EXTERNAL_SERVICES_RESPONSE,
    )

    args = {
        "domain": "testdomain.com",
    }

    response = list_external_service_command(args=args, client=client)
    assert response.outputs == EXTERNAL_SERVICES_RESULTS
    assert response.outputs_prefix == "ASM.ExternalService"
    assert response.outputs_key_field == "service_id"


def test_get_attack_surface_rule_command(requests_mock):
    """Tests get_attack_surface_rule_command command function.

    Given:
        - requests_mock instance to generate the appropriate get_attack_surface_rule_command API response,
          loaded from a local JSON file.
    When:
        - Running the 'get_attack_surface_rule_command'.
    Then:
        - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import get_attack_surface_rule_command

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/get_attack_surface_rules/",
        json=ASM_GET_ATTACK_SURFACE_RULE_RESPONSE,
    )

    args = {
        "attack_surface_rule_id": "RdpServer",
        "enabled_status": "ON",
        "priority": "High",
        "category": "Attack Surface Reduction"
    }

    response = get_attack_surface_rule_command(args=args, client=client)
    assert response.outputs == ASM_GET_ATTACK_SURFACE_RULE_RESULTS


def test_get_external_service_command(requests_mock):
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

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_external_service",
        json=EXTERNAL_SERVICE_RESPONSE,
    )

    args = {"service_id": "94232f8a-f001-3292-aa65-63fa9d981427"}

    response = get_external_service_command(args=args, client=client)

    assert response.outputs == EXTERNAL_SERVICE_RESULTS
    assert response.outputs_prefix == "ASM.ExternalService"
    assert response.outputs_key_field == "service_id"


def test_list_external_ip_address_range_command(requests_mock):
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

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_ranges/",
        json=EXTERNAL_RANGES_RESPONSE,
    )

    args = {}

    response = list_external_ip_address_range_command(args=args, client=client)

    assert response.outputs == EXTERNAL_RANGES_RESULTS
    assert response.outputs_prefix == "ASM.ExternalIpAddressRange"
    assert response.outputs_key_field == "range_id"


def test_get_external_ip_address_range_command(requests_mock):
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

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_range/",
        json=EXTERNAL_RANGE_RESPONSE,
    )

    args = {"range_id": "1093124c-ce26-33ba-8fb8-937fecb4c7b6"}

    response = get_external_ip_address_range_command(args=args, client=client)

    assert response.outputs == EXTERNAL_RANGE_RESULTS
    assert response.outputs_prefix == "ASM.ExternalIpAddressRange"
    assert response.outputs_key_field == "range_id"


def test_list_asset_internet_exposure_command(requests_mock):
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

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_assets_internet_exposure/",
        json=EXTERNAL_EXPOSURES_RESPONSE,
    )

    args_name = {"name": "testdomain.com"}
    args_externally_inferred_cves = {"externally_inferred_cves": ["CVE-2020-15778"]}
    args_ipv6s = {"ipv6s": ["2600:1900:4000:9664:0:7::"]}
    args_asm_id_list = {"asm_ids": ["3c176460-8735-333c-b618-8262e2fb660c"]}
    args_aws_cloud_tags = {"aws_cloud_tags": ["Name:AD Lab"]}
    args_gcp_cloud_tags = {"gcp_cloud_tags": ["Name:gcp Lab"]}
    args_azure_cloud_tags = {"azure_cloud_tags": ["Name:azure Lab"]}
    args_has_xdr_agent = {"has_xdr_agent": "NO"}
    args_externally_detected_providers = {"externally_detected_providers": ["Amazon Web Services"]}
    args_has_bu_overrides = {"has_bu_overrides": False}
    args_business_units_list = {"business_units": ["Acme"]}
    args_mac_address = {"mac_address": ["00:11:22:33:44:55"]}

    response_name = list_asset_internet_exposure_command(args=args_name, client=client)
    response_externally_inferred_cves = list_asset_internet_exposure_command(args=args_externally_inferred_cves, client=client)
    response_ipv6s = list_asset_internet_exposure_command(args=args_ipv6s, client=client)
    response_asm_id_list = list_asset_internet_exposure_command(args=args_asm_id_list, client=client)
    response_aws_cloud_tags = list_asset_internet_exposure_command(args=args_aws_cloud_tags, client=client)
    response_gcp_cloud_tags = list_asset_internet_exposure_command(args=args_gcp_cloud_tags, client=client)
    response_azure_cloud_tags = list_asset_internet_exposure_command(args=args_azure_cloud_tags, client=client)
    response_has_xdr_agent = list_asset_internet_exposure_command(args=args_has_xdr_agent, client=client)
    response_externally_detected_providers = list_asset_internet_exposure_command(
        args=args_externally_detected_providers, client=client)
    response_has_bu_overrides = list_asset_internet_exposure_command(args=args_has_bu_overrides, client=client)
    response_business_units_list = list_asset_internet_exposure_command(args=args_business_units_list, client=client)
    response_mac_address = list_asset_internet_exposure_command(args=args_mac_address, client=client)

    assert response_name.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_name.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_name.outputs_key_field == "asm_ids"

    assert response_externally_inferred_cves.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_externally_inferred_cves.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_externally_inferred_cves.outputs_key_field == "asm_ids"

    assert response_ipv6s.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_ipv6s.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_ipv6s.outputs_key_field == "asm_ids"

    assert response_asm_id_list.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_asm_id_list.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_asm_id_list.outputs_key_field == "asm_ids"

    assert response_aws_cloud_tags.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_aws_cloud_tags.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_aws_cloud_tags.outputs_key_field == "asm_ids"

    assert response_gcp_cloud_tags.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_gcp_cloud_tags.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_gcp_cloud_tags.outputs_key_field == "asm_ids"

    assert response_azure_cloud_tags.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_azure_cloud_tags.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_azure_cloud_tags.outputs_key_field == "asm_ids"

    assert response_has_xdr_agent.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_has_xdr_agent.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_has_xdr_agent.outputs_key_field == "asm_ids"

    assert response_externally_detected_providers.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_externally_detected_providers.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_externally_detected_providers.outputs_key_field == "asm_ids"

    assert response_has_bu_overrides.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_has_bu_overrides.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_has_bu_overrides.outputs_key_field == "asm_ids"

    assert response_business_units_list.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_business_units_list.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_business_units_list.outputs_key_field == "asm_ids"

    assert response_mac_address.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response_mac_address.outputs_prefix == "ASM.AssetInternetExposure"
    assert response_mac_address.outputs_key_field == "asm_ids"


def test_get_asset_internet_exposure_command(requests_mock, mocker):
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

    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.8.0", "buildNumber": "12345"},
    )

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/assets/get_asset_internet_exposure/",
        json=EXTERNAL_EXPOSURE_RESPONSE,
    )

    args = {"asm_id": "testdomain.com"}

    response = get_asset_internet_exposure_command(args=args, client=client)

    assert response.outputs == EXTERNAL_EXPOSURE_RESULTS
    assert response.outputs_prefix == "ASM.AssetInternetExposure"
    assert response.outputs_key_field == "asm_ids"


def test_list_remediation_rule_command(requests_mock):
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

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/xpanse_remediation_rules/rules/",
        json=REMEDIATION_RULES_RESPONSE,
    )

    args = {"asm_rule_id": "RdpServer"}

    response = list_remediation_rule_command(args=args, client=client)

    assert response.outputs == REMEDIATION_RULES_RESULTS
    assert response.outputs_prefix == "ASM.RemediationRule"
    assert response.outputs_key_field == "rule_id"


@pytest.mark.parametrize(
    "alert_internal_id, service_id, attack_surface_rule_id, expected_results, raw_response, status_code",
    [
        (
            123,
            "12345abc-123a-1234-a123-efgh12345678",
            "RdpServer",
            RCS_START_SCAN_SUCCESSFUL_RESULTS_201,
            RCS_START_SCAN_SUCCESSFUL_RESPONSE_201,
            201,
        ),
        (
            123,
            "12345abc-123a-1234-a123-efgh12345678",
            "RdpServer",
            RCS_START_SCAN_SUCCESSFUL_RESULTS_200,
            RCS_START_SCAN_SUCCESSFUL_RESPONSE_200,
            200,
        ),
    ],
)
def test_start_remediation_confirmation_scan_successful_codes(
    alert_internal_id,
    service_id,
    attack_surface_rule_id,
    expected_results,
    raw_response,
    status_code,
    requests_mock,
):
    """
    Given:
        - Mock request for /remediation_confirmation_scanning/requests/get_or_create/ that returns a 200.
    When:
        - Running the 'start_remediation_confirmation_scan_command'.
    Then:
        - Checks that the expected outputs, outputs_prefix, and outputs_key_field is returned.
    """
    from CortexAttackSurfaceManagement import start_remediation_confirmation_scan_command

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/remediation_confirmation_scanning/requests/get_or_create/",
        json=raw_response,
        status_code=status_code,
    )

    args = {
        "alert_internal_id": alert_internal_id,
        "service_id": service_id,
        "attack_surface_rule_id": attack_surface_rule_id,
    }

    response = start_remediation_confirmation_scan_command(args=args, client=client)

    assert response.outputs == expected_results
    assert response.outputs_prefix == "ASM.RemediationScan"
    assert response.outputs_key_field == ""


def test_start_remediation_confirmation_scan_failure():
    """
    Given:
        - Mock request for /remediation_confirmation_scanning/requests/get_or_create/ that returns a 200.
    When:
        - Running the 'start_remediation_confirmation_scan_command'.
    Then:
        - Checks that the expected outputs, outputs_prefix, and outputs_key_field is returned.
    """
    from CortexAttackSurfaceManagement import start_remediation_confirmation_scan_command

    args = {
        "alert_internal_id": -1,
        "service_id": "12345abc-123a-1234-a123-efgh12345678",
        "attack_surface_rule_id": "RdpServer",
    }

    with pytest.raises(ValueError) as err:
        start_remediation_confirmation_scan_command(args=args, client=client)

    assert type(err.value) is ValueError
    assert str(err.value) == "Expected a non-negative integer, but got -1."


@pytest.mark.parametrize(
    "alert_internal_id, service_id, attack_surface_rule_id, raw_results, exception_type",
    [
        (
            123,
            "12345abc-123a-1234-a123-efgh12345678",
            "RdpServer",
            RCS_START_SCAN_FAILURE_RESPONSE_100,
            ProcessingError,
        ),
        (None, None, None, GENERAL_API_FAILURE_RESPONSE_400, ProcessingError),
    ],
)
def test_start_remediation_confirmation_failure_codes(
    alert_internal_id,
    service_id,
    attack_surface_rule_id,
    raw_results,
    exception_type,
    requests_mock,
    mocker,
):
    """
    Given:
        - Mock request for /remediation_confirmation_scanning/requests/get_or_create/
          that returns a 400 error and application/json content type.
    When:
        - Running the 'start_remediation_confirmation_scan'.
    Then:
        - Checks that a ProcessingError exception is raised and that the correct error message is returned.
    """
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.8.0", "buildNumber": "12345"},
    )

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/remediation_confirmation_scanning/requests/get_or_create/",
        json=raw_results,
        status_code=400,
        headers={"Content-Type": "application/json"},
    )

    error_code = raw_results.get("reply").get("err_code")
    error_message = raw_results.get("reply").get("err_msg")
    extra_message = raw_results.get("reply").get("err_extra")

    with pytest.raises(exception_type) as err:
        client.start_remediation_confirmation_scan(
            alert_internal_id=alert_internal_id,
            service_id=service_id,
            attack_surface_rule_id=attack_surface_rule_id,
        )

    assert type(err.value) is exception_type
    assert str(err.value) == f"{error_code} - Received error message: '{error_message}. {extra_message}'."


@pytest.mark.parametrize(
    "scan_id, expected_results, raw_response, outputs_key_field",
    [
        (
            "12345abc-123a-1234-a123-efgh12345678",
            RCS_GET_SCAN_STATUS_SUCCESS_REMEDIATED_RESULTS_200,
            RCS_GET_SCAN_STATUS_SUCCESS_REMEDIATED_RESPONSE_200,
            ""
        ),
        (
            "12345abc-123a-1234-a123-efgh12345678",
            RCS_GET_SCAN_STATUS_SUCCESS_UNREMEDIATED_RESULTS_200,
            RCS_GET_SCAN_STATUS_SUCCESS_UNREMEDIATED_RESPONSE_200,
            ""
        ),
        (
            "12345abc-123a-1234-a123-efgh12345678",
            None,
            RCS_GET_SCAN_STATUS_IN_PROGRESS_RESPONSE_200,
            "scan_id"
        ),
        (
            "12345abc-123a-1234-a123-efgh12345678",
            RCS_GET_SCAN_STATUS_FAILED_ERROR_RESULTS_200,
            RCS_GET_SCAN_STATUS_FAILED_ERROR_RESPONSE_200,
            ""
        ),
        (
            "12345abc-123a-1234-a123-efgh12345678",
            RCS_GET_SCAN_STATUS_FAILED_TIMEOUT_RESULTS_200,
            RCS_GET_SCAN_STATUS_FAILED_TIMEOUT_RESPONSE_200,
            ""
        ),
        (
            "12345abc-123a-1234-a123-efgh12345678",
            RCS_GET_SCAN_STATUS_OTHER_RESULTS_200,
            RCS_GET_SCAN_STATUS_OTHER_RESPONSE_200,
            ""
        ),
    ],
)
def test_get_remediation_confirmation_scan_status_successful_codes(
    scan_id, expected_results, raw_response, outputs_key_field, requests_mock, mocker
):
    """
    Given:
        - Mock request for /remediation_confirmation_scanning/requests/get/ that returns a 200.
    When:
        - Running the 'get_remediation_confirmation_scan_status_command'.
    Then:
        - Checks that the expected outputs, outputs_prefix, and outputs_key_field is returned.
    """
    from CortexAttackSurfaceManagement import (
        get_remediation_confirmation_scan_status_command,
    )

    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.8.0", "buildNumber": "12345"},
    )

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/remediation_confirmation_scanning/requests/get/",
        json=raw_response,
        status_code=200,
    )

    args = {"scan_id": scan_id}

    response = get_remediation_confirmation_scan_status_command(args=args, client=client)

    assert response.outputs == expected_results
    assert response.outputs_prefix == "ASM.RemediationScan"
    assert response.outputs_key_field == outputs_key_field


def test_get_remediation_confirmation_scan_status_failure(requests_mock, mocker):
    """
    Given:
        - Mock request for /remediation_confirmation_scanning/requests/get_or_create/
          that returns a 500 error and application/json content type.
    When:
        - Running the 'start_remediation_confirmation_scan'.
    Then:
        - Checks that a ProcessingError exception is raised and that the correct error message is returned.
    """
    mocker.patch.object(
        demisto,
        "demistoVersion",
        return_value={"version": "6.8.0", "buildNumber": "12345"},
    )

    requests_mock.post(
        "https://test.com/api/webapp/public_api/v1/remediation_confirmation_scanning/requests/get/",
        json=RCS_GET_SCAN_FAILURE_RESPONSE_404,
        status_code=400,
        headers={"Content-Type": "application/json"},
    )

    error_code = RCS_GET_SCAN_FAILURE_RESPONSE_404.get("reply").get("err_code")
    error_message = RCS_GET_SCAN_FAILURE_RESPONSE_404.get("reply").get("err_msg")
    extra_message = RCS_GET_SCAN_FAILURE_RESPONSE_404.get("reply").get("err_extra")

    with pytest.raises(ProcessingError) as err:
        client.get_remediation_confirmation_scan_status(scan_id=None)

    assert type(err.value) is ProcessingError
    assert str(err.value) == f"{error_code} - Received error message: '{error_message}. {extra_message}'."
