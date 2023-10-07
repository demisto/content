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
    RCS_GET_SCAN_STATUS_OTHER_RESPONSE_200
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
    RCS_GET_SCAN_STATUS_OTHER_RESULTS_200
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

    args = {"name": "testdomain.com"}

    response = list_asset_internet_exposure_command(args=args, client=client)

    assert response.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response.outputs_prefix == "ASM.AssetInternetExposure"
    assert response.outputs_key_field == "asm_ids"


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
