"""
Tests module for Cortex Attack Surface Management integration.
"""


def test_format_asm_id_func(requests_mock):
    """Tests format_asm_id helper function.

        Given:
            - Mock JSON pre-formatting from the list_asset_internet_exposure_command function
        When:
            - Sending JSON to format_asm_id function.
        Then:
            - Checks the output of the helper function with the expected output.
    """
    from CortexAttackSurfaceManagement import format_asm_id

    from test_data.raw_response import INTERNET_EXPOSURE_PRE_FORMAT
    from test_data.expected_results import INTERNET_EXPOSURE_POST_FORMAT

    response = format_asm_id(INTERNET_EXPOSURE_PRE_FORMAT)

    assert response == INTERNET_EXPOSURE_POST_FORMAT


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
    from CortexAttackSurfaceManagement import Client, list_external_service_command

    from test_data.raw_response import EXTERNAL_SERVICES_RESPONSE
    from test_data.expected_results import EXTERNAL_SERVICES_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_external_services/',
                       json=EXTERNAL_SERVICES_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

    args = {
        'domain': 'testdomain.com',
    }

    response = list_external_service_command(client, args)

    assert response.outputs == EXTERNAL_SERVICES_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalService'
    assert response.outputs_key_field == 'service_id'


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
    from CortexAttackSurfaceManagement import Client, get_external_service_command

    from test_data.raw_response import EXTERNAL_SERVICE_RESPONSE
    from test_data.expected_results import EXTERNAL_SERVICE_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_external_service',
                       json=EXTERNAL_SERVICE_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)

    args = {
        'service_id': '94232f8a-f001-3292-aa65-63fa9d981427'
    }

    response = get_external_service_command(client, args)

    assert response.outputs == EXTERNAL_SERVICE_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalService'
    assert response.outputs_key_field == 'service_id'


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
    from CortexAttackSurfaceManagement import Client, list_external_ip_address_range_command

    from test_data.raw_response import EXTERNAL_RANGES_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGES_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_ranges/',
                       json=EXTERNAL_RANGES_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {}

    response = list_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGES_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalIpAddressRange'
    assert response.outputs_key_field == 'range_id'


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
    from CortexAttackSurfaceManagement import Client, get_external_ip_address_range_command

    from test_data.raw_response import EXTERNAL_RANGE_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGE_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_range/',
                       json=EXTERNAL_RANGE_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'range_id': '1093124c-ce26-33ba-8fb8-937fecb4c7b6'
    }

    response = get_external_ip_address_range_command(client, args)

    assert response.outputs == EXTERNAL_RANGE_RESULTS
    assert response.outputs_prefix == 'ASM.ExternalIpAddressRange'
    assert response.outputs_key_field == 'range_id'


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
    from CortexAttackSurfaceManagement import Client, list_asset_internet_exposure_command

    from test_data.raw_response import EXTERNAL_EXPOSURES_RESPONSE
    from test_data.expected_results import EXTERNAL_EXPOSURES_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_assets_internet_exposure/',
                       json=EXTERNAL_EXPOSURES_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'name': 'testdomain.com'
    }

    response = list_asset_internet_exposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response.outputs_prefix == 'ASM.AssetInternetExposure'
    assert response.outputs_key_field == 'asm_ids'


def test_get_asset_internet_exposure_command(requests_mock):
    """Tests get_asset_internet_exposure_command function.

        Given:
            - requests_mock instance to generate the appropriate get_asset_internet_exposure_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'get_asset_internet_exposure_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, get_asset_internet_exposure_command

    from test_data.raw_response import EXTERNAL_EXPOSURE_RESPONSE
    from test_data.expected_results import EXTERNAL_EXPOSURE_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_asset_internet_exposure/',
                       json=EXTERNAL_EXPOSURE_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'asm_id': 'testdomain.com'
    }

    response = get_asset_internet_exposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURE_RESULTS
    assert response.outputs_prefix == 'ASM.AssetInternetExposure'
    assert response.outputs_key_field == 'asm_ids'


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
    from CortexAttackSurfaceManagement import Client, list_remediation_rule_command

    from test_data.raw_response import REMEDIATION_RULES_RESPONSE
    from test_data.expected_results import REMEDIATION_RULES_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/xpanse_remediation_rules/rules/',
                       json=REMEDIATION_RULES_RESPONSE)

    client = Client(
        base_url='https://test.com/api/webapp/public_api/v1',
        verify=True,
        headers={
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
        },
        proxy=False)
    args = {
        'asm_rule_id': 'RdpServer'
    }

    response = list_remediation_rule_command(client, args)

    assert response.outputs == REMEDIATION_RULES_RESULTS
    assert response.outputs_prefix == 'ASM.RemediationRule'
    assert response.outputs_key_field == 'rule_id'
