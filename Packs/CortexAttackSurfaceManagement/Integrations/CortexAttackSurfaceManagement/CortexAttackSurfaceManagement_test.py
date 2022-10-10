"""
Tests module for Cortex Attack Surface Management integration.
"""

def test_getexternalservices_command(requests_mock):
    """Tests asm-getexternalservices_command command function.

        Given:
            - requests_mock instance to generate the appropriate getexternalservices_command API response,
              loaded from a local JSON file.
        When:
            - Running the 'getexternalservices_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getexternalservices_command

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
        proxy=False,
        auth=None)

    args = {
        'domain': 'testdomain.com',
    }

    response = getexternalservices_command(client, args)

    assert response.outputs == EXTERNAL_SERVICES_RESULTS
    assert response.outputs_prefix == 'ASM.GetExternalServices'
    assert response.outputs_key_field == 'service_id'


def test_getexternalservice_command(requests_mock):
    """Tests asm-getexternalservice_command command function.

        Given:
            - requests_mock instance to generate the appropriate getexternalservice_command API response,
              loaded from a local JSON file.
        When:
            - Running the 'getexternalservice_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getexternalservice_command

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
        proxy=False,
        auth=None)

    args = {
        'service_id': '94232f8a-f001-3292-aa65-63fa9d981427'
    }

    response = getexternalservice_command(client, args)

    assert response.outputs == EXTERNAL_SERVICE_RESULTS
    assert response.outputs_prefix == 'ASM.GetExternalService'
    assert response.outputs_key_field == 'service_id'


def test_getexternalipaddressranges_command(requests_mock):
    """Tests getexternalipaddressranges_command function.

        Given:
            - requests_mock instance to generate the appropriate getexternalipaddressranges_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'getexternalipaddressranges_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getexternalipaddressranges_command

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
        proxy=False,
        auth=None)
    args = {}

    response = getexternalipaddressranges_command(client, args)

    assert response.outputs == EXTERNAL_RANGES_RESULTS
    assert response.outputs_prefix == 'ASM.GetExternalIpAddressRanges'
    assert response.outputs_key_field == 'range_id'


def test_getexternalipaddressrange_command(requests_mock):
    """Tests getexternalipaddressrange_command function.

        Given:
            - requests_mock instance to generate the appropriate getexternalipaddressrange_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'getexternalipaddressrange_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getexternalipaddressrange_command

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
        proxy=False,
        auth=None)
    args = {
        'range_id': '1093124c-ce26-33ba-8fb8-937fecb4c7b6'
    }

    response = getexternalipaddressrange_command(client, args)

    assert response.outputs == EXTERNAL_RANGE_RESULTS
    assert response.outputs_prefix == 'ASM.GetExternalIpAddressRange'
    assert response.outputs_key_field == 'range_id'


def test_getassetsinternetexposure_command(requests_mock):
    """Tests ggetassetsinternetexposure_command function.

        Given:
            - requests_mock instance to generate the appropriate getassetsinternetexposure_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'getassetsinternetexposure_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getassetsinternetexposure_command

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
        proxy=False,
        auth=None)
    args = {
        'name': 'testdomain.com'
    }

    response = getassetsinternetexposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURES_RESULTS
    assert response.outputs_prefix == 'ASM.GetAssetsInternetExposure'
    assert response.outputs_key_field == 'asm_ids'


def test_getassetinternetexposure_command(requests_mock):
    """Tests ggetassetinternetexposure_command function.

        Given:
            - requests_mock instance to generate the appropriate getassetinternetexposure_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'getassetinternetexposure_command'.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getassetinternetexposure_command

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
        proxy=False,
        auth=None)
    args = {
        'asm_id': 'testdomain.com'
    }

    response = getassetinternetexposure_command(client, args)

    assert response.outputs == EXTERNAL_EXPOSURE_RESULTS
    assert response.outputs_prefix == 'ASM.GetAssetInternetExposure'
    assert response.outputs_key_field == 'asm_ids'
