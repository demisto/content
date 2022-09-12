import io
import json


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
            headers = {
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
            headers = {
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
            headers = {
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
            headers = {
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
            },
            proxy=False,
            auth=None)

    args = {
        'service_id': '94232f8a-f001-3292-aa65-63fa9d981427',
    }

    response = getexternalservice_command(client, args)

    assert response.outputs == EXTERNAL_SERVICE_RESULTS
    assert response.outputs_prefix == 'ASM.GetExternalService'
    assert response.outputs_key_field == 'service_id'


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
            headers = {
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


def test_getexternalipaddressranges_command((requests_mock):
    """Tests asm-getexternalservice_command command function.

        Given:
            - requests_mock instance to generate the appropriate getexternalipaddressranges_command( API response,
              loaded from a local JSON file.
        When:
            - Running the 'getexternalipaddressranges_command('.
        Then:
            - Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getexternalipaddressranges_command(

    from test_data.raw_response import EXTERNAL_RANGES_RESPONSE
    from test_data.expected_results import EXTERNAL_RANGES_RESULTS
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_external_ip_address_ranges/',
                      json=EXTERNAL_RANGES_RESPONSE)

    client = Client(
            base_url='https://test.com/api/webapp/public_api/v1',
            verify=True,
            headers = {
            "HOST": "test.com",
            "Authorizatio": "THISISAFAKEKEY",
            "Content-Type": "application/json"
            },
            proxy=False,
            auth=None)
        args = {}

    response = getexternalipaddressranges_command(client,args)

    assert response.outputs == EXTERNAL_RANGES_RESULTS
    assert response.outputs_prefix == 'ASM.GetExternalIpAddressRanges'
    assert response.outputs_key_field == 'range_id'