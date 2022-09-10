"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import pytest
import io
import json
from CommonServerPython import *
from CommonServerPython import Common
#from CortexAttackSurfaceManagement import Client, getexternalservices_command, getexternalservice_command, getexternalipaddressranges_command, getexternalipaddressrange_command, getassetsinternetexposure_command, getassetinternetexposure_command


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_getexternalservices_command(requests_mock):
    """Tests asm-getexternalservices_command command function.

    Checks the output of the command function with the expected output.
    """
    from CortexAttackSurfaceManagement import Client, getexternalservices_command

    mock_response_result = util_load_json('test_data/getexternalservices_result.json')
    mock_response_raw = util_load_json('test_data/getexternalservices_raw.json')
    requests_mock.post('https://test.com/api/webapp/public_api/v1/assets/get_external_services/',
                      json=mock_response_raw)

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

    assert response.outputs == mock_response_result
    assert response.outputs_prefix == 'ASM.GetExternalServices'
    assert response.outputs_key_field == 'service_id'
# TODO: ADD HERE unit tests for every command d
