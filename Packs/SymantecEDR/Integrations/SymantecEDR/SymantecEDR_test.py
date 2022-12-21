"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import pytest
import json
import io
from CommonServerPython import DemistoException
from SymantecEDRDev import Client, get_file_instance_command


def util_load_json(path):
    with io.open(path, mode='r') as f:
        return json.loads(f.read())


client = Client(
    base_url="http://host:port",
    secret_key="test_123",
    client_key="test@12345",
    verify=False,
    proxy=False
)

FILE_INSTANCE_RESPONSE = util_load_json('test_data/file_instance_data.json')

@pytest.mark.parametrize('raw_response, expected', [(FILE_INSTANCE_RESPONSE,
                                                    FILE_INSTANCE_RESPONSE
def test_get_file_instance_command(mocker, raw_response, expected):
    """
    Tests get_get_file_instance_command function.

        Given:
            - mocker object.
            - raw_response test data.
            - expected output.

        When:
            - Running the 'get_file_instance_command'.

        Then:
            -  Checks the output of the command function with the expected output.
    """
    args = {"limit": 1}
    mocker.patch.object(client, 'query_request_api', side_effect=[raw_response])
    command_results = get_file_instance_command(client, args)
    # results is CommandResults list
    context_detail = command_results.to_context()['Contents']
    assert context_detail == expected.get("result")

