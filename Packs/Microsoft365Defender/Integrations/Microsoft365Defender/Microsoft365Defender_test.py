"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import json
import io

from Microsoft365Defender import *


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_convert_incident():
    """
    Check for None input
    """
    empty_incident = {'ID': None,
                      'Display Name': None,
                      'Assigned User': None,
                      'Classification': None,
                      'Event Type': None,
                      'Occurred': None,
                      'Updated': None,
                      'Status': None,
                      'Severity': None,
                      'Tags': None,
                      'RawJSON': None}

    assert convert_incident(None) == empty_incident

def test_microsoft_365_defender_incidents_list_command(client,args):
    """
    Test invalid limit - negative, non number, bigger than 100
    Test empty params
    Test empty client
    Test client with no auth
    Args:
        client:
        args:

    Returns:

    """
    pass
def test_list_incidents_request(status: Optional[str], assigned_to: str, limit: str, timeout=TIMEOUT):

# TODO: REMOVE the following dummy unit test function
# def test_baseintegration_dummy():
#     """Tests helloworld-say-hello command function.
#
#     Checks the output of the command function with the expected output.
#
#     No mock is needed here because the say_hello_command does not call
#     any external API.
#     """
#     from BaseIntegration import Client, baseintegration_dummy_command
#
#     client = Client(base_url='some_mock_url', verify=False)
#     args = {
#         'dummy': 'this is a dummy response'
#     }
#     response = baseintegration_dummy_command(client, args)
#
#     mock_response = util_load_json('test_data/baseintegration-dummy.json')
#
#     assert response.outputs == mock_response
# # TODO: ADD HERE unit tests for every command
