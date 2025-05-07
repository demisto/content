
from demisto_sdk.commands.common.handlers import JSON_Handler
from CommonServerPython import *

import json

MOCK_BASEURL = "https://example.com"
MOCK_API = "api_key"



def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from BaseIntegration import Client, baseintegration_dummy_command

    client = Client(base_url="some_mock_url", verify=False)
    args = {"dummy": "this is a dummy response", "dummy2": "a dummy value"}
    response = baseintegration_dummy_command(client, args)

    assert response.outputs == args


# TODO: ADD HERE unit tests for every command
