import json
import io
import demistomock as demisto
import pytest
from TrendMicroVisionOneCommands import Client

MOCK_URL = "https://trendmicro-fake-api.com"
MOCK_API_KEY = "a1b2c3d4e5"
MOCK_APP_ID = "a1b2c3d4e5"

client = Client(
    base_url=MOCK_URL,
    api_key=MOCK_API_KEY,
    app_id=MOCK_APP_ID,
    proxy=False,
    verify=False,
)


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


# TODO: REMOVE the following dummy unit test function
def test_baseintegration_dummy():
    """Tests helloworld-say-hello command function.

    Checks the output of the command function with the expected output.

    No mock is needed here because the say_hello_command does not call
    any external API.
    """
    from BaseIntegration import Client, baseintegration_dummy_command

    client = Client(base_url='some_mock_url', verify=False)
    args = {
        'dummy': 'this is a dummy response'
    }
    response = baseintegration_dummy_command(client, args)

    mock_response = util_load_json('test_data/baseintegration-dummy.json')

    assert response.outputs == mock_response
# TODO: ADD HERE unit tests for every command
