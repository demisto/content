import json
import io


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
