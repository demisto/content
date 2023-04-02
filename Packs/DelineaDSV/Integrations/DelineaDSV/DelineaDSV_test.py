import pytest

from DelineaDSV import Client, dsv_secret_get_command
from test_data.context import SECRET_GET_ARGS_CONTEXT
from test_data.http_responses import SECRET_GET_ARGS_RAW_RESPONSE

SECRET_GET_ARGS = {"name": "accounts/xsoar"}


@pytest.mark.parametrize('command, args, http_response, context', [
    (dsv_secret_get_command, SECRET_GET_ARGS, SECRET_GET_ARGS_RAW_RESPONSE,
     SECRET_GET_ARGS_CONTEXT)
])
def test_delinea_commands(command, args, http_response, context, mocker):

    mocker.patch.object(Client, '_generate_token')
    client = Client(server_url="https://example.com", client_id="example",
                    client_secret="test@123", provider="Local Login",
                    proxy=False, verify=False)

    mocker.patch.object(Client, '_http_request', return_value=http_response)

    outputs = command(client, **args)
    results = outputs.to_context()

    assert results.get("EntryContext") == context
