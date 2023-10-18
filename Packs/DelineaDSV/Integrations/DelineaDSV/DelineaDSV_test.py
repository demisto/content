import pytest
from DelineaDSV import Client, dsv_secret_get_command
from test_data.context import SECRET_GET_ARGS_CONTEXT
from test_data.http_responses import SECRET_GET_ARGS_RAW_RESPONSE
from unittest.mock import patch

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


SAMPLE_RESPONSE = {
    "accessToken": "sample_access_token"
}


@pytest.fixture
def client_with_mocked_http_request():
    with patch('DelineaDSV.Client._http_request') as mock_http_request:
        mock_http_request.return_value = SAMPLE_RESPONSE
        yield Client(
            server_url="https://example.com",
            client_id="example",
            client_secret="test@123",
            provider="Local Login",
            proxy=False,
            verify=False
        )


def test_generate_token(client_with_mocked_http_request):
    token = client_with_mocked_http_request._generate_token()
    assert token == "Bearer sample_access_token"
