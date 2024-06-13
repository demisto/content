import pytest
from unittest.mock import patch, MagicMock
from CommonServerPython import CommandResults
import demistomock as demisto

# Import the functions and classes from the integration
from PrivX import Client, privx_get_cert_command, privx_get_secret_command

params = demisto.params()


@pytest.fixture
def mock_params():
    return {
        'ca-certificate': 'test-ca-cert',
        'hostname': 'test-hostname',
        'port': 1234,
        'oauth-client-id': 'test-client-id',
        'oauth-client-secret': 'test-client-secret',
        'api-client-id': 'test-api-client-id',
        'api-client-secret': 'test-api-client-secret',
        'public-key': 'test-public-key',
    }


@pytest.fixture
def mock_client(mock_params):
    with patch('PrivX.params', mock_params), patch('privx_api.PrivXAPI.authenticate', return_value=True):
        return Client(
            base_url='',
            verify=True,
            headers={},
            proxy=False
        )


def test_privx_get_cert_command(mock_client):
    args = {
        'public-key': 'ssh-rsa AAAA...',
        'role-id': 'role-id',
        'service': 'SSH',
        'username': 'user',
        'hostname': 'hostname',
        'host-id': 'host-id',
        'api-client-id': 'test-api-client-id',
        'api-client-secret': 'test-api-client-secret',
    }

    with patch('PrivX.api.get_target_host_credentials') as mock_get_target_host_credentials:
        mock_get_target_host_credentials.return_value = MagicMock(ok=True, data={
            "certificates": [
                {"data_string": "cert1-data"},
                {"data_string": "cert2-data"}
            ]
        })

        result = privx_get_cert_command(mock_client, args)
        assert isinstance(result, CommandResults)
        assert 'cert1-data' in result.outputs['certificates']
        assert 'cert2-data' in result.outputs['certificates']


def test_privx_get_secret_command(mock_client):
    args = {
        'name': 'secret-name',
        'api-client-id': 'test-api-client-id',
        'api-client-secret': 'test-api-client-secret',
    }

    with patch('PrivX.api.get_secret') as mock_get_secret:
        mock_get_secret.return_value = MagicMock(ok=True, data={
            "data": "secret-data"
        })

        result = privx_get_secret_command(mock_client, args)
        assert isinstance(result, CommandResults)
        assert result.outputs == 'secret-data'


if __name__ == '__main__':
    pytest.main()
