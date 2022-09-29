import pytest
from unittest.mock import MagicMock
from CyberTriage import CyberTriageClient
SERVER_URL = 'https://test_url.com'


@pytest.fixture()
def client():
    client = CyberTriageClient(
        server=SERVER_URL, rest_port='test', api_key='test', user='test', password='test', verify_server_cert=True, ok_codes=(200,)
    )
    return client


def test_test_connection_command(client: CyberTriageClient):
    """
    Args:
        client (pytest.fixture): CyberTriageClient instance whose methods will be mocked

    Given:
        - a CyberTriage client
    Then:
        - ensure triage_endpoint is called once
    """
    from CyberTriage import test_connection_command
    mock1 = MagicMock()
    client.test_connection = mock1
    test_connection_command(client)
    client.test_connection.assert_called_once()


def test_triage_endpoint_command(client: CyberTriageClient):
    """
    Args:
        client (pytest.fixture): CyberTriageClient instance whose methods will be mocked

    Given:
        - a CyberTriage client
    When:
        - the command arguments are as in the fake data below
    Then:
        - ensure triage_endpoint is called once with the expected arguments
    """
    from CyberTriage import triage_endpoint_command
    args = {
        'malware_hash_upload': 'yes',
        'malware_file_upload': 'no',
        'endpoint': 'made-up-endpoint',
        'scan_options': '',
        'incident_name': 'MADEUP'
    }
    mock2 = MagicMock()
    client.triage_endpoint = mock2
    triage_endpoint_command(client, args)
    client.triage_endpoint.assert_called_once_with(True, False, 'made-up-endpoint', '', 'MADEUP')
