from inspect import isclass
import pytest
from unittest.mock import MagicMock
from CyberTriage import CyberTriageClient, IS_2XX


SERVER_URL = 'https://test_url.com'


@pytest.fixture()
def client():
    client = CyberTriageClient(
        server=SERVER_URL, rest_port='test', api_key='test', user='test',
        password='test', verify_server_cert=True, ok_codes=(200,)
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
        'incident_name': 'MADEUP'
    }
    mock2 = MagicMock()
    client.triage_endpoint = mock2
    triage_endpoint_command(client, args)
    client.triage_endpoint.assert_called_once_with(True, False, 'made-up-endpoint', '', 'MADEUP')


is_2xx_test_data = [
    (200, True),
    (201, True),
    (234, True),
    (288, True),
    (300, False),
    (391, False),
    (101, False),
    (404, False),
    (505, False),
    (606, False),
    (-200, False),
    (-245, False),
    ('200', TypeError),
    ('help', TypeError)
]


@pytest.mark.parametrize('argument,expected', is_2xx_test_data)
def test_IS_2XX(argument, expected):
    if isclass(expected) and issubclass(expected, Exception):
        with pytest.raises(expected_exception=expected):
            IS_2XX(argument)
    else:
        assert IS_2XX(argument) == expected
