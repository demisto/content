from inspect import isclass
from unittest.mock import MagicMock

import pytest
from CyberTriage import IS_2XX, CyberTriageClient

SERVER_URL = "https://test_url.com"


@pytest.fixture()
def client():
    client = CyberTriageClient(
        server=SERVER_URL,
        rest_port="test",
        api_auth_token="test",
        user="test",
        password="test",
        verify_server_cert=True,
    )
    return client


def test_test_connection_command(client: CyberTriageClient):
    """
    Given:
        - a CyberTriage client with test_connection mocked
    Then:
        - ensure test_connection is called once
    """
    from CyberTriage import test_connection_command

    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    client.test_connection = MagicMock(return_value=mock_response)
    test_connection_command(client)
    client.test_connection.assert_called_once()


def test_triage_endpoint_command(client: CyberTriageClient):
    """
    Given:
        - a CyberTriage client with triage_endpoint mocked
    When:
        - the command arguments are as specified below
    Then:
        - ensure triage_endpoint is called once with the expected arguments
    """
    from CyberTriage import triage_endpoint_command

    args = {
        "malware_scan_requested": "yes",
        "send_content": "no",
        "host_name": "made-up-endpoint",
        "incident_name": "MADEUP",
    }
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}
    mock_response.raise_for_status.return_value = None
    client.triage_endpoint = MagicMock(return_value=mock_response)
    triage_endpoint_command(client, args)
    client.triage_endpoint.assert_called_once_with(True, False, "made-up-endpoint", "", "MADEUP", "")


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
    ("200", TypeError),
    ("help", TypeError),
]


@pytest.mark.parametrize("argument,expected", is_2xx_test_data)
def test_IS_2XX(argument, expected):
    if isclass(expected) and issubclass(expected, Exception):
        with pytest.raises(expected_exception=expected):
            IS_2XX(argument)
    else:
        assert IS_2XX(argument) == expected
