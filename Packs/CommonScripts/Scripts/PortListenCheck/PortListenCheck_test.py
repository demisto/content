import pytest
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


@pytest.fixture
def _socket(mocker):
    """
    Mocks the socket connection and will always return a 0 indicating a successful connection
    """
    socket = mocker.MagicMock()
    socket.connect_ex.return_value = 0
    mocker.patch('socket.socket', return_value=socket)
    return socket


def test_port_listen_check_success():
    """
    Given:
        Valid port and host
    When:
        Attempting to connect to a host on a given port
    Then:
        - human_readable should indicate the connection was a success and the port is open
        - outputs should indicate portOpen is True
    """
    from PortListenCheck import port_listen_check
    expected_human_readable = 'Port 80 is open on host: testhost.com'
    expected_outputs = {'portOpen': True}

    result = port_listen_check(80, "testhost.com")
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_outputs
