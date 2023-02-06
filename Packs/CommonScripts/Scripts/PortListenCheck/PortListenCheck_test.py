import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def test_port_listen_check_success(mocker):
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

    # Setup a socket connection which is successful
    socket = mocker.MagicMock()
    socket.connect_ex.return_value = 0
    mocker.patch('socket.socket', return_value=socket)

    expected_human_readable = 'Port 80 is open on host: testhost.com'
    expected_outputs = {'portOpen': True}

    result = port_listen_check(80, "testhost.com")
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_outputs


def test_port_listen_check_fail(mocker):
    """
    Given:
        Invalid port and host
    When:
        Attempting to connect to a host on a given port
    Then:
        - human_readable should indicate the connection was a failure and the port is closed
        - outputs should indicate portOpen is False
    """
    from PortListenCheck import port_listen_check

    # Setup a socket connection which is unsuccessful
    socket = mocker.MagicMock()
    socket.connect_ex.return_value = 1
    mocker.patch('socket.socket', return_value=socket)

    expected_human_readable = 'Port 80 is not open on host: testhost.com'
    expected_outputs = {'portOpen': False}

    result = port_listen_check(80, "testhost.com")
    assert result.readable_output == expected_human_readable
    assert result.outputs == expected_outputs


def test_main(mocker):
    """
    Given:
        Valid port and host
    When:
        Attempting to connect to a host on a given port using the main method
    Then:
        - outputs should indicate portOpen is True
    """
    from PortListenCheck import main

    # Setup a socket connection which is successful
    socket = mocker.MagicMock()
    socket.connect_ex.return_value = 0
    mocker.patch('socket.socket', return_value=socket)

    # Patch Demisto objects
    mocker.patch.object(demisto, 'args', return_value={'port': '80', 'host': 'testhost.com'})
    mocker.patch.object(demisto, 'results')

    # Execute Script
    main()

    # Validate Outputs
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['note']
    assert results[0]["EntryContext"]["portOpen"]
