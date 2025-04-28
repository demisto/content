from unittest.mock import patch, MagicMock

import demistomock as demisto
import pytest


def test_main(mocker):
    """
    Given:
        - Valid response from ssh command
    When:
        - Running the script
    Then:
        - Ensure results function is called with the expected output
    """
    from ServerLogsDocker import main

    mocker.patch("ServerLogsDocker.check_remote_access_integration_enable")
    mocker.patch.object(demisto, "executeCommand", return_value=[{"Contents": {"output": "output"}}])
    return_results = mocker.patch.object(demisto, "results")
    main()
    return_results.assert_called_with("File: /var/log/demisto/docker.log\noutput")


@patch('ServerLogsDocker.demisto.getModules')
def test_check_remote_access_integration_enable(mock_get_modules):
    """
    Given:
        - RemoteAccess Integration is configured
    When:
        - Running the script
    Then:
        - Does not return any error.
    """
    from ServerLogsDocker import check_remote_access_integration_enable
    mock_get_modules.return_value = {
        'module1': {'brand': 'RemoteAccess v2', 'state': 'active'}
    }
    with patch('ServerLogsDocker.demisto.debug') as mock_debug:
        check_remote_access_integration_enable()
        mock_debug.assert_called_with('RemoteAccess v2 is enabled.')


@pytest.fixture
def mock_return_error():
    with patch('ServerLogsDocker.return_error', MagicMock()) as mock_return_error:
        yield mock_return_error


@patch('ServerLogsDocker.demisto.getModules')
def test_check_remote_access_integration_disable(mock_get_modules, mock_return_error):
    with patch('ServerLogsDocker.return_error', MagicMock()) as mock_return_error:
        from ServerLogsDocker import check_remote_access_integration_enable
        mock_get_modules.return_value = {
                'module1': {'brand': 'Test', 'state': 'active'}
        }
        check_remote_access_integration_enable()
        mock_return_error.assert_called_once()
