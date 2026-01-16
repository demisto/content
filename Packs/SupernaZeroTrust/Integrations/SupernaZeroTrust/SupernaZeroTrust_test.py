"""Unit tests for SupernaZeroTrust integration"""

import pytest
from SupernaZeroTrust import Client


def test_client_initialization():
    """Test that client initializes correctly"""
    client = Client(
        base_url='https://test.example.com',
        verify=False,
        proxy=False,
        headers={'api_key': 'test-key'}
    )
    assert client._base_url == 'https://test.example.com/'


def test_snapshot_command(mocker):
    """Test snapshot-critical-paths command"""
    from SupernaZeroTrust import snapshot_critical_paths_command

    mock_client = mocker.Mock()
    mock_client.snapshot_critical_paths.return_value = {'status': 'success'}

    result = snapshot_critical_paths_command(mock_client)

    assert result.outputs == {'status': 'success'}
    assert 'SupernaZeroTrust.Snapshot.Result' in result.outputs_prefix


def test_lockout_command(mocker):
    """Test lockout-user command"""
    from SupernaZeroTrust import lockout_user_command

    mock_client = mocker.Mock()
    mock_client.lockout_user.return_value = {'status': 'success'}

    result = lockout_user_command(mock_client, {'username': 'testuser'})

    assert result.outputs == {'status': 'success'}
    assert 'SupernaZeroTrust.Lockout.Result' in result.outputs_prefix


def test_unlock_command(mocker):
    """Test unlock-user command"""
    from SupernaZeroTrust import unlock_user_command

    mock_client = mocker.Mock()
    mock_client.unlock_user.return_value = {'status': 'success'}

    result = unlock_user_command(mock_client, {'username': 'testuser'})

    assert result.outputs == {'status': 'success'}
    assert 'SupernaZeroTrust.Unlock.Result' in result.outputs_prefix
