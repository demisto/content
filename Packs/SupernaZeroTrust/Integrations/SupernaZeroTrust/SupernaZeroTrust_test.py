"""Unit tests for SupernaZeroTrust integration"""

from SupernaZeroTrust import Client


def test_client_initialization():
    """Test that client initializes correctly"""
    client = Client(
        base_url="https://test.example.com",
        api_key="test-key",
        verify=False,
        proxy=False,
    )
    assert client._base_url.rstrip("/") == "https://test.example.com"


def test_snapshot_command(mocker):
    """Test snapshot-critical-paths command"""
    from SupernaZeroTrust import snapshot_critical_paths_command

    mock_client = mocker.Mock()
    mock_client.snapshot_critical_paths.return_value = {"status": "success"}

    result = snapshot_critical_paths_command(mock_client)

    assert result.outputs_prefix == "SupernaZeroTrust.Snapshot"
    assert result.outputs["Status"] == "Success"
    assert result.outputs["Result"] == {"status": "success"}


def test_lockout_command(mocker):
    """Test lockout-user command"""
    from SupernaZeroTrust import lockout_user_command

    mock_client = mocker.Mock()
    mock_client.lockout_user.return_value = {"status": "success"}

    result = lockout_user_command(mock_client, {"username": "testuser"})

    assert result.outputs_prefix == "SupernaZeroTrust.Lockout"
    assert result.outputs["Username"] == "testuser"
    assert result.outputs["Result"] == {"status": "success"}


def test_unlock_command(mocker):
    """Test unlock-user command"""
    from SupernaZeroTrust import unlock_user_command

    mock_client = mocker.Mock()
    mock_client.unlock_user.return_value = {"status": "success"}

    result = unlock_user_command(mock_client, {"username": "testuser"})

    assert result.outputs_prefix == "SupernaZeroTrust.Unlock"
    assert result.outputs["Username"] == "testuser"
    assert result.outputs["Result"] == {"status": "success"}
