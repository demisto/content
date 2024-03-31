import json
from MatterMost_V2 import get_team_command, list_channels_command, create_channel_command, add_channel_member_command, remove_channel_member_command, list_users_command, close_channel_command, send_file_command
import pytest


def util_load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def http_mock(method: str, url_suffix: str = "", full_url: str = "", params: dict = {}, data: dict = {}, files: dict = {}):

    if url_suffix == "/api/v4/teams/name/team_name":
        return util_load_json("test_data/get_team_response.json")
    elif url_suffix == '/api/v4/teams/team_id/channels' or url_suffix == '/api/v4/teams/team_id/channels/private':
        return util_load_json("test_data/list_channels_response.json")
    elif url_suffix == '/api/v4/channels':
        return util_load_json("test_data/create_channel_response.json")
    elif url_suffix == '/api/v4/users':
        return util_load_json("test_data/list_users_response.json")
    elif url_suffix == '/api/v4/files':
        return util_load_json("test_data/send_file_response.json")
    else:
        return {}


@pytest.fixture(autouse=True)
def client(mocker):
    from MatterMost_V2 import Client

    headers = {"Authorization": "Token mock"}
    mocker.patch.object(Client, "_http_request", side_effect=http_mock)
    return Client(
        base_url='mock url',
        headers=headers,
        verify=True,
        proxy=False,
        bot_access_token='bot_access_token',
        personal_access_token='personal_access_token',
        team_name='team_name',
        notification_channel='notification_channel',
    )


def test_get_team_command(client):
    """
    Given: A mock MatterMost client.
    When: Running get_team_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name'}
    results = get_team_command(client, args)
    assert results.outputs.get('name') == 'team_name'


def test_list_channels_command(client):
    """
    Given: A mock MatterMost client.
    When: Running list_channels_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'include_private_channels': True}
    results = list_channels_command(client, args)
    assert results.outputs[0].get('name') == 'name'
    assert len(results.outputs) == 2


def test_create_channel_command(client):
    """
    Given: A mock MatterMost client.
    When: Running create_channel_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'name': 'channel_name',
            'display_name': 'display_name',
            'type': 'Public',
            'purpose': 'purpose',
            'header': 'header', }
    results = create_channel_command(client, args)
    assert results.outputs.get('name') == 'name'


def test_add_channel_member_command(client):
    """
    Given: A mock MatterMost client.
    When: Running add_channel_member_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name',
            'user_id': 'user_id', }
    results = add_channel_member_command(client, args)
    assert 'The member user_id was added to the channel successfully' in results.readable_output


def test_remove_channel_member_command(client):
    """
    Given: A mock MatterMost client.
    When: Running remove_channel_member_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name',
            'user_id': 'user_id', }
    results = remove_channel_member_command(client, args)
    assert 'The member user_id was removed from the channel successfully.' in results.readable_output


def test_list_users_command(client):
    """
    Given: A mock MatterMost client.
    When: Running list_users_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_id': 'channel_id', }
    results = list_users_command(client, args)
    assert results.outputs[0].get('first_name') == 'first_name'


def test_close_channel_command(client):
    """
    Given: A mock MatterMost client.
    When: Running close_channel_command with a team name.
    Then: Ensure we get the result.
    """
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name', }
    results = close_channel_command(client, args)
    assert 'The channel channel_name was delete successfully.' in results.readable_output


def test_send_file_command(client, mocker):
    """
    Given: A mock MatterMost client.
    When: Running send_file_command with a team name.
    Then: Ensure we get the result.
    """
    expected_file_info = {
        'name': 'test_file.txt',
        'path': '/path/to/test_file.txt'
    }
    mocker.patch('MatterMost_V2.demisto.getFilePath', return_value=expected_file_info)
    mocker.patch.object(client, 'send_file_request', return_value=util_load_json("test_data/send_file_response.json"))
    
    args = {'team_name': 'team_name',
            'channel_name': 'channel_name', }
    results = send_file_command(client, args)
    assert 'file test_file.txt was successfully sent to channel channel_name' in results.readable_output
