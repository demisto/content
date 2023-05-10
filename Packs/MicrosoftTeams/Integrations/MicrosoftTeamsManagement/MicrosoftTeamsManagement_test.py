import io
import json

import pytest

from MicrosoftTeamsManagement import (Client, add_member, archive_team,
                                      clone_team, create_team,
                                      create_team_from_group, delete_team,
                                      get_member, get_team, list_joined_teams,
                                      list_members, list_teams, remove_member,
                                      unarchive_team, update_member,
                                      update_team)


@pytest.fixture()
def client(mocker):
    mocker.patch('MicrosoftTeamsManagement.MicrosoftClient.get_access_token', return_value='token')
    return Client('app_id', False, False, 'Device Code', '', '')


def load_test_data(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_create_team(requests_mock, client):
    """
    Given:
        - Team display name and owner ID to create team of

    When:
        - Creating a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    requests_mock.post(f'{client.ms_client._base_url}/v1.0/teams', status_code=202)
    display_name = 'TestTeamName'
    owner = 'uuid'
    args = {
        'display_name': display_name,
        'owner': owner,
    }
    result = create_team(client, args)
    assert requests_mock.request_history[0].json() == {
        'template@odata.bind': "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
        'displayName': display_name,
        'description': None,
        'visibility': 'public',
        'members': [{
            '@odata.type': '#microsoft.graph.aadUserConversationMember',
            'roles': ['owner'],
            'user@odata.bind': f"https://graph.microsoft.com/v1.0/users('{owner}')",
        }],
        'guestSettings': {
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
        },
        'memberSettings': {
            'allowCreatePrivateChannels': False,
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
            'allowAddRemoveApps': False,
            'allowCreateUpdateRemoveTabs': False,
            'allowCreateUpdateRemoveConnectors': False,
        },
        'messagingSettings': {
            'allowUserEditMessages': False,
            'allowUserDeleteMessages': False,
            'allowOwnerDeleteMessages': False,
            'allowTeamMentions': False,
            'allowChannelMentions': False,
        },
    }
    assert result == f'Team {display_name} was created successfully.'


def test_create_team_from_group(requests_mock, client):
    """
    Given:
        - Team display name and owner ID to create team of

    When:
        - Creating a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    group_id = 'uuid'
    requests_mock.put(f'{client.ms_client._base_url}/v1.0/groups/{group_id}/team', status_code=202)
    args = {
        'group_id': group_id,
        'allow_guests_create_channels': 'true',
    }
    result = create_team_from_group(client, args)
    assert requests_mock.request_history[0].json() == {
        'displayName': None,
        'description': None,
        'visibility': 'public',
        'guestSettings': {
            'allowCreateUpdateChannels': True,
            'allowDeleteChannels': False,
        },
        'memberSettings': {
            'allowCreatePrivateChannels': False,
            'allowCreateUpdateChannels': False,
            'allowDeleteChannels': False,
            'allowAddRemoveApps': False,
            'allowCreateUpdateRemoveTabs': False,
            'allowCreateUpdateRemoveConnectors': False,
        },
        'messagingSettings': {
            'allowUserEditMessages': False,
            'allowUserDeleteMessages': False,
            'allowOwnerDeleteMessages': False,
            'allowTeamMentions': False,
            'allowChannelMentions': False,
        },
    }
    assert result == f'The team was created from group {group_id} successfully.'


def test_list_teams(requests_mock, client):
    """
    Given:
        - Teams list

    When:
        - Listing teams

    Then:
        - Verify entry context is populated as expected
    """
    api_response = load_test_data('./test_data/teams_list.json')
    requests_mock.get(
        f"{client.ms_client._base_url}/beta/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')",
        json=api_response
    )
    result = list_teams(client)
    assert result.outputs == api_response['value']


def test_update_team(requests_mock, client):
    """
    Given:
        - Team ID, display name and member setting to update team with

    When:
        - Updating a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    team_id = 'uuid'
    display_name = 'UpdatedDisplayName'
    requests_mock.patch(f'{client.ms_client._base_url}/v1.0/teams/{team_id}', status_code=204)
    args = {
        'team_id': team_id,
        'display_name': display_name,
        'allow_channel_mentions': 'true',
    }
    result = update_team(client, args)
    assert requests_mock.request_history[0].json() == {
        'displayName': display_name,
        'description': None,
        'visibility': None,
        'guestSettings': {
            'allowCreateUpdateChannels': None,
            'allowDeleteChannels': None,
        },
        'memberSettings': {
            'allowCreatePrivateChannels': None,
            'allowCreateUpdateChannels': None,
            'allowDeleteChannels': None,
            'allowAddRemoveApps': None,
            'allowCreateUpdateRemoveTabs': None,
            'allowCreateUpdateRemoveConnectors': None,
        },
        'messagingSettings': {
            'allowUserEditMessages': None,
            'allowUserDeleteMessages': None,
            'allowOwnerDeleteMessages': None,
            'allowTeamMentions': None,
            'allowChannelMentions': True,
        },
    }
    assert result == f'Team {team_id} was updated successfully.'


def test_delete_team(requests_mock, client):
    """
    Given:
        - ID of team to delete

    When:
        - Deleting a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    team_id = 'uuid'
    requests_mock.delete(f'{client.ms_client._base_url}/v1.0/groups/{team_id}', status_code=204)
    args = {
        'team_id': team_id,
    }
    result = delete_team(client, args)
    assert result == f'Team {team_id} was deleted successfully.'


def test_get_team(requests_mock, client):
    """
    Given:
        - ID of team to get

    When:
        - Getting a team

    Then:
        - Ensure expected request body is sent
        - Verify entry context output
    """
    api_response = load_test_data('./test_data/team_get.json')
    team_id = 'uuid'
    requests_mock.get(f'{client.ms_client._base_url}/v1.0/teams/{team_id}', json=api_response)
    args = {
        'team_id': team_id,
    }
    result = get_team(client, args)
    assert result.outputs == api_response


def test_list_members(requests_mock, client):
    """
    Given:
        - Team members

    When:
        - Listing team members

    Then:
        - Verify entry context is populated as expected
    """
    team_id = 'ee0f5ae2-8bc6-4ae5-8466-7daeebbfa062'
    api_response = load_test_data('./test_data/members_list.json')
    requests_mock.get(
        f'{client.ms_client._base_url}/v1.0/teams/{team_id}/members',
        json=api_response
    )
    args = {
        'team_id': team_id,
    }
    result = list_members(client, args)
    expected_outputs = [dict(member, **{'teamId': team_id}) for member in api_response.get('value', [])]
    assert result.outputs == expected_outputs


def test_get_member(requests_mock, client):
    """
    Given:
        - ID of member to get

    When:
        - Getting a memeber

    Then:
        - Verify entry context output
    """
    team_id = 'uuid'
    membership_id = 'id'
    api_response = load_test_data('./test_data/member_get.json')
    requests_mock.get(f'{client.ms_client._base_url}/v1.0/teams/{team_id}/members/{membership_id}', json=api_response)
    args = {
        'team_id': team_id,
        'membership_id': membership_id
    }
    result = get_member(client, args)
    expected_outputs = {**{'teamId': team_id}, **api_response}
    assert result.outputs == expected_outputs


def test_add_member(requests_mock, client):
    """
    Given:
        - ID of team to the add a user to
        - ID of user to add to a team
    When:
        - Adding a user to the team

    Then:
        - Ensure expected request body is sent
        - Verify entry context output
    """
    team_id = 'uuid'
    user_id = 'user_id'
    api_response = load_test_data('./test_data/member_get.json')
    requests_mock.post(
        f'{client.ms_client._base_url}/v1.0/teams/{team_id}/members',
        json=api_response,
        status_code=201
    )
    args = {
        'team_id': team_id,
        'user_id': user_id,
        'is_owner': 'true',
    }
    result = add_member(client, args)
    assert requests_mock.request_history[0].json() == {
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'roles': ['owner'],
        'user@odata.bind': f"{client.ms_client._base_url}/v1.0/users('{user_id}')"
    }
    assert result.outputs == api_response


def test_remove_member(requests_mock, client):
    """
    Given:
        - ID of team to remove the member from
        - ID of member to remove

    When:
        - Removing a member from team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    team_id = 'uuid'
    membership_id = 'id'
    requests_mock.delete(f'{client.ms_client._base_url}/v1.0/teams/{team_id}/members/{membership_id}', status_code=204)
    args = {
        'team_id': team_id,
        'membership_id': membership_id,
    }
    result = remove_member(client, args)
    assert result == f'Team member {membership_id} was removed from the team {team_id} successfully.'


def test_update_member(requests_mock, client):
    """
    Given:
        - ID of team to update the member in
        - ID of member to update

    When:
        - Updating a member to be team owner

    Then:
        - Ensure expected request body is sent
        - Verify entry context output
    """
    team_id = 'uuid'
    membership_id = 'id'
    api_response = load_test_data('./test_data/member_get.json')
    requests_mock.patch(
        f'{client.ms_client._base_url}/v1.0/teams/{team_id}/members/{membership_id}',
        json=api_response
    )
    args = {
        'team_id': team_id,
        'membership_id': membership_id,
        'is_owner': 'true',
    }
    result = update_member(client, args)
    assert requests_mock.request_history[0].json() == {
        '@odata.type': '#microsoft.graph.aadUserConversationMember',
        'roles': ['owner']
    }
    assert result.outputs == api_response


def test_archive_team(requests_mock, client):
    """
    Given:
        - ID of team to archive

    When:
        - Archiving a team

    Then:
        - Verify human readable output
    """
    team_id = 'uuid'
    requests_mock.post(f'{client.ms_client._base_url}/v1.0/teams/{team_id}/archive', status_code=202)
    args = {
        'team_id': team_id,
    }
    result = archive_team(client, args)
    assert result == f'Team {team_id} was archived successfully.'


def test_unarchive_team(requests_mock, client):
    """
    Given:
        - ID of team to unarchive

    When:
        - Unarchiving a team

    Then:
        - Verify human readable output
    """
    team_id = 'uuid'
    requests_mock.post(f'{client.ms_client._base_url}/v1.0/teams/{team_id}/unarchive', status_code=202)
    args = {
        'team_id': team_id,
    }
    result = unarchive_team(client, args)
    assert result == f'Team {team_id} was unarchived successfully.'


def test_clone_team(requests_mock, client):
    """
    Given:
        - ID of team to clone
        - Display name of cloned team

    When:
        - Cloning a team

    Then:
        - Ensure expected request body is sent
        - Verify human readable output
    """
    team_id = 'uuid'
    display_name = 'TestClonedTeam'
    requests_mock.post(f'{client.ms_client._base_url}/v1.0/teams/{team_id}/clone', status_code=202)
    args = {
        'team_id': team_id,
        'display_name': display_name,
    }
    result = clone_team(client, args)
    assert requests_mock.request_history[0].json() == {
        'displayName': display_name,
        'mailNickname': display_name,
        'description': None,
        'visibility': None,
        'partsToClone': 'apps,tabs,settings,channels',
    }
    assert result == f'Team {team_id} was cloned successfully.'


def test_list_joined_teams(requests_mock, client):
    """
    Given:
        - ID of user to get teams for

    When:
        - Listing user teams

    Then:
        - Verify entry context is populated as expected
    """
    user_id = 'id'
    api_response = load_test_data('./test_data/teams_list.json')
    requests_mock.get(
        f'{client.ms_client._base_url}/v1.0/users/{user_id}/joinedTeams',
        json=api_response
    )
    args = {
        'user_id': user_id,
    }
    result = list_joined_teams(client, args)
    assert result.outputs == api_response['value']


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
        Given:
            - Managed Identities client id for authentication.
        When:
            - Calling test_module.
        Then:
            - Ensure the output are as expected.
    """
    from MicrosoftTeamsManagement import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import MicrosoftTeamsManagement
    import demistomock as demisto

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)

    params = {
        'managed_identities_client_id': {'password': client_id},
        'authentication_type': 'Azure Managed Identities',
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(MicrosoftTeamsManagement, 'return_results', return_value=params)
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in MicrosoftTeamsManagement.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.graph]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
