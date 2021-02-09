import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

from typing import Dict, Optional

import urllib3

urllib3.disable_warnings()


class Client:
    def __init__(self, app_id: str, verify: bool, proxy: bool):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url='https://graph.microsoft.com',
            verify=verify,
            proxy=proxy,
            scope='offline_access Group.ReadWrite.All TeamMember.ReadWrite.All Team.ReadBasic.All'
        )

    @logger
    def create_team_request(
            self,
            display_name: str,
            owner: str,
            description: Optional[str] = None,
            visibility: str = 'public',
            allow_guests_create_channels: bool = False,
            allow_guests_delete_channels: bool = False,
            allow_members_create_private_channels: bool = False,
            allow_members_create_channels: bool = False,
            allow_members_delete_channels: bool = False,
            allow_members_add_remove_apps: bool = False,
            allow_members_add_remove_tabs: bool = False,
            allow_members_add_remove_connectors: bool = False,
            allow_user_edit_messages: bool = False,
            allow_user_delete_messages: bool = False,
            allow_owner_delete_messages: bool = False,
            allow_team_mentions: bool = False,
            allow_channel_mentions: bool = False,
    ) -> None:
        self.ms_client.http_request(
            method='POST',
            url_suffix='/v1.0/teams',
            json_data={
                'template@odata.bind': "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
                'displayName': display_name,
                'description': description,
                'visibility': visibility,
                'members': [{
                    '@odata.type': '#microsoft.graph.aadUserConversationMember',
                    'roles': ['owner'],
                    'user@odata.bind': f"https://graph.microsoft.com/v1.0/users('{owner}')",
                }],
                'guestSettings': {
                    'allowCreateUpdateChannels': allow_guests_create_channels,
                    'allowDeleteChannels': allow_guests_delete_channels,
                },
                'memberSettings': {
                    'allowCreatePrivateChannels': allow_members_create_private_channels,
                    'allowCreateUpdateChannels': allow_members_create_channels,
                    'allowDeleteChannels': allow_members_delete_channels,
                    'allowAddRemoveApps': allow_members_add_remove_apps,
                    'allowCreateUpdateRemoveTabs': allow_members_add_remove_tabs,
                    'allowCreateUpdateRemoveConnectors': allow_members_add_remove_connectors,
                },
                'messagingSettings': {
                    'allowUserEditMessages': allow_user_edit_messages,
                    'allowUserDeleteMessages': allow_user_delete_messages,
                    'allowOwnerDeleteMessages': allow_owner_delete_messages,
                    'allowTeamMentions': allow_team_mentions,
                    'allowChannelMentions': allow_channel_mentions,
                },
            },
            resp_type='response',
        )

    @logger
    def create_team_from_group_request(
            self,
            group_id: str,
            display_name: str,
            description: Optional[str] = None,
            visibility: str = 'public',
            allow_guests_create_channels: bool = False,
            allow_guests_delete_channels: bool = False,
            allow_members_create_private_channels: bool = False,
            allow_members_create_channels: bool = False,
            allow_members_delete_channels: bool = False,
            allow_members_add_remove_apps: bool = False,
            allow_members_add_remove_tabs: bool = False,
            allow_members_add_remove_connectors: bool = False,
            allow_user_edit_messages: bool = False,
            allow_user_delete_messages: bool = False,
            allow_owner_delete_messages: bool = False,
            allow_team_mentions: bool = False,
            allow_channel_mentions: bool = False,
    ) -> None:
        self.ms_client.http_request(
            method='PUT',
            url_suffix=f'/v1.0/groups/{group_id}/team',
            json_data={
                'displayName': display_name,
                'description': description,
                'visibility': visibility,
                'guestSettings': {
                    'allowCreateUpdateChannels': allow_guests_create_channels,
                    'allowDeleteChannels': allow_guests_delete_channels,
                },
                'memberSettings': {
                    'allowCreatePrivateChannels': allow_members_create_private_channels,
                    'allowCreateUpdateChannels': allow_members_create_channels,
                    'allowDeleteChannels': allow_members_delete_channels,
                    'allowAddRemoveApps': allow_members_add_remove_apps,
                    'allowCreateUpdateRemoveTabs': allow_members_add_remove_tabs,
                    'allowCreateUpdateRemoveConnectors': allow_members_add_remove_connectors,
                },
                'messagingSettings': {
                    'allowUserEditMessages': allow_user_edit_messages,
                    'allowUserDeleteMessages': allow_user_delete_messages,
                    'allowOwnerDeleteMessages': allow_owner_delete_messages,
                    'allowTeamMentions': allow_team_mentions,
                    'allowChannelMentions': allow_channel_mentions,
                },
            },
            resp_type='response',
        )

    @logger
    def list_teams_request(self) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix="/beta/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"
        )

    @logger
    def get_team_request(self, team_id: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/teams/{team_id}'
        )

    @logger
    def update_team_request(
            self,
            team_id: str,
            display_name: Optional[str] = None,
            description: Optional[str] = None,
            visibility: Optional[str] = None,
            allow_guests_create_channels: Optional[bool] = None,
            allow_guests_delete_channels: Optional[bool] = None,
            allow_members_create_private_channels: Optional[bool] = None,
            allow_members_create_channels: Optional[bool] = None,
            allow_members_delete_channels: Optional[bool] = None,
            allow_members_add_remove_apps: Optional[bool] = None,
            allow_members_add_remove_tabs: Optional[bool] = None,
            allow_members_add_remove_connectors: Optional[bool] = None,
            allow_user_edit_messages: Optional[bool] = None,
            allow_user_delete_messages: Optional[bool] = None,
            allow_owner_delete_messages: Optional[bool] = None,
            allow_team_mentions: Optional[bool] = None,
            allow_channel_mentions: Optional[bool] = None,
    ) -> None:
        self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'/v1.0/teams/{team_id}',
            json_data={
                'displayName': display_name,
                'description': description,
                'visibility': visibility,
                'guestSettings': {
                    'allowCreateUpdateChannels': allow_guests_create_channels,
                    'allowDeleteChannels': allow_guests_delete_channels,
                },
                'memberSettings': {
                    'allowCreatePrivateChannels': allow_members_create_private_channels,
                    'allowCreateUpdateChannels': allow_members_create_channels,
                    'allowDeleteChannels': allow_members_delete_channels,
                    'allowAddRemoveApps': allow_members_add_remove_apps,
                    'allowCreateUpdateRemoveTabs': allow_members_add_remove_tabs,
                    'allowCreateUpdateRemoveConnectors': allow_members_add_remove_connectors,
                },
                'messagingSettings': {
                    'allowUserEditMessages': allow_user_edit_messages,
                    'allowUserDeleteMessages': allow_user_delete_messages,
                    'allowOwnerDeleteMessages': allow_owner_delete_messages,
                    'allowTeamMentions': allow_team_mentions,
                    'allowChannelMentions': allow_channel_mentions,
                },
            },
            resp_type='response',
        )

    @logger
    def delete_team_request(self, team_id: str) -> None:
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=f'/v1.0/groups/{team_id}',
            resp_type='response',
        )

    @logger
    def list_members_request(self, team_id: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/teams/{team_id}/members',
        )

    @logger
    def get_member_request(self, team_id: str, membership_id: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/teams/{team_id}/members/{membership_id}',
        )

    @logger
    def add_member_request(self, team_id: str, user_id: str, roles: Optional[list] = None) -> Dict:
        return self.ms_client.http_request(
            method='POST',
            url_suffix=f'/v1.0/teams/{team_id}/members',
            json_data={
                '@odata.type': '#microsoft.graph.aadUserConversationMember',
                'roles': roles,
                'user@odata.bind': f"https://graph.microsoft.com/v1.0/users('{user_id}')",
            },
        )

    @logger
    def remove_member_request(self, team_id: str, membership_id: str) -> None:
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=f'/v1.0/teams/{team_id}/members/{membership_id}',
            resp_type='response',
        )

    @logger
    def update_member_request(self, team_id: str, membership_id: str, roles: Optional[list] = None) -> Dict:
        return self.ms_client.http_request(
            method='PATCH',
            url_suffix=f'/v1.0/teams/{team_id}/members/{membership_id}',
            json_data={
                '@odata.type': '#microsoft.graph.aadUserConversationMember',
                'roles': roles,
            },
        )

    @logger
    def archive_team_request(self, team_id: str) -> None:
        self.ms_client.http_request(
            method='POST',
            url_suffix=f'/v1.0/teams/{team_id}/archive',
            resp_type='response',
        )

    @logger
    def unarchive_team_request(self, team_id: str) -> None:
        self.ms_client.http_request(
            method='POST',
            url_suffix=f'/v1.0/teams/{team_id}/unarchive',
            resp_type='response',
        )

    @logger
    def clone_team_request(
            self,
            team_id: str,
            display_name: str,
            description: Optional[str] = None,
            visibility: Optional[str] = None,
            parts_to_clone: Optional[str] = None,
    ) -> None:
        self.ms_client.http_request(
            method='POST',
            url_suffix=f'/v1.0/teams/{team_id}/clone',
            json_data={
                'displayName': display_name,
                # from Microsoft docs: "mailNickname property must be specified when a group is created.
                # If this property is not specified, it will be computed from the displayName.
                # Known issue: this property is currently ignored."
                'mailNickname': display_name,
                'description': description,
                'visibility': visibility,
                'partsToClone': parts_to_clone,
            },
            resp_type='response',
        )

    @logger
    def list_joined_teams_request(self, user_id: str) -> Dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/users/{user_id}/joinedTeams',
        )


def create_team(client: Client, args: Dict) -> str:
    display_name = args.get('display_name', '')
    client.create_team_request(
        display_name=display_name,
        owner=args.get('owner', ''),
        description=args.get('description'),
        visibility=args.get('visibility', 'public'),
        allow_guests_create_channels=argToBoolean(args.get('allow_guests_create_channels', 'false')),
        allow_guests_delete_channels=argToBoolean(args.get('allow_guests_delete_channels', 'false')),
        allow_members_create_private_channels=argToBoolean(
            args.get('allow_members_create_private_channels', 'false')),
        allow_members_create_channels=argToBoolean(args.get('allow_members_create_channels', 'false')),
        allow_members_delete_channels=argToBoolean(args.get('allow_members_delete_channels', 'false')),
        allow_members_add_remove_apps=argToBoolean(args.get('allow_members_add_remove_apps', 'false')),
        allow_members_add_remove_tabs=argToBoolean(args.get('allow_members_add_remove_tabs', 'false')),
        allow_members_add_remove_connectors=argToBoolean(
            args.get('allow_members_add_remove_connectors', 'false')),
        allow_user_edit_messages=argToBoolean(args.get('allow_user_edit_messages', 'false')),
        allow_user_delete_messages=argToBoolean(args.get('allow_user_delete_messages', 'false')),
        allow_owner_delete_messages=argToBoolean(args.get('allow_owner_delete_messages', 'false')),
        allow_team_mentions=argToBoolean(args.get('allow_team_mentions', 'false')),
        allow_channel_mentions=argToBoolean(args.get('allow_channel_mentions', 'false')),
    )
    return f'Team {display_name} was created successfully.'


def create_team_from_group(client: Client, args: Dict) -> str:
    group_id = args.get('group_id', '')
    client.create_team_from_group_request(
        group_id=group_id,
        display_name=args.get('display_name'),
        description=args.get('description'),
        visibility=args.get('visibility', 'public'),
        allow_guests_create_channels=argToBoolean(args.get('allow_guests_create_channels', 'false')),
        allow_guests_delete_channels=argToBoolean(args.get('allow_guests_delete_channels', 'false')),
        allow_members_create_private_channels=argToBoolean(
            args.get('allow_members_create_private_channels', 'false')),
        allow_members_create_channels=argToBoolean(args.get('allow_members_create_channels', 'false')),
        allow_members_delete_channels=argToBoolean(args.get('allow_members_delete_channels', 'false')),
        allow_members_add_remove_apps=argToBoolean(args.get('allow_members_add_remove_apps', 'false')),
        allow_members_add_remove_tabs=argToBoolean(args.get('allow_members_add_remove_tabs', 'false')),
        allow_members_add_remove_connectors=argToBoolean(
            args.get('allow_members_add_remove_connectors', 'false')),
        allow_user_edit_messages=argToBoolean(args.get('allow_user_edit_messages', 'false')),
        allow_user_delete_messages=argToBoolean(args.get('allow_user_delete_messages', 'false')),
        allow_owner_delete_messages=argToBoolean(args.get('allow_owner_delete_messages', 'false')),
        allow_team_mentions=argToBoolean(args.get('allow_team_mentions', 'false')),
        allow_channel_mentions=argToBoolean(args.get('allow_channel_mentions', 'false')),
    )
    return f'The team was created from group {group_id} successfully.'


def list_teams(client: Client) -> CommandResults:
    response = client.list_teams_request()
    teams = response.get('value', [])
    return CommandResults(
        outputs_prefix='MicrosoftTeams.Team',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            'Microsoft Teams List',
            teams,
            ['id', 'displayName', 'createdDateTime', 'description']
        ),
        outputs=teams,
        raw_response=response,
    )


def get_team(client: Client, args: Dict) -> CommandResults:
    team_id = args.get('team_id')
    team = client.get_team_request(team_id)
    team.pop('@odata.context', None)
    return CommandResults(
        outputs_prefix='MicrosoftTeams.Team',
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Team {team_id}', team),
        outputs=team,
    )


def update_team(client: Client, args: Dict) -> str:
    team_id = args.get('team_id', '')
    update_team_args = {
        'team_id': team_id,
        'display_name': args.get('display_name'),
        'description': args.get('description'),
    }
    for bool_arg in [
        'allow_guests_create_channels', 'allow_guests_delete_channels', 'allow_members_create_private_channels',
        'allow_members_create_channels', 'allow_members_delete_channels', 'allow_members_delete_channels',
        'allow_members_add_remove_apps', 'allow_members_add_remove_tabs', 'allow_members_add_remove_connectors',
        'allow_user_edit_messages', 'allow_user_delete_messages', 'allow_owner_delete_messages',
        'allow_team_mentions', 'allow_channel_mentions'
    ]:
        if bool_arg in args:
            update_team_args[bool_arg] = argToBoolean(args[bool_arg])
    client.update_team_request(**update_team_args)
    return f'Team {team_id} was updated successfully.'


def delete_team(client: Client, args: Dict) -> str:
    team_id = args.get('team_id')
    client.delete_team_request(team_id)
    return f'Team {team_id} was deleted successfully.'


def list_members(client: Client, args: Dict) -> CommandResults:
    team_id = args.get('team_id')
    response = client.list_members_request(team_id)
    members = [dict(member, **{'teamId': team_id}) for member in response.get('value', [])]
    return CommandResults(
        outputs_prefix='MicrosoftTeams.TeamMember',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            f'Team {team_id} Members List',
            members,
            ['id', 'displayName', 'email', 'roles'],
        ),
        outputs=members,
        raw_response=response,
    )


def get_member(client: Client, args: Dict) -> CommandResults:
    team_id = args.get('team_id')
    membership_id = args.get('membership_id')
    team_member = client.get_member_request(team_id, membership_id)
    team_member['teamId'] = team_id
    return CommandResults(
        outputs_prefix='MicrosoftTeams.TeamMember',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            f'Team Member {membership_id} Details',
            team_member,
            ['id', 'displayName', 'email', 'roles'],
        ),
        outputs=team_member,
        raw_response=team_member,
    )


def add_member(client: Client, args: Dict) -> CommandResults:
    team_id = args.get('team_id', '')
    user_id = args.get('user_id', '')
    team_member = client.add_member_request(
        team_id=team_id,
        user_id=user_id,
        roles=['owner'] if argToBoolean(args.get('is_owner', 'false')) else [],
    )
    return CommandResults(
        outputs_prefix='MicrosoftTeams.TeamMember',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            f'User {user_id} was added to the team {team_id} successfully.',
            team_member,
            ['id', 'displayName', 'email', 'roles'],
        ),
        outputs=team_member,
        raw_response=team_member,
    )


def remove_member(client: Client, args: Dict) -> str:
    team_id = args.get('team_id')
    membership_id = args.get('membership_id')
    client.remove_member_request(team_id, membership_id)
    return f'Team member {membership_id} was removed from the team {team_id} successfully.'


def update_member(client: Client, args: Dict) -> CommandResults:
    team_id = args.get('team_id', '')
    membership_id = args.get('membership_id', '')
    team_member = client.update_member_request(
        team_id=team_id,
        membership_id=membership_id,
        roles=['owner'] if argToBoolean(args.get('is_owner', 'false')) else [],
    )
    return CommandResults(
        outputs_prefix='MicrosoftTeams.TeamMember',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            f'Team member {membership_id} was updated successfully.',
            team_member,
            ['id', 'displayName', 'email', 'roles'],
        ),
        outputs=team_member,
        raw_response=team_member,
    )


def archive_team(client: Client, args: Dict) -> str:
    team_id = args.get('team_id')
    client.archive_team_request(team_id)
    return f'Team {team_id} was archived successfully.'


def unarchive_team(client: Client, args: Dict) -> str:
    team_id = args.get('team_id')
    client.unarchive_team_request(team_id)
    return f'Team {team_id} was unarchived successfully.'


def clone_team(client: Client, args: Dict) -> str:
    team_id = args.get('team_id')
    parts_to_clone = []
    if argToBoolean(args.get('clone_apps', 'true')):
        parts_to_clone.append('apps')
    if argToBoolean(args.get('clone_tabs', 'true')):
        parts_to_clone.append('tabs')
    if argToBoolean(args.get('clone_settings', 'true')):
        parts_to_clone.append('settings')
    if argToBoolean(args.get('clone_channels', 'true')):
        parts_to_clone.append('channels')
    if not parts_to_clone:
        raise ValueError('At least one of the parts of the team must be cloned: apps, tabs, settings, channels')
    client.clone_team_request(
        team_id=team_id,
        display_name=args.get('display_name'),
        description=args.get('description'),
        visibility=args.get('visibility'),
        parts_to_clone=','.join(parts_to_clone),
    )
    return f'Team {team_id} was cloned successfully.'


def list_joined_teams(client: Client, args: Dict) -> CommandResults:
    user_id = args.get('user_id')
    response = client.list_joined_teams_request(user_id)
    teams = response.get('value', [])
    return CommandResults(
        outputs_prefix='MicrosoftTeams.Team',
        outputs_key_field='id',
        readable_output=tableToMarkdown(
            f'User {user_id} Teams',
            teams,
            ['id', 'displayName', 'description'],
        ),
        outputs=teams,
        raw_response=response,
    )


def start_auth(client: Client) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!microsoft-teams-auth-complete** command in the War Room.""")


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(
        readable_output='Authorization was reset successfully. Run **!microsoft-teams-auth-start** to start the '
                        'authentication process.'
    )


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    handle_proxy()
    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            app_id=params.get('app_id', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        if command == 'test-module':
            return_results('The test module is not functional, run the microsoft-teams-auth-start command instead.')
        elif command == 'microsoft-teams-auth-start':
            return_results(start_auth(client))
        elif command == 'microsoft-teams-auth-complete':
            return_results(complete_auth(client))
        elif command == 'microsoft-teams-auth-test':
            return_results(test_connection(client))
        elif command == 'microsoft-teams-auth-reset':
            return_results(reset_auth())
        elif command == 'microsoft-teams-team-create':
            return_results(create_team(client, args))
        elif command == 'microsoft-teams-team-create-from-group':
            return_results(create_team_from_group(client, args))
        elif command == 'microsoft-teams-teams-list':
            return_results(list_teams(client))
        elif command == 'microsoft-teams-team-get':
            return_results(get_team(client, args))
        elif command == 'microsoft-teams-team-update':
            return_results(update_team(client, args))
        elif command == 'microsoft-teams-team-delete':
            return_results(delete_team(client, args))
        elif command == 'microsoft-teams-members-list':
            return_results(list_members(client, args))
        elif command == 'microsoft-teams-member-get':
            return_results(get_member(client, args))
        elif command == 'microsoft-teams-member-add':
            return_results(add_member(client, args))
        elif command == 'microsoft-teams-member-remove':
            return_results(remove_member(client, args))
        elif command == 'microsoft-teams-member-update':
            return_results(update_member(client, args))
        elif command == 'microsoft-teams-team-archive':
            return_results(archive_team(client, args))
        elif command == 'microsoft-teams-team-unarchive':
            return_results(unarchive_team(client, args))
        elif command == 'microsoft-teams-team-clone':
            return_results(clone_team(client, args))
        elif command == 'microsoft-teams-teams-list-joined':
            return_results(list_joined_teams(client, args))
        else:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}', e)


from MicrosoftApiModule import *  # noqa: E402


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
