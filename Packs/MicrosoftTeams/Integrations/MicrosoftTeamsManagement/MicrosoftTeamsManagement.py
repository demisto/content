import demistomock as demisto
from MicrosoftApiModule import *  # noqa: E402
from CommonServerPython import *
from CommonServerUserPython import *


import urllib3

urllib3.disable_warnings()
GRANT_BY_CONNECTION = {'Device Code': DEVICE_CODE, 'Client Credentials': CLIENT_CREDENTIALS}
SCOPE_BY_CONNECTION = {'Device Code': 'offline_access Group.ReadWrite.All TeamMember.ReadWrite.All Team.ReadBasic.All',
                       'Client Credentials': 'https://graph.microsoft.com/.default'}


class Client:
    def __init__(self, app_id: str, verify: bool, proxy: bool,
                 connection_type: str, tenant_id: str, enc_key: str,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 managed_identities_client_id: str | None = None):
        if app_id and '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        token_retrieval_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' \
                              if 'Client' not in connection_type \
                              else None

        client_args = assign_params(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url=token_retrieval_url,
            grant_type=GRANT_BY_CONNECTION.get(connection_type),
            base_url='https://graph.microsoft.com',
            verify=verify,
            proxy=proxy,
            scope=SCOPE_BY_CONNECTION.get(connection_type),
            azure_ad_endpoint=azure_ad_endpoint,
            tenant_id=tenant_id,
            enc_key=enc_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.graph,
            command_prefix="microsoft-teams",
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.connection_type = connection_type

    @logger
    def create_team_request(
            self,
            display_name: str,
            owner: str,
            description: str | None = None,
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
            description: str | None = None,
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
    def list_teams_request(self) -> dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix="/beta/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')"
        )

    @logger
    def get_team_request(self, team_id: str) -> dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/teams/{team_id}'
        )

    @logger
    def update_team_request(
            self,
            team_id: str,
            display_name: str | None = None,
            description: str | None = None,
            visibility: str | None = None,
            allow_guests_create_channels: bool | None = None,
            allow_guests_delete_channels: bool | None = None,
            allow_members_create_private_channels: bool | None = None,
            allow_members_create_channels: bool | None = None,
            allow_members_delete_channels: bool | None = None,
            allow_members_add_remove_apps: bool | None = None,
            allow_members_add_remove_tabs: bool | None = None,
            allow_members_add_remove_connectors: bool | None = None,
            allow_user_edit_messages: bool | None = None,
            allow_user_delete_messages: bool | None = None,
            allow_owner_delete_messages: bool | None = None,
            allow_team_mentions: bool | None = None,
            allow_channel_mentions: bool | None = None,
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
    def list_members_request(self, team_id: str) -> dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/teams/{team_id}/members',
        )

    @logger
    def get_member_request(self, team_id: str, membership_id: str) -> dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/teams/{team_id}/members/{membership_id}',
        )

    @logger
    def add_member_request(self, team_id: str, user_id: str, roles: list | None = None) -> dict:
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
    def update_member_request(self, team_id: str, membership_id: str, roles: list | None = None) -> dict:
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
            description: str | None = None,
            visibility: str | None = None,
            parts_to_clone: str | None = None,
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
    def list_joined_teams_request(self, user_id: str) -> dict:
        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'/v1.0/users/{user_id}/joinedTeams',
        )


def create_team(client: Client, args: dict) -> str:
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


def create_team_from_group(client: Client, args: dict) -> str:
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


def get_team(client: Client, args: dict) -> CommandResults:
    team_id = args.get('team_id')
    team = client.get_team_request(team_id)
    team.pop('@odata.context', None)
    return CommandResults(
        outputs_prefix='MicrosoftTeams.Team',
        outputs_key_field='id',
        readable_output=tableToMarkdown(f'Team {team_id}', team),
        outputs=team,
    )


def update_team(client: Client, args: dict) -> str:
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


def delete_team(client: Client, args: dict) -> str:
    team_id = args.get('team_id')
    client.delete_team_request(team_id)
    return f'Team {team_id} was deleted successfully.'


def list_members(client: Client, args: dict) -> CommandResults:
    team_id = args.get('team_id')
    response = client.list_members_request(team_id)
    members = [{**member, 'teamId': team_id} for member in response.get('value', [])]
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


def get_member(client: Client, args: dict) -> CommandResults:
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


def add_member(client: Client, args: dict) -> CommandResults:
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


def remove_member(client: Client, args: dict) -> str:
    team_id = args.get('team_id')
    membership_id = args.get('membership_id')
    client.remove_member_request(team_id, membership_id)
    return f'Team member {membership_id} was removed from the team {team_id} successfully.'


def update_member(client: Client, args: dict) -> CommandResults:
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


def archive_team(client: Client, args: dict) -> str:
    team_id = args.get('team_id')
    client.archive_team_request(team_id)
    return f'Team {team_id} was archived successfully.'


def unarchive_team(client: Client, args: dict) -> str:
    team_id = args.get('team_id')
    client.unarchive_team_request(team_id)
    return f'Team {team_id} was unarchived successfully.'


def clone_team(client: Client, args: dict) -> str:
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


def list_joined_teams(client: Client, args: dict) -> CommandResults:
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
    result = client.ms_client.start_auth('!microsoft-teams-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication for client credentials only.
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type client: ``Client``
    :param Client: client to use
    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    # This should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if client.connection_type not in {'Client Credentials', 'Azure Managed Identities'}:
        raise DemistoException(
            "Test module is available for Client Credentials or Azure Managed Identities only."
            " For the `Device Code Flow` use the `msgraph-apps-auth-start` command")

    test_connection(client)
    return "ok"


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
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com',
            enc_key=(params.get('credentials', {})).get('password'),
            tenant_id=params.get('tenant_id'),
            connection_type=params.get('authentication_type', 'Device Code'),
            managed_identities_client_id=get_azure_managed_identities_client_id(params)
        )
        if command == 'test-module':
            return_results(test_module(client))
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


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
