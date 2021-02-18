"""
An integration to MS Graph Identity and Access endpoint.
https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
"""

import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class Client:
    def __init__(self, app_id: str, verify: bool, proxy: bool):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context['current_refresh_token'] = refresh_token
            set_integration_context(integration_context)

        self.ms_client = MicrosoftClient(
            self_deployed=True,
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=DEVICE_CODE,
            base_url='https://graph.microsoft.com',
            verify=verify,
            proxy=proxy,
            scope='offline_access RoleManagement.ReadWrite.Directory'
        )

    def get_directory_roles(self, limit: int) -> list:
        """Get all service principals.

        Args:
            limit: Maximum of services to get.

        Returns:
            All given service principals

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0&tabs=http
        """
        results = list()
        res = self.ms_client.http_request(
            'GET', 'v1.0/directoryRoles')
        results.extend(res.get('value'))
        while (next_link := res.get('@odata.nextLink')) and len(results) < limit:
            res = self.ms_client.http_request('GET', '', next_link)
            results.extend(res.get('value'))
        return results[:limit]

    def get_role_members(self, role_id: str, limit: int) -> dict:
        """Get all members of a specific role

        Args:
            role_id: a role id to get its members.
            limit: Maximum roles to get.

        Returns:
            directoryObject

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-list-members?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'GET', f'v1.0/directoryRoles/{role_id}/members')['value'][:limit]

    def activate_directory_role(self, template_id: str) -> dict:
        """Activating a role in the directory.
        Args:
            template_id: A template id to activate

        Returns:
            directoryRole object.

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-post-directoryroles?view=graph-rest-1.0&tabs=http
        """
        return self.ms_client.http_request(
            'POST',
            'v1.0/directoryRoles',
            json_data={'roleTemplateId': template_id}
        )

    def add_member_to_role(self, role_object_id: str, user_id: str):
        """Adds a member to a specific role.

        Args:
            role_object_id: A role to add the user to.
            user_id: The user to add to the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed add (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-post-members?view=graph-rest-1.0&tabs=http
        """
        body = {
            '@odata.id': f'https://graph.microsoft.com/v1.0/directoryObjects/{user_id}'
        }
        self.ms_client.http_request(
            'POST',
            f'v1.0/directoryRoles/{role_object_id}/members/$ref',
            json_data=body,
            return_empty_response=True
        )

    def remove_member_from_role(self, role_object_id: str, user_id: str):
        """Removing a member from a specific role.

        Args:
            role_object_id: A role to remove the user from.
            user_id: The user to remove from the role.

        Return:
            True if succeeded.

        Raises:
            Error on failed removal (as long with requests errors).

        Docs:
            https://docs.microsoft.com/en-us/graph/api/directoryrole-delete-member?view=graph-rest-1.0&tabs=http
        """
        self.ms_client.http_request(
            'DELETE',
            f'v1.0/directoryRoles/{role_object_id}/members/{user_id}/$ref',
            return_empty_response=True
        )


''' COMMAND FUNCTIONS '''


def start_auth(client: Client) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(
        readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!msgraph-identity-auth-complete** command in the War Room."""
    )


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(
        readable_output='Authorization was reset successfully. Run **!msgraph-identity-auth-start** to '
                        'start the authentication process.'
    )


def list_directory_roles(ms_client: Client, args: dict) -> CommandResults:
    """Lists all service principals

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    limit_str = args.get('limit', '')
    try:
        limit = int(limit_str)
    except ValueError:
        raise DemistoException(f'Limit must be an integer, not "{limit_str}"')
    results = ms_client.get_directory_roles(limit)
    return CommandResults(
        "MSGraphIdentity.Role",
        "id",
        outputs=results,
        readable_output=tableToMarkdown(
            'Directory roles:',
            results,
            ['id', 'displayName', 'description', 'roleTemplateId', 'deletedDateTime'],
            removeNull=True
        )
    )


def list_role_members_command(ms_client: Client, args: dict) -> CommandResults:
    """Lists all service principals

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    limit_str = args.get('limit', '')
    try:
        limit = int(limit_str)
    except ValueError:
        raise DemistoException(f'Limit must be an integer, not "{limit_str}"')
    role_id = args['role_id']
    if results := ms_client.get_role_members(role_id, limit):
        ids = [member['id'] for member in results]
        context = {
            'role_id': role_id,
            'user_id': ids
        }
        return CommandResults(
            'MSGraphIdentity.RoleMember',
            'role_id',
            outputs=context,
            raw_response=results,
            readable_output=tableToMarkdown(
                f'Role \'{role_id}\' members:',
                context
            )
        )
    else:
        return CommandResults(readable_output=f"No members found in {role_id}")


def activate_directory_role_command(ms_client: Client, args: dict) -> CommandResults:
    template_id = args['role_template_id']
    results = ms_client.activate_directory_role(template_id)
    return CommandResults(
        "MSGraphIdentity.Role",
        "id",
        outputs=results,
        readable_output=tableToMarkdown(
            'Role has been activated',
            results,
            ['id', 'roleTemplateId', 'displayName', 'description', 'deletedDateTime']
        )
    )


def add_member_to_role_command(client: Client, args: dict) -> str:
    user_id = args['user_id']
    role_object_id = args['role_id']
    client.add_member_to_role(role_object_id, user_id)
    return f"User ID {user_id} has been added to role {role_object_id}"


def remove_member_from_role(client: Client, args: dict) -> str:
    role_object_id = args['role_id']
    user_id = args['user_id']
    client.remove_member_from_role(role_object_id, user_id)
    return f"User ID {user_id} has been removed from role {role_object_id}"


def main():
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        command = demisto.command()
        params = demisto.params()
        args = demisto.args()
        handle_proxy()
        client = Client(
            app_id=params['app_id'],
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        if command == 'test-module':
            return_results('The test module is not functional, run the msgraph-identity-auth-start command instead.')
        elif command == 'msgraph-identity-auth-start':
            return_results(start_auth(client))
        elif command == 'msgraph-identity-auth-complete':
            return_results(complete_auth(client))
        elif command == 'msgraph-identity-auth-test':
            return_results(test_connection(client))
        elif command == 'msgraph-identity-auth-reset':
            return_results(test_connection(client))
        elif command == 'msgraph-identity-directory-roles-list':
            return_results(list_directory_roles(client, args))
        elif command == 'msgraph-identity-directory-role-members-list':
            return_results(list_role_members_command(client, args))
        elif command == 'msgraph-identity-directory-role-activate':
            return_results(activate_directory_role_command(client, args))
        elif command == 'msgraph-identity-directory-role-member-add':
            return_results(add_member_to_role_command(client, args))
        elif command == 'msgraph-identity-directory-role-member-remove':
            return_results(remove_member_from_role(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' not found.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

from MicrosoftApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
