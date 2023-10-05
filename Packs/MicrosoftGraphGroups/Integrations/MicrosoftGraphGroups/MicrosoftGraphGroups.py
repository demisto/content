import demistomock as demisto
import urllib3
from CommonServerPython import *
from MicrosoftApiModule import *  # noqa: E402

# Disable insecure warnings

urllib3.disable_warnings()

INTEGRATION_CONTEXT_NAME = 'MSGraphGroups'
NO_OUTPUTS: dict = {}
APP_NAME = 'ms-graph-groups'


def camel_case_to_readable(text: str) -> str:
    """'camelCase' -> 'Camel Case'

    Args:
        text: the text to transform

    Returns:
        A Camel Cased string.
    """
    if text == 'id':
        return 'ID'
    return ''.join(' ' + char if char.isupper() else char.strip() for char in text).strip().title()


def parse_outputs(groups_data: dict[str, str]) -> tuple[dict, dict]:
    """Parse group data as received from Microsoft Graph API into Demisto's conventions

    Args:
        groups_data: a dictionary containing the group data

    Returns:
        A Camel Cased dictionary with the relevant fields.
        groups_readable: for the human readable
        groups_outputs: for the entry context
    """
    # Unnecessary fields, dropping as to not load the incident context.
    fields_to_drop = ['@odata.context', '@odata.nextLink', '@odata.deltaLink', '@odata.type', '@removed',
                      'resourceProvisioningOptions', 'securityIdentifier', 'onPremisesSecurityIdentifier',
                      'onPremisesNetBiosName', 'onPremisesProvisioningErrors', 'onPremisesSamAccountName',
                      'resourceBehaviorOptions', 'creationOptions', 'preferredDataLocation']
    if isinstance(groups_data, list):
        groups_readable, groups_outputs = [], []
        for group_data in groups_data:
            group_readable = {camel_case_to_readable(i): j for i, j in group_data.items() if i not in fields_to_drop}
            if '@removed' in group_data:
                group_readable['Status'] = 'deleted'
            groups_readable.append(group_readable)
            groups_outputs.append({k.replace(' ', ''): v for k, v in group_readable.copy().items()})

        return groups_readable, groups_outputs

    group_readable = {camel_case_to_readable(i): j for i, j in groups_data.items() if i not in fields_to_drop}
    if '@removed' in groups_data:
        group_readable['Status'] = 'deleted'
    group_outputs = {k.replace(' ', ''): v for k, v in group_readable.copy().items()}

    return group_readable, group_outputs


class MsGraphClient:
    """
      Microsoft Graph Mail Client enables authorized access to a user's Office 365 mail data in a personal account.
      """

    def __init__(self, tenant_id, auth_id, enc_key, app_name, base_url, verify, proxy,
                 self_deployed, handle_error, redirect_uri=None, auth_code=None,
                 certificate_thumbprint: str | None = None, private_key: str | None = None,
                 managed_identities_client_id: str | None = None):
        grant_type = AUTHORIZATION_CODE if auth_code and redirect_uri else CLIENT_CREDENTIALS
        resource = None if self_deployed else ''
        self.ms_client = MicrosoftClient(tenant_id=tenant_id, auth_id=auth_id, enc_key=enc_key, app_name=app_name,
                                         base_url=base_url, verify=verify, proxy=proxy, self_deployed=self_deployed,
                                         redirect_uri=redirect_uri, auth_code=auth_code, grant_type=grant_type,
                                         resource=resource, certificate_thumbprint=certificate_thumbprint,
                                         private_key=private_key,
                                         managed_identities_client_id=managed_identities_client_id,
                                         managed_identities_resource_uri=Resources.graph,
                                         command_prefix="msgraph-groups",
                                         )

        self.handle_error = handle_error

    def test_function(self):
        """Performs basic GET request to check if the API is reachable and authentication is successful.

        Returns:
            ok if successful.
        """
        self.ms_client.http_request(method='GET', url_suffix='groups', params={'$orderby': 'displayName'})
        demisto.results('ok')

    def list_groups(self, order_by: str = None, next_link: str = None, top: int = None, filter_: str = None):
        """Returns all groups by sending a GET request.

        Args:
            order_by: the group fields to order by the response.
            next_link: the link for the next page of results, if exists. see Microsoft documentation for more details.
                docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0
            top: sets the page size of results.
            filter_: filters results.
        Returns:
            Response from API.
        """
        if next_link:  # pagination
            return self.ms_client.http_request(method='GET', full_url=next_link)
        # default value = 100
        params = {'$top': top}
        if order_by:
            params['$orderby'] = order_by  # type: ignore
        if filter_:
            params['$filter'] = filter_  # type: ignore
        return self.ms_client.http_request(
            method='GET',
            url_suffix='groups',
            params=params)

    def get_group(self, group_id: str) -> dict:
        """Returns a single group by sending a GET request.

        Args:
            group_id: the group id.

        Returns:
            Response from API.
        """
        group = self.ms_client.http_request(method='GET', url_suffix=f'groups/{group_id}')
        return group

    def create_group(self, properties: dict[str, Any | None]) -> dict:
        """Create a single group by sending a POST request.

        Args:
            properties: the group properties.

        Returns:
            Response from API.
        """
        group = self.ms_client.http_request(method='POST', url_suffix='groups', json_data=properties)
        return group

    def delete_group(self, group_id: str):
        """Delete a single group by sending a DELETE request.

        Args:
            group_id: the group id to delete.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        #  Using resp_type="text" to avoid parsing error in the calling method.
        self.ms_client.http_request(method='DELETE', url_suffix=f'groups/{group_id}', resp_type="text")

    def list_members(self, group_id: str, next_link: str = None, top: int = None, filter_: str = None):
        """List all group members by sending a GET request.

        Args:
            group_id: the group id to list its members.
            next_link: the link for the next page of results, if exists. see Microsoft documentation for more details.
                docs.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0
            top: sets the page size of results.
            filter_: filters results.
        Returns:
            Response from API.
        """
        headers = {}

        if next_link:  # pagination
            return self.ms_client.http_request(method='GET', full_url=next_link)
        params = {'$top': top}

        if filter_:
            params['$filter'] = filter_  # type: ignore

        if count := demisto.args().get('count'):
            params['$count'] = count
            headers['ConsistencyLevel'] = 'eventual'

        return self.ms_client.http_request(
            method='GET',
            url_suffix=f'groups/{group_id}/members',
            params=params,
            headers=headers)

    def add_member(self, group_id: str, properties: dict[str, str]):
        """Add a single member to a group by sending a POST request.
        Args:
            group_id: the group id to add the member to.
            properties: the member properties.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        #  Using resp_type="text" to avoid parsing error in the calling method.
        self.ms_client.http_request(
            method='POST',
            url_suffix=f'groups/{group_id}/members/$ref',
            json_data=properties,
            resp_type="text")

    def remove_member(self, group_id: str, user_id: str):
        """Remove a single member to a group by sending a DELETE request.
        Args:
            group_id: the group id to add the member to.
            user_id: the user id to remove.
        """
        #  If successful, this method returns 204 No Content response code.
        #  It does not return anything in the response body.
        #  Using resp_type="text" to avoid parsing error in the calling method.
        self.ms_client.http_request(
            method='DELETE',
            url_suffix=f'groups/{group_id}/members/{user_id}/$ref', resp_type="text")


def suppress_errors_with_404_code(func):
    def wrapper(client: MsGraphClient, args: dict):
        try:
            return func(client, args)
        except NotFoundError:
            if client.handle_error:
                human_readable = f'#### Group id -> {args.get("group_id")} does not exist'
                return human_readable, None, None
            raise
    return wrapper


def test_function_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Tuple.
    """
    client.test_function()
    return 'ok', {}, {}


def list_groups_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Lists all groups and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    order_by = args.get('order_by')
    next_link = args.get('next_link')
    top = args.get('top')
    filter_ = args.get('filter')
    groups = client.list_groups(order_by, next_link, top, filter_)

    groups_readable, groups_outputs = parse_outputs(groups['value'])

    next_link_response = ''
    if '@odata.nextLink' in groups:
        next_link_response = groups['@odata.nextLink']

    if next_link_response:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}NextLink': {'GroupsNextLink': next_link_response},
                         f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': groups_outputs}
        title = 'Groups (Note that there are more results. Please use the next_link argument to see them. The value ' \
                'can be found in the context under MSGraphGroupsNextLink.GroupsNextLink): '
    else:
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': groups_outputs}
        title = 'Groups:'

    human_readable = tableToMarkdown(name=title, t=groups_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail'],
                                     removeNull=True)

    return human_readable, entry_context, groups


@suppress_errors_with_404_code
def get_group_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Get a group by group id and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    group = client.get_group(group_id)

    group_readable, group_outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name="Groups:", t=group_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail',
                                              'Security Enabled', 'Visibility'],
                                     removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(obj.ID === {group_id})': group_outputs}
    return human_readable, entry_context, group


def create_group_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Create a group and return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    required_properties = {
        'displayName': str(args.get('display_name')),
        'mailNickname': str(args.get('mail_nickname')),
        'mailEnabled': args.get('mail_enabled') == 'true',
        'securityEnabled': args.get('security_enabled')
    }

    # create the group
    group = client.create_group(required_properties)

    # display the new group and it's properties
    group_readable, group_outputs = parse_outputs(group)
    human_readable = tableToMarkdown(name=f"{required_properties['displayName']} was created successfully:",
                                     t=group_readable,
                                     headers=['ID', 'Display Name', 'Description', 'Created Date Time', 'Mail',
                                              'Security Enabled', 'Mail Enabled'],
                                     removeNull=True)
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_outputs}
    return human_readable, entry_context, group


@suppress_errors_with_404_code
def delete_group_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Delete a group by group id and return outputs in Demisto's format

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    client.delete_group(group_id)

    # get the group data from the context
    group_data = demisto.dt(demisto.context(), f'{INTEGRATION_CONTEXT_NAME}(val.ID === "{group_id}")')
    if isinstance(group_data, list):
        group_data = group_data[0]

    # add a field that indicates that the group was deleted
    group_data['Deleted'] = True  # add a field with the members to the group
    entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_data}

    human_readable = f'Group: "{group_id}" was deleted successfully.'
    return human_readable, entry_context, NO_OUTPUTS


@suppress_errors_with_404_code
def list_members_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """List a group members by group id. return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    next_link = args.get('next_link')
    top = args.get('top')
    filter_ = args.get('filter')
    members = client.list_members(group_id, next_link, top, filter_)

    if not members['value']:
        human_readable = f'The group {group_id} has no members.'
        return human_readable, NO_OUTPUTS, NO_OUTPUTS

    members_readable, members_outputs = parse_outputs(members['value'])

    # get the group data from the context
    group_data = demisto.dt(demisto.context(), f'{INTEGRATION_CONTEXT_NAME}(val.ID === "{group_id}")')
    if not group_data:
        return_error('Could not find group data in the context, please run "!msgraph-groups-get-group" to retrieve group data.')
    if isinstance(group_data, list):
        group_data = group_data[0]

    if '@odata.nextLink' in members:
        next_link_response = members['@odata.nextLink']
        group_data['Members'] = members_outputs  # add a field with the members to the group
        group_data['MembersNextLink'] = next_link_response
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_data}
        title = f'Group {group_id} members ' \
                f'(Note that there are more results. Please use the next_link argument to see them. The value can be ' \
                f'found in the context under {INTEGRATION_CONTEXT_NAME}.MembersNextLink): '
    else:
        group_data['Members'] = members_outputs  # add a field with the members to the group
        entry_context = {f'{INTEGRATION_CONTEXT_NAME}(val.ID === obj.ID)': group_data}
        title = f'Group {group_id} members:'

    human_readable = tableToMarkdown(name=title, t=members_readable,
                                     headers=['ID', 'Display Name', 'Job Title', 'Mail'],
                                     removeNull=True)

    return human_readable, entry_context, members


@suppress_errors_with_404_code
def add_member_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Add a member to a group by group id and user id. return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    user_id = str(args.get('user_id'))
    required_properties = {
        "@odata.id": f'https://graph.microsoft.com/v1.0/users/{user_id}'}
    client.add_member(group_id, required_properties)

    human_readable = f'User {user_id} was added to the Group {group_id} successfully.'
    return human_readable, NO_OUTPUTS, NO_OUTPUTS


@suppress_errors_with_404_code
def remove_member_command(client: MsGraphClient, args: dict) -> tuple[str, dict, dict]:
    """Remove a member from a group by group id and user id. return outputs in Demisto's format.

    Args:
        client: Client object with request
        args: Usually demisto.args()

    Returns:
        Outputs.
    """
    group_id = str(args.get('group_id'))
    user_id = str(args.get('user_id'))
    client.remove_member(group_id, user_id)

    human_readable = f'User {user_id} was removed from the Group "{group_id}" successfully.'
    return human_readable, NO_OUTPUTS, NO_OUTPUTS


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params: dict = demisto.params()
    base_url = params.get('url', '').rstrip('/') + '/v1.0/'
    tenant = params.get('creds_tenant_id', {}).get('password', '') or params.get('tenant_id') or params.get('_tenant_id')
    auth_and_token_url = params.get('creds_auth_id', {}).get('password', '') or params.get('auth_id') or params.get('_auth_id')
    enc_key = params.get('enc_key') or params.get('credentials', {}).get('password')
    verify = not params.get('insecure', False)
    redirect_uri = params.get('redirect_uri', '')
    auth_code = params.get('creds_auth_code', {}).get('password', '') or params.get('auth_code', '')
    proxy = params.get('proxy')
    handle_error: bool = argToBoolean(params.get('handle_error', 'true'))
    certificate_thumbprint = params.get('credentials_certificate_thumbprint', {}).get(
        'password', '') or params.get('certificate_thumbprint')
    private_key = params.get('private_key')
    managed_identities_client_id = get_azure_managed_identities_client_id(params)
    self_deployed: bool = params.get('self_deployed', False) or managed_identities_client_id is not None

    if not managed_identities_client_id:
        if not self_deployed and not enc_key:
            raise DemistoException('Key must be provided. For further information see '
                                   'https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication')
        elif self_deployed and auth_code and not redirect_uri:
            raise DemistoException('Please provide both Application redirect URI and Authorization code '
                                   'for Authorization Code flow, or None for the Client Credentials flow')
        elif not enc_key and not (certificate_thumbprint and private_key):
            raise DemistoException('Key or Certificate Thumbprint and Private Key must be provided.')
        if not auth_and_token_url:
            raise Exception('Authentication ID must be provided.')
        if not tenant:
            raise Exception('Token must be provided.')

    commands = {
        'test-module': test_function_command,
        'msgraph-groups-list-groups': list_groups_command,
        'msgraph-groups-get-group': get_group_command,
        'msgraph-groups-create-group': create_group_command,
        'msgraph-groups-delete-group': delete_group_command,
        'msgraph-groups-list-members': list_members_command,
        'msgraph-groups-add-member': add_member_command,
        'msgraph-groups-remove-member': remove_member_command
    }
    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        client: MsGraphClient = MsGraphClient(tenant_id=tenant, auth_id=auth_and_token_url, enc_key=enc_key,
                                              app_name=APP_NAME, base_url=base_url, verify=verify, proxy=proxy,
                                              self_deployed=self_deployed, redirect_uri=redirect_uri,
                                              auth_code=auth_code, handle_error=handle_error,
                                              certificate_thumbprint=certificate_thumbprint,
                                              private_key=private_key,
                                              managed_identities_client_id=managed_identities_client_id)
        if command == 'msgraph-groups-generate-login-url':
            return_results(generate_login_url(client.ms_client))
        elif command == 'msgraph-groups-auth-reset':
            return_results(reset_auth())
        else:
            human_readable, entry_context, raw_response = commands[command](client, demisto.args())  # type: ignore
            return_outputs(readable_output=human_readable, outputs=entry_context, raw_response=raw_response)

    except Exception as err:
        return_error(str(err))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
