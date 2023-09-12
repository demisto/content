"""
An integration to MS Graph Service Principals endpoint.
https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
"""

import urllib3
from MicrosoftApiModule import *  # noqa: E402
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
urllib3.disable_warnings()
GRANT_BY_CONNECTION = {'Device Code': DEVICE_CODE, 'Client Credentials': CLIENT_CREDENTIALS}
SCOPE_BY_CONNECTION = {'Device Code': 'offline_access Application.ReadWrite.All',
                       'Client Credentials': 'https://graph.microsoft.com/.default'}


class Client:
    def __init__(self, app_id: str, verify: bool, proxy: bool, connection_type: str, tenant_id: str, enc_key: str,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 managed_identities_client_id: Optional[str] = None):
        if app_id and '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)

        token_retrieval_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token' if 'Client' not in \
                                                                                                     connection_type \
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
            command_prefix="msgraph-apps",
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.connection_type = connection_type

    def get_service_principals(
            self,
            limit: int
    ) -> list:
        """Get all service principals.

        Arguments:
            limit: Maximum of services to get.

        Returns:
            All given service principals

        Docs:
            https://docs.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0&tabs=http
        """
        suffix = 'v1.0/servicePrincipals'
        if limit > 0:
            res = self.ms_client.http_request(
                'GET',
                suffix + f'?$top={limit}'
            )
            return res['value']
        else:  # unlimited, should page
            results = []
            res = self.ms_client.http_request(
                'GET',
                suffix
            )
            results.extend(res.get('value'))
            while next_link := res.get('@odata.nextLink'):
                res = self.ms_client.http_request('GET', '', next_link)
                results.extend(res.get('value'))
            return results

    def get_single_service_principal(
            self,
            object_or_app_id: str
    ):
        """

        Arguments:
            object_or_app_id: object id or application id of the service.

        Returns:
            Retrieve the properties and relationships of a servicePrincipal object.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0&tabs=http
        """
        suffix = f'v1.0/servicePrincipals{object_or_app_id}'
        return self.ms_client.http_request(method='GET', url_suffix=suffix)

    def update_single_service_principal(
            self,
            object_or_app_id: str,
            data: dict
    ):
        """

        Arguments:
            object_or_app_id: object id or application id of the service.
            data: Fields to update.

        Returns:
            Update the properties of servicePrincipal object.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update?view=graph-rest-1.0&tabs=http
        """
        suffix = f'v1.0/servicePrincipals{object_or_app_id}'
        return self.ms_client.http_request(method='PATCH', url_suffix=suffix, json_data=data, return_empty_response=True)

    def delete_service_principals(
            self,
            service_id: str
    ):
        """Deletes a given id from authorized apps.

        Arguments:
            service_id: the service to remove

        Returns:
            True if removed successfully

        Raises:
            DemistoException if no app exists or any other requests error.

        Docs:
            https://docs.microsoft.com/en-us/graph/api/serviceprincipal-delete?view=graph-rest-1.0&tabs=http
        """
        self.ms_client.http_request(method='DELETE', url_suffix=f'v1.0/servicePrincipals{service_id}', return_empty_response=True)


''' COMMAND FUNCTIONS '''


def start_auth(client: Client) -> CommandResults:
    result = client.ms_client.start_auth('!msgraph-apps-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def list_service_principals_command(ms_client: Client, args: dict) -> CommandResults:
    """Lists all service principals

    Arguments:
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
    results = ms_client.get_service_principals(limit)
    return CommandResults(
        'MSGraphApplication',
        'id',
        outputs=results,
        readable_output=tableToMarkdown(
            'Available services (applications):',
            results,
            headers=['id', 'appId', 'appDisplayName', 'accountEnabled', 'deletedDateTime'],
            removeNull=True
        )
    )


def validate_service_principal_input(args: dict) -> tuple:
    """
    Ensure at least one argument is given.

    Args:
        args: The arguments were passed with the command.

    Returns:
        If the two arguments are missing, raise an exception, otherwise return them.
    """
    object_id = args.get('id')
    app_client_id = args.get('app_id')
    if not (object_id or app_client_id):
        raise DemistoException("User must provide one of (object) id or application id.")

    return object_id, app_client_id


def get_service_principal_command(ms_client: Client, args: dict) -> CommandResults:
    """

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    object_id, app_client_id = validate_service_principal_input(args=args)

    # if both are provided, pass the object_id
    if object_id:
        results = ms_client.get_single_service_principal(f"/{object_id}")
    else:
        results = ms_client.get_single_service_principal(f"(appId='{app_client_id}')")

    return CommandResults(
        'MSGraphApplication',
        'id',
        outputs=results,
        readable_output=tableToMarkdown(
            'Available service (application):',
            results,
            headers=['id', 'appId', 'appDisplayName', 'accountEnabled', 'deletedDateTime'],
            removeNull=True
        )
    )


def update_service_principal_command(ms_client: Client, args: dict) -> CommandResults:
    """
    Update the properties of servicePrincipal object.
    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:

    """
    object_id, app_client_id = validate_service_principal_input(args=args)
    data = {}

    if account_enabled := args.get("account_enabled"):
        data["accountEnabled"] = argToBoolean(account_enabled)

    # Dict
    if add_ins := args.get("add_ins"):
        data["addIns"] = add_ins

    # String collection
    if alternative_names := args.get("alternative_names"):
        data["alternativeNames"] = alternative_names

    if app_role_assignment_required := args.get("app_role_assignment_required"):
        data["appRoleAssignmentRequired"] = argToBoolean(app_role_assignment_required)

    # Dict collection
    if app_roles := args.get("app_roles"):
        data["appRoles"] = app_roles

    # Dict
    if custom_security_attributes := args.get("custom_security_attributes"):
        data["customSecurityAttributes"] = custom_security_attributes

    # String
    if display_name := args.get("display_name"):
        data["displayName"] = display_name

    # String
    if home_page := args.get("home_page"):
        data["homepage"] = home_page

    # Dict collection
    if key_credentials := args.get("key_credentials"):
        data["keyCredentials"] = key_credentials

    # String
    if logout_url := args.get("logout_url"):
        data["logoutUrl"] = logout_url

    # Dict collection
    if oauth2_permission_scopes := args.get("oauth2_permission_scopes"):
        data["oauth2PermissionScopes"] = oauth2_permission_scopes

    # String
    if preferred_single_sign_on_mode := args.get("preferred_single_sign_on_mode"):
        data["preferredSingleSignOnMode"] = preferred_single_sign_on_mode

    # String collection
    if reply_urls := args.get("reply_urls"):
        data["replyUrls"] = reply_urls

    # String collection
    if service_principal_names := args.get("service_principal_names"):
        data["servicePrincipalNames"] = service_principal_names

    # String collection
    if tags := args.get("tags"):
        data["tags"] = tags

    # String
    if token_encryption_key_id := args.get("token_encryption_key_id"):
        data["tokenEncryptionKeyId"] = token_encryption_key_id

    # if both are provided, pass the object_id
    if object_id:
        ms_client.update_single_service_principal(f"/{object_id}", data=data)
        service_id = object_id
    else:
        ms_client.update_single_service_principal(f"(appId='{app_client_id}')", data=data)
        service_id = app_client_id

    return CommandResults(
        readable_output=f'Service {service_id} was updated successfully.'
    )


def remove_service_principals_command(ms_client: Client, args: dict) -> CommandResults:
    """Remove an authorized app.

        Arguments:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    object_id, app_client_id = validate_service_principal_input(args=args)

    # if both are provided, pass the object_id
    if object_id:
        ms_client.delete_service_principals(f"/{object_id}")
        service_id = object_id
    else:
        ms_client.delete_service_principals(f"(appId='{app_client_id}')")
        service_id = app_client_id

    return CommandResults(
        readable_output=f'Service {service_id} was deleted.'
    )


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
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if client.connection_type == 'Device Code':
        raise DemistoException(
            "Test module is available for Client Credentials or Azure Managed Identities only,"
            " for other authentication types use the msgraph-apps-auth-start command")

    test_connection(client)
    return "ok"


def main():
    handle_proxy()
    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        command = demisto.command()
        params = demisto.params()
        args = demisto.args()
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
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))
        elif command == 'msgraph-apps-auth-start':
            return_results(start_auth(client))
        elif command == 'msgraph-apps-auth-complete':
            return_results(complete_auth(client))
        elif command == 'msgraph-apps-auth-test':
            return_results(test_connection(client))
        elif command == 'msgraph-apps-auth-reset':
            return_results(reset_auth())
        elif command == 'msgraph-apps-service-principal-list':
            return_results(list_service_principals_command(client, args))
        elif command == 'msgraph-apps-service-principal-remove':
            return_results(remove_service_principals_command(client, args))
        elif command == 'msgraph-apps-service-principal-get':
            return_results(get_service_principal_command(client, args))
        elif command == 'msgraph-apps-service-principal-update':
            return_results(update_service_principal_command(client, args))
        else:
            raise NotImplementedError(f"Command '{command}' not found.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
