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
            service_id: str
    ):
        """

        Arguments:
            service_id: object id or application id of the service.

        Returns:
            Retrieve the properties and relationships of a servicePrincipal object.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/serviceprincipal-get?view=graph-rest-1.0&tabs=http
        """
        suffix = f'v1.0/servicePrincipals{service_id}'
        return self.ms_client.http_request(method='GET', url_suffix=suffix)

    def update_single_service_principal(
            self,
            service_id: str,
            data: dict
    ):
        """

        Arguments:
            service_id: object id or application id of the service.
            data: Fields to update.

        Returns:
            Update the properties of servicePrincipal object.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/serviceprincipal-update?view=graph-rest-1.0&tabs=http
        """
        suffix = f'v1.0/servicePrincipals{service_id}'
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

    def add_password_service_principal(
            self,
            service_id: str,
            data: dict
    ):
        """

        Arguments:
            service_id: object id or application id of the service.
            data: the body request. As you can see in the documentation, it may have displayName, endDateTime, and startDateTime.

        Returns:
            Adds a strong password or secret to an application.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/application-addpassword?view=graph-rest-1.0&tabs=http
        """
        suffix = f'v1.0/servicePrincipals{service_id}/addPassword'
        json_data = {"passwordCredential": data}
        return self.ms_client.http_request(method='POST', url_suffix=suffix, json_data=json_data)

    def remove_password_service_principal(
            self,
            service_id: str,
            data: dict
    ):
        """

        Arguments:
            service_id: object id or application id of the service.
            data: the body request. As you can see in the documentation, it should contain the keyId,
            the unique identifier for the password.

        Returns:
            Remove a password from an application.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/application-removepassword?view=graph-rest-1.0&tabs=http
        """
        suffix = f'v1.0/servicePrincipals{service_id}/removePassword'
        return self.ms_client.http_request(method='POST', url_suffix=suffix, json_data=data, return_empty_response=True)

    def unlock_configuration_service_principal(
            self,
            service_id: str,
            lock: bool
    ):
        """

        Arguments:
            lock: Whether to lock or unlock. True to lock, False to unlock.
            service_id: object id or application id of the service.

        Returns:
            Remove a password from an application.

        Docs:
            https://learn.microsoft.com/en-us/graph/api/application-removepassword?view=graph-rest-1.0&tabs=http
        """
        data = {"servicePrincipalLockConfiguration":
                {"isEnabled": lock,
                 "credentialsWithUsageSign": True,
                 "credentialsWithUsageVerify": True}
                }
        suffix = f'/beta/applications/{service_id}'
        return self.ms_client.http_request(method='PATCH', url_suffix=suffix, json_data=data, return_empty_response=True)


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


def validate_service_principal_input(args: dict) -> tuple[str, Optional[Any]]:
    """
    Ensure at least one argument (object) id or app id is given.

    Args:
        args: The arguments were passed with the command.

    Returns:
        If the two arguments are missing, raise an exception, otherwise return the (object) id.
        This validation returns tuple, the first element will be sent to the api call, the second is the given id/app id as is.
    """
    object_id = args.get('id')
    app_client_id = args.get('app_id')
    if not (object_id or app_client_id):
        raise DemistoException("Either the (object's) `id` or the `application_id` arguments must be provided.")

    # if both are provided, pass the object_id
    if object_id:
        return f"/{object_id}", object_id
    return f"(appId='{app_client_id}')", app_client_id


def get_service_principal_command(ms_client: Client, args: dict) -> CommandResults:
    """

    Args:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    id_for_request, service_id = validate_service_principal_input(args=args)
    results = ms_client.get_single_service_principal(id_for_request)
    return CommandResults(
        'MSGraphApplication',
        'id',
        outputs=results,
        readable_output=tableToMarkdown(
            'Service Principal (application):',
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
        an informative message.
    """
    id_for_request, service_id = validate_service_principal_input(args=args)
    fields_to_update = {"app_role_assignment_required": "appRoleAssignmentRequired", "display_name": "displayName",
                        "preferred_single_sign_on_mode": "preferredSingleSignOnMode"
                        }
    boolean_fields_to_update = {"account_enabled": "accountEnabled", "app_role_assignment_required": "appRoleAssignmentRequired"}

    data = {
        fields_to_update[field]: args[field]
        for field in fields_to_update
        if field in args
    }

    for field in boolean_fields_to_update:
        if field in args:
            data[boolean_fields_to_update[field]] = argToBoolean(args[field])

    ms_client.update_single_service_principal(id_for_request, data=data)

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
    id_for_request, service_id = validate_service_principal_input(args=args)
    ms_client.delete_service_principals(id_for_request)
    return CommandResults(
        readable_output=f'Service {service_id} was deleted.'
    )


def add_password_service_principal_command(ms_client: Client, args: dict) -> CommandResults:
    """
    Adds a strong password or secret to the service principal.

    Arguments:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    id_for_request, service_id = validate_service_principal_input(args=args)

    fields_for_body_request = {"display_name": "displayName", "end_date_time": "endDateTime", "start_date_time": "startDateTime"}

    data = {
        fields_for_body_request[field]: args[field]
        for field in fields_for_body_request
        if field in args
    }

    # If the user didn't pass the expiration time, we set it to 1 hour when the API set it to +2 years.
    if "endDateTime" not in data:
        data["endDateTime"] = str(datetime.now() + timedelta(hours=1))

    results = ms_client.add_password_service_principal(id_for_request, data=data)

    return CommandResults(
        'MSGraphApplication',
        'id',
        outputs=results,
        readable_output=f'A password was added to application {service_id} successfully.'
    )


def remove_password_service_principal_command(ms_client: Client, args: dict) -> CommandResults:
    """
    Remove a password from the service principal.

    Arguments:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    id_for_request, service_id = validate_service_principal_input(args=args)

    data = {"keyId": args["key_id"]}

    ms_client.remove_password_service_principal(id_for_request, data=data)

    return CommandResults(
        readable_output=f'The password of the unique identifier {args["key_id"]} was removed successfully.'
    )


def change_configuration_service_principal_lock_status(ms_client: Client, args: dict, lock: bool) -> CommandResults:
    """
    Unlock / Lock configuration of a service principal.

    Arguments:
        lock: in the case of locking back the configuration.
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    object_id = args["id"]

    ms_client.unlock_configuration_service_principal(service_id=object_id, lock=lock)

    return CommandResults(
        readable_output=f'The configuration of {object_id} was {"locked" if lock else "unlocked"} successfully.'
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


def main():  # pragma: no cover
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
        elif command == 'msgraph-apps-service-principal-password-add':
            return_results(add_password_service_principal_command(client, args))
        elif command == 'msgraph-apps-service-principal-password-remove':
            return_results(remove_password_service_principal_command(client, args))
        elif command == 'msgraph-apps-service-principal-unlock-configuration':
            return_results(change_configuration_service_principal_lock_status(client, args, lock=False))
        elif command == 'msgraph-apps-service-principal-lock-configuration':
            return_results(change_configuration_service_principal_lock_status(client, args, lock=True))
        else:
            raise NotImplementedError(f"Command '{command}' not found.")

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
