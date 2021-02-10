"""
An integration to MS Graph Service Principals endpoint.
https://docs.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
"""

import urllib3

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

# Disable insecure warnings
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
            scope='offline_access Application.ReadWrite.All'
        )

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
            results = list()
            res = self.ms_client.http_request(
                'GET',
                suffix
            )
            results.extend(res.get('value'))
            while next_link := res.get('@odata.nextLink'):
                res = self.ms_client.http_request('GET', '', next_link)
                results.extend(res.get('value'))
            return results

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
        self.ms_client.http_request(
            'DELETE', f'v1.0/servicePrincipals/{service_id}', return_empty_response=True
        )


''' COMMAND FUNCTIONS '''


def start_auth(client: Client) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!msgraph-apps-auth-complete** command in the War Room.""")


def complete_auth(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_connection(client: Client) -> str:
    client.ms_client.get_access_token()
    return '✅ Success!'


def reset_auth() -> CommandResults:
    set_integration_context({})
    return CommandResults(
        readable_output='Authorization was reset successfully. Run **!msgraph-apps-start** to start the '
                        'authentication process.'
    )


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


def remove_service_principals_command(ms_client: Client, args: dict) -> CommandResults:
    """Remove an authorized app.

        Arguments:
        ms_client: The Client
        args: demisto.args()

    Returns:
        Results to post in demisto
    """
    app_id = str(args.get('id'))
    ms_client.delete_service_principals(app_id)
    return CommandResults(
        readable_output=f'Service {app_id} was deleted.'
    )


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
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('The test module is not functional, run the msgraph-apps-auth-start command instead.')
        elif command == 'msgraph-apps-auth-start':
            return_results(start_auth(client))
        elif command == 'msgraph-apps-auth-complete':
            return_results(complete_auth(client))
        elif command == 'msgraph-apps-auth-test':
            return_results(test_connection(client))
        elif command == 'msgraph-apps-auth-reset':
            return_results(test_connection(client))
        elif command == 'msgraph-apps-service-principal-list':
            return_results(list_service_principals_command(client, args))
        elif command == 'msgraph-apps-service-principal-remove':
            return_results(remove_service_principals_command(client, args))
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
