import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import dateparser
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2019-06-01-preview'
''' CLIENT CLASS '''


class Client:
    """Client class to interact with the service API
    """
    @logger
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy):
        self.resource_group_name = resource_group_name
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}'
        client_args = {
            'self_deployed': True,  # We always set the self_deployed key as True because when not using a self
                                    # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
                                    # flow and most of the same arguments should be set, as we're !not! using OProxy.
            'auth_id': app_id,
            'token_retrieval_url': 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            'grant_type': DEVICE_CODE,  # disable-secrets-detection
            'base_url': base_url,
            'verify': verify,
            'proxy': proxy,
            'resource': 'https://management.core.windows.net',   # disable-secrets-detection
            'scope': 'https://management.azure.com/user_impersonation offline_access user.read',
            'ok_codes': (200, 201, 202, 204),
        }
        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = {},
                     data: dict = None, resp_type: str = 'json') -> requests.Response:
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type)

    @logger
    def azure_sql_servers_list(self):
        return self.http_request('GET', '/providers/Microsoft.Sql/servers')


def azure_sql_servers_list_command(client: Client) -> CommandResults:
    """azure-sql-servers-list command: Returns a list of all servers

    :type client: ``Client``
    :param client: AzureSQLManagement client to use

    :return:
        A ``CommandResults`` object that is then passed to ``return_results``,
        that contains a scan status

    :rtype: ``CommandResults``
    """

    server_list = client.azure_sql_servers_list()

    readable_output = tableToMarkdown(name='Servers List', t=server_list.get('value', ''),
                                      headerTransform=pascalToSpace)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureSQL.Server',
        outputs_key_field='id',
        outputs=server_list
    )


@logger
def test_connection(client: Client) -> CommandResults:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


@logger
def start_auth(client: Client) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!azure-nsg-auth-complete** command in the War Room.""")


@logger
def complete_auth(client: Client) -> CommandResults:
    client.ms_client.get_access_token()
    return CommandResults(readable_output='✅ Authorization completed successfully.')


@logger
def reset_auth(client: Client) -> CommandResults:
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. You can now run '
                                          '**!azure-nsg-auth-start** and **!azure-nsg-auth-complete**.')


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        commands = {
            'azure-sql-servers-list': azure_sql_servers_list_command,
            # 'azure-sql-db-list': azure_sql_db_list_command,
            # 'azure-sql-db-audit-policy-list': azure_sql_db_audit_policy_list_command,
            # 'azure-sql-db-audit-policy-create-update': azure_sql_db_audit_policy_create_update_command,
            # 'azure-sql-db-threat-policy-get': azure_sql_db_threat_policy_get_command,
            # 'azure-sql-db-threat-policy-create-update': azure_sql_db_threat_policy_create_update_command,
            # 'azure-sql-auth-start': start_auth,
            # 'azure-sql-auth-complete': complete_auth,
            # 'azure-sql-auth-reset': reset_auth,
        }
        if command == 'test-module':
            return_error("Please run `!azure-nsg-auth-start` and `!azure-nsg-auth-complete` to log in."
                         " For more details press the (?) button.")

        if command == 'azure-sql-auth-test':
            return_results(test_connection(client))
        else:
            return_results(commands[command](client, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from MicrosoftApiModule import *  # noqa: E402

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
