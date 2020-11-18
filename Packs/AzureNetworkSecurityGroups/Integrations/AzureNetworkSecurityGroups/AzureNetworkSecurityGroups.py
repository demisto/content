import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
from typing import Any, Dict, Tuple, List, Optional, Union, cast

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2020-05-01'

''' CLIENT CLASS '''


class Client:
    @logger
    def __init__(self, self_deployed, refresh_token, auth_and_token_url, enc_key, redirect_uri, auth_code,
                 subscription_id, resource_group_name, workspace_name, verify, proxy):
        #TODO: do we need the `workspace_name` parameter?

        tenant_id = refresh_token if self_deployed else ''  #TODO: why is this saved in the refresh token?
        refresh_token = (demisto.getIntegrationContext().get('current_refresh_token') or refresh_token)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/' \
            f'resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkSecurityGroups'
        self.ms_client = MicrosoftClient(
            self_deployed=self_deployed,
            auth_id=auth_and_token_url,
            refresh_token=refresh_token,
            enc_key=enc_key,
            redirect_uri=redirect_uri,
            token_retrieval_url='https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            grant_type=AUTHORIZATION_CODE,  # disable-secrets-detection
            app_name='',  #TODO: Do we need an appname?
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            resource='https://management.core.windows.net',
            scope='',  # TODO: See if scope is needed
            tenant_id=tenant_id,
            auth_code=auth_code,
            ok_codes=(200, 201, 202, 204, 400, 401, 403, 404)  # TODO: why are these OK codes?
        )

    @logger
    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None, is_get_entity_cmd=False):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,  # disable-secrets-detection
                                          url_suffix=url_suffix,
                                          full_url=full_url,
                                          json_data=data,
                                          params=params)

    @logger
    def list_network_security_groups(self):
        return self.http_request('GET', '')


    @logger
    def list_rules(self, security_group: str):
        return self.http_request('GET', f'{security_group}/securityRules')


''' COMMAND FUNCTIONS '''


@logger
def list_groups_command(client: Client, args: dict) -> dict:
    """

    Args:
        client: The MSClient
        args: args dictionary. Should be empty for this command.

    Returns:
        A detailed list of all network security groups
    """
    network_groups = client.list_network_security_groups()
    network_groups = network_groups.get('value', [])

    # The property value holds all the rules under the security group. This will be returned in a different command.
    for group in network_groups:
        group.pop('properties', '')

    hr = tableToMarkdown('Network Security Groups', network_groups)
    return CommandResults(outputs_prefix='AzureNSG.SecurityGroup',
                          outputs_key_field='id',
                          outputs=network_groups,
                          readable_output=hr)


@logger
def list_rules_command(client: Client, args: dict) -> dict:
    """

    Args:
        client: The MSclient
        args: args should hold the name of the security group as `security_group_name` (the value could be a
            comma-seperated list of names).

    Returns:
        a list of  rules for the security group
    """
    #TODO: in the yml, check isArray
    security_groups = argToList(args.get('security_group_name', ''))
    rules = []
    for group in security_groups:
        rules_returned = client.list_rules(group)
        rules.extend(rules_returned.get('value', []))


    # We want to flatten the rules `properties` key as this is the more important key and we'd like to be able to display it nicely
    for rule in rules:
        rule.update(rule.pop('properties', {}))
    hr = tableToMarkdown(f"Rules in {args.get('security_group_name', '')}", rules, removeNull=True)

    return CommandResults(outputs_prefix='AzureNSG.Rules',
                          outputs_key_field='id',
                          outputs=rules,
                          readable_output=hr)


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(
            self_deployed=params.get('self_deployed', False),
            auth_and_token_url=params.get('auth_id', ''),
            refresh_token=params.get('tenant_id', ''),
            enc_key=params.get('enc_key', ''),
            redirect_uri=params.get('redirect_uri', ''),
            auth_code=params.get('auth_code', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            workspace_name=params.get('workspaceName', ''),  #TODO: is it needed?
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False)
        )
        commands = {
            'azure-nsg-list-groups': list_groups_command,
            'azure-nsg-list-rules': list_rules_command,
        }

        return_results(commands[command](client, args))


    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


from MicrosoftApiModule import *

''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()


