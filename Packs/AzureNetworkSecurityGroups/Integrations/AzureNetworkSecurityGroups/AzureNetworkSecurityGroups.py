import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
import traceback
from typing import List, Union

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2020-05-01'

''' CLIENT CLASS '''


class AzureNSGClient:
    @logger
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/' \
            f'resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkSecurityGroups'
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
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = None,
                     data: dict = None, resp_type: str = 'json') -> requests.Response:
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type)

    @logger
    def list_network_security_groups(self):
        return self.http_request('GET', '')

    @logger
    def list_rules(self, security_group: str):
        return self.http_request('GET', f'{security_group}/securityRules')

    @logger
    def delete_rule(self, security_group: str, rule_name: str):
        return self.http_request('DELETE', f'/{security_group}/securityRules/{rule_name}', resp_type='response')

    @logger
    def create_rule(self, security_group: str, rule_name: str, properties: dict):
        return self.http_request('PUT', f'/{security_group}/securityRules/{rule_name}', data={"properties": properties})

    @logger
    def get_rule(self, security_group: str, rule_name: str):
        try:
            return self.http_request('GET', f'/{security_group}/securityRules/{rule_name}')
        except Exception as e:
            if '404' in str(e):
                raise ValueError(f'Rule {rule_name} was not found.')
            raise


'''HELPER FUNCTIONS'''


def format_rule(rule_json: Union[dict, List], security_rule_name: str):
    """
    format the rule and create the commandResult object with it
    Args:
        rule_json: the json returned from the http_request
        security_rule_name: the name of the rule

    Returns:
        CommandResults for the rule
    """
    # We want to flatten the rules `properties` key as this is the more important key and we'd like
    # to be able to display it nicely
    if isinstance(rule_json, dict):
        rule_json.update(rule_json.pop('properties', {}))
    if isinstance(rule_json, list):
        for rule in rule_json:
            rule.update(rule.pop('properties', {}))

    hr = tableToMarkdown(f"Rules {security_rule_name}", rule_json, removeNull=True)

    return CommandResults(outputs_prefix='AzureNSG.Rule',
                          outputs_key_field='id',
                          outputs=rule_json,
                          readable_output=hr)


''' COMMAND FUNCTIONS '''


@logger
def list_groups_command(client: AzureNSGClient) -> CommandResults:
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
def list_rules_command(client: AzureNSGClient, security_group_name: str, limit: str = '50', offset: str = '1')\
        -> CommandResults:
    """

    Args:
        client: The MSclient
        security_group_name: a comma-seperated list of security group names
        limit: The maximum number of rules to display
        offset: The index of the first rule to display

    Returns:
        a list of  rules for the security group
    """
    security_groups = argToList(security_group_name)
    rules_limit = int(limit)
    rules_offset = int(offset) - 1  # As offset will start at 1
    rules: List = list()
    for group in security_groups:
        rules_returned = client.list_rules(group)
        rules.extend(rules_returned.get('value', []))
    rules = rules[rules_offset:rules_offset + rules_limit]
    return format_rule(rules, f"in {security_group_name}")


@logger
def delete_rule_command(client: AzureNSGClient, security_group_name: str, security_rule_name: str) -> str:
    """

    Args:
        client: The MSClient
        security_group_name: the name of the security group
        security_rule_name: The name of the rule to delete

    """

    rule_deleted = client.delete_rule(security_group_name, security_rule_name)
    if rule_deleted.status_code == 204:
        return f"Rule {security_rule_name} not found."
    if rule_deleted.status_code == 202:
        return f"Rule {security_rule_name} deleted."
    else:
        return f"Rule {security_rule_name} was not deleted. Got back the following result:\n{rule_deleted.content}"


@logger
def create_rule_command(client: AzureNSGClient, security_group_name: str, security_rule_name: str, direction: str,
                        action: str = 'Allow', protocol: str = 'Any', source: str = 'Any', source_ports: str = '*',
                        destination: str = 'Any', destination_ports: str = '*', priority: str = '4096',
                        description: str = None):

    # The reason for using 'Any' as default instead of '*' is to adhere to the standards in the UI.
    properties = {
        "protocol": '*' if protocol == 'Any' else protocol,
        "access": action,
        "priority": priority,
        "direction": direction,
    }
    source_ports_list = argToList(source_ports)
    if len(source_ports_list) > 1:
        properties["sourcePortRanges"] = source_ports_list
    else:
        properties["sourcePortRange"] = source_ports

    dest_ports_list = argToList(destination_ports)
    if len(dest_ports_list) > 1:
        properties['destinationPortRanges'] = dest_ports_list
    else:
        properties['destinationPortRange'] = destination_ports

    source_list = argToList(source)
    if len(source_list) > 1:
        properties["sourceAddressPrefixes"] = source_list
    else:
        properties["sourceAddressPrefix"] = '*' if source == 'Any' else source

    dest_list = argToList(destination)
    if len(dest_list) > 1:
        properties["destinationAddressPrefixes"] = dest_list
    else:
        properties["destinationAddressPrefix"] = '*' if destination == 'Any' else destination

    if description:
        properties['description'] = description
    rule = client.create_rule(security_group_name, security_rule_name, properties)

    return format_rule(rule, security_rule_name)


@logger
def update_rule_command(client: AzureNSGClient, security_group_name: str, security_rule_name: str, direction: str = None,
                        action: str = None, protocol: str = None, source: str = None, source_ports: str = None,
                        destination: str = None, destination_ports: str = None, priority: str = None,
                        description: str = None) -> CommandResults:
    """
    Update an existing rule.

    As I couldn't find a way to just update specific fields, the command gets the existing rule, then updates
    the wanted fields and sends that as a "new" rule. This will update the rule and not create a new rule.

    Args:
        client: The MS Client
        security_group_name: the security group name
        security_rule_name: The name of the rule to update
        ... The rest of the arguments are described in the command yml

    Returns:
    an updated rule
    """

    rule = client.get_rule(security_group_name, security_rule_name)
    properties = rule.get('properties')

    updated_properties = assign_params(protocol='*' if protocol == 'Any' else protocol,
                                       access=action, priority=priority,
                                       direction=direction, description=description)
    if source_ports:
        source_ports_list = argToList(source_ports)
        if len(source_ports_list) > 1:
            properties.pop("sourcePortRange", None)  # Can't supply both sourcePortRange and sourcePortRanges
            updated_properties["sourcePortRanges"] = source_ports_list
        else:
            properties.pop("sourcePortRanges", None)  # Can't supply both sourcePortRange and sourcePortRanges
            updated_properties["sourcePortRange"] = source_ports

    if destination_ports:
        dest_ports_list = argToList(destination_ports)
        if len(dest_ports_list) > 1:
            properties.pop("destinationPortRange", None)  # Can't supply both destinationPortRange,destinationPortRanges
            updated_properties['destinationPortRanges'] = dest_ports_list
        else:
            properties.pop("destinationPortRanges", None)  # Can't supply destinationPortRange and destinationPortRanges
            updated_properties['destinationPortRange'] = destination_ports

    if destination:
        dest_list = argToList(destination)
        if len(dest_list) > 1:
            properties.pop("destinationAddressPrefix", None)  # Can't supply both destinationAddressPrefix and
            # destinationAddressPrefix
            updated_properties['destinationAddressPrefixes'] = dest_list
        else:
            properties.pop("destinationAddressPrefixes", None)  # Can't supply both
            # destinationAddressPrefixes, destinationAddressPrefixes
            updated_properties['destinationAddressPrefix'] = '*' if destination == 'Any' else destination

    if source:
        source_list = argToList(source)
        if len(source_list) > 1:
            properties.pop("sourceAddressPrefix", None)  # Can't supply both sourceAddressPrefixes, sourceAddressPrefix
            updated_properties['sourceAddressPrefixes'] = source_list
        else:
            properties.pop("sourceAddressPrefixes", None)  # Can't supply both sourceAddressPrefixes,sourceAddressPrefix
            updated_properties['sourceAddressPrefix'] = '*' if source == 'Any' else source

    properties.update(updated_properties)

    rule = client.create_rule(security_group_name, security_rule_name, properties)
    return format_rule(rule, security_rule_name)


@logger
def get_rule_command(client: AzureNSGClient, security_group_name: str, security_rule_name: str):
    rules = []
    rule_list = argToList(security_rule_name)
    for rule in rule_list:
        rules.append(client.get_rule(security_group_name, rule))
    return format_rule(rules, security_rule_name)


@logger
def test_connection(client: AzureNSGClient, params: dict) -> str:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return '✅ Success!'


@logger
def start_auth(client: AzureNSGClient) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
1. To sign in, use a web browser to open the page [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
 and enter the code **{user_code}** to authenticate.
2. Run the **!azure-nsg-auth-complete** command in the War Room.""")


@logger
def complete_auth(client: AzureNSGClient):
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


@logger
def reset_auth(client: AzureNSGClient):
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. You can now run '
                                          '**!azure-nsg-auth-start** and **!azure-nsg-auth-complete**.')


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')
    try:
        client = AzureNSGClient(
            app_id=params.get('app_id', ''),
            subscription_id=params.get('subscription_id', ''),
            resource_group_name=params.get('resource_group_name', ''),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        commands = {
            'azure-nsg-security-groups-list': list_groups_command,
            'azure-nsg-security-rules-list': list_rules_command,
            'azure-nsg-security-rule-delete': delete_rule_command,
            'azure-nsg-security-rule-create': create_rule_command,
            'azure-nsg-security-rule-update': update_rule_command,
            'azure-nsg-security-rule-get': get_rule_command,
            'azure-nsg-auth-start': start_auth,
            'azure-nsg-auth-complete': complete_auth,
            'azure-nsg-auth-reset': reset_auth,
        }
        if command == 'test-module':
            return_error("Please run `!azure-nsg-auth-start` and `!azure-nsg-auth-complete` to log in."
                         " For more details press the (?) button.")

        if command == 'azure-nsg-auth-test':
            return_results(test_connection(client, params))
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
