import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
from MicrosoftApiModule import *  # noqa: E402

import urllib3
import traceback
# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''


DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2022-09-01'
GRANT_BY_CONNECTION = {'Device Code': DEVICE_CODE, 'Authorization Code': AUTHORIZATION_CODE}
SCOPE_BY_CONNECTION = {'Device Code': "https://management.azure.com/user_impersonation offline_access user.read",
                       'Authorization Code': "https://management.azure.com/.default"}
DEFAULT_LIMIT = 50
PREFIX_URL = 'https://management.azure.com/subscriptions/'
''' CLIENT CLASS '''


class AzureNSGClient:
    @logger
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy, connection_type: str,
                 azure_ad_endpoint='https://login.microsoftonline.com', tenant_id: str = None, enc_key: str = None,
                 auth_code: str = None, redirect_uri: str = None,
                 managed_identities_client_id=None):
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = f'{PREFIX_URL}{subscription_id}/' \
            f'resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkSecurityGroups'
        client_args = assign_params(
            self_deployed=True,  # We always set the self_deployed key as True because when not using a self
                                 # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
                                 # flow and most of the same arguments should be set, as we're !not! using OProxy.
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token',
            grant_type=GRANT_BY_CONNECTION.get(connection_type),  # disable-secrets-detection
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            resource='https://management.core.windows.net' if 'Device' in connection_type
            else None,   # disable-secrets-detection
            scope=SCOPE_BY_CONNECTION.get(connection_type),
            ok_codes=(200, 201, 202, 204),
            azure_ad_endpoint=azure_ad_endpoint,
            tenant_id=tenant_id,
            enc_key=enc_key,
            auth_code=auth_code,
            redirect_uri=redirect_uri,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-nsg",
        )
        self.ms_client = MicrosoftClient(**client_args)
        self.connection_type = connection_type

    @logger
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = None,
                     data: dict = None, resp_type: str = 'json') -> requests.Response:

        params = params or {}
        if not params.get('api-version'):
            params['api-version'] = API_VERSION
        return self.ms_client.http_request(method=method,
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type)

    @logger
    def list_network_security_groups(self, subscription_id: str, resource_group_name: str):
        return self.http_request('GET',
                                 full_url=f'{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}/providers\
/Microsoft.Network/networkSecurityGroups?')

    @logger
    def list_rules(self, subscription_id: str, resource_group_name: str, security_group: str):
        return self.http_request('GET',
                                 full_url=f'{PREFIX_URL}{subscription_id}/\
resourceGroups/{resource_group_name}/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules?'
                                 )

    @logger
    def delete_rule(self, security_group_name: str, security_rule_name: str, subscription_id: str, resource_group_name: str):
        return self.http_request('DELETE',
                                 full_url=f'{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}\
/providers/Microsoft.Network/networkSecurityGroups/{security_group_name}/securityRules/{security_rule_name}?',
                                 resp_type='response')

    @logger
    def create_rule(self, security_group: str, rule_name: str, properties: dict, subscription_id: str, resource_group_name: str):
        return self.http_request('PUT',
                                 full_url=f'{PREFIX_URL}{subscription_id}/resourceGroups/{resource_group_name}\
/providers/Microsoft.Network/networkSecurityGroups/{security_group}/securityRules/{rule_name}?',
                                 data={"properties": properties})

    @logger
    def get_rule(self, security_group: str, rule_name: str, subscription_id: str, resource_group_name: str):
        try:
            return self.http_request('GET',
                                     full_url=f'{PREFIX_URL}{subscription_id}/\
resourceGroups/{resource_group_name}/providers/Microsoft.Network/\
networkSecurityGroups/{security_group}/securityRules/{rule_name}?'
                                     )
        except Exception as e:
            if '404' in str(e):
                raise ValueError(f'Rule {rule_name} under subscription ID "{subscription_id}" \
and resource group "{resource_group_name}" was not found.')
            raise

    @logger
    def list_subscriptions_request(self):
        return self.ms_client.http_request(
            method='GET',
            full_url='https://management.azure.com/subscriptions?api-version=2020-01-01')

    @logger
    def list_resource_groups_request(self, subscription_id: str | None,
                                     filter_by_tag: str | None, limit: int | None) -> Dict:
        full_url = f'{PREFIX_URL}{subscription_id}/resourcegroups?'
        return self.ms_client.http_request('GET', full_url=full_url,
                                           params={'$filter': filter_by_tag, '$top': limit,
                                                   'api-version': '2021-04-01'})


'''HELPER FUNCTIONS'''


def format_rule(rule_json: dict | list, security_rule_name: str):
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
def list_groups_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """

    Args:
        client: The MSClient
        params: configuration parameters
        args: args dictionary.

    Returns:
        A detailed list of all network security groups
    """
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')
    network_groups = client.list_network_security_groups(subscription_id=subscription_id,
                                                         resource_group_name=resource_group_name)
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
def list_rules_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """

    Args:
        client: The MSclient
        params: configuration parameters
        args: args dictionary.

    Returns:
        a list of  rules for the security group
    """
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')
    security_group_name = args.get('security_group_name')
    security_groups = argToList(security_group_name)
    rules_limit = arg_to_number(args.get('limit')) or DEFAULT_LIMIT
    rules_offset = (arg_to_number(args.get('offset', '1')) or 1) - 1  # As offset will start at 1
    rules: List = []

    for group in security_groups:
        rules_returned = client.list_rules(subscription_id=subscription_id,
                                           resource_group_name=resource_group_name,
                                           security_group=group)
        rules.extend(rules_returned.get('value', []))
    rules = rules[rules_offset:rules_offset + rules_limit]
    return format_rule(rules, f"in {security_group_name}")


@logger
def delete_rule_command(client: AzureNSGClient, params: Dict, args: Dict) -> str:
    """
    Deletes a rule from a security group
    Args:
        client: The MSClient
        params: configuration parameters
        args: args dictionary.
    """
    security_group_name = args.get('security_group_name')
    security_rule_name = args.get('security_rule_name')
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')
    message = ''
    rule_deleted = client.delete_rule(security_group_name=security_group_name,
                                      security_rule_name=security_rule_name,
                                      subscription_id=subscription_id,
                                      resource_group_name=resource_group_name)
    if rule_deleted.status_code == 204:
        message = (f"Rule '{security_rule_name}' with resource_group_name \
'{resource_group_name} and subscription id '{subscription_id}' was not found.\n\n")
    elif rule_deleted.status_code == 202:
        message = (f"Rule '{security_rule_name}' with resource_group_name \
'{resource_group_name}' and subscription id '{subscription_id}' was successfully deleted.\n\n")

    return message


@logger
def create_rule_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """
    Creates a rule in a security group
    Args:
        client: The MSClient
        params: configuration parameters
        args: args dictionary.
    """
    security_group_name = args.get('security_group_name', '')
    security_rule_name = args.get('security_rule_name', '')
    direction = args.get('direction', '')
    action = args.get('action', 'Allow')
    protocol = args.get('protocol', 'Any')
    source = args.get('source', 'Any')
    source_ports = args.get('source_ports', '*')
    destination = args.get('destination', 'Any')
    destination_ports = args.get('destination_ports', '*')
    priority = args.get('priority', '4096')
    description = args.get('description', '')
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')

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

    rule = client.create_rule(security_group=security_group_name, rule_name=security_rule_name,
                              properties=properties, subscription_id=subscription_id,
                              resource_group_name=resource_group_name)

    return format_rule(rule, security_rule_name)


@logger
def update_rule_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """
    Update an existing rule.

    As I couldn't find a way to just update specific fields, the command gets the existing rule, then updates
    the wanted fields and sends that as a "new" rule. This will update the rule and not create a new rule.

    Args:
        client: The MS Client
        params: configuration parameters
        args: args dictionary.

    Returns:
    an updated rule
    """
    security_group_name = args.get('security_group_name', '')
    security_rule_name = args.get('security_rule_name', '')
    direction = args.get('direction', '')
    action = args.get('action', '')
    protocol = args.get('protocol', '')
    source = args.get('source', '')
    source_ports = args.get('source_ports', '')
    destination = args.get('destination', '')
    destination_ports = args.get('destination_ports', '')
    priority = args.get('priority', '')
    description = args.get('description', '')
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')

    rule = client.get_rule(security_group=security_group_name, rule_name=security_rule_name,
                           subscription_id=subscription_id, resource_group_name=resource_group_name)
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

    rule = client.create_rule(security_group=security_group_name, rule_name=security_rule_name,
                              properties=properties, subscription_id=subscription_id,
                              resource_group_name=resource_group_name)

    return format_rule(rule, security_rule_name)


@logger
def get_rule_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """
    This command will get a rule from a security group.
    Args:
        client: The MS Client
        params: configuration parameters
        args: args dictionary.
    Returns:
        CommandResults: The rule that was requested
    """
    security_group_name = args.get('security_group_name', '')
    security_rule_name = args.get('security_rule_name', '')
    # subscription_id and resource_group_name can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    resource_group_name = get_from_args_or_params(params=params, args=args, key='resource_group_name')
    rule_list = argToList(security_rule_name)

    rules = [client.get_rule(security_group=security_group_name, rule_name=rule,
                             subscription_id=subscription_id, resource_group_name=resource_group_name) for rule in rule_list]
    return format_rule(rules, security_rule_name)


@logger
def nsg_subscriptions_list_command(client: AzureNSGClient) -> CommandResults:
    """
        Gets a list of subscriptions.
    Args:
        client: The microsoft client.
    Returns:
        CommandResults: The command results in MD table and context data.
    """
    res = client.list_subscriptions_request()
    subscriptions = res.get('value', [])

    return CommandResults(
        outputs_prefix='AzureNSG.Subscription',
        outputs_key_field='id',
        outputs=subscriptions,
        readable_output=tableToMarkdown(
            'Azure Network Security Groups Subscriptions list',
            subscriptions,
            ['subscriptionId', 'tenantId', 'displayName', 'state'],
        ),
        raw_response=res
    )


@logger
def nsg_resource_group_list_command(client: AzureNSGClient, params: Dict, args: Dict) -> CommandResults:
    """
    List all resource groups in the subscription.
    Args:
        client (AzureNSGClient): AzureNSG client.
        args (Dict[str, Any]): command arguments.
        params (Dict[str, Any]): configuration parameters.
    Returns:
        Command results with raw response, outputs and readable outputs.
    """
    tag = args.get('tag')
    limit = arg_to_number(args.get('limit', DEFAULT_LIMIT))
    # subscription_id can be passed as command argument or as configuration parameter,
    # if both are passed as arguments, the command argument will be used.
    subscription_id = get_from_args_or_params(params=params, args=args, key='subscription_id')
    filter_by_tag = azure_tag_formatter(tag) if tag else ''

    response = client.list_resource_groups_request(subscription_id=subscription_id,
                                                   filter_by_tag=filter_by_tag, limit=limit)
    data_from_response = response.get('value', [])

    readable_output = tableToMarkdown('Resource Groups List',
                                      data_from_response,
                                      ['name', 'location', 'tags',
                                       'properties.provisioningState'
                                       ],
                                      removeNull=True, headerTransform=string_to_table_header)
    return CommandResults(
        outputs_prefix='AzureNSG.ResourceGroup',
        outputs_key_field='id',
        outputs=data_from_response,
        raw_response=response,
        readable_output=readable_output,
    )


@logger
def test_connection(client: AzureNSGClient, params: dict) -> str:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return '✅ Success!'


@logger
def start_auth(client: AzureNSGClient) -> CommandResults:
    result = client.ms_client.start_auth('!azure-nsg-auth-complete')
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: AzureNSGClient):
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def test_module(client: AzureNSGClient) -> str:
    """Tests API connectivity and authentication'
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.
    :type AzureNSGClient: ``Client``
    :param Client: client to use
    :return: 'ok' if test passed.
    :rtype: ``str``
    """
    # This  should validate all the inputs given in the integration configuration panel,
    # either manually or by using an API that uses them.
    if "Device" in client.connection_type:
        raise DemistoException("Please enable the integration and run `!azure-nsg-auth-start`"
                               "and `!azure-nsg-auth-complete` to log in."
                               "You can validate the connection by running `!azure-nsg-auth-test`\n"
                               "For more details press the (?) button.")
    elif client.connection_type == 'Azure Managed Identities':
        client.ms_client.get_access_token()
        return 'ok'

    else:
        raise Exception("When using user auth flow configuration, "
                        "Please enable the integration and run the !azure-nsg-auth-test command in order to test it")


''' MAIN FUNCTION '''


def main() -> None:     # pragma: no cover
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
            connection_type=params.get('auth_type', 'Device Code'),
            azure_ad_endpoint=params.get('azure_ad_endpoint',
                                         'https://login.microsoftonline.com') or 'https://login.microsoftonline.com',
            tenant_id=params.get('tenant_id'),
            enc_key=params.get('credentials', {}).get('password', ''),
            auth_code=(params.get('auth_code', {})).get('password'),
            redirect_uri=params.get('redirect_uri'),
            managed_identities_client_id=get_azure_managed_identities_client_id(params)
        )
        commands_with_params_and_args = {
            'azure-nsg-security-groups-list': list_groups_command,
            'azure-nsg-security-rules-list': list_rules_command,
            'azure-nsg-security-rule-delete': delete_rule_command,
            'azure-nsg-security-rule-create': create_rule_command,
            'azure-nsg-security-rule-update': update_rule_command,
            'azure-nsg-security-rule-get': get_rule_command,
            'azure-nsg-resource-group-list': nsg_resource_group_list_command

        }
        commands_without_args = {
            'azure-nsg-auth-start': start_auth,
            'azure-nsg-auth-complete': complete_auth,
            'azure-nsg-subscriptions-list': nsg_subscriptions_list_command
        }
        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'azure-nsg-auth-test':
            return_results(test_connection(client, params))
        elif command == 'azure-nsg-generate-login-url':
            return_results(generate_login_url(client.ms_client))
        elif command == 'azure-nsg-auth-reset':
            return_results(reset_auth())
        elif command in commands_without_args:
            return_results(commands_without_args[command](client, **args))
        elif command in commands_with_params_and_args:
            return_results(commands_with_params_and_args[command](client=client, params=params, args=args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
