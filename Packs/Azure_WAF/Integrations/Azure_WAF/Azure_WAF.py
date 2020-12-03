import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import json
import urllib3
import traceback
from typing import Any, Dict, List, Union
from MicrosoftApiModule import *

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

UPSERT_PARAMS = {'resource_id': 'id', 'policy_settings': 'properties.policySettings',
                 'location': 'location', 'custom_rules': 'properties.customRules',
                 'tags': 'tags', 'managed_rules': 'properties.managedRules'}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2020-05-01'

''' CLIENT CLASS '''


class AzureWAFClient:
    @logger
    def __init__(self, self_deployed, tenant_id, app_id, app_secret, redirect_uri, auth_code,
                 subscription_id, resource_group_name, verify, proxy):

        refresh_token = demisto.getIntegrationContext().get('current_refresh_token')
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/'
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        client_args = {
            'self_deployed': True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.
            'auth_id': app_id,
            'auth_code': auth_code,
            'refresh_token': refresh_token,
            'enc_key': app_secret,
            'redirect_uri': redirect_uri,
            'token_retrieval_url': 'https://login.microsoftonline.com/{tenant_id}/oauth2/token',
            'grant_type': AUTHORIZATION_CODE,  # disable-secrets-detection
            'app_name': '',  # TODO: Do we need an appname?
            'base_url': base_url,
            'verify': verify,
            'proxy': proxy,
            'resource': 'https://management.core.windows.net',
            'tenant_id': tenant_id,
            'ok_codes': (200, 201, 202, 204)
        }
        if not self_deployed:
            client_args['grant_type'] = DEVICE_CODE
            client_args['token_retrieval_url'] = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
            client_args['scope'] = 'https://management.azure.com/user_impersonation offline_access user.read'
        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def http_request(self, method, url_suffix=None, full_url=None, params=None, data=None, resp_type='json'):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,  # disable-secrets-detection
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type)

    def get_policy_by_name(self, policy_name: str, resource_group_name: str) -> Dict:
        return self.http_request(
            method='GET',
            url_suffix=f'/resourceGroups/{resource_group_name}/providers/Microsoft.Network/'
                       f'ApplicationGatewayWebApplicationFirewallPolicies/{policy_name}'
        )

    def get_policy_list_by_resource_group_name(self, resource_group_name: str) -> Dict:
        return self.http_request(
            method='GET',
            url_suffix=f'/resourceGroups/{resource_group_name}/providers/'
                       f'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
        )

    def get_policy_list_by_subscription_id(self) -> Dict:
        return self.http_request(
            method='GET',
            url_suffix='/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'
        )

    def update_policy_upsert(self, policy_name: str, resource_group_name: str, data: Dict) -> Dict:

        return self.http_request(
            method='PUT',
            url_suffix=f'/resourceGroups/{resource_group_name}/providers/'
                       f'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{policy_name}',
            data=data
        )

    def delete_policy(self, policy_name: str, resource_group_name: str) -> Dict:

        return self.http_request(
            method='DELETE',
            url_suffix=f'/resourceGroups/{resource_group_name}/providers/'
                       f'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{policy_name}',
        )


''' COMMAND FUNCTIONS '''


def test_module(client: AzureWAFClient) -> str:
    pass


@logger
def start_auth(client: AzureWAFClient) -> CommandResults:
    user_code = client.ms_client.device_auth_request()
    return CommandResults(readable_output=f"""### Authorization instructions
        1. To sign in, use a web browser to open the page:
            [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
           and enter the code **{user_code}** to authenticate.
        2. Run the **!azure-waf-auth-complete** command in the War Room.""")


@logger
def complete_auth(client: AzureWAFClient):
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def policy_get_command(client: AzureWAFClient, **args) -> CommandResults:
    policy_name: str = args.get('policy_name', '')
    resource_group_name: str = args.get('resource_group_name', client.resource_group_name)
    policies: List[Dict] = []
    try:
        if policy_name:
            policy = client.get_policy_by_name(policy_name, resource_group_name)
            policies.extend(policy)
        else:
            policies.extend(client.get_policy_list_by_resource_group_name(resource_group_name))
    except DemistoException:
        raise
    res = CommandResults(readable_output=policies_to_markdown(policies),
                         outputs=policies,
                         raw_response=policies)
    return res


def policy_get_list_by_subscription_command(client: AzureWAFClient, **args: Dict[str, Any]) -> CommandResults:
    policies: List[Dict] = []
    try:
        policies.extend(client.get_policy_list_by_subscription_id().get("value"))
    except DemistoException:
        raise
    res = CommandResults(readable_output=policies_to_markdown(policies),
                         outputs=policies,
                         raw_response=policies)
    return res


def policy_upsert_command(client: AzureWAFClient, **args: Dict[str, Any]) -> CommandResults:
    def parse_nested_keys_to_dict(base_dict: Dict, keys: List, value: Union[str, Dict]) -> None:
        """ A recursive function to make a list of type [x,y,z] and value a to a dictionary of type {x:{y:{z:a}}}"""
        if len(keys) == 1:
            base_dict[keys[0]] = value
        else:
            if keys[0] not in base_dict:
                base_dict[keys[0]] = {}
            parse_nested_keys_to_dict(base_dict[keys[0]], keys[1:], value)

    policy_name = str(args.get('policy_name', ''))
    resource_group_name = str(args.get('resource_group_name', client.resource_group_name))
    managed_rules = args.get('managed_rules', {})
    location = args.get("location", '')
    if not policy_name or not managed_rules or not location:
        raise Exception('In order to add/ update policy, '
                        'please provide policy_name, location and managed_rules. ')

    body: Dict[str, Any] = {}
    for param in UPSERT_PARAMS:
        val = str(args.get(param, ''))
        try:
            val = json.loads(val)
        except json.decoder.JSONDecodeError:
            pass
        if val:
            key_hierarchy = UPSERT_PARAMS[param].split('.')
            parse_nested_keys_to_dict(base_dict=body, keys=key_hierarchy, value=val)

    updated_policy = client.update_policy_upsert(policy_name, resource_group_name, data=body)
    res = CommandResults(readable_output=policy_to_markdown(updated_policy),
                         outputs=updated_policy,
                         raw_response=updated_policy)
    return res


def policy_delete_command(client: AzureWAFClient, **args: Dict[str, str]):
    policy_name = str(args.get('policy_name', ''))
    resource_group_name = str(args.get('resource_group_name', client.resource_group_name))
    status = client.delete_policy(policy_name, resource_group_name)
    res = CommandResults(readable_output=status.get('status'))
    return res


def policy_to_markdown(policy: Dict):
    deep_policy_fields = {'customRules', 'managedRules'}
    try:
        policy.update(policy.pop('properties', {}))
        md = ""
        for key in policy:
            if isinstance(policy[key], str):
                md += f'**{key}:** {policy[key]} \n'
            if isinstance(policy[key], Dict):
                if key not in deep_policy_fields:
                    md += tableToMarkdown(key, policy[key]) + "\n"
                else:
                    for data in policy[key]:
                        md += tableToMarkdown(data, policy[key][data]) + "\n"
        return md
    except KeyError:
        demisto.debug("Error in creating policy markdown")
        raise


def policies_to_markdown(policies: List[Dict]) -> str:
    md = ""
    for policy in policies:
        md += policy_to_markdown(policy)

    return md


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """
    demisto_commands = {'azure-waf-policy-get': policy_get_command,
                        'azure-waf-policy-list-all-in-subscription': policy_get_list_by_subscription_command,
                        'azure-waf-policy-upsert': policy_upsert_command,
                        'azure-waf-policy-delete': policy_delete_command,
                        'azure-waf-auth-start': start_auth,
                        'azure-waf-auth-complete': complete_auth,

                        }
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    client = AzureWAFClient(
        self_deployed=params.get('self_deployed', False),
        app_id=params.get('app_id', ''),
        tenant_id=params.get('tenant_id', ''),
        app_secret=params.get('app_secret', ''),
        redirect_uri=params.get('redirect_uri', ''),
        subscription_id=params.get('subscription_id', ''),
        auth_code=params.get('auth_code', ''),
        resource_group_name=params.get('resource_group_name', ''),
        verify=not params.get('insecure', False),
        proxy=params.get('proxy', False),
    )

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        if command == 'test-module':
            if params.get('self_deployed'):
                raise ValueError("Please use `!azure-waf-test` instead")
            raise ValueError("Please run `!azure-waf-auth-start` and `!azure-waf-auth-complete` to log in."
                             " For more details press the (?) button.")
        if command == 'azure-waf-test':
            # return_results(test_connection(client, **params))
            pass
        else:
            return_results(demisto_commands[command](client, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
