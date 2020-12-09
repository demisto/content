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
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy):

        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = demisto.getIntegrationContext()
            integration_context.update(current_refresh_token=refresh_token)
            demisto.setIntegrationContext(integration_context)
        base_url = f'https://management.azure.com/subscriptions/{subscription_id}/'
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        client_args = client_args = {
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
            'ok_codes': (200, 201, 202, 204)
        }

        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: Dict = None,
                     data: Dict = None, resp_type: str = 'json', return_empty_response: bool = False):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,  # disable-secrets-detection
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type,
                                           timeout=20,
                                           return_empty_response=return_empty_response)

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

    def delete_policy(self, policy_name: str, resource_group_name: str):

        return self.http_request(
            method='DELETE',
            return_empty_response=True,
            resp_type='response',
            url_suffix=f'/resourceGroups/{resource_group_name}/providers/'
                       f'Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{policy_name}',
        )


''' COMMAND FUNCTIONS '''


def test_connection(client: AzureWAFClient, params: Dict):
    if params.get('self_deployed', False) and not params.get('auth_code'):
        return_error('You must enter an authorization code in a self-deployed configuration.')
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return '✅ Success!'


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
    verbose = True if args.get("verbose", "false") == "true" else False
    limit = str(args.get("limit"))
    if not limit.isdigit():
        raise Exception("please provide a numeric limit")
    limit = int(limit)

    policies: List[Dict] = []
    try:
        if policy_name:
            policy = client.get_policy_by_name(policy_name, resource_group_name)
            policies.append(policy)
        else:
            policy = client.get_policy_by_name(policy_name, resource_group_name).get('value', [])
            policies.extend(policy)
    except Exception:
        raise
    res = CommandResults(readable_output=policies_to_markdown(policies, verbose, limit), outputs=policies,
                         outputs_key_field='id', outputs_prefix='AzureWAF.Policy',
                         raw_response=policies)
    return res


def policy_get_list_by_subscription_command(client: AzureWAFClient, **args: Dict[str, Any]) -> CommandResults:
    policies: List[Dict] = []
    verbose = True if args.get("verbose", "false") == "true" else False
    limit = str(args.get("limit"))
    if not limit.isdigit():
        raise Exception("please provide a numeric limit")
    limit = int(limit)
    try:
        policies.extend(client.get_policy_list_by_subscription_id().get("value", []))
    except DemistoException:
        raise
    res = CommandResults(readable_output=policies_to_markdown(policies, verbose, limit),
                         outputs=policies, outputs_key_field='id', outputs_prefix='AzureWAF.Policy',
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
    verbose = True if args.get("verbose", "false") == "true" else False

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
    updated_policy = [client.update_policy_upsert(policy_name, resource_group_name, data=body)]
    res = CommandResults(readable_output=policies_to_markdown(updated_policy, verbose),
                         outputs=updated_policy,
                         outputs_key_field='id', outputs_prefix='AzureWAF.Policy',
                         raw_response=updated_policy)
    return res


def policy_delete_command(client: AzureWAFClient, **args: Dict[str, str]):
    policy_name = str(args.get('policy_name', ''))
    resource_group_name = str(args.get('resource_group_name', client.resource_group_name))
    policy_id = f'/subscriptions/{client.subscription_id}/resourceGroups/{resource_group_name}/' \
                f'providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/{policy_name}'
    status = client.delete_policy(policy_name, resource_group_name)
    md = f"Response got {status.status_code} status code."
    context = None
    if status.status_code in [200, 202]:
        md = f"Policy {policy_name} was deleted successfully."
        old_context = demisto.dt(demisto.context(), f'AzureWAF.Policy(val.id === "{policy_id}")')
        if old_context:
            if isinstance(old_context, list):
                old_context = old_context[0]
            old_context['IsDeleted'] = True
            context = {
                'AzureWAF.Policy(val.id === obj.id)': old_context
            }
    if status.status_code == 204:
        md = f"Policy {policy_name} was not found."

    res = CommandResults(outputs=context, readable_output=md)
    return res


def policies_to_markdown(policies: List[Dict], verbose: bool = False, limit: int = 10) -> str:
    def policy_to_full_markdown(policy_data: Dict):
        """
        Creates a full markdown with all data field of the policy.
        """
        deep_policy_fields = {'customRules', 'managedRules', 'policySettings'}
        try:
            policy_data.update(policy_data.pop('properties', {}))
            short_md = ""
            policy_for_md = {}
            for key in policy_data:
                if key not in deep_policy_fields:
                    policy_for_md[key] = policy_data[key]
                else:
                    short_md += tableToMarkdown(key, policy_data[key]) + "\n"

            short_md = tableToMarkdown(f"Policy: {policy_data.get('name')}", policy_for_md) + short_md
            return short_md

        except KeyError:
            demisto.debug("Policy has no 'properties' section")
            raise Exception("Policy does not have 'properties' section, "
                            "therefore has invalid structure, please contact a developer.")

    def policy_to_short_markdown(policy_data: Dict):
        """
        Creates a short markdown containing only basic information on policy.
        """
        short_md = ''
        try:
            policy_data.pop('properties')
            policy_for_md = {}
            for key in policy_data:
                policy_for_md[key] = policy_data[key]

            short_md = tableToMarkdown(f"Policy: {policy_data.get('name')}", policy_for_md) + short_md

        except KeyError:
            demisto.debug("Policy has no 'properties' section")
            raise Exception("Policy does not have 'properties' section, "
                            "therefore has invalid structure, please contact a developer.")
        return short_md

    md = ""
    policies_num = len(policies)
    policies = policies[:min(limit, policies_num)]
    for policy in policies:
        md += policy_to_full_markdown(policy.copy()) if verbose else policy_to_short_markdown(policy.copy())

    md += f"Showing {min(limit, len(policies))} policies out of {policies_num}"
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
                        'azure-waf-test': test_connection,

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
