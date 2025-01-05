import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import contextlib
from CommonServerUserPython import *

from typing import Any
from MicrosoftApiModule import *
import urllib3

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

UPSERT_PARAMS = {'resource_id': 'id', 'policy_settings': 'properties.policySettings',
                 'location': 'location', 'custom_rules': 'properties.customRules',
                 'tags': 'tags', 'managed_rules': 'properties.managedRules'}

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
API_VERSION = '2020-05-01'
BASE_URL = 'https://management.azure.com'
POLICY_PATH = 'providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies'

''' CLIENT CLASS '''


class AzureWAFClient:
    @logger
    def __init__(self, app_id, subscription_id, resource_group_name, verify, proxy, auth_type, tenant_id=None,
                 enc_key=None, auth_code=None, redirect_uri=None,
                 azure_ad_endpoint: str = 'https://login.microsoftonline.com',
                 managed_identities_client_id: str = None):
        AUTH_TYPES_DICT: dict = {
            'Authorization Code': {
                'grant_type': AUTHORIZATION_CODE,
                'resource': None,
                'scope': 'https://management.azure.com/.default'
            },
            'Device Code': {
                'grant_type': DEVICE_CODE,
                'resource': 'https://management.core.windows.net',
                'scope': 'https://management.azure.com/user_impersonation offline_access user.read'
            },
            'Client Credentials': {
                'grant_type': CLIENT_CREDENTIALS,
                'resource': None,
                'scope': 'https://management.azure.com/.default'
            }
        }
        # for dev environment use:
        if '@' in app_id:
            app_id, refresh_token = app_id.split('@')
            integration_context = get_integration_context()
            integration_context.update(current_refresh_token=refresh_token)
            set_integration_context(integration_context)
        base_url = f'{BASE_URL}/subscriptions/{subscription_id}'
        self.subscription_id = subscription_id
        self.resource_group_name = resource_group_name
        client_args = assign_params(
            self_deployed=True,  # We always set the self_deployed key as True because when not using a self
            # deployed machine, the DEVICE_CODE flow should behave somewhat like a self deployed
            # flow and most of the same arguments should be set, as we're !not! using OProxy.
            auth_id=app_id,
            token_retrieval_url='https://login.microsoftonline.com/organizations/oauth2/v2.0/token' if 'Device Code' in
                                                                                                       auth_type else None,
            grant_type=AUTH_TYPES_DICT.get(auth_type, {}).get('grant_type'),  # disable-secrets-detection
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            resource=AUTH_TYPES_DICT.get(auth_type, {}).get('resource'),  # disable-secrets-detection
            scope=AUTH_TYPES_DICT.get(auth_type, {}).get('scope'),
            ok_codes=(200, 201, 202, 204),
            redirect_uri=redirect_uri,
            auth_code=auth_code,
            azure_ad_endpoint=azure_ad_endpoint,
            tenant_id=tenant_id,
            enc_key=enc_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-waf",
        )

        self.ms_client = MicrosoftClient(**client_args)

    @logger
    def http_request(self, method: str, url_suffix: str = None, full_url: str = None, params: dict = None,
                     data: dict = None, resp_type: str = 'json', return_empty_response: bool = False):
        if not params:
            params = {}
        if not full_url:
            params['api-version'] = API_VERSION

        return self.ms_client.http_request(method=method,
                                           url_suffix=url_suffix,
                                           full_url=full_url,
                                           json_data=data,
                                           params=params,
                                           resp_type=resp_type,
                                           timeout=20,
                                           return_empty_response=return_empty_response)

    def get_policy_by_name(self, policy_name: str, subscription_id: str, resource_group_name_list: list) -> list[dict]:
        base_url = f'{BASE_URL}/subscriptions/{subscription_id}'
        res = []
        for resource_group_name in resource_group_name_list:
            try:
                res.append(self.http_request(
                    method='GET',
                    full_url=f'{base_url}/resourceGroups/{resource_group_name}/{POLICY_PATH}/{policy_name}',
                    params={'api-version': API_VERSION}
                ))
            except Exception as e:
                res.append({'properties': f'{resource_group_name} threw Exception: {str(e)}'})
        return res

    def get_policy_list_by_resource_group_name(self, subscription_id: str, resource_group_name_list: list) -> list[dict]:
        base_url = f'{BASE_URL}/subscriptions/{subscription_id}'
        res = []
        for resource_group_name in resource_group_name_list:
            try:
                res.append(self.http_request(
                    method='GET',
                    full_url=f'{base_url}/resourceGroups/{resource_group_name}/{POLICY_PATH}',
                    params={'api-version': API_VERSION}
                ))
            except Exception as e:
                res.append({'properties': f'{resource_group_name} threw Exception: {str(e)}'})
        return res

    def get_policy_list_by_subscription_id(self, subscription_ids) -> list[dict]:
        res = []
        for subscription_id in subscription_ids:
            base_url = f'{BASE_URL}/subscriptions/{subscription_id}'
            try:
                res.append(
                    self.http_request(
                        method='GET',
                        full_url=f'{base_url}/{POLICY_PATH}',
                        params={'api-version': API_VERSION}
                    )
                )
            except Exception as e:
                res.append({'properties': f'Listing {subscription_id} threw Exception: {str(e)}'})
        return res

    def update_policy_upsert(self, policy_name: str, resource_group_names: list, subscription_id: str, data: dict) -> list[dict]:
        base_url = f'{BASE_URL}/subscriptions/{subscription_id}'
        res = []
        for resource_group_name in resource_group_names:
            try:
                res.append(
                    self.http_request(
                        method='PUT',
                        full_url=f'{base_url}/resourceGroups/{resource_group_name}/{POLICY_PATH}/{policy_name}',
                        data=data,
                        params={'api-version': API_VERSION}
                    )
                )
            except Exception as e:
                res.append({'properties': f'{resource_group_name} threw Exception: {str(e)}'})
        return res

    def delete_policy(self, policy_name: str, resource_group_name: str) -> requests.Response:
        return self.http_request(
            method='DELETE',
            return_empty_response=True,
            resp_type='response',
            url_suffix=f'/resourceGroups/{resource_group_name}/{POLICY_PATH}/{policy_name}',
        )

    def subscriptions_list(self) -> dict:
        return self.http_request(
            method='GET',
            return_empty_response=True,
            full_url=f'{BASE_URL}/subscriptions',
            params={'api-version': API_VERSION}
        )

    def resource_group_list(self, subscription_ids: list, tag: str, limit: int) -> list[dict]:
        params = {
            '$top': limit,
            'api-version': API_VERSION
        }
        if (tag):
            params['$filter'] = tag
        res = []
        for subscription_id in subscription_ids:
            full_url = f'{BASE_URL}/subscriptions/{subscription_id}/resourcegroups'
            try:
                res.append({subscription_id: self.http_request(
                    method='GET',
                    return_empty_response=True,
                    full_url=full_url,
                    params=params
                ).get('value', {})})
            except Exception as e:
                res.append({'properties': f'{subscription_id} threw Exception: {str(e)}'})
        return res


''' COMMAND FUNCTIONS '''


def test_connection(client: AzureWAFClient, params: dict) -> CommandResults:
    client.ms_client.get_access_token()  # If fails, MicrosoftApiModule returns an error
    return CommandResults(readable_output='✅ Success!')


@logger
def start_auth(client: AzureWAFClient) -> CommandResults:
    result = client.ms_client.start_auth('!azure-waf-auth-complete')
    return CommandResults(readable_output=result)


@logger
def complete_auth(client: AzureWAFClient):
    client.ms_client.get_access_token()
    return '✅ Authorization completed successfully.'


def policies_get_command(client: AzureWAFClient, **args) -> CommandResults:
    """
    Gets resource group name (or taking instance's default one),
    subscription id (or taking instance's default one) and policy name(optional).
    If a policy name provided, Retrieve the policy by name and resource group.
    Otherwise, retrieves all policies within the resource group.
    """

    policy_name: str = args.get('policy_name', '')
    subscription_id: str = args.get('subscription_id', client.subscription_id)
    resource_group_name_list: list = argToList(args.get('resource_group_name', client.resource_group_name))
    verbose = args.get("verbose", "false") == "true"
    limit = int(str(args.get("limit", '20')))

    policies: list[dict] = []
    try:
        if policy_name:
            policies = client.get_policy_by_name(policy_name, subscription_id, resource_group_name_list)
        else:
            raw_policy_list = client.get_policy_list_by_resource_group_name(subscription_id, resource_group_name_list)
            for policy in raw_policy_list:
                policies.extend(policy.get('value', []))

        # only showing number of policies until reaching the limit provided.
        policies_num = len(policies)
    except Exception:
        raise
    return CommandResults(readable_output=policies_to_markdown(policies, verbose, limit),
                          outputs=policies[:min(limit, policies_num)],
                          outputs_key_field='id', outputs_prefix='AzureWAF.Policy',
                          raw_response=policies)


def policies_get_list_by_subscription_command(client: AzureWAFClient, **args) -> CommandResults:
    """
    Retrieve all policies within the subscription id.
    """
    policies: list[dict] = []
    verbose = args.get("verbose", "false") == "true"
    limit = int(str(args.get("limit", '10')))
    subscription_ids = argToList(args.get('subscription_id', client.subscription_id))

    try:
        results = client.get_policy_list_by_subscription_id(subscription_ids)
        for res in results:
            policies.extend(res.get('value', []))

        # only showing number of policies until reaching the limit provided.
        policies_num = len(policies)
    except DemistoException:
        raise

    return CommandResults(readable_output=policies_to_markdown(policies, verbose, limit),
                          outputs=policies[:min(limit, policies_num)], outputs_key_field='id',
                          outputs_prefix='AzureWAF.Policy', raw_response=policies)


def policy_upsert_command(client: AzureWAFClient, **args) -> CommandResults:
    """
    Gets a policy name, resource groups (or taking instance's default), location,
    subscription id (or taking instance's default) and rules.
    Updates the policy if exists, otherwise creates a new policy.
    """

    def parse_nested_keys_to_dict(base_dict: dict, keys: list, value: str | dict) -> None:
        """ A recursive function to make a list of type [x,y,z] and value a to a dictionary of type {x:{y:{z:a}}}"""
        if len(keys) == 1:
            base_dict[keys[0]] = value
        else:
            if keys[0] not in base_dict:
                base_dict[keys[0]] = {}
            parse_nested_keys_to_dict(base_dict[keys[0]], keys[1:], value)

    policy_name = str(args.get('policy_name', ''))
    resource_group_names = argToList(args.get('resource_group_name', client.resource_group_name))
    subscription_id = args.get('subscription_id', client.subscription_id)
    managed_rules = args.get('managed_rules', {})
    location = args.get("location", '')  # location is not required by documentation but is required by the api itself.
    verbose = args.get("verbose", "false") == "true"

    if not policy_name or not managed_rules or not location:
        raise Exception('In order to add/ update policy, '
                        'please provide policy_name, location and managed_rules. ')

    body: dict[str, Any] = {}

    # creating the body for the request, using pre-defined fields.
    for param in UPSERT_PARAMS:
        val = str(args.get(param, ''))
        with contextlib.suppress(json.decoder.JSONDecodeError):
            val = json.loads(val)
        if val:
            key_hierarchy = UPSERT_PARAMS[param].split('.')
            parse_nested_keys_to_dict(base_dict=body, keys=key_hierarchy, value=val)

    updated_policy = client.update_policy_upsert(policy_name=policy_name, resource_group_names=resource_group_names,
                                                 subscription_id=subscription_id, data=body)

    return CommandResults(readable_output=policies_to_markdown(updated_policy, verbose),
                          outputs=updated_policy,
                          outputs_key_field='id', outputs_prefix='AzureWAF.Policy',
                          raw_response=updated_policy)


def policy_delete_command(client: AzureWAFClient, **args):
    """
    Gets a policy name, resource group (or taking instance's default)
    and subscription id (or taking instance's default)
    and delete the policy from the resource group.
    """
    policy_name = str(args.get('policy_name', ''))
    subscription_id = args.get('subscription_id', client.subscription_id)
    resource_group_names = argToList(args.get('resource_group_name', client.resource_group_name))

    for resource_group_name in resource_group_names:
        # policy_path is unique and used as unique id in the product.
        policy_id = f'/subscriptions/{subscription_id}/' \
                    f'resourceGroups/{resource_group_name}/{POLICY_PATH}/{policy_name}'
        status = client.delete_policy(policy_name, resource_group_name)
        md = ""
        context: dict = {}
        if status.status_code in [200, 202]:
            if not context:
                context = {}
            if old_context := demisto.dt(
                demisto.context(), f'AzureWAF.Policy(val.id === "{policy_id}")'
            ):
                if isinstance(old_context, list):
                    old_context = old_context[0]
                old_context['IsDeleted'] = True
                context['AzureWAF.Policy(val.id === obj.id)'] = old_context

            md = f"Policy {policy_name} was deleted successfully."

        if status.status_code == 204:
            md = f"Policy {policy_name} was not found."

    return CommandResults(outputs=context, readable_output=md)


def policies_to_markdown(policies: list[dict], verbose: bool = False, limit: int = 10) -> str:
    """
    Gets a list of json representing policies and create a markdown of relevant data in it.
    """

    def policy_to_full_markdown(policy_data: dict):
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

    def policy_to_short_markdown(policy_data: dict):
        """
        Creates a short markdown containing only basic information on policy.
        """
        short_md = ''
        try:
            policy_data.pop('properties', {})
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
    if not policies:
        return "No policies were found."

    policies_num = len(policies)
    policies = policies[:min(limit, policies_num)]
    for policy in policies:
        md += policy_to_full_markdown(policy.copy()) if verbose else policy_to_short_markdown(policy.copy())

    md += f"Showing {min(limit, len(policies))} policies out of {policies_num}"
    return md


def subscriptions_to_md(subscriptions: list[dict]) -> str:
    """
    Formats a list of subscription dictionaries as a Markdown table.

    Args:
        subscriptions (list[dict]): A list of subscription dictionaries. Each dictionary hold keys for
        'subscriptionId', 'tenantId', 'state', and 'displayName'.

    Returns:
        str: A Markdown-formatted string representing the subscription data as a table.
    """
    list_md = []
    for subscription in subscriptions:
        sub_md = {
            key: subscription.get(key)
            for key in subscription
            if key in ('subscriptionId', 'tenantId', 'state', 'displayName')
        }
        list_md.append(sub_md)
    return tableToMarkdown('Subscriptions: ', list_md)


def format_resource_group_dict(resource_group: dict) -> dict:
    """
    Formats a resource group dictionary by extracting its relevant fields.

    Args:
        resource_group (dict): A resource group dictionary.

    Returns:
        dict: A dictionary containing the resource group's name, location, tags, and provisioning state (if available).
    """
    formatted_dict = {
        'name': resource_group.get('name'),
        'location': resource_group.get('location'),
        'tags': resource_group.get('tags', {}),
    }
    if provisioning_state := demisto.get(resource_group, 'properties.provisioningState'):
        formatted_dict['provisioningState'] = provisioning_state
    return formatted_dict


def resourcegroups_to_md(subscription_ids: list[dict]) -> str:
    """
    Formats a list of resource group dictionaries as a Markdown table.

    Args:
        resource_groups (list[dict]): A list of resource group dictionaries. Each dictionary hold keys for
            'name', 'location', 'tags', and 'properties.provisioningState'.

    Returns:
        str: A Markdown-formatted string representing the resource group data as a table.
    """
    top_md = []
    for subscription_id in subscription_ids:
        subscription_to_resource_groups_dict = {}
        for subscription_id_key in subscription_id:
            resource_groups_md = []
            for group_resource in subscription_id.get(subscription_id_key, {}):
                resource_group_md = format_resource_group_dict(group_resource)
                resource_groups_md.append([resource_group_md])
            subscription_to_resource_groups_dict[f'Subscription ID {subscription_id_key}'] = resource_groups_md
        top_md.append(subscription_to_resource_groups_dict)
    return tableToMarkdown('Resource Groups: ', top_md)


def subscriptions_list_command(client: AzureWAFClient):
    subscriptions_res = client.subscriptions_list()
    subscriptions = subscriptions_res.get('value', []) if subscriptions_res else {}
    return CommandResults(readable_output=subscriptions_to_md(subscriptions),  # type: ignore[arg-type]
                          outputs=subscriptions,
                          outputs_key_field='subscriptionId', outputs_prefix='AzureWAF.Subscription',
                          raw_response=subscriptions)


def resource_group_list_command(client: AzureWAFClient, **args) -> CommandResults:
    resource_groups: list[dict] = []
    subscription_ids = argToList(args.get('subscription_id', client.subscription_id))
    tag = args.get('tag', '')
    limit = args.get('limit', 50)
    results = client.resource_group_list(subscription_ids, tag, limit)
    for res in results:
        for key in res:
            sub_dict = {key: res.get(key, {})}
            resource_groups.append(sub_dict)
    return CommandResults(readable_output=resourcegroups_to_md(resource_groups),
                          outputs=resource_groups,
                          outputs_key_field='subscriptionId', outputs_prefix='AzureWAF.ResourceGroup',
                          raw_response=resource_groups)


@logger
def test_module(client, params):
    """
    Performs basic GET request to check if the API is reachable and authentication is successful.
    Returns ok if successful.
    """
    params = demisto.params()
    if params.get('auth_type') == 'Device Code':
        raise Exception("When using device code flow configuration, "
                        "Please enable the integration and run `!azure-waf-auth-start` and `!azure-waf-auth-complete` to "
                        "log in. You can validate the connection by running `!azure-waf-auth-test`\n"
                        "For more details press the (?) button.")

    elif params.get('auth_type') == 'Authorization Code':
        raise Exception("When using user auth flow configuration, "
                        "Please enable the integration and run the !azure-waf-auth-test command in order to test it")

    elif params.get('auth_type') == 'Azure Managed Identities':
        test_connection(client, params)
        return 'ok'
    elif params.get('auth_type') == 'Client Credentials':
        client.ms_client.get_access_token()
        return 'ok'
    return None


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions"""
    demisto_commands = {
        'azure-waf-policies-get': policies_get_command,
        'azure-waf-policies-list-all-in-subscription': policies_get_list_by_subscription_command,
        'azure-waf-policy-update-or-create': policy_upsert_command,
        'azure-waf-policy-delete': policy_delete_command,
        'azure-waf-auth-start': start_auth,
        'azure-waf-auth-complete': complete_auth,
        'azure-waf-auth-test': test_connection,
        'azure-waf-resource-group-list': resource_group_list_command,
    }
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    client = AzureWAFClient(
        tenant_id=params.get('tenant_id', ''),
        auth_type=params.get('auth_type', 'Device Code'),
        auth_code=params.get('auth_code', {}).get('password', ''),
        redirect_uri=params.get('redirect_uri', ''),
        enc_key=params.get('credentials', {}).get('password', ''),
        app_id=params.get('app_id', ''),
        subscription_id=params.get('subscription_id', ''),
        resource_group_name=params.get('resource_group_name', ''),
        verify=not params.get('insecure', False),
        proxy=params.get('proxy', False),
        azure_ad_endpoint=params.get('azure_ad_endpoint',
                                     'https://login.microsoftonline.com') or 'https://login.microsoftonline.com',
        managed_identities_client_id=get_azure_managed_identities_client_id(params)
    )

    demisto.debug(f'Command being called in Azure WAF is {command}')
    try:

        if command == 'test-module':
            return_results(test_module(client, params))
        elif command == 'azure-waf-auth-test':
            return_results(test_connection(client, params))
        elif command == 'azure-waf-generate-login-url':
            return_results(generate_login_url(client.ms_client))
        elif command == 'azure-waf-subscriptions-list':
            return_results(subscriptions_list_command(client))
        elif command == 'azure-waf-auth-reset':
            return_results(reset_auth())
        else:
            return_results(demisto_commands[command](client, **args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
