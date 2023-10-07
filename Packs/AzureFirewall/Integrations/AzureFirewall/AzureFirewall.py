import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import copy
from requests import Response
from MicrosoftApiModule import *  # noqa: E402
import urllib3


class AzureFirewallClient:
    def __init__(self,
                 subscription_id: str,
                 resource_group: str,
                 client_id: str,
                 api_version: str,
                 verify: bool,
                 proxy: bool,
                 client_secret: str | None = None,
                 tenant_id: str = '',
                 certificate_thumbprint: str | None = None,
                 private_key: str | None = None,
                 managed_identities_client_id: str | None = None):
        self.resource_group = resource_group
        self.subscription_id = subscription_id
        self.api_version = api_version
        self.default_params = {"api-version": api_version}

        is_credentials = (client_secret and tenant_id) or (certificate_thumbprint and private_key)

        scope = Scopes.management_azure if is_credentials else \
            'https://management.azure.com/user_impersonation offline_access user.read'
        grant_type = CLIENT_CREDENTIALS if is_credentials else DEVICE_CODE
        token_retrieval_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token' if tenant_id \
            else 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'

        if not is_credentials:
            client_secret = None
            tenant_id = ''
            certificate_thumbprint = None
            private_key = None

        self.ms_client = MicrosoftClient(
            self_deployed=True,
            tenant_id=tenant_id,
            token_retrieval_url=token_retrieval_url,
            auth_id=client_id,
            enc_key=client_secret,
            grant_type=grant_type,
            base_url=f'https://management.azure.com/subscriptions/{subscription_id}'
                     f'/resourceGroups/{resource_group}/providers/Microsoft.Network',
            scope=scope,
            verify=verify,
            proxy=proxy,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id,
            managed_identities_resource_uri=Resources.management_azure,
            command_prefix="azure-firewall",
        )

    def azure_firewall_list_request(self, resource: str, next_link: str = None) -> dict:
        """
        List azure firewalls in resource group or subscription.
        Args:
            resource (str): The resource which contains the firewalls to list.
            next_link (str): URL to retrieve the next set of results.

        Returns:
            dict: API response from Azure.

        """
        if next_link:
            full_url = next_link
            response = self.ms_client.http_request('GET', full_url=full_url, resp_type="json", timeout=100)

            return response
        if resource == "resource_group":
            full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}' \
                       f'/resourceGroups/{self.resource_group}/providers/Microsoft.Network/azureFirewalls'
        else:
            full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}' \
                       f'/providers/Microsoft.Network/azureFirewalls'

        response = self.ms_client.http_request('GET', full_url=full_url, params=self.default_params, resp_type="json",
                                               timeout=100)

        return response

    def azure_firewall_get_request(self, firewall_name: str) -> dict:
        """
        Retrieve azure firewall information.
        Args:
            firewall_name (str): The name of the azure firewall to retrieve.

        Returns:
            dict: API response from Azure.

        """

        url_suffix = f'azureFirewalls/{firewall_name}'

        response = self.ms_client.http_request('GET', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_update_request(self, firewall_name: str, firewall_data: dict) -> dict:
        """
        Update firewall resource.
        Args:
            firewall_name (str): The name of the firewall to update.
            firewall_data (dict): Firewall resource JSON information.
        Returns:
            dict: API response from Azure.
        """
        url_suffix = f'azureFirewalls/{firewall_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params,
                                               json_data=firewall_data,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_policy_create_request(self, policy_name: str, threat_intelligence_mode: str, ip_address: list,
                                             domain_address: list, location: str, tier: str, base_policy_id: str,
                                             enable_proxy: bool, dns_servers: list) -> dict:
        """
        Create firewall policy.
        Args:
            policy_name (str): The name of the azure policy to create.
            threat_intelligence_mode (str): The operation mode for Threat Intelligence.
            ip_address (list): IP addresses for the threat intelligence whitelist.
            domain_address (list): Fully qualified domain name for the threat intelligence whitelist.
            location (str): Policy resource region location.
            tier (str): Tier of an Azure Policy.
            base_policy_id (str): The ID of the parent firewall policy from which rules are inherited.
            enable_proxy (bool): Enable DNS Proxy on Firewalls attached to the Firewall Policy.
            dns_servers (list): Custom DNS Servers.

        Returns:
            dict: API response from Azure.

        """

        data = remove_empty_elements({
            "location": location,
            "properties": {
                "threatIntelMode": threat_intelligence_mode,
                "threatIntelWhitelist": {
                    "ipAddresses": ip_address,
                    "fqdns": domain_address
                },
                "snat": {
                    "privateRanges": None
                },
                "dnsSettings": {
                    "servers": dns_servers,
                    "enableProxy": enable_proxy
                },
                "basePolicy": {"id": base_policy_id},
                "sku": {
                    "tier": tier
                }
            }
        })

        url_suffix = f'firewallPolicies/{policy_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params, json_data=data,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_policy_update_request(self, policy_name: str, policy_data: dict) -> dict:
        """
        Update policy resource.
        Args:
            policy_name (str): The name of the policy resource to update.
            policy_data (dict): Policy resource JSON information.

        Returns:
            dict: API response from Azure.

        """
        url_suffix = f'firewallPolicies/{policy_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params,
                                               json_data=policy_data,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_policy_get_request(self, policy_name: str) -> dict:
        """
        Retrieve policy information.
        Args:
            policy_name (str): The name of the policy to retrieve.

        Returns:
            dict: API response from Azure.

        """
        url_suffix = f'firewallPolicies/{policy_name}'

        response = self.ms_client.http_request('GET', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_policy_delete_request(self, policy_name: str) -> Response:
        """
        Delete policy resource.
        Args:
            policy_name (str): The name of the policy to delete.

        Returns:
            Response: API response from Azure.

        """
        url_suffix = f'firewallPolicies/{policy_name}'

        response = self.ms_client.http_request('DELETE', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="response", timeout=100)

        return response

    def azure_firewall_policy_list_request(self, resource: str, next_link: str = None) -> dict:
        """
        List policies in resource group or subscription.
        Args:
            resource (str): The resource which contains the policy to list.
            next_link (str): URL to retrieve the next set of results.

        Returns:
            dict: API response from Azure.

        """
        if next_link:
            full_url = next_link
            response = self.ms_client.http_request('GET', full_url=full_url, resp_type="json", timeout=100)

            return response

        if resource == "resource_group":
            full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}' \
                       f'/resourceGroups/{self.resource_group}/providers/Microsoft.Network/firewallPolicies'
        else:
            full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}' \
                       f'/providers/Microsoft.Network/firewallPolicies'

        response = self.ms_client.http_request('GET', full_url=full_url, params=self.default_params, resp_type="json",
                                               timeout=100)

        return response

    def azure_firewall_policy_rule_collection_create_or_update_request(self, policy_name: str, collection_name: str,
                                                                       collection_data: dict) -> dict:
        """
        Create or update policy rule collection.
        Args:
            policy_name (str): The name of the policy which contains the collection.
            collection_name (str): The name of the rule collection to create or update.
            collection_data (dict): Rule collection information.

        Returns:
            dict: API response from Azure.

        """
        url_suffix = f'firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="json", json_data=collection_data, timeout=100)

        return response

    def azure_firewall_policy_rule_collection_list_request(self, policy_name: str, next_link: str = None) -> dict:
        """
        List collection rules in policy.
        Args:
            policy_name (str): The resource which contains the policy to list.
            next_link (str): URL to retrieve the next set of results.

        Returns:
            dict: API response from Azure.

        """
        if next_link:
            full_url = next_link
            response = self.ms_client.http_request('GET', full_url=full_url, resp_type="json", timeout=100)
            return response

        url_suffix = f'firewallPolicies/{policy_name}/ruleCollectionGroups'

        response = self.ms_client.http_request('GET', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_policy_rule_collection_get_request(self, policy_name: str,
                                                          collection_name: str) -> dict:
        """
        Retrieve policy collection group information.
        Args:
            policy_name (str): The name of the policy which contains the collection.
            collection_name (str): he name of the policy rule collection to retrieve.

        Returns:
            dict: API response from Azure.

        """
        url_suffix = f'firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

        response = self.ms_client.http_request('GET', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_policy_rule_collection_delete_request(self, policy_name: str, collection_name: str) -> Response:
        """
        Delete policy collection group information.
        Args:
            policy_name (str): The name of the policy which contains the collection.
            collection_name (str): The name of the policy rule collection to delete.

        Returns:
            Response: API response from Azure.

        """

        url_suffix = f'firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

        response = self.ms_client.http_request('DELETE', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="response", timeout=100)

        return response

    def azure_firewall_policy_network_rule_collection_create_request(self, policy_name: str, collection_priority: int | None,
                                                                     collection_name: str, action: str,
                                                                     rule_information: dict) -> dict:
        """
        Create network rule collection in firewall or policy.
        Args:
            policy_name (str): The name of the policy which contains the collection.
            collection_priority (int): The priority of the nat rule collection resource.
            collection_name (str): The name of the nat rule collection which contains the rule.
            action (str): The action type of a rule collection.
            rule_information (dict): Rule information.

        Returns:
            dict: API response from Azure.

        """

        payload = remove_empty_elements({
            "properties": {
                "priority": collection_priority,
                "ruleCollections": [
                    {
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "name": collection_name,
                        "priority": collection_priority,
                        "action": {
                            "type": action
                        },
                        "rules": [
                            rule_information
                        ]

                    }
                ]
            }
        })

        url_suffix = f'firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params,
                                               json_data=payload, resp_type="json", timeout=100)

        return response

    def azure_firewall_service_tag_list_request(self, location: str, next_link: str = None) -> dict:
        """
        Retrieve service tag information resources.
        Args:
            location (str): The location that will be used as a reference for version
            next_link (str): URL to retrieve the next set of results.

        Returns:
            dict: API response from Azure.

        """

        if next_link:
            full_url = next_link
            response = self.ms_client.http_request('GET', full_url=full_url, resp_type="json", timeout=100)
            return response

        full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}' \
                   f'/providers/Microsoft.Network/locations/{location}/serviceTagDetails'

        response = self.ms_client.http_request('GET', full_url=full_url, resp_type="json", params=self.default_params)

        return response

    def azure_firewall_ip_group_create_request(self, ip_group_name: str, location: str,
                                               ip_address: list = None) -> dict:
        """
        Create IP group resource.
        Args:
            ip_group_name (str): The name of the IP group resource to create.
            location (str): The location of the IP group resource.
            ip_address (list): IP addresses or IP address prefixes in the IP group resource.

        Returns:
            dict: API response from Azure.

        """
        payload = remove_empty_elements({
            "location": location,
            "properties": {
                "ipAddresses": ip_address
            }
        })

        url_suffix = f'ipGroups/{ip_group_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params,
                                               json_data=payload, resp_type="json", timeout=100)

        return response

    def azure_firewall_ip_group_list_request(self, resource: str, next_link: str = None) -> dict:
        """
        List IP Groups in resource group or subscription.
        Args:
            resource (str): The resource which contains the IP Groups to list.
            next_link (str): URL to retrieve the next set of results.

        Returns:
            dict: API response from Azure.

        """
        if next_link:
            full_url = next_link
            response = self.ms_client.http_request('GET', full_url=full_url, resp_type="json", timeout=100)
            return response

        if resource == "resource_group":
            full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}' \
                       f'/resourceGroups/{self.resource_group}/providers/Microsoft.Network/ipGroups'
        else:
            full_url = f'https://management.azure.com/subscriptions/{self.subscription_id}/providers/Microsoft.Network/ipGroups'

        response = self.ms_client.http_request('GET', full_url=full_url, params=self.default_params, resp_type="json",
                                               timeout=100)

        return response

    def azure_firewall_ip_group_get_request(self, ip_group_name: str) -> dict:
        """
        Retrieve IP group information.
        Args:
            ip_group_name (str): The name of the IP group resource to retrieve.

        Returns:
            dict: API response from Azure.

        """

        url_suffix = f'ipGroups/{ip_group_name}'

        response = self.ms_client.http_request('GET', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="json", timeout=100)

        return response

    def azure_firewall_ip_group_delete_request(self, ip_group_name: str) -> Response:
        """
        Delete IP group resource.
        Args:
            ip_group_name (str): The name of the IP group resource to delete.

        Returns:
            Response: API response from Azure.

        """

        url_suffix = f'ipGroups/{ip_group_name}'

        response = self.ms_client.http_request('DELETE', url_suffix=url_suffix, params=self.default_params,
                                               resp_type="response", timeout=100)

        return response

    def azure_firewall_ip_group_update_request(self, ip_group_name: str, ip_group_data: dict) -> dict:
        """
        Update IP Group resource.
        Args:
            ip_group_name (str): The name of the IP Group resource to update.
            ip_group_data (dict): IP Group resource JSON information.

        Returns:
            dict: API response from Azure.

        """
        url_suffix = f'ipGroups/{ip_group_name}'

        response = self.ms_client.http_request('PUT', url_suffix=url_suffix, params=self.default_params,
                                               json_data=ip_group_data, resp_type="json", timeout=100)

        return response


def generate_polling_readable_message(resource_type_name: str, resource_name: str) -> str:
    """
    Generate appropriate markdown message for polling commands.
    Args:
        resource_type_name (str): The name type of the updated resource. For example: Policy, Firewall, IP-Group, etc.
        resource_name (str): The name of the updated resource.

    Returns:
        str: Polling header message.

    """
    return f'## Polling in progress for {resource_type_name} {resource_name}.'


def create_scheduled_command(command_name: str, interval: int, timeout: int, **kwargs):
    """
    Create scheduled command object.
    Args:
        command_name (str): The command that'll run after next_run_in_seconds has passed.
        interval (int): How long to wait before executing the command.
        timeout (int): Number of seconds until the polling sequence will timeout.

    Returns:
        ScheduledCommand : ScheduledCommand object

    """
    polling_args = {
        'interval': interval,
        'polling': True,
        'timeout': timeout,
        **kwargs
    }
    return ScheduledCommand(
        command=command_name,
        next_run_in_seconds=interval,
        timeout_in_seconds=timeout,
        args=polling_args,
    )


def validate_pagination_arguments(limit: int, page: int) -> None:
    """
    Validate pagination arguments values.
    Args:
        limit (int): Number of elements to retrieve.
        page (int): Page number.

    """
    if page < 1 or limit < 1:
        raise Exception('Page and limit arguments must be greater than 0.')


def get_pagination_readable_message(header: str, limit: int, page: int) -> str:
    """
    Generate pagination commands readable message.
    Args:
        header (str): Message header
        limit (int): Number of elements to retrieve.
        page (int): Page number.

    Returns:
        str: Readable message.

    """
    readable_message = f'{header}\n Current page size: {limit}\n Showing page {page} out others that may exist.'

    return readable_message


def generate_firewall_command_output(response: dict | list, readable_header: str, output_key: str = None) -> CommandResults:
    """
    Generate command output for firewall commands.
    Args:
        response (dict | list): API response from Azure.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    outputs = copy.deepcopy(response.get(output_key, [])) if output_key and isinstance(response, dict) \
        else copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    readable_data = []

    for firewall in outputs:
        properties = firewall.get("properties", {})
        ip_configuration = properties.get("ipConfigurations", [])
        ip_configuration = ip_configuration[0] if ip_configuration else {}
        data = {
            "name": firewall.get("name"),
            "id": firewall.get("id"),
            "location": firewall.get("location"),
            "threat_intel_mode": properties.get("threatIntelMode"),
            "private_ip_address": dict_safe_get(ip_configuration, ["properties", "privateIPAddress"]),
            "subnet": dict_safe_get(ip_configuration, ["properties", "subnet", "id"]),
            "provisioning_state": properties.get("provisioningState")
        }

        readable_data.append(data)

    readable_output = tableToMarkdown(
        readable_header,
        readable_data,
        headers=['name', 'id', 'location', 'subnet', 'threat_intel_mode', 'private_ip_address', 'provisioning_state'],
        headerTransform=string_to_table_header
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureFirewall.Firewall',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def azure_firewall_list_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    List azure firewalls in resource group or subscription.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    resource = args.get('resource', 'resource_group')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header='Firewall List:',
                                                       limit=limit, page=page)

    start_offset = (page - 1) * limit
    end_offset = start_offset + limit
    complete_requests = False
    total_response: dict[str, list] = {'value': []}
    response = client.azure_firewall_list_request(resource=resource)

    while not complete_requests:
        total_response['value'].extend(response.get('value', []))
        if len(total_response['value']) >= end_offset or not response.get('nextLink'):
            complete_requests = True
        else:
            response = client.azure_firewall_list_request(resource=resource, next_link=response.get('nextLink'))

    return generate_firewall_command_output(response.get('value', [])[start_offset: end_offset],
                                            readable_header=readable_message)


def azure_firewall_get_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Retrieve azure firewall information.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    firewall_names = argToList(args.get('firewall_names'))

    scheduled = argToBoolean(args.get('polling', False))
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    command_results_list: List[CommandResults] = []

    for firewall in firewall_names:
        try:
            response = client.azure_firewall_get_request(firewall)

            state = dict_safe_get(response, ["properties", "provisioningState"], '')

            if scheduled and state not in ["Succeeded", "Failed"]:
                # schedule next poll
                scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                             timeout=timeout, firewall_names=firewall)

                # result with scheduled_command only - no update to the war room
                command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                           readable_output=generate_polling_readable_message(
                                                               resource_type_name="Firewall",
                                                               resource_name=firewall)))

            else:
                command_results = generate_firewall_command_output(response,
                                                                   readable_header=f'Firewall {firewall} information:')

                command_results_list.append(command_results)

        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while retrieving {firewall}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def get_firewall_rule_collection_name(rule_type: str) -> str:
    """
    Get firewall rule collection API name convention.
    Args:
        rule_type (str): Command rule type name convention.

    Returns:
        str: Azure collection API name convention.

    """
    rule_types = {
        "network_rule": "networkRuleCollections",
        "application_rule": "applicationRuleCollections",
        "nat_rule": "natRuleCollections"
    }

    return rule_types.get(rule_type, '')


def get_policy_rule_collection_name(rule_type: str) -> str:
    """
    Get policy rule collection API name convention.
    Args:
        rule_type (str): Command rule type name convention.

    Returns:
        str: Azure collection API name convention.

    """
    rule_types = {
        "network_rule": "FirewallPolicyFilterRuleCollection",
        "application_rule": "FirewallPolicyFilterRuleCollection",
        "nat_rule": "FirewallPolicyNatRuleCollection"
    }

    return rule_types.get(rule_type, "")


def get_policy_rule_name(rule_type: str) -> str:
    """
    Get policy rule API name convention.
    Args:
        rule_type (str): Command rule type name convention.

    Returns:
        str: Azure collection API name convention.

    """
    rule_types = {
        "network_rule": "NetworkRule",
        "application_rule": "ApplicationRule",
        "nat_rule": "NatRule"
    }

    return rule_types.get(rule_type, "")


def generate_rule_collection_output(rule_collection_response: dict, readable_header: str,
                                    outputs: list, is_firewall_collection: bool) -> CommandResults:
    """
    Generate command output for rule collection commands.
    Args:
        rule_collection_response (dict): API response from Azure.
        readable_header (str): Readable message header for XSOAR war room.
        outputs (list): Output for XSOAR platform.
        is_firewall_collection (bool): Indicates if the rule collection belongs to firewall or policy.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    readable_data = []

    if is_firewall_collection:
        for collection in outputs:
            collection_name = collection.get("name")
            collection_priority = dict_safe_get(collection, ["properties", "priority"])
            collection_action = dict_safe_get(collection, ["properties", "action", "type"])

            data = {"priority": collection_priority, "action": collection_action, "name": collection_name}
            readable_data.append(data)

    else:  # Policy collection
        for collection in outputs:
            collection_action, collection_priority, collection_name = None, None, None

            collection_data = dict_safe_get(collection, ["properties", "ruleCollections"])
            if collection_data and isinstance(collection_data, list):
                collection_action = dict_safe_get(collection_data[0], ["action", "type"])

                collection_name = collection_data[0].get("name")
                collection_priority = collection_data[0].get("priority")

            data = {"priority": collection_priority, "action": collection_action, "name": collection_name}
            readable_data.append(data)

    readable_output = tableToMarkdown(
        readable_header,
        readable_data,
        headers=['name', 'action', 'priority'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureFirewall.RuleCollection',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=rule_collection_response
    )

    return command_results


def generate_rule_output(response: dict, readable_header: str,
                         outputs: list) -> CommandResults:
    """
    Generate command output for rule commands.
    Args:
        response (dict): API response from Azure.
        readable_header (str): Readable message header for XSOAR war room.
        outputs (list): Output for XSOAR platform.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """

    readable_output = tableToMarkdown(
        readable_header,
        outputs,
        headers=['name'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureFirewall.Rule',
        outputs_key_field='name',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def filter_policy_rules_collection(rules_collections: list, rule_type: str) -> list:
    """
    Filter policy rules collection by the rule type.
    Args:
        rules_collections (list): Rules collection from API response.
        rule_type (str): Rule type to filter.

    Returns:
        list: Filtered rules collection.

    """
    if not rules_collections:
        return []

    collection_key = get_policy_rule_collection_name(rule_type=rule_type)
    rule_key = get_policy_rule_name(rule_type=rule_type)

    collections = []

    for collection in rules_collections:
        current_collections = dict_safe_get(collection, ["properties", "ruleCollections"], [])

        if isinstance(current_collections, list) and len(current_collections) > 0:
            rule_collection = current_collections[0]
            if rule_collection.get("ruleCollectionType") == collection_key \
                    and isinstance(rule_collection.get("rules"), list) \
                    and len(rule_collection.get("rules")) > 0 and rule_collection.get("rules")[0].get("ruleType") == rule_key:
                collections.append(collection)

    return collections


def get_firewall_rule_collection(client: AzureFirewallClient, firewall_name: str, rule_type: str) -> tuple:
    """
    Retrieve firewall rule collections.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        firewall_name (str): The name of the firewall which contains the collection.
        rule_type (str): The name of the rule collection type to retrieve.

    Returns:
        tuple: response, rule_collections

    """

    response = client.azure_firewall_get_request(firewall_name=firewall_name)

    rule_type_key = get_firewall_rule_collection_name(rule_type)
    filtered_rules = dict_safe_get(response, ["properties", rule_type_key])

    return response, filtered_rules


def azure_firewall_rules_collection_list_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    List collection rules in firewall or in policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    rule_type = args.get('rule_type', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)
    start_offset = (page - 1) * limit
    end_offset = start_offset + limit

    resource = firewall_name or policy

    readable_message = get_pagination_readable_message(header=f'{resource} Rule Collections List:',
                                                       limit=limit, page=page)

    if firewall_name:

        response, filtered_rules = get_firewall_rule_collection(client, firewall_name, rule_type)

        filtered_rules = filtered_rules[start_offset: end_offset]

    else:
        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        complete_requests = False
        total_response: dict[str, list] = {'value': []}

        response = client.azure_firewall_policy_rule_collection_list_request(policy_name=policy)

        while not complete_requests:
            total_response['value'].extend(response.get('value', []))
            if not response.get('nextLink'):
                complete_requests = True
            else:
                response = client.azure_firewall_policy_rule_collection_list_request(policy_name=policy,
                                                                                     next_link=response.get('nextLink'))

        filtered_rules = filter_policy_rules_collection(total_response.get('value', []),
                                                        rule_type)[start_offset: end_offset]

    return generate_rule_collection_output(rule_collection_response=response,
                                           readable_header=readable_message, outputs=filtered_rules,
                                           is_firewall_collection=firewall_name is not None)


def get_policy_collection_rules(client: AzureFirewallClient, policy: str, collection_name: str) -> tuple:
    """
    Retrieve rules of policy rules collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        policy (str): The name of the policy which contains the rule collection.
        collection_name (str): The name of the collection which contains the rules.

    Returns:
        tuple: API response , rules list

    """
    rules = []
    response = client.azure_firewall_policy_rule_collection_get_request(policy_name=policy,
                                                                        collection_name=collection_name)
    rules_path = ["properties", "ruleCollections"]

    rule_collections = dict_safe_get(response, rules_path)

    if isinstance(rule_collections, list) and len(rule_collections) > 0:
        rules = rule_collections[0].get("rules")

    return response, rules


def azure_firewall_rules_list_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    List rules in firewall or in policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    rule_type = args.get('rule_type', '')
    collection_name = args.get('collection_name', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    start_offset = (page - 1) * limit
    end_offset = start_offset + limit
    rules = []

    if firewall_name:

        if not rule_type:
            raise Exception("The `rule_type` argument must be provided for firewall rules.")

        response, filtered_rules = get_firewall_rule_collection(client, firewall_name, rule_type)
        readable_message = get_pagination_readable_message(header=f'Firewall {firewall_name} {rule_type} Rules List:',
                                                           limit=limit, page=page)

        rules_path = ["properties", "rules"]

        for rule_collection in filtered_rules:
            if rule_collection.get("name") == collection_name:
                rules = dict_safe_get(rule_collection, rules_path)
                break

        if not rules:
            raise Exception(f'Collection {collection_name} is not exists in {firewall_name} firewall.')

    else:

        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        readable_message = get_pagination_readable_message(header=f'Policy {policy} {rule_type} Rules List:',
                                                           limit=limit, page=page)

        response, rules = get_policy_collection_rules(client=client, policy=policy, collection_name=collection_name)

    return generate_rule_output(response=response, readable_header=readable_message,
                                outputs=rules[start_offset: end_offset])


def azure_firewall_rule_get_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve rule information.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    rule_type = args.get('rule_type', '')
    collection_name = args.get('collection_name', '')
    rule_name = args.get('rule_name', '')
    rule_data = None

    if firewall_name:

        if not rule_type:
            raise Exception("The `rule_type` argument must be provided for firewall rules.")

        response, filtered_rules = get_firewall_rule_collection(client, firewall_name, rule_type)

        rules_path = ["properties", "rules"]

        for rule_collection in filtered_rules:
            if rule_collection.get("name") == collection_name:
                rules = dict_safe_get(rule_collection, rules_path)
                for rule in rules:
                    if rule.get("name") == rule_name:
                        rule_data = rule
                        break

            if rule_data:
                break

    else:
        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        response, rules = get_policy_collection_rules(client=client, policy=policy, collection_name=collection_name)

        for rule in rules:
            if rule.get("name") == rule_name:
                rule_data = rule
                break

    if not rule_data:
        raise Exception(f'Rule {rule_name} is not exists.')

    return generate_rule_output(response=response, readable_header=f'Rule {rule_name} Information:',
                                outputs=rule_data)


def azure_firewall_policy_create_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Create firewall policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    policy_name = args.get('policy_name', '')
    threat_intelligence_mode = args.get('threat_intelligence_mode', 'Turned-off')
    threat_intelligence_mode = 'Off' if threat_intelligence_mode == 'Turned-off' else threat_intelligence_mode
    ip_address = argToList(args.get('ips'))
    domain_address = argToList(args.get('domains'))
    location = args.get('location', '')
    tier = args.get('tier', 'Standard')
    base_policy_id = args.get('base_policy_id', '')
    enable_proxy = argToBoolean(args.get('enable_proxy', 'False'))
    dns_servers = argToList(args.get('dns_servers'))

    response = client.azure_firewall_policy_create_request(
        policy_name, threat_intelligence_mode, ip_address, domain_address, location, tier, base_policy_id, enable_proxy,
        dns_servers)

    state = dict_safe_get(response, ["properties", "provisioningState"], '')

    if should_poll and state not in ["Succeeded", "Failed"]:
        # schedule next poll
        scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                     timeout=timeout, policy_names=policy_name)

        return CommandResults(scheduled_command=scheduled_command,
                              readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                resource_name=policy_name))

    return generate_policy_command_output(response, readable_header=f'Successfully Created Policy "{policy_name}"')


def dict_nested_set(dictionary: dict, keys: list, value: Any) -> None:
    """
    Set nested dictionary value.
    Args:
        dictionary (dict): Dictionary to set.
        keys (list): Keys for recursive get.
        value (Any): Required value.

    """
    keys = argToList(keys)
    for key in keys[:-1]:
        dictionary = dictionary.setdefault(key, {})
    dictionary[keys[-1]] = value


def azure_firewall_policy_update_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Update policy resource.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    policy_name = args.get('policy_name', '')

    threat_intelligence_mode = args.get('threat_intelligence_mode', '')
    threat_intelligence_mode = 'Off' if threat_intelligence_mode == 'Turned-off' else threat_intelligence_mode
    ip_address = argToList(args.get('ips'))
    domain_address = argToList(args.get('domains'))
    base_policy_id = args.get('base_policy_id')
    enable_proxy = argToBoolean(args.get('enable_proxy')) if args.get('enable_proxy') else None
    dns_servers = argToList(args.get('dns_servers'))

    policy_data = client.azure_firewall_policy_get_request(policy_name=policy_name)

    properties = policy_data.get("properties", {})

    update_fields = assign_params(threat_intelligence_mode=threat_intelligence_mode, ips=ip_address,
                                  domains=domain_address, base_policy_id=base_policy_id,
                                  enable_proxy=enable_proxy, dns_servers=dns_servers)

    policy_fields_mapper = {
        'threat_intelligence_mode': ["threatIntelMode"],
        'ips': ["threatIntelWhitelist", "ipAddresses"],
        'domains': ["threatIntelWhitelist", "fqdns"],
        'base_policy_id': ["basePolicy", "id"],
        'enable_proxy': ["dnsSettings", "enableProxy"],
        'dns_servers': ["dnsSettings", "servers"]
    }

    for field_key, value in update_fields.items():
        key_path = policy_fields_mapper.get(field_key, [])

        dict_nested_set(properties, key_path, value)

    response = client.azure_firewall_policy_update_request(policy_name=policy_name, policy_data=policy_data)

    state = dict_safe_get(response, ["properties", "provisioningState"], '')

    if should_poll and state not in ["Succeeded", "Failed"]:
        # schedule next poll
        scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                     timeout=timeout, policy_names=policy_name)

        return CommandResults(scheduled_command=scheduled_command,
                              readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                resource_name=policy_name))

    return generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy_name}"')


def generate_policy_command_output(response: dict | list, readable_header: str, output_key: str = None) -> CommandResults:
    """
    Generate command output for policy commands.
    Args:
        response (dict | list): API response from Azure.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    outputs = copy.deepcopy(response.get(output_key, [])) if output_key and isinstance(response, dict) \
        else copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    readable_data = []
    for policy in outputs:
        name = policy.get('name')
        id = policy.get('id')
        location = policy.get("location")
        properties = policy.get("properties", {})
        threat_intel_mode = properties.get("threatIntelMode")
        tier = dict_safe_get(properties, ['sku', 'tier'])
        child_policies = properties.get("childPolicies", [])
        child_policies = [child_policy.get('id') for child_policy in child_policies]
        firewalls = properties.get("firewalls", {})
        firewalls = [firewall.get('id') for firewall in firewalls]
        base_policy = dict_safe_get(properties, ["basePolicy", "id"])
        provisioning_state = properties.get("provisioningState")

        data = {"name": name, "location": location, "threat_intel_mode": threat_intel_mode, "child_policies": child_policies,
                "firewalls": firewalls, "base_policy": base_policy, "provisioning_state": provisioning_state,
                "id": id, "tier": tier}
        readable_data.append(data)

    readable_output = tableToMarkdown(
        readable_header,
        readable_data,
        headers=['name', 'id', 'tier', 'location', 'firewalls', 'base_policy', 'child_policies', 'provisioning_state'],
        headerTransform=string_to_table_header
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureFirewall.Policy',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def azure_firewall_policy_get_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Retrieve policy information.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    policy_names = argToList(args.get('policy_names'))

    scheduled = argToBoolean(args.get('polling', False))
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    command_results_list: List[CommandResults] = []

    for policy in policy_names:
        try:
            response = client.azure_firewall_policy_get_request(policy)

            state = dict_safe_get(response, ["properties", "provisioningState"], '')

            if scheduled and state not in ["Succeeded", "Failed"]:
                # schedule next poll
                scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get',
                                                             interval=interval, timeout=timeout, policy_names=policy)

                # result with scheduled_command only - no update to the war room
                command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                           readable_output=generate_polling_readable_message(
                                                               resource_type_name="Policy",
                                                               resource_name=policy)))

            else:
                command_results_list.append(
                    generate_policy_command_output(response, readable_header=f'Policy {policy} information:'))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while retrieving {policy}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def azure_firewall_policy_delete_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Delete policy resource.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    policy_names = argToList(args.get('policy_names'))

    command_results_list: List[CommandResults] = []

    for policy in policy_names:
        try:
            response = client.azure_firewall_policy_delete_request(policy)

            if response.status_code == 202:
                readable_output = f'Policy {policy} delete operation accepted and will complete asynchronously.'
            else:
                readable_output = f'Policy {policy} deleted successfully.'

            command_results_list.append(CommandResults(
                readable_output=readable_output
            ))

        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while deleting {policy}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def azure_firewall_policy_list_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    List policy in resource group or subscription.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    resource = args.get('resource', 'resource_group')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header='Policy List:',
                                                       limit=limit, page=page)

    start_offset = (page - 1) * limit
    end_offset = start_offset + limit
    complete_requests = False
    total_response: dict[str, list] = {'value': []}
    response = client.azure_firewall_policy_list_request(resource=resource)

    while not complete_requests:
        total_response['value'].extend(response.get('value', []))
        if len(total_response['value']) >= end_offset or not response.get('nextLink'):
            complete_requests = True
        else:
            response = client.azure_firewall_policy_list_request(resource=resource,
                                                                 next_link=response.get('nextLink'))

    return generate_policy_command_output(total_response.get('value', [])[start_offset: end_offset],
                                          readable_header=readable_message)


def azure_firewall_policy_attach_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Attach policy to firewall.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    firewall_names = argToList(args.get('firewall_names'))
    policy_id = args.get('policy_id')

    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    command_results_list: List[CommandResults] = []

    for firewall in firewall_names:

        try:

            firewall_data = client.azure_firewall_get_request(firewall_name=firewall)

            firewall_data["properties"]["firewallPolicy"] = {"id": policy_id}

            response = client.azure_firewall_update_request(firewall_name=firewall, firewall_data=firewall_data)

            state = dict_safe_get(response, ["properties", "provisioningState"], '')

            if should_poll and state not in ["Succeeded", "Failed"]:
                # schedule next poll
                scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                             timeout=timeout, firewall_names=firewall)

                # result with scheduled_command only - no update to the war room
                command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                           readable_output=generate_polling_readable_message(
                                                               resource_type_name="Firewall",
                                                               resource_name=firewall)))

            else:
                command_results_list.append(generate_firewall_command_output(response,
                                                                             readable_header=f'Successfully Updated Firewall '
                                                                                             f'"{firewall}"'))

        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while updating {firewall}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def azure_firewall_policy_remove_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Remove policy from firewall. This command will detach between policy and firewall, and not delete the policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_names = argToList(args.get('firewall_names'))

    command_results_list: List[CommandResults] = []

    for firewall in firewall_names:

        try:

            firewall_data = client.azure_firewall_get_request(firewall_name=firewall)

            firewall_data["properties"].pop("firewallPolicy", None)

            response = client.azure_firewall_update_request(firewall_name=firewall, firewall_data=firewall_data)

            state = dict_safe_get(response, ["properties", "provisioningState"], '')

            if should_poll and state not in ["Succeeded", "Failed"]:
                # schedule next poll
                scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                             timeout=timeout, firewall_names=firewall)

                # result with scheduled_command only - no update to the war room
                command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                           readable_output=generate_polling_readable_message(
                                                               resource_type_name="Firewall",
                                                               resource_name=firewall)))

            else:
                command_results_list.append(generate_firewall_command_output(response,
                                                                             readable_header=f'Successfully Updated Firewall '
                                                                                             f'"{firewall}"'))

        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while updating {firewall}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def delete_rule_collection(client: AzureFirewallClient, collection_name: str, rule_type: str, firewall_name: str = None,
                           policy: str = None, should_poll: bool = False, interval: int = 30,
                           timeout: int = 60) -> CommandResults:
    """
    Delete rule collection from firewall or policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        collection_name (str): The name of the rule collection to delete.
        rule_type (str): The name of the rule collection type.
        firewall_name (str): The name of the firewall which contains the collection.
        policy (str): The name of the policy which contains the collection.
        should_poll (bool): Use Cortex XSOAR built-in polling to retrieve the resource
                            when it's finished the updating process.
        interval (int): Indicates how long to wait between command execution.
        timeout (int): Indicates the time in seconds until the polling sequence timeouts.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    if firewall_name:
        firewall_data, filtered_rules = get_firewall_rule_collection(client, firewall_name, rule_type=rule_type)

        collection_index = -1
        for index, collection in enumerate(filtered_rules):
            if collection.get("name") == collection_name:
                collection_index = index
                break
        if collection_index == -1:
            raise Exception(f'Collection {collection_name} is not exists in {firewall_name} firewall.')

        del filtered_rules[collection_index]

        response: dict = client.azure_firewall_update_request(firewall_name=firewall_name, firewall_data=firewall_data)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                         timeout=timeout, firewall_names=firewall_name)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Firewall",
                                                                                    resource_name=firewall_name))

        else:
            return generate_firewall_command_output(response,
                                                    readable_header=f'Successfully Updated Firewall "{firewall_name}"')

    else:
        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        response_delete = client.azure_firewall_policy_rule_collection_delete_request(policy_name=policy,
                                                                                      collection_name=collection_name)

        is_resource_deleted = response_delete.status_code == 200

        if should_poll and not is_resource_deleted:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                         timeout=timeout, policy_names=policy)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                    resource_name=policy))

        response = client.azure_firewall_policy_get_request(policy)

        return generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy}"')


def add_rule_to_policy_collection(client: AzureFirewallClient, policy: str, collection_name: str,
                                  rule_object: dict, rule_name: str) -> dict:
    """
    Add rule to policy rule collection
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        policy (str): The name of the policy which contains the collection.
        collection_name (str): The name of the rule collection which contains the rule.
        rule_object (dict): Policy rule information.
        rule_name (str): The name of the rule to create.

    Returns:
        dict: API response from Azure.

    """
    collection_information = client.azure_firewall_policy_rule_collection_get_request(
        policy_name=policy, collection_name=collection_name)

    for rule in collection_information["properties"]["ruleCollections"][0]["rules"]:
        if rule.get("name") == rule_name:
            raise Exception(f'Rule {rule_name} already exists.')

    collection_information["properties"]["ruleCollections"][0]["rules"].append(rule_object)

    return client.azure_firewall_policy_rule_collection_create_or_update_request(policy_name=policy,
                                                                                 collection_name=collection_name,
                                                                                 collection_data=collection_information)


def remove_rule_from_collection(client: AzureFirewallClient, collection_name: str, rule_type: str, rule_names: list,
                                firewall_name: str = None, policy: str = None, should_poll: bool = False,
                                interval: int = 30, timeout: int = 60) -> list:
    """
    Remove rule from collection in firewall or policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        collection_name (str): The name of the rule collection which contains the rule.
        rule_type (str): The name of the rule collection type.
        rule_names (list): The name of the rule to remove.
        firewall_name (str): The name of the firewall which contains the collection.
        policy (str): The name of the policy which contains the collection.
        should_poll (bool): Use Cortex XSOAR built-in polling to retrieve the resource
                            when it's finished the updating process.
        interval (int): Indicates how long to wait between command execution.
        timeout (int): Indicates the time in seconds until the polling sequence timeouts.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """

    command_results_list: List[CommandResults] = []

    if firewall_name:
        firewall_data, filtered_rules = get_firewall_rule_collection(client, firewall_name, rule_type=rule_type)

        collection_index = -1
        for index, collection in enumerate(filtered_rules):
            if collection.get("name") == collection_name:
                collection_index = index
                break
        if collection_index == -1:
            raise Exception(f'Collection {collection_name} is not exists.')

        for rule_name in rule_names:
            rule_index = -1
            for index, rule in enumerate(dict_safe_get(filtered_rules[collection_index], ["properties", "rules"], [])):
                if rule.get("name") == rule_name:
                    rule_index = index
                    break

            if rule_index == -1:
                error = CommandResults(
                    readable_output=f'Rule {rule_name} is not exists.'
                )
                command_results_list.append(error)
                continue

            del filtered_rules[collection_index]["properties"]["rules"][rule_index]

        response = client.azure_firewall_update_request(firewall_name=firewall_name, firewall_data=firewall_data)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                         timeout=timeout, firewall_names=firewall_name)

            command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                       readable_output=generate_polling_readable_message(
                                                           resource_type_name="Firewall",
                                                           resource_name=firewall_name)))

        else:
            command_results_list.append(generate_firewall_command_output(response,
                                                                         readable_header=f'Successfully Updated Firewall '
                                                                                         f'"{firewall_name}"'))

    else:
        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        collection_information = client.azure_firewall_policy_rule_collection_get_request(
            policy_name=policy, collection_name=collection_name)

        rules = collection_information["properties"]["ruleCollections"][0]["rules"]

        for rule_name in rule_names:
            rule_index = -1
            for index, rule in enumerate(rules):
                if rule.get("name") == rule_name:
                    rule_index = index

            if rule_index == -1:
                error = CommandResults(
                    readable_output=f'Rule {rule_name} is not exists.'
                )
                command_results_list.append(error)
                continue

            del rules[rule_index]

        response = client.azure_firewall_policy_rule_collection_create_or_update_request(policy_name=policy,
                                                                                         collection_name=collection_name,
                                                                                         collection_data=collection_information)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                         timeout=timeout, policy_names=policy)

            command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                       readable_output=generate_polling_readable_message(
                                                           resource_type_name="Policy",
                                                           resource_name=policy)))

        else:
            response = client.azure_firewall_policy_get_request(policy)

            command_results_list.append(
                generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy}"'))

    return command_results_list


def create_firewall_collection(client: AzureFirewallClient, firewall_name: str, rule_type: str,
                               collection_object: dict) -> dict:
    """
    Create firewall rules collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        firewall_name (str): The name of the firewall which contains the collection.
        rule_type (str): The name of the rule collection type.
        collection_object (dict): Collection information.
    Returns:
        dict: API response from Azure.

    """
    firewall_data = client.azure_firewall_get_request(firewall_name=firewall_name)
    rule_type_key = get_firewall_rule_collection_name(rule_type=rule_type)

    firewall_data["properties"][rule_type_key].append(collection_object)

    return client.azure_firewall_update_request(firewall_name=firewall_name, firewall_data=firewall_data)


def validate_predefined_argument(argument_name: str, argument_value: object, argument_options: list) -> bool:
    """
    Validate predefined argument is a valid option.
    Args:
        argument_name (str): The name of the argument to validate.
        argument_value (object): The value of the argument to validate.
        argument_options (list): Argument predifuend options.

    Returns:
        bool: True if the argument is valid, otherwise raise an exception.

    """
    if not isinstance(argument_value, list):
        argument_value = [argument_value]

    for value in argument_value:
        if value not in argument_options:
            raise Exception(f'Invalid {argument_name} argument. Please provide one of the following options:'
                            f'{str(argument_options)}')

    return True


def validate_network_rule_properties(source_type: str, destination_type: str, protocols: list,
                                     ip_source_address: list = None, source_ip_group_ids: list = None) -> bool:
    """
    Validate the provided network rule properties are valid.
    Args:
        source_type (str): Rule source type.
        destination_type (str):
        protocols (list): Protocols for the created rule
        ip_source_address (str): Source IP addresses for the created rule
        source_ip_group_ids (str): Source IP group IDs for the created rule.

    Returns:
        bool: True if the properties are valid, otherwise raise an exception.

    """

    validate_predefined_argument(argument_name='protocols', argument_value=protocols,
                                 argument_options=['TCP', 'UDP', 'ICMP', 'Any'])

    validate_predefined_argument(argument_name='source_type', argument_value=source_type,
                                 argument_options=['ip_address', 'ip_group'])

    validate_predefined_argument(argument_name='destination_type', argument_value=destination_type,
                                 argument_options=['ip_address', 'ip_group', 'service_tag', 'fqdn'])

    if source_type == 'ip_address' and not ip_source_address:
        raise Exception("`ip_source_address` argument most be provided when `ip_address` argument is provided.")

    if source_type == 'ip_group' and not source_ip_group_ids:
        raise Exception("`source_ip_group_ids` argument most be provided when `ip_group` argument is provided.")

    return True


def create_firewall_network_rule_object(rule_name: str, description: str, protocol: list, source_type: str,
                                        destination_type: str, destinations: list, destination_port: list,
                                        ip_source_address: list | None = None, source_ip_group_ids: list | None = None,
                                        is_firewall_rule: bool = False) -> dict:
    """
    Generate network rule object for firewall resource.
    Args:
        rule_name (str): The name of the rule.
        description (str): The description of the rule.
        protocol (list): Protocols of the rule.
        source_type (str): Rule source type.
        destination_type (str): Rule destination type.
        destinations (list): Destinations of the rule.
        destination_port (list): Destination ports
        ip_source_address (list): Source IP addresses of the rule.
        source_ip_group_ids (list): Source IP group IDs of the rule.
        is_firewall_rule (bool): Indicates if the rule belongs to firewall or policy.

    Returns:
        dict: Rule object information.

    """

    rule_object = {
        "name": rule_name,
        "description": description,
        "destinationPorts": destination_port,
    }

    if source_type == 'ip_address':
        rule_object["sourceAddresses"] = ip_source_address  # type: ignore[assignment]
    else:  # source_type == 'ip_group'
        rule_object["sourceIpGroups"] = source_ip_group_ids  # type: ignore[assignment]

    destination_path = {"ip_address": "destinationAddresses", "ip_group": "destinationIpGroups",
                        "service_tag": "destinationAddresses", "fqdn": "destinationFqdns"}

    rule_object[destination_path[destination_type]] = destinations

    if is_firewall_rule:
        rule_object["protocols"] = protocol
    else:
        rule_object["ipProtocols"] = protocol
        rule_object["ruleType"] = "NetworkRule"

    return rule_object


def azure_firewall_network_rule_collection_create_command(client: AzureFirewallClient,
                                                          args: Dict[str, Any]) -> CommandResults:
    """
    Create network rule collection in firewall or policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    collection_name = args.get('collection_name', '')
    collection_priority = arg_to_number(args.get('collection_priority'))
    action = args.get('action', '')
    rule_name = args.get('rule_name', '')
    description = args.get('description', '')
    protocol = argToList(args.get('protocols'))
    source_type = args.get('source_type', '')  # ip_address or ip_group
    ip_source_address = argToList(
        args.get('source_ips', []))  # Must be provided when 'source_type' argument is assigned to 'ip_address'.

    source_ip_group_ids = argToList(
        args.get('source_ip_group_ids', []))  # Must be provided when 'source_type' argument is assigned to 'ip_group'.

    destination_type = args.get('destination_type', '')  # ip_address or ip_group or service_tag or fqdn.
    destinations = argToList(args.get('destinations'))
    destination_port = argToList(args.get('destination_ports'))

    validate_network_rule_properties(source_type=source_type, destination_type=destination_type, protocols=protocol,
                                     ip_source_address=ip_source_address, source_ip_group_ids=source_ip_group_ids)

    rule_information = create_firewall_network_rule_object(rule_name=rule_name, description=description,
                                                           protocol=protocol,
                                                           source_type=source_type,
                                                           destination_type=destination_type,
                                                           destinations=destinations,
                                                           destination_port=destination_port,
                                                           ip_source_address=ip_source_address,
                                                           source_ip_group_ids=source_ip_group_ids,
                                                           is_firewall_rule=policy is None)

    if firewall_name:
        collection_object = remove_empty_elements({
            "name": collection_name,
            "properties": {
                "priority": collection_priority,
                "action": {
                    "type": action
                },
                "rules": [
                    rule_information
                ]
            }
        })

        response = create_firewall_collection(client=client, firewall_name=firewall_name, rule_type="network_rule",
                                              collection_object=collection_object)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                         timeout=timeout, firewall_names=firewall_name)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Firewall",
                                                                                    resource_name=firewall_name))

        else:
            return generate_firewall_command_output(response,
                                                    readable_header=f'Successfully Updated Firewall "{firewall_name}"')

    else:

        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        collection_information = None

        try:
            collection_information = client.azure_firewall_policy_rule_collection_get_request(
                policy_name=policy,
                collection_name=collection_name)

        except NotFoundError:
            pass

        if collection_information:
            raise Exception(f'The collection {collection_name} already exists in policy.')

        response = client.azure_firewall_policy_network_rule_collection_create_request(policy_name=policy,
                                                                                       collection_priority=collection_priority,
                                                                                       collection_name=collection_name,
                                                                                       action=action,
                                                                                       rule_information=rule_information)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                         timeout=timeout, policy_names=policy)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                    resource_name=policy))

        response = client.azure_firewall_policy_get_request(policy)

        return generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy}"')


def update_policy_rule_collection(client: AzureFirewallClient, policy: str, collection_name: str,
                                  priority: int = None, action: str = None) -> dict:
    """
    Update rule collection in policy
    Args:
        client ():
        policy (str): The name of the policy which contains the collection.
        collection_name (str): The name of the rule collection to update.
        priority (int): The priority of the rule collection resource.
        action (str): The action type of a rule collection.

    Returns:
        dict: API response from Azure.
    """

    collection_information = client.azure_firewall_policy_rule_collection_get_request(
        policy_name=policy, collection_name=collection_name)

    rule_collections = dict_safe_get(collection_information, ["properties", "ruleCollections"], [])

    if action:
        rule_collections[0]["action"]["type"] = action

    if priority:
        rule_collections[0]["priority"] = priority
        collection_information["properties"]["priority"] = priority

    return client.azure_firewall_policy_rule_collection_create_or_update_request(policy_name=policy,
                                                                                 collection_name=collection_name,
                                                                                 collection_data=collection_information)


def azure_firewall_network_rule_collection_update_command(client: AzureFirewallClient,
                                                          args: Dict[str, Any]) -> CommandResults:
    """
    Update network rule collection in firewall or policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    collection_name = args.get('collection_name', '')
    priority = args.get('priority')
    if priority:
        priority = arg_to_number(priority)
    action = args.get('action')

    if firewall_name:

        firewall_data, filtered_rules = get_firewall_rule_collection(client, firewall_name,
                                                                     rule_type="network_rule")

        collection_index = -1
        for index, collection in enumerate(filtered_rules):
            if collection.get("name") == collection_name:
                collection_index = index
                break
        if collection_index == -1:
            raise Exception(f'Collection {collection_name} is not exists in {firewall_name} firewall.')

        if action:
            filtered_rules[collection_index]["properties"]["action"]["type"] = action

        if priority:
            filtered_rules[collection_index]["properties"]["priority"] = priority

        response = client.azure_firewall_update_request(firewall_name=firewall_name, firewall_data=firewall_data)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                         timeout=timeout, firewall_names=firewall_name)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Firewall",
                                                                                    resource_name=firewall_name))

        else:
            return generate_firewall_command_output(response,
                                                    readable_header=f'Successfully Updated Firewall "{firewall_name}"')

    else:
        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        response = update_policy_rule_collection(client=client, policy=policy, collection_name=collection_name,
                                                 priority=priority,
                                                 action=action)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                         timeout=timeout, policy_names=policy)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                    resource_name=policy))

        response = client.azure_firewall_policy_get_request(policy)

        return generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy}"')


def azure_firewall_network_rule_collection_delete_command(client: AzureFirewallClient,
                                                          args: Dict[str, Any]) -> CommandResults:
    """
    Delete network rule collection from firewall or policy.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    collection_name = args.get('collection_name', '')

    return delete_rule_collection(client=client, collection_name=collection_name, rule_type="network_rule",
                                  firewall_name=firewall_name, policy=policy, should_poll=should_poll,
                                  interval=interval, timeout=timeout)


def add_rule_to_firewall_collection(client: AzureFirewallClient, firewall_name: str, collection_name: str,
                                    rule_type: str, rule_object: dict) -> dict:
    """
    Add rule to firewall rule collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        firewall_name (str): The name of the firewall which contains the collection.
        collection_name (str): The name of the rule collection which contains the rule.
        rule_type (str) The name of the rule collection type.
        rule_object (dict): Firewall rule information.

    Returns:
        dict: API response from Azure.

    """
    firewall_data, filtered_rules = get_firewall_rule_collection(client, firewall_name,
                                                                 rule_type=rule_type)

    collection_index = -1
    for index, collection in enumerate(filtered_rules):
        if collection.get("name") == collection_name:
            collection_index = index
            break
    if collection_index == -1:
        raise Exception(f'Collection {collection_name} is not exists.')

    filtered_rules[collection_index]["properties"]["rules"].append(rule_object)

    return client.azure_firewall_update_request(firewall_name=firewall_name, firewall_data=firewall_data)


def azure_firewall_network_rule_create_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Create network rule in firewall or policy rule collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    collection_name = args.get('collection_name', '')
    rule_name = args.get('rule_name', '')
    description = args.get('description', '')
    protocol = argToList(args.get('protocols'))
    source_type = args.get('source_type', '')  # ip_address or ip_group
    ip_source_address = argToList(
        args.get('source_ips', []))  # Must be provided when 'source_type' argument is assigned to 'ip_address'.

    source_ip_group_ids = argToList(
        args.get('source_ip_group_ids', []))  # Must be provided when 'source_type' argument is assigned to 'ip_group'.

    destination_type = args.get('destination_type', '')  # ip_address or ip_group or service_tag or fqdn.
    destinations = argToList(args.get('destinations'))
    destination_port = argToList(args.get('destination_ports'))

    validate_network_rule_properties(source_type=source_type, destination_type=destination_type, protocols=protocol,
                                     ip_source_address=ip_source_address, source_ip_group_ids=source_ip_group_ids)

    rule_information = create_firewall_network_rule_object(rule_name=rule_name, description=description,
                                                           protocol=protocol,
                                                           source_type=source_type,
                                                           destination_type=destination_type,
                                                           destinations=destinations,
                                                           destination_port=destination_port,
                                                           ip_source_address=ip_source_address,
                                                           source_ip_group_ids=source_ip_group_ids,
                                                           is_firewall_rule=policy is None)

    if firewall_name:

        response = add_rule_to_firewall_collection(client=client, firewall_name=firewall_name,
                                                   collection_name=collection_name,
                                                   rule_type="network_rule", rule_object=rule_information)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                         timeout=timeout, firewall_names=firewall_name)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Firewall",
                                                                                    resource_name=firewall_name))

        else:
            return generate_firewall_command_output(response,
                                                    readable_header=f'Successfully Updated Firewall "{firewall_name}"')

    else:
        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        response = add_rule_to_policy_collection(client=client, policy=policy, collection_name=collection_name,
                                                 rule_object=rule_information, rule_name=rule_name)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                         timeout=timeout, policy_names=policy)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                    resource_name=policy))

        response = client.azure_firewall_policy_get_request(policy)

        return generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy}"')


def update_firewall_collection_rule(client: AzureFirewallClient, firewall_name: str, collection_name: str,
                                    rule_name: str, rule_type: str, rule_fields_mapper: dict,
                                    update_fields: dict) -> dict:
    """
    Update rule in firewall rules collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        firewall_name (str): The name of the firewall which contains the collection.
        collection_name (str): The name of the rule collection which contains the rule.
        rule_name (str): The name of the rule to update
        rule_type (str): The name of the rule collection type.
        rule_fields_mapper (dict): Mapper between field name and Azure field name convention.
        update_fields (dict): New rule information to update.

    Returns:
        dict: API response from Azure.
    """

    firewall_data, filtered_rules = get_firewall_rule_collection(client, firewall_name, rule_type=rule_type)

    collection_index = -1
    rule_found = False

    for index, collection in enumerate(filtered_rules):
        if collection.get("name") == collection_name:
            collection_index = index
            break
    if collection_index == -1:
        raise Exception(f'Collection {collection_name} is not exists.')

    for rule in dict_safe_get(filtered_rules[collection_index], ["properties", "rules"], []):
        if rule.get("name") == rule_name:
            rule_found = True
            for field_key, value in update_fields.items():
                key_path = rule_fields_mapper.get(field_key, [])
                rule[key_path] = value

            break

    if not rule_found:
        raise Exception(f'Rule {rule_name} is not exists.')

    return client.azure_firewall_update_request(firewall_name=firewall_name, firewall_data=firewall_data)


def update_policy_collection_rule(client: AzureFirewallClient, policy: str, collection_name: str,
                                  rule_name: str, rule_fields_mapper: dict,
                                  update_fields: dict) -> dict:
    """
    Update rule in policy rules collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        policy (str): The name of the policy which contains the collection.
        collection_name (str): The name of the rule collection which contains the rule.
        rule_name (str): The name of the rule to update
        rule_fields_mapper (dict): Mapper between field name and Azure field name convention.
        update_fields (dict): New rule information to update.

    Returns:
        dict: API response from Azure.

    """
    collection_information = client.azure_firewall_policy_rule_collection_get_request(
        policy_name=policy, collection_name=collection_name)

    rules = collection_information["properties"]["ruleCollections"][0]["rules"]
    rule_found = False

    for rule in rules:
        if rule.get("name") == rule_name:
            rule_found = True
            for field_key, value in update_fields.items():
                key_path = rule_fields_mapper.get(field_key, [])
                rule[key_path] = value
            break

    if not rule_found:
        raise Exception(f'Rule {rule_name} is not exists.')

    return client.azure_firewall_policy_rule_collection_create_or_update_request(policy_name=policy,
                                                                                 collection_name=collection_name,
                                                                                 collection_data=collection_information)


def azure_firewall_network_rule_update_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Update network rule in firewall or policy collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    collection_name = args.get('collection_name', '')
    rule_name = args.get('rule_name', '')
    description = args.get('description', '')
    protocol = argToList(args.get('protocols'))
    ip_source_address = argToList(args.get('source_ips'))
    source_ip_group_ids = argToList(args.get('source_ip_group_ids'))
    destination_port = argToList(args.get('destination_ports'))
    destination_type = args.get('destination_type', '')
    source_type = args.get('source_type', '')
    destinations = argToList(args.get('destinations'))

    update_fields = assign_params(description=description, destination_port=destination_port,
                                  protocol=protocol)

    rule_fields_mapper = {"description": "description", "destination_port": "destinationPorts"}

    if source_type:
        if source_type == 'ip_address':
            rule_fields_mapper["ip_source_address"] = "sourceAddresses"
            update_fields["ip_source_address"] = ip_source_address
        else:  # source_type == 'ip_group'
            rule_fields_mapper["ip_source_address"] = "sourceIpGroups"
            update_fields["ip_source_address"] = source_ip_group_ids

    if destinations:
        destination_path = {"ip_address": "destinationAddresses", "ip_group": "destinationIpGroups",
                            "service_tag": "destinationAddresses", "fqdn": "destinationFqdns"}

        rule_fields_mapper["ip_destination_address"] = destination_path[destination_type]
        update_fields["ip_destination_address"] = destinations

    if firewall_name:
        if protocol:
            rule_fields_mapper["protocol"] = "protocols"

        response = update_firewall_collection_rule(client=client, firewall_name=firewall_name,
                                                   collection_name=collection_name,
                                                   rule_name=rule_name, rule_type="network_rule",
                                                   rule_fields_mapper=rule_fields_mapper,
                                                   update_fields=update_fields)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-get', interval=interval,
                                                         timeout=timeout, firewall_names=firewall_name)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Firewall",
                                                                                    resource_name=firewall_name))

        else:
            return generate_firewall_command_output(response,
                                                    readable_header=f'Successfully Updated Firewall "{firewall_name}"')

    else:

        if not policy:
            raise Exception("One of the arguments: `firewall_name` or `policy` must be provided.")

        if protocol:
            rule_fields_mapper["protocol"] = "ipProtocols"

        response = update_policy_collection_rule(client=client, policy=policy, collection_name=collection_name,
                                                 rule_name=rule_name, rule_fields_mapper=rule_fields_mapper,
                                                 update_fields=update_fields)

        state = dict_safe_get(response, ["properties", "provisioningState"], '')

        if should_poll and state not in ["Succeeded", "Failed"]:
            # schedule next poll
            scheduled_command = create_scheduled_command(command_name='azure-firewall-policy-get', interval=interval,
                                                         timeout=timeout, policy_names=policy)

            return CommandResults(scheduled_command=scheduled_command,
                                  readable_output=generate_polling_readable_message(resource_type_name="Policy",
                                                                                    resource_name=policy))

        response = client.azure_firewall_policy_get_request(policy)

        return generate_policy_command_output(response, readable_header=f'Successfully Updated Policy "{policy}"')


def azure_firewall_network_rule_remove_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Remove network rule from rules collection.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        list[CommandResults]: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    firewall_name = args.get('firewall_name')
    policy = args.get('policy')
    collection_name = args.get('collection_name', '')
    rule_names = argToList(args.get('rule_names'))

    return remove_rule_from_collection(client=client, collection_name=collection_name, rule_type="network_rule",
                                       rule_names=rule_names, firewall_name=firewall_name, policy=policy,
                                       should_poll=should_poll, interval=interval, timeout=timeout)


def azure_firewall_service_tag_list_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve service tags information.

    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    location = args.get('location', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header='Service Tag List:',
                                                       limit=limit, page=page)

    start_offset = (page - 1) * limit
    end_offset = start_offset + limit
    complete_requests = False
    total_response: dict[str, list] = {'value': []}

    response = client.azure_firewall_service_tag_list_request(location=location)

    while not complete_requests:
        total_response['value'].extend(response.get('value', []))
        if len(total_response['value']) >= end_offset or not response.get('nextLink'):
            complete_requests = True
        else:
            response = client.azure_firewall_service_tag_list_request(location=location,
                                                                      next_link=response.get('nextLink'))

    readable_output = tableToMarkdown(
        readable_message,
        total_response.get('value', [])[start_offset: end_offset],
        headers=['name', 'id'],
        headerTransform=string_to_table_header
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureFirewall.ServiceTag',
        outputs_key_field='id',
        outputs=total_response.get('value', [])[start_offset: end_offset],
        raw_response=total_response
    )

    return command_results


def generate_ip_group_command_output(response: dict | list, readable_header: str, output_key: str = None) -> CommandResults:
    """
    Generate command output for IP groups commands.
    Args:
        response (dict | list): API response from Azure.
        output_key (str): Used to access to required data in the response.
        readable_header (str): Readable message header for XSOAR war room.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    outputs = copy.deepcopy(response.get(output_key, [])) if output_key and isinstance(response, dict) \
        else copy.deepcopy(response)

    if not isinstance(outputs, list):
        outputs = [outputs]

    readable_data = []

    for ip_group in outputs:
        properties = ip_group.get("properties")

        data = {
            "name": ip_group.get("name"),
            "id": ip_group.get("id"),
            **properties,
        }

        readable_data.append(data)

    readable_output = tableToMarkdown(
        readable_header,
        readable_data,
        headers=['name', 'id', 'ipAddresses', 'firewalls', 'firewallPolicies', 'provisioningState'],
        headerTransform=pascalToSpace
    )

    command_results = CommandResults(
        readable_output=readable_output,
        outputs_prefix='AzureFirewall.IPGroup',
        outputs_key_field='id',
        outputs=outputs,
        raw_response=response
    )

    return command_results


def azure_firewall_ip_group_create_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Create IP group resource.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    ip_group_name = args.get('ip_group_name', '')
    location = args.get('location', '')
    ip_address = argToList(args.get('ips'))
    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    response = client.azure_firewall_ip_group_create_request(ip_group_name=ip_group_name, location=location,
                                                             ip_address=ip_address)

    state = dict_safe_get(response, ["properties", "provisioningState"], '')

    if should_poll and state not in ["Succeeded", "Failed"]:
        # schedule next poll
        scheduled_command = create_scheduled_command(command_name='azure-firewall-ip-group-get', interval=interval,
                                                     timeout=timeout, ip_group_names=ip_group_name)

        return CommandResults(scheduled_command=scheduled_command,
                              readable_output=generate_polling_readable_message(resource_type_name="IP-Group",
                                                                                resource_name=ip_group_name))

    return generate_ip_group_command_output(response,
                                            readable_header=f'Successfully Created IP Group "{ip_group_name}"')


def azure_firewall_ip_group_update_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    Update IP group. Add or remove IPs from the group.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    ip_group_name = args.get('ip_group_name', '')
    ip_address_to_add = argToList(args.get('ips_to_add'))
    ip_address_to_remove = argToList(args.get('ips_to_remove'))

    should_poll = True
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    if not ip_address_to_add and not ip_address_to_remove:
        raise Exception("One of the arguments: `ip_address_to_add` or `ip_address_to_remove` must be provided.")

    ip_group_data = client.azure_firewall_ip_group_get_request(ip_group_name=ip_group_name)

    ip_addresses = dict_safe_get(ip_group_data, ["properties", "ipAddresses"])

    ip_addresses.extend(ip_address_to_add)

    for ip_item in ip_address_to_remove:
        try:
            ip_addresses.remove(ip_item)
        except ValueError:
            continue

    response = client.azure_firewall_ip_group_update_request(ip_group_name=ip_group_name, ip_group_data=ip_group_data)

    state = dict_safe_get(response, ["properties", "provisioningState"], '')

    if should_poll and state not in ["Succeeded", "Failed"]:
        # schedule next poll
        scheduled_command = create_scheduled_command(command_name='azure-firewall-ip-group-get', interval=interval,
                                                     timeout=timeout, ip_group_names=ip_group_name)

        return CommandResults(scheduled_command=scheduled_command,
                              readable_output=generate_polling_readable_message(resource_type_name="IP-Group",
                                                                                resource_name=ip_group_name))

    return generate_ip_group_command_output(response, readable_header=f'{ip_group_name} IP Group Information:')


def azure_firewall_ip_group_list_command(client: AzureFirewallClient, args: Dict[str, Any]) -> CommandResults:
    """
    List IP groups in resource group or subscription.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    resource = args.get('resource', '')
    limit = arg_to_number(args.get('limit')) or 50
    page = arg_to_number(args.get('page')) or 1
    validate_pagination_arguments(limit, page)

    readable_message = get_pagination_readable_message(header='IP Group List:',
                                                       limit=limit, page=page)

    start_offset = (page - 1) * limit
    end_offset = start_offset + limit
    complete_requests = False
    total_response: dict[str, list] = {'value': []}
    response = client.azure_firewall_ip_group_list_request(resource=resource)

    while not complete_requests:
        total_response['value'].extend(response.get('value', []))
        if len(total_response['value']) >= end_offset or not response.get('nextLink'):
            complete_requests = True
        else:
            response = client.azure_firewall_ip_group_list_request(resource=resource,
                                                                   next_link=response.get('nextLink'))

    return generate_ip_group_command_output(total_response.get('value', [])[start_offset: end_offset],
                                            readable_header=readable_message)


def azure_firewall_ip_group_get_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Retrieve IP group information.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ScheduledCommand.raise_error_if_not_supported()
    ip_group_names = argToList(args.get('ip_group_names'))

    scheduled = argToBoolean(args.get('polling', False))
    interval = arg_to_number(args.get('interval')) or 30
    timeout = arg_to_number(args.get('timeout')) or 60

    command_results_list: List[CommandResults] = []

    for ip_group in ip_group_names:
        try:
            response = client.azure_firewall_ip_group_get_request(ip_group_name=ip_group)

            state = dict_safe_get(response, ["properties", "provisioningState"], '')

            if scheduled and state not in ["Succeeded", "Failed"]:
                # schedule next poll
                scheduled_command = create_scheduled_command(command_name='azure-firewall-ip-group-get',
                                                             interval=interval, timeout=timeout,
                                                             ip_group_names=ip_group)

                # result with scheduled_command only - no update to the war room
                command_results_list.append(CommandResults(scheduled_command=scheduled_command,
                                                           readable_output=generate_polling_readable_message(
                                                               resource_type_name="IP-Group",
                                                               resource_name=ip_group)))

            else:

                command_results_list.append(
                    generate_ip_group_command_output(response, readable_header=f'{ip_group} IP Group Information:'))
        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while retrieving {ip_group}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


def azure_firewall_ip_group_delete_command(client: AzureFirewallClient, args: Dict[str, Any]) -> list:
    """
    Delete IP group resource.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.
        args (dict): Command arguments from XSOAR.

    Returns:
        CommandResults: outputs, readable outputs and raw response for XSOAR.

    """
    ip_group_names = argToList(args.get('ip_group_names'))

    command_results_list: List[CommandResults] = []

    for ip_group in ip_group_names:
        try:
            response = client.azure_firewall_ip_group_delete_request(ip_group_name=ip_group)

            if response.status_code == 202:
                readable_output = f'IP Group {ip_group} delete operation accepted and will complete asynchronously.'
            else:
                readable_output = f'IP Group {ip_group} deleted successfully.'

            command_results_list.append(CommandResults(
                readable_output=readable_output
            ))

        except Exception as exception:
            error = CommandResults(
                readable_output=f'An error occurred while deleting {ip_group}.\n {exception}'
            )
            command_results_list.append(error)

    return command_results_list


# --Authorization Commands--

def start_auth(client: AzureFirewallClient) -> CommandResults:
    """
    Start the authorization process.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.

    Returns:
        CommandResults: Authentication guidelines.

    """
    result = client.ms_client.start_auth('!azure-firewall-auth-complete')
    return CommandResults(readable_output=result)


def complete_auth(client: AzureFirewallClient) -> str:
    """
    Complete authorization process.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.

    Returns:
        str: Informative message.

    """
    client.ms_client.get_access_token()
    return 'Authorization completed successfully.'


def test_connection(client: AzureFirewallClient) -> str:
    """
    Test connectivity to Azure.
    Args:
        client (AzureFirewallClient): Azure Firewall API client.

    Returns:
        str: Informative message.

    """
    try:
        client.ms_client.get_access_token()
    except Exception as err:
        return f'Authorization Error: \n{err}'
    return 'Success!'


def main() -> None:
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    verify_certificate: bool = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    api_version = params.get('api_version', '')

    subscription_id = params['subscription_id']['password']
    resource_group = params['resource_group']
    client_id = params.get('client_id', '')

    client_secret = dict_safe_get(params, ['client_secret', 'password'])
    tenant_id = dict_safe_get(params, ['tenant_id', 'password'])

    certificate_thumbprint = params.get('certificate_thumbprint')
    private_key = params.get('private_key')
    managed_identities_client_id = get_azure_managed_identities_client_id(params)

    if tenant_id and not client_secret and (
            (private_key and not certificate_thumbprint) or (certificate_thumbprint and not private_key)):
        raise DemistoException(
            'When Tenant ID is provided, either Client Secret or Certificate Thumbprint and Private Key must be provided.')

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client: AzureFirewallClient = AzureFirewallClient(
            subscription_id=subscription_id,
            resource_group=resource_group,
            client_id=client_id,
            api_version=api_version,
            verify=verify_certificate,
            proxy=proxy,
            client_secret=client_secret,
            tenant_id=tenant_id,
            certificate_thumbprint=certificate_thumbprint,
            private_key=private_key,
            managed_identities_client_id=managed_identities_client_id)

        commands = {
            'azure-firewall-list': azure_firewall_list_command,
            'azure-firewall-get': azure_firewall_get_command,
            'azure-firewall-rule-collection-list': azure_firewall_rules_collection_list_command,
            'azure-firewall-rule-list': azure_firewall_rules_list_command,
            'azure-firewall-rule-get': azure_firewall_rule_get_command,
            'azure-firewall-policy-create': azure_firewall_policy_create_command,
            'azure-firewall-policy-update': azure_firewall_policy_update_command,
            'azure-firewall-policy-get': azure_firewall_policy_get_command,
            'azure-firewall-policy-delete': azure_firewall_policy_delete_command,
            'azure-firewall-policy-list': azure_firewall_policy_list_command,
            'azure-firewall-policy-attach': azure_firewall_policy_attach_command,
            'azure-firewall-policy-detach': azure_firewall_policy_remove_command,
            'azure-firewall-network-rule-collection-create': azure_firewall_network_rule_collection_create_command,
            'azure-firewall-network-rule-collection-update': azure_firewall_network_rule_collection_update_command,
            'azure-firewall-network-rule-collection-delete': azure_firewall_network_rule_collection_delete_command,
            'azure-firewall-network-rule-create': azure_firewall_network_rule_create_command,
            'azure-firewall-network-rule-update': azure_firewall_network_rule_update_command,
            'azure-firewall-network-rule-delete': azure_firewall_network_rule_remove_command,
            'azure-firewall-service-tag-list': azure_firewall_service_tag_list_command,
            'azure-firewall-ip-group-create': azure_firewall_ip_group_create_command,
            'azure-firewall-ip-group-update': azure_firewall_ip_group_update_command,
            'azure-firewall-ip-group-list': azure_firewall_ip_group_list_command,
            'azure-firewall-ip-group-get': azure_firewall_ip_group_get_command,
            'azure-firewall-ip-group-delete': azure_firewall_ip_group_delete_command,
        }

        if command == 'test-module':
            if managed_identities_client_id:
                # test-module expected to get 'ok' in case of success
                test_res = test_connection(client=client)
                return return_results('ok' if 'Success' in test_res else test_res)

            else:
                return return_results(
                    'The test module is not functional, '
                    'run the azure-firewall-auth-start command instead.')

        if command == 'azure-firewall-auth-start':
            return_results(start_auth(client))

        elif command == 'azure-firewall-auth-complete':
            return_results(complete_auth(client))

        elif command == 'azure-firewall-auth-test':
            return_results(test_connection(client))

        elif command == 'azure-firewall-auth-reset':
            return_results(reset_auth())

        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f'{command} command is not implemented.')

    except Exception as e:
        return_error(str(e))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
