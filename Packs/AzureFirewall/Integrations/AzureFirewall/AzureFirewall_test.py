import copy

import pytest
from unittest.mock import Mock
from CommonServerPython import *

SUBSCRIPTION_ID = "sub_id"
RESOURCE_GROUP_NAME = "group_name"
BASE_URL = f'https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}' \
           f'/resourceGroups/{RESOURCE_GROUP_NAME}/providers/Microsoft.Network'
CLIENT_ID = "XXXX"

ScheduledCommand.raise_error_if_not_supported = Mock()


def load_mock_response(file_path: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_path (str): Path of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(file_path, encoding='utf-8') as mock_file:
        return mock_file.read()


def get_azure_access_token_mock() -> dict:
    """
    Mock Azure access token object.

    Returns:
        dict: Azure access token mock.
    """
    return {
        'access_token': 'my-access-token',
        'expires_in': 3595,
        'refresh_token': 'my-refresh-token',
    }


def get_client_mock():
    """
    Get API Client mock.
    Returns:
        AzureFirewallClient: API Client

    """
    from AzureFirewall import AzureFirewallClient
    return AzureFirewallClient(
        subscription_id=SUBSCRIPTION_ID,
        resource_group=RESOURCE_GROUP_NAME,
        client_id=CLIENT_ID,
        api_version='2021-03-01',
        verify=False,
        proxy=False)


def authorization_mock(requests_mock):
    """
    Azure authorization API request mock.

    """
    authorization_url = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    requests_mock.post(authorization_url, json=get_azure_access_token_mock())


def test_azure_firewall_list_command(requests_mock):
    """
    Scenario: List azure firewalls in resource group or subscription.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     -Ensure the firewall name expected is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    url = f'{BASE_URL}/azureFirewalls'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_list.json'))
    requests_mock.get(url, json=mock_response)

    result = azure_firewall_list_command(client, {'resource': 'resource_group'})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.Firewall'
    assert result.outputs[0].get('name') == 'xsoar-firewall'


def test_azure_firewall_get_command(requests_mock):
    """
    Scenario: Retrieve azure firewall information.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-get called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the firewall name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_get_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"firewall_names": firewall_name}
    result = azure_firewall_get_command(client, command_arguments)

    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'AzureFirewall.Firewall'
    assert result[0].outputs[0].get('name') == firewall_name


def test_azure_firewall_rules_collection_list_command_for_firewall(requests_mock):
    """
    Scenario: List collection rules in firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-rule-collection-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_rules_collection_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"firewall_name": firewall_name, "rule_type": "application_rule"}
    result = azure_firewall_rules_collection_list_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'id'
    assert result.outputs_prefix == 'AzureFirewall.RuleCollection'
    assert result.outputs[0].get('name') == "my-app-collection"
    assert dict_safe_get(result.outputs[0], ["properties", "rules"])[0].get("name") == "my-app-rule-1"


def test_azure_firewall_rules_collection_list_command_for_policy(requests_mock):
    """
    Scenario: List collection rules in policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-rule-collection-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the rule collection name searched is the same as in the context returned.
     - Ensure the rule collection key (type) searched is the same as in the context returned.
     - Ensure the rule type (type) searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_rules_collection_list_command, get_policy_rule_collection_name, \
        get_policy_rule_name

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-firewall'

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_rule_collection_list.json'))
    requests_mock.get(url, json=mock_response)

    rule_type = "application_rule"
    command_arguments = {"policy": policy_name, "rule_type": rule_type}
    result = azure_firewall_rules_collection_list_command(client, command_arguments)

    collection_key = get_policy_rule_collection_name(rule_type=rule_type)
    rule_key = get_policy_rule_name(rule_type=rule_type)

    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'id'
    assert result.outputs_prefix == 'AzureFirewall.RuleCollection'
    assert result.outputs[0].get('name') == "DefaultApplicationRuleCollectionGroup"
    assert dict_safe_get(result.outputs[0], ["properties", "ruleCollections"])[0].get("rules")[0].get(
        'ruleType') == rule_key
    assert dict_safe_get(result.outputs[0], ["properties", "ruleCollections"])[0].get(
        "ruleCollectionType") == collection_key


def test_azure_firewall_rules_list_command_for_policy(requests_mock):
    """
    Scenario: List rules in policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-rule-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the rule name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_rules_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-firewall'
    collection_name = "DefaultApplicationRuleCollectionGroup"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_rule_list.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"policy": policy_name, "collection_name": collection_name}
    result = azure_firewall_rules_list_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'name'
    assert result.outputs_prefix == 'AzureFirewall.Rule'
    assert result.outputs[0].get('name') == "my-app-rule-1"


def test_azure_firewall_rules_list_command_for_firewall(requests_mock):
    """
    Scenario: List rules in firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-rule-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the rule name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_rules_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'
    collection_name = "my-app-collection"

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"firewall_name": firewall_name, "collection_name": collection_name, "rule_type": "application_rule"}
    result = azure_firewall_rules_list_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_key_field == 'name'
    assert result.outputs_prefix == 'AzureFirewall.Rule'
    assert result.outputs[0].get('name') == "my-app-rule-1"


def test_azure_firewall_rules_get_command_for_firewall(requests_mock):
    """
    Scenario: Retrieve rule information in firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-rule-get called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the rule name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_rule_get_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'
    collection_name = "my-app-collection"
    rule_name = "my-app-rule-1"

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"firewall_name": firewall_name, "collection_name": collection_name, "rule_type": "application_rule",
                         "rule_name": rule_name}
    result = azure_firewall_rule_get_command(client, command_arguments)

    assert result.outputs_key_field == 'name'
    assert result.outputs_prefix == 'AzureFirewall.Rule'
    assert result.outputs.get('name') == rule_name


def test_azure_firewall_rule_get_command_for_policy(requests_mock):
    """
    Scenario: Retrieve rule information in policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-rule-get called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the rule name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_rule_get_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-firewall'
    collection_name = "DefaultApplicationRuleCollectionGroup"
    rule_name = "my-app-rule-1"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_rule_list.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"policy": policy_name, "collection_name": collection_name, "rule_name": rule_name}
    result = azure_firewall_rule_get_command(client, command_arguments)

    assert result.outputs_key_field == 'name'
    assert result.outputs_prefix == 'AzureFirewall.Rule'
    assert result.outputs.get('name') == "my-app-rule-1"


def test_azure_firewall_policy_create_command(requests_mock):
    """
    Scenario: Create firewall policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-create called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the policy name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_policy_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_create.json'))
    requests_mock.put(url, json=mock_response)

    command_arguments = {"policy_name": policy_name, "threat_intelligence_mode": "Turned-off", "location": "eastus",
                         "tier": "Standard", "enable_proxy": "False"}
    result = azure_firewall_policy_create_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_policy_update_command(requests_mock):
    """
    Scenario: Update firewall policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-update called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the policy name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_policy_update_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/policy/policy_update.json'))
    requests_mock.put(url, json=mock_response)

    command_arguments = {
        'base_policy_id': '/firewallPolicies/my-policy',
        'domains': 'microsoft.com', 'enable_proxy': 'True',
        'ips': '189.160.40.11', 'policy_name': policy_name, 'threat_intelligence_mode': 'Alert'}

    result = azure_firewall_policy_update_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_policy_list_command(requests_mock):
    """
    Scenario: List policy in resource group or subscription.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the policy name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_policy_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    url = f'{BASE_URL}/firewallPolicies'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_list.json'))
    requests_mock.get(url, json=mock_response)

    result = azure_firewall_policy_list_command(client, {})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == "xsoar-policy"


def test_azure_firewall_policy_get_command(requests_mock):
    """
    Scenario: Retrieve policy information.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-get called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the policy name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_policy_get_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'

    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {"policy_names": policy_name}
    result = azure_firewall_policy_get_command(client, command_arguments)

    assert len(result) == 1
    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'AzureFirewall.Policy'
    assert result[0].outputs[0].get('name') == policy_name


def test_azure_firewall_policy_delete_command(requests_mock):
    """
    Scenario: Delete policy resource.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
     """
    from AzureFirewall import azure_firewall_policy_delete_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'

    requests_mock.delete(url, status_code=202)

    command_arguments = {"policy_names": policy_name}
    result = azure_firewall_policy_delete_command(client, command_arguments)

    assert len(result) == 1
    assert result[0].outputs is None
    assert result[0].outputs_prefix is None
    assert result[0].readable_output == f'Policy {policy_name} ' \
                                        f'delete operation accepted and will complete asynchronously.'


def test_azure_firewall_policy_attach_command(requests_mock):
    """
    Scenario: Attach policy to firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-attach called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_policy_attach_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_subnet_public_ip_attach.json'))
    requests_mock.put(url, json=mock_response)

    command_arguments = {'firewall_names': firewall_name, 'policy_id': '/firewallPolicies/xsoar-platform-policy'}
    result = azure_firewall_policy_attach_command(client, command_arguments)

    assert len(result) == 1
    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'AzureFirewall.Firewall'
    assert result[0].outputs[0].get('name') == firewall_name


def test_azure_firewall_policy_remove_command(requests_mock):
    """
    Scenario: Remove policy from firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-remove called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_policy_remove_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_subnet_public_ip_remove.json'))
    requests_mock.put(url, json=mock_response)

    command_arguments = {'firewall_names': firewall_name}
    result = azure_firewall_policy_remove_command(client, command_arguments)

    assert len(result) == 1
    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'AzureFirewall.Firewall'
    assert result[0].outputs[0].get('name') == firewall_name


def test_azure_firewall_ip_group_create_command(requests_mock):
    """
    Scenario: Create IP group resource.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-ip-group-create called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the ip-group name created is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_ip_group_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    ip_group_name = 'xsoar-ip-group'

    url = f'{BASE_URL}/ipGroups/{ip_group_name}'

    mock_response = json.loads(load_mock_response('test_data/ip_group/ip_group_create.json'))
    requests_mock.put(url, json=mock_response)

    command_arguments = {'ip_group_name': ip_group_name, 'location': 'eastus', 'ips': '189.160.40.11,189.160.40.11'}
    result = azure_firewall_ip_group_create_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.IPGroup'
    assert result.outputs[0].get('name') == ip_group_name


def test_azure_firewall_ip_group_update_command(requests_mock):
    """
    Scenario: Update IP group. Add or remove IPs from the group.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-ip-group-update called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the ip-group name updated is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_ip_group_update_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    ip_group_name = 'xsoar-ip-group'

    url = f'{BASE_URL}/ipGroups/{ip_group_name}'

    mock_response = json.loads(load_mock_response('test_data/ip_group/ip_group_get.json'))
    requests_mock.get(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/ip_group/ip_group_update.json'))
    requests_mock.put(url, json=mock_response)

    ips_to_add = '189.160.40.11,189.160.40.11'

    ips_to_remove = '189.160.40.11'

    command_arguments = {'ip_group_name': ip_group_name, 'ips_to_add': ips_to_add, 'ips_to_remove': ips_to_remove}
    result = azure_firewall_ip_group_update_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.IPGroup'
    assert result.outputs[0].get('name') == ip_group_name


def test_azure_firewall_ip_group_list_command(requests_mock):
    """
    Scenario: List IP groups in resource group or subscription.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-ip-group-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the ip-group name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_ip_group_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    ip_group_name = 'xsoar-ip-group'
    url = f'{BASE_URL}/ipGroups'

    mock_response = json.loads(load_mock_response('test_data/ip_group/ip_group_list.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'resource': 'resource_group'}
    result = azure_firewall_ip_group_list_command(client, command_arguments)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.IPGroup'
    assert result.outputs[0].get('name') == ip_group_name


def test_azure_firewall_ip_group_get_command(requests_mock):
    """
    Scenario: List IP groups in resource group or subscription.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-ip-group-get called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the ip-group name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_ip_group_get_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    ip_group_name = 'xsoar-ip-group'
    url = f'{BASE_URL}/ipGroups/{ip_group_name}'

    mock_response = json.loads(load_mock_response('test_data/ip_group/ip_group_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'ip_group_names': ip_group_name}
    result = azure_firewall_ip_group_get_command(client, command_arguments)

    assert len(result) == 1
    assert len(result[0].outputs) == 1
    assert result[0].outputs_prefix == 'AzureFirewall.IPGroup'
    assert result[0].outputs[0].get('name') == ip_group_name


def test_azure_firewall_ip_group_delete_command(requests_mock):
    """
    Scenario: Delete IP group resource.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-policy-delete called.
    Then:
     - Ensure that the output is empty (None).
     - Ensure readable output message content.
     """
    from AzureFirewall import azure_firewall_ip_group_delete_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    ip_group_name = 'xsoar-ip-group'

    url = f'{BASE_URL}/ipGroups/{ip_group_name}'

    requests_mock.delete(url, status_code=202)

    command_arguments = {'ip_group_names': ip_group_name}
    result = azure_firewall_ip_group_delete_command(client, command_arguments)

    assert len(result) == 1
    assert result[0].outputs is None
    assert result[0].outputs_prefix is None
    assert result[0].readable_output == f'IP Group {ip_group_name} ' \
                                        f'delete operation accepted and will complete asynchronously.'


def test_azure_firewall_network_rule_collection_create_command_for_firewall(requests_mock):
    """
    Scenario: Create network rule collection in firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-create called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/firewall_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'action': 'Allow', 'collection_name': 'my-collection', 'collection_priority': '105',
                         'description': 'my-poc-collection', 'destination_ports': '8080',
                         'destination_type': 'ip_address',
                         'destinations': '189.160.40.11,189.160.40.11', 'firewall_name': firewall_name,
                         'protocols': 'UDP,TCP',
                         'rule_name': 'my-ip-rule', 'source_ips': '189.160.40.11,189.160.40.11',
                         'source_type': 'ip_address'}

    result = azure_firewall_network_rule_collection_create_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Firewall'
    assert result.outputs[0].get('name') == firewall_name


def test_azure_firewall_network_rule_collection_create_command_for_policy(requests_mock):
    """
    Scenario: Create network rule collection in policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-create called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the policy name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'
    collection_name = "xsoar-collection"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/policy_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    requests_mock.get(url, status_code=404)

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'
    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'action': 'Allow', 'collection_name': collection_name, 'collection_priority': '109',
                         'description': 'my-poc-collection', 'destination_ports': '8080',
                         'destination_type': 'ip_address', 'destinations': '189.160.40.11,189.160.40.11',
                         'policy': policy_name, 'protocols': 'UDP,TCP', 'rule_name': 'my-ip-rule',
                         'source_ips': '189.160.40.11,189.160.40.11', 'source_type': 'ip_address'}

    result = azure_firewall_network_rule_collection_create_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_network_rule_collection_create_command_invalid_arguments(requests_mock):
    """
    Scenario: Create network rule collection in firewall. The user provided invalid or missing arguments.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-create called.
    Then:
     - Ensure that exception is raised.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    command_arguments = {'action': 'Allow', 'collection_priority': '105',
                         'description': 'my-poc-collection', 'destination_ports': '8080',
                         'destination_type': 'ip_address', 'firewall_name': firewall_name,
                         'protocols': 'UDP,TCP', 'source_ips': '189.160.40.11,189.160.40.11',
                         'source_type': 'ip_address'}

    with pytest.raises(Exception):
        invalid_arguments = copy.deepcopy(command_arguments)
        invalid_arguments['protocols'] = 'test'
        azure_firewall_network_rule_collection_create_command(client, invalid_arguments)

    with pytest.raises(Exception):
        invalid_arguments = copy.deepcopy(command_arguments)
        invalid_arguments['source_type'] = 'test'
        azure_firewall_network_rule_collection_create_command(client, invalid_arguments)

    with pytest.raises(Exception):
        invalid_arguments = copy.deepcopy(command_arguments)
        invalid_arguments['destination_type'] = 'test'
        azure_firewall_network_rule_collection_create_command(client, invalid_arguments)

    with pytest.raises(Exception):
        invalid_arguments = copy.deepcopy(command_arguments)
        invalid_arguments['source_type'] = 'ip_address'
        del invalid_arguments['source_ips']
        azure_firewall_network_rule_collection_create_command(client, invalid_arguments)

    with pytest.raises(Exception):
        invalid_arguments = copy.deepcopy(command_arguments)
        invalid_arguments['source_type'] = 'ip_group'
        del invalid_arguments['source_ips']
        azure_firewall_network_rule_collection_create_command(client, invalid_arguments)


def test_azure_firewall_network_rule_create_command_for_firewall(requests_mock):
    """
    Scenario: Create network rule in firewall rule collection.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-create called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/firewall_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': 'my-network-rule-collection',
                         'description': 'my-poc-collection', 'destination_ports': '8080',
                         'destination_type': 'ip_address',
                         'destinations': '189.160.40.11,189.160.40.11', 'firewall_name': firewall_name,
                         'protocols': 'UDP,TCP',
                         'rule_name': 'my-ip-rule', 'source_ips': '189.160.40.11,189.160.40.11',
                         'source_type': 'ip_address'}

    result = azure_firewall_network_rule_create_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Firewall'
    assert result.outputs[0].get('name') == firewall_name


def test_azure_firewall_network_rule_create_command_for_policy(requests_mock):
    """
    Scenario: Create network rule in policy rule collection.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-create called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the policy name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_create_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'
    collection_name = "xsoar-collection"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/policy_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(
        load_mock_response('test_data/policy/policy_rule_collection_get.json'))
    requests_mock.get(url, json=mock_response)

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'
    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': collection_name,
                         'description': 'my-poc-collection', 'destination_ports': '8080',
                         'destination_type': 'ip_address', 'destinations': '189.160.40.11,189.160.40.11',
                         'policy': policy_name, 'protocols': 'UDP,TCP', 'rule_name': 'my-rule',
                         'source_ips': '189.160.40.11,189.160.40.11', 'source_type': 'ip_address'}

    result = azure_firewall_network_rule_create_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_network_rule_collection_update_command_for_firewall(requests_mock):
    """
    Scenario: Update network rule collection in firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-update called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_update_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/firewall_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'action': 'Deny', 'collection_name': 'my-network-rule-collection',
                         'firewall_name': firewall_name, 'priority': '201'}

    result = azure_firewall_network_rule_collection_update_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Firewall'
    assert result.outputs[0].get('name') == firewall_name


def test_azure_firewall_network_rule_collection_update_command_for_policy(requests_mock):
    """
    Scenario: Update network rule collection in policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-update called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the policy name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_update_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'
    collection_name = "xsoar-collection"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/policy_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(
        load_mock_response('test_data/policy/policy_rule_collection_get.json'))
    requests_mock.get(url, json=mock_response)

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'
    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'action': 'Deny', 'collection_name': collection_name,
                         'policy': policy_name, 'priority': '201'}

    result = azure_firewall_network_rule_collection_update_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_network_rule_collection_delete_command_for_firewall(requests_mock):
    """
    Scenario: Delete network rule collection from firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-delete called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_delete_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'
    collection_name = 'my-network-rule-collection'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(
        load_mock_response('test_data/firewall/firewall_update.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': collection_name, 'firewall_name': firewall_name}

    result = azure_firewall_network_rule_collection_delete_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Firewall'
    assert result.outputs[0].get('name') == firewall_name


def test_azure_firewall_network_rule_collection_delete_command_for_policy(requests_mock):
    """
    Scenario: Delete network rule collection from policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-collection-delete called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the policy name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_collection_delete_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'
    collection_name = "xsoar-collection"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    requests_mock.delete(url, status_code=200)

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'
    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'action': 'Deny', 'collection_name': collection_name,
                         'policy': policy_name, 'priority': '201'}

    result = azure_firewall_network_rule_collection_delete_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_network_rule_remove_command_for_firewall(requests_mock):
    """
    Scenario: Remove network rule from rules collection in firewall.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-delete called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
     - Ensure that the output is empty (None) for non-exists rules.
     """
    from AzureFirewall import azure_firewall_network_rule_remove_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'
    collection_name = 'my-network-rule-collection'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(
        load_mock_response('test_data/firewall/firewall_update.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': collection_name, 'firewall_name': firewall_name,
                         'rule_names': 'my-network-rule,not-exists-rule'}

    result = azure_firewall_network_rule_remove_command(client, command_arguments)

    assert result[0].outputs is None
    assert result[0].outputs_prefix is None
    assert result[0].readable_output == 'Rule not-exists-rule is not exists.'
    assert result[1].outputs[0].get("name") == firewall_name
    assert result[1].outputs_prefix == "AzureFirewall.Firewall"


def test_azure_firewall_network_rule_remove_command_for_policy(requests_mock):
    """
    Scenario: Remove network rule from rules collection in policy.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-delete called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the policy name updated is the same as in the context returned.
     - Ensure that the output is empty (None) for non-exists rules.
     """
    from AzureFirewall import azure_firewall_network_rule_remove_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'
    collection_name = "xsoar-collection"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/policy_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(
        load_mock_response('test_data/policy/policy_rule_collection_get.json'))
    requests_mock.get(url, json=mock_response)

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'
    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': collection_name, 'policy': policy_name,
                         'rule_names': 'my-ip-rule,not-exists-rule'}

    result = azure_firewall_network_rule_remove_command(client, command_arguments)

    assert result[0].outputs is None
    assert result[0].outputs_prefix is None
    assert result[0].readable_output == 'Rule not-exists-rule is not exists.'
    assert result[1].outputs[0].get("name") == policy_name
    assert result[1].outputs_prefix == 'AzureFirewall.Policy'


def test_azure_firewall_network_rule_update_command_policy(requests_mock):
    """
    Scenario: Update network rule in policy rule collection.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-update called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the policy name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_update_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    policy_name = 'xsoar-policy'
    collection_name = "xsoar-collection"

    url = f'{BASE_URL}/firewallPolicies/{policy_name}/ruleCollectionGroups/{collection_name}'

    mock_response = json.loads(
        load_mock_response('test_data/network_rule/policy_network_rule_collection_create.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(
        load_mock_response('test_data/policy/policy_rule_collection_get.json'))
    requests_mock.get(url, json=mock_response)

    url = f'{BASE_URL}/firewallPolicies/{policy_name}'
    mock_response = json.loads(load_mock_response('test_data/policy/policy_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': collection_name, 'description': 'new-description',
                         'destination_ports': '8085',
                         'destination_type': 'ip_address', 'destinations': '189.160.40.11', 'new_rule_name': 'new-name',
                         'policy': policy_name, 'protocols': 'UDP', 'rule_name': 'my-ip-rule',
                         'source_ips': '189.160.40.11',
                         'source_type': 'ip_address'}

    result = azure_firewall_network_rule_update_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Policy'
    assert result.outputs[0].get('name') == policy_name


def test_azure_firewall_network_rule_update_command_for_firewall(requests_mock):
    """
    Scenario: Update network rule in firewall rule collection.
    Given:
     - User has provided valid credentials.
    When:
     - azure-firewall-network-rule-update called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure the firewall name updated is the same as in the context returned.
     """
    from AzureFirewall import azure_firewall_network_rule_update_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    firewall_name = 'xsoar-firewall'
    collection_name = 'my-network-rule-collection'

    url = f'{BASE_URL}/azureFirewalls/{firewall_name}'

    mock_response = json.loads(
        load_mock_response('test_data/firewall/firewall_update.json'))
    requests_mock.put(url, json=mock_response)

    mock_response = json.loads(load_mock_response('test_data/firewall/firewall_get.json'))
    requests_mock.get(url, json=mock_response)

    command_arguments = {'collection_name': collection_name, 'description': 'new-description',
                         'destination_ports': '8085', 'firewall_name': firewall_name,
                         'destination_type': 'ip_address', 'destinations': '189.160.40.11', 'new_rule_name': 'new-name',
                         'protocols': 'UDP', 'rule_name': 'my-network-rule',
                         'source_ips': '189.160.40.11',
                         'source_type': 'ip_address'}

    result = azure_firewall_network_rule_update_command(client, command_arguments)

    assert result.outputs_prefix == 'AzureFirewall.Firewall'
    assert result.outputs[0].get('name') == firewall_name


def test_azure_firewall_service_tag_list_command(requests_mock):
    """
    Scenario: Retrieve service tags information.
    Given:
     - User has provided valid credentials.
    When:
     - azure-service-tag-list called.
    Then:
     - Ensure 1 result is returned.
     - Ensure outputs prefix is correct.
     - Ensure the service tag name searched is the same as in the context returned.
    """
    from AzureFirewall import azure_firewall_service_tag_list_command

    authorization_mock(requests_mock)
    client = get_client_mock()

    location = "eastus"
    url = f'https://management.azure.com/subscriptions/{SUBSCRIPTION_ID}/providers' \
          f'/Microsoft.Network/locations/{location}/serviceTagDetails'

    mock_response = json.loads(load_mock_response('test_data/network_rule/service_tag_list.json'))
    requests_mock.get(url, json=mock_response)

    result = azure_firewall_service_tag_list_command(client, {'location': location, "limit": 1})

    assert len(result.outputs) == 1
    assert result.outputs_prefix == 'AzureFirewall.ServiceTag'
    assert result.outputs[0].get('name') == 'ActionGroup'


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Given:
     - User has provided managed identities client oid.
    When:
     - test-module called.
    Then:
     - Ensure the out[ut are as expected
    """
    from AzureFirewall import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import AzureFirewall

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    params = {
        'managed_identities_client_id': {'password': client_id},
        'use_managed_identities': 'True',
        'subscription_id': {'password': 'test'},
        'resource_group': 'test_resource_group'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureFirewall, 'return_results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in AzureFirewall.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.management_azure]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs
