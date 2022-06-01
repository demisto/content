import json
from typing import Any, Dict, List, Union

from TrendMicroDeepSecurity import Client, convert_args

BASE_URL = "https://test.api.deepsecurity.trendmicro.com"


def load_mock_response(filename: str) -> Union[List[Any], Dict[str, Any]]:
    return json.loads(open(f"test_data/{filename}.json").read())


def test_trendmicro_list_computers_command(requests_mock):
    """
    Scenario: Lists all computers.
    Given:
        - User has provided valid credentials.
    When:
        - list_computers is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import list_computers_command

    mock_response = {"computers": [load_mock_response("computer")]}
    requests_mock.get(f"{BASE_URL}/api/computers?expand=none&overrides=true", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(list_computers_command, {"expand": "none", "overrides": "true"})
    result = list_computers_command(client, **args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.Computers"
    assert result.outputs[0]["hostName"] == "TestComputer"


def test_trendmicro_create_computer_command(requests_mock):
    """
    Scenario: Create a new computer.
    Given:
        - User has provided valid credentials.
    When:
        - create_computer is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import create_computer_command

    mock_response = load_mock_response("computer")
    requests_mock.post(f"{BASE_URL}/api/computers", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(create_computer_command, {"hostName": "TestComputer", "expand": "none", "overrides": "true"})
    result = create_computer_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.Computers"
    assert result.outputs["hostName"] == "TestComputer"


def test_trendmicro_search_computers_command(requests_mock):
    """
    Scenario: Search for computers using optional filters.
    Given:
        - User has provided valid credentials.
    When:
        - search_computers is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import search_computers_command

    mock_response = {"computers": [load_mock_response("computer")]}
    requests_mock.post(f"{BASE_URL}/api/computers/search", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(search_computers_command,
                        {"field_name": "hostName", "field_type": "string", "operation": "equal",
                         "value": "TestComputer", "max_items": "50"})
    result = search_computers_command(client, **args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.Computers"
    assert result.outputs[0]["hostName"] == "TestComputer"


def test_trendmicro_get_computer_command(requests_mock):
    """
    Scenario: Describe a computer by ID.
    Given:
        - User has provided valid credentials.
    When:
        - get_computer is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_computer_command

    mock_response = load_mock_response("computer")
    requests_mock.get(f"{BASE_URL}/api/computers/3", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_computer_command, {"computer_id": "3", "expand": "none", "overrides": "true"})
    result = get_computer_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.Computers"
    assert result.outputs["hostName"] == "TestComputer"


def test_trendmicro_modify_computer_command(requests_mock):
    """
    Scenario: Modify a computer by ID.
    Given:
        - User has provided valid credentials.
    When:
        - modify_computer is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_computer_command

    mock_response = load_mock_response("computer")
    requests_mock.post(f"{BASE_URL}/api/computers/3", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_computer_command,
                        {"computer_id": "3", "description": "Test", "expand": "none", "overrides": "true"})
    result = modify_computer_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.Computers"
    assert result.outputs["hostName"] == "TestComputer"


def test_trendmicro_delete_computer_command(requests_mock):
    """
    Scenario: Delete a computer by ID.
    Given:
        - User has provided valid credentials.
    When:
        - delete_computer is called.
    Then:
        - Ensure the output indicates a successful delete.
    """

    from TrendMicroDeepSecurity import delete_computer_command

    requests_mock.delete(f"{BASE_URL}/api/computers/3", text="")

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(delete_computer_command, {"computer_id": "3"})
    result = delete_computer_command(client, **args)

    assert result.readable_output == "The computer was successfully deleted!"


def test_trendmicro_get_computer_setting_command(requests_mock):
    """
    Scenario: Return the value for a computer setting.
    Given:
        - User has provided valid credentials.
    When:
        - get_computer_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_computer_setting_command

    mock_response = load_mock_response("computer_setting")
    requests_mock.get(f"{BASE_URL}/api/computers/3/settings/firewallSettingEngineOptionVerifyTcpChecksumEnabled",
                      json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_computer_setting_command,
                        {"computer_id": "3", "name": "firewallSettingEngineOptionVerifyTcpChecksumEnabled",
                         "overrides": "true"})
    result = get_computer_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.ComputersSettings"
    assert result.outputs["value"] == "true"


def test_trendmicro_modify_computer_setting_command(requests_mock):
    """
    Scenario: Modify the value for a computer setting.
    Given:
        - User has provided valid credentials.
    When:
        - modify_computer_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_computer_setting_command

    mock_response = load_mock_response("computer_setting")
    requests_mock.post(f"{BASE_URL}/api/computers/3/settings/firewallSettingEngineOptionVerifyTcpChecksumEnabled",
                       json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_computer_setting_command,
                        {"computer_id": "3", "name": "firewallSettingEngineOptionVerifyTcpChecksumEnabled",
                         "overrides": "true", "value": "true"})
    result = modify_computer_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.ComputersSettings"
    assert result.outputs["value"] == "true"


def test_trendmicro_reset_computer_setting_command(requests_mock):
    """
    Scenario: Reset the value for a computer setting.
    Given:
        - User has provided valid credentials.
    When:
        - reset_computer_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import reset_computer_setting_command

    mock_response = load_mock_response("computer_setting")

    requests_mock.delete(f"{BASE_URL}/api/computers/3/settings/firewallSettingEngineOptionVerifyTcpChecksumEnabled",
                         json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(reset_computer_setting_command,
                        {"computer_id": "3", "name": "firewallSettingEngineOptionVerifyTcpChecksumEnabled",
                         "overrides": "true"})
    result = reset_computer_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.ComputersSettings"
    assert result.outputs["value"] == "true"


def test_trendmicro_list_firewall_rule_ids_on_computer_command(requests_mock):
    """
    Scenario: Lists all firewall rule IDs assigned to a computer.
    Given:
        - User has provided valid credentials.
    When:
        - list_firewall_rule_ids_on_computer is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import list_firewall_rule_ids_of_computer_command

    mock_response = {"assignedRuleIDs": load_mock_response("firewall_rule_ids")}
    requests_mock.get(f"{BASE_URL}/api/computers/3/firewall/assignments", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(list_firewall_rule_ids_of_computer_command, {"computer_id": "3", "overrides": "true"})
    result = list_firewall_rule_ids_of_computer_command(client, **args)

    assert len(result.outputs["assignedRuleIDs"]) == 3
    assert result.outputs_prefix == "TrendMicro.FirewallAssignments"
    assert result.outputs["assignedRuleIDs"][0] == 18


def test_trendmicro_set_firewall_rule_ids_on_computer_command(requests_mock):
    """
    Scenario: Set firewall rule IDs assigned to a computer.
    Given:
        - User has provided valid credentials.
    When:
        - set_firewall_rule_ids_on_computer is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import set_firewall_rule_ids_to_computer_command

    mock_response = {"assignedRuleIDs": load_mock_response("firewall_rule_ids")}
    requests_mock.put(f"{BASE_URL}/api/computers/3/firewall/assignments", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(set_firewall_rule_ids_to_computer_command,
                        {"computer_id": "3", "overrides": "true", "rule_ids": "18,19,20"})
    result = set_firewall_rule_ids_to_computer_command(client, **args)

    assert len(result.outputs["assignedRuleIDs"]) == 3
    assert result.outputs_prefix == "TrendMicro.FirewallAssignments"
    assert result.outputs["assignedRuleIDs"][0] == 18


def test_trendmicro_add_firewall_rule_ids_to_computer_command(requests_mock):
    """
    Scenario: Assign firewall rule IDs to a computer.
    Given:
        - User has provided valid credentials.
    When:
        - add_firewall_rule_ids_to_computer is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import add_firewall_rule_ids_to_computer_command

    mock_response = {"assignedRuleIDs": load_mock_response("firewall_rule_ids") + [21]}
    requests_mock.post(f"{BASE_URL}/api/computers/3/firewall/assignments", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(add_firewall_rule_ids_to_computer_command,
                        {"computer_id": "3", "overrides": "true", "rule_ids": "21"})
    result = add_firewall_rule_ids_to_computer_command(client, **args)

    assert len(result.outputs["assignedRuleIDs"]) == 4
    assert result.outputs_prefix == "TrendMicro.FirewallAssignments"
    assert result.outputs["assignedRuleIDs"][-1] == 21


def test_trendmicro_remove_firewall_rule_id_from_computer_command(requests_mock):
    """
    Scenario: Remove a firewall rule ID from a computer
    Given:
        - User has provided valid credentials.
    When:
        - remove_firewall_rule_id_from_computer is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import remove_firewall_rule_id_from_computer_command

    mock_response = {"assignedRuleIDS": load_mock_response("firewall_rule_ids")[1:]}
    requests_mock.delete(f"{BASE_URL}/api/computers/3/firewall/assignments/18", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(remove_firewall_rule_id_from_computer_command, {"computer_id": "3", "firewall_rule_id": "18"})
    result = remove_firewall_rule_id_from_computer_command(client, **args)

    assert result.readable_output == "The firewall rule 18 was successfully deleted from computer 3!"


def test_trendmicro_list_computer_groups_command(requests_mock):
    """
    Scenario: Lists all computer groups.
    Given:
        - User has provided valid credentials.
    When:
        - list_computer_groups is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import list_computer_groups_command

    mock_response = {"computerGroups": [load_mock_response("computer_group")]}
    requests_mock.get(f"{BASE_URL}/api/computergroups", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    result = list_computer_groups_command(client)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.ComputerGroups"
    assert result.outputs[0]["name"] == "TestGroup"


def test_trendmicro_create_computer_group_command(requests_mock):
    """
    Scenario: Create a new computer group.
    Given:
        - User has provided valid credentials.
    When:
        - create_computer_group is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import create_computer_group_command

    mock_response = load_mock_response("computer_group")
    requests_mock.post(f"{BASE_URL}/api/computergroups", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(create_computer_group_command, {"name": "TestGroup", "description": "", "parent_group_id": "0"})
    result = create_computer_group_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.ComputerGroups"
    assert result.outputs["name"] == "TestGroup"


def test_trendmicro_search_computer_groups_command(requests_mock):
    """
    Scenario: Search for computer groups using optional filters
    Given:
        - User has provided valid credentials.
    When:
        - search_computer_groups is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import search_computer_groups_command

    mock_response = {"computerGroups": [load_mock_response("computer_group")]}
    requests_mock.post(f"{BASE_URL}/api/computergroups/search", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(search_computer_groups_command,
                        {"field_name": "name", "field_type": "string", "operation": "equal", "value": "TestGroup",
                         "max_items": "50"}, )
    result = search_computer_groups_command(client, **args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.ComputerGroups"
    assert result.outputs[0]["name"] == "TestGroup"


def test_trendmicro_get_computer_group_command(requests_mock):
    """
    Scenario: Describe a computer group by ID.
    Given:
        - User has provided valid credentials.
    When:
        - get_computer_group is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_computer_group_command

    mock_response = load_mock_response("computer_group")
    requests_mock.get(f"{BASE_URL}/api/computergroups/67", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_computer_group_command, {"computer_group_id": "67"})
    result = get_computer_group_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.ComputerGroups"
    assert result.outputs["name"] == "TestGroup"


def test_trendmicro_modify_computer_group_command(requests_mock):
    """
    Scenario: Modify a computer group by ID
    Given:
        - User has provided valid credentials.
    When:
        - modify_computer_group is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_computer_group_command

    mock_response = load_mock_response("computer_group")
    requests_mock.post(f"{BASE_URL}/api/computergroups/67", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_computer_group_command, {"computer_group_id": "67", "description": "Test Group"})
    result = modify_computer_group_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.ComputerGroups"
    assert result.outputs["name"] == "TestGroup"


def test_trendmicro_delete_computer_group_command(requests_mock):
    """
    Scenario: Delete a computer group by ID.
    Given:
        - User has provided valid credentials.
    When:
        - delete_computer_group is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import delete_computer_group_command

    requests_mock.delete(f"{BASE_URL}/api/computergroups/67", text="")

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(delete_computer_group_command, {"computer_group_id": "67"})
    result = delete_computer_group_command(client, **args)

    assert result.readable_output == "The computer group was successfully deleted!"


def test_trendmicro_search_firewall_rules_command(requests_mock):
    """
    Scenario: Search for firewall rules using optional filters.
    Given:
        - User has provided valid credentials.
    When:
        - search_firewall_rules is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import search_firewall_rules_command

    mock_response = {"firewallRules": [load_mock_response("firewall_rule")]}
    requests_mock.post(f"{BASE_URL}/api/firewallrules/search", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(search_firewall_rules_command,
                        {"field_type": "choice", "field_name": "action", "operation": "equal", "value": "allow",
                         "max_items": "50"})
    result = search_firewall_rules_command(client, **args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.FirewallRules"
    assert result.outputs[0]["name"] == "TestRule"


def test_trendmicro_list_firewall_rules_command(requests_mock):
    """
    Scenario: Lists all firewall rules.
    Given:
        - User has provided valid credentials.
    When:
        - list_firewall_rules is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import list_firewall_rules_command

    mock_response = {"firewallRules": [load_mock_response("firewall_rule")]}
    requests_mock.get(f"{BASE_URL}/api/firewallrules", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    result = list_firewall_rules_command(client)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.FirewallRules"
    assert result.outputs[0]["name"] == "TestRule"


def test_trendmicro_create_firewall_rule_command(requests_mock):
    """
    Scenario: Create a new firewall rule.
    Given:
        - User has provided valid credentials.
    When:
        - create_firewall_rule is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import create_firewall_rule_command

    mock_response = load_mock_response("firewall_rule")
    requests_mock.post(f"{BASE_URL}/api/firewallrules", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(create_firewall_rule_command, {"name": "TestRule"})
    result = create_firewall_rule_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.FirewallRules"
    assert result.outputs["name"] == "TestRule"


def test_trendmicro_get_firewall_rule_command(requests_mock):
    """
    Scenario: Describe a firewall rule by ID.
    Given:
        - User has provided valid credentials.
    When:
        - get_firewall_rule is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_firewall_rule_command

    mock_response = load_mock_response("firewall_rule")
    requests_mock.get(f"{BASE_URL}/api/firewallrules/5", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_firewall_rule_command, {"firewall_rule_id": "5"})
    result = get_firewall_rule_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.FirewallRules"
    assert result.outputs["name"] == "TestRule"


def test_trendmicro_modify_firewall_rule_command(requests_mock):
    """
    Scenario: Modify a firewall rule by ID.
    Given:
        - User has provided valid credentials.
    When:
        - modify_firewall_rule is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_firewall_rule_command

    mock_response = load_mock_response("firewall_rule")
    requests_mock.post(f"{BASE_URL}/api/firewallrules/5", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_firewall_rule_command, {"firewall_rule_id": "5", "description": "Test"})
    result = modify_firewall_rule_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.FirewallRules"
    assert result.outputs["name"] == "TestRule"


def test_trendmicro_delete_firewall_rule_command(requests_mock):
    """
    Scenario: Delete a firewall rule by ID
    Given:
        - User has provided valid credentials.
    When:
        - delete_firewall_rule is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import delete_firewall_rule_command

    requests_mock.delete(f"{BASE_URL}/api/firewallrules/5", text="")

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(delete_firewall_rule_command, {"firewall_rule_id": "5"})
    result = delete_firewall_rule_command(client, **args)

    assert result.readable_output == "The firewall rule was successfully deleted!"


def test_trendmicro_search_policies_command(requests_mock):
    """
    Scenario: Search for policies using optional filters.
    Given:
        - User has provided valid credentials.
    When:
        - search_policies is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import search_policies_command

    mock_response = {"policies": [load_mock_response("policy")]}
    requests_mock.post(f"{BASE_URL}/api/policies/search", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(search_policies_command,
                        {"field_name": "name", "field_type": "string", "operation": "equal", "value": "TestPolicy",
                         "max_items": "50"})
    result = search_policies_command(client, **args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.Policies"
    assert result.outputs[0]["name"] == "TestPolicy"


def test_trendmicro_get_policy_command(requests_mock):
    """
    Scenario: Describe a policy by ID.
    Given:
        - User has provided valid credentials.
    When:
        - get_policy is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_policy_command

    mock_response = load_mock_response("policy")
    requests_mock.get(f"{BASE_URL}/api/policies/12", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_policy_command, {"policy_id": "12", "overrides": "true"})
    result = get_policy_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.Policies"
    assert result.outputs["name"] == "TestPolicy"


def test_trendmicro_modify_policy_command(requests_mock):
    """
    Scenario: Modify a policy by ID.
    Given:
        - User has provided valid credentials.
    When:
        - modify_policy is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_policy_command

    mock_response = load_mock_response("policy")
    requests_mock.post(f"{BASE_URL}/api/policies/12", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_policy_command, {"policy_id": "12", "name": "TestPolicy", "overrides": "true"})
    result = modify_policy_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.Policies"
    assert result.outputs["name"] == "TestPolicy"


def test_trendmicro_delete_policy_command(requests_mock):
    """
    Scenario: Delete a policy by ID.
    Given:
        - User has provided valid credentials.
    When:
        - delete_policy is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import delete_policy_command

    requests_mock.delete(f"{BASE_URL}/api/policies/12", text="")

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(delete_policy_command, {"policy_id": "12"})
    result = delete_policy_command(client, **args)

    assert result.readable_output == "The policy was successfully deleted!"


def test_trendmicro_get_default_policy_setting_command(requests_mock):
    """
    Scenario: Return the value for a default policy setting.
    Given:
        - User has provided valid credentials.
    When:
        - get_default_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_default_policy_setting_command

    mock_response = load_mock_response("default_policy_setting")
    requests_mock.get(f"{BASE_URL}/api/policies/default/settings/webReputationSettingBlockedUrls", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_default_policy_setting_command, {"name": "webReputationSettingBlockedUrls"})
    result = get_default_policy_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.DefaultPolicySettings"
    assert result.outputs["name"] == "webReputationSettingBlockedUrls"


def test_trendmicro_modify_default_policy_setting_command(requests_mock):
    """
    Scenario: Modify the value for a default policy setting.
    Given:
        - User has provided valid credentials.
    When:
        - modify_default_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_default_policy_setting_command

    mock_response = load_mock_response("default_policy_setting")
    requests_mock.post(f"{BASE_URL}/api/policies/default/settings/webReputationSettingBlockedUrls", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_default_policy_setting_command,
                        {"name": "webReputationSettingBlockedUrls", "value": "true"})
    result = modify_default_policy_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.DefaultPolicySettings"
    assert result.outputs["name"] == "webReputationSettingBlockedUrls"


def test_trendmicro_reset_default_policy_setting_command(requests_mock):
    """
    Scenario: Reset the value for a default policy setting.
    Given:
        - User has provided valid credentials.
    When:
        - reset_default_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import reset_default_policy_setting_command

    mock_response = load_mock_response("default_policy_setting")
    requests_mock.delete(f"{BASE_URL}/api/policies/default/settings/webReputationSettingBlockedUrls",
                         json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(reset_default_policy_setting_command, {"name": "webReputationSettingBlockedUrls"})
    result = reset_default_policy_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.DefaultPolicySettings"
    assert result.outputs["name"] == "webReputationSettingBlockedUrls"


def test_trendmicro_list_default_policy_settings_command(requests_mock):
    """
    Scenario: Lists all default policy settings.
    Given:
        - User has provided valid credentials.
    When:
        - list_default_settings is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import list_default_policy_settings_command

    mock_response = load_mock_response("default_policy_setting")
    requests_mock.get(f"{BASE_URL}/api/policies/default", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    result = list_default_policy_settings_command(client)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.DefaultPolicySettings"
    assert result.outputs[0]["name"] == "webReputationSettingBlockedUrls"


def test_trendmicro_get_policy_setting_command(requests_mock):
    """
    Scenario: Return the value for a policy setting
    Given:
        - User has provided valid credentials.
    When:
        - get_policy_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import get_policy_setting_command

    mock_response = load_mock_response("policy_setting")
    requests_mock.get(f"{BASE_URL}/api/policies/12/settings/firewallSettingEngineOptionsEnabled", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(get_policy_setting_command,
                        {"policy_id": "12", "name": "firewallSettingEngineOptionsEnabled", "overrides": "true"}, )
    result = get_policy_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.PolicySettings"
    assert result.outputs["value"] == "true"


def test_trendmicro_modify_policy_setting_command(requests_mock):
    """
    Scenario: Modify the value for a policy setting.
    Given:
        - User has provided valid credentials.
    When:
        - modify_policy_setting is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import modify_policy_setting_command

    mock_response = load_mock_response("policy_setting")
    requests_mock.post(f"{BASE_URL}/api/policies/12/settings/firewallSettingEngineOptionsEnabled", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(modify_policy_setting_command,
                        {"policy_id": "12", "name": "firewallSettingEngineOptionsEnabled", "value": "true",
                         "overrides": "true"}, )
    result = modify_policy_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.PolicySettings"
    assert result.outputs["value"] == "true"


def test_trendmicro_reset_policy_setting_command(requests_mock):
    """
    Scenario: Reset the value for a policy setting.
    Given:
        - User has provided valid credentials.
    When:
        - reset_policy_setting is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import reset_policy_setting_command

    mock_response = load_mock_response("policy_setting")
    requests_mock.delete(f"{BASE_URL}/api/policies/12/settings/firewallSettingEngineOptionsEnabled", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(reset_policy_setting_command,
                        {"policy_id": "12", "name": "firewallSettingEngineOptionsEnabled", "overrides": "true"}, )
    result = reset_policy_setting_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.PolicySettings"
    assert result.outputs["value"] == "true"


def test_trendmicro_list_policies_command(requests_mock):
    """
    Scenario: Lists all policies.
    Given:
        - User has provided valid credentials.
    When:
        - list_policies is called.
    Then:
        - Ensure number of items is correct.
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import list_policies_command

    mock_response = {"policies": [load_mock_response("policy")]}
    requests_mock.get(f"{BASE_URL}/api/policies", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(list_policies_command, {"overrides": "true"})
    result = list_policies_command(client, **args)

    assert len(result.outputs) == 1
    assert result.outputs_prefix == "TrendMicro.Policies"
    assert result.outputs[0]["name"] == "TestPolicy"


def test_trendmicro_create_policy_command(requests_mock):
    """
    Scenario: Create a new policy.
    Given:
        - User has provided valid credentials.
    When:
        - create_policy is called.
    Then:
        - Ensure outputs prefix is correct.
        - Ensure a sample value from the API matches what is generated in the context.
    """

    from TrendMicroDeepSecurity import create_policy_command

    mock_response = load_mock_response("policy")
    requests_mock.post(f"{BASE_URL}/api/policies", json=mock_response)

    client = Client(base_url=BASE_URL, api_key="xxx", use_ssl=False, use_proxy=False)
    args = convert_args(create_policy_command, {"name": "TestPolicy", "overrides": "true"})
    result = create_policy_command(client, **args)

    assert result.outputs_prefix == "TrendMicro.Policies"
    assert result.outputs["name"] == "TestPolicy"
