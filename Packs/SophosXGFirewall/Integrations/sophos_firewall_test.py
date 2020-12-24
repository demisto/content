import json
import pytest

BASE_URL = 'https://1.1.1.1:1111/'
REQUEST_URL = 'https://1.1.1.1:1111/webconsole/APIController'


def load_mock_response(file_name: str) -> str:
    """
    Load one of the mock responses to be used for assertion.
    Args:
        file_name (str): Name of the mock response XML file to return.

    Returns:
        str: XML String containing the entire contents of the file.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as xml_file:
        return xml_file.read()


def test_sophos_firewall_rule_list_command(requests_mock):
    """
    Scenario: List all rules.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_list_command
    mock_response = load_mock_response('rule_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicy'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == 'Auto added firewall policy for MTA'


def test_sophos_firewall_rule_get_command(requests_mock):
    """
    Scenario: Get a single rule by name.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_get_command
    mock_response = load_mock_response('rule_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_get_command(client, 'unitest')
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicy'
    assert result.outputs.get('Name') == 'forunitest2'


def test_sophos_firewall_rule_add_command(requests_mock):
    """
    Scenario: Add a new rule.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_add_command
    mock_response = load_mock_response('rule_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('rule_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_add_command(client, {'name': 'forunitest2', 'policy_type': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicy'
    assert result.outputs.get('Name') == 'forunitest2'


def test_sophos_firewall_rule_update_command(requests_mock):
    """
    Scenario: Update an existing rule.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_update_command
    mock_response = load_mock_response('rule_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('rule_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_update_command(client, {'name': 'forunitest2',
                                                          'policy_type': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicy'
    assert result.outputs.get('Name') == 'forunitest2'


def test_sophos_firewall_rule_delete_command(requests_mock):
    """
    Scenario: Delete an existing rule.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_delete_command
    mock_response = load_mock_response('rule_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('rule_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicy'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_rule_group_list_command(requests_mock):
    """
    Scenario: List all rule groups.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_group_list is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_group_list_command
    mock_response = load_mock_response('rule_group_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_group_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicyGroup'
    assert len(result.outputs) == 4
    assert result.outputs[0].get('Name') == 'Traffic to Internal Zones'


def test_sophos_firewall_rule_group_get_command(requests_mock):
    """
    Scenario: Get a single rule group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_group_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_group_get_command
    mock_response = load_mock_response('rule_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_group_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicyGroup'
    assert result.outputs.get('Name') == 'unitest3'


def test_sophos_firewall_rule_group_add_command(requests_mock):
    """
    Scenario: Add a new rule group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_group_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_group_add_command
    mock_response = load_mock_response('rule_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('rule_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_group_add_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicyGroup'
    assert result.outputs.get('Name') == 'unitest3'


def test_sophos_firewall_rule_group_update_command(requests_mock):
    """
    Scenario: Update an existing rule group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_group_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_group_update_command
    mock_response = load_mock_response('rule_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('rule_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_group_update_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicyGroup'
    assert result.outputs.get('Name') == 'unitest3'


def test_sophos_firewall_rule_group_delete_command(requests_mock):
    """
    Scenario: Delete an existing rule group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_rule_group_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_rule_group_delete_command
    mock_response = load_mock_response('rule_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_rule_group_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.SecurityPolicyGroup'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_url_group_list_command(requests_mock):
    """
    Scenario: List all URL groups.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_url_group_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_url_group_list_command
    mock_response = load_mock_response('url_group_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_url_group_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.WebFilterURLGroup'
    assert len(result.outputs) == 5
    assert result.outputs[0].get('Name') == '1'


def test_sophos_firewall_url_group_get_command(requests_mock):
    """
    Scenario: Get a single URL group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_url_group_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_url_group_get_command
    mock_response = load_mock_response('url_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_url_group_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.WebFilterURLGroup'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_url_group_add_command(requests_mock):
    """
    Scenario: Add a new URL group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_url_group_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_url_group_add_command
    mock_response = load_mock_response('url_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('url_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_url_group_add_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.WebFilterURLGroup'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_url_group_update_command(requests_mock):
    """
    Scenario: Update an existing URL group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_url_group_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_url_group_update_command
    mock_response = load_mock_response('url_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('url_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_url_group_update_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.WebFilterURLGroup'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_url_group_delete_command(requests_mock):
    """
    Scenario: Delete an existing URL group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_url_group_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_url_group_delete_command
    mock_response = load_mock_response('url_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_url_group_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.WebFilterURLGroup'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_ip_host_list_command(requests_mock):
    """
    Scenario: List all IP hosts.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_list_command
    mock_response = load_mock_response('ip_host_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.IPHost'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == '##ALL_RW'


def test_sophos_firewall_ip_host_get_command(requests_mock):
    """
    Scenario: Get a single IP host.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_get_command
    mock_response = load_mock_response('ip_host_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.IPHost'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_ip_host_add_command(requests_mock):
    """
    Scenario: Add a new IP host.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_add_command
    mock_response = load_mock_response('ip_host_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('ip_host_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_add_command(client, {'name': 'b', 'host_type': 'IP',
                                                          'ip_address': '1.2.3.4'})
    assert result.outputs_prefix == 'SophosFirewall.IPHost'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_ip_host_update_command(requests_mock):
    """
    Scenario: Update an existing IP host.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_update_command
    mock_response = load_mock_response('ip_host_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('ip_host_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_update_command(client, {'name': 'b', 'host_type': 'IP',
                                                             'ip_address': '1.2.3.4'})
    assert result.outputs_prefix == 'SophosFirewall.IPHost'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_ip_host_delete_command(requests_mock):
    """
    Scenario: Delete an existing IP host.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_delete is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_delete_command
    mock_response = load_mock_response('ip_host_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.IPHost'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_ip_host_group_list_command(requests_mock):
    """
    Scenario: List all IP host groups.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_group_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_group_list_command
    mock_response = load_mock_response('ip_host_group_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_group_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.IPHostGroup'
    assert len(result.outputs) == 2
    assert result.outputs[0].get('Name') == 'ip_hosts'


def test_sophos_firewall_ip_host_group_get_command(requests_mock):
    """
    Scenario: Get a single IP host group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_group_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_group_get_command
    mock_response = load_mock_response('ip_host_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_group_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.IPHostGroup'
    assert result.outputs.get('Name') == 'unitest2'


def test_sophos_firewall_ip_host_group_add_command(requests_mock):
    """
    Scenario: Add a new IP host group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_group_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_group_add_command
    mock_response = load_mock_response('ip_host_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('ip_host_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_group_add_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.IPHostGroup'
    assert result.outputs.get('Name') == 'unitest2'


def test_sophos_firewall_ip_host_group_update_command(requests_mock):
    """
    Scenario: Update an existing IP host group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_group_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_group_update_command
    mock_response = load_mock_response('ip_host_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('ip_host_group_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_group_update_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.IPHostGroup'
    assert result.outputs.get('Name') == 'unitest2'


def test_sophos_firewall_ip_host_group_delete_command(requests_mock):
    """
    Scenario: Delete an existing IP host group.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_ip_host_group_delete is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_ip_host_group_delete_command
    mock_response = load_mock_response('ip_host_group_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_ip_host_group_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.IPHostGroup'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_services_list_command(requests_mock):
    """
    Scenario: List all services.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_services_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_services_list_command
    mock_response = load_mock_response('services_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_services_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.Services'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == 'AH'


def test_sophos_firewall_services_get_command(requests_mock):
    """
    Scenario: Get a single service.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_services_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_services_get_command
    mock_response = load_mock_response('services_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_services_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.Services'
    assert result.outputs.get('Name') == 'unitest2'


def test_sophos_firewall_services_add_command(requests_mock):
    """
    Scenario: Add a new service.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_services_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_services_add_command
    mock_response = load_mock_response('services_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('services_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_services_add_command(client, {'name': 'b', 'service_type': 'IP',
                                                           'protocol_name': 'ARGUS'})
    assert result.outputs_prefix == 'SophosFirewall.Services'
    assert result.outputs.get('Name') == 'unitest2'


def test_sophos_firewall_services_update_command(requests_mock):
    """
    Scenario: Update an existing service.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_services_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_services_update_command
    mock_response = load_mock_response('services_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('services_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_services_update_command(client, {'name': 'b', 'service_type': 'IP',
                                                              'protocol_name': 'ARGUS'})
    assert result.outputs_prefix == 'SophosFirewall.Services'
    assert result.outputs.get('Name') == 'unitest2'


def test_sophos_firewall_services_delete_command(requests_mock):
    """
    Scenario: Delete an existing service.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_services_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_services_delete_command
    mock_response = load_mock_response('services_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_services_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.Services'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_app_policy_list_command(requests_mock):
    """
    Scenario: List all app policies.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_policy_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_policy_list_command
    mock_response = load_mock_response('app_policy_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_policy_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterPolicy'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == 'Allow All'


def test_sophos_firewall_app_policy_get_command(requests_mock):
    """
    Scenario: Get a single app policy.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_policy_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_policy_get_command
    mock_response = load_mock_response('app_policy_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_policy_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterPolicy'
    assert result.outputs.get('Name') == 'unitests3'


def test_sophos_firewall_app_policy_add_command(requests_mock):
    """
    Scenario: Add a new app policy.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_policy_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_policy_add_command
    mock_response = load_mock_response('app_policy_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('app_policy_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_policy_add_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterPolicy'
    assert result.outputs.get('Name') == 'unitests3'


def test_sophos_firewall_app_policy_update_command(requests_mock):
    """
    Scenario: Update an existing app policy.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_policy_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_policy_update_command
    mock_response = load_mock_response('app_policy_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('app_policy_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_policy_update_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterPolicy'
    assert result.outputs.get('Name') == 'unitests3'


def test_sophos_firewall_app_policy_delete_command(requests_mock):
    """
    Scenario: Delete an existing app policy.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_policy_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_policy_delete_command
    mock_response = load_mock_response('app_policy_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_policy_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterPolicy'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_app_category_list_command(requests_mock):
    """
    Scenario: List all app categories.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_category_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_category_list_command
    mock_response = load_mock_response('app_category_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_category_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterCategory'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == 'Conferencing'


def test_sophos_firewall_app_category_get_command(requests_mock):
    """
    Scenario: Get a single app category.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_category_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_category_get_command
    mock_response = load_mock_response('app_category_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_category_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterCategory'
    assert result.outputs.get('Name') == 'Conferencing'


def test_sophos_firewall_app_category_update_command(requests_mock):
    """
    Scenario: Update an existing app category.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_app_category_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_app_category_update_command
    mock_response = load_mock_response('app_category_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('app_category_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_app_category_update_command(client, {'name': 'b'})
    assert result.outputs_prefix == 'SophosFirewall.ApplicationFilterCategory'
    assert result.outputs.get('Name') == 'Conferencing'


def test_sophos_firewall_web_filter_list_command(requests_mock):
    """
    Scenario: List all web filters.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_web_filter_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_web_filter_list_command
    mock_response = load_mock_response('web_filter_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_web_filter_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.WebFilterPolicy'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == 'xy1'


def test_sophos_firewall_web_filter_get_command(requests_mock):
    """
    Scenario: Get a single web filter.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_web_filter_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_web_filter_get_command
    mock_response = load_mock_response('web_filter_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_web_filter_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.WebFilterPolicy'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_web_filter_add_command(requests_mock):
    """
    Scenario: Add a new web filter.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_web_filter_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_web_filter_add_command
    mock_response = load_mock_response('web_filter_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('web_filter_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_web_filter_add_command(client, {'name': 'b',
                                                             'default_action': 'Allow'})
    assert result.outputs_prefix == 'SophosFirewall.WebFilterPolicy'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_web_filter_update_command(requests_mock):
    """
    Scenario: Update an existing web filter.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_web_filter_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_web_filter_update_command
    mock_response = load_mock_response('web_filter_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('web_filter_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_web_filter_update_command(client, {'name': 'b',
                                                                'default_action': 'Allow'})
    assert result.outputs_prefix == 'SophosFirewall.WebFilterPolicy'
    assert result.outputs.get('Name') == 'unitest'


def test_sophos_firewall_web_filter_delete_command(requests_mock):
    """
    Scenario: Delete an existing web filter.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_web_filter_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_web_filter_delete_command
    mock_response = load_mock_response('web_filter_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_web_filter_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.WebFilterPolicy'
    assert result.outputs.get('Name') == 'forunitest'


def test_sophos_firewall_user_list_command(requests_mock):
    """
    Scenario: List all users.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_user_list is called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_user_list_command
    mock_response = load_mock_response('user_list.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_user_list_command(client, 0, 10)
    assert result.outputs_prefix == 'SophosFirewall.User'
    assert len(result.outputs) == 10
    assert result.outputs[0].get('Name') == 'user'


def test_sophos_firewall_user_get_command(requests_mock):
    """
    Scenario: Get a single user.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_user_get is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_user_get_command
    mock_response = load_mock_response('user_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_user_get_command(client, name='b')
    assert result.outputs_prefix == 'SophosFirewall.User'
    assert result.outputs.get('Name') == 'unitest3'


def test_sophos_firewall_user_add_command(requests_mock):
    """
    Scenario: Add a new user.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_user_add is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_user_add_command
    mock_response = load_mock_response('user_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('user_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_user_add_command(client, {'name': 'b', 'username': 'shadowmuffin',
                                                       'password': 'xcd', 'email': 'a@b.c'})
    assert result.outputs_prefix == 'SophosFirewall.User'
    assert result.outputs.get('Name') == 'unitest3'


def test_sophos_firewall_user_update_command(requests_mock):
    """
    Scenario: Update an existing user.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_user_update is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_user_update_command
    mock_response = load_mock_response('user_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    mock_response = load_mock_response('user_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_user_update_command(client, {'name': 'b', 'username': 'shadowmuffin',
                                                          'password': 'xcd', 'email': 'a@b.c'})
    assert result.outputs_prefix == 'SophosFirewall.User'
    assert result.outputs.get('Name') == 'unitest3'


def test_sophos_firewall_user_delete_command(requests_mock):
    """
    Scenario: Delete an existing user.
    Given:
     - User has provided valid credentials.
    When:
     - sophos_firewall_user_delete is called.
    Then:
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """
    from sophos_firewall import Client, sophos_firewall_user_delete_command
    mock_response = load_mock_response('user_set.xml')
    requests_mock.post(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = sophos_firewall_user_delete_command(client, 'forunitest')
    assert result.outputs_prefix == 'SophosFirewall.User'
    assert result.outputs.get('Name') == 'forunitest'


def test_prepare_builder_params(requests_mock):
    """
    Scenario: Prepare list objects for builder
    Given:
     - User has provided valid credentials.
    When:
     - Before a builder is used.
    Then:
     - Ensure the correct item is returned from the function based on the arguemnts.
    """
    from sophos_firewall import Client, prepare_builder_params
    mock_response = load_mock_response('rule_get.xml')
    requests_mock.get(REQUEST_URL, text=mock_response)
    client = Client(base_url=BASE_URL, verify=False, auth=('uname', 'passwd'), proxy=False)
    result = prepare_builder_params(client, {'members': ['Identity', 'Member']}, True,
                                    'rule', 'SecurityPolicy', {'members': 'new'})
    assert result == {'members': ['new']}


def test_update_dict_from_params_using_path():
    """
    Scenario: Update dictionary from parameters using path.
    Given:
     - User has provided valid credentials.
    When:
     - A value is supposed to be added to a dictionary.
    Then:
     - Ensure the correct item is returned from the function based on the arguemnts.
    """
    from sophos_firewall import update_dict_from_params_using_path
    result = update_dict_from_params_using_path({'a': ['b', 'c']}, {'a': ['b', 'c']}, {'a': ['d']})
    assert result == {'a': ['d'], 'b': {'c': ['b', 'c']}}


def test_check_error_on_response():
    """
    Scenario: Check for any errors in a response.
    Given:
     - User has provided valid credentials.
    When:
     - A response is returned from the API
    Then:
     - Ensure the correct item is returned from the function based on the arguemnts.
    """
    from sophos_firewall import check_error_on_response
    good_result = json.loads(load_mock_response('rule_get.json'))
    check_error_on_response(good_result)
    bad_result = {'Status': 'No. of records Zero.'}
    with pytest.raises(Exception):
        check_error_on_response(bad_result)


def test_retrieve_dict_item_recursively():
    """
    Scenario: Recursively find an item in a dictionary.
    Given:
     - User has provided valid credentials.
    When:
     - Whenever an item needs to be found in a multi-level dictionary.
    Then:
     - Ensure the correct item is returned from the function based on the arguemnts.
    """
    from sophos_firewall import retrieve_dict_item_recursively
    result = retrieve_dict_item_recursively({'a': {'b': 'c'}}, 'b')
    assert result == 'c'
    result = retrieve_dict_item_recursively({'a': 'b'}, 'b')
    assert result is None
