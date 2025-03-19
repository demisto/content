import json
import os
import pytest
from CloudflareWAF import Client


'''MOCK PARAMETERS '''
CREDENTIALS = "credentials"
ACCOUNT_ID = "account_id"
ZONE_ID = "zone_id"

'''CONSTANTS'''
BASE_URL = 'https://api.cloudflare.com/client/v4/'


def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """

    with open(os.path.join('test_data', file_name), encoding='utf-8') as mock_file:
        return json.loads(mock_file.read())


@pytest.fixture(autouse=True)
def mock_client():
    return Client(account_id=ACCOUNT_ID,
                  zone_id=ZONE_ID,
                  credentials=CREDENTIALS,
                  base_url=BASE_URL,
                  proxy=False,
                  insecure=True)


def test_cloudflare_waf_firewall_rule_create_command(requests_mock, mock_client):
    """
    Scenario: Create firewall rule.
    Given:
     - User has provided valid credentials.
     - Firewall rule action and expression.
    When:
     - cloudflare-waf-firewall-rule-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_create_command

    mock_response = load_mock_response('create_firewall_rule.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/firewall/rules'
    requests_mock.post(url=url, json=mock_response)

    action = 'allow'
    filter_expression = 'filter_expression'

    result = cloudflare_waf_firewall_rule_create_command(
        mock_client, {'action': action, 'filter_expression': filter_expression})

    assert result.outputs_prefix == 'CloudflareWAF.FirewallRule'
    assert len(result.outputs[0]) == 8
    assert result.outputs[0]['id'] == 'firewall_rule_id'


def test_cloudflare_waf_firewall_rule_update_command(requests_mock, mock_client):
    """
    Scenario: Update firewall rule.
    Given:
     - User has provided valid credentials.
     - Firewall rule ID, action and filter ID.
    When:
     - cloudflare-waf-firewall-rule-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_update_command

    mock_response = load_mock_response('create_firewall_rule.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/firewall/rules'
    requests_mock.put(url=url, json=mock_response)

    result = cloudflare_waf_firewall_rule_update_command(
        mock_client, {'id': 'rule_id', 'action': 'action', 'filter_id': 'filter_id'})

    assert result.outputs_prefix == 'CloudflareWAF.FirewallRule'
    assert len(result.outputs[0]) == 8
    assert result.outputs[0]['id'] == 'firewall_rule_id'


def test_cloudflare_waf_firewall_rule_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete firewall rule.
    Given:
     - User has provided valid credentials.
     - Firewall rule ID.
    When:
     - cloudflare-waf-firewall-rule-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure raw response is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_delete_command

    mock_response = load_mock_response('delete_firewall_rule.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/firewall/rules'
    requests_mock.delete(url=url, json=mock_response)

    rule_id = 'rule_id'

    result = cloudflare_waf_firewall_rule_delete_command(
        mock_client, {'id': rule_id})

    assert len(result.raw_response) == 4
    assert result.raw_response['success'] is True
    assert result.raw_response['result'][0]['id'] == 'firewall_rule_id'


def test_cloudflare_waf_firewall_rule_list_command(requests_mock, mock_client):
    """
    Scenario: List firewall rule.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-firewall-rule-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_firewall_rule_list_command

    mock_response = load_mock_response('list_firewall_rule.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/firewall/rules'
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_firewall_rule_list_command(mock_client, {'page': 1, 'page_size': 5})

    assert result.outputs_prefix == 'CloudflareWAF.FirewallRule'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'firewall_rule_id_1'


def test_cloudflare_waf_zone_list_command(requests_mock, mock_client):
    """
    Scenario: List zones.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-zone-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_zone_list_command

    mock_response = load_mock_response('list_zone.json')
    url = f'{BASE_URL}zones'
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_zone_list_command(mock_client, {'page': 1, 'page_size': 5})

    assert result.outputs_prefix == 'CloudflareWAF.Zone'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'zone_id_1'


def test_cloudflare_waf_filter_create_command(requests_mock, mock_client):
    """
    Scenario: Create filter.
    Given:
     - User has provided valid credentials.
     - Filter expression.
    When:
     - cloudflare-waf-filter-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_create_command

    mock_response = load_mock_response('create_filter.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/filters'
    requests_mock.post(url=url, json=mock_response)

    filter_expression = 'filter_expression'

    result = cloudflare_waf_filter_create_command(
        mock_client, {'expression': filter_expression})

    assert result.outputs_prefix == 'CloudflareWAF.Filter'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'filter_id'


def test_cloudflare_waf_filter_update_command(requests_mock, mock_client):
    """
    Scenario: Update filter.
    Given:
     - User has provided valid credentials.
     - Filter expression.
    When:
     - cloudflare-waf-filter-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_update_command

    mock_response = load_mock_response('create_filter.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/filters'
    requests_mock.put(url=url, json=mock_response)

    filter_expression = 'filter_expression'
    filter_id = 'filter_id'

    result = cloudflare_waf_filter_update_command(
        mock_client, {'id': filter_id, 'expression': filter_expression})

    assert result.outputs_prefix == 'CloudflareWAF.Filter'
    assert len(result.outputs) == 1
    assert result.outputs[0]['id'] == 'filter_id'


def test_cloudflare_waf_filter_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete filter.
    Given:
     - User has provided valid credentials.
     - Filter expression.
    When:
     - cloudflare-waf-filter-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_delete_command

    mock_response = load_mock_response('create_filter.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/filters'
    requests_mock.delete(url=url, json=mock_response)

    filter_id = 'filter_id'

    result = cloudflare_waf_filter_delete_command(mock_client, {'filter_id': filter_id})

    assert len(result.raw_response) == 4
    assert result.raw_response['result'][0]['id'] == 'filter_id'


def test_cloudflare_waf_filter_list_command(requests_mock, mock_client):
    """
    Scenario: List filters.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-filter-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_filter_list_command

    mock_response = load_mock_response('list_filter.json')
    url = f'{BASE_URL}zones/{ZONE_ID}/filters'
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_filter_list_command(mock_client, {'limit': 5})

    assert result.outputs_prefix == 'CloudflareWAF.Filter'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'filter_id_1'


def test_cloudflare_waf_ip_list_create_command(requests_mock, mock_client):
    """
    Scenario: Create ip list.
    Given:
     - User has provided valid credentials.
     - IP list name.
    When:
     - cloudflare-waf-ip-list-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_create_command

    mock_response = load_mock_response('create_ip_list.json')

    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists'
    requests_mock.post(url=url, json=mock_response)

    name = 'list_name'

    result = cloudflare_waf_ip_list_create_command(
        mock_client, {'name': name})

    assert result.outputs_prefix == 'CloudflareWAF.IpList'
    assert len(result.outputs) == 7
    assert result.outputs['id'] == 'list_id'
    assert result.outputs['name'] == 'list_name'


def test_cloudflare_waf_ip_list_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete ip list.
    Given:
     - User has provided valid credentials.
     - IP list name.
    When:
     - cloudflare-waf-ip-list-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_delete_command

    mock_response = load_mock_response('delete_ip_list.json')

    list_id = 'list_id'

    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}'
    requests_mock.delete(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_delete_command(
        mock_client, {'id': list_id})

    assert len(result.raw_response) == 4
    assert result.raw_response['result']['id'] == 'list_id'


def test_cloudflare_waf_ip_lists_list_command(requests_mock, mock_client):
    """
    Scenario: List filters.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-filter-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_lists_list_command

    mock_response = load_mock_response('lists_ip_list.json')
    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists'
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ip_lists_list_command(
        mock_client, {'page': 1, 'page_size': 5})

    assert result.outputs_prefix == 'CloudflareWAF.IpList'
    assert len(result.outputs) == 2
    assert result.outputs[0]['id'] == 'list_id_1'


def test_cloudflare_waf_ip_list_item_list_command(requests_mock, mock_client):
    """
    Scenario: List filters.
    Given:
     - User has provided valid credentials.
    When:
     - cloudflare-waf-filter-list called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_list_command

    mock_response = load_mock_response('ip_list_item_list.json')
    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/123/items'
    requests_mock.get(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_list_command(
        mock_client, {'page': 1, 'page_size': 5, 'list_id': '123', 'item_ip': 'ip1'})

    assert result.outputs_prefix == 'CloudflareWAF.IpListItem'
    assert result.outputs['list_id'] == '123'


def test_cloudflare_waf_ip_list_item_create_command(requests_mock, mock_client):
    """
    Scenario: Create ip list items.
    Given:
     - User has provided valid credentials.
     - IP list ID.
     - Items.
    When:
     - cloudflare-waf-ip-list-item-create called.
    Then:
     - Ensure number of items is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_create_command

    mock_response = load_mock_response('ip_list_item.json')

    list_id = 'list_id'
    items = '120.2.2.8'

    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}/items'

    requests_mock.post(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_create_command(mock_client, {'list_id': list_id, 'items': items})

    assert result.raw_response['operation_id'] == 'operation_id'


def test_cloudflare_waf_ip_list_item_update_command(requests_mock, mock_client):
    """
    Scenario: Replace ip list items.
    Given:
     - User has provided valid credentials.
     - IP list ID.
     - Items.
    When:
     - cloudflare-waf-ip-list-item-update called.
    Then:
     - Ensure number of items is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_update_command

    mock_response = load_mock_response('ip_list_item.json')

    list_id = 'list_id'
    items = '120.2.2.8'

    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}/items'

    requests_mock.put(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_update_command(mock_client, {'list_id': list_id, 'items': items})

    assert result.raw_response['operation_id'] == 'operation_id'


def test_cloudflare_waf_ip_list_item_delete_command(requests_mock, mock_client):
    """
    Scenario: Delete items from ip list.
    Given:
     - User has provided valid credentials.
     - IP list ID.
     - Items ID.
    When:
     - cloudflare-waf-ip-list-item-delete called.
    Then:
     - Ensure number of items is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import cloudflare_waf_ip_list_item_delete_command

    mock_response = load_mock_response('ip_list_item.json')

    list_id = 'list_id'
    items = 'item_id'

    url = f'{BASE_URL}accounts/{ACCOUNT_ID}/rules/lists/{list_id}/items'

    requests_mock.delete(url=url, json=mock_response)

    result = cloudflare_waf_ip_list_item_delete_command(mock_client, {'list_id': list_id, 'items': items})

    assert result.raw_response['operation_id'] == 'operation_id'
