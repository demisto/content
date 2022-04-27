import json
import demistomock as demisto
from CommonServerPython import *

'''MOCK PARAMETERS '''
CREDENTIALS = "credentials"
ACCOUNT_ID = "account_id"
ZONE_ID = "zone_id"

'''CONSTANTS'''
BASE_URL = 'https://api.cloudflare.com/client/v4'

def load_mock_response(file_name: str) -> str:
    """
    Load mock file that simulates an API response.
    Args:
        file_name (str): Name of the mock response JSON file to return.
    Returns:
        str: Mock file content.
    """
    with open(f'test_data/{file_name}', mode='r', encoding='utf-8') as mock_file:
        return mock_file.read()

def test_cloudflare_waf_firewall_rule_create_command(requests_mock):
    """
    Scenario: Add user to organization.
    Given:
     - User has provided valid credentials.
    When:
     - azure-devops-user-add called.
    Then:
     - Ensure number of items is correct.
     - Ensure outputs prefix is correct.
     - Ensure a sample value from the API matches what is generated in the context.
    """

    from CloudflareWAF import Client, cloudflare_waf_firewall_rule_create_command

    mock_response = json.loads(load_mock_response('create_firewall_rule.json'))
    url = f'{BASE_URL}/zones/{ZONE_ID}/firewall/rules'
    requests_mock.post(url=url, json=mock_response)

    client = Client(
        account_id=ACCOUNT_ID,
        zone_id=ZONE_ID,
        credentials=CREDENTIALS)

    action = 'allow'
    filter_expression = '(ip.src eq 135.8.79.13)'

    result = cloudflare_waf_firewall_rule_create_command(client, {'action': action, 'filter_expression': filter_expression})

    assert result.outputs_prefix == 'CloudflareWAF.FirewallRule'
    assert len(result.outputs) == 8
    assert result.outputs.get('id') == 'XXX'


