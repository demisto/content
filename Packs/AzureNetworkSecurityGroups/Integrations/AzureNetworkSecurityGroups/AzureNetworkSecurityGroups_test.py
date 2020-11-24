import json
import io
import pytest
import demistomock as demisto
from AzureNetworkSecurityGroups import Client


def mock_client(mocker, http_request_result=None):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = Client(
        self_deployed=True,
        refresh_token='refresh_token',
        auth_and_token_url='auth_id',
        redirect_uri='redirect_uri',
        enc_key='enc_key',
        auth_code='auth_code',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        workspace_name='workspaceName',
        verify=False,
        proxy=False
    )
    if http_request_result:
        mocker.patch.object(client, 'http_request', return_value=http_request_result)
    return client


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


def test_format_rule():
    """
    Given: rule data and rule name
    Then: Command outputs is returned as expected and flattens the `properties` field.

    """
    from AzureNetworkSecurityGroups import format_rule
    rule = util_load_json("test_data/get_rule_result.json")
    cr = format_rule(rule, "RuleName")
    assert cr.raw_response['name'] == 'wow'
    assert cr.raw_response['sourceAddressPrefix'] == '8.1.2.3'
    assert '### Rule RuleName' in cr.readable_output


def test_list_groups_command(mocker):
    from AzureNetworkSecurityGroups import list_groups_command
    client = mock_client(mocker, util_load_json("test_data/list_network_groups_result.json"))
    results = list_groups_command(client)
    assert '### Network Security Groups' in results.readable_output
    assert results.outputs[0].get('name') == 'alerts-nsg'


def test_create_rule_command(mocker):
    from AzureNetworkSecurityGroups import create_rule_command
    client = mock_client(mocker, util_load_json("test_data/list_network_groups_result.json"))
    result = create_rule_command(client, security_group_name='securityGroup', security_rule_name='test_rule',
                                 direction='Inbound', action='Allow', protocol='Any', source='Any',
                                  source_ports='900-1000', destination_ports='1,2,3,4-6')
    properties = client.http_request.call_args_list[0][1].get('data').get('properties')
    assert properties.get('protocol') == '*'
    assert properties.get('sourceAddressPrefix') == '*'
    assert 'sourcePortRanges' not in properties.keys()
    assert ['1', '2', '3', '4-6'] == properties.get('destinationPortRanges')


def test_list_rules_command(mocker):
    from AzureNetworkSecurityGroups import list_rules_command
    client = mock_client(mocker, util_load_json("test_data/list_rule_results.json"))
    result = list_rules_command(client, 'groupName')
    assert '### Rules in groupName' in result.readable_output
    assert result.outputs[0].get('name') == 'Port_8080'


def test_get_rule(mocker):
    from AzureNetworkSecurityGroups import get_rule_command
    client = mock_client(mocker, util_load_json("test_data/list_rule_results.json"))
    result = get_rule_command(client, 'groupName', 'Port_8080')
    assert '### Rule Port_8080' in result.readable_output
    assert result.outputs[0].get('name') == 'Port_8080'


def test_start_scan(requests_mock):
    """Tests helloworld-scan-start command function.

    Configures requests_mock instance to generate the appropriate start_scan
    API response when the correct start_scan API request is performed. Checks
    the output of the command function with the expected output.
    """
    from HelloWorld import Client, scan_start_command

    mock_response = {
        'scan_id': '7a161a3f-8d53-42de-80cd-92fb017c5a12',
        'status': 'RUNNING'
    }
    requests_mock.get('https://test.com/api/v1/start_scan?hostname=example.com', json=mock_response)

    client = Client(
        base_url='https://test.com/api/v1',
        verify=False,
        headers={
            'Authentication': 'Bearer some_api_key'
        }
    )

    args = {
        'hostname': 'example.com'
    }

    response = scan_start_command(client, args)

    assert response.outputs_prefix == 'HelloWorld.Scan'
    assert response.outputs_key_field == 'scan_id'
    assert response.outputs == {
        'scan_id': '7a161a3f-8d53-42de-80cd-92fb017c5a12',
        'status': 'RUNNING',
        'hostname': 'example.com'
    }
