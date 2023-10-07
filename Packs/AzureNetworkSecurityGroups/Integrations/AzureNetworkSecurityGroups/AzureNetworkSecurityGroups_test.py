import json
import io

import pytest

import demistomock as demisto
from AzureNetworkSecurityGroups import AzureNSGClient


def mock_client(mocker, http_request_result=None):
    mocker.patch.object(demisto, 'getIntegrationContext', return_value={'current_refresh_token': 'refresh_token'})
    client = AzureNSGClient(
        app_id='app_id',
        subscription_id='subscriptionID',
        resource_group_name='resourceGroupName',
        verify=False,
        proxy=False,
        connection_type='Device Code'
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
    assert cr.raw_response['sourceAddressPrefix'] == '3.2.3.2'
    assert '### Rules RuleName' in cr.readable_output


def test_list_groups_command(mocker):
    """
    Validate that list_groups_command returns the output in the correct format
    """
    from AzureNetworkSecurityGroups import list_groups_command
    client = mock_client(mocker, util_load_json("test_data/list_network_groups_result.json"))
    results = list_groups_command(client, args={}, params={'subscription_id': 'subscriptionID',
                                                           'resource_group_name': 'resourceGroupName'})
    assert '### Network Security Groups' in results.readable_output
    assert results.outputs[0].get('name') == 'alerts-nsg'


def test_create_rule_command(mocker):
    """
    Given: a rule to be created
    When: protocol is 'Allow', source ports are a range and destination ports are an array of ports
    Then: Validate protocol and source are converted to `*` and destination port is converted to list.
    """
    from AzureNetworkSecurityGroups import create_rule_command
    client = mock_client(mocker, util_load_json("test_data/list_network_groups_result.json"))
    create_rule_command(client, args={'security_group_name': 'securityGroup', 'security_rule_name': 'test_rule',
                        'direction': 'Inbound', 'action': 'Allow', 'protocol': 'Any', 'source': 'Any',
                                      'source_ports': '900-1000', 'destination_ports': '1,2,3,4-6'},
                        params={'subscription_id': 'subscriptionID',
                                'resource_group_name': 'resourceGroupName'})
    properties = client.http_request.call_args_list[0][1].get('data').get('properties')
    assert properties.get('protocol') == '*'
    assert properties.get('sourceAddressPrefix') == '*'
    assert 'sourcePortRanges' not in properties.keys()
    assert ['1', '2', '3', '4-6'] == properties.get('destinationPortRanges')


def test_update_rule_command(mocker):
    """
    Given: a rule to update
    When: destination ports are changed from one port to a list and protocol and source are any
    Then: Validate `destinationPortRange` `sourcePortRanges` are not a keys in the passed properties dict and
        `destinationPortRanges`, `sourcePortRange` are keys. Also check that source and protocol are changed to `*` as
        they are general

    """
    from AzureNetworkSecurityGroups import update_rule_command
    client = mock_client(mocker, util_load_json("test_data/get_rule_result.json"))
    update_rule_command(client, args={'security_group_name': 'securityGroup', 'security_rule_name': 'wow', 'direction': 'Inbound',
                        'action': 'Allow', 'protocol': 'Any', 'source': 'Any', 'source_ports': '900-1000',
                                      'destination_ports': '1,2,3,4-6'}, params={'subscription_id': 'subscriptionID',
                                                                                 'resource_group_name': 'resourceGroupName'})
    properties = client.http_request.call_args_list[1][1].get('data').get('properties')
    assert 'destinationPortRange' not in properties.keys()
    assert 'destinationPortRanges' in properties.keys()
    assert 'sourcePortRanges' not in properties.keys()
    assert 'sourcePortRange' in properties.keys()
    assert properties.get('protocol') == properties.get('sourceAddressPrefix') == '*'


def test_list_rules_command(mocker):
    """
    Validate that list_rules_command returns the output in the correct format
    """
    from AzureNetworkSecurityGroups import list_rules_command
    client = mock_client(mocker, util_load_json("test_data/list_rule_results.json"))
    result = list_rules_command(client, args={'security_group_name': 'groupName'},
                                params={'subscription_id': 'subscriptionID',
                                        'resource_group_name': 'resourceGroupName'})
    assert '### Rules in groupName' in result.readable_output
    assert result.outputs[0].get('name') == 'Port_8080'


def test_get_rule(mocker):
    """
    Validate that get_rule_command returns the output in the correct format
    """
    from AzureNetworkSecurityGroups import get_rule_command
    client = mock_client(mocker, util_load_json("test_data/get_rule_result.json"))
    result = get_rule_command(client,
                              args={'security_group_name': 'groupName', 'security_rule_name': 'wow'},
                              params={'subscription_id': 'subscriptionID',
                                      'resource_group_name': 'resourceGroupName'})
    assert '### Rules wow' in result.readable_output
    assert result.outputs[0].get('name') == 'wow'


@pytest.mark.parametrize(argnames='client_id', argvalues=['test_client_id', None])
def test_test_module_command_with_managed_identities(mocker, requests_mock, client_id):
    """
    Scenario: run test module when managed identities client id provided.
    Given:
     - User has provided managed identities client oid.
    When:
     - test-module called.
    Then:
     - Ensure the output are as expected
    """
    from AzureNetworkSecurityGroups import main, MANAGED_IDENTITIES_TOKEN_URL, Resources
    import AzureNetworkSecurityGroups

    mock_token = {'access_token': 'test_token', 'expires_in': '86400'}
    get_mock = requests_mock.get(MANAGED_IDENTITIES_TOKEN_URL, json=mock_token)
    params = {
        'managed_identities_client_id': {'password': client_id},
        'auth_type': 'Azure Managed Identities',
        'subscription_id': {'password': 'test'},
        'resource_group': 'test_resource_group'
    }
    mocker.patch.object(demisto, 'params', return_value=params)
    mocker.patch.object(demisto, 'command', return_value='test-module')
    mocker.patch.object(AzureNetworkSecurityGroups, 'return_results')
    mocker.patch('MicrosoftApiModule.get_integration_context', return_value={})

    main()

    assert 'ok' in AzureNetworkSecurityGroups.return_results.call_args[0][0]
    qs = get_mock.last_request.qs
    assert qs['resource'] == [Resources.management_azure]
    assert client_id and qs['client_id'] == [client_id] or 'client_id' not in qs


def test_generate_login_url(mocker):
    """
    Given:
        - Self-deployed are true and auth code are the auth flow
    When:
        - Calling function azure-nsg-generate-login-url
    Then:
        - Ensure the generated url are as expected.
    """
    # prepare
    import demistomock as demisto
    from AzureNetworkSecurityGroups import main
    import AzureNetworkSecurityGroups

    redirect_uri = 'redirect_uri'
    tenant_id = 'tenant_id'
    client_id = 'client_id'
    mocked_params = {
        'redirect_uri': redirect_uri,
        'auth_type': 'Authorization Code',
        'tenant_id': tenant_id,
        'app_id': client_id,
        'credentials': {
            'password': 'client_secret'
        }
    }
    mocker.patch.object(demisto, 'params', return_value=mocked_params)
    mocker.patch.object(demisto, 'command', return_value='azure-nsg-generate-login-url')
    mocker.patch.object(AzureNetworkSecurityGroups, 'return_results')

    # call
    main()

    # assert
    expected_url = f'[login URL](https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?' \
                   'response_type=code&scope=offline_access%20https://management.azure.com/.default' \
                   f'&client_id={client_id}&redirect_uri={redirect_uri})'
    res = AzureNetworkSecurityGroups.return_results.call_args[0][0].readable_output
    assert expected_url in res
