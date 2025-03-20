import json

import pytest

import demistomock as demisto
from AzureNetworkSecurityGroups import AzureNSGClient

AUTHORIZATION_CODE = 'Authorization Code'
CLIENT_CREDENTIALS_FLOW = 'Client Credentials'
SNAKED_CASE_AUTHORIZATION_CODE = 'authorization_code'
SNAKED_CASE_CLIENT_CREDENTIALS_FLOW = 'client_credentials'


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
    with open(path, encoding='utf-8') as f:
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


def test_azure_nsg_public_ip_addresses_list(mocker):
    """
    Given:
        - subscription_id and resource_group_name
    When:
        - Calling function azure_nsg_public_ip_addresses_list
    Then:
        - Ensure the generated output is as expected.
    """
    from AzureNetworkSecurityGroups import azure_nsg_public_ip_addresses_list_command
    client = mock_client(mocker)
    http_mock_request = mocker.patch.object(client, 'http_request',
                                            return_value=util_load_json('test_data/list_public_ip_addresses.json'))
    results = azure_nsg_public_ip_addresses_list_command(client, args={}, params={'subscription_id': 'subscriptionID',
                                                                                  'resource_group_name': 'resourceGroupName'})
    http_mock_request.assert_called_with('GET', full_url='https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/publicIPAddresses',
                                         params={'api-version': '2024-05-01'})
    assert '### Public IP Addresses List' in results.readable_output
    res = results.outputs[0]
    assert res.get('name') == 'testDNS-ip'
    assert res.get('id') == '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/testDNS-ip'
    assert res.get('etag') == 'etag'
    assert res.get('provisioningState') == 'Succeeded'
    assert res.get('publicIPAddressVersion') == 'IPv4'
    assert res.get('ipAddress') == '1.1.1.1'
    assert res.get('domainNameLabel') == 'testlbl'
    assert res.get('fqdn') == 'testlbl.westus.cloudapp.azure.com'


def test_azure_nsg_virtual_networks_list(mocker):
    """
    Given:
        - subscription_id and resource_group_name
    When:
        - Calling function azure_nsg_virtual_networks_list
    Then:
        - Ensure the generated output is as expected.
    """
    from AzureNetworkSecurityGroups import azure_nsg_virtual_networks_list_command
    client = mock_client(mocker)
    http_mock_request = mocker.patch.object(client, 'http_request',
                                            return_value=util_load_json('test_data/list_virtual_networks.json'))
    results = azure_nsg_virtual_networks_list_command(client, args={}, params={'subscription_id': 'subscriptionID',
                                                                               'resource_group_name': 'resourceGroupName'})
    http_mock_request.assert_called_with('GET', full_url='https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/virtualNetworks',
                                         params={'api-version': '2024-05-01'})

    assert '### Virtual Networks List' in results.readable_output
    res = results.outputs[0]
    assert res.get('name') == 'vnet1'
    assert res.get('etag') == 'etag'
    assert res.get('location') == 'westus'
    assert res.get('addressPrefixes') == ["10.0.0.0/8"]
    assert res.get('subnetName') == ['test-1']
    assert res.get('subnetAdrdressPrefix') == ['10.0.0.0/24']
    assert res.get('subnetID') == ["/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/\
networkInterfaces/testDNS649/ipConfigurations/ipconfig1"]


def test_azure_nsg_networks_interfaces_list(mocker):
    """
    Given:
        - subscription_id and resource_group_name
    When:
        - Calling function azure_nsg_networks_interfaces_list
    Then:
        - Ensure the generated output is as expected.
    """

    client = mock_client(mocker)
    from AzureNetworkSecurityGroups import azure_nsg_networks_interfaces_list_command
    client = mock_client(mocker)
    http_mock_request = mocker.patch.object(client, 'http_request',
                                            return_value=util_load_json('test_data/list_networks_interfaces.json'))
    results = azure_nsg_networks_interfaces_list_command(client, args={}, params={'subscription_id': 'subscriptionID',
                                                                                  'resource_group_name': 'resourceGroupName'})
    http_mock_request.assert_called_with('GET', full_url='https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/networkInterfaces',
                                         params={'api-version': '2024-05-01'})
    assert '### Network Interfaces List' in results.readable_output
    res = results.outputs[0]
    assert res.get('name') == 'test-nic'
    assert res.get('id') == '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic'
    assert res.get('provisioningState') == 'Succeeded'
    assert res.get('ipConfigurationName') == ["ipconfig1"]
    assert res.get('ipConfigurationID') == [
        '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic/ipConfigurations/ipconfig1']
    assert res.get('ipConfigurationPrivateIPAddress') == ['1.1.1.1']
    assert res.get('ipConfigurationPublicIPAddressName') == [
        '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/test-ip']
    assert res.get('dnsServers') == []
    assert res.get('appliedDnsServers') == []
    assert res.get('internalDomainNameSuffix') == 'test.bx.internal.cloudapp.net'
    assert res.get('macAddress') == '00-0D-3A-1B-C7-21'
    assert res.get('virtualMachineId') == '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Compute/\
virtualMachines/vm1'
    assert res.get('location') == 'eastus'
    assert res.get('kind') == 'kind'


def test_create_azure_nsg_security_group(mocker):
    """
    Given:
        - a security group to be created, subscription_id and resource_group_name
    When:
        - Calling function azure_nsg_security_group_create
    Then:
        - Ensure the request sent as requested and the generated output is as expected.
    """
    from AzureNetworkSecurityGroups import azure_nsg_security_group_create_command
    client = mock_client(mocker)
    http_mock_request = mocker.patch.object(client, 'http_request', return_value=util_load_json('test_data/put_data.json'))
    res = azure_nsg_security_group_create_command(client, args={'security_group_name': 'securityGroup', 'location': 'westus'},
                                                  params={'subscription_id': 'subscriptionID', 'resource_group_name':
                                                  'resourceGroupName'})
    http_mock_request.assert_called_with('PUT', full_url='https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/networkSecurityGroups/securityGroup',
                                         params={'api-version': '2024-05-01'}, data={'location': 'westus'})
    assert '### Security Group' in res.readable_output
    res = res.outputs
    assert res.get('name') == 'test-nic'
    assert res.get('etag') == 'etag'
    assert res.get('location') == 'eastus'
    assert res.get('securityRules') == []


def test_create_azure_nsg_network_interfaces(mocker):
    """
    Given:
        - a network interface (nic_name) to be created, subscription_id, resource_group_name, location,
        ip_config_name, vnet_name and subnet_name
    When:
        - Calling function azure_nsg_network_interfaces_create
    Then:
        - Ensure the request sent as requested and the generated output is as expected.
    """
    from AzureNetworkSecurityGroups import azure_nsg_network_interfaces_create_command
    client = mock_client(mocker)
    http_mock_request = mocker.patch.object(client, 'http_request', return_value=util_load_json('test_data/put_data.json'))
    res = azure_nsg_network_interfaces_create_command(client, args={'nic_name': 'nic_name', 'location': 'westus',
                                                                    'ip_config_name': 'ip_config_name', 'vnet_name': 'vnet_name',
                                                                    'subnet_name': 'subnet_name'},
                                                      params={'subscription_id': 'subscriptionID', 'resource_group_name':
                                                      'resourceGroupName'})
    data = {
        'location': 'westus',
        'properties': {
            'ipConfigurations': [
                {
                    'name': 'ip_config_name',
                    'properties': {
                        'subnet': {
                            'id': '/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network'
                            '/virtualNetworks/vnet_name/subnets/subnet_name'
                        }
                    }
                }
            ]
        }
    }
    http_mock_request.assert_called_with('PUT', full_url='https://management.azure.com/subscriptions/subscriptionID/resourceGroups/resourceGroupName/providers/Microsoft.Network/networkInterfaces/nic_name',
                                         params={'api-version': '2024-05-01'}, data=data)

    assert '### Network Interface' in res.readable_output
    res = res.outputs
    assert res.get('name') == 'test-nic'
    assert res.get('etag') == 'etag'
    assert res.get('provisioningState') == 'Succeeded'
    assert res.get('ipConfigurationName') == ['ipconfig1']
    assert res.get('ipConfigurationPrivateIPAddress') == ['1.1.1.1']
    assert res.get('ipConfigurationPublicIPAddressName') == [
        '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/test-ip']
    assert res.get('subnetId') == [
        '/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/rg1-vnet/subnets/default']


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
    assert properties.get('destinationPortRanges') == ['1', '2', '3', '4-6']


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
    assert 'destinationPortRanges' in properties
    assert 'sourcePortRanges' not in properties.keys()
    assert 'sourcePortRange' in properties
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


def test_auth_code_params(mocker):
    """
    Given:
        - The auth_type is Authorization Code
    When:
        - Creating a Microsoft client.
    Then:
        - Ensure that the token_retrieval_url isn't in the MicrosoftClient args.
    """
    from AzureNetworkSecurityGroups import main
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
    mocker.patch.object(demisto, 'command', return_value='command')
    mocked_request = mocker.patch('AzureNetworkSecurityGroups.MicrosoftClient.__init__', return_value=None)
    expected_args = {
        'self_deployed': True,
        'auth_id': 'client_id',
        'grant_type': 'authorization_code',
        'base_url': 'https://management.azure.com/subscriptions//resourceGroups//providers/Microsoft.Network/'
                    'networkSecurityGroups',
        'verify': True,
        'proxy': False,
        'scope': 'https://management.azure.com/.default',
        'ok_codes': (200, 201, 202, 204),
        'azure_ad_endpoint': 'https://login.microsoftonline.com',
        'tenant_id': 'tenant_id',
        'enc_key': 'client_secret',
        'redirect_uri': 'redirect_uri',
        'managed_identities_resource_uri': 'https://management.azure.com/',
        'command_prefix': 'azure-nsg'}

    main()

    mocked_request.assert_called_with(**expected_args)


''' HELPER FUNCTIONS TESTS '''


def test_reformat_data():
    """
   Given:
        - data
    When:
        - Calling function reformat_data
    Then:
        - Ensure the reformat_data is as expected.
    """
    from AzureNetworkSecurityGroups import reformat_data
    data = {
        'a': 'b',
        'c': {
            'd': 'e',
            'f': 'g',
            'k': [{'1': '11', '2': '12'}, {'1': '13', '2': '14'}]
        }
    }

    excepted_data = {
        'a': 'b',
        'c': {
            'd': 'e',
            'f': 'g',
            'k': [{'1': '11', '2': '12'}, {'1': '13', '2': '14'}]
        },
        'k': [{'1': '11', '2': '12'}, {'1': '13', '2': '14'}],
        'd': 'e',
        'f': 'g',
        'new': ['11', '13']
    }
    reformat_data(data, dict_to_extract=[('c',)], list_to_extract=[('k', '1', 'new')])
    assert data == excepted_data
