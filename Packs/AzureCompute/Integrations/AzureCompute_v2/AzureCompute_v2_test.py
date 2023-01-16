import pytest
import json

from AzureCompute_v2 import MsGraphClient, screen_errors, assign_image_attributes, list_vms_command,\
    create_vm_parameters, get_network_interface_command, get_public_ip_details_command,\
    get_all_public_ip_details_command, create_nic_command, get_single_ip_details_from_list_of_ip_details

# test_create_vm_parameters data:
CREATE_VM_PARAMS_ARGS = {"resource_group": "compute-integration",
                         "nic_name": "test-compute-integration-nic",
                         "virtual_machine_location": "westeurope",
                         "vm_size": "Standard_D1_v2",
                         "virtual_machine_name": "TestVM",
                         "os_image": "Ubuntu Server 18.04 LTS",
                         "admin_username": 'Admin',
                         'admin_password': 'password'}
Expected_VM_PARAMS = {
    'location': 'westeurope',
    'properties': {
        'hardwareProfile': {
            'vmSize': 'Standard_D1_v2'
        },
        'storageProfile': {
            'imageReference': {
                'sku': '18.04-LTS',
                'publisher': 'Canonical',
                'version': 'latest',
                'offer': 'UbuntuServer'
            },
            'osDisk': {
                'caching': 'ReadWrite',
                'managedDisk': {
                    'storageAccountType': 'Standard_LRS'
                },
                'name': 'TestVM',
                'createOption': 'FromImage'
            }
        },
        'osProfile': {
            'adminUsername': 'Admin',
            'computerName': 'TestVM',
            'adminPassword': 'password'
        },
        'networkProfile': {
            'networkInterfaces': [
                {
                    'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers'
                          '/Microsoft.Network/networkInterfaces/test-compute-integration-nic',
                    'properties': {
                        'primary': 'true'
                    }
                }
            ]
        }
    },
    'name': 'TestVM'
}

''' HELPER FUNCTIONS '''


def load_test_data(json_path):
    with open(json_path) as f:
        return json.load(f)

# test_list_vms data:


VM_LIST_EC = {'Azure.Compute(val.Name && val.Name === obj.Name)': [
    {'Name': 'testvm', 'ID': 'vm_id', 'Size': 30, 'OS': 'Linux', 'Location': 'westeurope',
     'ProvisioningState': 'Succeeded', 'ResourceGroup': 'resource_group'},
    {'Name': 'vm2_name', 'ID': 'vm2_id', 'Size': 32, 'OS': 'Linux', 'Location': 'westeurope',
     'ProvisioningState': 'Succeeded', 'ResourceGroup': 'resource_group'}]}

INTERFACE_EC = {
    'Azure.Network.Interfaces(val.ID === obj.ID)':
        {
            'Name': 'nic_name',
            'ID': 'nic_id',
            'MACAddress': '00-22-48-1C-73-AF',
            'NetworkSecurityGroup': {'id': 'security_group_id'},
            'IsPrimaryInterface': 'true',
            'Location': 'eastus',
            'AttachedVirtualMachine': 'vm_id',
            'ResourceGroup': 'resource_group',
            'NICType': 'Standard',
            'DNSSuffix': None,
            'IPConfigurations': [{
                'ConfigName': 'ipconfig1',
                'ConfigID': 'nic_id',
                'PrivateIPAddress': '10.0.0.4',
                'PublicIPAddressID': None
            }]
        }
}

PUBLIC_IP_EC = {
    'Azure.Network.IPConfigurations(val.PublicIPAddressID === obj.PublicIPAddressID)':
        {
            'PublicIPAddressID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/publicIPAddresses/webserver-ip',  # noqa: E501
            'PublicConfigName': 'webserver-ip',
            'Location': 'eastus',
            'PublicConfigID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/networkInterfaces/fake-network-interface-name-z1/ipConfigurations/ipconfig1',  # noqa: E501
            'ResourceGroup': 'fake-resource-group',
            'PublicIPAddress': '1.1.1.1',
            'PublicIPAddressVersion': 'IPv4',
            'PublicIPAddressAllocationMethod': 'Static',
            'PublicIPAddressDomainName': 'tesdomain',
            'PublicIPAddressFQDN': 'webserver.eastus.cloudapp.azure.com',
        }
}

PUBLIC_IP_DETAILS_LIST_ENTRY_EC = {
    "name": "webserver-ip",
    "id": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/publicIPAddresses/webserver-ip",  # noqa: E501
    "etag": "tag",
    "location": "eastus",
    "properties": {
        "provisioningState": "Succeeded",
        "resourceGuid": "ip_id",
        "ipAddress": "1.1.1.1",
        "publicIPAddressVersion": "IPv4",
        "publicIPAllocationMethod": "Static",
        "idleTimeoutInMinutes": 4,
        "dnsSettings": {
            "domainNameLabel": "tesdomain",
            "fqdn": "webserver.eastus.cloudapp.azure.com"
        },
        "ipTags": [],
        "ipConfiguration": {
            "id": "/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/networkInterfaces/fake-network-interface-name-z1/ipConfigurations/ipconfig1"  # noqa: E501
        }
    },
    "type": "Microsoft.Network/publicIPAddresses",
    "sku": {
        "name": "Basic",
        "tier": "Regional"
    }
}

MANY_PUBLIC_IP_EC = {
    'Azure.Network.IPConfigurations(val.PublicIPAddressID === obj.PublicIPAddressID)':
        [{
            'PublicIPAddressID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/publicIPAddresses/webserver-ip',  # noqa: E501
            'PublicConfigName': 'webserver-ip',
            'Location': 'eastus',
            'PublicConfigID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/networkInterfaces/fake-network-interface-name-z1/ipConfigurations/ipconfig1',  # noqa: E501
            'ResourceGroup': 'fake-resource-group',
            'PublicIPAddress': '1.1.1.1',
            'PublicIPAddressVersion': 'IPv4',
            'PublicIPAddressAllocationMethod': 'Static',
            'PublicIPAddressDomainName': 'tesdomain',
            'PublicIPAddressFQDN': 'webserver.eastus.cloudapp.azure.com',
        }, {
            'PublicIPAddressID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/publicIPAddresses/webserver-ip2',  # noqa: E501
            'PublicConfigName': 'webserver-ip2',
            'Location': 'eastus',
            'PublicConfigID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group/providers/Microsoft.Network/networkInterfaces/fake-network-interface-2-z1/ipConfigurations/ipconfig2',  # noqa: E501
            'ResourceGroup': 'fake-resource-group',
            'PublicIPAddress': '1.1.1.2',
            'PublicIPAddressVersion': 'IPv4',
            'PublicIPAddressAllocationMethod': 'Static',
            'PublicIPAddressDomainName': 'tesdomain',
            'PublicIPAddressFQDN': 'webserver.eastus.cloudapp.azure.com',
        }, {
            'PublicIPAddressID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group2/providers/Microsoft.Network/publicIPAddresses/webserver-ip3',  # noqa: E501
            'PublicConfigName': 'webserver-ip3',
            'Location': 'eastus',
            'PublicConfigID': '/subscriptions/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/resourceGroups/fake-resource-group2/providers/Microsoft.Network/networkInterfaces/fake-network-interface-3-z1/ipConfigurations/ipconfig3',  # noqa: E501
            'ResourceGroup': 'fake-resource-group2',
            'PublicIPAddress': '1.1.1.3',
            'PublicIPAddressVersion': 'IPv4',
            'PublicIPAddressAllocationMethod': 'Static',
            'PublicIPAddressDomainName': 'tesdomain',
            'PublicIPAddressFQDN': 'webserver.eastus.cloudapp.azure.com',
        }]
}

CREATE_NIC_EC = {
    'Azure.Network.Interfaces(val.ID && val.Name === obj.ID)':
        {
            'Name': 'test-nic100',
            'ID': 'nic_id',
            'IPConfigurations': [{'ConfigName': 'ipconfig1', 'ConfigID': 'nic_id', 'PrivateIPAddress': '10.0.0.5',
                                  'PublicIPAddressID': 'NA', 'SubNet': 'subnet_id'}],
            'ProvisioningState': 'Succeeded',
            'Location': 'eastus',
            'ResourceGroup': 'resource_group',
            'NetworkSecurityGroup': 'security_group_id',
            'DNSSuffix': 'test.bx.internal.cloudapp.net'
        }
}

client = MsGraphClient(
    base_url="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", ok_codes=(1, 2), server="server", subscription_id="subscription_id",
    certificate_thumbprint='', private_key='')


@pytest.mark.parametrize(
    'error_message, tenant, expected_error_message',
    [("Error Message tenant_id", "tenant_id", "Error Message <xxxxxxxxx>")]
)
def test_screen_errors(error_message, tenant, expected_error_message):
    assert expected_error_message == screen_errors(error_message, tenant)


@pytest.mark.parametrize(
    'image, expected',
    [('Ubuntu Server 18.04 LTS', ('18.04-LTS', 'Canonical', 'UbuntuServer', 'latest')),
     pytest.param("macOS Catalina", '', marks=pytest.mark.xfail)]
)
def test_assign_image_attributes(image, expected):
    assert expected == assign_image_attributes(image)


@pytest.mark.parametrize(
    'args, expected_parameters', [
        (CREATE_VM_PARAMS_ARGS, Expected_VM_PARAMS)
    ]
)
def test_create_vm_parameters(args, expected_parameters):
    assert expected_parameters == create_vm_parameters(args, client.subscription_id)


def test_list_vms_command(mocker):
    vms_data = load_test_data('./test_data/list_vms_command.json')
    mocker.patch.object(client, 'list_vms', return_value=vms_data)
    _, ec, _ = list_vms_command(client, {'resource_group': 'resource_group'})
    assert VM_LIST_EC == ec


def test_get_network_interface_command(mocker):
    interface_data = load_test_data('./test_data/get_network_interface_command.json')
    mocker.patch.object(client, 'get_network_interface', return_value=interface_data)
    _, ec, _ = get_network_interface_command(client, {'resource_group': 'resource_group', 'nic_name': 'nic_name'})
    assert INTERFACE_EC == ec


def test_get_public_ip_details_command(mocker):
    ip_data = load_test_data('./test_data/get_public_ip_details_command.json')
    mocker.patch.object(client, 'get_public_ip_details', return_value=ip_data)
    _, ec, _ = get_public_ip_details_command(client, {'resource_group': 'fake-resource-group', 'address_name': 'webserver-ip'})
    assert PUBLIC_IP_EC == ec


def test_get_public_ip_details_command_without_resource_group(mocker):
    ip_data = load_test_data('./test_data/get_public_ip_details_command_multiple_ips.json')
    mocker.patch.object(client, 'get_all_public_ip_details', return_value=ip_data)
    _, ec, _ = get_public_ip_details_command(client, {'address_name': '1.1.1.1'})
    assert PUBLIC_IP_EC == ec


def test_failure_get_public_ip_details_command_without_resource_group(mocker):
    ip_data = load_test_data('./test_data/get_public_ip_details_command_multiple_ips.json')
    mocker.patch.object(client, 'get_all_public_ip_details', return_value=ip_data)
    with pytest.raises(ValueError) as err:
        get_public_ip_details_command(client, {'address_name': 'fake_name'})
    if not err:
        assert False
    else:
        err_msg = "'fake_name' was not found. Please try specifying the resource group the IP would be associated with."
        assert str(err.value) == err_msg


def test_get_all_public_ip_details_command(mocker):
    ip_data = load_test_data('./test_data/get_public_ip_details_command_multiple_ips.json')
    mocker.patch.object(client, 'get_all_public_ip_details', return_value=ip_data)
    _, ec, _ = get_all_public_ip_details_command(client, None)
    assert MANY_PUBLIC_IP_EC == ec


def test_get_single_ip_details_from_list_of_ip_details_function():
    ip_data = load_test_data('./test_data/get_public_ip_details_command_multiple_ips.json')
    test_target = "1.1.1.1"
    ec = get_single_ip_details_from_list_of_ip_details(ip_data.get('value'), test_target)
    assert PUBLIC_IP_DETAILS_LIST_ENTRY_EC == ec


def test_get_single_ip_details_from_list_of_ip_details_function_is_none():
    ip_data = load_test_data('./test_data/get_public_ip_details_command_multiple_ips.json')
    invalid_test_target = "1.1.1.9"
    ec = get_single_ip_details_from_list_of_ip_details(ip_data.get('value'), invalid_test_target)
    assert ec is None


def test_create_nic_command(mocker):
    nic_data = load_test_data('./test_data/create_nic_command.json')
    mocker.patch.object(client, 'create_nic', return_value=nic_data)
    _, ec, _ = create_nic_command(client, {'resource_group': 'resource_group', 'nic_name': 'test-nic100',
                                           'nic_location': 'eastus', 'vnet_name': 'subnet_id',
                                           'subnet_name': 'subnet_name', 'address_assignment_method': 'Static',
                                           'private_ip_address': '10.0.0.5', 'ip_config_name': 'ipconfig1',
                                           'network_security_group': 'security_group_id'})
    assert CREATE_NIC_EC == ec
