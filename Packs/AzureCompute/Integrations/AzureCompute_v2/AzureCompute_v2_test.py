import pytest
from AzureCompute_v2 import MsGraphClient, screen_errors, assign_image_attributes, list_vms_command, create_vm_parameters

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

# test_list_vms data:
LIST_VM_RAW_DATA = {
    'value': [
        {
            'name': 'testvm',
            'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers/Microsoft.Compute'
                  '/virtualMachines/testvm',
            'type': 'Microsoft.Compute/virtualMachines',
            'location': 'westeurope',
            'properties': {
                'vmId': 'vm_id',
                'hardwareProfile': {
                    'vmSize': 'Standard_D1_v2'
                },
                'storageProfile': {
                    'imageReference': {
                        'publisher': 'OpenLogic',
                        'offer': 'CentOS',
                        'sku': '7.5',
                        'version': 'latest'
                    },
                    'osDisk': {
                        'osType': 'Linux',
                        'name': 'testvm',
                        'createOption': 'FromImage',
                        'caching': 'ReadWrite',
                        'managedDisk': {
                            'storageAccountType': 'Standard_LRS',
                            'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers'
                                  '/Microsoft.Compute/disks/testvm '
                        },
                        'diskSizeGB': 30
                    },
                    'dataDisks': [

                    ]
                },
                'osProfile': {
                    'computerName': 'testvm',
                    'adminUsername': 'admin',
                    'linuxConfiguration': {
                        'disablePasswordAuthentication': False,
                        'provisionVMAgent': True
                    },
                    'secrets': [

                    ],
                    'allowExtensionOperations': True
                },
                'networkProfile': {
                    'networkInterfaces': [
                        {
                            'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers'
                                  '/Microsoft.Network/networkInterfaces/compute-integration-nic1',
                            'properties': {
                                'primary': True
                            }
                        }
                    ]
                },
                'provisioningState': 'Succeeded'
            }
        },
        {
            'name': 'vm2_name',
            'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers/Microsoft.Compute'
                  '/virtualMachines/vm2_name',
            'type': 'Microsoft.Compute/virtualMachines',
            'location': 'westeurope',
            'properties': {
                'vmId': 'vm2_id',
                'hardwareProfile': {
                    'vmSize': 'Standard_B1s'
                },
                'storageProfile': {
                    'imageReference': {
                        'publisher': 'RedHat',
                        'offer': 'RHEL',
                        'sku': '7-RAW',
                        'version': 'latest'
                    },
                    'osDisk': {
                        'osType': 'Linux',
                        'name': 'vm2_name',
                        'createOption': 'FromImage',
                        'caching': 'ReadWrite',
                        'managedDisk': {
                            'storageAccountType': 'Standard_LRS',
                            'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers'
                                  '/Microsoft.Compute/disks/vm2_name '
                        },
                        'diskSizeGB': 32
                    },
                    'dataDisks': [

                    ]
                },
                'osProfile': {
                    'computerName': 'vm2_name',
                    'adminUsername': 'admin',
                    'linuxConfiguration': {
                        'disablePasswordAuthentication': False,
                        'provisionVMAgent': True
                    },
                    'secrets': [

                    ],
                    'allowExtensionOperations': True
                },
                'networkProfile': {
                    'networkInterfaces': [
                        {
                            'id': '/subscriptions/subscription_id/resourceGroups/compute-integration/providers'
                                  '/Microsoft.Network/networkInterfaces/compute-integration-nic',
                            'properties': {
                                'primary': True
                            }
                        }
                    ]
                },
                'provisioningState': 'Succeeded'
            }
        }
    ]
}
VM_LIST_EC = {'Azure.Compute(val.Name && val.Name === obj.Name)': [
    {'Name': 'testvm', 'ID': 'vm_id', 'Size': 30, 'OS': 'Linux', 'Location': 'westeurope',
     'ProvisioningState': 'Succeeded', 'ResourceGroup': 'resource_group'},
    {'Name': 'vm2_name', 'ID': 'vm2_id', 'Size': 32, 'OS': 'Linux', 'Location': 'westeurope',
     'ProvisioningState': 'Succeeded', 'ResourceGroup': 'resource_group'}]}

client = MsGraphClient(
    base_url="url", tenant_id="tenant", auth_id="auth_id", enc_key="enc_key", app_name="APP_NAME", verify="verify",
    proxy="proxy", self_deployed="self_deployed", ok_codes=(1, 2), server="server", subscription_id="subscription_id")


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
    mocker.patch.object(client, 'list_vms', return_value=LIST_VM_RAW_DATA)
    _, ec, _ = list_vms_command(client, {'resource_group': 'resource_group'})
    assert VM_LIST_EC == ec
