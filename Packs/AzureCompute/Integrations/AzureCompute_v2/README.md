You can use this integration to create and manage Azure Virtual Machines.
This integration was integrated and tested with Azure Compute API Version: 2017-12-01.

## Authentication
For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication).

- After authorizing the Demisto App or the Self-Deployed Application, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields. After giving consent, the application has to have a role assigned so it can access the relevant resources per subscription.
- In order to assign a role to the application after consent was given:
  - Go to the Azure Portal UI. 
  - Go to Subscriptions, and then Access Control (IAM). 
  - Click "Add role assignment". 
  - Create a new role or select a role that includes the following permissions:
    - Microsoft.Compute/virtualMachines/*
    - Microsoft.Network/networkInterfaces/read 
    - Microsoft.Resources/subscriptions/resourceGroups/read 
  - Select the Azure Compute application. By default, Azure AD applications aren't displayed in the available options. To find your application, search for the name and select it.

## Configure Azure Compute v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Host URL (e.g. https://management.azure.com) |  | True |
| ID (received from the admin consent - see Detailed Instructions (?) |  | True |
| Token (received from the admin consent - see Detailed Instructions (?) section) |  | True |
| Key (received from the admin consent - see Detailed Instructions (?) |  | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp; secrets" page of the app. | False |
| ID (received from the admin consent - see Detailed Instructions (?) |  | False |
| Token (received from the admin consent - see Detailed Instructions (?) section) |  | False |
| Key (received from the admin consent - see Detailed Instructions (?) |  | True |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates &amp;amp; secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Default Subscription ID |  | False |
| Default Subscription ID |  | False |
| Default Resource Group Name | This parameter can be overridden by the resource_group argument in any command. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |
| Use a self-deployed Azure Application | Select this checkbox if you are using a self-deployed Azure application. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-vm-list-instances

***
Lists the virtual machine instances in the given resource group.

#### Base Command

`azure-vm-list-instances`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group of the virtual machines.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Compute.Name | string | The name of the virtual machine. | 
| Azure.Compute.Location | string | The location of the virtual machine. | 
| Azure.Compute.ProvisioningState | string | The provisioning state of the virtual machine. | 
| Azure.Compute.ResourceGroup | string | The resource group in which the virtual machine resides. | 
| Azure.Compute.ID | string | The ID of the virtual machine. | 
| Azure.Compute.Size | number | The size of the deployed virtual machine \(in gigabytes\). | 
| Azure.Compute.OS | string | The OS running on the virtual machine. | 

#### Command example
```!azure-vm-list-instances resource_group=Compute-Labs```
#### Context Example
```json
{
    "Azure": {
        "Compute": [
            {
                "ID": "d25e7ce9-258b-4d8d-a516-c2206eef08ef",
                "Location": "eastus",
                "Name": "test12",
                "OS": "Windows",
                "ProvisioningState": "Succeeded",
                "ResourceGroup": "Compute-Labs",
                "Size": 127
            },
            {
                "ID": "befbbbba-64a6-49e9-84f7-27f3cc27818d",
                "Location": "eastus",
                "Name": "test1234",
                "OS": "Windows",
                "ProvisioningState": "Succeeded",
                "ResourceGroup": "Compute-Labs",
                "Size": 127
            },
            {
                "ID": "xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx",
                "Location": "eastus",
                "Name": "webserver",
                "OS": "Windows",
                "ProvisioningState": "Succeeded",
                "ResourceGroup": "Compute-Labs",
                "Size": 127
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Azure - List of Virtual Machines in Resource Group "Compute-Labs"
>|Name|ID|Size|OS|Location|ProvisioningState|ResourceGroup|
>|---|---|---|---|---|---|---|
>| test12 | d25e7ce9-258b-4d8d-a516-c2206eef08ef | 127 | Windows | eastus | Succeeded | Compute-Labs |
>| test1234 | befbbbba-64a6-49e9-84f7-27f3cc27818d | 127 | Windows | eastus | Succeeded | Compute-Labs |
>| webserver | xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx | 127 | Windows | eastus | Succeeded | Compute-Labs |


### azure-vm-start-instance

***
Powers on a given virtual machine.

#### Base Command

`azure-vm-start-instance`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | Resource Group to which the virtual machine belongs.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| virtual_machine_name | Name of the virtual machine to power on. To see all virtual machines and their associated names for a specific resource group, run the `azure-vm-list-instances` command. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Compute.Name | string | Name of the VM that was started. | 
| Azure.Compute.ResourceGroup | string | Resource group the VM resides in. | 
| Azure.Compute.PowerState | string | Whether the VM instance is powered on or off. | 

#### Command example
```!azure-vm-start-instance resource_group="Compute-Labs" virtual_machine_name="webserver"```
#### Context Example
```json
{
    "Azure": {
        "Compute": {
            "Name": "webserver",
            "PowerState": "VM starting",
            "ResourceGroup": "Compute-Labs"
        }
    }
}
```

#### Human Readable Output

>### Power-on of Virtual Machine "webserver" Successfully Initiated
>|Name|PowerState|ResourceGroup|
>|---|---|---|
>| webserver | VM starting | Compute-Labs |


### azure-vm-poweroff-instance

***
Powers off a given virtual machine.

#### Base Command

`azure-vm-poweroff-instance`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the virtual machine belongs.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| virtual_machine_name | The name of the virtual machine to power off. To see all virtual machines with their associated names for a specific resource group, run the `azure-vm-list-instances` command. | Required | 
| skip_shutdown | Set to True to request non-graceful VM shutdown. Default value is False. Possible values are: True, False. Default is False. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Compute.Name | string | The name of the virtual machine that was powered off. | 
| Azure.Compute.ResourceGroup | string | The resource group in which the virtual machine resides. | 
| Azure.Compute.PowerState | string | Whether the virtual machine instance is powered on or off. | 

#### Command example
```!azure-vm-poweroff-instance resource_group=Compute-Labs virtual_machine_name=test12```
#### Context Example
```json
{
    "Azure": {
        "Compute": {
            "Name": "test12",
            "PowerState": "VM stopping",
            "ResourceGroup": "Compute-Labs"
        }
    }
}
```

#### Human Readable Output

>### Power-off of Virtual Machine "test12" Successfully Initiated
>|Name|PowerState|ResourceGroup|
>|---|---|---|
>| test12 | VM stopping | Compute-Labs |


### azure-vm-get-instance-details

***
Gets the properties of a given virtual machine.

#### Base Command

`azure-vm-get-instance-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the virtual machine belongs.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| virtual_machine_name | The name of the virtual machine you want to view the details of. To see all the virtual machines with their associated names for a specific resource group, run the `azure-vm-list-instances` command. | Required | 
| expand | The expand expression to apply on the operation. 'instanceView' retrieves a snapshot of the runtime properties of the virtual machine that is managed by the platform and can change outside of control plane operations. 'userData' retrieves the UserData property as part of the VM model view that was provided by the user during the VM Create/Update operation. Default value is False. Possible values are: instanceView, userData. Default is instanceView. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Compute.Name | string | The name of the virtual machine you want to get details of. | 
| Azure.Compute.ID | string | The ID of the virtual machine. | 
| Azure.Compute.Size | number | The size of the deployed virtual machine \(in gigabytes\). | 
| Azure.Compute.OS | string | The OS running on the given virtual machine. | 
| Azure.Compute.ProvisioningState | string | The provisioning state of the deployed virtual machine. | 
| Azure.Compute.Location | string | The region in which the virtual machine is hosted. | 
| Azure.Compute.PowerState | string | Whether the virtual machine instance is powered on or off. | 
| Azure.Compute.ResourceGroup | string | The resource group to which the virtual machine belongs. | 
| Azure.Compute.NetworkInterfaces | Unknown | The list of network interfaces attached to this machine. | 
| Azure.Compute.UserData | string | UserData for the VM. | 
| Azure.Compute.Tags | string | Tags associated with the VM. | 

#### Command example
```!azure-vm-get-instance-details resource_group=Compute-Labs virtual_machine_name=webserver```
#### Context Example
```json
{
    "Azure": {
        "Compute": {
            "ID": "xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx",
            "Location": "eastus",
            "Name": "webserver",
            "NetworkInterfaces": [
                {
                    "id": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver729",
                    "properties": {
                        "deleteOption": "Delete"
                    }
                }
            ],
            "OS": "Windows",
            "PowerState": "VM running",
            "ProvisioningState": "Succeeded",
            "ResourceGroup": "Compute-Labs",
            "Size": 127,
            "Tags": {
                "env": "dev",
                "owner" : "testuser"
            }
        }
    }
}
```

#### Human Readable Output

>### Properties of VM "webserver"
>|Name|ID|Size|OS|ProvisioningState|Location|PowerState|
>|---|---|---|---|---|---|---|
>| webserver | xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx | 127 | Windows | Succeeded | eastus | VM running |


### azure-vm-create-instance

***
Creates a virtual machine instance with the specified OS image.

#### Base Command

`azure-vm-create-instance`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the new virtual machine will belong.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| virtual_machine_name | The name of the virtual machine to create. | Required | 
| virtual_machine_location | The location in which to create the virtual machine. Possible values are: westus2, westus, westindia, westeurope, westcentralus, uksouth, ukwest, southeastasia, northcentralus, northeurope, southcentralus, southindia, francesouth, francecentral, japaneast, japanwest, koreacentral, koreasouth, brazilsouth, canadacentral, canadaeast, centralindia, eastus2, eastasia, westus, centralus, eastus, australiacentral, australiacentral2, australiaeast, australiasoutheast. | Required | 
| nic_name | The name of the Network Interface to link the virtual machine with. Note that the virtual machine's location property must match that of the Network Interface you choose to link it to. To see a list of available Network Interfaces visit the Azure Web Portal, navigate to the search bar at the top of the page, type "network interfaces", and in the dynamic drop-down menu that appears, click the 'Network interfaces' option that appears under the 'Services' category. If none are present, you will need to create a new Network Interface. | Required | 
| vm_size | The name of a VirtualMachineSize, which determines the size of the deployed virtual machine. For more information, see the Azure documentation at https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/listavailablesizes#virtualmachinesize. Possible values are: Standard_D1_v2, Standard_D2_v2, Standard_D2s_v3, Standard_B1ms, Standard_B1s, Standard_B2s, Standard_B4ms, Standard_D4s_v3, Standard_DS1_v2, Standard_DS2_v2, Standard_DS3_v2, Promo_DS2_v2, Promo_DS3_v2. | Required | 
| os_image | The base operating system image of the virtual machine. Possible values are: Ubuntu Server 14.04 LTS, Ubuntu Server 16.04 LTS, Ubuntu Server 18.04 LTS, Red Hat Enterprise Linux 7.6, CentOS-based 7.5, Windows Server 2012 R2 Datacenter, Windows Server 2016 Datacenter, Windows 10 Pro Version 1803, Windows 10 Pro Version 1809. | Optional | 
| sku | SKU of the OS image to be used. To see a list of available SKUs, visit your Azure Web Portal, click the symbol that looks similar to a '&gt;' on the top bar of the page. This should open a cloud shell, make sure it is a bash shell. At the command prompt enter `az vm image list-skus` along with the appropriate arguments that it will prompt you with to display the list of VM image SKUs available in the Azure Marketplace. Default is 2016-Datacenter. | Optional | 
| publisher | Name of the publisher of the OS image. To see a list of available publishers, visit your Azure Web Portal, click the symbol that looks similar to a '&gt;' on the top bar of the page which should open a cloud shell, make sure it is a bash shell. At the command prompt enter `az vm image list-publishers` along with the appropriate arguments that it will prompt you with to display the list of VM image publishers available in the Azure Marketplace. Default is MicrosoftWindowsServer. | Optional | 
| version | Version of the image to use. The supported formats are Major.Minor.Build or 'latest'. Major, Minor, and Build are decimal numbers. Specify 'latest' to use the latest version of an image available at deploy time. Default is latest. | Optional | 
| offer | Specifies the offer of the platform image or marketplace image used to create the virtual machine. To see a list of available offers, visit your Azure Web Portal, click the symbol that looks similar to a '&gt;' on the top bar of the page which should open a cloud shell, make sure it is a bash shell. At the command prompt enter `az vm image list-offers` along with the appropriate arguments that it will prompt you with to display the list of VM image offers available in the Azure Marketplace. Default is WindowsServer. | Optional | 
| admin_username | The admin username to use when creating the virtual machine. Default is DemistoUser. | Optional | 
| admin_password | The admin password to use when creating the virtual machine. Default is Passw0rd@123. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Compute.Name | string | The name of the created virtual machine instance. | 
| Azure.Compute.ResourceGroup | string | The resource group in which the virtual machine resides. | 
| Azure.Compute.ID | string | The ID of the virtual machine. | 
| Azure.Compute.Size | number | The size of the deployed virtual machine \(in gigabytes\). | 
| Azure.Compute.OS | string | The OS running on the specified virtual machine. | 
| Azure.Compute.ProvisioningState | string | The provisioning state of the deployed virtual machine. | 
| Azure.Compute.Location | string | The region in which the virtual machine is hosted. | 

#### Command example
```!azure-vm-create-instance nic_name=test_nic3 resource_group=Compute-Labs virtual_machine_location=eastus virtual_machine_name=test567 vm_size=Standard_D1_v2```
#### Context Example
```json
{
    "Azure": {
        "Compute": {
          "ID": "xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx",
          "Location": "eastus",
          "Name": "test567",
          "OS": "Windows",
          "ProvisioningState": "Creating",
          "ResourceGroup": "Compute-Labs",
          "Size": "127"

        }
    }
}
```

#### Human Readable Output

>### List of Resource Groups
>|ID|Location|Name|OS|ProvisioningState|ResourceGroup|Size|
>|---|---|---|---|---|---|---|
>| 	xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx | eastus | test567 | Windows | Creating | Compute-Labs | 127 |


### azure-list-resource-groups

***
Lists all resource groups that belong to your Azure subscription.

#### Base Command

`azure-list-resource-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| tag | A single tag in the form of '{"Tag Name":"Tag Value"}' to filter the list by. | Optional | 
| limit | Limit on the number of resource-groups to return. Default value is 50. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.ResourceGroup.Name | string | The name of the resource group. | 
| Azure.ResourceGroup.ID | string | The ID of the resource group. | 
| Azure.ResourceGroup.Location | string | The location of the resource group. | 
| Azure.ResourceGroup.ProvisioningState | string | The provisioning state of the resource group. | 

#### Command example
```!azure-list-resource-groups```
#### Context Example
```json
{
    "Azure": {
        "ResourceGroup": [
            {
                "ID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs",
                "Location": "ukwest",
                "Name": "Compute-Labs",
                "ProvisioningState": "Succeeded"
            },
            {
                "ID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/NetworkWatcherRG",
                "Location": "eastus",
                "Name": "NetworkWatcherRG",
                "ProvisioningState": "Succeeded"
            }
        ]
    }
}
```

#### Human Readable Output

>### List of Resource Groups
>|ID|Location|Name|ProvisioningState|
>|---|---|---|---|
>| /subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs | ukwest | Compute-Labs | Succeeded |
>| /subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/NetworkWatcherRG | eastus | NetworkWatcherRG | Succeeded |


### azure-vm-delete-instance

***
Deletes a specified virtual machine.

#### Base Command

`azure-vm-delete-instance`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the virtual machine belongs.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| virtual_machine_name | The name of the virtual machine to delete. To see all the virtual machines with their associated names for a specific resource group, run the `azure-vm-list-instances` command. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-vm-delete-instance resource_group=Compute-Labs virtual_machine_name=test1234```
#### Human Readable Output

>"test1234" VM Deletion Successfully Initiated

### azure-list-subscriptions

***
Lists the subscriptions for this application.

#### Base Command

`azure-list-subscriptions`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Subscription.ID | String | The ID of the subscription. | 
| Azure.Subscription.Name | String | The name of the subscription. | 
| Azure.Subscription.State | String | The state of the subscription. | 

#### Command example
```!azure-list-subscriptions```
#### Context Example
```json
{
    "Azure": {
        "Subscription": {
            "ID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx",
            "Name": "Azure subscription 1",
            "State": "Enabled"
        }
    }
}
```

#### Human Readable Output

>### List of Subscriptions
>|ID|Name|State|
>|---|---|---|
>| /subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx | Azure subscription 1 | Enabled |


### azure-vm-get-nic-details

***
Gets the properties of a given network interface.

#### Base Command

`azure-vm-get-nic-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the network interface belongs.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| nic_name | The name of the network interface you want to view the details of. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Network.Interfaces.AttachedVirtualMachine | String | The attached virtual machine to this interface. | 
| Azure.Network.Interfaces.IsPrimaryInterface | String | True if this interface is a primary interface of the attached virtual machine. | 
| Azure.Network.Interfaces.NICType | String | The interface type. | 
| Azure.Network.Interfaces.IPConfigurations.ConfigID | String | The interface IP configuration ID. | 
| Azure.Network.Interfaces.IPConfigurations.ConfigName | String | The interface IP configuration name. | 
| Azure.Network.Interfaces.IPConfigurations.PrivateIPAddress | String | The interface private IP address. | 
| Azure.Network.Interfaces.IPConfigurations.PublicIPAddressID | Unknown | The interface public IP address ID. | 
| Azure.Network.Interfaces.MACAddress | String | The interface MAC address. | 
| Azure.Network.Interfaces.Name | String | The interface name. | 
| Azure.Network.Interfaces.ResourceGroup | String | The interface resource group. | 
| Azure.Network.Interfaces.NetworkSecurityGroup.id | String | The interface network security group ID. | 
| Azure.Network.Interfaces.Location | String | The interface location. | 
| Azure.Network.Interfaces.ID | String | The interface ID. | 

#### Command example
```!azure-vm-get-nic-details resource_group=Compute-Labs nic_name=webserver729```
#### Context Example
```json
{
    "Azure": {
        "Network":{
          "Interfaces": {
            "AttachedVirtualMachine": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Compute/virtualMachines/webserver",
            "DNSSuffix": "test.bx.internal.cloudapp.net",
            "ID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver729",
            "IPConfigurations": [
              {
                "ConfigID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver729/ipConfigurations/ipconfig1",
                "ConfigName": "ipconfig1",
                "PrivateIPAddress": "10.0.0.4",
                "PublicIPAddressID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/publicIPAddresses/webserver-ip"
              }
            ],
            "IsPrimaryInterface": true,
            "Location": "eastus",
            "MACAddress": "00-22-48-1C-73-AF",
            "NICType": "NA",
            "Name": "webserver729",
            "NetworkSecurityGroup": {
              "id": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkSecurityGroups/webserver-nsg"
            },
            "ResourceGroup": "Compute-Labs"
          }
        }
    }
}
```

#### Human Readable Output

>### Properties of Network Interface "webserver729"
>|Name|ID|MACAddress|NetworkSecurityGroup|NICType|PrivateIPAddresses|AttachedVirtualMachine|
>|---|---|---|---|---|---|---|
>| webserver729 | /subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver729 | 00-22-48-1C-73-AF | id: /subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkSecurityGroups/webserver-nsg | NA | 10.0.0.4|sample-webserver|


### azure-vm-get-public-ip-details

***
Gets the properties of a given public IP address.

#### Base Command

`azure-vm-get-public-ip-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the IP address belongs.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional |  
| address_name | The IP address name. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Network.IPConfigurations.PublicIPAddress | String | The public IP address. | 
| Azure.Network.IPConfigurations.PublicIPAddressFQDN | String | The address fully-qualified domain name \(FQDN\). | 
| Azure.Network.IPConfigurations.PublicIPAddressAllocationMethod | String | The address allocation method. | 
| Azure.Network.IPConfigurations.PublicConfigID | String | The address configuration ID. | 
| Azure.Network.IPConfigurations.ResourceGroup | String | The address resource group. | 
| Azure.Network.IPConfigurations.PublicIPAddressDomainName | String | The address domain name. | 
| Azure.Network.IPConfigurations.PublicIPAddressVersion | String | The address version. | 
| Azure.Network.IPConfigurations.Location | String | The address location. | 
| Azure.Network.IPConfigurations.PublicConfigName | String | The address configuration name. | 
| Azure.Network.IPConfigurations.PublicIPAddressID | String | The address ID. | 

#### Command examples
```!azure-vm-get-public-ip-details resource_group=Compute-Labs address_name=webserver-ip```

```!azure-vm-get-public-ip-details address_name=xx.xx.xx.xx```
#### Context Example
```json
{
    "Azure": {
        "Network": {
            "IPConfigurations": {
                "Location": "eastus",
                "PublicConfigID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver729/ipConfigurations/ipconfig1",
                "PublicConfigName": "webserver-ip",
                "PublicIPAddress": "xx.xx.xx.xx",
                "PublicIPAddressAllocationMethod": "Dynamic",
                "PublicIPAddressDomainName": "cortexmea-webserver",
                "PublicIPAddressFQDN": "test.eastus.cloudapp.azure.com",
                "PublicIPAddressID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/publicIPAddresses/webserver-ip",
                "PublicIPAddressVersion": "IPv4",
                "ResourceGroup": "Compute-Labs"
            }
        }
    }
}
```


### azure-vm-get-all-public-ip-details
***
Gets the properties of all public ip address in a subscription.

#### Base Command

`azure-vm-get-all-public-ip-details`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Network.IPConfigurations.PublicIPAddress | String | The public IP address. | 
| Azure.Network.IPConfigurations.PublicIPAddressFQDN | String | The address fully-qualified domain name \(FQDN\). | 
| Azure.Network.IPConfigurations.PublicIPAddressAllocationMethod | String | The address allocation method. | 
| Azure.Network.IPConfigurations.PublicConfigID | String | The address configuration ID. | 
| Azure.Network.IPConfigurations.ResourceGroup | String | The address resource group. | 
| Azure.Network.IPConfigurations.PublicIPAddressDomainName | String | The address domain name. | 
| Azure.Network.IPConfigurations.PublicIPAddressVersion | String | The address version. | 
| Azure.Network.IPConfigurations.Location | String | The address location. | 
| Azure.Network.IPConfigurations.PublicConfigName | String | The address configuration name. | 
| Azure.Network.IPConfigurations.PublicIPAddressID | String | The address ID. | 

#### Command example
```!azure-vm-get-all-public-ip-details```
#### Context Example
```json
{
    "Azure": {
        "Network": [{
            "IPConfigurations": {
                "Location": "eastus",
                "PublicConfigID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver729/ipConfigurations/ipconfig1",
                "PublicConfigName": "webserver-ip",
                "PublicIPAddress": "xx.xx.xx.xx",
                "PublicIPAddressAllocationMethod": "Dynamic",
                "PublicIPAddressDomainName": "cortexmea-webserver",
                "PublicIPAddressFQDN": "test.eastus.cloudapp.azure.com",
                "PublicIPAddressID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/publicIPAddresses/webserver-ip",
                "PublicIPAddressVersion": "IPv4",
                "ResourceGroup": "Compute-Labs"
            }
        }, {
            "IPConfigurations": {
                "Location": "eastus",
                "PublicConfigID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/webserver145/ipConfigurations/ipconfig2",
                "PublicConfigName": "webserver-ip2",
                "PublicIPAddress": "xx.xx.xx.xx",
                "PublicIPAddressAllocationMethod": "Dynamic",
                "PublicIPAddressDomainName": "cortexmea-webserver",
                "PublicIPAddressFQDN": "test.eastus.cloudapp.azure.com",
                "PublicIPAddressID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/publicIPAddresses/webserver-ip2",
                "PublicIPAddressVersion": "IPv4",
                "ResourceGroup": "Compute-Labs"
            }
        }, {
            "IPConfigurations": {
                "Location": "eastus",
                "PublicConfigID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Other-Labs/providers/Microsoft.Network/networkInterfaces/webserver832/ipConfigurations/ipconfig3",
                "PublicConfigName": "webserver-ip3",
                "PublicIPAddress": "xx.xx.xx.xx",
                "PublicIPAddressAllocationMethod": "Dynamic",
                "PublicIPAddressDomainName": "cortexmea-webserver",
                "PublicIPAddressFQDN": "test.eastus.cloudapp.azure.com",
                "PublicIPAddressID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Other-Labs/providers/Microsoft.Network/publicIPAddresses/webserver-ip3",
                "PublicIPAddressVersion": "IPv4",
                "ResourceGroup": "Compute-Labs"
            }
        }]
    }
}
```

#### Human Readable Output

>### Properties of Public Address "webserver-ip"
>|PublicConfigName|PublicIPAddress| Location |PublicIPAddressVersion|PublicIPAddressAllocationMethod|
>|-----------|--------|---|------|--------|
>| test-publicip1|xx.xx.xx.xx| ukwest | IPv4|Static|


### azure-vm-create-nic

***
Creates a virtual machine network interface.

#### Base Command

`azure-vm-create-nic`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group | The resource group to which the new network interface will belong.<br/>To see all the resource groups associated with your subscription, run the `azure-list-resource-groups` command. If none are present, navigate to the Azure Web Portal to create resource groups.<br/>Note: This argument will override the instance parameter ‘Default Resource Group Name'.<br/>. | Optional | 
| nic_name | The network interface name. | Required | 
| nic_location | The location in which to create the network interface. Possible values are: westus2, westus, westindia, westeurope, westcentralus, uksouth, ukwest, southeastasia, northcentralus, northeurope, southcentralus, southindia, francesouth, francecentral, japaneast, japanwest, koreacentral, koreasouth, brazilsouth, canadacentral, canadaeast, centralindia, eastus2, eastasia, westus, centralus, eastus, australiacentral, australiacentral2, australiaeast, australiasoutheast. | Required | 
| vnet_name | The virtual network name of the interface. | Required | 
| subnet_name | The subnet name of the interface. | Required | 
| address_assignment_method | The address assignment method. Possible values are: Static, Dynamic. Default is Dynamic. | Optional | 
| private_ip_address | The private IP address of the interface if you chose the static assignment method. | Optional | 
| ip_config_name | The IP address configuration name. | Required | 
| network_security_group | The network security group of the interface. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Network.Interfaces.IPConfigurations.ConfigID | String | The interface IP configuration ID. | 
| Azure.Network.Interfaces.IPConfigurations.ConfigName | String | The interface IP configuration name. | 
| Azure.Network.Interfaces.IPConfigurations.PrivateIPAddress | String | The interface private IP address. | 
| Azure.Network.Interfaces.IPConfigurations.PublicIPAddressID | Unknown | The interface public IP address ID. | 
| Azure.Network.Interfaces.Name | String | The interface name. | 
| Azure.Network.Interfaces.ResourceGroup | String | The interface resource group. | 
| Azure.Network.Interfaces.NetworkSecurityGroup.id | String | The interface network security group ID. | 
| Azure.Network.Interfaces.Location | String | The interface location. | 
| Azure.Network.Interfaces.ID | String | The interface ID. | 

#### Command example
```!azure-vm-create-nic nic_location=eastus nic_name=test_nic2 resource_group=Compute-Labs subnet_name=default vnet_name=Compute-Labs-vnet ip_config_name=ipconfigtest```
#### Context Example
```json
{
    "Azure": {
        "Network":{
          "Interfaces": {
            "DNSSuffix": "test.bx.internal.cloudapp.net",
            "ID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/test_nic2",
            "IPConfigurations": [
              {
                "ConfigID": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/test_nic2/ipConfigurations/ipconfigtest",
                "ConfigName": "ipconfigtest",
                "PrivateIPAddress": "10.0.0.13",
                "PublicIPAddressID": "NA",
                "SubNet": "/subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/virtualNetworks/Compute-Labs-vnet/subnets/default"
              }
            ],
            "Location": "eastus",
            "Name": "test_nic2",
            "NetworkSecurityGroup": "NA",
            "ProvisioningState": "Succeeded",
            "ResourceGroup": "Compute-Labs"
          }
        }
    }
}
```

#### Human Readable Output

>### Created Network Interface "test_nic2"
>|ID|PrivateIPAddresses|Location|Name|NetworkSecurityGroup|
>|---|---|---|---|---|
>| /subscriptions/xxxxxxxxx-xxxxx-xxxxx-xxxxx-xxxxxxxxxxxxx/resourceGroups/Compute-Labs/providers/Microsoft.Network/networkInterfaces/test_nic2 | 10.0.0.13 | eastus | test_nic2 | NA |


### azure-vm-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-vm-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.