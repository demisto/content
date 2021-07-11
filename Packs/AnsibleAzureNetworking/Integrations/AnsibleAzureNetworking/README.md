This integration enables the management of Azure Networking Services using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands.

To use this integration, configure an instance of this integration. This will associate a credential to be used to manage a Azure Subscription.

# Authorize Cortex XSOAR for Azure Cloud
To use this integration you must generate a Service Principal for your Azure subscription. Follow [Microsoft's guide](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-group-create-service-principal-portal) on how to create a Azure AD application and associated service principal.

After stepping through the guide you will have:

* Your Client ID, which is found in the “client id” box in the “Configure” page of your application in the Azure portal
* Your Secret key, generated when you created the application. You cannot show the key after creation. If you lost the key, you must create a new one in the “Configure” page of your application.
* And finally, a tenant ID. It’s a UUID (e.g. ABCDEFGH-1234-ABCD-1234-ABCDEFGHIJKL) pointing to the AD containing your application. You will find it in the URL from within the Azure portal, or in the “view endpoints” of any given URL.

## Configure Ansible Azure Networking on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Ansible Azure Networking.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Subscription ID | Your Azure subscription Id. | True |
    | Access Secret | Azure client secret | True |
    | Client ID | Azure client ID | True |
    | Tenant ID | Azure tenant ID | True |
    | Azure Cloud Environment | For cloud environments other than the US public cloud, the environment name \(as defined by Azure Python SDK, eg, \`AzureChinaCloud\`, \`AzureUSGovernment\`\), or a metadata discovery endpoint URL \(required for Azure Stack\). | True |
    | Certificate Validation Mode | Controls the certificate validation behavior for Azure endpoints. By default, all modules will validate the server certificate, but when an HTTPS proxy is in use, or against Azure Stack, it may be necessary to disable this behavior by passing \`ignore\`. | True |
    | API Profile | Selects an API profile to use when communicating with Azure services. Default value of \`latest\` is appropriate for public clouds; future values will allow use with Azure Stack. | True |

4. Click **Test** to validate the URLs, token, and connection.

# Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

# State Arguement
Some of the commands in this integration take a state argument. These define the desired end state of the object being managed. As a result these commands are able to perform multiple management operations depending on the desired state value. Common state values are:
| **State** | **Result** |
| --- | --- |
| present | Object should exist. If not present, the object will be created with the provided parameters. If present but not with correct parameters, it will be modified to met provided parameters. |
| running | Object should be running not stopped. |
| stopped | Object should be stopped not running. |
| restarted | Object will be restarted. |
| absent | Object should not exist. If it it exists it will be deleted. |
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-rm-azurefirewall
***
Manage Azure Firewall instance.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_azurefirewall_module.html


#### Base Command

`azure-rm-azurefirewall`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| name | The name of the Azure Firewall. | Required | 
| location | Resource location. | Optional | 
| application_rule_collections | Collection of application rule collections used by Azure Firewall. | Optional | 
| nat_rule_collections | Collection of NAT rule collections used by Azure Firewall. | Optional | 
| network_rule_collections | Collection of network rule collections used by Azure Firewall. | Optional | 
| ip_configurations | IP configuration of the Azure Firewall resource. | Optional | 
| state | Assert the state of the AzureFirewall. Use `present` to create or update an AzureFirewall and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmAzurefirewall.id | string | Resource ID. | 


#### Command Example
```!azure-rm-azurefirewall resource_group="myResourceGroup" name="myAzureFirewall" tags="{{ {'key1': 'value1'} }}" ip_configurations="{{ [{'subnet': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet', 'public_ip_address': '/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/myPublicIpAddress', 'name': 'azureFirewallIpConfiguration'}] }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmAzurefirewall": [
            {
                "changed": false,
                "compare": [],
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall",
                "modifiers": {
                    "/location": {
                        "comparison": "location",
                        "updatable": false
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall
>  * ## Compare
>  * ## Modifiers
>    * ### /Location
>      * comparison: location
>      * updatable: False


### azure-rm-azurefirewall-info
***
Get AzureFirewall info.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_azurefirewall_info_module.html


#### Base Command

`azure-rm-azurefirewall-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Optional | 
| name | Resource name. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmAzurefirewallInfo.firewalls | unknown | A list of dict results where the key is the name of the AzureFirewall and the values are the facts for that AzureFirewall. | 


#### Command Example
```!azure-rm-azurefirewall-info ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmAzurefirewallInfo": [
            {
                "changed": false,
                "firewalls": [
                    {
                        "etag": "W/\"3c426480-93a2-4db2-93d9-d3f0cbfd45ba\"",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall",
                        "ip_configurations": [
                            {
                                "etag": "W/\"3c426480-93a2-4db2-93d9-d3f0cbfd45ba\"",
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall/azureFirewallIpConfigurations/azureFirewallIpConfiguration",
                                "name": "azureFirewallIpConfiguration",
                                "properties": {
                                    "privateIPAddress": "10.0.2.4",
                                    "privateIPAllocationMethod": "Dynamic",
                                    "provisioningState": "Succeeded",
                                    "publicIPAddress": {
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/myPublicIpAddress"
                                    },
                                    "subnet": {
                                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet"
                                    }
                                },
                                "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations"
                            }
                        ],
                        "location": "australiasoutheast",
                        "name": "myAzureFirewall",
                        "nat_rule_collections": [],
                        "network_rule_collections": [],
                        "provisioning_state": "Succeeded",
                        "tags": {
                            "key1": "value1"
                        }
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Firewalls
>  * ## Myazurefirewall
>    * etag: W/"3c426480-93a2-4db2-93d9-d3f0cbfd45ba"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall
>    * location: australiasoutheast
>    * name: myAzureFirewall
>    * provisioning_state: Succeeded
>    * ### Ip_Configurations
>    * ### Azurefirewallipconfiguration
>      * etag: W/"3c426480-93a2-4db2-93d9-d3f0cbfd45ba"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/azureFirewalls/myAzureFirewall/azureFirewallIpConfigurations/azureFirewallIpConfiguration
>      * name: azureFirewallIpConfiguration
>      * type: Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations
>      * #### Properties
>        * privateIPAddress: 10.0.2.4
>        * privateIPAllocationMethod: Dynamic
>        * provisioningState: Succeeded
>        * ##### Publicipaddress
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/myPublicIpAddress
>        * ##### Subnet
>          * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet
>    * ### Nat_Rule_Collections
>    * ### Network_Rule_Collections
>    * ### Tags
>      * key1: value1


### azure-rm-virtualnetwork
***
Manage Azure virtual networks
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetwork_module.html


#### Base Command

`azure-rm-virtualnetwork`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| address_prefixes_cidr | List of IPv4 address ranges where each is formatted using CIDR notation. Required when creating a new virtual network or using `purge_address_prefixes`. | Optional | 
| dns_servers | Custom list of DNS servers. Maximum length of two. The first server in the list will be treated as the Primary server. This is an explicit list. Existing DNS servers will be replaced with the specified list. Use the `purge_dns_servers` option to remove all custom DNS servers and revert to default Azure servers. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| name | Name of the virtual network. | Required | 
| purge_address_prefixes | Use with `state=present` to remove any existing `address_prefixes`. Default is no. | Optional | 
| purge_dns_servers | Use with `state=present` to remove existing DNS servers, reverting to default Azure servers. Mutually exclusive with DNS servers. | Optional | 
| state | State of the virtual network. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmVirtualnetwork.state | unknown | Current state of the virtual network. | 


#### Command Example
```!azure-rm-virtualnetwork resource_group="myResourceGroup" name="myVirtualNetwork" address_prefixes_cidr="{{ ['10.1.0.0/16', '172.100.0.0/16'] }}" dns_servers="{{ ['127.0.0.1', '127.0.0.2'] }}" tags="{{ {'testing': 'testing', 'delete': 'on-exit'} }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmVirtualnetwork": [
            {
                "changed": false,
                "check_mode": false,
                "state": {
                    "address_prefixes": [
                        "10.0.0.0/16",
                        "10.1.0.0/16",
                        "172.100.0.0/16"
                    ],
                    "dns_servers": [
                        "127.0.0.1",
                        "127.0.0.2"
                    ],
                    "etag": "W/\"fb7ef035-16d2-4915-80b7-956c42d7a2fb\"",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork",
                    "location": "australiasoutheast",
                    "name": "myVirtualNetwork",
                    "provisioning_state": "Succeeded",
                    "tags": {
                        "delete": "on-exit",
                        "testing": "testing"
                    },
                    "type": "Microsoft.Network/virtualNetworks"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * check_mode: False
>  * ## State
>    * etag: W/"fb7ef035-16d2-4915-80b7-956c42d7a2fb"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork
>    * location: australiasoutheast
>    * name: myVirtualNetwork
>    * provisioning_state: Succeeded
>    * type: Microsoft.Network/virtualNetworks
>    * ### Address_Prefixes
>      * 0: 10.0.0.0/16
>      * 1: 10.1.0.0/16
>      * 2: 172.100.0.0/16
>    * ### Dns_Servers
>      * 0: 127.0.0.1
>      * 1: 127.0.0.2
>    * ### Tags
>      * delete: on-exit
>      * testing: testing


### azure-rm-virtualnetwork-info
***
Get virtual network facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetwork_info_module.html


#### Base Command

`azure-rm-virtualnetwork-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific security group. | Optional | 
| resource_group | Limit results by resource group. Required when filtering by name. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmVirtualnetworkInfo.azure_virtualnetworks | unknown | List of virtual network dicts. | 
| AzureNetworking.azureRmVirtualnetworkInfo.virtualnetworks | unknown | List of virtual network dicts with same format as \`azure_rm_virtualnetwork\` module parameters. | 


#### Command Example
```!azure-rm-virtualnetwork-info resource_group="myResourceGroup" name="myVirtualNetwork" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmVirtualnetworkInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "virtualnetworks": [
                    {
                        "address_prefixes": [
                            "10.0.0.0/16",
                            "10.1.0.0/16",
                            "172.100.0.0/16"
                        ],
                        "dns_servers": [
                            "127.0.0.1",
                            "127.0.0.2"
                        ],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork",
                        "location": "australiasoutheast",
                        "name": "myVirtualNetwork",
                        "provisioning_state": "Succeeded",
                        "subnets": [
                            {
                                "address_prefix": "10.0.0.0/24",
                                "address_prefixes": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/default",
                                "name": "default",
                                "network_security_group": null,
                                "provisioning_state": "Succeeded",
                                "route_table": null
                            },
                            {
                                "address_prefix": "10.1.0.0/24",
                                "address_prefixes": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                                "name": "mySubnet",
                                "network_security_group": null,
                                "provisioning_state": "Succeeded",
                                "route_table": null
                            },
                            {
                                "address_prefix": "10.0.1.0/24",
                                "address_prefixes": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/GatewaySubnet",
                                "name": "GatewaySubnet",
                                "network_security_group": null,
                                "provisioning_state": "Succeeded",
                                "route_table": null
                            },
                            {
                                "address_prefix": "10.0.2.0/24",
                                "address_prefixes": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet",
                                "name": "AzureFirewallSubnet",
                                "network_security_group": null,
                                "provisioning_state": "Succeeded",
                                "route_table": null
                            }
                        ],
                        "tags": {
                            "delete": "on-exit",
                            "testing": "testing"
                        }
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Virtualnetworks
>  * ## Myvirtualnetwork
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork
>    * location: australiasoutheast
>    * name: myVirtualNetwork
>    * provisioning_state: Succeeded
>    * ### Address_Prefixes
>      * 0: 10.0.0.0/16
>      * 1: 10.1.0.0/16
>      * 2: 172.100.0.0/16
>    * ### Dns_Servers
>      * 0: 127.0.0.1
>      * 1: 127.0.0.2
>    * ### Subnets
>    * ### Default
>      * address_prefix: 10.0.0.0/24
>      * address_prefixes: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/default
>      * name: default
>      * network_security_group: None
>      * provisioning_state: Succeeded
>      * route_table: None
>    * ### Mysubnet
>      * address_prefix: 10.1.0.0/24
>      * address_prefixes: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>      * name: mySubnet
>      * network_security_group: None
>      * provisioning_state: Succeeded
>      * route_table: None
>    * ### Gatewaysubnet
>      * address_prefix: 10.0.1.0/24
>      * address_prefixes: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/GatewaySubnet
>      * name: GatewaySubnet
>      * network_security_group: None
>      * provisioning_state: Succeeded
>      * route_table: None
>    * ### Azurefirewallsubnet
>      * address_prefix: 10.0.2.0/24
>      * address_prefixes: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/AzureFirewallSubnet
>      * name: AzureFirewallSubnet
>      * network_security_group: None
>      * provisioning_state: Succeeded
>      * route_table: None
>    * ### Tags
>      * delete: on-exit
>      * testing: testing


### azure-rm-virtualnetworkgateway
***
Manage Azure virtual network gateways
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetworkgateway_module.html


#### Base Command

`azure-rm-virtualnetworkgateway`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where VPN Gateway exists or will be created. | Required | 
| name | Name of VPN Gateway. | Required | 
| state | State of the VPN Gateway. Use `present` to create or update VPN gateway and `absent` to delete VPN gateway. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| virtual_network | An existing virtual network with which the VPN Gateway will be associated. Required when creating a VPN Gateway. Can be the name of the virtual network. Must be in the same resource group as VPN gateway when specified by name. Can be the resource ID of the virtual network. Can be a dict which contains `name` and `resource_group` of the virtual network. | Required | 
| ip_configurations | List of IP configurations. | Optional | 
| gateway_type | The type of this virtual network gateway. Possible values are: vpn, express_route. Default is vpn. | Optional | 
| vpn_type | The type of this virtual private network. Possible values are: route_based, policy_based. Default is route_based. | Optional | 
| enable_bgp | Whether BGP is enabled for this virtual network gateway or not. Possible values are: Yes, No. Default is No. | Optional | 
| sku | The reference of the VirtualNetworkGatewaySku resource which represents the SKU selected for Virtual network gateway. Possible values are: VpnGw1, VpnGw2, VpnGw3. Default is VpnGw1. | Optional | 
| bgp_settings | Virtual network gateway's BGP speaker settings. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmVirtualnetworkgateway.id | string | Virtual Network Gateway resource ID. | 


#### Command Example
```!azure-rm-virtualnetworkgateway resource_group="myResourceGroup" name="myVirtualNetworkGateway" ip_configurations="{{ [{'name': 'testipconfig', 'private_ip_allocation_method': 'Dynamic', 'public_ip_address_name': 'testipaddr'}] }}" virtual_network="myVirtualNetwork" tags="{{ {'common': 'xyz'} }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmVirtualnetworkgateway": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworkGateways/myVirtualNetworkGateway",
                "state": {},
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworkGateways/myVirtualNetworkGateway
>  * ## State


### azure-rm-virtualnetworkpeering
***
Manage Azure Virtual Network Peering
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetworkpeering_module.html


#### Base Command

`azure-rm-virtualnetworkpeering`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the vnet exists. | Required | 
| name | Name of the virtual network peering. | Required | 
| virtual_network | Name or resource ID of the virtual network to be peered. | Required | 
| remote_virtual_network | Remote virtual network to be peered. It can be name of remote virtual network in same resource group. It can be remote virtual network resource ID. It can be a dict which contains `name` and `resource_group` of remote virtual network. Required when creating. | Optional | 
| allow_virtual_network_access | Allows VMs in the remote VNet to access all VMs in the local VNet. Possible values are: Yes, No. Default is No. | Optional | 
| allow_forwarded_traffic | Allows forwarded traffic from the VMs in the remote VNet. Possible values are: Yes, No. Default is No. | Optional | 
| use_remote_gateways | If remote gateways can be used on this virtual network. Possible values are: Yes, No. Default is No. | Optional | 
| allow_gateway_transit | Allows VNet to use the remote VNet's gateway. Remote VNet gateway must have --allow-gateway-transit enabled for remote peering. Only 1 peering can have this flag enabled. Cannot be set if the VNet already has a gateway. Possible values are: Yes, No. Default is No. | Optional | 
| state | State of the virtual network peering. Use `present` to create or update a peering and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmVirtualnetworkpeering.id | string | ID of the Azure virtual network peering. | 


#### Command Example
```!azure-rm-virtualnetworkpeering resource_group="myResourceGroup" virtual_network="myVirtualNetwork" name="myPeering" remote_virtual_network="{{ {'resource_group': 'mySecondResourceGroup', 'name': 'myRemoteVirtualNetwork'} }}" allow_virtual_network_access="False" allow_forwarded_traffic="True" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmVirtualnetworkpeering": [
            {
                "changed": false,
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False


### azure-rm-virtualnetworkpeering-info
***
Get facts of Azure Virtual Network Peering
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_virtualnetworkpeering_info_module.html


#### Base Command

`azure-rm-virtualnetworkpeering-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the vnet exists. | Required | 
| virtual_network | Name or resource ID of a virtual network. | Required | 
| name | Name of the virtual network peering. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmVirtualnetworkpeeringInfo.vnetpeerings | unknown | A list of Virtual Network Peering facts. | 


#### Command Example
```!azure-rm-virtualnetworkpeering-info resource_group="myResourceGroup" virtual_network="myVirtualNetwork" name="myPeering" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmVirtualnetworkpeeringInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "vnetpeerings": [
                    {
                        "allow_forwarded_traffic": true,
                        "allow_gateway_transit": false,
                        "allow_virtual_network_access": false,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/virtualNetworkPeerings/myPeering",
                        "name": "myPeering",
                        "peering_state": "Initiated",
                        "provisioning_state": "Succeeded",
                        "remote_address_space": {
                            "address_prefixes": [
                                "10.2.0.0/16"
                            ]
                        },
                        "remote_virtual_network": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/mySecondResourceGroup/providers/Microsoft.Network/virtualNetworks/myRemoteVirtualNetwork",
                        "use_remote_gateways": false
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Vnetpeerings
>  * ## Mypeering
>    * allow_forwarded_traffic: True
>    * allow_gateway_transit: False
>    * allow_virtual_network_access: False
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/virtualNetworkPeerings/myPeering
>    * name: myPeering
>    * peering_state: Initiated
>    * provisioning_state: Succeeded
>    * remote_virtual_network: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/mySecondResourceGroup/providers/Microsoft.Network/virtualNetworks/myRemoteVirtualNetwork
>    * use_remote_gateways: False
>    * ### Remote_Address_Space
>      * #### Address_Prefixes
>        * 0: 10.2.0.0/16


### azure-rm-subnet
***
Manage Azure subnets
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_subnet_module.html


#### Base Command

`azure-rm-subnet`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the subnet. | Required | 
| address_prefix_cidr | CIDR defining the IPv4 address space of the subnet. Must be valid within the context of the virtual network. | Optional | 
| security_group | Existing security group with which to associate the subnet. It can be the security group name which is in the same resource group. Can be the resource ID of the security group. Can be a dict containing the `name` and `resource_group` of the security group. | Optional | 
| state | Assert the state of the subnet. Use `present` to create or update a subnet and use `absent` to delete a subnet. Possible values are: absent, present. Default is present. | Optional | 
| virtual_network_name | Name of an existing virtual network with which the subnet is or will be associated. | Required | 
| route_table | The reference of the RouteTable resource. Can be the name or resource ID of the route table. Can be a dict containing the `name` and `resource_group` of the route table. | Optional | 
| service_endpoints | An array of service endpoints. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmSubnet.state | unknown | Current state of the subnet. | 


#### Command Example
```!azure-rm-subnet resource_group="myResourceGroup" virtual_network_name="myVirtualNetwork" name="mySubnet" address_prefix_cidr="10.1.0.0/24" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmSubnet": [
            {
                "changed": false,
                "state": {
                    "address_prefix": "10.1.0.0/24",
                    "address_prefixes": null,
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                    "name": "mySubnet",
                    "network_security_group": {},
                    "private_endpoint_network_policies": "Enabled",
                    "private_link_service_network_policies": "Enabled",
                    "provisioning_state": "Succeeded",
                    "route_table": {}
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * address_prefix: 10.1.0.0/24
>    * address_prefixes: None
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>    * name: mySubnet
>    * private_endpoint_network_policies: Enabled
>    * private_link_service_network_policies: Enabled
>    * provisioning_state: Succeeded
>    * ### Network_Security_Group
>    * ### Route_Table


### azure-rm-subnet-info
***
Get Azure Subnet facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_subnet_info_module.html


#### Base Command

`azure-rm-subnet-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | The name of the resource group. | Required | 
| virtual_network_name | The name of the virtual network. | Required | 
| name | The name of the subnet. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmSubnetInfo.subnets | unknown | A list of dictionaries containing facts for subnet. | 


#### Command Example
```!azure-rm-subnet-info resource_group="myResourceGroup" virtual_network_name="myVirtualNetwork" name="mySubnet" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmSubnetInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "subnets": [
                    {
                        "address_prefix_cidr": "10.1.0.0/24",
                        "address_prefixes_cidr": null,
                        "delegations": [],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                        "name": "mySubnet",
                        "private_endpoint_network_policies": "Enabled",
                        "private_link_service_network_policies": "Enabled",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "route_table": null,
                        "security_group": null,
                        "service_endpoints": null,
                        "virtual_network_name": "myVirtualNetwork"
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Subnets
>  * ## Mysubnet
>    * address_prefix_cidr: 10.1.0.0/24
>    * address_prefixes_cidr: None
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>    * name: mySubnet
>    * private_endpoint_network_policies: Enabled
>    * private_link_service_network_policies: Enabled
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * route_table: None
>    * security_group: None
>    * service_endpoints: None
>    * virtual_network_name: myVirtualNetwork
>    * ### Delegations


### azure-rm-trafficmanagerendpoint
***
Manage Azure Traffic Manager endpoint
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerendpoint_module.html


#### Base Command

`azure-rm-trafficmanagerendpoint`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the Traffic Manager endpoint exists or will be created. | Required | 
| name | The name of the endpoint. | Required | 
| profile_name | Name of Traffic Manager profile where this endpoints attaches to. | Required | 
| type | The type of the endpoint. Possible values are: azure_endpoints, external_endpoints, nested_endpoints. | Required | 
| target_resource_id | The Azure Resource URI of the of the endpoint. Not applicable to endpoints of `type=external_endpoints`. | Optional | 
| target | The fully-qualified DNS name of the endpoint. | Optional | 
| enabled | The status of the endpoint. Possible values are: Yes, No. Default is Yes. | Optional | 
| weight | The weight of this endpoint when traffic manager profile has routing_method of `weighted`. Possible values are from 1 to 1000. | Optional | 
| priority | The priority of this endpoint when traffic manager profile has routing_method of `priority`. Possible values are from 1 to 1000, lower values represent higher priority. This is an optional parameter. If specified, it must be specified on all endpoints. No two endpoints can share the same priority value. | Optional | 
| location | Specifies the location of the external or nested endpoints when using the 'Performance' traffic routing method. | Optional | 
| min_child_endpoints | The minimum number of endpoints that must be available in the child profile in order for the parent profile to be considered available. Only applicable to endpoint of `type=nested_endpoints`. | Optional | 
| geo_mapping | The list of countries/regions mapped to this endpoint when traffic manager profile has routing_method of `geographic`. | Optional | 
| state | Assert the state of the Traffic Manager endpoint. Use `present` to create or update a Traffic Manager endpoint and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmTrafficmanagerendpoint.id | string | The ID of the traffic manager endpoint. | 


#### Command Example
```!azure-rm-trafficmanagerendpoint resource_group="myResourceGroup" profile_name="tmtest" name="testendpoint1" type="external_endpoints" location="westus" priority="2" weight="1" target="1.2.3.4" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmTrafficmanagerendpoint": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1


### azure-rm-trafficmanagerendpoint-info
***
Get Azure Traffic Manager endpoint facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerendpoint_info_module.html


#### Base Command

`azure-rm-trafficmanagerendpoint-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific Traffic Manager endpoint. | Optional | 
| resource_group | The resource group to search for the desired Traffic Manager profile. | Required | 
| profile_name | Name of Traffic Manager Profile. | Required | 
| type | Type of endpoint. Possible values are: azure_endpoints, external_endpoints, nested_endpoints. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmTrafficmanagerendpointInfo.endpoints | unknown | List of Traffic Manager endpoints. | 


#### Command Example
```!azure-rm-trafficmanagerendpoint-info resource_group="myResourceGroup" profile_name="tmtest" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmTrafficmanagerendpointInfo": [
            {
                "changed": false,
                "endpoints": [
                    {
                        "enabled": true,
                        "geo_mapping": null,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1",
                        "location": "West US",
                        "min_child_endpoints": null,
                        "monitor_status": "Degraded",
                        "name": "testendpoint1",
                        "priority": 2,
                        "resource_group": "myResourceGroup",
                        "target": "1.2.3.4",
                        "target_resource_id": null,
                        "type": "external_endpoints",
                        "weight": 1
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Endpoints
>  * ## Testendpoint1
>    * enabled: True
>    * geo_mapping: None
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1
>    * location: West US
>    * min_child_endpoints: None
>    * monitor_status: Degraded
>    * name: testendpoint1
>    * priority: 2
>    * resource_group: myResourceGroup
>    * target: 1.2.3.4
>    * target_resource_id: None
>    * type: external_endpoints
>    * weight: 1


### azure-rm-trafficmanagerprofile
***
Manage Azure Traffic Manager profile
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerprofile_module.html


#### Base Command

`azure-rm-trafficmanagerprofile`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the Traffic Manager profile exists or will be created. | Required | 
| name | Name of the Traffic Manager profile. | Required | 
| state | Assert the state of the Traffic Manager profile. Use `present` to create or update a Traffic Manager profile and `absent` to delete it. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to `global` because in default public Azure cloud, Traffic Manager profile can only be deployed globally. Reference `https://docs.microsoft.com/en-us/azure/traffic-manager/quickstart-create-traffic-manager-profile#create-a-traffic-manager-profile`. Default is global. | Optional | 
| profile_status | The status of the Traffic Manager profile. Possible values are: enabled, disabled. Default is enabled. | Optional | 
| routing_method | The traffic routing method of the Traffic Manager profile. Possible values are: performance, priority, weighted, geographic. Default is performance. | Optional | 
| dns_config | The DNS settings of the Traffic Manager profile. | Optional | 
| monitor_config | The endpoint monitoring settings of the Traffic Manager profile. Default is {'protocol': 'HTTP', 'port': 80, 'path': '/'}. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmTrafficmanagerprofile.id | string | The ID of the traffic manager profile. | 
| AzureNetworking.azureRmTrafficmanagerprofile.endpoints | unknown | List of endpoint IDs attached to the profile. | 


#### Command Example
```!azure-rm-trafficmanagerprofile name="tmtest" resource_group="myResourceGroup" location="global" profile_status="enabled" routing_method="priority" dns_config="{{ {'relative_name': 'xsoartmtest', 'ttl': 60} }}" monitor_config="{{ {'protocol': 'HTTPS', 'port': 80, 'path': '/'} }}" tags="{{ {'Environment': 'Test'} }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmTrafficmanagerprofile": [
            {
                "changed": false,
                "endpoints": [
                    "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1"
                ],
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest
>  * ## Endpoints
>    * 0: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1


### azure-rm-trafficmanagerprofile-info
***
Get Azure Traffic Manager profile facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_trafficmanagerprofile_info_module.html


#### Base Command

`azure-rm-trafficmanagerprofile-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific Traffic Manager profile. | Optional | 
| resource_group | The resource group to search for the desired Traffic Manager profile. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmTrafficmanagerprofileInfo.tms | unknown | List of Traffic Manager profiles. | 


#### Command Example
```!azure-rm-trafficmanagerprofile-info ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmTrafficmanagerprofileInfo": [
            {
                "changed": false,
                "status": "SUCCESS",
                "tms": [
                    {
                        "dns_config": {
                            "fqdn": "xsoartmtest.trafficmanager.net",
                            "relative_name": "xsoartmtest",
                            "ttl": 60
                        },
                        "endpoints": [
                            {
                                "geo_mapping": null,
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1",
                                "location": "West US",
                                "min_child_endpoints": null,
                                "name": "testendpoint1",
                                "priority": 2,
                                "status": "Enabled",
                                "target": "1.2.3.4",
                                "target_resource_id": null,
                                "type": "external_endpoints",
                                "weight": 1
                            }
                        ],
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest",
                        "location": "global",
                        "monitor_config": {
                            "interval": 30,
                            "path": "/",
                            "port": 80,
                            "profile_monitor_status": null,
                            "protocol": "HTTPS",
                            "timeout": 10,
                            "tolerated_failures": 3
                        },
                        "name": "tmtest",
                        "profile_status": "Enabled",
                        "resource_group": "myresourcegroup",
                        "routing_method": "priority",
                        "state": "present",
                        "tags": {
                            "Environment": "Test"
                        }
                    }
                ]
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Tms
>  * ## Tmtest
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest
>    * location: global
>    * name: tmtest
>    * profile_status: Enabled
>    * resource_group: myresourcegroup
>    * routing_method: priority
>    * state: present
>    * ### Dns_Config
>      * fqdn: xsoartmtest.trafficmanager.net
>      * relative_name: xsoartmtest
>      * ttl: 60
>    * ### Endpoints
>    * ### Testendpoint1
>      * geo_mapping: None
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/trafficManagerProfiles/tmtest/externalEndpoints/testendpoint1
>      * location: West US
>      * min_child_endpoints: None
>      * name: testendpoint1
>      * priority: 2
>      * status: Enabled
>      * target: 1.2.3.4
>      * target_resource_id: None
>      * type: external_endpoints
>      * weight: 1
>    * ### Monitor_Config
>      * interval: 30
>      * path: /
>      * port: 80
>      * profile_monitor_status: None
>      * protocol: HTTPS
>      * timeout: 10
>      * tolerated_failures: 3
>    * ### Tags
>      * Environment: Test


### azure-rm-networkinterface
***
Manage Azure network interfaces
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_networkinterface_module.html


#### Base Command

`azure-rm-networkinterface`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of a resource group where the network interface exists or will be created. | Required | 
| name | Name of the network interface. | Required | 
| state | Assert the state of the network interface. Use `present` to create or update an interface and `absent` to delete an interface. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| virtual_network | An existing virtual network with which the network interface will be associated. Required when creating a network interface. It can be the virtual network's name. Make sure your virtual network is in the same resource group as NIC when you give only the name. It can be the virtual network's resource id. It can be a dict which contains `name` and `resource_group` of the virtual network. | Required | 
| subnet_name | Name of an existing subnet within the specified virtual network. Required when creating a network interface. Use the `virtual_network`'s resource group. | Required | 
| os_type | Determines any rules to be added to a default security group. When creating a network interface, if no security group name is provided, a default security group will be created. If the `os_type=Windows`, a rule allowing RDP access will be added. If the `os_type=Linux`, a rule allowing SSH access will be added. Possible values are: Windows, Linux. Default is Linux. | Optional | 
| private_ip_address | (Deprecate) Valid IPv4 address that falls within the specified subnet. This option will be deprecated in 2.9, use `ip_configurations` instead. | Optional | 
| private_ip_allocation_method | (Deprecate) Whether or not the assigned IP address is permanent. When creating a network interface, if you specify `private_ip_address=Static`, you must provide a value for `private_ip_address`. You can update the allocation method to `Static` after a dynamic private IP address has been assigned. This option will be deprecated in 2.9, use `ip_configurations` instead. Possible values are: Dynamic, Static. Default is Dynamic. | Optional | 
| public_ip | (Deprecate) When creating a network interface, if no public IP address name is provided a default public IP address will be created. Set to `false` if you do not want a public IP address automatically created. This option will be deprecated in 2.9, use `ip_configurations` instead. Default is yes. | Optional | 
| public_ip_address_name | (Deprecate) Name of an existing public IP address object to associate with the security group. This option will be deprecated in 2.9, use `ip_configurations` instead. | Optional | 
| public_ip_allocation_method | (Deprecate) If a `public_ip_address_name` is not provided, a default public IP address will be created. The allocation method determines whether or not the public IP address assigned to the network interface is permanent. This option will be deprecated in 2.9, use `ip_configurations` instead. Possible values are: Dynamic, Static. Default is Dynamic. | Optional | 
| ip_configurations | List of IP configurations. Each configuration object should include field `private_ip_address`, `private_ip_allocation_method`, `public_ip_address_name`, `public_ip`, `public_ip_allocation_method`, `name`. | Optional | 
| enable_accelerated_networking | Whether the network interface should be created with the accelerated networking feature or not. Possible values are: Yes, No. Default is No. | Optional | 
| create_with_security_group | Whether a security group should be be created with the NIC. If this flag set to `True` and no `security_group` set, a default security group will be created. Possible values are: Yes, No. Default is Yes. | Optional | 
| security_group | An existing security group with which to associate the network interface. If not provided, a default security group will be created when `create_with_security_group=true`. It can be the name of security group. Make sure the security group is in the same resource group when you only give its name. It can be the resource id. It can be a dict contains security_group's `name` and `resource_group`. | Optional | 
| open_ports | When a default security group is created for a Linux host a rule will be added allowing inbound TCP connections to the default SSH port `22`, and for a Windows host rules will be added allowing inbound access to RDP ports `3389` and `5986`. Override the default ports by providing a list of open ports. | Optional | 
| enable_ip_forwarding | Whether to enable IP forwarding. Possible values are: Yes, No. Default is No. | Optional | 
| dns_servers | Which DNS servers should the NIC lookup. List of IP addresses. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmNetworkinterface.state | unknown | The current state of the network interface. | 


#### Command Example
```!azure-rm-networkinterface name="nic001" resource_group="myResourceGroup" virtual_network="myVirtualNetwork" subnet_name="mySubnet" ip_configurations="{{ [{'name': 'ipconfig1', 'public_ip_address_name': 'publicip001', 'primary': True}] }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmNetworkinterface": [
            {
                "changed": false,
                "state": {
                    "dns_servers": [],
                    "dns_settings": {
                        "applied_dns_servers": [],
                        "dns_servers": [],
                        "internal_dns_name_label": null,
                        "internal_fqdn": null
                    },
                    "enable_accelerated_networking": false,
                    "enable_ip_forwarding": false,
                    "etag": "W/\"165cdc7d-852f-4e0c-af11-0511290660a3\"",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001",
                    "ip_configuration": {
                        "application_security_groups": null,
                        "load_balancer_backend_address_pools": null,
                        "name": "ipconfig1",
                        "primary": true,
                        "private_ip_address": "10.1.0.4",
                        "private_ip_allocation_method": "Dynamic",
                        "public_ip_address": {
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001",
                            "name": "publicip001",
                            "public_ip_allocation_method": null
                        },
                        "subnet": {
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                            "name": "mySubnet",
                            "resource_group": "myResourceGroup",
                            "virtual_network_name": "myVirtualNetwork"
                        }
                    },
                    "ip_configurations": [
                        {
                            "application_security_groups": null,
                            "load_balancer_backend_address_pools": null,
                            "name": "ipconfig1",
                            "primary": true,
                            "private_ip_address": "10.1.0.4",
                            "private_ip_allocation_method": "Dynamic",
                            "public_ip_address": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001",
                                "name": "publicip001",
                                "public_ip_allocation_method": null
                            },
                            "subnet": {
                                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet",
                                "name": "mySubnet",
                                "resource_group": "myResourceGroup",
                                "virtual_network_name": "myVirtualNetwork"
                            }
                        }
                    ],
                    "location": "australiasoutheast",
                    "mac_address": null,
                    "name": "nic001",
                    "network_security_group": {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001",
                        "name": "nic001"
                    },
                    "provisioning_state": "Succeeded",
                    "tags": {},
                    "type": "Microsoft.Network/networkInterfaces"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * enable_accelerated_networking: False
>    * enable_ip_forwarding: False
>    * etag: W/"165cdc7d-852f-4e0c-af11-0511290660a3"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001
>    * location: australiasoutheast
>    * mac_address: None
>    * name: nic001
>    * provisioning_state: Succeeded
>    * type: Microsoft.Network/networkInterfaces
>    * ### Dns_Servers
>    * ### Dns_Settings
>      * internal_dns_name_label: None
>      * internal_fqdn: None
>      * #### Applied_Dns_Servers
>      * #### Dns_Servers
>    * ### Ip_Configuration
>      * application_security_groups: None
>      * load_balancer_backend_address_pools: None
>      * name: ipconfig1
>      * primary: True
>      * private_ip_address: 10.1.0.4
>      * private_ip_allocation_method: Dynamic
>      * #### Public_Ip_Address
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001
>        * name: publicip001
>        * public_ip_allocation_method: None
>      * #### Subnet
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>        * name: mySubnet
>        * resource_group: myResourceGroup
>        * virtual_network_name: myVirtualNetwork
>    * ### Ip_Configurations
>    * ### Ipconfig1
>      * application_security_groups: None
>      * load_balancer_backend_address_pools: None
>      * name: ipconfig1
>      * primary: True
>      * private_ip_address: 10.1.0.4
>      * private_ip_allocation_method: Dynamic
>      * #### Public_Ip_Address
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001
>        * name: publicip001
>        * public_ip_allocation_method: None
>      * #### Subnet
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/virtualNetworks/myVirtualNetwork/subnets/mySubnet
>        * name: mySubnet
>        * resource_group: myResourceGroup
>        * virtual_network_name: myVirtualNetwork
>    * ### Network_Security_Group
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001
>      * name: nic001
>    * ### Tags


### azure-rm-networkinterface-info
***
Get network interface facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_networkinterface_info_module.html


#### Base Command

`azure-rm-networkinterface-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific network interface. | Optional | 
| resource_group | Name of the resource group containing the network interface(s). Required when searching by name. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmNetworkinterfaceInfo.azure_networkinterfaces | unknown | List of network interface dicts. | 
| AzureNetworking.azureRmNetworkinterfaceInfo.networkinterfaces | unknown | List of network interface dicts. Each dict contains parameters can be passed to \`azure_rm_networkinterface\` module. | 


#### Command Example
```!azure-rm-networkinterface-info resource_group="myResourceGroup" name="nic001" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmNetworkinterfaceInfo": [
            {
                "changed": false,
                "networkinterfaces": [
                    {
                        "dns_servers": [],
                        "dns_settings": {
                            "applied_dns_servers": [],
                            "dns_servers": [],
                            "internal_dns_name_label": null,
                            "internal_fqdn": null
                        },
                        "enable_accelerated_networking": false,
                        "enable_ip_forwarding": false,
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001",
                        "ip_configurations": [
                            {
                                "application_security_groups": null,
                                "load_balancer_backend_address_pools": null,
                                "name": "ipconfig1",
                                "primary": true,
                                "private_ip_address": "10.1.0.4",
                                "private_ip_allocation_method": "Dynamic",
                                "public_ip_address": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001",
                                "public_ip_allocation_method": null
                            }
                        ],
                        "location": "australiasoutheast",
                        "mac_address": null,
                        "name": "nic001",
                        "provisioning_state": "Succeeded",
                        "resource_group": "myResourceGroup",
                        "security_group": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001",
                        "subnet": "mySubnet",
                        "tags": null,
                        "virtual_network": {
                            "name": "myVirtualNetwork",
                            "resource_group": "myResourceGroup"
                        }
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Networkinterfaces
>  * ## Nic001
>    * enable_accelerated_networking: False
>    * enable_ip_forwarding: False
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkInterfaces/nic001
>    * location: australiasoutheast
>    * mac_address: None
>    * name: nic001
>    * provisioning_state: Succeeded
>    * resource_group: myResourceGroup
>    * security_group: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/nic001
>    * subnet: mySubnet
>    * tags: None
>    * ### Dns_Servers
>    * ### Dns_Settings
>      * internal_dns_name_label: None
>      * internal_fqdn: None
>      * #### Applied_Dns_Servers
>      * #### Dns_Servers
>    * ### Ip_Configurations
>    * ### Ipconfig1
>      * application_security_groups: None
>      * load_balancer_backend_address_pools: None
>      * name: ipconfig1
>      * primary: True
>      * private_ip_address: 10.1.0.4
>      * private_ip_allocation_method: Dynamic
>      * public_ip_address: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/publicip001
>      * public_ip_allocation_method: None
>    * ### Virtual_Network
>      * name: myVirtualNetwork
>      * resource_group: myResourceGroup


### azure-rm-publicipaddress
***
Manage Azure Public IP Addresses
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_publicipaddress_module.html


#### Base Command

`azure-rm-publicipaddress`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group with which the Public IP is associated. | Required | 
| allocation_method | Control whether the assigned Public IP remains permanently assigned to the object. If not set to `Static`, the IP address my changed anytime an associated virtual machine is power cycled. Possible values are: dynamic, static, Static, Dynamic. Default is dynamic. | Optional | 
| domain_name | The customizable portion of the FQDN assigned to public IP address. This is an explicit setting. If no value is provided, any existing value will be removed on an existing public IP. | Optional | 
| name | Name of the Public IP. | Required | 
| state | Assert the state of the Public IP. Use `present` to create or update a and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| location | Valid Azure location. Defaults to location of the resource group. | Optional | 
| sku | The public IP address SKU. Possible values are: basic, standard, Basic, Standard. | Optional | 
| ip_tags | List of IpTag associated with the public IP address. Each element should contain type:value pair. | Optional | 
| idle_timeout | Idle timeout in minutes. | Optional | 
| version | The public IP address version. Possible values are: ipv4, ipv6. Default is ipv4. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmPublicipaddress.state | unknown | Facts about the current state of the object. | 


#### Command Example
```!azure-rm-publicipaddress resource_group="myResourceGroup" name="my_public_ip" allocation_method="static" domain_name="foobar" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmPublicipaddress": [
            {
                "changed": false,
                "state": {
                    "dns_settings": {
                        "domain_name_label": "foobar",
                        "fqdn": "foobar.australiasoutheast.cloudapp.azure.com",
                        "reverse_fqdn": null
                    },
                    "etag": "W/\"1bee56b0-3bdb-45c8-b378-ddc94cc8e504\"",
                    "idle_timeout_in_minutes": 4,
                    "ip_address": "52.189.237.98",
                    "location": "australiasoutheast",
                    "name": "my_public_ip",
                    "provisioning_state": "Succeeded",
                    "public_ip_address_version": "ipv4",
                    "public_ip_allocation_method": "static",
                    "sku": "Basic",
                    "tags": {},
                    "type": "Microsoft.Network/publicIPAddresses"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * etag: W/"1bee56b0-3bdb-45c8-b378-ddc94cc8e504"
>    * idle_timeout_in_minutes: 4
>    * ip_address: 52.189.237.98
>    * location: australiasoutheast
>    * name: my_public_ip
>    * provisioning_state: Succeeded
>    * public_ip_address_version: ipv4
>    * public_ip_allocation_method: static
>    * sku: Basic
>    * type: Microsoft.Network/publicIPAddresses
>    * ### Dns_Settings
>      * domain_name_label: foobar
>      * fqdn: foobar.australiasoutheast.cloudapp.azure.com
>      * reverse_fqdn: None
>    * ### Tags


### azure-rm-publicipaddress-info
***
Get public IP facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_publicipaddress_info_module.html


#### Base Command

`azure-rm-publicipaddress-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific Public IP. | Optional | 
| resource_group | Limit results by resource group. Required when using name parameter. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmPublicipaddressInfo.azure_publicipaddresses | unknown | List of public IP address dicts. Please note that this option will be deprecated in 2.10 when curated format will become the only supported format. | 
| AzureNetworking.azureRmPublicipaddressInfo.publicipaddresses | unknown | List of publicipaddress. Contains the detail which matches azure_rm_publicipaddress parameters. Returned when the format parameter set to curated. | 


#### Command Example
```!azure-rm-publicipaddress-info resource_group="myResourceGroup" name="my_public_ip" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmPublicipaddressInfo": [
            {
                "changed": false,
                "publicipaddresses": [
                    {
                        "allocation_method": "static",
                        "dns_settings": {
                            "domain_name_label": "foobar",
                            "fqdn": "foobar.australiasoutheast.cloudapp.azure.com",
                            "reverse_fqdn": null
                        },
                        "etag": "W/\"1bee56b0-3bdb-45c8-b378-ddc94cc8e504\"",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/my_public_ip",
                        "idle_timeout": 4,
                        "ip_address": "52.189.237.98",
                        "ip_tags": {},
                        "location": "australiasoutheast",
                        "name": "my_public_ip",
                        "provisioning_state": "Succeeded",
                        "sku": "Basic",
                        "tags": null,
                        "type": "Microsoft.Network/publicIPAddresses",
                        "version": "ipv4"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Publicipaddresses
>  * ## My_Public_Ip
>    * allocation_method: static
>    * etag: W/"1bee56b0-3bdb-45c8-b378-ddc94cc8e504"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/publicIPAddresses/my_public_ip
>    * idle_timeout: 4
>    * ip_address: 52.189.237.98
>    * location: australiasoutheast
>    * name: my_public_ip
>    * provisioning_state: Succeeded
>    * sku: Basic
>    * tags: None
>    * type: Microsoft.Network/publicIPAddresses
>    * version: ipv4
>    * ### Dns_Settings
>      * domain_name_label: foobar
>      * fqdn: foobar.australiasoutheast.cloudapp.azure.com
>      * reverse_fqdn: None
>    * ### Ip_Tags


### azure-rm-route
***
Manage Azure route resource
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_route_module.html


#### Base Command

`azure-rm-route`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the route. | Required | 
| state | Assert the state of the route. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| address_prefix | The destination CIDR to which the route applies. | Optional | 
| next_hop_type | The type of Azure hop the packet should be sent to. Possible values are: virtual_network_gateway, vnet_local, internet, virtual_appliance, none. Default is none. | Optional | 
| next_hop_ip_address | The IP address packets should be forwarded to. Next hop values are only allowed in routes where the next hop type is VirtualAppliance. | Optional | 
| route_table_name | The name of the route table. | Required | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmRoute.id | string | Current state of the route. | 


#### Command Example
```!azure-rm-route resource_group="myResourceGroup" name="myRoute" address_prefix="10.1.0.0/16" next_hop_type="virtual_network_gateway" route_table_name="myRouteTable" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmRoute": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable/routes/myRoute",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable/routes/myRoute


### azure-rm-routetable
***
Manage Azure route table resource
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_routetable_module.html


#### Base Command

`azure-rm-routetable`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| name | Name of the route table. | Required | 
| state | Assert the state of the route table. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| disable_bgp_route_propagation | Specified whether to disable the routes learned by BGP on that route table. Possible values are: Yes, No. Default is No. | Optional | 
| location | Region of the resource. Derived from `resource_group` if not specified. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmRoutetable.changed | boolean | Whether the resource is changed. | 
| AzureNetworking.azureRmRoutetable.id | string | Resource ID. | 


#### Command Example
```!azure-rm-routetable resource_group="myResourceGroup" name="myRouteTable" disable_bgp_route_propagation="False" tags="{{ {'purpose': 'testing'} }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmRoutetable": [
            {
                "changed": false,
                "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable",
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/routeTables/myRouteTable


### azure-rm-routetable-info
***
Get route table facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_routetable_info_module.html


#### Base Command

`azure-rm-routetable-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Limit results to a specific route table. | Optional | 
| resource_group | Limit results in a specific resource group. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmRoutetableInfo.id | string | Resource ID. | 
| AzureNetworking.azureRmRoutetableInfo.name | string | Name of the resource. | 
| AzureNetworking.azureRmRoutetableInfo.resource_group | string | Resource group of the route table. | 
| AzureNetworking.azureRmRoutetableInfo.disable_bgp_route_propagation | boolean | Whether the routes learned by BGP on that route table disabled. | 
| AzureNetworking.azureRmRoutetableInfo.tags | unknown | Tags of the route table. | 
| AzureNetworking.azureRmRoutetableInfo.routes | unknown | Current routes of the route table. | 


#### Command Example
```!azure-rm-routetable-info name="Testing" resource_group="myResourceGroup"```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmRoutetableInfo": [
            {
                "changed": false,
                "route_tables": [],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Route_Tables


### azure-rm-securitygroup
***
Manage Azure network security groups
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_securitygroup_module.html


#### Base Command

`azure-rm-securitygroup`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| default_rules | The set of default rules automatically added to a security group at creation. In general default rules will not be modified. Modify rules to shape the flow of traffic to or from a subnet or NIC. See rules below for the makeup of a rule dict. | Optional | 
| location | Valid azure location. Defaults to location of the resource group. | Optional | 
| name | Name of the security group to operate on. | Optional | 
| purge_default_rules | Remove any existing rules not matching those defined in the default_rules parameter. Default is no. | Optional | 
| purge_rules | Remove any existing rules not matching those defined in the rules parameters. Default is no. | Optional | 
| resource_group | Name of the resource group the security group belongs to. | Required | 
| rules | Set of rules shaping traffic flow to or from a subnet or NIC. Each rule is a dictionary. | Optional | 
| state | Assert the state of the security group. Set to `present` to create or update a security group. Set to `absent` to remove a security group. Possible values are: absent, present. Default is present. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmSecuritygroup.state | unknown | Current state of the security group. | 


#### Command Example
```!azure-rm-securitygroup resource_group="myResourceGroup" name="mysecgroup" purge_rules="True" rules="{{ [{'name': 'DenySSH', 'protocol': 'Tcp', 'destination_port_range': 22, 'access': 'Deny', 'priority': 100, 'direction': 'Inbound'}, {'name': 'AllowSSH', 'protocol': 'Tcp', 'source_address_prefix': ['174.109.158.0/24', '174.109.159.0/24'], 'destination_port_range': 22, 'access': 'Allow', 'priority': 101, 'direction': 'Inbound'}, {'name': 'AllowMultiplePorts', 'protocol': 'Tcp', 'source_address_prefix': ['174.109.158.0/24', '174.109.159.0/24'], 'destination_port_range': [80, 443], 'access': 'Allow', 'priority': 102}] }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmSecuritygroup": [
            {
                "changed": true,
                "state": {
                    "default_rules": [
                        {
                            "access": "Allow",
                            "description": "Allow inbound traffic from all VMs in VNET",
                            "destination_address_prefix": "VirtualNetwork",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound",
                            "name": "AllowVnetInBound",
                            "priority": 65000,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "VirtualNetwork",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Allow",
                            "description": "Allow inbound traffic from azure load balancer",
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowAzureLoadBalancerInBound",
                            "name": "AllowAzureLoadBalancerInBound",
                            "priority": 65001,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "AzureLoadBalancer",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Deny",
                            "description": "Deny all inbound traffic",
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllInBound",
                            "name": "DenyAllInBound",
                            "priority": 65500,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "*",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Allow",
                            "description": "Allow outbound traffic from all VMs to all VMs in VNET",
                            "destination_address_prefix": "VirtualNetwork",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Outbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetOutBound",
                            "name": "AllowVnetOutBound",
                            "priority": 65000,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "VirtualNetwork",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Allow",
                            "description": "Allow outbound traffic from all VMs to Internet",
                            "destination_address_prefix": "Internet",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Outbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowInternetOutBound",
                            "name": "AllowInternetOutBound",
                            "priority": 65001,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "*",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Deny",
                            "description": "Deny all outbound traffic",
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "*",
                            "destination_port_ranges": [],
                            "direction": "Outbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllOutBound",
                            "name": "DenyAllOutBound",
                            "priority": 65500,
                            "protocol": "*",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "*",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        }
                    ],
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup",
                    "location": "australiasoutheast",
                    "name": "mysecgroup",
                    "network_interfaces": [],
                    "rules": [
                        {
                            "access": "Deny",
                            "description": null,
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "22",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH",
                            "name": "DenySSH",
                            "priority": 100,
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": "*",
                            "source_address_prefixes": [],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Allow",
                            "description": null,
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": "22",
                            "destination_port_ranges": [],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowSSH",
                            "name": "AllowSSH",
                            "priority": 101,
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": null,
                            "source_address_prefixes": [
                                "174.109.158.0/24",
                                "174.109.159.0/24"
                            ],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        },
                        {
                            "access": "Allow",
                            "description": null,
                            "destination_address_prefix": "*",
                            "destination_address_prefixes": [],
                            "destination_application_security_groups": null,
                            "destination_port_range": null,
                            "destination_port_ranges": [
                                "80",
                                "443"
                            ],
                            "direction": "Inbound",
                            "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowMultiplePorts",
                            "name": "AllowMultiplePorts",
                            "priority": 102,
                            "protocol": "Tcp",
                            "provisioning_state": "Succeeded",
                            "source_address_prefix": null,
                            "source_address_prefixes": [
                                "174.109.158.0/24",
                                "174.109.159.0/24"
                            ],
                            "source_application_security_groups": null,
                            "source_port_range": "*",
                            "source_port_ranges": []
                        }
                    ],
                    "subnets": [],
                    "tags": {},
                    "type": "Microsoft.Network/networkSecurityGroups"
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * ## State
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup
>    * location: australiasoutheast
>    * name: mysecgroup
>    * type: Microsoft.Network/networkSecurityGroups
>    * ### Default_Rules
>    * ### Allowvnetinbound
>      * access: Allow
>      * description: Allow inbound traffic from all VMs in VNET
>      * destination_address_prefix: VirtualNetwork
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound
>      * name: AllowVnetInBound
>      * priority: 65000
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: VirtualNetwork
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Allowazureloadbalancerinbound
>      * access: Allow
>      * description: Allow inbound traffic from azure load balancer
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowAzureLoadBalancerInBound
>      * name: AllowAzureLoadBalancerInBound
>      * priority: 65001
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: AzureLoadBalancer
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Denyallinbound
>      * access: Deny
>      * description: Deny all inbound traffic
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllInBound
>      * name: DenyAllInBound
>      * priority: 65500
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: *
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Allowvnetoutbound
>      * access: Allow
>      * description: Allow outbound traffic from all VMs to all VMs in VNET
>      * destination_address_prefix: VirtualNetwork
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Outbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetOutBound
>      * name: AllowVnetOutBound
>      * priority: 65000
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: VirtualNetwork
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Allowinternetoutbound
>      * access: Allow
>      * description: Allow outbound traffic from all VMs to Internet
>      * destination_address_prefix: Internet
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Outbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowInternetOutBound
>      * name: AllowInternetOutBound
>      * priority: 65001
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: *
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Denyalloutbound
>      * access: Deny
>      * description: Deny all outbound traffic
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: *
>      * direction: Outbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllOutBound
>      * name: DenyAllOutBound
>      * priority: 65500
>      * protocol: *
>      * provisioning_state: Succeeded
>      * source_address_prefix: *
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Network_Interfaces
>    * ### Rules
>    * ### Denyssh
>      * access: Deny
>      * description: None
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: 22
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH
>      * name: DenySSH
>      * priority: 100
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * source_address_prefix: *
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>      * #### Source_Port_Ranges
>    * ### Allowssh
>      * access: Allow
>      * description: None
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: 22
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowSSH
>      * name: AllowSSH
>      * priority: 101
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * source_address_prefix: None
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>      * #### Source_Address_Prefixes
>        * 0: 174.109.158.0/24
>        * 1: 174.109.159.0/24
>      * #### Source_Port_Ranges
>    * ### Allowmultipleports
>      * access: Allow
>      * description: None
>      * destination_address_prefix: *
>      * destination_application_security_groups: None
>      * destination_port_range: None
>      * direction: Inbound
>      * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowMultiplePorts
>      * name: AllowMultiplePorts
>      * priority: 102
>      * protocol: Tcp
>      * provisioning_state: Succeeded
>      * source_address_prefix: None
>      * source_application_security_groups: None
>      * source_port_range: *
>      * #### Destination_Address_Prefixes
>      * #### Destination_Port_Ranges
>        * 0: 80
>        * 1: 443
>      * #### Source_Address_Prefixes
>        * 0: 174.109.158.0/24
>        * 1: 174.109.159.0/24
>      * #### Source_Port_Ranges
>    * ### Subnets
>    * ### Tags


### azure-rm-securitygroup-info
***
Get security group facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_securitygroup_info_module.html


#### Base Command

`azure-rm-securitygroup-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Only show results for a specific security group. | Optional | 
| resource_group | Name of the resource group to use. | Required | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmSecuritygroupInfo.securitygroups | unknown | List containing security group dicts. | 


#### Command Example
```!azure-rm-securitygroup-info resource_group="myResourceGroup" name="mysecgroup" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmSecuritygroupInfo": [
            {
                "changed": false,
                "securitygroups": [
                    {
                        "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup",
                        "location": "australiasoutheast",
                        "name": "mysecgroup",
                        "properties": {
                            "defaultSecurityRules": [
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound",
                                    "name": "AllowVnetInBound",
                                    "properties": {
                                        "access": "Allow",
                                        "description": "Allow inbound traffic from all VMs in VNET",
                                        "destinationAddressPrefix": "VirtualNetwork",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 65000,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "VirtualNetwork",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowAzureLoadBalancerInBound",
                                    "name": "AllowAzureLoadBalancerInBound",
                                    "properties": {
                                        "access": "Allow",
                                        "description": "Allow inbound traffic from azure load balancer",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 65001,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "AzureLoadBalancer",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllInBound",
                                    "name": "DenyAllInBound",
                                    "properties": {
                                        "access": "Deny",
                                        "description": "Deny all inbound traffic",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 65500,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "*",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetOutBound",
                                    "name": "AllowVnetOutBound",
                                    "properties": {
                                        "access": "Allow",
                                        "description": "Allow outbound traffic from all VMs to all VMs in VNET",
                                        "destinationAddressPrefix": "VirtualNetwork",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Outbound",
                                        "priority": 65000,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "VirtualNetwork",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowInternetOutBound",
                                    "name": "AllowInternetOutBound",
                                    "properties": {
                                        "access": "Allow",
                                        "description": "Allow outbound traffic from all VMs to Internet",
                                        "destinationAddressPrefix": "Internet",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Outbound",
                                        "priority": 65001,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "*",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllOutBound",
                                    "name": "DenyAllOutBound",
                                    "properties": {
                                        "access": "Deny",
                                        "description": "Deny all outbound traffic",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "*",
                                        "destinationPortRanges": [],
                                        "direction": "Outbound",
                                        "priority": 65500,
                                        "protocol": "*",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "*",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                }
                            ],
                            "provisioningState": "Succeeded",
                            "resourceGuid": "2ceea731-b4fb-4999-8ac6-0b6a74a1df94",
                            "securityRules": [
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH",
                                    "name": "DenySSH",
                                    "properties": {
                                        "access": "Deny",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "22",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 100,
                                        "protocol": "Tcp",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefix": "*",
                                        "sourceAddressPrefixes": [],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowSSH",
                                    "name": "AllowSSH",
                                    "properties": {
                                        "access": "Allow",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRange": "22",
                                        "destinationPortRanges": [],
                                        "direction": "Inbound",
                                        "priority": 101,
                                        "protocol": "Tcp",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefixes": [
                                            "174.109.158.0/24",
                                            "174.109.159.0/24"
                                        ],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                },
                                {
                                    "etag": "W/\"eeeac0dc-126e-4b2f-abee-b8247bc16757\"",
                                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowMultiplePorts",
                                    "name": "AllowMultiplePorts",
                                    "properties": {
                                        "access": "Allow",
                                        "destinationAddressPrefix": "*",
                                        "destinationAddressPrefixes": [],
                                        "destinationPortRanges": [
                                            "80",
                                            "443"
                                        ],
                                        "direction": "Inbound",
                                        "priority": 102,
                                        "protocol": "Tcp",
                                        "provisioningState": "Succeeded",
                                        "sourceAddressPrefixes": [
                                            "174.109.158.0/24",
                                            "174.109.159.0/24"
                                        ],
                                        "sourcePortRange": "*",
                                        "sourcePortRanges": []
                                    }
                                }
                            ]
                        },
                        "tags": {},
                        "type": "Microsoft.Network/networkSecurityGroups"
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Securitygroups
>  * ## Mysecgroup
>    * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup
>    * location: australiasoutheast
>    * name: mysecgroup
>    * type: Microsoft.Network/networkSecurityGroups
>    * ### Properties
>      * provisioningState: Succeeded
>      * resourceGuid: 2ceea731-b4fb-4999-8ac6-0b6a74a1df94
>      * #### Defaultsecurityrules
>      * #### Allowvnetinbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetInBound
>        * name: AllowVnetInBound
>        * ##### Properties
>          * access: Allow
>          * description: Allow inbound traffic from all VMs in VNET
>          * destinationAddressPrefix: VirtualNetwork
>          * destinationPortRange: *
>          * direction: Inbound
>          * priority: 65000
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: VirtualNetwork
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Allowazureloadbalancerinbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowAzureLoadBalancerInBound
>        * name: AllowAzureLoadBalancerInBound
>        * ##### Properties
>          * access: Allow
>          * description: Allow inbound traffic from azure load balancer
>          * destinationAddressPrefix: *
>          * destinationPortRange: *
>          * direction: Inbound
>          * priority: 65001
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: AzureLoadBalancer
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Denyallinbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllInBound
>        * name: DenyAllInBound
>        * ##### Properties
>          * access: Deny
>          * description: Deny all inbound traffic
>          * destinationAddressPrefix: *
>          * destinationPortRange: *
>          * direction: Inbound
>          * priority: 65500
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: *
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Allowvnetoutbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowVnetOutBound
>        * name: AllowVnetOutBound
>        * ##### Properties
>          * access: Allow
>          * description: Allow outbound traffic from all VMs to all VMs in VNET
>          * destinationAddressPrefix: VirtualNetwork
>          * destinationPortRange: *
>          * direction: Outbound
>          * priority: 65000
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: VirtualNetwork
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Allowinternetoutbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/AllowInternetOutBound
>        * name: AllowInternetOutBound
>        * ##### Properties
>          * access: Allow
>          * description: Allow outbound traffic from all VMs to Internet
>          * destinationAddressPrefix: Internet
>          * destinationPortRange: *
>          * direction: Outbound
>          * priority: 65001
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: *
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Denyalloutbound
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/defaultSecurityRules/DenyAllOutBound
>        * name: DenyAllOutBound
>        * ##### Properties
>          * access: Deny
>          * description: Deny all outbound traffic
>          * destinationAddressPrefix: *
>          * destinationPortRange: *
>          * direction: Outbound
>          * priority: 65500
>          * protocol: *
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: *
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Securityrules
>      * #### Denyssh
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/DenySSH
>        * name: DenySSH
>        * ##### Properties
>          * access: Deny
>          * destinationAddressPrefix: *
>          * destinationPortRange: 22
>          * direction: Inbound
>          * priority: 100
>          * protocol: Tcp
>          * provisioningState: Succeeded
>          * sourceAddressPrefix: *
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>          * ###### Sourceportranges
>      * #### Allowssh
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowSSH
>        * name: AllowSSH
>        * ##### Properties
>          * access: Allow
>          * destinationAddressPrefix: *
>          * destinationPortRange: 22
>          * direction: Inbound
>          * priority: 101
>          * protocol: Tcp
>          * provisioningState: Succeeded
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>          * ###### Sourceaddressprefixes
>            * 0: 174.109.158.0/24
>            * 1: 174.109.159.0/24
>          * ###### Sourceportranges
>      * #### Allowmultipleports
>        * etag: W/"eeeac0dc-126e-4b2f-abee-b8247bc16757"
>        * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/networkSecurityGroups/mysecgroup/securityRules/AllowMultiplePorts
>        * name: AllowMultiplePorts
>        * ##### Properties
>          * access: Allow
>          * destinationAddressPrefix: *
>          * direction: Inbound
>          * priority: 102
>          * protocol: Tcp
>          * provisioningState: Succeeded
>          * sourcePortRange: *
>          * ###### Destinationaddressprefixes
>          * ###### Destinationportranges
>            * 0: 80
>            * 1: 443
>          * ###### Sourceaddressprefixes
>            * 0: 174.109.158.0/24
>            * 1: 174.109.159.0/24
>          * ###### Sourceportranges
>    * ### Tags


### azure-rm-dnsrecordset
***
Create, delete and update DNS record sets and records
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnsrecordset_module.html


#### Base Command

`azure-rm-dnsrecordset`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Name of resource group. | Required | 
| zone_name | Name of the existing DNS zone in which to manage the record set. | Required | 
| relative_name | Relative name of the record set. | Required | 
| record_type | The type of record set to create or delete. Possible values are: A, AAAA, CNAME, MX, NS, SRV, TXT, PTR, CAA, SOA. | Required | 
| record_mode | Whether existing record values not sent to the module should be purged. Possible values are: append, purge. Default is purge. | Optional | 
| state | Assert the state of the record set. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| time_to_live | Time to live of the record set in seconds. Default is 3600. | Optional | 
| records | List of records to be created depending on the type of record (set). | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmDnsrecordset.state | unknown | Current state of the DNS record set. | 


#### Command Example
```!azure-rm-dnsrecordset resource_group="myResourceGroup" relative_name="www" zone_name="xsoarexample.com" record_type="A" records="{{ [{'entry': '192.168.100.101'}, {'entry': '192.168.100.102'}, {'entry': '192.168.100.103'}] }}" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmDnsrecordset": [
            {
                "changed": false,
                "state": {
                    "arecords": [
                        {
                            "ipv4_address": "192.168.100.101"
                        },
                        {
                            "ipv4_address": "192.168.100.102"
                        },
                        {
                            "ipv4_address": "192.168.100.103"
                        }
                    ],
                    "etag": "97b23b1e-1d39-4340-a97b-325b17725d55",
                    "fqdn": "www.xsoarexample.com.",
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www",
                    "name": "www",
                    "provisioning_state": "Succeeded",
                    "target_resource": {},
                    "ttl": 3600,
                    "type": "A"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## State
>    * etag: 97b23b1e-1d39-4340-a97b-325b17725d55
>    * fqdn: www.xsoarexample.com.
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www
>    * name: www
>    * provisioning_state: Succeeded
>    * ttl: 3600
>    * type: A
>    * ### Arecords
>    * ### List
>      * ipv4_address: 192.168.100.101
>    * ### List
>      * ipv4_address: 192.168.100.102
>    * ### List
>      * ipv4_address: 192.168.100.103
>    * ### Target_Resource


### azure-rm-dnsrecordset-info
***
Get DNS Record Set facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnsrecordset_info_module.html


#### Base Command

`azure-rm-dnsrecordset-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| relative_name | Only show results for a Record Set. | Optional | 
| resource_group | Limit results by resource group. Required when filtering by name or type. | Optional | 
| zone_name | Limit results by zones. Required when filtering by name or type. | Optional | 
| record_type | Limit record sets by record type. | Optional | 
| top | Limit the maximum number of record sets to return. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmDnsrecordsetInfo.azure_dnsrecordset | unknown | List of record set dicts. | 
| AzureNetworking.azureRmDnsrecordsetInfo.dnsrecordsets | unknown | List of record set dicts, which shares the same hierarchy as \`azure_rm_dnsrecordset\` module's parameter. | 


#### Command Example
```!azure-rm-dnsrecordset-info resource_group="myResourceGroup" zone_name="xsoarexample.com" relative_name="www" record_type="A" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmDnsrecordsetInfo": [
            {
                "changed": false,
                "dnsrecordsets": [
                    {
                        "fqdn": "www.xsoarexample.com.",
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www",
                        "provisioning_state": "Succeeded",
                        "record_type": "A",
                        "records": [
                            {
                                "ipv4_address": "192.168.100.101"
                            },
                            {
                                "ipv4_address": "192.168.100.102"
                            },
                            {
                                "ipv4_address": "192.168.100.103"
                            }
                        ],
                        "relative_name": "www",
                        "time_to_live": 3600
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Dnsrecordsets
>  * ## Www
>    * fqdn: www.xsoarexample.com.
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myResourceGroup/providers/Microsoft.Network/dnszones/xsoarexample.com/A/www
>    * provisioning_state: Succeeded
>    * record_type: A
>    * relative_name: www
>    * time_to_live: 3600
>    * ### Records
>    * ### List
>      * ipv4_address: 192.168.100.101
>    * ### List
>      * ipv4_address: 192.168.100.102
>    * ### List
>      * ipv4_address: 192.168.100.103


### azure-rm-dnszone
***
Manage Azure DNS zones
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnszone_module.html


#### Base Command

`azure-rm-dnszone`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | name of resource group. | Required | 
| name | Name of the DNS zone. | Required | 
| state | Assert the state of the zone. Use `present` to create or update and `absent` to delete. Possible values are: absent, present. Default is present. | Optional | 
| type | The type of this DNS zone (`public` or `private`). Possible values are: public, private. | Optional | 
| registration_virtual_networks | A list of references to virtual networks that register hostnames in this DNS zone. This is a only when `type=private`. Each element can be the name or resource id, or a dict contains `name`, `resource_group` information of the virtual network. | Optional | 
| resolution_virtual_networks | A list of references to virtual networks that resolve records in this DNS zone. This is a only when `type=private`. Each element can be the name or resource id, or a dict contains `name`, `resource_group` information of the virtual network. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| tags | Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object will be updated with any provided values. To remove tags set append_tags option to false. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmDnszone.state | unknown | Current state of the zone. | 


#### Command Example
```!azure-rm-dnszone resource_group="myResourceGroup" name="xsoarexample.com" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmDnszone": [
            {
                "changed": false,
                "check_mode": false,
                "state": {
                    "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com",
                    "name": "xsoarexample.com",
                    "name_servers": [
                        "ns1-01.azure-dns.com.",
                        "ns2-01.azure-dns.net.",
                        "ns3-01.azure-dns.org.",
                        "ns4-01.azure-dns.info."
                    ],
                    "number_of_record_sets": 3,
                    "registration_virtual_networks": null,
                    "resolution_virtual_networks": null,
                    "tags": {},
                    "type": "public"
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * check_mode: False
>  * ## State
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com
>    * name: xsoarexample.com
>    * number_of_record_sets: 3
>    * registration_virtual_networks: None
>    * resolution_virtual_networks: None
>    * type: public
>    * ### Name_Servers
>      * 0: ns1-01.azure-dns.com.
>      * 1: ns2-01.azure-dns.net.
>      * 2: ns3-01.azure-dns.org.
>      * 3: ns4-01.azure-dns.info.
>    * ### Tags


### azure-rm-dnszone-info
***
Get DNS zone facts
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/azure_rm_dnszone_info_module.html


#### Base Command

`azure-rm-dnszone-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group | Limit results by resource group. Required when filtering by name. | Optional | 
| name | Only show results for a specific zone. | Optional | 
| tags | Limit results by providing a list of tags. Format tags as 'key' or 'key:value'. | Optional | 
| subscription_id | Your Azure subscription Id. | Optional | 
| append_tags | Use to control if tags field is canonical or just appends to existing tags. When canonical, any tags not found in the tags parameter will be removed from the object's metadata. Possible values are: Yes, No. Default is Yes. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNetworking.azureRmDnszoneInfo.azure_dnszones | unknown | List of zone dicts. | 
| AzureNetworking.azureRmDnszoneInfo.dnszones | unknown | List of zone dicts, which share the same layout as azure_rm_dnszone module parameter. | 


#### Command Example
```!azure-rm-dnszone-info resource_group="myResourceGroup" name="xsoarexample.com" ```

#### Context Example
```json
{
    "azurenetworking": {
        "azureRmDnszoneInfo": [
            {
                "changed": false,
                "dnszones": [
                    {
                        "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com",
                        "max_number_of_record_sets": 10000,
                        "name": "xsoarexample.com",
                        "name_servers": [
                            "ns1-01.azure-dns.com.",
                            "ns2-01.azure-dns.net.",
                            "ns3-01.azure-dns.org.",
                            "ns4-01.azure-dns.info."
                        ],
                        "number_of_record_sets": 3,
                        "registration_virtual_networks": null,
                        "resolution_virtual_networks": null,
                        "tags": {},
                        "type": "public"
                    }
                ],
                "info": {
                    "azure_dnszones": [
                        {
                            "etag": "00000002-0000-0000-2a52-97b25176d701",
                            "id": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com",
                            "location": "global",
                            "name": "xsoarexample.com",
                            "properties": {
                                "maxNumberOfRecordSets": 10000,
                                "nameServers": [
                                    "ns1-01.azure-dns.com.",
                                    "ns2-01.azure-dns.net.",
                                    "ns3-01.azure-dns.org.",
                                    "ns4-01.azure-dns.info."
                                ],
                                "numberOfRecordSets": 3,
                                "zoneType": "Public"
                            },
                            "tags": {},
                            "type": "Microsoft.Network/dnszones"
                        }
                    ]
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Info
>    * ### Azure_Dnszones
>    * ### Xsoarexample.Com
>      * etag: 00000002-0000-0000-2a52-97b25176d701
>      * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com
>      * location: global
>      * name: xsoarexample.com
>      * type: Microsoft.Network/dnszones
>      * #### Properties
>        * maxNumberOfRecordSets: 10000
>        * numberOfRecordSets: 3
>        * zoneType: Public
>        * ##### Nameservers
>          * 0: ns1-01.azure-dns.com.
>          * 1: ns2-01.azure-dns.net.
>          * 2: ns3-01.azure-dns.org.
>          * 3: ns4-01.azure-dns.info.
>      * #### Tags
>  * ## Dnszones
>  * ## Xsoarexample.Com
>    * id: /subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/myresourcegroup/providers/Microsoft.Network/dnszones/xsoarexample.com
>    * max_number_of_record_sets: 10000
>    * name: xsoarexample.com
>    * number_of_record_sets: 3
>    * registration_virtual_networks: None
>    * resolution_virtual_networks: None
>    * type: public
>    * ### Name_Servers
>      * 0: ns1-01.azure-dns.com.
>      * 1: ns2-01.azure-dns.net.
>      * 2: ns3-01.azure-dns.org.
>      * 3: ns4-01.azure-dns.info.
>    * ### Tags

