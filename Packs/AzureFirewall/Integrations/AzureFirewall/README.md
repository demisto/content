Azure Firewall is a cloud-native and intelligent network firewall security service that provides breed threat protection for cloud workloads running in Azure. It's a fully stateful, firewall as a service, with built-in high availability and unrestricted cloud scalability.
This integration was integrated and tested with version 2021-03-01 of Azure Firewall.

## Configure Azure Firewall in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Resource Group Name. |  | True |
| Client ID. |  | True |
| Subscription ID. |  | True |
| Tenant ID. |  | False |
| Client Secret. |  | False |
| Certificate Thumbprint | Used for certificate authentication. As appears in the "Certificates & secrets" page of the app. | False |
| Private Key | Used for certificate authentication. The private key of the registered certificate. | False |
| Use Azure Managed Identities | Relevant only if the integration is running on Azure VM. If selected, authenticates based on the value provided for the Azure Managed Identities Client ID field. If no value is provided for the Azure Managed Identities Client ID field, authenticates based on the System Assigned Managed Identity. For additional information, see the Help tab. | False |
| Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
| Use system proxy settings |  | False |
| Trust any certificate (not secure) |  | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-firewall-auth-test

***
Tests the connectivity to Azure.

#### Base Command

`azure-firewall-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-firewall-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`azure-firewall-auth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-firewall-auth-complete

***
Run this command to complete the authorization process. Should be used after running the azure-firewall-auth-start command.

#### Base Command

`azure-firewall-auth-complete`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-firewall-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-firewall-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### azure-firewall-list

***
List Azure firewalls in the specified resource group or subscription.

#### Base Command

`azure-firewall-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The resource that contains the firewalls to list. Possible values are: resource_group, subscription. Default is resource_group. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Firewall.id | String | Firewall resource ID. | 
| AzureFirewall.Firewall.name | String | Firewall resource name. | 
| AzureFirewall.Firewall.location | String | Firewall resource location. | 

#### Command example
```!azure-firewall-list resource=resource_group limit=1 page=1```
#### Context Example
```json
{
    "AzureFirewall": {
        "Firewall": {
            "etag": "W/\"b4fb1688-7055-40e7-8a5e-d17d81b902ed\"",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip",
            "location": "eastus",
            "name": "test-ip",
            "properties": {
                "additionalProperties": {},
                "applicationRuleCollections": [],
                "ipConfigurations": [
                    {
                        "etag": "W/\"b4fb1688-7055-40e7-8a5e-d17d81b902ed\"",
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip/azureFirewallIpConfigurations/test-ip",
                        "name": "test-ip",
                        "properties": {
                            "privateIPAddress": "189.160.40.11",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "publicIPAddress": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/publicIPAddresses/test-ip"
                            },
                            "subnet": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet"
                            }
                        },
                        "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations"
                    }
                ],
                "natRuleCollections": [],
                "networkRuleCollections": [],
                "provisioningState": "Succeeded",
                "sku": {
                    "name": "AZFW_VNet",
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "tags": {},
            "type": "Microsoft.Network/azureFirewalls"
        }
    }
}
```

#### Human Readable Output

>### Firewall List:
> Current page size: 1
> Showing page 1 out others that may exist.
>
>|Name|Id|Location|Subnet|Threat Intel Mode|Private Ip Address|Provisioning State|
>|---|---|---|---|---|---|---|
>| test-ip | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip | eastus | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet | Alert | 189.160.40.11 | Succeeded |

### azure-firewall-get

***
Retrieve Azure firewall information.

#### Base Command

`azure-firewall-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_names | Comma-separated list of firewall names to retrieve. | Required | 
| polling | Indicates if the command was scheduled. Possible values are: True, False. Default is True. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Firewall.id | String | Firewall resource ID. | 
| AzureFirewall.Firewall.name | String | Firewall resource name. | 
| AzureFirewall.Firewall.location | String | Firewall resource location. | 

#### Command example
```!azure-firewall-get firewall_names=test-ip interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Firewall": {
            "etag": "W/\"b4fb1688-7055-40e7-8a5e-d17d81b902ed\"",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip",
            "location": "eastus",
            "name": "test-ip",
            "properties": {
                "additionalProperties": {},
                "applicationRuleCollections": [],
                "ipConfigurations": [
                    {
                        "etag": "W/\"b4fb1688-7055-40e7-8a5e-d17d81b902ed\"",
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip/azureFirewallIpConfigurations/test-ip",
                        "name": "test-ip",
                        "properties": {
                            "privateIPAddress": "189.160.40.11",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "publicIPAddress": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/publicIPAddresses/test-ip"
                            },
                            "subnet": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet"
                            }
                        },
                        "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations"
                    }
                ],
                "natRuleCollections": [],
                "networkRuleCollections": [],
                "provisioningState": "Succeeded",
                "sku": {
                    "name": "AZFW_VNet",
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "tags": {},
            "type": "Microsoft.Network/azureFirewalls"
        }
    }
}
```

#### Human Readable Output

>### Firewall test-ip information:
>|Name|Id|Location|Subnet|Threat Intel Mode|Private Ip Address|Provisioning State|
>|---|---|---|---|---|---|---|
>| test-ip | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip | eastus | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet | Alert | 189.160.40.11 | Succeeded |

### azure-firewall-rule-collection-list

***
List the collection rules in the firewall or policy. One of the arguments 'firewall_name' or 'policy' must be provided.

#### Base Command

`azure-firewall-rule-collection-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the Azure firewall that contains the collections. | Optional | 
| policy | The name of the Azure policy that contains the collections. | Optional | 
| rule_type | The names of the rule collection type to retrieve. Possible values are: application_rule, network_rule, nat_rule. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.RuleCollection.name | String | Rule collection unique name. | 

#### Command example
```!azure-firewall-rule-collection-list policy=xsoar-policy rule_type=network_rule limit=1 page=1```
#### Context Example
```json
{
    "AzureFirewall": {
        "RuleCollection": {
            "etag": "e09cf677-e019-43f0-98a6-eeee540a74ae",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection",
            "location": "eastus",
            "name": "playbook-collection",
            "properties": {
                "priority": 201,
                "provisioningState": "Succeeded",
                "ruleCollections": [
                    {
                        "action": {
                            "type": "Deny"
                        },
                        "name": "playbook-collection",
                        "priority": 201,
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "rules": [
                            {
                                "description": "test-playbook-collection",
                                "destinationAddresses": [
                                    "189.160.40.11",
                                    "189.160.40.11"
                                ],
                                "destinationFqdns": [],
                                "destinationIpGroups": [],
                                "destinationPorts": [
                                    "8080"
                                ],
                                "ipProtocols": [
                                    "UDP",
                                    "TCP"
                                ],
                                "name": "playbook-rule",
                                "ruleType": "NetworkRule",
                                "sourceAddresses": [
                                    "189.160.40.11",
                                    "189.160.40.11"
                                ],
                                "sourceIpGroups": []
                            }
                        ]
                    }
                ]
            },
            "type": "Microsoft.Network/FirewallPolicies/RuleCollectionGroups"
        }
    }
}
```

#### Human Readable Output

>### xsoar-policy Rule Collections List:
> Current page size: 1
> Showing page 1 out others that may exist.
> 
>|Name|Action|Priority|
>|---|---|---|
>| playbook-collection | Deny | 201 |

### azure-firewall-rule-list

***
List rules in the firewall or in the policy. One of the arguments 'firewall_name' or 'policy' must be provided.

#### Base Command

`azure-firewall-rule-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the Azure firewall that contains the rules. | Optional | 
| policy | The name of the Azure policy that contains the rules. | Optional | 
| rule_type | The names of the rule types to retrieve. Required when the "firewall_name" argument is provided. Possible values are: application_rule, network_rule, nat_rule. | Optional | 
| collection_name | The name of the rule collection that contains the rules. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Rule.name | String | Rule name. | 

#### Command example
```!azure-firewall-rule-list policy=xsoar-policy collection_name=playbook-collection rule_type=network_rule limit=1 page=1```
#### Context Example
```json
{
    "AzureFirewall": {
        "Rule": {
            "description": "test-playbook-collection",
            "destinationAddresses": [
                "189.160.40.11",
                "189.160.40.11"
            ],
            "destinationFqdns": [],
            "destinationIpGroups": [],
            "destinationPorts": [
                "8080"
            ],
            "ipProtocols": [
                "UDP",
                "TCP"
            ],
            "name": "playbook-rule",
            "ruleType": "NetworkRule",
            "sourceAddresses": [
                "189.160.40.11",
                "189.160.40.11"
            ],
            "sourceIpGroups": []
        }
    }
}
```

#### Human Readable Output

>### Policy xsoar-policy network_rule Rules List:
> Current page size: 1
> Showing page 1 out others that may exist.
> 
>|Name|
>|---|
>| playbook-rule |

### azure-firewall-rule-get

***
Retrieve rule information. One of the arguments 'firewall_name' or 'policy' must be provided.

#### Base Command

`azure-firewall-rule-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the rule. | Optional | 
| policy | The name of the Azure policy that contains the rules. | Optional | 
| rule_type | The name of the rule type collection that contains the rule. Required when the "firewall_name" argument is provided. Possible values are: application_rule, network_rule, nat_rule. | Optional | 
| collection_name | The name of the rule collection that contains the rule. | Required | 
| rule_name | The name of the rule to retrieve. | Required | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Rule.name | String | Rule name. | 

#### Command example
```!azure-firewall-rule-get policy=xsoar-policy collection_name=playbook-collection rule_name=new-playbook-rule```
#### Context Example
```json
{
    "AzureFirewall": {
        "Rule": {
            "description": "test-playbook-collection",
            "destinationAddresses": [
                "189.160.40.11",
                "189.160.40.11"
            ],
            "destinationFqdns": [],
            "destinationIpGroups": [],
            "destinationPorts": [
                "8080"
            ],
            "ipProtocols": [
                "UDP"
            ],
            "name": "new-playbook-rule",
            "ruleType": "NetworkRule",
            "sourceAddresses": [
                "189.160.40.11",
                "189.160.40.11"
            ],
            "sourceIpGroups": []
        }
    }
}
```

#### Human Readable Output

>### Rule new-playbook-rule Information:
>|Name|
>|---|
>| new-playbook-rule |

### azure-firewall-policy-create

***
Create a firewall policy. This command only creates the policy resource. In order to attach the policy to a firewall, run the 'azure-firewall-policy-attach' command.

#### Base Command

`azure-firewall-policy-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the Azure policy to create. | Required | 
| threat_intelligence_mode | The operation mode for threat intelligence. Possible values are: Alert, Deny, Turned-off. Default is Turned-off. | Required | 
| ips | Comma-separated list of IP addresses for the threat intelligence whitelist. | Optional | 
| domains | Comma-separated list of fully qualified domain names for the threat intelligence whitelist. For example : *.microsoft.com,email.college.edu . | Optional | 
| location | Policy resource region location. Possible values are: northcentralus, eastus, northeurope, westeurope, eastasia, southeastasia, eastus2, centralus, southcentralus, westus, japaneast, japanwest, australiaeast, australiasoutheast, brazilsouth, centralindia, southindia, westindia, canadacentral, canadaeast, uksouth, ukwest, westcentralus, westus2, koreacentral, francecentral, australiacentral, uaenorth, southafricanorth, switzerlandnorth, germanywestcentral, norwayeast, westus3, jioindiawest. | Required | 
| tier | Tier of an Azure policy. Possible values are: Standard, Premium. Default is Standard. | Required | 
| base_policy_id | The ID of the parent firewall policy from which rules are inherited. | Optional | 
| enable_proxy | Whether to enable the DNS proxy on firewalls attached to the firewall policy. Possible values are: True, False. Default is False. | Optional | 
| dns_servers | Comma-separated list of custom DNS servers. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Policy.id | String | Policy resource ID. | 
| AzureFirewall.Policy.name | String | Policy resource name. | 

#### Command example
```!azure-firewall-policy-create policy_name=xsoar-policy threat_intelligence_mode=Alert location=eastus tier=Standard interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "b5074926-9b59-4ab8-ba44-7fb39a2879a3",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Updating",
                "ruleCollectionGroups": [],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Created Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Updating |

### azure-firewall-policy-update

***
Update the policy resource. The command will update the provided arguments.

#### Base Command

`azure-firewall-policy-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of the Azure policy to update. | Required | 
| threat_intelligence_mode | The operation mode for threat intelligence. Possible values are: Alert, Deny, Turned-off. | Optional | 
| ips | Comma-separated list of IP addresses for the threat intelligence whitelist. | Optional | 
| domains | Comma-separated list of fully qualified domain names for the threat intelligence whitelist. For example : *.microsoft.com,email.college.edu . | Optional | 
| base_policy_id | The ID of the parent firewall policy from which rules are inherited. | Optional | 
| enable_proxy | Whether to enable the DNS Proxy on Firewalls attached to the Firewall Policy. Possible values are: True, False. | Optional | 
| dns_servers | Comma-separated list of custom DNS servers. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Policy.id | String | Policy resource ID. | 
| AzureFirewall.Policy.name | String | Policy resource name. | 

#### Command example
```!azure-firewall-policy-update policy_name=xsoar-policy threat_intelligence_mode=Deny interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "15f105aa-3059-4e9b-97e9-3b85a839ecf3",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Updating",
                "ruleCollectionGroups": [],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Updating |

### azure-firewall-policy-get

***
Retrieve policy information.

#### Base Command

`azure-firewall-policy-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_names | Comma-separated list of policy names to retrieve. | Required | 
| polling | Indicates if the command was scheduled. Possible values are: True, False. Default is True. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Policy.id | String | Policy resource ID. | 
| AzureFirewall.Policy.name | String | Policy resource name. | 

#### Command example
```!azure-firewall-policy-get policy_names=xsoar-policy interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "b5074926-9b59-4ab8-ba44-7fb39a2879a3",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Succeeded",
                "ruleCollectionGroups": [],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Policy xsoar-policy information:
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Succeeded |

### azure-firewall-policy-delete

***
Delete policy resource.

#### Base Command

`azure-firewall-policy-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_names | Comma-separated list of policy names to delete. | Required | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
### azure-firewall-policy-list

***
List the policy in the resource group or subscription.

#### Base Command

`azure-firewall-policy-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The resource that contains the policies to list. Possible values are: resource_group, subscription. Default is resource_group. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Policy.id | String | Policy resource ID. | 
| AzureFirewall.Policy.name | String | Policy resource name. | 
#### Command example
```!azure-firewall-policy-list resource=resource_group limit=1 page=1```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "b5074926-9b59-4ab8-ba44-7fb39a2879a3",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Succeeded",
                "ruleCollectionGroups": [],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Policy List:
> Current page size: 1
> Showing page 1 out others that may exist.
> 
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Succeeded |

### azure-firewall-policy-attach

***
Attach a policy to a firewall. The policy and firewall have to belong to the same tier.

#### Base Command

`azure-firewall-policy-attach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_names | Comma-separated list of firewall names to which the policy will be attached. | Required | 
| policy_id | The ID of the policy to attach. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Firewall.id | String | Firewall resource ID. | 
| AzureFirewall.Firewall.name | String | Firewall resource name. | 
| AzureFirewall.Firewall.location | String | Firewall resource location. | 

#### Command example
```!azure-firewall-policy-attach firewall_names=test-ip policy_id=/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Firewall": {
            "etag": "W/\"03a287f1-5106-426c-b181-166258b1fc6a\"",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip",
            "location": "eastus",
            "name": "test-ip",
            "properties": {
                "additionalProperties": {},
                "applicationRuleCollections": [],
                "firewallPolicy": {
                    "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy"
                },
                "ipConfigurations": [
                    {
                        "etag": "W/\"03a287f1-5106-426c-b181-166258b1fc6a\"",
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip/azureFirewallIpConfigurations/test-ip",
                        "name": "test-ip",
                        "properties": {
                            "privateIPAddress": "189.160.40.11",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "publicIPAddress": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/publicIPAddresses/test-ip"
                            },
                            "subnet": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet"
                            }
                        },
                        "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations"
                    }
                ],
                "natRuleCollections": [],
                "networkRuleCollections": [],
                "provisioningState": "Updating",
                "sku": {
                    "name": "AZFW_VNet",
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "tags": {},
            "type": "Microsoft.Network/azureFirewalls"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Firewall "test-ip"
>|Name|Id|Location|Subnet|Threat Intel Mode|Private Ip Address|Provisioning State|
>|---|---|---|---|---|---|---|
>| test-ip | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip | eastus | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet | Alert | 189.160.40.11 | Updating |

### azure-firewall-policy-detach

***
Remove a policy from the firewall. This command will detach the policy and firewall, but will not delete the policy.

#### Base Command

`azure-firewall-policy-detach`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_names | Comma-separated list of firewall names from which the policy will be removed. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Firewall.id | String | Firewall resource ID. | 
| AzureFirewall.Firewall.name | String | Firewall resource name. | 
| AzureFirewall.Firewall.location | String | Firewall resource location. | 

#### Command example
```!azure-firewall-policy-detach firewall_names=test-ip interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Firewall": {
            "etag": "W/\"f4e53250-f431-437b-a86f-7aa6a34d4616\"",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip",
            "location": "eastus",
            "name": "test-ip",
            "properties": {
                "additionalProperties": {},
                "applicationRuleCollections": [],
                "ipConfigurations": [
                    {
                        "etag": "W/\"f4e53250-f431-437b-a86f-7aa6a34d4616\"",
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip/azureFirewallIpConfigurations/test-ip",
                        "name": "test-ip",
                        "properties": {
                            "privateIPAddress": "189.160.40.11",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "publicIPAddress": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/publicIPAddresses/test-ip"
                            },
                            "subnet": {
                                "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet"
                            }
                        },
                        "type": "Microsoft.Network/azureFirewalls/azureFirewallIpConfigurations"
                    }
                ],
                "natRuleCollections": [],
                "networkRuleCollections": [],
                "provisioningState": "Updating",
                "sku": {
                    "name": "AZFW_VNet",
                    "tier": "Standard"
                },
                "threatIntelMode": "Alert"
            },
            "tags": {},
            "type": "Microsoft.Network/azureFirewalls"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Firewall "test-ip"
>|Name|Id|Location|Subnet|Threat Intel Mode|Private Ip Address|Provisioning State|
>|---|---|---|---|---|---|---|
>| test-ip | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/azureFirewalls/test-ip | eastus | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/virtualNetworks/test-v-n/subnets/AzureFirewallSubnet | Alert | 189.160.40.11 | Updating |

### azure-firewall-network-rule-collection-create

***
Create a network rule collection in a firewall or policy. The command will return firewall or policy rule collection resource information. One of the arguments 'firewall_name' or 'policy'  must be provided.

#### Base Command

`azure-firewall-network-rule-collection-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the collection. | Optional | 
| policy | The name of the policy that contains the collection. | Optional | 
| collection_name | The name of the network rule collection to create. | Required | 
| collection_priority | The priority of the network rule collection resource. Minimum value is 100, maximum value is 65000. | Required | 
| action | The action type of a rule collection. Possible values are: Allow, Deny. | Required | 
| rule_name | The name of the network rule to create. | Required | 
| description | The description of the created rule. | Required | 
| protocols | Comma-separated list of protocols for the created rule. Possible values are: TCP, UDP, ICMP, Any. | Required | 
| source_type | Rule source type. Possible values are: ip_address, ip_group. | Required | 
| source_ips | Comma-separated list of source IP addresses for the created rule. Must be provided when the 'source_type' argument is assigned to 'ip_address'. | Optional | 
| source_ip_group_ids | Comma-separated list of source IP group IDs for the created rule. Must be provided when the 'source_type' argument is assigned to 'ip_group'. | Optional | 
| destination_type | Rule destination type. Possible values are: ip_address, ip_group, service_tag, fqdn. | Required | 
| destinations | Comma-separated list of destinations for the created rule. Must be consistent with the provided 'destination_type' argument. Supports IP addresses, service tag names, IP group IDs and FQDN addresses. | Required | 
| destination_ports | Comma-separated list of destination ports. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-network-rule-collection-create policy=xsoar-policy collection_name=playbook-collection collection_priority=105 action=Allow rule_name=playbook-rule description=test-playbook-collection protocols=UDP,TCP source_type=ip_address source_ips=189.160.40.11,189.160.40.11 destination_type=ip_address destinations=189.160.40.11,189.160.40.11 destination_ports=8080 interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "23384541-d2ae-4922-95ed-9c70ffbe336e",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Updating",
                "ruleCollectionGroups": [
                    {
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection"
                    }
                ],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Updating |

### azure-firewall-network-rule-collection-delete

***
Delete a network rule collection from the firewall or policy. One of the arguments 'firewall_name' or 'policy'  must be provided.

#### Base Command

`azure-firewall-network-rule-collection-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the collection. | Optional | 
| policy | The name of the policy the contains the collection. | Optional | 
| collection_name | The name of the network rule collection to delete. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-network-rule-collection-delete policy=xsoar-policy collection_name=playbook-collection interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "5984cc1d-8e84-4385-adbe-e1d9293d7e97",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Updating",
                "ruleCollectionGroups": [
                    {
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection"
                    }
                ],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Updating |

### azure-firewall-network-rule-create

***
Create a network rule in the firewall or policy rule collection. One of the arguments 'firewall_name' or 'policy'  must be provided.

#### Base Command

`azure-firewall-network-rule-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the collection. | Optional | 
| policy | The name of the policy that contains the collection. | Optional | 
| collection_name | The name of the network rule collection that contains the rule. | Required | 
| rule_name | The name of the network rule to create. | Required | 
| description | The description of the created rule. | Required | 
| protocols | Comma-separated list of protocols for the created rule. Possible values are: TCP, UDP, ICMP, Any. | Required | 
| source_type | Rule source type. Possible values are: ip_address, ip_group. | Required | 
| source_ips | Comma-separated list of source IP addresses for the created rule. Must be provided when the 'source_type' argument is assigned to 'ip_address'. | Optional | 
| source_ip_group_ids | Comma-separated list of source IP group IDs for the created rule. Must be provided when the 'source_type' argument is assigned to 'ip_group'. | Optional | 
| destination_type | Rule destination type. Possible values are: ip_address, ip_group, service_tag, fqdn. | Required | 
| destinations | Comma-separated list of destinations for the created rule. Must be consistent with the provided 'destination_type' argument. Supports IP addresses, service tag names, IP group IDs and FQDN addresses. | Required | 
| destination_ports | Comma-separated list of destination ports. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-network-rule-create policy=xsoar-policy collection_name=playbook-collection rule_name=new-playbook-rule description=test-playbook-collection protocols=UDP,TCP source_type=ip_address source_ips=189.160.40.11,189.160.40.11 destination_type=ip_address destinations=189.160.40.11,189.160.40.11 destination_ports=8080 interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "e1950ec2-3ab1-43aa-9d84-a3c4053c2f52",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Updating",
                "ruleCollectionGroups": [
                    {
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection"
                    }
                ],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Updating |

### azure-firewall-network-rule-update

***
Update the network rule in the firewall. The provided arguments will replace the existing rule configuration. One of the arguments 'firewall_name' or 'policy'  must be provided. The command will not replace the rule source or destination types.

#### Base Command

`azure-firewall-network-rule-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the collection. | Optional | 
| policy | The name of the policy that contains the collection. | Optional | 
| collection_name | The name of the network rule collection to update. | Required | 
| rule_name | The name of the network rule to update. | Required | 
| description | The new description of the rule. | Optional | 
| protocols | Comma-separated list of protocols for the rule. Possible values are: TCP, UDP, ICMP, Any. | Optional | 
| source_type | Rule source type. Possible values are: ip_address, ip_group. | Optional | 
| source_ips | Comma-separated list of source IP addresses for the created rule. Must be provided when the 'source_type' argument is assigned to 'ip_address'. | Optional | 
| source_ip_group_ids | Comma-separated list of source IP group IDs for the created rule. Must be provided when the 'source_type' argument is assigned to 'ip_group'. | Optional | 
| destination_type | Rule destination type. Must be provided when the 'destinations' argument is provided. Possible values are: ip_address, ip_group, service_tag, fqdn. | Optional | 
| destinations | Comma-separated list of destinations for the created rule. Must be consistent with the provided 'destination_type' argument. Supports IP addresses, service tag names, IP group IDs and FQDN addresses. | Optional | 
| destination_ports | Comma-separated list of destination ports. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-network-rule-update policy=xsoar-policy collection_name=playbook-collection rule_name=new-playbook-rule protocols=UDP interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "9e0bdc8a-99e9-4337-8778-2ec85d29d445",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Succeeded",
                "ruleCollectionGroups": [
                    {
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection"
                    }
                ],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Succeeded |

### azure-firewall-network-rule-delete

***
Delete a network rule from the collection. One of the arguments 'firewall_name' or 'policy'  must be provided.

#### Base Command

`azure-firewall-network-rule-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the collection. | Optional | 
| policy | The name of the policy that contains the collection. | Optional | 
| collection_name | The name of the network rule collection to update. | Required | 
| rule_names | Comma-separated list of network rule names to delete from the collection. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-network-rule-delete policy=xsoar-policy collection_name=playbook-collection rule_names=new-playbook-rule interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "6b9e5bf4-3e11-4705-84c6-d5c14e45f13c",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Updating",
                "ruleCollectionGroups": [
                    {
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection"
                    }
                ],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Updating |

### azure-firewall-network-rule-collection-update

***
Update a network rule collection in a firewall or policy. The command will update the provided arguments. One of the arguments 'firewall_name' or 'policy'  must be provided. The command will return firewall or policy rule collection resource information.

#### Base Command

`azure-firewall-network-rule-collection-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| firewall_name | The name of the firewall that contains the collection. | Optional | 
| policy | The name of the policy that contains the collection. | Optional | 
| collection_name | The name of the network rule collection to update. | Required | 
| priority | The priority of the network rule collection resource. Minimum value is 100, maximum value us 65000. | Optional | 
| action | The action type of a rule collection. Possible values are: Allow, Deny. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-network-rule-collection-update policy=xsoar-policy collection_name=playbook-collection priority=201 action=Deny interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "Policy": {
            "etag": "a4caa2e4-cc96-460b-9202-4914f74ce5e9",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy",
            "location": "eastus",
            "name": "xsoar-policy",
            "properties": {
                "childPolicies": [],
                "dnsSettings": {
                    "servers": []
                },
                "firewalls": [],
                "provisioningState": "Succeeded",
                "ruleCollectionGroups": [
                    {
                        "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy/ruleCollectionGroups/playbook-collection"
                    }
                ],
                "sku": {
                    "tier": "Standard"
                },
                "threatIntelMode": "Deny"
            },
            "type": "Microsoft.Network/FirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Successfully Updated Policy "xsoar-policy"
>|Name|Id|Tier|Location|Firewalls|Base Policy|Child Policies|Provisioning State|
>|---|---|---|---|---|---|---|---|
>| xsoar-policy | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/firewallPolicies/xsoar-policy | Standard | eastus |  |  |  | Succeeded |

### azure-firewall-service-tag-list

***
Retrieve service tags information.

#### Base Command

`azure-firewall-service-tag-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| location | The location that will be used as a reference for a version (not as a filter based on location, the command will retrieve the list of service tags with prefix details across all regions but limited to the cloud that your subscription belongs to). Possible values are: northcentralus, eastus, northeurope, westeurope, eastasia, southeastasia, eastus2, centralus, southcentralus, westus, japaneast, japanwest, australiaeast, australiasoutheast, brazilsouth, centralindia, southindia, westindia, canadacentral, canadaeast, uksouth, ukwest, westcentralus, westus2, koreacentral, francecentral, australiacentral, uaenorth, southafricanorth, switzerlandnorth, germanywestcentral, norwayeast, westus3, jioindiawest. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-service-tag-list location=eastus limit=1 page=3```
#### Context Example
```json
{
    "AzureFirewall": {
        "ServiceTag": {
            "id": "ApiManagement.AustraliaCentral",
            "name": "ApiManagement.AustraliaCentral",
            "properties": {
                "addressPrefixes": [
                    "20.36.106.68/31",
                    "20.36.107.176/28",
                    "20.37.52.67/32",
                    "2603:1010:304:402::140/124"
                ],
                "changeNumber": "2",
                "networkFeatures": [
                    "API",
                    "NSG",
                    "UDR",
                    "FW"
                ],
                "region": "australiacentral",
                "state": "GA",
                "systemService": "AzureApiManagement"
            },
            "serviceTagChangeNumber": "86"
        }
    }
}
```

#### Human Readable Output

>### Service Tag List:
> Current page size: 1
> Showing page 3 out others that may exist.
> 
>|Name|Id|
>|---|---|
>| ApiManagement.AustraliaCentral | ApiManagement.AustraliaCentral |

### azure-firewall-ip-group-create

***
Create an IP group.

#### Base Command

`azure-firewall-ip-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_name | The name of the IP group resource to create. | Required | 
| ips | Comma-separated list of IP addresses or IP address prefixes in the IP group resource. | Optional | 
| location | The location of the IP group resource. Possible values are: northcentralus, eastus, northeurope, westeurope, eastasia, southeastasia, eastus2, centralus, southcentralus, westus, japaneast, japanwest, australiaeast, australiasoutheast, brazilsouth, centralindia, southindia, westindia, canadacentral, canadaeast, uksouth, ukwest, westcentralus, westus2, koreacentral, francecentral, australiacentral, uaenorth, southafricanorth, switzerlandnorth, germanywestcentral, norwayeast, westus3, jioindiawest. | Required | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.IPGroup.id | String | IP group resource ID. | 
| AzureFirewall.IPGroup.name | String | IP group resource name. | 
| AzureFirewall.IPGroup.properties.ipAddresses | String | List of IP addresses or IP address prefixes in the IP groups resource. | 

#### Command example
```!azure-firewall-ip-group-create ip_group_name=xsoar-ip-group ips=189.160.40.11 location=eastus interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "IPGroup": {
            "etag": "8ea22ba3-4023-4c7f-a887-34f5f349d7c6",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group",
            "location": "eastus",
            "name": "xsoar-ip-group",
            "properties": {
                "firewallPolicies": [],
                "firewalls": [],
                "ipAddresses": [
                    "189.160.40.11"
                ],
                "provisioningState": "Updating"
            },
            "type": "Microsoft.Network/IpGroups"
        }
    }
}
```

#### Human Readable Output

>### Successfully Created IP Group "xsoar-ip-group"
>|Name|Id|Ip Addresses|Firewalls|Firewall Policies|Provisioning State|
>|---|---|---|---|---|---|
>| xsoar-ip-group | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group | 189.160.40.11 |  |  | Updating |

### azure-firewall-ip-group-update

***
Update an IP group. Add or remove IP addresses from the group.

#### Base Command

`azure-firewall-ip-group-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_name | The name of the IP group resource to update. | Required | 
| ips_to_add | Comma-separated list of IP addresses or IP address prefixes to add to the IP group resource. | Optional | 
| ips_to_remove | Comma-separated list of IP addresses or IP address prefixes to remove from the IP group resource. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.IPGroup.id | String | IP group resource ID. | 
| AzureFirewall.IPGroup.name | String | IP group resource name. | 
| AzureFirewall.IPGroup.properties.ipAddresses | String | List of IP addresses or IP address prefixes in the IP groups resource. | 

#### Command example
```!azure-firewall-ip-group-update ip_group_name=xsoar-ip-group ips_to_add=189.160.40.11,189.160.40.11 ips_to_remove=189.160.40.11,1.1.1 interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "IPGroup": {
            "etag": "8f0e7d5d-6dfd-429c-ad07-e670f57e4dab",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group",
            "location": "eastus",
            "name": "xsoar-ip-group",
            "properties": {
                "firewallPolicies": [],
                "firewalls": [],
                "ipAddresses": [
                    "189.160.40.11",
                    "189.160.40.11"
                ],
                "provisioningState": "Updating"
            },
            "type": "Microsoft.Network/IpGroups"
        }
    }
}
```

#### Human Readable Output

>### xsoar-ip-group IP Group Information:
>|Name|Id|Ip Addresses|Firewalls|Firewall Policies|Provisioning State|
>|---|---|---|---|---|---|
>| xsoar-ip-group | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group | 189.160.40.11,<br/>189.160.40.11 |  |  | Updating |

### azure-firewall-ip-group-list

***
List IP groups in a resource group or subscription.

#### Base Command

`azure-firewall-ip-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource | The resource that contains the IP groups to list. Possible values are: resource_group, subscription. Default is resource_group. | Required | 
| limit | The maximum number of results to retrieve. Minimum value is 1. Default is 50. | Optional | 
| page | The page number of the results to retrieve. Minimum value is 1. Default is 1. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.IPGroup.id | String | IP group resource ID. | 
| AzureFirewall.IPGroup.name | String | IP group resource name. | 
| AzureFirewall.IPGroup.properties.ipAddresses | String | List of IP addresses or IP address prefixes in the IP groups resource. | 

#### Command example
```!azure-firewall-ip-group-list resource=resource_group limit=1 page=1```
#### Context Example
```json
{
    "AzureFirewall": {
        "IPGroup": {
            "etag": "4c626477-c875-4392-9d7c-02464d2a82d9",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group",
            "location": "eastus",
            "name": "xsoar-ip-group",
            "properties": {
                "firewallPolicies": [],
                "firewalls": [],
                "ipAddresses": [
                    "189.160.40.11"
                ],
                "provisioningState": "Succeeded"
            },
            "type": "Microsoft.Network/IpGroups"
        }
    }
}
```

#### Human Readable Output

>### IP Group List:
> Current page size: 1
> Showing page 1 out others that may exist.
> 
>|Name|Id|Ip Addresses|Firewalls|Firewall Policies|Provisioning State|
>|---|---|---|---|---|---|
>| xsoar-ip-group | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group | 189.160.40.11 |  |  | Succeeded |

### azure-firewall-ip-group-get

***
Retrieve IP group information.

#### Base Command

`azure-firewall-ip-group-get`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_names | Comma-separated list of IP group names resource to retrieve. | Required | 
| polling | Indicates if the command was scheduled. Possible values are: True, False. Default is True. | Optional | 
| interval | Indicates how long to wait between command executions (in seconds) when the 'polling' argument is true. Minimum value is 10 seconds. Default is 30. | Optional | 
| timeout | Indicates the time in seconds until the polling sequence times out. Default is 60. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.IPGroup.id | String | IP group resource ID. | 
| AzureFirewall.IPGroup.name | String | IP group resource name. | 
| AzureFirewall.IPGroup.properties.ipAddresses | String | List of IP addresses or IP address prefixes in the IP groups resource. | 

#### Command example
```!azure-firewall-ip-group-get ip_group_names=xsoar-ip-group interval=10 timeout=600```
#### Context Example
```json
{
    "AzureFirewall": {
        "IPGroup": {
            "etag": "4c626477-c875-4392-9d7c-02464d2a82d9",
            "id": "/subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group",
            "location": "eastus",
            "name": "xsoar-ip-group",
            "properties": {
                "firewallPolicies": [],
                "firewalls": [],
                "ipAddresses": [
                    "189.160.40.11"
                ],
                "provisioningState": "Succeeded"
            },
            "type": "Microsoft.Network/IpGroups"
        }
    },
    "IP": {
        "Address": "189.160.40.11"
    }
}
```

#### Human Readable Output

>### xsoar-ip-group IP Group Information:
>|Name|Id|Ip Addresses|Firewalls|Firewall Policies|Provisioning State|
>|---|---|---|---|---|---|
>| xsoar-ip-group | /subscriptions/xsoar-subscription/resourceGroups/xsoar-resource-group/providers/Microsoft.Network/ipGroups/xsoar-ip-group | 189.160.40.11 |  |  | Succeeded |

### azure-firewall-ip-group-delete

***
Delete an IP group resource.

#### Base Command

`azure-firewall-ip-group-delete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip_group_names | Comma-separated list of IP group names resource to delete. | Required | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!azure-firewall-ip-group-delete ip_group_names=xsoar-ip-group```
#### Human Readable Output
>IP Group xsoar-ip-group deleted successfully.

### azure-firewall-subscriptions-list

***
List all subscriptions for a tenant.

#### Base Command

`azure-firewall-subscriptions-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.Subscription.authorizationSource | String | The authorization source of the request. | 
| AzureFirewall.Subscription.displayName | String | The subscription display name. | 
| AzureFirewall.Subscription.id | String | The fully qualified ID for the subscription. For example, /subscriptions/8d65815f-a5b6-402f-9298-045155da7d74. | 
| AzureFirewall.Subscription.managedByTenants | Unknown | An array containing the tenants managing the subscription. | 
| AzureFirewall.Subscription.state | Unknown | The subscription state. Possible values are Enabled, Warned, PastDue, Disabled, and Deleted. | 
| AzureFirewall.Subscription.subscriptionId | String | The subscription ID. | 
| AzureFirewall.Subscription.subscriptionPolicies | Unknown | The subscription policies. | 
| AzureFirewall.Subscription.tags | Object | The tags attached to the subscription. | 
| AzureFirewall.Subscription.tenantId | String | The subscription tenant ID. | 

### azure-firewall-resource-group-list

***
List all resource groups for a subscription.

#### Base Command

`azure-firewall-resource-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| limit | Limit on the number of resource groups to return. Default is 50. | Optional | 
| tag | A single tag in the form of '{"Tag Name":"Tag Value"}' to filter the list by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureFirewall.ResourceGroup.id | String | The ID of the resource group. | 
| AzureFirewall.ResourceGroup.location | String | The location of the resource group. | 
| AzureFirewall.ResourceGroup.managedBy | String | The ID of the resource that manages this resource group. | 
| AzureFirewall.ResourceGroup.name | String | The name of the resource group. | 
| AzureFirewall.ResourceGroup.properties.provisioningState | String | The provisioning state. | 
| AzureFirewall.ResourceGroup.tags | Object | The tags attached to the resource group. | 
| AzureFirewall.ResourceGroup.type | String | The type of the resource group. | 