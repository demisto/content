This script identifies the first inbound Allow rule in the specified NSG that matches the criteria for network exposure. It returns details about the identified rule as well as a list of available priority numbers to insert new security rules with a higher priority.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| subscription_id | The Azure Subscription ID where the NSG resides. |
| resource_group_name | The Azure Resource Group Name where the NSG resides. |
| network_security_group_name | The Azure Network Security Group \(NSG\) Name to analyze for exposure rules. |
| private_ip_addresses | The destination private IP address\(es\) of the Virtual Machine interface. |
| port | TCP/UDP port to be restricted. |
| protocol | Protocol of the port to be restricted. |
| priority_count | The number of available priority values below the matching rule to return. |
| integration_instance | The Azure Integration Instance to use. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AzurePublicExposure.MatchingRuleName | The name of the matching inbound security rule in the NSG that allows exposure. | String |
| AzurePublicExposure.MatchingRulePriority | The priority number of the matching inbound security rule. | Number |
| AzurePublicExposure.NextAvailablePriorityValues | The next available priority values to insert new security rules before the matching rule, given in descending order. | Unknown |
| AzurePublicExposure.IntegrationInstance | The Azure Integration Instance used for identification. | String |
