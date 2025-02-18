Azure network security groups are used to filter network traffic to and from Azure resources in an Azure virtual network.
This integration was integrated and tested with version 2022-09-01 of Azure Network Security Groups.

# Authorization

In order to connect to the Azure Storage Accounts and the Blob Service use either the Cortex XSOAR Azure App or the Self-Deployed Azure App.
Use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Client Credentials*
3. *Device Code Flow*.

## Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

To add the registration, refer to the following [Microsoft article](https://learn.microsoft.com/en-us/defender-xdr/api-create-app-web?view=o365-worldwide) steps 1-8.

### Required permissions

- Azure Service Management - permission `user_impersonation` of type Delegated
- Microsoft Graph - permission `offline_access` of type Delegated

To add a permission:
1. Navigate to **Home** > **App registrations**.
2. Search for your app under 'all applications'.
3. Click **API permissions** > **Add permission**.
4.  Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Authorization Code Flow (recommended)

1. In the *Authentication Type* field, select the **Authorization Code** option.
2. In the *Application ID* field, enter your Client/Application ID.
3. In the *Client Secret* field, enter your Client Secret.
4. In the *Tenant ID* field, enter your Tenant ID .
5. In the *Application redirect URI* field, enter your Application redirect URI.
6. Save the instance.
7. Run the `!azure-nsg-generate-login-url` command in the War Room and follow the instruction.

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* In the *Select members* section, assign the application you created earlier.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   a. In the *Authentication Type* field, select the **Client Credentials** option.
   b. In the *Application ID* field, enter your Client/Application ID.
   c. In the *Subscription ID* field, enter your Subscription ID.
   d. In the *Resource Group Name* field, enter you Resource Group Name.
   e. In the *Tenant ID* field, enter your Tenant ID .
   f. In the *Client Secret* field, enter your Client Secret.
   g. Click **Test** to validate the URLs, token, and connection
   h. Save the instance.

### Authentication Using the Device Code Flow

Use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:

1. Fill in the required parameters.
2. Run the ***!azure-nsg-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-nsg-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (d4736600-e3d5-4c97-8e65-57abd2b979fe).

You only need to fill in your subscription ID and resource group name.

## Configure Azure Network Security Groups on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Network Security Groups.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter**                      | **Description**                                                                                                                                                                                    | **Required** |
             |------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
   | Application ID                     |                                                                                                                                                                                                    | False        |
   | Default Subscription ID            | There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value. | True         |
   | Default Resource Group Name        | There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value. | True         |
   | Azure AD endpoint                  | Azure AD endpoint associated with a national cloud.                                                                                                                                                | False        |
   | Trust any certificate (not secure) |                                                                                                                                                                                                    | False        |
   | Use system proxy settings          |                                                                                                                                                                                                    | False        |
   | Authentication Type                | Type of authentication - can be Authorization Code flow \(recommended\), Client Credentials, Device Code Flow, or Azure Managed Identities.                                                        | True         |
   | Tenant ID                          |                                                                                                                                                                                                    | False        |
   | Client Secret                      |                                                                                                                                                                                                    | False        |
   | Application redirect URI           |                                                                                                                                                                                                    | False        |
   | Authorization code                 | For user-auth mode - received from the authorization step. See Detailed Instructions \(?\) section.                                                                                                | False        |
   | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM.                                                                                     | False        |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-nsg-security-groups-list

***
List all network security groups.

#### Base Command

`azure-nsg-security-groups-list`

#### Input

| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional |
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional |

#### Context Output

| **Path**                        | **Type** | **Description**                |
|---------------------------------|----------|--------------------------------|
| AzureNSG.SecurityGroup.name     | String   | The security group's name.     | 
| AzureNSG.SecurityGroup.id       | String   | The security group's ID.       | 
| AzureNSG.SecurityGroup.etag     | String   | The security group's ETag.     | 
| AzureNSG.SecurityGroup.type     | String   | The security group's type.     | 
| AzureNSG.SecurityGroup.location | String   | The security group's location. | 
| AzureNSG.SecurityGroup.tags     | String   | The security group's tags.     | 

#### Command Example

```!azure-nsg-security-groups-list```

#### Context Example

```json
{
    "AzureNSG": {
        "SecurityGroup": {
            "etag": "W/\"fdba51cf-46b3-44af-8da5-16666aa578cc\"",
            "id": "/subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg",
            "location": "westeurope",
            "name": "alerts-nsg",
            "tags": {},
            "type": "Microsoft.Network/networkSecurityGroups"
        }
    }
}
```

#### Human Readable Output

> ### Network Security Groups
>|etag|id|location|name|tags|type|
>|---|---|---|---|---|---|
>| W/"fdba51cf-46b3-44af-8da5-16666aa578cc" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg | westeurope | alerts-nsg |  | Microsoft.Network/networkSecurityGroups |

### azure-nsg-security-rules-list

***
List all rules of the specified security groups.

#### Base Command

`azure-nsg-security-rules-list`

#### Input

| **Argument Name**   | **Description**                                                                                                  | **Required** |
|---------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | A comma-separated list of the names of the security groups.                                                      | Required     | 
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     | 
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     | 
| limit               | The maximum number of rules to display. Default is 50.                                                           | Optional     | 
| offset              | The index of the first rule to display. Used for pagination. Default is 0.                                       | Optional     | 

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", or "\*"".                                                                                    | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.           | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of source ports. Note that for single ports, \`sourcePortRange\` will appear instead.                        | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be either "Allow" or "Deny".                                                                                     | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be either "Inbound" or "Outbound".                                                                            | 

#### Command Example

```!azure-nsg-security-rules-list security_group_name=alerts-nsg```

#### Context Example

```json
{
    "AzureNSG": {
        "Rule": {
            "access": "Allow",
            "destinationAddressPrefix": "1.1.1.1",
            "destinationAddressPrefixes": [],
            "destinationPortRange": "*",
            "destinationPortRanges": [],
            "direction": "Inbound",
            "etag": "W/\"fdba51cf-46b3-44af-8da5-16666aa578cc\"",
            "id": "/subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/wow",
            "name": "wow",
            "priority": 3323,
            "protocol": "*",
            "provisioningState": "Succeeded",
            "sourceAddressPrefix": "8.8.8.8",
            "sourceAddressPrefixes": [],
            "sourcePortRanges": [
                "1",
                "2",
                "3"
            ],
            "type": "Microsoft.Network/networkSecurityGroups/securityRules"
        }
    }
}
```

#### Human Readable Output

> ### Rules in alerts-nsg
>|access|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRanges|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | 1.1.1.1 | * | Inbound | W/"fdba51cf-46b3-44af-8da5-16666aa578cc" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/wow | wow | 3323 | * | Succeeded | 8.8.8.8 | 1,<br/>2,<br/>3 | Microsoft.Network/networkSecurityGroups/securityRules |

### azure-nsg-auth-test

***
Tests the connectivity to the Azure Network Security Groups.

#### Base Command

`azure-nsg-auth-test`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!azure-nsg-auth-test```

#### Human Readable Output

> ✅ Success!

### azure-nsg-security-rules-delete

***
Delete a security rule.

#### Base Command

`azure-nsg-security-rule-delete`

#### Input

| **Argument Name**   | **Description**                                                                                                  | **Required** |
|---------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                                                                                  | Required     | 
| security_rule_name  | The name of the rule to be deleted.                                                                              | Required     |
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

```!azure-nsg-security-rules-delete security_group_name=alerts-nsg security_rule_name=wow```

#### Human Readable Output

> Rule wow deleted.

### azure-nsg-security-rules-create

***
Create a security rule.

#### Base Command

`azure-nsg-security-rule-create`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                                                                                                         | **Required** |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                                                                                                                                                                                                                                                                         | Required     | 
| security_rule_name  | The name of the rule to be created.                                                                                                                                                                                                                                                                     | Required     | 
| direction           | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound.                                                                                                                                                                                       | Required     | 
| action              | Whether to allow the traffic. Possible values are: "Allow" and "Deny". Possible values are: Allow, Deny.                                                                                                                                                                                                | Optional     | 
| protocol            | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP" and "ICMP". Possible values are: Any, TCP, UDP, ICMP.                                                                                                                                                                 | Optional     | 
| source              | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. Default is "Any".                                                                                      | Optional     | 
| priority            | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. Default is "4096".                                       | Optional     | 
| source_ports        | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional     | 
| destination         | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag.                                                                                  | Optional     | 
| destination_ports   | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port.             | Optional     | 
| description         | A description to add to the rule.                                                                                                                                                                                                                                                                       | Optional     |
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.                                                                                                                                                                                                | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'.                                                                                                                                                                                        | Optional     |

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", or "\*".                                                                                     | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.         | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead.                         | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be "Allow" or "Deny".                                                                                            | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be "Inbound" or "Outbound".                                                                                   | 

#### Command Example

```!azure-nsg-security-rules-create direction=Inbound security_group_name=alerts-nsg security_rule_name=rulerule source=1.1.1.1```

#### Context Example

```json
{
    "AzureNSG": {
        "Rule": {
            "access": "Allow",
            "destinationAddressPrefix": "*",
            "destinationAddressPrefixes": [],
            "destinationPortRange": "*",
            "destinationPortRanges": [],
            "direction": "Inbound",
            "etag": "W/\"276dc93a-488d-47a1-8971-19a1171242a9\"",
            "id": "/subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/rulerule",
            "name": "rulerule",
            "priority": 4096,
            "protocol": "*",
            "provisioningState": "Updating",
            "sourceAddressPrefix": "1.1.1.1",
            "sourceAddressPrefixes": [],
            "sourcePortRange": "*",
            "sourcePortRanges": [],
            "type": "Microsoft.Network/networkSecurityGroups/securityRules"
        }
    }
}
```

#### Human Readable Output

> ### Rules rulerule
>|access|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRange|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | * | * | Inbound | W/"276dc93a-488d-47a1-8971-19a1171242a9" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/rulerule | rulerule | 4096 | * | Updating | 1.1.1.1 | * | Microsoft.Network/networkSecurityGroups/securityRules |

### azure-nsg-security-rules-update

***
Update a security rule. If one does not exist, it will be created.

#### Base Command

`azure-nsg-security-rule-update`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                                                                                                         | **Required** |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                                                                                                                                                                                                                                                                         | Required     | 
| security_rule_name  | The name of the rule to be updated.                                                                                                                                                                                                                                                                     | Required     | 
| direction           | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound.                                                                                                                                                                                       | Optional     | 
| action              | Whether to allow the traffic. Possible values are "Allow" and "Deny". Possible values are: Allow, Deny.                                                                                                                                                                                                 | Optional     | 
| protocol            | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP", and "ICMP". Possible values are: Any, TCP, UDP, ICMP.                                                                                                                                                                | Optional     | 
| source              | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. Default is "Any".                                                                                      | Optional     | 
| priority            | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. Default is "4096".                                       | Optional     | 
| source_ports        | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional     | 
| destination         | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag.                                                                                  | Optional     | 
| destination_ports   | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port.             | Optional     | 
| description         | A description to add to the rule.                                                                                                                                                                                                                                                                       | Optional     | 
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.                                                                                                                                                                                                | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'.                                                                                                                                                                                        | Optional     |

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", "\*".                                                                                        | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.         | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead.                         | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be "Allow" or "Deny".                                                                                            | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be "Inbound" or "Outbound".                                                                                   | 

#### Command Example

```!azure-nsg-security-rules-update security_group_name=alerts-nsg security_rule_name=XSOAR_Rule action=Allow description=description```

#### Context Example

```json
{
    "AzureNSG": {
        "Rule": {
            "access": "Allow",
            "description": "description",
            "destinationAddressPrefix": "11.0.0.0/8",
            "destinationAddressPrefixes": [],
            "destinationPortRange": "8080",
            "destinationPortRanges": [],
            "direction": "Outbound",
            "etag": "W/\"9fad6036-4c3a-4d60-aac9-18281dba3305\"",
            "id": "/subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/XSOAR_Rule",
            "name": "XSOAR_Rule",
            "priority": 100,
            "protocol": "*",
            "provisioningState": "Succeeded",
            "sourceAddressPrefix": "10.0.0.0/8",
            "sourceAddressPrefixes": [],
            "sourcePortRange": "*",
            "sourcePortRanges": [],
            "type": "Microsoft.Network/networkSecurityGroups/securityRules"
        }
    }
}
```

#### Human Readable Output

> ### Rules XSOAR_Rule
>|access|description|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRange|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | description | 11.0.0.0/8 | 8080 | Outbound | W/"9fad6036-4c3a-4d60-aac9-18281dba3305" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/XSOAR_Rule | XSOAR_Rule | 100 | * | Succeeded | 10.0.0.0/8 | * | Microsoft.Network/networkSecurityGroups/securityRules |

### azure-nsg-security-rules-get

***
Get a specific rule.

#### Base Command

`azure-nsg-security-rule-get`

#### Input

| **Argument Name**   | **Description**                                                                                                         | **Required** |
|---------------------|-------------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                                                                                         | Optional     | 
| security_rule_name  | A comma-separated list of the names of the rules to get.                                                                | Optional     |
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.                | Optional     |
 resource_group_name | The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", "\*".                                                                                        | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.         | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead.                         | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be "Allow" or "Deny".                                                                                            | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be "Inbound" or "Outbound".                                                                                   | 

#### Command Example

```!azure-nsg-security-rules-get security_group_name=alerts-nsg security_rule_name=wow```

#### Context Example

```json
{
    "AzureNSG": {
        "Rule": {
            "access": "Allow",
            "destinationAddressPrefix": "1.1.1.1",
            "destinationAddressPrefixes": [],
            "destinationPortRange": "*",
            "destinationPortRanges": [],
            "direction": "Inbound",
            "etag": "W/\"fdba51cf-46b3-44af-8da5-16666aa578cc\"",
            "id": "/subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/wow",
            "name": "wow",
            "priority": 3323,
            "protocol": "*",
            "provisioningState": "Succeeded",
            "sourceAddressPrefix": "8.8.8.8",
            "sourceAddressPrefixes": [],
            "sourcePortRanges": [
                "1",
                "2",
                "3"
            ],
            "type": "Microsoft.Network/networkSecurityGroups/securityRules"
        }
    }
}
```

#### Human Readable Output

> ### Rules wow
>|access|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRanges|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | 1.1.1.1 | * | Inbound | W/"fdba51cf-46b3-44af-8da5-16666aa578cc" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/wow | wow | 3323 | * | Succeeded | 8.8.8.8 | 1,<br/>2,<br/>3 | Microsoft.Network/networkSecurityGroups/securityRules |

### azure-nsg-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`azure-nsg-auth-start`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!azure-nsg-auth-start ```

#### Human Readable Output

> To sign in, use a web browser to open the page https://microsoft.com/devicelogin
> and enter the code CODECODE to authenticate.
> Run the ***!azure-nsg-auth-complete*** command in the War Room.

### azure-nsg-auth-complete

***
Run this command to complete the authorization process. Should be used after running the azure-nsg-auth-start command.

#### Base Command

`azure-nsg-auth-complete`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!azure-nsg-auth-complete```

#### Human Readable Output

> ✅ Authorization completed successfully.

### azure-nsg-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-nsg-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```!azure-nsg-auth-reset```

#### Human Readable Output

> Authorization was reset successfully. You can now run **!azure-nsg-auth-start** and **!azure-nsg-auth-complete**.

### azure-nsg-security-rule-delete

***
Delete a security rule.

#### Base Command

`azure-nsg-security-rule-delete`

#### Input

| **Argument Name**   | **Description**                     | **Required** |
|---------------------|-------------------------------------|--------------|
| security_group_name | The name of the security group.     | Required     | 
| security_rule_name  | The name of the rule to be deleted. | Required     | 

#### Context Output

There is no context output for this command.

### azure-nsg-security-rule-create

***
Create a security rule.

#### Base Command

`azure-nsg-security-rule-create`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                                                                                             | **Required** |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                                                                                                                                                                                                                                                             | Required     | 
| security_rule_name  | The name of the rule to be created.                                                                                                                                                                                                                                                         | Required     | 
| direction           | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound.                                                                                                                                                                           | Required     | 
| action              | Whether to allow the traffic. Possible values are: "Allow" and "Deny". Possible values are: Allow, Deny.                                                                                                                                                                                    | Optional     | 
| protocol            | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP" and "ICMP". Possible values are: Any, TCP, UDP, ICMP.                                                                                                                                                     | Optional     | 
| source              | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag.                                                                                            | Optional     | 
| priority            | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules.                                              | Optional     | 
| source_ports        | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port.     | Optional     | 
| destination         | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag.                                                                      | Optional     | 
| destination_ports   | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional     | 
| description         | A description to add to the rule.                                                                                                                                                                                                                                                           | Optional     | 

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", or "\*".                                                                                     | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.         | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead.                         | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be "Allow" or "Deny".                                                                                            | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be "Inbound" or "Outbound".                                                                                   | 

### azure-nsg-security-rule-update

***
Update a security rule. If one does not exist, it will be created.

#### Base Command

`azure-nsg-security-rule-update`

#### Input

| **Argument Name**   | **Description**                                                                                                                                                                                                                                                                             | **Required** |
|---------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                                                                                                                                                                                                                                                             | Required     | 
| security_rule_name  | The name of the rule to be updated.                                                                                                                                                                                                                                                         | Required     | 
| direction           | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound.                                                                                                                                                                           | Optional     | 
| action              | Whether to allow the traffic. Possible values are "Allow" and "Deny". Possible values are: Allow, Deny.                                                                                                                                                                                     | Optional     | 
| protocol            | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP", and "ICMP". Possible values are: Any, TCP, UDP, ICMP.                                                                                                                                                    | Optional     | 
| source              | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag.                                                                                            | Optional     | 
| priority            | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules.                                              | Optional     | 
| source_ports        | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port.     | Optional     | 
| destination         | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag.                                                                      | Optional     | 
| destination_ports   | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional     | 
| description         | A description to add to the rule.                                                                                                                                                                                                                                                           | Optional     | 

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", "\*".                                                                                        | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.         | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead.                         | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be "Allow" or "Deny".                                                                                            | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be "Inbound" or "Outbound".                                                                                   | 

### azure-nsg-security-rule-get

***
Get a specific rule.

#### Base Command

`azure-nsg-security-rule-get`

#### Input

| **Argument Name**   | **Description**                                          | **Required** |
|---------------------|----------------------------------------------------------|--------------|
| security_group_name | The name of the security group.                          | Optional     | 
| security_rule_name  | A comma-separated list of the names of the rules to get. | Optional     | 

#### Context Output

| **Path**                               | **Type** | **Description**                                                                                                                         |
|----------------------------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------|
| AzureNSG.Rule.name                     | String   | The rule's name.                                                                                                                        | 
| AzureNSG.Rule.id                       | String   | The rule's ID.                                                                                                                          | 
| AzureNSG.Rule.etag                     | String   | The rule's ETag.                                                                                                                        | 
| AzureNSG.Rule.type                     | String   | The rule's type.                                                                                                                        | 
| AzureNSG.Rule.provisioningState        | String   | The rule's provisioning state.                                                                                                          | 
| AzureNSG.Rule.protocol                 | String   | The protocol. Can be "TCP", "UDP", "ICMP", "\*".                                                                                        | 
| AzureNSG.Rule.sourcePortRange          | String   | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead.         | 
| AzureNSG.Rule.sourcePortRanges         | String   | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead.                         | 
| AzureNSG.Rule.destinationPortRange     | String   | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges    | String   | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead.              | 
| AzureNSG.Rule.sourceAddressPrefix      | String   | The source address.                                                                                                                     | 
| AzureNSG.Rule.destinationAddressPrefix | String   | The destination address.                                                                                                                | 
| AzureNSG.Rule.access                   | String   | The rule's access. Can be "Allow" or "Deny".                                                                                            | 
| AzureNSG.Rule.priority                 | Number   | The rule's priority. Can be from 100 to 4096.                                                                                           | 
| AzureNSG.Rule.direction                | String   | The rule's direction. Can be "Inbound" or "Outbound".                                                                                   | 

### azure-nsg-generate-login-url

***
Generate the login url used for Authorization code.

#### Base Command

`azure-nsg-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```azure-nsg-generate-login-url```

#### Human Readable Output

> ### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
    You will be automatically redirected to a link with the following structure:
    ```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
    and paste it in your instance configuration under the **Authorization code** parameter.

### azure-nsg-subscriptions-list

***
Gets all subscriptions for a tenant.

#### Base Command

`azure-nsg-subscriptions-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path**                                                       | **Type** | **Description**                                                                             |
|----------------------------------------------------------------|----------|---------------------------------------------------------------------------------------------|
| AzureNSG.Subscription.id                                       | String   | The unique identifier of the Azure Network Security Groups subscription.                    | 
| AzureNSG.Subscription.authorizationSource                      | String   | The source of authorization for the Azure Network Security Groups subscription.             | 
| AzureNSG.Subscription.managedByTenants                         | Unknown  | The tenants that have access to manage the Azure Network Security Groups subscription.      | 
| AzureNSG.Subscription.subscriptionId                           | String   | The ID of the Azure Network Security Groups subscription.                                   | 
| AzureNSG.Subscription.tenantId                                 | String   | The ID of the tenant associated with the Azure Network Security Groups subscription.        | 
| AzureNSG.Subscription.displayName                              | String   | The display name of the Azure Network Security Groups subscription.                         | 
| AzureNSG.Subscription.state                                    | String   | The current state of the Azure Network Security Groups subscription.                        | 
| AzureNSG.Subscription.subscriptionPolicies.locationPlacementId | String   | The ID of the location placement policy for the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.subscriptionPolicies.quotaId             | String   | The ID of the quota policy for the Azure Network Security Groups subscription.              | 
| AzureNSG.Subscription.subscriptionPolicies.spendingLimit       | String   | The spending limit policy for the Azure Network Security Groups subscription.               | 
| AzureNSG.Subscription.count.type                               | String   | The type of the Azure Network Security Groups subscription count.                           | 
| AzureNSG.Subscription.count.value                              | Number   | The value of the Azure Network Security Groups subscription count.                          | 

#### Command example

```!azure-nsg-subscriptions-list```

#### Context Example

```json
{
    "AzureNSG": {
        "Subscription": [
            {
                "authorizationSource": "RoleBased",
                "displayName": "Access to Azure Active Directory",
                "id": "/subscriptions/057b1785-fd",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "057b1785-fd7b-4ca",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "AAD_2015-09-01",
                    "spendingLimit": "On"
                },
                "tenantId": "ebac1a16-81bf-4"
            },
            {
                "authorizationSource": "RoleBased",
                "displayName": "Pay-As-You-Go",
                "id": "/subscriptions/0f907ea4",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "0f907ea4-bc",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "PayAsYouGo_2014-09-01",
                    "spendingLimit": "Off"
                },
                "tenantId": "ebac1a16-81bf-"
            }
        ]
    }
}
```

#### Human Readable Output

> ### Azure Network Security Groups Subscriptions list
>|subscriptionId|tenantId|displayName|state|
>|---|---|---|---|
>| 057b1785-fd7b-4 | ebac1a16-81bf-449 | Access to Azure Active Directory | Enabled |
>| 0f907ea4-bc8b-4 | ebac1a16-81bf-449 | Pay-As-You-Go | Enabled |

### azure-nsg-resource-group-list

***
Gets all resource groups for a subscription.

#### Base Command

`azure-nsg-resource-group-list`

#### Input

| **Argument Name** | **Description**                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------|--------------|
| subscription_id   | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional     | 
| limit             | Limit on the number of resource groups to return. Default is 50.                                         | Optional     | 
| tag               | A single tag in the form of '{"Tag Name":"Tag Value"}' to filter the list by.                            | Optional     | 

#### Context Output

| **Path**                                              | **Type** | **Description**                                                                                               |
|-------------------------------------------------------|----------|---------------------------------------------------------------------------------------------------------------|
| AzureNSG.ResourceGroup.id                             | String   | The unique identifier of the Azure Network Security Groups resource group.                                    | 
| AzureNSG.ResourceGroup.name                           | String   | The name of the Azure Network Security Groups resource group.                                                 | 
| AzureNSG.ResourceGroup.type                           | String   | The type of the Azure Network Security Groups resource group.                                                 | 
| AzureNSG.ResourceGroup.location                       | String   | The location of the Azure Network Security Groups resource group.                                             | 
| AzureNSG.ResourceGroup.properties.provisioningState   | String   | The provisioning state of the Azure Network Security Groups resource group.                                   | 
| AzureNSG.ResourceGroup.tags.Owner                     | String   | The owner tag of the Azure Network Security Groups resource group.                                            | 
| AzureNSG.ResourceGroup.tags                           | Unknown  | The tags associated with the Azure Network Security Groups resource group.                                    | 
| AzureNSG.ResourceGroup.tags.Name                      | String   | The name tag of the Azure Network Security Groups resource group.                                             | 
| AzureNSG.ResourceGroup.managedBy                      | String   | The entity that manages the Azure Network Security Groups resource group.                                     | 
| AzureNSG.ResourceGroup.tags.aNSG-managed-cluster-name | String   | The ANSG managed cluster name tag associated with the Azure Network Security Groups resource group.           | 
| AzureNSG.ResourceGroup.tags.aNSG-managed-cluster-rg   | String   | The ANSG managed cluster resource group tag associated with the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags.type                      | String   | The type tag associated with the Azure Network Security Groups resource group.                                | 

#### Command example

```!azure-nsg-resource-group-list```

#### Context Example

```json
{
    "AzureNSG": {
        "ResourceGroup": [
            {
                "id": "/subscriptions/0f907ea4-bc8b-4c11-9d7/resourceGroups/cloud-shell-storage-eastus",
                "location": "eastus",
                "name": "cloud-shell-storage-eastus",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/0f907ea4-bc8b-4c11-9d7/resourceGroups/demi",
                "location": "centralus",
                "name": "demi",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "tags": {
                    "Owner": "Demi"
                },
                "type": "Microsoft.Resources/resourceGroups"
            }
        ]
    }
}
```

#### Human Readable Output

> ### Resource Groups List
>|Name|Location|Tags|
>|---|---|---|
>| cloud-shell-storage-eastus | eastus |  |
>| demi | centralus | Owner: Demi |

### azure-nsg-network-interfaces-create

***
Creates or updates a network interface.

#### Base Command

`azure-nsg-network-interfaces-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nic_name | The network interface name. | Required | 
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name’. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| nsg_name | Existing network security group name. Note: Use azure-nsg-security-groups-list in order to find existing network security group name. | Optional | 
| ip_config_name | Existing IP configuration name. Note: Use azure-nsg-public-ip-adresses-list in order to find available ip configuration. | Required | 
| private_ip | The private IP. | Optional | 
| public_ip_address_name | The public IP address name. | Optional | 
| vnet_name | The virtual network name. | Required | 
| subnet_name | The subnet name. | Required | 
| location | The resource location. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.NetworkInterface.name | String | The network interface's name. | 
| AzureNSG.NetworkInterface.etag | String | The network interface's etag. | 
| AzureNSG.NetworkInterface.properties.provisioningState | String | The network interface's provisioning state. | 
| AzureNSG.NetworkInterface.properties.ipConfigurations.name | List | The name of the resource that is unique within a resource group. | 
| AzureNSG.NetworkInterface.ipConfigurationPrivateIPAddress | List | The private IP address of the IP configuration. | 
| AzureNSG.NetworkInterface.ipConfigurationPublicIPAddressName | List | The ID of the public IP address of the IP configuration. | 
| AzureNSG.NetworkInterface.subnetId | List | The subnet ID of the IP configuration. | 

#### Command example
```!azure-nsg-network-interfaces-create ip_config_name=ipconfig1 location=westeurope nic_name=test subnet_name=default vnet_name=reso-vnet```
#### Context Example
```json
{
    "AzureNSG": {
        "NetworkInterface": {
            "allowPort25Out": false,
            "auxiliaryMode": "None",
            "auxiliarySku": "None",
            "defaultOutboundConnectivityEnabled": false,
            "disableTcpStateTracking": false,
            "dnsSettings": {
                "appliedDnsServers": [],
                "dnsServers": [],
                "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
            },
            "enableAcceleratedNetworking": false,
            "enableIPForwarding": false,
            "etag": "9951f336-2839-426b-864f-9f7b6e5712228",
            "hostedWorkloads": [],
            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test",
            "ipConfigurationName": [
                "ipconfig1"
            ],
            "ipConfigurationPrivateIPAddress": [
                "1.1.1.1"
            ],
            "ipConfigurationProperties": [
                {
                    "primary": true,
                    "privateIPAddress": "1.1.1.1",
                    "privateIPAddressVersion": "IPv4",
                    "privateIPAllocationMethod": "Dynamic",
                    "provisioningState": "Succeeded",
                    "subnet": {
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                    }
                }
            ],
            "ipConfigurationSub": [
                {
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                }
            ],
            "ipConfigurations": [
                {
                    "etag": "W/\"9951f336-2839-426b-864f-9f7b6e5712228\"",
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1",
                    "name": "ipconfig1",
                    "properties": {
                        "primary": true,
                        "privateIPAddress": "1.1.1.1",
                        "privateIPAddressVersion": "IPv4",
                        "privateIPAllocationMethod": "Dynamic",
                        "provisioningState": "Succeeded",
                        "subnet": {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                        }
                    },
                    "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                }
            ],
            "kind": "Regular",
            "location": "westeurope",
            "name": "test",
            "nicType": "Standard",
            "properties": {
                "allowPort25Out": false,
                "auxiliaryMode": "None",
                "auxiliarySku": "None",
                "defaultOutboundConnectivityEnabled": false,
                "disableTcpStateTracking": false,
                "dnsSettings": {
                    "appliedDnsServers": [],
                    "dnsServers": [],
                    "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                },
                "enableAcceleratedNetworking": false,
                "enableIPForwarding": false,
                "hostedWorkloads": [],
                "ipConfigurations": [
                    {
                        "etag": "W/\"9951f336-2839-426b-864f-9f7b6e5712228\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1",
                        "name": "ipconfig1",
                        "properties": {
                            "primary": true,
                            "privateIPAddress": "1.1.1.1",
                            "privateIPAddressVersion": "IPv4",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "subnet": {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                            }
                        },
                        "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                    }
                ],
                "nicType": "Standard",
                "provisioningState": "Succeeded",
                "resourceGuid": "ac108ab8-3aa6-490c-921e-48b83685294d",
                "tapConfigurations": [],
                "vnetEncryptionSupported": false
            },
            "provisioningState": "Succeeded",
            "resourceGuid": "ac108ab8-3aa6-490c-921e-48b83685294d",
            "subnetId": [
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
            ],
            "tapConfigurations": [],
            "type": "Microsoft.Network/networkInterfaces",
            "vnetEncryptionSupported": false
        }
    }
}
```

#### Human Readable Output

>### Network Interface
>|Name|Etag|Provisioning State|Ip Configuration Name|Ip Configuration Private IP Address|Subnet Id|
>|---|---|---|---|---|---|
>| test | 9951f336-2839-426b-864f-9f7b6e5712228 | Succeeded | ipconfig1 | 1.1.1.1 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default |


#### Command example
```!azure-nsg-network-interfaces-create ip_config_name=ipconfig1 location=westeurope nic_name=test subnet_name=default vnet_name=reso-vnet nsg_name=b_tdemo```
#### Context Example
```json
{
    "AzureNSG": {
        "NetworkInterface": {
            "allowPort25Out": false,
            "auxiliaryMode": "None",
            "auxiliarySku": "None",
            "defaultOutboundConnectivityEnabled": false,
            "disableTcpStateTracking": false,
            "dnsSettings": {
                "appliedDnsServers": [],
                "dnsServers": [],
                "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
            },
            "enableAcceleratedNetworking": false,
            "enableIPForwarding": false,
            "etag": "b91a6977-be89-4454-9d76-5c1218427dec",
            "hostedWorkloads": [],
            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test",
            "ipConfigurationName": [
                "ipconfig1"
            ],
            "ipConfigurationPrivateIPAddress": [
                "1.1.1.1"
            ],
            "ipConfigurationProperties": [
                {
                    "primary": true,
                    "privateIPAddress": "1.1.1.1",
                    "privateIPAddressVersion": "IPv4",
                    "privateIPAllocationMethod": "Dynamic",
                    "provisioningState": "Succeeded",
                    "subnet": {
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                    }
                }
            ],
            "ipConfigurationSub": [
                {
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                }
            ],
            "ipConfigurations": [
                {
                    "etag": "W/\"b91a6977-be89-4454-9d76-5c1218427dec\"",
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1",
                    "name": "ipconfig1",
                    "properties": {
                        "primary": true,
                        "privateIPAddress": "1.1.1.1",
                        "privateIPAddressVersion": "IPv4",
                        "privateIPAllocationMethod": "Dynamic",
                        "provisioningState": "Succeeded",
                        "subnet": {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                        }
                    },
                    "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                }
            ],
            "kind": "Regular",
            "location": "westeurope",
            "name": "test",
            "networkSecurityGroup": {
                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo"
            },
            "nicType": "Standard",
            "properties": {
                "allowPort25Out": false,
                "auxiliaryMode": "None",
                "auxiliarySku": "None",
                "defaultOutboundConnectivityEnabled": false,
                "disableTcpStateTracking": false,
                "dnsSettings": {
                    "appliedDnsServers": [],
                    "dnsServers": [],
                    "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                },
                "enableAcceleratedNetworking": false,
                "enableIPForwarding": false,
                "hostedWorkloads": [],
                "ipConfigurations": [
                    {
                        "etag": "W/\"b91a6977-be89-4454-9d76-5c1218427dec\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1",
                        "name": "ipconfig1",
                        "properties": {
                            "primary": true,
                            "privateIPAddress": "1.1.1.1",
                            "privateIPAddressVersion": "IPv4",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "subnet": {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                            }
                        },
                        "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                    }
                ],
                "networkSecurityGroup": {
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo"
                },
                "nicType": "Standard",
                "provisioningState": "Succeeded",
                "resourceGuid": "ac108ab8-3aa6-490c-921e-48b83685294d",
                "tapConfigurations": [],
                "vnetEncryptionSupported": false
            },
            "provisioningState": "Succeeded",
            "resourceGuid": "ac108ab8-3aa6-490c-921e-48b83685294d",
            "subnetId": [
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
            ],
            "tapConfigurations": [],
            "type": "Microsoft.Network/networkInterfaces",
            "vnetEncryptionSupported": false
        }
    }
}
```

#### Human Readable Output

>### Network Interface
>|Name|Etag|Provisioning State|Ip Configuration Name|Ip Configuration Private IP Address|Subnet Id|
>|---|---|---|---|---|---|
>| test | b91a6977-be89-4454-9d76-5c1218427dec | Succeeded | ipconfig1 | 1.1.1.1 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default |


### azure-nsg-virtual-networks-list

***
Gets virtual networks in a resource group.

#### Base Command

`azure-nsg-virtual-networks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name’. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.VirtualNetwork.name | String | The virtual network's name. | 
| AzureNSG.VirtualNetwork.etag | String | The virtual network's etag. | 
| AzureNSG.VirtualNetwork.location | String | The virtual network's location. | 
| AzureNSG.VirtualNetwork.properties.addressSpace.addressPrefixes | String | A list of address blocks reserved for this virtual network in CIDR notation. | 
| AzureNSG.VirtualNetwork.properties.subnets.name | List | The virtual network's subnet name. | 
| AzureNSG.VirtualNetwork.subnetAdrdressPrefix | List | The virtual network's subnet address prefix. | 
| AzureNSG.VirtualNetwork.subnetID | List | List of the virtual network's subnets ID. | 

#### Command example
```!azure-nsg-virtual-networks-list```
#### Context Example
```json
{
    "AzureNSG": {
        "VirtualNetwork": {
            "addressPrefixes": [
                "1.1.1.1/16"
            ],
            "addressSpace": {
                "addressPrefixes": [
                    "1.1.1.1/16"
                ]
            },
            "enableDdosProtection": false,
            "etag": "702f1e03-4a6b-43de-a0ae-d09cc4808ba5",
            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet",
            "location": "westeurope",
            "name": "reso-vnet",
            "privateEndpointVNetPolicies": "Disabled",
            "properties": {
                "addressSpace": {
                    "addressPrefixes": [
                        "1.1.1.1/16"
                    ]
                },
                "enableDdosProtection": false,
                "privateEndpointVNetPolicies": "Disabled",
                "provisioningState": "Succeeded",
                "resourceGuid": "60d3a04a-d654-49e9-abf1-a4f0f33230b9",
                "subnets": [
                    {
                        "etag": "W/\"702f1e03-4a6b-43de-a0ae-d09cc4808ba5\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default",
                        "name": "default",
                        "properties": {
                            "addressPrefix": "1.1.1.1/24",
                            "delegations": [],
                            "ipConfigurations": [
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TE/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TEST/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR___/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/B_TEST/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC1/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC2/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE/ipConfigurations/IPCONFIG1"
                                },
                                {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/TEST/ipConfigurations/IPCONFIG1"
                                }
                            ],
                            "privateEndpointNetworkPolicies": "Enabled",
                            "privateLinkServiceNetworkPolicies": "Enabled",
                            "provisioningState": "Succeeded"
                        },
                        "type": "Microsoft.Network/virtualNetworks/subnets"
                    }
                ],
                "virtualNetworkPeerings": []
            },
            "provisioningState": "Succeeded",
            "resourceGuid": "60d3a04a-d654-49e9-abf1-a4f0f33230b9",
            "subnetAdrdressPrefix": [
                "1.1.1.1/24"
            ],
            "subnetID": [
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TE/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TEST/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR___/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/B_TEST/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC1/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC2/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE/ipConfigurations/IPCONFIG1",
                "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/TEST/ipConfigurations/IPCONFIG1"
            ],
            "subnetName": [
                "default"
            ],
            "subnetProperties": [
                {
                    "addressPrefix": "1.1.1.1/24",
                    "delegations": [],
                    "ipConfigurations": [
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TE/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TEST/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR___/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/B_TEST/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC1/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC2/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE/ipConfigurations/IPCONFIG1"
                        },
                        {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/TEST/ipConfigurations/IPCONFIG1"
                        }
                    ],
                    "privateEndpointNetworkPolicies": "Enabled",
                    "privateLinkServiceNetworkPolicies": "Enabled",
                    "provisioningState": "Succeeded"
                }
            ],
            "subnets": [
                {
                    "etag": "W/\"702f1e03-4a6b-43de-a0ae-d09cc4808ba5\"",
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default",
                    "name": "default",
                    "properties": {
                        "addressPrefix": "1.1.1.1/24",
                        "delegations": [],
                        "ipConfigurations": [
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TE/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TEST/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR___/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/B_TEST/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC1/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC2/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE/ipConfigurations/IPCONFIG1"
                            },
                            {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/TEST/ipConfigurations/IPCONFIG1"
                            }
                        ],
                        "privateEndpointNetworkPolicies": "Enabled",
                        "privateLinkServiceNetworkPolicies": "Enabled",
                        "provisioningState": "Succeeded"
                    },
                    "type": "Microsoft.Network/virtualNetworks/subnets"
                }
            ],
            "type": "Microsoft.Network/virtualNetworks",
            "virtualNetworkPeerings": []
        }
    }
}
```

#### Human Readable Output

>### Virtual Networks List
>|Name|Etag|Location|Address Prefixes|Subnet Name|Subnet Adrdress Prefix|Subnet ID|
>|---|---|---|---|---|---|---|
>| reso-vnet | 702f1e03-4a6b-43de-a0ae-d09cc4808ba5 | westeurope | 1.1.1.1/16 | default | 1.1.1.1/24 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TE/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR_TEST/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/BAR___/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/B_TEST/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC1/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE-INTEGRATION-NIC2/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/COMPUTE/ipConfigurations/IPCONFIG1,<br/>/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/COMPUTE-INTEGRATION/providers/Microsoft.Network/networkInterfaces/TEST/ipConfigurations/IPCONFIG1 |


### azure-nsg-security-group-create

***
Creates a network security group in the specified resource group.

#### Base Command

`azure-nsg-security-group-create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The security group name. | Required | 
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name’. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| location | The resource location. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.SecurityGroup.name | String | The network security group's name. | 
| AzureNSG.SecurityGroup.etag | String | The network security group's etag. | 
| AzureNSG.SecurityGroup.location | String | The network security group's location. | 
| AzureNSG.SecurityGroup.properties.securityRules | List | A collection of security rules of the network security group. | 

#### Command example
```!azure-nsg-security-group-create location=westeurope security_group_name=b_tdemo```
#### Context Example
```json
{
    "AzureNSG": {
        "SecurityGroup": {
            "etag": "793369e4-1c53-4d8e-b36d-a064fbb7ee78",
            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo",
            "location": "westeurope",
            "name": "b_tdemo",
            "properties": {
                "defaultSecurityRules": [
                    {
                        "etag": "W/\"793369e4-1c53-4d8e-b36d-a064fbb7ee78\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo/defaultSecurityRules/AllowVnetInBound",
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
                        },
                        "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"
                    },
                    {
                        "etag": "W/\"793369e4-1c53-4d8e-b36d-a064fbb7ee78\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo/defaultSecurityRules/AllowAzureLoadBalancerInBound",
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
                        },
                        "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"
                    },
                    {
                        "etag": "W/\"793369e4-1c53-4d8e-b36d-a064fbb7ee78\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo/defaultSecurityRules/DenyAllInBound",
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
                        },
                        "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"
                    },
                    {
                        "etag": "W/\"793369e4-1c53-4d8e-b36d-a064fbb7ee78\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo/defaultSecurityRules/AllowVnetOutBound",
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
                        },
                        "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"
                    },
                    {
                        "etag": "W/\"793369e4-1c53-4d8e-b36d-a064fbb7ee78\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo/defaultSecurityRules/AllowInternetOutBound",
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
                        },
                        "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"
                    },
                    {
                        "etag": "W/\"793369e4-1c53-4d8e-b36d-a064fbb7ee78\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/b_tdemo/defaultSecurityRules/DenyAllOutBound",
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
                        },
                        "type": "Microsoft.Network/networkSecurityGroups/defaultSecurityRules"
                    }
                ],
                "provisioningState": "Succeeded",
                "resourceGuid": "8ec671ac-b5d3-4b95-9be3-21e6015044ce",
                "securityRules": []
            },
            "securityRules": [],
            "type": "Microsoft.Network/networkSecurityGroups"
        }
    }
}
```

#### Human Readable Output

>### Security Group List
>|Name|Etag|Location|
>|---|---|---|
>| b_tdemo | 793369e4-1c53-4d8e-b36d-a064fbb7ee78 | westeurope |


### azure-nsg-network-interfaces-list

***
Gets network interfaces in a resource group.

#### Base Command

`azure-nsg-network-interfaces-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name’. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.NetworkInterfaces.name | String | The network interface's name. | 
| AzureNSG.NetworkInterfaces.id | String | The network interface's ID. | 
| AzureNSG.NetworkInterfaces.properties.provisioningState | String | The network interface's provisioning state. | 
| AzureNSG.NetworkInterfaces.ipConfigurationName | List | The name of the resource that is unique within a resource group. | 
| AzureNSG.NetworkInterfaces.ipConfigurationID | List | The resource ID. | 
| AzureNSG.NetworkInterfaces.ipConfigurationPrivateIPAddress | List | The private IP address of the IP configuration. | 
| AzureNSG.NetworkInterfaces.ipConfigurationPublicIPAddressName | List | The ID of the public IP address of the IP configuration. | 
| AzureNSG.NetworkInterfaces.dnsServers | List | List of DNS servers IP addresses. | 
| AzureNSG.NetworkInterfaces.appliedDnsServers | List | List of all DNS servers from all NICs that are part of the Availability Set. | 
| AzureNSG.NetworkInterfaces.internalDomainNameSuffix | String | The network interface's internal domain name suffix. | 
| AzureNSG.NetworkInterfaces.properties.macAddress | String | The network interface's MAC address. | 
| AzureNSG.NetworkInterfaces.properties.virtualMachine.id | String | The network interface's virtual machine's ID. | 
| AzureNSG.NetworkInterfaces.location | String | The network interface's location. | 
| AzureNSG.NetworkInterfaces.kind | String | The network interface's kind. | 

#### Command example
```!azure-nsg-network-interfaces-list all_results=false limit=3```
#### Context Example
```json
{
    "AzureNSG": {
        "NetworkInterfaces": [
            {
                "allowPort25Out": false,
                "appliedDnsServers": [],
                "auxiliaryMode": "None",
                "auxiliarySku": "None",
                "defaultOutboundConnectivityEnabled": false,
                "disableTcpStateTracking": false,
                "dnsServers": [],
                "dnsSettings": {
                    "appliedDnsServers": [],
                    "dnsServers": [],
                    "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                },
                "enableAcceleratedNetworking": false,
                "enableIPForwarding": false,
                "etag": "W/\"4f006f0c-acd1-4aeb-8d53-37ae4159f05a\"",
                "hostedWorkloads": [],
                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te",
                "internalDomainNameSuffix": "example.ax.internal.cloudapp.net",
                "ipConfigurationID": [
                    "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te/ipConfigurations/ipconfig1"
                ],
                "ipConfigurationName": [
                    "ipconfig1"
                ],
                "ipConfigurationPrivateIPAddress": [
                    "1.1.1.1"
                ],
                "ipConfigurationPublicIPAddress": [
                    {
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST"
                    }
                ],
                "ipConfigurationPublicIPAddressName": [
                    "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST"
                ],
                "ipConfigurations": [
                    {
                        "etag": "W/\"4f006f0c-acd1-4aeb-8d53-37ae4159f05a\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te/ipConfigurations/ipconfig1",
                        "name": "ipconfig1",
                        "properties": {
                            "primary": true,
                            "privateIPAddress": "1.1.1.1",
                            "privateIPAddressVersion": "IPv4",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "publicIPAddress": {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST"
                            },
                            "subnet": {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                            }
                        },
                        "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                    }
                ],
                "ipConfigurationsProperties": [
                    {
                        "primary": true,
                        "privateIPAddress": "1.1.1.1",
                        "privateIPAddressVersion": "IPv4",
                        "privateIPAllocationMethod": "Dynamic",
                        "provisioningState": "Succeeded",
                        "publicIPAddress": {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST"
                        },
                        "subnet": {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                        }
                    }
                ],
                "kind": "Regular",
                "location": "westeurope",
                "name": "b_te",
                "networkSecurityGroup": {
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/test"
                },
                "nicType": "Standard",
                "properties": {
                    "allowPort25Out": false,
                    "auxiliaryMode": "None",
                    "auxiliarySku": "None",
                    "defaultOutboundConnectivityEnabled": false,
                    "disableTcpStateTracking": false,
                    "dnsSettings": {
                        "appliedDnsServers": [],
                        "dnsServers": [],
                        "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                    },
                    "enableAcceleratedNetworking": false,
                    "enableIPForwarding": false,
                    "hostedWorkloads": [],
                    "ipConfigurations": [
                        {
                            "etag": "W/\"4f006f0c-acd1-4aeb-8d53-37ae4159f05a\"",
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te/ipConfigurations/ipconfig1",
                            "name": "ipconfig1",
                            "properties": {
                                "primary": true,
                                "privateIPAddress": "1.1.1.1",
                                "privateIPAddressVersion": "IPv4",
                                "privateIPAllocationMethod": "Dynamic",
                                "provisioningState": "Succeeded",
                                "publicIPAddress": {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST"
                                },
                                "subnet": {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                                }
                            },
                            "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                        }
                    ],
                    "networkSecurityGroup": {
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/test"
                    },
                    "nicType": "Standard",
                    "provisioningState": "Succeeded",
                    "resourceGuid": "2afeba51-01f4-4cb7-b771-4ecc84a3417f",
                    "tapConfigurations": [],
                    "vnetEncryptionSupported": false
                },
                "provisioningState": "Succeeded",
                "resourceGuid": "2afeba51-01f4-4cb7-b771-4ecc84a3417f",
                "tapConfigurations": [],
                "type": "Microsoft.Network/networkInterfaces",
                "vnetEncryptionSupported": false
            },
            {
                "allowPort25Out": false,
                "appliedDnsServers": [],
                "auxiliaryMode": "None",
                "auxiliarySku": "None",
                "defaultOutboundConnectivityEnabled": false,
                "disableTcpStateTracking": false,
                "dnsServers": [],
                "dnsSettings": {
                    "appliedDnsServers": [],
                    "dnsServers": [],
                    "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                },
                "enableAcceleratedNetworking": false,
                "enableIPForwarding": false,
                "etag": "W/\"9951f336-2839-426b-864f-9f7b6e5712228\"",
                "hostedWorkloads": [],
                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test",
                "internalDomainNameSuffix": "example.ax.internal.cloudapp.net",
                "ipConfigurationID": [
                    "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1"
                ],
                "ipConfigurationName": [
                    "ipconfig1"
                ],
                "ipConfigurationPrivateIPAddress": [
                    "1.1.1.1"
                ],
                "ipConfigurations": [
                    {
                        "etag": "W/\"9951f336-2839-426b-864f-9f7b6e5712228\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1",
                        "name": "ipconfig1",
                        "properties": {
                            "primary": true,
                            "privateIPAddress": "1.1.1.1",
                            "privateIPAddressVersion": "IPv4",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "subnet": {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                            }
                        },
                        "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                    }
                ],
                "ipConfigurationsProperties": [
                    {
                        "primary": true,
                        "privateIPAddress": "1.1.1.1",
                        "privateIPAddressVersion": "IPv4",
                        "privateIPAllocationMethod": "Dynamic",
                        "provisioningState": "Succeeded",
                        "subnet": {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                        }
                    }
                ],
                "kind": "Regular",
                "location": "westeurope",
                "name": "test",
                "nicType": "Standard",
                "properties": {
                    "allowPort25Out": false,
                    "auxiliaryMode": "None",
                    "auxiliarySku": "None",
                    "defaultOutboundConnectivityEnabled": false,
                    "disableTcpStateTracking": false,
                    "dnsSettings": {
                        "appliedDnsServers": [],
                        "dnsServers": [],
                        "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                    },
                    "enableAcceleratedNetworking": false,
                    "enableIPForwarding": false,
                    "hostedWorkloads": [],
                    "ipConfigurations": [
                        {
                            "etag": "W/\"9951f336-2839-426b-864f-9f7b6e5712228\"",
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1",
                            "name": "ipconfig1",
                            "properties": {
                                "primary": true,
                                "privateIPAddress": "1.1.1.1",
                                "privateIPAddressVersion": "IPv4",
                                "privateIPAllocationMethod": "Dynamic",
                                "provisioningState": "Succeeded",
                                "subnet": {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                                }
                            },
                            "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                        }
                    ],
                    "nicType": "Standard",
                    "provisioningState": "Succeeded",
                    "resourceGuid": "ac108ab8-3aa6-490c-921e-48b83685294d",
                    "tapConfigurations": [],
                    "vnetEncryptionSupported": false
                },
                "provisioningState": "Succeeded",
                "resourceGuid": "ac108ab8-3aa6-490c-921e-48b83685294d",
                "tapConfigurations": [],
                "type": "Microsoft.Network/networkInterfaces",
                "vnetEncryptionSupported": false
            },
            {
                "allowPort25Out": false,
                "appliedDnsServers": [],
                "auxiliaryMode": "None",
                "auxiliarySku": "None",
                "defaultOutboundConnectivityEnabled": false,
                "disableTcpStateTracking": false,
                "dnsServers": [],
                "dnsSettings": {
                    "appliedDnsServers": [],
                    "dnsServers": [],
                    "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                },
                "enableAcceleratedNetworking": false,
                "enableIPForwarding": false,
                "etag": "W/\"330eecfe-c3f8-4f5e-8af0-6a21d4a1c80a\"",
                "hostedWorkloads": [],
                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b___",
                "internalDomainNameSuffix": "example.ax.internal.cloudapp.net",
                "ipConfigurationID": [
                    "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b___/ipConfigurations/ipconfig1"
                ],
                "ipConfigurationName": [
                    "ipconfig1"
                ],
                "ipConfigurationPrivateIPAddress": [
                    "1.1.1.1"
                ],
                "ipConfigurations": [
                    {
                        "etag": "W/\"330eecfe-c3f8-4f5e-8af0-6a21d4a1c80a\"",
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b___/ipConfigurations/ipconfig1",
                        "name": "ipconfig1",
                        "properties": {
                            "primary": true,
                            "privateIPAddress": "1.1.1.1",
                            "privateIPAddressVersion": "IPv4",
                            "privateIPAllocationMethod": "Dynamic",
                            "provisioningState": "Succeeded",
                            "subnet": {
                                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                            }
                        },
                        "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                    }
                ],
                "ipConfigurationsProperties": [
                    {
                        "primary": true,
                        "privateIPAddress": "1.1.1.1",
                        "privateIPAddressVersion": "IPv4",
                        "privateIPAllocationMethod": "Dynamic",
                        "provisioningState": "Succeeded",
                        "subnet": {
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                        }
                    }
                ],
                "kind": "Regular",
                "location": "westeurope",
                "name": "b___",
                "networkSecurityGroup": {
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/test"
                },
                "nicType": "Standard",
                "properties": {
                    "allowPort25Out": false,
                    "auxiliaryMode": "None",
                    "auxiliarySku": "None",
                    "defaultOutboundConnectivityEnabled": false,
                    "disableTcpStateTracking": false,
                    "dnsSettings": {
                        "appliedDnsServers": [],
                        "dnsServers": [],
                        "internalDomainNameSuffix": "example.ax.internal.cloudapp.net"
                    },
                    "enableAcceleratedNetworking": false,
                    "enableIPForwarding": false,
                    "hostedWorkloads": [],
                    "ipConfigurations": [
                        {
                            "etag": "W/\"330eecfe-c3f8-4f5e-8af0-6a21d4a1c80a\"",
                            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b___/ipConfigurations/ipconfig1",
                            "name": "ipconfig1",
                            "properties": {
                                "primary": true,
                                "privateIPAddress": "1.1.1.1",
                                "privateIPAddressVersion": "IPv4",
                                "privateIPAllocationMethod": "Dynamic",
                                "provisioningState": "Succeeded",
                                "subnet": {
                                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/virtualNetworks/reso-vnet/subnets/default"
                                }
                            },
                            "type": "Microsoft.Network/networkInterfaces/ipConfigurations"
                        }
                    ],
                    "networkSecurityGroup": {
                        "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkSecurityGroups/test"
                    },
                    "nicType": "Standard",
                    "provisioningState": "Succeeded",
                    "resourceGuid": "d8289f9e-0a9f-47ba-8e01-061f2bf8e868",
                    "tapConfigurations": [],
                    "vnetEncryptionSupported": false
                },
                "provisioningState": "Succeeded",
                "resourceGuid": "d8289f9e-0a9f-47ba-8e01-061f2bf8e868",
                "tapConfigurations": [],
                "type": "Microsoft.Network/networkInterfaces",
                "vnetEncryptionSupported": false
            }
        ]
    }
}
```

#### Human Readable Output

>### Network Interfaces List
>|Name|Id|Provisioning State|Ip Configuration Name|Ip Configuration ID|Ip Configuration Private IP Address|Ip Configuration Public IP Address Name|Internal Domain Name Suffix|Location|Kind|
>|---|---|---|---|---|---|---|---|---|---|
>| b_te | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te | Succeeded | ipconfig1 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te/ipConfigurations/ipconfig1 | 1.1.1.1 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST | example.ax.internal.cloudapp.net | westeurope | Regular |
>| test | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test | Succeeded | ipconfig1 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/test/ipConfigurations/ipconfig1 | 1.1.1.1 |  | example.ax.internal.cloudapp.net | westeurope | Regular |
>| b___ | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b___ | Succeeded | ipconfig1 | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b___/ipConfigurations/ipconfig1 | 1.1.1.1 |  | example.ax.internal.cloudapp.net | westeurope | Regular |


### azure-nsg-public-ip-addresses-list

***
Gets public IP addresses in a resource group.

#### Base Command

`azure-nsg-public-ip-addresses-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name’. | Optional | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| limit | The maximum number of records to return. Default is 50. | Optional | 
| all_results | Whether to retrieve all the results by overriding the default limit. Possible values are: false, true. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.PublicIPAdress.name | String | The public IP address's name. | 
| AzureNSG.PublicIPAdress.id | String | The public IP address's ID. | 
| AzureNSG.PublicIPAdress.etag | String | The public IP address's etag. | 
| AzureNSG.PublicIPAdress.provisioningState | String | The public IP address's provisioning state. | 
| AzureNSG.PublicIPAdress.publicIPAddressVersion | String | The public IP address's version. | 
| AzureNSG.PublicIPAdress.ipAddress | String | The public IP address's IP address. | 
| AzureNSG.PublicIPAdress.domainNameLabel | String | The public IP address's domain name label. | 
| AzureNSG.PublicIPAdress.fqdn | String | The public IP address's fully qualified domain name \(FQDN\). | 

#### Command example
```!azure-nsg-public-ip-addresses-list```
#### Context Example
```json
{
    "AzureNSG": {
        "PublicIPAddress": {
            "ddosSettings": {
                "protectionMode": "Enabled"
            },
            "etag": "f71be785-f134-4ccc-a1f9-b044415d9969",
            "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST",
            "idleTimeoutInMinutes": 4,
            "ipAddress": "1.1.1.1",
            "ipConfiguration": {
                "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te/ipConfigurations/ipconfig1"
            },
            "ipTags": [],
            "location": "westeurope",
            "name": "WinVM-CRTX-71942-ip-TEST",
            "properties": {
                "ddosSettings": {
                    "protectionMode": "Enabled"
                },
                "idleTimeoutInMinutes": 4,
                "ipAddress": "1.1.1.1",
                "ipConfiguration": {
                    "id": "/subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/networkInterfaces/b_te/ipConfigurations/ipconfig1"
                },
                "ipTags": [],
                "provisioningState": "Succeeded",
                "publicIPAddressVersion": "IPv4",
                "publicIPAllocationMethod": "Static",
                "resourceGuid": "c9a6ea68-c4b9-4a90-97b3-60ff40e30ecb"
            },
            "provisioningState": "Succeeded",
            "publicIPAddressVersion": "IPv4",
            "publicIPAllocationMethod": "Static",
            "resourceGuid": "c9a6ea68-c4b9-4a90-97b3-60ff40e30ecb",
            "sku": {
                "name": "Standard",
                "tier": "Regional"
            },
            "tags": {},
            "type": "Microsoft.Network/publicIPAddresses",
            "zones": [
                "3",
                "1",
                "2"
            ]
        }
    }
}
```

#### Human Readable Output

>### Public IP Addresses List
>|Name|Id|Etag|Provisioning State|Public IP Address Version|Ip Address|
>|---|---|---|---|---|---|
>| WinVM-CRTX-71942-ip-TEST | /subscriptions/0f945ea2-bc8a-4c11-9d7e-806c1fd144fb/resourceGroups/reso/providers/Microsoft.Network/publicIPAddresses/WinVM-CRTX-71942-ip-TEST | f71be785-f134-4ccc-a1f9-b044415d9969 | Succeeded | IPv4 | 1.1.1.1 |


