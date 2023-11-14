Azure network security groups are used to filter network traffic to and from Azure resources in an Azure virtual network.
This integration was integrated and tested with version 2022-09-01 of Azure Network Security Groups.
## Configure Azure Network Security Groups on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Network Security Groups.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID |  | False |
     | Default Subscription ID | There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value. | True |
    | Default Resource Group Name |There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value.  | True |
    | Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Authentication Type | Type of authentication - can be Authorization Code flow \(recommended\), Device Code Flow, or Azure Managed Identities. | True |
    | Tenant ID (for user-auth mode) |  | False |
    | Client Secret (for user-auth mode) |  | False |
    | Application redirect URI (for user-auth mode) |  | False |
    | Authorization code | For user-auth mode - received from the authorization step. See Detailed Instructions \(?\) section. | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. |False |

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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.SecurityGroup.name | String | The security group's name. | 
| AzureNSG.SecurityGroup.id | String | The security group's ID. | 
| AzureNSG.SecurityGroup.etag | String | The security group's ETag. | 
| AzureNSG.SecurityGroup.type | String | The security group's type. | 
| AzureNSG.SecurityGroup.location | String | The security group's location. | 
| AzureNSG.SecurityGroup.tags | String | The security group's tags. | 


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

>### Network Security Groups
>|etag|id|location|name|tags|type|
>|---|---|---|---|---|---|
>| W/"fdba51cf-46b3-44af-8da5-16666aa578cc" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg | westeurope | alerts-nsg |  | Microsoft.Network/networkSecurityGroups |


### azure-nsg-security-rules-list
***
List all rules of the specified security groups.


#### Base Command

`azure-nsg-security-rules-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | A comma-separated list of the names of the security groups. | Required | 
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| limit | The maximum number of rules to display. Default is 50. | Optional | 
| offset | The index of the first rule to display. Used for pagination. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", or "\*"". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of source ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be either "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be either "Inbound" or "Outbound". | 


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

>### Rules in alerts-nsg
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

>✅ Success!

### azure-nsg-security-rules-delete
***
Delete a security rule.


#### Base Command

`azure-nsg-security-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be deleted. | Required |
|subscription_id|The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. |Optional|
resource_group_name| The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'.|Optional|


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-nsg-security-rules-delete security_group_name=alerts-nsg security_rule_name=wow```

#### Human Readable Output

>Rule wow deleted.

### azure-nsg-security-rules-create
***
Create a security rule.


#### Base Command

`azure-nsg-security-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be created. | Required | 
| direction | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound. | Required | 
| action | Whether to allow the traffic. Possible values are: "Allow" and "Deny". Possible values are: Allow, Deny. | Optional | 
| protocol | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP" and "ICMP". Possible values are: Any, TCP, UDP, ICMP. | Optional | 
| source | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. Default is "Any". | Optional | 
| priority | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. Default is "4096".| Optional | 
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional | 
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional | 
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional | 
| description | A description to add to the rule. | Optional |
|subscription_id|The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. |Optional|
resource_group_name| The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'.|Optional|


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", or "\*". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". | 


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

>### Rules rulerule
>|access|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRange|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | * | * | Inbound | W/"276dc93a-488d-47a1-8971-19a1171242a9" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/rulerule | rulerule | 4096 | * | Updating | 1.1.1.1 | * | Microsoft.Network/networkSecurityGroups/securityRules |


### azure-nsg-security-rules-update
***
Update a security rule. If one does not exist, it will be created.


#### Base Command

`azure-nsg-security-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be updated. | Required | 
| direction | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound. | Optional | 
| action | Whether to allow the traffic. Possible values are "Allow" and "Deny". Possible values are: Allow, Deny. | Optional | 
| protocol | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP", and "ICMP". Possible values are: Any, TCP, UDP, ICMP. | Optional | 
| source | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. Default is "Any". | Optional | 
| priority | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. Default is "4096". | Optional | 
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*".| Optional | 
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional | 
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional | 
| description | A description to add to the rule. | Optional | 
|subscription_id|The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. |Optional|
resource_group_name|The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. |Optional|


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", "\*". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". | 


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

>### Rules XSOAR_Rule
>|access|description|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRange|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | description | 11.0.0.0/8 | 8080 | Outbound | W/"9fad6036-4c3a-4d60-aac9-18281dba3305" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/XSOAR_Rule | XSOAR_Rule | 100 | * | Succeeded | 10.0.0.0/8 | * | Microsoft.Network/networkSecurityGroups/securityRules |


### azure-nsg-security-rules-get
***
Get a specific rule.


#### Base Command

`azure-nsg-security-rule-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Optional | 
| security_rule_name | A comma-separated list of the names of the rules to get. | Optional |
|subscription_id|The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. |Optional|
resource_group_name| The name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. |Optional|


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", "\*". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". | 


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

>### Rules wow
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
>To sign in, use a web browser to open the page https://microsoft.com/devicelogin
and enter the code CODECODE to authenticate.
Run the !azure-nsg-auth-complete command in the War Room.


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

>✅ Authorization completed successfully.

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

>Authorization was reset successfully. You can now run **!azure-nsg-auth-start** and **!azure-nsg-auth-complete**.
### azure-nsg-security-rule-delete
***
Delete a security rule.


#### Base Command

`azure-nsg-security-rule-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be deleted. | Required | 


#### Context Output

There is no context output for this command.
### azure-nsg-security-rule-create
***
Create a security rule.


#### Base Command

`azure-nsg-security-rule-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be created. | Required | 
| direction | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound. | Required | 
| action | Whether to allow the traffic. Possible values are: "Allow" and "Deny". Possible values are: Allow, Deny. | Optional | 
| protocol | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP" and "ICMP". Possible values are: Any, TCP, UDP, ICMP. | Optional | 
| source | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. | Optional | 
| priority | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. | Optional | 
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional | 
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional | 
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional | 
| description | A description to add to the rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", or "\*". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". | 
### azure-nsg-security-rule-update
***
Update a security rule. If one does not exist, it will be created.


#### Base Command

`azure-nsg-security-rule-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be updated. | Required | 
| direction | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound. | Optional | 
| action | Whether to allow the traffic. Possible values are "Allow" and "Deny". Possible values are: Allow, Deny. | Optional | 
| protocol | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP", and "ICMP". Possible values are: Any, TCP, UDP, ICMP. | Optional | 
| source | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. | Optional | 
| priority | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. | Optional | 
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional | 
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional | 
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. | Optional | 
| description | A description to add to the rule. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", "\*". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". | 
### azure-nsg-security-rule-get
***
Get a specific rule.


#### Base Command

`azure-nsg-security-rule-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Optional | 
| security_rule_name | A comma-separated list of the names of the rules to get. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Rule.name | String | The rule's name. | 
| AzureNSG.Rule.id | String | The rule's ID. | 
| AzureNSG.Rule.etag | String | The rule's ETag. | 
| AzureNSG.Rule.type | String | The rule's type. | 
| AzureNSG.Rule.provisioningState | String | The rule's provisioning state. | 
| AzureNSG.Rule.protocol | String | The protocol. Can be "TCP", "UDP", "ICMP", "\*". | 
| AzureNSG.Rule.sourcePortRange | String | For a single port, the source port or a range of ports. Note that for multiple ports, \`sourcePortRanges\` will appear instead. | 
| AzureNSG.Rule.sourcePortRanges | String | For multiple ports, a list of these ports. Note that for single ports, \`sourcePortRange\` will appear instead. | 
| AzureNSG.Rule.destinationPortRange | String | For a single port, the destination port or range of ports. Note that for multiple ports, \`destinationPortRanges\` will appear instead. | 
| AzureNSG.Rule.destinationPortRanges | String | For multiple ports, a list of destination ports. Note that for single ports, \`destinationPortRange\` will appear instead. | 
| AzureNSG.Rule.sourceAddressPrefix | String | The source address. | 
| AzureNSG.Rule.destinationAddressPrefix | String | The destination address. | 
| AzureNSG.Rule.access | String | The rule's access. Can be "Allow" or "Deny". | 
| AzureNSG.Rule.priority | Number | The rule's priority. Can be from 100 to 4096. | 
| AzureNSG.Rule.direction | String | The rule's direction. Can be "Inbound" or "Outbound". | 


### azure-nsg-generate-login-url
***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-nsg-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```azure-nsg-generate-login-url```

#### Human Readable Output

>### Authorization instructions
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

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.Subscription.id | String | The unique identifier of the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.authorizationSource | String | The source of authorization for the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.managedByTenants | Unknown | The tenants that have access to manage the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.subscriptionId | String | The ID of the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.tenantId | String | The ID of the tenant associated with the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.displayName | String | The display name of the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.state | String | The current state of the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.subscriptionPolicies.locationPlacementId | String | The ID of the location placement policy for the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.subscriptionPolicies.quotaId | String | The ID of the quota policy for the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.subscriptionPolicies.spendingLimit | String | The spending limit policy for the Azure Network Security Groups subscription. | 
| AzureNSG.Subscription.count.type | String | The type of the Azure Network Security Groups subscription count. | 
| AzureNSG.Subscription.count.value | Number | The value of the Azure Network Security Groups subscription count. | 

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

>### Azure Network Security Groups Subscriptions list
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

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional | 
| limit | Limit on the number of resource groups to return. Default is 50. | Optional | 
| tag | A single tag in the form of '{"Tag Name":"Tag Value"}' to filter the list by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureNSG.ResourceGroup.id | String | The unique identifier of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.name | String | The name of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.type | String | The type of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.location | String | The location of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.properties.provisioningState | String | The provisioning state of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags.Owner | String | The owner tag of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags | Unknown | The tags associated with the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags.Name | String | The name tag of the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.managedBy | String | The entity that manages the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags.aNSG-managed-cluster-name | String | The ANSG managed cluster name tag associated with the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags.aNSG-managed-cluster-rg | String | The ANSG managed cluster resource group tag associated with the Azure Network Security Groups resource group. | 
| AzureNSG.ResourceGroup.tags.type | String | The type tag associated with the Azure Network Security Groups resource group. | 

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
            },
        ]
    }
}
```

#### Human Readable Output

>### Resource Groups List
>|Name|Location|Tags|
>|---|---|---|
>| cloud-shell-storage-eastus | eastus |  |
>| demi | centralus | Owner: Demi |
