Azure network security groups are used to filter network traffic to and from Azure resources in an Azure virtual network.
## Configure Azure Network Security Groups on Cortex XSOAR

In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!azure-nsg-auth-start*** command. 
3. Follow the instructions that appear.
4. Run the ***!azure-nsg-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully. 

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (d4736600-e3d5-4c97-8e65-57abd2b979fe).

You only need to fill in your subscription ID and resource group name. 

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-nsg-security-groups-list
***
List all network security groups.


#### Base Command

`azure-nsg-security-groups-list`
#### Input

There are no input arguments for this command.

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
| limit | The maximum number of rules to display. Default is 50. | Optional | 
| offset | The index of the first rule to display.  Used for pagination. Default is 0. | Optional | 


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
            "sourceAddressPrefix": "8.1.2.3",
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
>| Allow | 1.1.1.1 | * | Inbound | W/"fdba51cf-46b3-44af-8da5-16666aa578cc" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/wow | wow | 3323 | * | Succeeded | 8.1.2.3 | 1,<br/>2,<br/>3 | Microsoft.Network/networkSecurityGroups/securityRules |


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

`azure-nsg-security-rules-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be deleted. | Required | 


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

`azure-nsg-security-rules-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| security_group_name | The name of the security group. | Required | 
| security_rule_name | The name of the rule to be created. | Required | 
| direction | The direction of the rule. Possible values are: "Inbound" and "Outbound". Possible values are: Inbound, Outbound. | Required | 
| action | Whether to allow the traffic. Possible values are: "Allow" and "Deny". Possible values are: Allow, Deny. | Optional | 
| protocol | The protocol on which to apply the rule. Possible values are: "Any", "TCP", "UDP" and "ICMP". Possible values are: Any, TCP, UDP, ICMP. | Optional | 
| source | The source IP address range from which incoming traffic will be allowed or denied by this rule. Possible values are "Any", an IP address range, an application security group, or a default tag. Default is "Any". | Optional | 
| priority | The priority by which the rules will be processed. The lower the number, the higher the priority. We recommend leaving gaps between rules - 100, 200, 300, etc. - so that it is easier to add new rules without having to edit existing rules. Default is "4096". | Optional | 
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional | 
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional | 
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional | 
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

`azure-nsg-security-rules-update`
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
| source_ports | The source ports from which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional | 
| destination | The specific destination IP address range for outgoing traffic that will be allowed or denied by this rule. The destination filter can be "Any", an IP address range, an application security group, or a default tag. | Optional | 
| destination_ports | The destination ports for which traffic will be allowed or denied by this rule. Provide a single port, such as 80; a port range, such as 1024-65535; or a comma-separated list of single ports and/or port ranges, such as 80,1024-65535. Use an asterisk (*) to allow traffic on any port. Default is "*". | Optional | 
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


#### Command Example
```!azure-nsg-security-rules-update security_group_name=alerts-nsg security_rule_name=Demisto_Rule action=Allow description=description```

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
            "id": "/subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/Demisto_Rule",
            "name": "Demisto_Rule",
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

>### Rules Demisto_Rule
>|access|description|destinationAddressPrefix|destinationPortRange|direction|etag|id|name|priority|protocol|provisioningState|sourceAddressPrefix|sourcePortRange|type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| Allow | description | 11.0.0.0/8 | 8080 | Outbound | W/"9fad6036-4c3a-4d60-aac9-18281dba3305" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/Demisto_Rule | Demisto_Rule | 100 | * | Succeeded | 10.0.0.0/8 | * | Microsoft.Network/networkSecurityGroups/securityRules |


### azure-nsg-security-rules-get
***
Get a specific rule.


#### Base Command

`azure-nsg-security-rules-get`
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
            "sourceAddressPrefix": "8.1.2.3",
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
>| Allow | 1.1.1.1 | * | Inbound | W/"fdba51cf-46b3-44af-8da5-16666aa578cc" | /subscriptions/123456789/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Network/networkSecurityGroups/alerts-nsg/securityRules/wow | wow | 3323 | * | Succeeded | 8.1.2.3 | 1,<br/>2,<br/>3 | Microsoft.Network/networkSecurityGroups/securityRules |


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
