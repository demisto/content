The Azure WAF (Web Application Firewall) integration provides centralized protection of your web applications from common exploits and vulnerabilities.
It enables you to control policies that are configured in the Azure Firewall management platform, and allows you to add, delete, or update policies,
and also to get details of a specific policy or a list of policies.
## Configure AzureWAF on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureWAF.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | app_id | App ID | True |
    | subscription_id | Subscription ID | True |
    | resource_group_name | Default Resource Group Name | True |
    | insecure | Trust any certificate \(not secure\) | False |
    | proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-waf-policies-get
***
Retrieves protection policies within a resource group.


#### Base Command

`azure-waf-policies-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of a policy. Used to retrieve a protection policy with a specified name within a resource group. If policy_name is not provided, will retrieve all policies. | Optional | 
| resource_group_name | The name of the resource group. If not provided, the instance's default resource group name will be used. | Optional | 
| verbose | Whether to retrieve full details of the policy. Possible values are: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of policies to fetch. Default is "10". Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureWAF.Policy.name | String | Resource name. | 
| AzureWAF.Policy.id | String | Resource ID. | 
| AzureWAF.Policy.type | String | Resource type. | 
| AzureWAF.Policy.etag | String | A unique read-only string that changes whenever the resource is updated. | 
| AzureWAF.Policy.tags | String | Resource tag. | 
| AzureWAF.Policy.location | String | Resource location. | 
| AzureWAF.Policy.properties.resourceState | String | Resource status of the policy. | 
| AzureWAF.Policy.properties.provisioningState | String | The provisioning state of the application gateway resource. | 
| AzureWAF.Policy.properties.policySettings.state | String | The state of the policy. | 
| AzureWAF.Policy.properties.policySettings.mode | String | The mode of the policy. | 
| AzureWAF.Policy.properties.policySettings.maxRequestBodySizeInKb | Number | Maximum request body size in Kb for WAF. | 
| AzureWAF.Policy.properties.policySettings.fileUploadLimitInMb | Number | Maximum file upload size in Mb for WAF. | 
| AzureWAF.Policy.properties.policySettings.requestBodyCheck | Boolean | Whether to allow WAF to check the request body. | 
| AzureWAF.Policy.properties.customRules.name | String | The name of the resource that is unique within a policy. This name can be used to access the resource. | 
| AzureWAF.Policy.properties.customRules.priority | Number | Priority of the rule. Rules with a lower value will be evaluated before rules with a higher value. | 
| AzureWAF.Policy.properties.customRules.ruleType | String | The rule type. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchVariables.variableName | String | Match variable. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchVariables.selector | String | The selector of the match variable. | 
| AzureWAF.Policy.properties.customRules.matchConditions.operator | String | The operator to be matched. | 
| AzureWAF.Policy.properties.customRules.matchConditions.negationCondition | Boolean | Whether this is a negate condition. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchValues | String | Match value. | 
| AzureWAF.Policy.properties.customRules.action | String | Type of actions. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleSetType | String | The rule set type to use. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleSetVersion | String | The version of the rule set to use. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.ruleGroupName | String | The managed rule group to override. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.rules.ruleId | String | Identifier for the managed rule. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.rules.state | String | The state of the managed rule. Defaults to disabled if not specified. | 
| AzureWAF.Policy.properties.managedRules.exclusions.matchVariable | String | The variable to be excluded. | 
| AzureWAF.Policy.properties.managedRules.exclusions.selectorMatchOperator | String | When matchVariable is a collection, operate on the selector to specify which elements in the collection this exclusion applies to. | 
| AzureWAF.Policy.properties.managedRules.exclusions.selector | String | When matchVariable is a collection, the operator used to specify which elements in the collection this exclusion applies to. | 


#### Command Example
```!azure-waf-policies-get limit=2```

#### Context Example
```json
{
    "AzureWAF": {
        "Policy": [
            {
                "etag": "W/\"4bf9c37a-81b7-4c14-a27c-67962c7af825\"",
                "id": "/subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example_policy",
                "location": "example_location",
                "name": "example_policy",
                "properties": {
                    "customRules": [],
                    "managedRules": {
                        "exclusions": [],
                        "managedRuleSets": [
                            {
                                "ruleGroupOverrides": [],
                                "ruleSetType": "OWASP",
                                "ruleSetVersion": "3.0"
                            }
                        ]
                    },
                    "policySettings": {
                        "fileUploadLimitInMb": 750,
                        "maxRequestBodySizeInKb": 128,
                        "mode": "Detection",
                        "requestBodyCheck": true,
                        "state": "Disabled"
                    },
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policy: example_policy
>|etag|id|location|name|type|
>|---|---|---|---|---|
>| W/"4bf9c37a" | /subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example_policy | westus | example_policy | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies |
>### Policy: test_policy
>|etag|id|location|name|type|
>|---|---|---|---|---|
>| W/"4e844e6c" | /subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/test_policy | westus | test_policy | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies |
>Showing 2 policies out of 7

### azure-waf-policies-list-all-in-subscription
***
Retrieves all the WAF policies in a subscription.


#### Base Command

`azure-waf-policies-list-all-in-subscription`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| verbose | Whether to retrieve the full details of the policy. Possible values are "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 
| limit | Maximum number of policies to be shown. (This will only affect visualized data, not context.). Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureWAF.Policy.name | String | Resource name. | 
| AzureWAF.Policy.id | String | Resource ID. | 
| AzureWAF.Policy.type | String | Resource type. | 
| AzureWAF.Policy.etag | String | A unique read-only string that changes whenever the resource is updated. | 
| AzureWAF.Policy.tags | String | Resource tags. | 
| AzureWAF.Policy.location | String | Resource location. | 
| AzureWAF.Policy.properties.resourceState | String | Resource status of the policy. | 
| AzureWAF.Policy.properties.provisioningState | String | The provisioning state of the application gateway resource. | 
| AzureWAF.Policy.properties.policySettings.state | String | The state of the policy. | 
| AzureWAF.Policy.properties.policySettings.mode | String | The mode of the policy. | 
| AzureWAF.Policy.properties.policySettings.maxRequestBodySizeInKb | Number | Maximum request body size in Kb for WAF. | 
| AzureWAF.Policy.properties.policySettings.fileUploadLimitInMb | Number | Maximum file upload size in Mb for WAF. | 
| AzureWAF.Policy.properties.policySettings.requestBodyCheck | Boolean | Whether to allow WAF to check the request body. | 
| AzureWAF.Policy.properties.customRules.name | String | The name of the resource that is unique within a policy. This name can be used to access the resource. | 
| AzureWAF.Policy.properties.customRules.priority | Number | Priority of the rule. Rules with a lower value will be evaluated before rules with a higher value. | 
| AzureWAF.Policy.properties.customRules.ruleType | String | The rule type. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchVariables.variableName | String | Match variable. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchVariables.selector | String | The selector of the match variable. | 
| AzureWAF.Policy.properties.customRules.matchConditions.operator | String | The operator to be matched. | 
| AzureWAF.Policy.properties.customRules.matchConditions.negationConditon | Boolean | Whether this is a negate condition. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchValues | String | Match value. | 
| AzureWAF.Policy.properties.customRules.action | String | Type of actions. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleSetType | String | The rule set type to use. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleSetVersion | String | The version of the rule set to use. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.ruleGroupName | String | The managed rule group to override. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.rules.ruleId | String | Identifier for the managed rule. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.rules.state | String | The state of the managed rule. Defaults to disabled if not specified. | 
| AzureWAF.Policy.properties.managedRules.exclusions.matchVariable | String | The variable to be excluded. | 
| AzureWAF.Policy.properties.managedRules.exclusions.selectorMatchOperator | String | When matchVariable is a collection, operate on the selector to specify which elements in the collection this exclusion applies to. | 
| AzureWAF.Policy.properties.managedRules.exclusions.selector | String | When matchVariable is a collection, the operator used to specify which elements in the collection this exclusion applies to. | 


#### Command Example
```!azure-waf-policies-list-all-in-subscription limit=2```

#### Context Example
```json
{
    "AzureWAF": {
        "Policy": [
            {
                "etag": "W/\"4bf9c37a-81b7-4c14-a27c-67962c7af825\"",
                "id": "/subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example_policy",
                "location": "westus",
                "name": "example_policy",
                "properties": {
                    "customRules": [],
                    "managedRules": {
                        "exclusions": [],
                        "managedRuleSets": [
                            {
                                "ruleGroupOverrides": [],
                                "ruleSetType": "OWASP",
                                "ruleSetVersion": "3.0"
                            }
                        ]
                    },
                    "policySettings": {
                        "fileUploadLimitInMb": 750,
                        "maxRequestBodySizeInKb": 128,
                        "mode": "Detection",
                        "requestBodyCheck": true,
                        "state": "Disabled"
                    },
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
            }
        ]
    }
}
```

#### Human Readable Output

>### Policy: example_policy
>|etag|id|location|name|type|
>|---|---|---|---|---|
>| W/"4bf9c37a" | /subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example_policy | westus | example_policy | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies |
>### Policy: test_policy_1608641948_
>|etag|id|location|name|type|
>|---|---|---|---|---|
>| W/"422867fc-a697-4978-83f5-20a57ab51511" | /subscriptions/0f907ea4-bc8b-4c11-9d7e-805c2fd144fb/resourceGroups/demisto-sentinel2/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/test_policy_1608641948_ | westus | test_policy_1608641948_ | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies |
>Showing 2 policies out of 6

### azure-waf-policy-update-or-create
***
Creates or updates a policy with a specified rule set name within a resource group.


#### Base Command

`azure-waf-policy-update-or-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of a policy. Used to retrieve a protection policy with a specified name within a resource group. If policy_name is not provided, will retrieve all policies. | Required | 
| resource_group_name | The name of the resource group. If not provided, the instance's default resource group name will be used. | Optional | 
| managed_rules | Describes the managedRules structure. | Required | 
| resource_id | Resource ID. | Optional | 
| location | Describes the resource location. | Optional | 
| custom_rules | The custom rules inside the policy. | Optional | 
| policy_settings | The policy setting for the policy. | Optional | 
| verbose | Whether to retrieve the full details of the policy. Possible values are: "true" and "false". Default is "false". Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureWAF.Policy.name | String | Resource name. | 
| AzureWAF.Policy.id | String | Resource ID. | 
| AzureWAF.Policy.type | String | Resource type. | 
| AzureWAF.Policy.etag | String | A unique read-only string that changes whenever the resource is updated. | 
| AzureWAF.Policy.tags | String | Resource type. | 
| AzureWAF.Policy.location | String | Resource location. | 
| AzureWAF.Policy.properties.resourceState | String | Resource status of the policy. | 
| AzureWAF.Policy.properties.provisioningState | String | The provisioning state of the application gateway resource. | 
| AzureWAF.Policy.properties.policySettings.state | String | The state of the policy. | 
| AzureWAF.Policy.properties.policySettings.mode | String | The mode of the policy. | 
| AzureWAF.Policy.properties.policySettings.maxRequestBodySizeInKb | Number | Maximum request body size in Kb for WAF. | 
| AzureWAF.Policy.properties.policySettings.fileUploadLimitInMb | Number | Maximum file upload size in Mb for WAF. | 
| AzureWAF.Policy.properties.policySettings.requestBodyCheck | Boolean | Whether to allow WAF to check the request body. | 
| AzureWAF.Policy.properties.customRules.name | String | The name of the resource that is unique within a policy. This name can be used to access the resource. | 
| AzureWAF.Policy.properties.customRules.priority | Number | Priority of the rule. Rules with a lower value will be evaluated before rules with a higher value. | 
| AzureWAF.Policy.properties.customRules.ruleType | String | The rule type. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchVariables.variableName | String | Match variable. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchVariables.selector | String | The selector of the match variable. | 
| AzureWAF.Policy.properties.customRules.matchConditions.operator | String | The operator to be matched. | 
| AzureWAF.Policy.properties.customRules.matchConditions.negationConditon | Boolean | Whether this is a negate condition. | 
| AzureWAF.Policy.properties.customRules.matchConditions.matchValues | String | Match value. | 
| AzureWAF.Policy.properties.customRules.action | String | Type of actions. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleSetType | String | Defines the rule set type to use. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleSetVersion | String | Defines the version of the rule set to use. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.ruleGroupName | String | The managed rule group to override. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.rules.ruleId | String | Identifier for the managed rule. | 
| AzureWAF.Policy.properties.managedRules.managedRuleSets.ruleGroupOverrides.rules.state | String | The state of the managed rule. Defaults to disabled if not specified. | 
| AzureWAF.Policy.properties.managedRules.exclusions.matchVariable | String | The variable to be excluded. | 
| AzureWAF.Policy.properties.managedRules.exclusions.selectorMatchOperator | String | When matchVariable is a collection, operate on the selector to specify which elements in the collection this exclusion applies to. | 
| AzureWAF.Policy.properties.managedRules.exclusions.selector | String | When matchVariable is a collection, the operator used to specify which elements in the collection this exclusion applies to. | 


#### Command Example
```!azure-waf-policy-update-or-create policy_name="example_policy" resource_group_name="demisto-sentinel2" location="WestUs" managed_rules="{ \"managedRuleSets\": [{\"ruleSetType\": \"OWASP\",\"ruleSetVersion\": \"3.0\"}]}"```

#### Context Example
```json
{
    "AzureWAF": {
        "Policy": {
            "etag": "W/\"f1121c83-d9c1-47a4-912b-6f6731c991a4\"",
            "id": "/subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example_policy",
            "location": "westus",
            "name": "example_policy",
            "properties": {
                "customRules": [],
                "managedRules": {
                    "exclusions": [],
                    "managedRuleSets": [
                        {
                            "ruleGroupOverrides": [],
                            "ruleSetType": "OWASP",
                            "ruleSetVersion": "3.0"
                        }
                    ]
                },
                "policySettings": {
                    "fileUploadLimitInMb": 100,
                    "maxRequestBodySizeInKb": 128,
                    "mode": "Detection",
                    "requestBodyCheck": true,
                    "state": "Disabled"
                },
                "provisioningState": "Updating"
            },
            "type": "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
        }
    }
}
```

#### Human Readable Output

>### Policy: example_policy
>|etag|id|location|name|type|
>|---|---|---|---|---|
>| W/"f1121c83" | /subscriptions/example_subscription/resourceGroups/example_resource_group/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/example_policy | westus | example_policy | Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies |
>Showing 1 policies out of 1

### azure-waf-policy-delete
***
Deletes a policy.


#### Base Command

`azure-waf-policy-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_name | The name of a policy. Used to retrieve a protection policy with a specified name within a resource group. If policy_name is not provided, will retrieve all policies. | Required | 
| resource_group_name | The name of the resource group. If not provided, the instance's default resource group name will be used. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-waf-policy-delete policy_name="example_policy"```

#### Human Readable Output

>Policy example_policy was deleted successfully.

### azure-waf-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.


#### Base Command

`azure-waf-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-waf-auth-start```


#### Human Readable Output

>### Authorization instructions
>        1. To sign in, use a web browser to open the page:
>            [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
>           and enter the code **CKVE788YV** to authenticate.
>        2. Run the **!azure-waf-auth-complete** command in the War Room.

### azure-waf-auth-complete
***
Run this command to complete the authorization process.
Should be used after running the azure_waf-auth-start command.


#### Base Command

`azure-waf-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-waf-auth-complete```


#### Human Readable Output

>✅ Authorization completed successfully.

### azure-waf-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-waf-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-waf-auth-reset```


#### Human Readable Output

>Authorization was reset successfully. You can now run **!azure-waf-auth-start** and **!azure-waf-auth-complete**.

### azure-waf-auth-test
***
Tests connectivity to the Azure Web Application Firewall.


#### Base Command

`azure-waf-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-waf-auth-test```


#### Human Readable Output

>✅ Great Success!
