The Azure WAF (Web Application Firewall) integration provides centralized protection of your web applications from common exploits and vulnerabilities.
It enables you to control policies that are configured in the Azure Firewall management platform, and allows you to add, delete, or update policies,
and also to get details of a specific policy or a list of policies.

In order to connect to the AzureWAF using either Cortex XSOAR Azure App or the Self-Deployed Azure App, use one of the following methods:

- *Authorization Code Flow* (Recommended).
- *Device Code Flow*.
- *Azure Managed Identities*
- *Client Credentials Flow*.

# Self-Deployed Application
To use a self-configured Azure application, you need to add a [new Azure App Registration in the Azure Portal](https://docs.microsoft.com/en-us/graph/auth-register-app-v2#register-a-new-application-using-the-azure-portal).

## Required Permissions:
1. user_impersonation
2. offline_access
3. user.read 

## Authentication Using the  User-Authentication Flow (recommended)

Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. choose the 'User Auth' option in the ***Authentication Type*** parameter.
3. Enter your Client/Application ID in the ***Application ID*** parameter. 
4. Enter your Client Secret in the ***Client Secret*** parameter.
5. Enter your Tenant ID in the ***Tenant ID*** parameter.
6. Enter your Application redirect URI in the ***Application redirect URI*** parameter.
7. Save the instance.
8. Run the `!azure-waf-generate-login-url` command in the War Room and follow the instruction.
9. Run the ***!azure-waf-auth-test*** command - a 'Success' message should be printed to the War Room.


### Authentication Using the Device Code Flow
Use the [device code flow](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#device-code-flow)
to link Azure SQL Management with Cortex XSOAR.

In order to connect to Azure Web Application Firewall using either the Cortex XSOAR Azure or Self Deployed Azure application:
1. Fill in the required parameters
2. choose the 'Device' option in the ***user_auth_flow*** parameter.
4. Run the ***!azure-waf-auth-start*** command.
4. Follow the instructions that appear.
5. Run the ***!azure-waf-auth-complete*** command.
At end of the process, you will see a message that you logged in successfully.

#### Cortex XSOAR Azure app
In order to use the Cortex XSOAR Azure application, use the default application ID (cf22fd73-29f1-4245-8e16-533704926d20) and fill in your subscription ID and default resource group name. 

You only need to fill in your subscription ID and resource group name. You can find your resource group and 
subscription ID in the Azure Portal. For a more detailed explanation, visit [this page](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

## Client Credentials Flow Authentication

Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)
*Note:* In the *Select members* section, assign the application you created earlier.
To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:
   1. In the **Authentication Type** field, select the **Client Credentials** option.
   2. In the **Application ID** field, enter your Client/Application ID.
   3. In the **Tenant ID** field, enter your Tenant ID .
   4. In the **Client Secret** field, enter your Client Secret.
   5. Click **Test** to validate the URLs, token, and connection
   6. Save the instance.

### Testing authentication and connectivity
If you are using Device Code Flow or Authorization Code Flow, for testing your authentication and connectivity to the AzureWAF service run the ***!azure-waf-auth-test*** command. 

## Configure AzureWAF on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Web Application Firewall.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | App ID |  | False |
    | Default Subscription ID |  | True |
    | Default Resource Group Name |  | True |
    | Authentication Type | Type of authentication - can be Authorization Code Flow \(recommended\), Device Code Flow, or Azure Managed Identities. | True |
    | Tenant ID (for authorization code mode) |  | False |
    | Client Secret (for authorization code mode) |  | False |
    | Client Secret (for authorization code mode) |  | False |
    | Application redirect URI (for authorization code mode) |  | False |
    | Authorization code | for user-auth mode - received from the authorization step. see Detailed Instructions \(?\) section | False |
    | Authorization code |  | False |
    | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
    | Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

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
| resource_group_names | Comma-separated value list of the names of the resource groups. If not provided, the instance's default resource group name will be used. | Optional | 
| subscription_id | The subscription ID. If not provided, the integration default subscription ID will be used. | Optional | 
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
| subscription_id | Comma-separated list of subscription IDs. Will override the default subscription ID. | Optional | 



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
| resource_group_names | Comma-separated list of the names of the resource groups. If not provided, the instance's default resource group name will be used. | Optional | 
| subscription_id | The subscription ID. If not provided, the integration default subscription ID will be used. | Optional | 
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
| subscription_id | The subscription ID. If not provided, the integration default subscription ID will be used. | Optional | 


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

### azure-waf-generate-login-url
***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-waf-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```azure-waf-generate-login-url```

#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.

### azure-waf-subscriptions-list

***
Gets all subscriptions for a tenant.

#### Base Command

`azure-waf-subscriptions-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureWAF.Subscription.authorizationSource | String | Subscription authorization source. | 
| AzureWAF.Subscription.displayName | String | Subscription display name. | 
| AzureWAF.Subscription.id | String | Subscription ID with subscriptions prefix. | 
| AzureWAF.Subscription.subscriptionId | String | Subscription ID. | 
| AzureWAF.Subscription.locationPlacementId | String | Placmement ID of subscription. | 
| AzureWAF.Subscription.tenantId | String | The tenatnt ID of the subscription. | 

### azure-waf-resource-group-list

***
Gets all the resource groups for a subscription.

#### Base Command

`azure-waf-resource-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID. If not provided, the integration default subscription ID will be used. | Optional | 
| tag | You can filter by tag names and values. For example, to filter for a tag name and value, tagName=tagValue'. | Optional | 
| limit | Maximum number of resource groups to fetch. Default is "50". Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureWAF.ResourceGroup.id | String | Resource group ID. | 
| AzureWAF.ResourceGroup.location | String | Resource group location. | 
| AzureWAF.ResourceGroup.name | String | Resource group name. | 
| AzureWAF.ResourceGroup.type | String | Resource group type. | 
| AzureWAF.ResourceGroup.properties | String | Resource group properties. | 
| AzureWAF.ResourceGroup.tags | String | Resource group tags. | 
