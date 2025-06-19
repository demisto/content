Unified security management and advanced threat protection across hybrid cloud workloads.
For more information see [Azure Security Center documentation](https://docs.microsoft.com/en-us/rest/api/securitycenter/)

## Use Case

With Security Center, you can apply security policies across your workloads, limit your exposure to threats, and detect and respond to attacks.

## Authentication

For more details about the authentication used in this integration, see [Microsoft Integrations - Authentication](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication) .

* After authorizing the Demisto app, you will get an ID, Token, and Key, which should be inserted in the integration instance configuration's corresponding fields. After giving consent, the application has to have a role assigned so it can access the relevant resources per subscription.
* In order to assign a role to the application after consent was given:
  * Go to the Azure Portal UI.
  * Go to Subscriptions, and then Access Control (IAM).
  * Click Add.
  * Select a role that includes the following permissions:
    * Microsoft.Security/locations/read
    * Microsoft.Security/alerts/read
    * Microsoft.Security/locations/alerts/read
    * Microsoft.Storage/storageAccounts/read
    * Microsoft.Management/managementGroups/read
    * Microsoft.Security/advancedThreatProtectionSettings/*
    * Microsoft.Security/informationProtectionPolicies/read
    * Microsoft.Security/locations/jitNetworkAccessPolicies/*
    * Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action
  * Select the Azure Security Center application.

## Configure Azure Security Center v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations**   > **Servers & Services**.
2. Search for Azure Security Center v2.
3. Click **Add instance** to create and configure a new integration instance.
    * **Name**: a textual name for the integration instance.
    * **Microsoft Azure Management URL**
    * **ID (received from the admin consent - see Detailed Instructions (?)**
    * **Token (received from the admin consent - see Detailed Instructions (?) section)**
    * **Key (received from the admin consent - see Detailed Instructions (?)**
    * **Trust any certificate (not secure)**
    * **Use system proxy settings**
    * **Default subscription ID to use**
4. Click **Test** to validate the new instance.

## Commands

#### Subscription ID

Some commands require a subscription ID parameter in order to run.
You can find your organization's subscriptions list in the ***Microsoft Azure Portal > Subscriptions*** or by running the ***azure-list-subscriptions*** command.

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. azure-sc-list-alert
2. azure-sc-update-atp
3. azure-sc-get-atp
4. azure-sc-update-aps
5. azure-sc-get-aps
6. azure-sc-list-aps
7. azure-sc-list-jit
8. azure-sc-list-storage
9. azure-list-subscriptions
10. azure-sc-list-location
11. azure-sc-get-alert
12. azure-get-secure-score

### azure-sc-list-alert

***
Lists alerts for the subscription according to the specified filters.

#### Base Command

`azure-sc-list-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the ascLocation. This command requires the resourceGroupName argument. | Optional | 
| filter | OData filter. | Optional | 
| select | OData select. | Optional | 
| expand | OData expand. | Optional | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Alert.DisplayName | string | The display name of the alert. | 
| AzureSecurityCenter.Alert.CompromisedEntity | string | The entity on which the incident occurred. | 
| AzureSecurityCenter.Alert.Description | string | Description of the suspicious activity that was detected. | 
| AzureSecurityCenter.Alert.DetectedTime | date | The time the vendor detected the incident. | 
| AzureSecurityCenter.Alert.ReportedSeverity | string | The estimated severity of this alert. | 
| AzureSecurityCenter.Alert.State | string | The alert state \(Active, Dismissed, etc.\). | 
| AzureSecurityCenter.Alert.ID | string | The alert ID. | 

### azure-sc-get-alert

***
Gets an alert that is associated with a resource group or a subscription. The subscription_id argument is required in case it was not defined in the integration's configuration.

#### Base Command

`azure-sc-get-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the ascLocation. This command requires the resourceGroupName argument. | Required | 
| alert_id | The alert ID. | Optional | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Alert.DisplayName | string | The display name of the alert. | 
| AzureSecurityCenter.Alert.CompromisedEntity | string | The entity on which the incident occurred. | 
| AzureSecurityCenter.Alert.DetectedTime | date | The time the vendor detected the incident. | 
| AzureSecurityCenter.Alert.ReportedSeverity | string | The estimated severity of the alert. | 
| AzureSecurityCenter.Alert.State | string | The alert state \(Active, Dismissed, etc.\). | 
| AzureSecurityCenter.Alert.RemediationSteps | string | Recommended steps to remediate the incident. | 
| AzureSecurityCenter.Alert.VendorName | string | Name of the vendor that discovered the incident. | 
| AzureSecurityCenter.Alert.AlertName | string | Name of the alert type. | 
| AzureSecurityCenter.Alert.ID | string | The alert ID. | 
| AzureSecurityCenter.Alert.Description | string | Description of the incident and what it means. | 
| AzureSecurityCenter.Alert.ExtendedProperties | string | Changing set of properties depending on the alert type. | 
| AzureSecurityCenter.Alert.Entities | string | Objects that are related to the alert. | 

### azure-sc-update-alert

***
Update an alert's state.

#### Base Command

`azure-sc-update-alert`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the ascLocation. This command requires the resourceGroupName argument. | Required | 
| alert_id | The alert ID. | Required | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 
| alert_update_action_type | The update action type. Possible values are: activate, dismiss, in_progress, resolve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Alert.ID | string | The alert ID. | 

### azure-sc-update-atp

***
Updates Advanced Threat Detection settings.

#### Base Command

`azure-sc-update-atp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | Resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| setting_name | Name of the Advanced Threat Detection setting. Default is current. | Optional | 
| storage_account | The storage name in your Azure account. | Required | 
| is_enabled | Indicates whether Advanced Threat Protection is enabled. | Required | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AdvancedThreatProtection.ID | string | The resource ID. | 
| AzureSecurityCenter.AdvancedThreatProtection.Name | string | The name of the resource. | 
| AzureSecurityCenter.AdvancedThreatProtection.IsEnabled | string | Indicates whether the Advanced Threat Protection is enabled. | 

### azure-sc-get-atp

***
Returns the Advanced Threat Protection setting.

#### Base Command

`azure-sc-get-atp`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | Name of the resource group. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| setting_name | Name of the Advanced Threat Detection setting. The default setting's name is 'current'. Default is current. | Optional | 
| storage_account | Name of a storage in your azure account. | Required | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AdvancedThreatProtection.ID | string | The resource ID. | 
| AzureSecurityCenter.AdvancedThreatProtection.Name | string | The name of the resource. | 
| AzureSecurityCenter.AdvancedThreatProtection.IsEnabled | string | Indicates whether the Advanced Threat Protection is enabled. | 

### azure-sc-update-aps

***
Updates a specific auto provisioning setting.

#### Base Command

`azure-sc-update-aps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setting_name | Name of the auto provisioning setting. The default setting's name is 'default'. Default is default. | Required | 
| auto_provision | Describes the type of security agent provisioning action to take (On or Off). | Required | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AutoProvisioningSetting.Name | string | The setting display name. | 
| AzureSecurityCenter.AutoProvisioningSetting.AutoProvision | string | Displays the type of security agent provisioning action to take \(On or Off\). | 
| AzureSecurityCenter.AutoProvisioningSetting.ID | string | The setting resource ID. | 

### azure-sc-get-aps

***
Returns details of a specific auto provisioning setting.

#### Base Command

`azure-sc-get-aps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setting_name | Name of the auto provisioning setting. Default is default. | Required | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AutoProvisioningSetting.Name | string | The setting display name. | 
| AzureSecurityCenter.AutoProvisioningSetting.AutoProvision | string | Displays the type of security agent provisioning action to take \(On or Off\). | 
| AzureSecurityCenter.AutoProvisioningSetting.ID | string | The setting resource ID. | 

### azure-sc-list-aps

***
Lists auto provisioning settings in the subscription.

#### Base Command

`azure-sc-list-aps`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AutoProvisioningSetting.Name | string | The setting display name. | 
| AzureSecurityCenter.AutoProvisioningSetting.AutoProvision | string | Displays the type of security agent provisioning action to take \(On or Off\). | 
| AzureSecurityCenter.AutoProvisioningSetting.ID | string | The setting resource ID. | 

### azure-sc-list-jit

***
Lists all policies for protecting resources using Just-in-Time access control.

#### Base Command

`azure-sc-list-jit`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the asc_location. | Optional | 
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.JITPolicy.Name | string | The display name of the policy. | 
| AzureSecurityCenter.JITPolicy.Rules | string | A CSV list of access rules for Microsoft.Compute/virtualMachines resource, in the format \(VMName: allowPort1,...\) | 
| AzureSecurityCenter.JITPolicy.Location | string | The location where the resource is stored. | 
| AzureSecurityCenter.JITPolicy.Kind | string | The resource type of the policy. | 

### azure-sc-list-storage

***
Lists all the storage accounts available under the subscription.

#### Base Command

`azure-sc-list-storage`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Storage.Name | string | Name of the storage account. | 
| AzureSecurityCenter.Storage.ResourceGroupName | string | Name of the attached resource group. | 
| AzureSecurityCenter.Storage.Location | string | The geo-location where the resource resides. | 

### azure-list-subscriptions

***
Lists available subscriptions for this application.

#### Base Command

`azure-list-subscriptions`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Subscription.ID | String | The ID of the subscription. | 
| Azure.Subscription.Name | String | The name of the subscription. | 
| Azure.Subscription.Enabled | String | The state of the subscription. | 

### azure-sc-list-location

***
The location of the responsible ASC of the specific subscription. For each subscription there is only one responsible location.

#### Base Command

`azure-sc-list-location`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 

#### Context Output

There is no context output for this command.
### azure-get-secure-score

***
Retrieve the Secure Score for the provided subscription and score name.

#### Base Command

`azure-get-secure-score`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secure_score_name | description. Possible values are: . Default is ascScore. | Optional | 
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. Possible values are: . | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Securescore.displayName | String | The initiative’s name. | 
| Azure.Securescore.score.max | String | The max score of the Securescore. | 
| Azure.Securescore.score.current | String | The current score of the Securescore. | 
| Azure.Securescore.score.percentage | String | The Ratio of the current score divided by the maximum. | 
| Azure.Securescore.weight | String | The relative weight for each subscription. | 

### azure-sc-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-sc-auth-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### azure-resource-group-list

***
List all resource groups for a subscription.

#### Base Command

`azure-resource-group-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | The subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscription ID is used. | Optional | 
| limit | Limit on the number of resource groups to return. Default is 50. | Optional | 
| tag | A single tag in the form of '{"Tag Name":"Tag Value"}' to filter the list by. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.ResourceGroupName.name | String | Resource group name. | 
| Azure.ResourceGroupName.location | String | Resource group location. | 
| Azure.ResourceGroupName.tags | Unknown | Resource group tags. | 
| Azure.ResourceGroupName.properties.provisioningState | unknown | Resource group provisioning state. | 
