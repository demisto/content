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
      - Microsoft.Security/locations/read
      - Microsoft.Security/alerts/read
      - Microsoft.Security/locations/alerts/read
      - Microsoft.Storage/storageAccounts/read
      - Microsoft.Management/managementGroups/read
      - Microsoft.Security/advancedThreatProtectionSettings/*
      - Microsoft.Security/informationProtectionPolicies/read
      - Microsoft.Security/locations/jitNetworkAccessPolicies/*
      - Microsoft.Security/locations/jitNetworkAccessPolicies/initiate/action
    * Select the Azure Security Center application.

## Configure Azure Security Center v2 on Demisto

1. Navigate to **Settings** > **Integrations**   > **Servers & Services**.
2. Search for Azure Security Center v2.
3. Click **Add instance** to create and configure a new integration instance.
    - **Name**: a textual name for the integration instance.
    - **Microsoft Azure Management URL**
    - **ID (received from the admin consent - see Detailed Instructions (?)**
    - **Token (received from the admin consent - see Detailed Instructions (?) section)**
    - **Key (received from the admin consent - see Detailed Instructions (?)**
    - **Trust any certificate (not secure)**
    - **Use system proxy settings**
    - **Default subscription ID to use**
4. Click **Test** to validate the new instance.


## Commands
#### Subscription ID
Some commands require a subscription ID parameter in order to run.
You can find your organization's subscriptions list in the ***Microsoft Azure Portal > Subscriptions*** or by running the ***azure-list-subscriptions*** command.

You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
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

### 1. azure-sc-list-alert

***

Lists alerts for the subscription according to the specified filters.

*Require Subscription ID*
##### Base Command

`azure-sc-list-alert`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. | Optional |
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the ascLocation. This command requires the resourceGroupName argument. | Optional |
| filter | OData filter | Optional |
| select | OData select | Optional |
| expand | OData expand | Optional |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Alert.AlertDisplayName | string | Alert display name |
| AzureSecurityCenter.Alert.CompromisedEntity | string | The entity on which the incident occurred |
| AzureSecurityCenter.Alert.DetectedTimeUtc | date | Time the vendor detected the incident |
| AzureSecurityCenter.Alert.ReportedSeverity | string | Estimated severity of this alert |
| AzureSecurityCenter.Alert.State | string | Alert state (Active, Dismissed, etc.) |
| AzureSecurityCenter.Alert.ID | string | Alert ID |

##### Command Example

`!azure-sc-list-alert`

##### Context Example

```
{
    "AzureSecurityCenter.Alert": [
        {
            "ActionTaken": "Undefined",
            "CompromisedEntity": "alerts",
            "Description": "Azure security center has detected incoming traffic from IP addresses, which have been identified as IP addresses that should be blocked by the Adaptive Network Hardening control",
            "DetectedTime": "2019-10-27T00:00:00Z",
            "DisplayName": "Traffic from unrecommended IP addresses was detected",
            "ID": "2518301663999999999_d1521d81-f4c1-40ae-b224-01456637790c",
            "ReportedSeverity": "Information",
            "State": "Active"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - List Alerts

| **DisplayName** | **CompromisedEntity** | **DetectedTime** | **ReportedSeverity** | **State** | **ActionTaken** | **Description** | **ID** |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Traffic from unrecommended IP addresses was detected | alerts | 2019-10-27T00:00:00Z | Information | Active | Undefined | Azure security center has detected incoming traffic from IP addresses, which have been identified as IP addresses that should be blocked by the Adaptive Network Hardening control | 2518301663999999999_d1521d81-f4c1-40ae-b224-01456637790c |

### 2. azure-sc-update-atp

***

Updates Advanced Threat Detection settings.

*Require Subscription ID*
##### Base Command

`azure-sc-update-atp`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | Resource group name | Required |
| setting_name | Name of the Advanced Threat Detection setting, default is 'current'. | Optional |
| storage_account | Storage name in your Azure account | Required |
| is_enabled | Indicates whether Advanced Threat Protection is enabled. | Required |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AdvancedThreatProtection.ID | string | Resource ID |
| AzureSecurityCenter.AdvancedThreatProtection.Name | string | Resource Name |
| AzureSecurityCenter.AdvancedThreatProtection.IsEnabled | string | Indicates whether Advanced Threat Protection is enabled |

##### Command Example

`!azure-sc-update-atp resource_group_name=recouce_name`

### 3. azure-sc-get-atp

***

Returns the Advanced Threat Protection setting.

*Require Subscription ID*
##### Base Command

`azure-sc-get-atp`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | Name of the resource group. | Required |
| setting_name | Name of Advanced Threat Detection setting, default setting's name is 'current'. | Optional |
| storage_account | Name of a storage in your azure account. | Required |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AdvancedThreatProtection.ID | string | Resource ID |
| AzureSecurityCenter.AdvancedThreatProtection.Name | string | Resource name |
| AzureSecurityCenter.AdvancedThreatProtection.IsEnabled | string | Indicates whether Advanced Threat Protection is enabled |

##### Command Example

`!azure-sc-get-atp resource_group_name=resource_group storage_account=st_acc1`

### 4. azure-sc-update-aps

***

Updates a specific auto provisioning setting.

*Require Subscription ID*
##### Base Command

`azure-sc-update-aps`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setting_name | Name of the auto provisioning setting, default setting's name is 'default' | Required |
| auto_provision | Describes the type of security agent provisioning action to take (On or Off) | Required |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AutoProvisioningSetting.Name | string | Setting display name |
| AzureSecurityCenter.AutoProvisioningSetting.AutoProvision | string | Display the type of security agent provisioning action to take (On or Off) |
| AzureSecurityCenter.AutoProvisioningSetting.ID | string | Setting resource ID |

##### Command Example

`!azure-sc-update-aps setting_name=default auto_provision=Off`

##### Context Example

```
{
    "AzureSecurityCenter.AutoProvisioningSetting": [
        {
            "AutoProvision": null,
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default",
            "Name": "default"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - Update Auto Provisioning Setting

| **Name** | **ID** |
| --- | --- |
| default | /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default |

### 5. azure-sc-get-aps

***

Returns details of a specific auto provisioning setting.

*Require Subscription ID*
##### Base Command

`azure-sc-get-aps`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| setting_name | Name of the auto provisioning setting | Required |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AutoProvisioningSetting.Name | string | Setting display name |
| AzureSecurityCenter.AutoProvisioningSetting.AutoProvision | string | Display the type of security agent provisioning action to take (On or Off) |
| AzureSecurityCenter.AutoProvisioningSetting.ID | string | Set resource ID |

##### Command Example

`!azure-sc-get-aps setting_name=default`

##### Context Example

```
{
    "AzureSecurityCenter.AutoProvisioningSetting": [
        {
            "AutoProvision": "Off",
            "ID": "/subscriptions/0xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default",
            "Name": "default"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - Get Auto Provisioning Setting

| **Name** | **AutoProvision** | **ID** |
| --- | --- | --- |
| default | Off | /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default |

### 6. azure-sc-list-aps

***

Lists auto provisioning settings in the subscription.

*Require Subscription ID*
##### Base Command

`azure-sc-list-aps`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.AutoProvisioningSetting.Name | string | Setting display name |
| AzureSecurityCenter.AutoProvisioningSetting.AutoProvision | string | Display the type of security agent provisioning action to take (On or Off) |
| AzureSecurityCenter.AutoProvisioningSetting.ID | string | Setting resource ID |

##### Command Example

`!azure-sc-list-aps`

##### Context Example

```
{
    "AzureSecurityCenter.AutoProvisioningSetting": [
        {
            "AutoProvision": "Off",
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default",
            "Name": "default"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - List Auto Provisioning Settings

| **Name** | **AutoProvision** | **ID** |
| --- | --- | --- |
| default | Off | /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/autoProvisioningSettings/default |

### 7. azure-sc-list-jit

***

Lists all policies for protecting resources using Just-in-Time access control.

*Require Subscription ID*
##### Base Command

`azure-sc-list-jit`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the asc_location. | Optional |
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. | Optional |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.JITPolicy.Name | string | Poliyc display name |
| AzureSecurityCenter.JITPolicy.Rules | string | CSV list of access rules for Microsoft.Compute/virtualMachines resource, in the format (VMName: allowPort1,...) |
| AzureSecurityCenter.JITPolicy.Location | string | Location where the resource is stored |
| AzureSecurityCenter.JITPolicy.Kind | string | Policy resource type |

##### Command Example

`!azure-sc-list-jit `

### 8. azure-sc-list-storage

***

Lists all the storage accounts available under the subscription.

*Require Subscription ID*
##### Base Command

`azure-sc-list-storage`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subscription_id | Subscription ID to use. Can be retrieved from the azure-sc-list-subscriptions command. If not specified, the default subscripton ID will be used. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Storage.Name | string | Name of the storage account |
| AzureSecurityCenter.Storage.ResourceGroupName | string | Names of the attached resource group |
| AzureSecurityCenter.Storage.Location | string | The geo-location where the resource resides |

##### Command Example

`!azure-sc-list-storage`

##### Context Example

```
{
    "AzureSecurityCenter.Storage": [
        {
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/resourceGroups/cloud-shell-storage-eastus/providers/Microsoft.Storage/storageAccounts/cs20f907ea4bc8bx4c11x9d7",
            "Location": "eastus",
            "Name": "cs20f907ea4bc8bx4c11x9d7",
            "ResourceGroupName": "cloud-shell-storage-eastus"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - List Storage Accounts

| **Name** | **ResourceGroupName** | **Location** |
| --- | --- | --- |
| cs20f907ea4bc8bx4c11x9d7 | cloud-shell-storage-eastus | eastus |
| useastrgdiag204 | us-east-rg | eastus |
| demistodevops | cloud-shell-storage-eastus | westeurope |

### 9. azure-list-subscriptions

***

List available subscriptions for this application.

##### Base Command

`azure-list-subscriptions`

##### Input

There are no input arguments for this command.

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Azure.Subscription.ID | String | Subscription ID |
| Azure.Subscription.Name | String | Subscription Name |
| Azure.Subscription.Enabled | String | Subscription state |

##### Command Example

`!azure-list-subscriptions`

##### Context Example

```
{
    "Azure.Subscription": [
        {
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx",
            "Name": "Pay-As-You-Go",
            "State": "Enabled"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - Subscriptions

| **ID** | **Name** | **State** |
| --- | --- | --- |
| /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx | Pay-As-You-Go | Enabled |

### List of Subscriptions

| **ID** | **Name** | **State** |
| --- | --- | --- |
| /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx | Pay-As-You-Go | Enabled |

### 10. azure-sc-list-location

***

The location of the responsible ASC of the specific subscription. For each subscription there is only one responsible location.

*Require Subscription ID*
##### Base Command

`azure-sc-list-location`

##### Input

There are no input arguments for this command.

##### Context Output

There are no context output for this command.

##### Command Example

`!azure-sc-list-location`

##### Context Example

```
{
    "AzureSecurityCenter.Location": [
        {
            "HomeRegionName": "centralus",
            "ID": "/subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/locations/centralus",
            "Name": "centralus"
        }
    ]
}
```

##### Human Readable Output

### Azure Security Center - List Locations

| **HomeRegionName** | **Name** | **ID** |
| --- | --- | --- |
| centralus | centralus | /subscriptions/xxxx-xxxx-xxxx-xxxx-xxxx/providers/Microsoft.Security/locations/centralus |

### 11. azure-sc-get-alert

***

Get an alert that is associated a resource group or a subscription.

*Require Subscription ID*
##### Base Command

`azure-sc-get-alert`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_group_name | The name of the resource group within the user's subscription. The name is case insensitive. | Optional |
| asc_location | The location where Azure Security Center stores the data of the subscription. Run the 'azure-sc-list-location' command to get the ascLocation. This command requires the resourceGroupName argument. | Required |
| alert_id | The alert ID. | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureSecurityCenter.Alert.DisplayName | string | The display name of the alert. |
| AzureSecurityCenter.Alert.CompromisedEntity | string | The entity on which the incident occurred. |
| AzureSecurityCenter.Alert.DetectedTime | date | The time the vendor detected the incident. |
| AzureSecurityCenter.Alert.ReportedTime | date | The time the incident was reported to Microsoft.Security, in UTC. |
| AzureSecurityCenter.Alert.ReportedSeverity | string | The estimated severity of the alert. |
| AzureSecurityCenter.Alert.State | string | The alert state (Active, Dismissed, etc.). |
| AzureSecurityCenter.Alert.ConfidenceScore | string | Level of confidence for the alert. |
| AzureSecurityCenter.Alert.ActionTaken | string | The action that was taken as a response to the alert (Active, Blocked etc.). |
| AzureSecurityCenter.Alert.CanBeInvestigated | string | Whether this alert can be investigated using Azure Security Center. |
| AzureSecurityCenter.Alert.RemediationSteps | string | Recommended steps to remediate the incident. |
| AzureSecurityCenter.Alert.VendorName | string | Name of the vendor that discovered the incident. |
| AzureSecurityCenter.Alert.AssociatedResource | string | Azure resource ID of the associated resource. |
| AzureSecurityCenter.Alert.AlertName | string | Name of the alert type. |
| AzureSecurityCenter.Alert.InstanceID | string | Instance ID of the alert. |
| AzureSecurityCenter.Alert.ID | string | The alert ID. |
| AzureSecurityCenter.Alert.SubscriptionID | string | Azure subscription ID of the resource that had the security alert or the subscription ID of the workspace that this resource reports to. |
| AzureSecurityCenter.Alert.Description | string | Description and explanation of the incident. |
| AzureSecurityCenter.Alert.ExtendedProperties | string | Changing set of properties depending on the alert type. |
| AzureSecurityCenter.Alert.Entities | string | Objects that are related to the alert. |

##### Command Example

`!azure-sc-get-alert asc_location="location" alert_id="alert_id"`

## Additional Information

For more information regarding roles, see [the microsoft documentation.](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)
