This integration enables you to deploy and manage storage accounts and blob services.
This integration was integrated and tested with version 2022-09-01 of Azure Storage

# Authorization

In order to connect to the Azure Storage Accounts and the Blob Service use either the Cortex XSOAR Azure App or the Self-Deployed Azure App.
Use one of the following methods:

1. *Authorization Code Flow* (Recommended).
2. *Client Credentials Flow*.
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
4. Search for the specific Microsoft API and select the specific permission of type Delegated.

### Authentication Using the Authorization Code Flow (recommended)

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. In the *Authentication Type* field, select the **Authorization Code** option.
3. In the *Application ID* field, enter your Client/Application ID.
4. In the *Client Secret* field, enter your Client Secret.
5. In the *Tenant ID* field, enter your Tenant ID .
6. In the *Application redirect URI* field, enter your Application redirect URI.
7. Save the instance.
8. Run the `!azure-storage-generate-login-url` command in the War Room and follow the instruction.

### Authentication Using the Client Credentials Flow

1. Assign Azure roles using the Azure portal [Microsoft article](https://learn.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal)

   *Note:* At the 'Select members' section, assign the application you created before.

2. To configure a Microsoft integration that uses this authorization flow with a self-deployed Azure application:

   a. In the **Authentication Type** field, select the **Client Credentials** option.

   b. In the **Application ID** field, enter your Client/Application ID.

   c. In the **Subscription ID** field, enter your Subscription ID.

   d. In the **Resource Group Name** field, enter you Resource Group Name.

   e. In the **Tenant ID** field, enter your Tenant ID.

   f. In the **Client Secret** field, enter your Client Secret.

   g. Click **Test** to validate the URLs, token, and connection

   h. Save the instance.


### Authentication Using the Device Code Flow

Use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

1. Fill in the required parameters.
2. Run the ***!azure-storage-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-storage-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (55f9764e-300a-474a-a2bb-549cece85439).

You only need to fill in your subscription ID and resource group name. For more details, follow [Azure Integrations Parameters](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

#### Self-Configured Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have *user_impersonation* permission and must allow public client flows (can be found under the **Authentication** section of the app).

## Configure Azure Storage on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Storage Management.
3. Click **Add instance** to create and configure a new integration instance.

   | **Parameter** | **Description** | **Required** |
             | --- | --- | --- |
   | Application ID |  | False |
   | Default Subscription ID | There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value. | True |
   | Default Resource Group Name | There are two options to set the specified value, either in the configuration or directly within the commands. However, setting values in both places will cause an override by the command value. | True |
   | Trust any certificate (not secure) |  | False |
   | Use system proxy settings |  | False |
   | Authentication Type | Type of authentication - can be Authorization Code flow \(recommended\), Device Code Flow, or Azure Managed Identities. | True |
   | Tenant ID (for user-auth mode) |  | False |
   | Client Secret (for user-auth mode) |  | False |
   | Azure Managed Identities Client ID | The Managed Identities client ID for authentication - relevant only if the integration is running on Azure VM. | False |
   | Application redirect URI (for user-auth mode) |  | False |
   | Authorization code | For user-auth mode - received from the authorization step. See Detailed Instructions \(?\) section. | False |

1. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### azure-storage-auth-test

***
Tests the connectivity to Azure.

#### Base Command

`azure-storage-auth-test`

#### Input

There are no input arguments for this command.

#### Human Readable Output

> ✅ Success!

### azure-storage-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

#### Base Command

`azure-storage-auth-start`

#### Input

There are no input arguments for this command.

#### Human Readable Output

> ### Authorization instructions
>        1. To sign in, use a web browser to open the page:
>            [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
>           and enter the code **XXXXXXXX** to authenticate.
>        2. Run the ***!azure-storage-auth-complete*** command in the War Room.

### azure-storage-auth-complete

***
Run this command to complete the authorization process. Should be used after running the ***azure-storage-auth-start*** command.

#### Base Command

`azure-storage-auth-complete`

#### Input

There are no input arguments for this command.

#### Human Readable Output

> ✅ Authorization completed successfully.

### azure-storage-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

#### Base Command

`azure-storage-auth-reset`

#### Input

There are no input arguments for this command.

#### Human Readable Output

> Authorization was reset successfully. You can now run ***!azure-storage-auth-start*** and ***!azure-storage-auth-complete***.

### azure-storage-account-list

***
Run this command to get the all or specific account storage details.

#### Base Command

`azure-storage-account-list`

#### Input

| **Argument Name**   | **Description**                                                                                                  | **Required** |
|---------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name        | The name of the storage account, optional.                                                                       | Optional     | 
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

| **Path**                                                                           | **Type** | **Description**                                                                                                                                                                                                                                   |
|------------------------------------------------------------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AzureStorage.StorageAccount.id                                                     | String   | Fully qualified resource ID for the resource.                                                                                                                                                                                                     | 
| AzureStorage.StorageAccount.kind                                                   | String   | Gets the Kind.                                                                                                                                                                                                                                    | 
| AzureStorage.StorageAccount.location                                               | String   | The geo-location where the resource lives                                                                                                                                                                                                         | 
| AzureStorage.StorageAccount.name                                                   | String   | The name of the resource                                                                                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.isHnsEnabled                                | Boolean  | Account HierarchicalNamespace enabled if sets to true.                                                                                                                                                                                            | 
| AzureStorage.StorageAccount.properties.allowBlobPublicAccess                       | Boolean  | Allow or disallow public access to all blobs or containers in the storage account. The default interpretation is true for this property.                                                                                                          | 
| AzureStorage.StorageAccount.properties.minimumTlsVersion                           | String   | Set the minimum TLS version to be permitted on requests to storage. The default interpretation is TLS 1.0 for this property.                                                                                                                      | 
| AzureStorage.StorageAccount.properties.allowSharedKeyAccess                        | Boolean  | Indicates whether the storage account permits requests to be authorized with the account access key via Shared Key. If false, then all requests, including shared access signatures, must be authorized with Azure Active Directory \(Azure AD\). | 
| AzureStorage.StorageAccount.properties.creationTime                                | Date     | Gets the creation date and time of the storage account in UTC.                                                                                                                                                                                    | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.web                        | String   | Gets the web endpoint.                                                                                                                                                                                                                            | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.dfs                        | String   | Gets the dfs endpoint.                                                                                                                                                                                                                            | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.blob                       | String   | Gets the blob endpoint.                                                                                                                                                                                                                           | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.file                       | String   | Gets the file endpoint.                                                                                                                                                                                                                           | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.queue                      | String   | Gets the queue endpoint.                                                                                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.table                      | String   | Gets the table endpoint.                                                                                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.web     | String   | Gets the web microsoft endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.dfs     | String   | Gets the dfs microsoft endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.blob    | String   | Gets the blob microsoft endpoint.                                                                                                                                                                                                                 | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.file    | String   | Gets the file microsoft endpoint.                                                                                                                                                                                                                 | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.queue   | String   | Gets the queue microsoft endpoint.                                                                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.table   | String   | Gets the table microsoft endpoint.                                                                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.web      | String   | Gets the web internet endpoint.                                                                                                                                                                                                                   | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.dfs      | String   | Gets the dfs internet endpoint.                                                                                                                                                                                                                   | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.blob     | String   | Gets the blob internet endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.file     | String   | Gets the file internet endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryLocation                             | String   | Gets the location of the primary data center for the storage account.                                                                                                                                                                             | 
| AzureStorage.StorageAccount.properties.provisioningState                           | String   | Gets the status of the storage account at the time the operation was called.                                                                                                                                                                      | 
| AzureStorage.StorageAccount.properties.routingPreference.routingChoice             | String   | Routing Choice defines the kind of network routing opted by the user.                                                                                                                                                                             | 
| AzureStorage.StorageAccount.properties.routingPreference.publishMicrosoftEndpoints | Boolean  | A boolean flag which indicates whether microsoft routing storage endpoints are to be published.                                                                                                                                                   | 
| AzureStorage.StorageAccount.properties.routingPreference.publishInternetEndpoints  | Boolean  | A boolean flag which indicates whether internet routing storage endpoints are to be published.                                                                                                                                                    | 
| AzureStorage.StorageAccount.properties.encryption.services.file.keyType            | String   | Encryption key type to be used for the encryption service. 'Account' key type implies that an account-scoped encryption key will be used. 'Service' key type implies that a default service key is used.                                          | 
| AzureStorage.StorageAccount.properties.encryption.services.file.enabled            | Boolean  | A boolean indicating whether or not the service encrypts the data as it is stored.                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.encryption.services.file.lastEnabledTime    | Date     | Gets a rough estimate of the date/time when the encryption was last enabled by the user.                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.encryption.services.blob.keyType            | String   | Encryption key type to be used for the encryption service. 'Account' key type implies that an account-scoped encryption key will be used. 'Service' key type implies that a default service key is used.                                          | 
| AzureStorage.StorageAccount.properties.encryption.services.blob.enabled            | Boolean  | A boolean indicating whether or not the service encrypts the data as it is stored.                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.encryption.services.blob.lastEnabledTime    | Date     | Gets a rough estimate of the date/time when the encryption was last enabled by the user.                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.encryption.requireInfrastructureEncryption  | Boolean  | A boolean indicating whether or not the service applies a secondary layer of encryption with platform managed keys for data at rest.                                                                                                              | 
| AzureStorage.StorageAccount.properties.encryption.keySource                        | String   | The encryption keySource \(provider\). Possible values \(case-insensitive\): Microsoft.Storage, Microsoft.Keyvault.                                                                                                                               | 
| AzureStorage.StorageAccount.properties.secondaryLocation                           | String   | Gets the location of the geo-replicated secondary for the storage account. Only available if the accountType is Standard_GRS or Standard_RAGRS.                                                                                                   | 
| AzureStorage.StorageAccount.properties.statusOfPrimary                             | String   | Gets the status indicating whether the primary location of the storage account is available or unavailable                                                                                                                                        | 
| AzureStorage.StorageAccount.properties.statusOfSecondary                           | String   | Gets the status indicating whether the secondary location of the storage account is available or unavailable. Only available if the SKU name is Standard_GRS or Standard_RAGRS.                                                                   | 
| AzureStorage.StorageAccount.properties.supportsHttpsTrafficOnly                    | Boolean  | Allows https traffic only to storage service if sets to true.                                                                                                                                                                                     | 
| AzureStorage.StorageAccount.sku.name                                               | String   | The SKU name. Required for account creation; optional for update.                                                                                                                                                                                 | 
| AzureStorage.StorageAccount.sku.tier                                               | String   | The SKU tier. This is based on the SKU name.                                                                                                                                                                                                      | 
| AzureStorage.StorageAccount.tags                                                   | Unknown  | Resource tags.                                                                                                                                                                                                                                    | 
| AzureStorage.StorageAccount.type                                                   | String   | The type of the resource.                                                                                                                                                                                                                         | 

#### Command Example

```!azure-storage-account-list```

#### Context Example

```json
{
    "AzureStorage": {
        "StorageAccount": [
            {
                "id": "/subscriptions/subsciption_id/resourceGroups/esource_group_name/providers/Microsoft.Storage/storageAccounts/account_name",
                "kind": "Storage",
                "location": "eastus",
                "name": "account_name",
                "properties": {
                    "creationTime": "2018-10-22T22:38:38.8180662Z",
                    "encryption": {
                        "keySource": "Microsoft.Storage",
                        "services": {
                            "blob": {
                                "enabled": true,
                                "keyType": "Account",
                                "lastEnabledTime": "2018-10-22T22:38:38.9742903Z"
                            },
                            "file": {
                                "enabled": true,
                                "keyType": "Account",
                                "lastEnabledTime": "2018-10-22T22:38:38.9742903Z"
                            }
                        }
                    },
                    "minimumTlsVersion": "TLS1_1",
                    "networkAcls": {
                        "bypass": "AzureServices",
                        "defaultAction": "Allow",
                        "ipRules": [],
                        "virtualNetworkRules": []
                    },
                    "primaryEndpoints": {
                        "blob": "",
                        "file": "",
                        "queue": "",
                        "table": ""
                    },
                    "primaryLocation": "eastus",
                    "privateEndpointConnections": [],
                    "provisioningState": "Succeeded",
                    "secondaryLocation": "westus",
                    "statusOfPrimary": "available",
                    "statusOfSecondary": "available",
                    "supportsHttpsTrafficOnly": false
                },
                "sku": {
                    "name": "Standard_GRS",
                    "tier": "Standard"
                },
                "tags": {
                    "ms-resource-usage": "azure-cloud-shell"
                },
                "type": "Microsoft.Storage/storageAccounts"
            }
        ]
    }
}
```

#### Human Readable Output

> ### Azure Storage Account List
>|Account Name|Subscription ID|Resource Group|Kind|Status Primary|Status Secondary|Location|
>|---|---|---|---|---|---|---|
>| acount_name1 | subscription_id1 | resource_group_name1 | Storage | available | available | eastus |
>| acount_name2 | subscription_id2 | resource_group_name2 | BlobStorage | available | available | eastus |
>| acount_name3 | subscription_id3 | resource_group_name3 | Storage | available |  | westeurope |

### azure-storage-account-create-update

***
Run this command to create or update a specific
account storage.

#### Base Command

`azure-storage-account-create-update`

#### Input

| **Argument Name**                   | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | **Required** |
|-------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| account_name                        | The name of the storage account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Required     | 
| sku                                 | Gets or sets the SKU name, Required for account creation; optional for update. Possible values are: Premium_LRS, Premium_ZRS, Standard_GRS, Standard_GZRS, Standard_LRS, Standard_RAGRS, Standard_RAGZRS, Standard_ZRS.                                                                                                                                                                                                                                                                                                                                                                                                                                           | Required     | 
| kind                                | Indicates the type of storage account. Possible values are: Storage, StorageV2, BlobStorage, FileStorage, BlockBlobStorage.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       | Required     | 
| location                            | Gets or sets the location of the resource. The geo region of a resource cannot be changed once it is created, but if an identical geo region is specified on update, the request will succeed. Possible values are: eastus, eastus2, westus, westeurope, eastasia, southeastasia, japaneast, japanwest, northcentralus, southcentralus, centralus, northeurope, brazilsouth, australiaeast, australiasoutheast, southindia, centralindia, westindia, canadaeast, canadacentral, westus2, westcentralus, uksouth, ukwest, koreacentral, koreasouth, francecentral, australiacentral, southafricanorth, uaenorth, switzerlandnorth, germanywestcentral, norwayeast. | Required     | 
| tags                                | Gets or sets a list of tags that describe the resource.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Optional     | 
| custom_domain_name                  | Gets or sets the custom domain name assigned to the storage account.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional     | 
| use_sub_domain_name                 | Indicates whether indirect CName validation is enabled. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional     | 
| enc_key_source                      | The encryption keySource. Possible values are: Microsoft.Storage, Microsoft.Keyvault.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Optional     | 
| enc_requireInfrastructureEncryption | Indicating whether the service applies a secondary layer of encryption with platform managed keys for data at rest. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Optional     | 
| enc_keyvault_key_name               | The name of KeyVault key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         | Optional     | 
| enc_keyvault_key_version            | The version of KeyVault key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Optional     | 
| enc_keyvault_uri                    | The Uri of KeyVault.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional     | 
| access_tier                         | The access tier for the account. Required where kind = BlobStorage. Possible values are: Hot, Cool.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional     | 
| supports_https_traffic_only         | Allows https traffic only to storage service if sets to true. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional     | 
| is_hns_enabled                      | Account HierarchicalNamespace enabled if sets to true. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Optional     | 
| large_file_shares_state             | Allow large file shares if sets to Enabled. Possible values are: Disabled, Enabled.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Optional     | 
| allow_blob_public_access            | Allow or disallow public access to all blobs or containers in the storage account. Possible values are: true, false.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional     | 
| minimum_tls_version                 | Set the minimum TLS version to be permitted on requests to storage. Possible values are: TLS1_0, TLS1_1, TLS1_2.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional     | 
| network_ruleset_bypass              | Specifies whether traffic is bypassed for Logging/Metrics/AzureServices. Possible values are: AzureServices, Logging, Metrics, None.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Optional     | 
| network_ruleset_default_action      | Specifies the default action of allow or deny when no other rules match.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Optional     | 
| network_ruleset_ipRules             | Sets the IP ACL rules.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Optional     | 
| virtual_network_rules               | Sets the virtual network rules.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Optional     | 
| subscription_id                     | The subscription ID. Note: This argument will override the instance parameter Default Subscription ID'.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Optional     |
 resource_group_name                 | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Optional     |

#### Context Output

| **Path**                                                                           | **Type** | **Description**                                                                                                                                                                                                                                   |
|------------------------------------------------------------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AzureStorage.StorageAccount.id                                                     | String   | Fully qualified resource ID for the resource.                                                                                                                                                                                                     | 
| AzureStorage.StorageAccount.kind                                                   | String   | Gets the Kind.                                                                                                                                                                                                                                    | 
| AzureStorage.StorageAccount.location                                               | String   | The geo-location where the resource lives.                                                                                                                                                                                                        | 
| AzureStorage.StorageAccount.name                                                   | String   | The name of the resource.                                                                                                                                                                                                                         | 
| AzureStorage.StorageAccount.properties.isHnsEnabled                                | Boolean  | Account HierarchicalNamespace enabled if sets to true.                                                                                                                                                                                            | 
| AzureStorage.StorageAccount.properties.allowBlobPublicAccess                       | Boolean  | Allow or disallow public access to all blobs or containers in the storage account. The default interpretation is true for this property.                                                                                                          | 
| AzureStorage.StorageAccount.properties.minimumTlsVersion                           | String   | Set the minimum TLS version to be permitted on requests to storage. The default interpretation is TLS 1.0 for this property.                                                                                                                      | 
| AzureStorage.StorageAccount.properties.allowSharedKeyAccess                        | Boolean  | Indicates whether the storage account permits requests to be authorized with the account access key via Shared Key. If false, then all requests, including shared access signatures, must be authorized with Azure Active Directory \(Azure AD\). | 
| AzureStorage.StorageAccount.properties.creationTime                                | Date     | Gets the creation date and time of the storage account in UTC.                                                                                                                                                                                    | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.web                        | String   | Gets the web endpoint.                                                                                                                                                                                                                            | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.dfs                        | String   | Gets the dfs endpoint.                                                                                                                                                                                                                            | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.blob                       | String   | Gets the blob endpoint.                                                                                                                                                                                                                           | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.file                       | String   | Gets the file endpoint.                                                                                                                                                                                                                           | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.queue                      | String   | Gets the queue endpoint.                                                                                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.table                      | String   | Gets the table endpoint.                                                                                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.web     | String   | Gets the web microsoft endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.dfs     | String   | Gets the dfs microsoft endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.blob    | String   | Gets the blob microsoft endpoint.                                                                                                                                                                                                                 | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.file    | String   | Gets the file microsoft endpoint.                                                                                                                                                                                                                 | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.queue   | String   | Gets the queue microsoft endpoint.                                                                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.microsoftEndpoints.table   | String   | Gets the table microsoft endpoint.                                                                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.web      | String   | Gets the web internet endpoint.                                                                                                                                                                                                                   | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.dfs      | String   | Gets the dfs internet endpoint.                                                                                                                                                                                                                   | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.blob     | String   | Gets the blob internet endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryEndpoints.internetEndpoints.file     | String   | Gets the file internet endpoint.                                                                                                                                                                                                                  | 
| AzureStorage.StorageAccount.properties.primaryLocation                             | String   | Gets the location of the primary data center for the storage account.                                                                                                                                                                             | 
| AzureStorage.StorageAccount.properties.provisioningState                           | String   | Gets the status of the storage account at the time the operation was called.                                                                                                                                                                      | 
| AzureStorage.StorageAccount.properties.routingPreference.routingChoice             | String   | Routing Choice defines the kind of network routing opted by the user.                                                                                                                                                                             | 
| AzureStorage.StorageAccount.properties.routingPreference.publishMicrosoftEndpoints | Boolean  | A boolean flag which indicates whether microsoft routing storage endpoints are to be published.                                                                                                                                                   | 
| AzureStorage.StorageAccount.properties.routingPreference.publishInternetEndpoints  | Boolean  | A boolean flag which indicates whether internet routing storage endpoints are to be published.                                                                                                                                                    | 
| AzureStorage.StorageAccount.properties.encryption.services.file.keyType            | String   | Encryption key type to be used for the encryption service. 'Account' key type implies that an account-scoped encryption key will be used. 'Service' key type implies that a default service key is used.                                          | 
| AzureStorage.StorageAccount.properties.encryption.services.file.enabled            | Boolean  | A boolean indicating whether or not the service encrypts the data as it is stored.                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.encryption.services.file.lastEnabledTime    | Date     | Gets a rough estimate of the date/time when the encryption was last enabled by the user.                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.encryption.services.blob.keyType            | String   | Encryption key type to be used for the encryption service. 'Account' key type implies that an account-scoped encryption key will be used. 'Service' key type implies that a default service key is used.                                          | 
| AzureStorage.StorageAccount.properties.encryption.services.blob.enabled            | Boolean  | A boolean indicating whether or not the service encrypts the data as it is stored.                                                                                                                                                                | 
| AzureStorage.StorageAccount.properties.encryption.services.blob.lastEnabledTime    | Date     | Gets a rough estimate of the date/time when the encryption was last enabled by the user.                                                                                                                                                          | 
| AzureStorage.StorageAccount.properties.encryption.requireInfrastructureEncryption  | Boolean  | A boolean indicating whether or not the service applies a secondary layer of encryption with platform managed keys for data at rest.                                                                                                              | 
| AzureStorage.StorageAccount.properties.encryption.keySource                        | String   | The encryption keySource \(provider\). Possible values \(case-insensitive\): Microsoft.Storage, Microsoft.Keyvault.                                                                                                                               | 
| AzureStorage.StorageAccount.properties.secondaryLocation                           | String   | Gets the location of the geo-replicated secondary for the storage account. Only available if the accountType is Standard_GRS or Standard_RAGRS.                                                                                                   | 
| AzureStorage.StorageAccount.properties.statusOfPrimary                             | String   | Gets the status indicating whether the primary location of the storage account is available or unavailable                                                                                                                                        | 
| AzureStorage.StorageAccount.properties.statusOfSecondary                           | String   | Gets the status indicating whether the secondary location of the storage account is available or unavailable. Only available if the SKU name is Standard_GRS or Standard_RAGRS.                                                                   | 
| AzureStorage.StorageAccount.properties.supportsHttpsTrafficOnly                    | Boolean  | Allows https traffic only to storage service if sets to true.                                                                                                                                                                                     | 
| AzureStorage.StorageAccount.sku.name                                               | String   | The SKU name. Required for account creation; optional for update.                                                                                                                                                                                 | 
| AzureStorage.StorageAccount.sku.tier                                               | String   | The SKU tier. This is based on the SKU name.                                                                                                                                                                                                      | 
| AzureStorage.StorageAccount.tags                                                   | Unknown  | Resource tags.                                                                                                                                                                                                                                    | 
| AzureStorage.StorageAccount.type                                                   | String   | The type of the resource.                                                                                                                                                                                                                         | 

#### Command Example

```!azure-storage-account-create-update account_name=account_name1 kind=BlobStorage location=eastus sku=Standard_GRS```

#### Context Example

```json
{
    "AzureStorage": {
        "StorageAccount": {
            "id": "/subscriptions/sub_id/resourceGroups/resource_g_name/providers/Microsoft.Storage/storageAccounts/account_name",
            "kind": "BlobStorage",
            "location": "eastus",
            "name": "account_name",
            "properties": {
                "accessTier": "Cool",
                "creationTime": "2021-02-22T13:15:19.2816113Z",
                "encryption": {
                    "keySource": "Microsoft.Storage",
                    "services": {
                        "blob": {
                            "enabled": true,
                            "keyType": "Account",
                            "lastEnabledTime": "2021-02-22T13:15:19.3910225Z"
                        },
                        "file": {
                            "enabled": true,
                            "keyType": "Account",
                            "lastEnabledTime": "2021-02-22T13:15:19.3910225Z"
                        }
                    }
                },
                "minimumTlsVersion": "TLS1_1",
                "networkAcls": {
                    "bypass": "AzureServices",
                    "defaultAction": "Allow",
                    "ipRules": [],
                    "virtualNetworkRules": []
                },
                "primaryEndpoints": {
                    "blob": "",
                    "dfs": "",
                    "table": ""
                },
                "primaryLocation": "eastus",
                "privateEndpointConnections": [],
                "provisioningState": "Succeeded",
                "secondaryLocation": "westus",
                "statusOfPrimary": "available",
                "statusOfSecondary": "available",
                "supportsHttpsTrafficOnly": false
            },
            "sku": {
                "name": "Standard_GRS",
                "tier": "Standard"
            },
            "tags": {},
            "type": "Microsoft.Storage/storageAccounts"
        }
    }
}
```

#### Human Readable Output

> ### Azure Storage Account
>|Account Name|Subscription ID|Resource Group|Kind|Status Primary|Status Secondary|Location|
>|---|---|---|---|---|---|---|
>| acount_name1 | subscription_id1 | resource_group_name1 | BlobStorage | available | available | eastus |

### azure-storage-blob-service-properties-get

***
Run this command to get the blob service properties of a specific account storage.

#### Base Command

`azure-storage-blob-service-properties-get`

#### Input

| **Argument Name**   | **Description**                                                                                                  | **Required** |
|---------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name        | The name of the storage account.                                                                                 | Required     | 
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

| **Path**                                                                                             | **Type** | **Description**                                                                                                      |
|------------------------------------------------------------------------------------------------------|----------|----------------------------------------------------------------------------------------------------------------------|
| AzureStorage.BlobServiceProperties.id                                                                | String   | Fully qualified resource ID for the resource.                                                                        | 
| AzureStorage.BlobServiceProperties.name                                                              | String   | The name of the resource                                                                                             | 
| AzureStorage.BlobServiceProperties.type                                                              | String   | The type of the resource.                                                                                            | 
| AzureStorage.BlobServiceProperties.properties.lastAccessTimeTrackingPolicy.enable                    | Boolean  | When set to true last access time based tracking is enabled.                                                         | 
| AzureStorage.BlobServiceProperties.properties.lastAccessTimeTrackingPolicy.name                      | String   | Name of the policy. The valid value is AccessTimeTracking.                                                           | 
| AzureStorage.BlobServiceProperties.properties.lastAccessTimeTrackingPolicy.trackingGranularityInDays | Number   | The field specifies blob object tracking granularity in days, typically how often the blob object should be tracked. | 
| AzureStorage.BlobServiceProperties.properties.lastAccessTimeTrackingPolicy.blobType                  | String   | An array of predefined supported blob types. Only blockBlob is the supported value.                                  | 

#### Command Example

```!azure-storage-blob-service-properties-get account_name=account_name1```

#### Context Example

```json
{
    "AzureStorage": {
        "BlobServiceProperties": {
            "id": "/subscriptions/sub_id/resourceGroups/resource_g_name/providers/Microsoft.Storage/storageAccounts/account_name/blobServices/default",
            "name": "default",
            "properties": {
                "changeFeed": {
                    "enabled": false
                },
                "cors": {
                    "corsRules": []
                },
                "deleteRetentionPolicy": {
                    "enabled": false
                },
                "isVersioningEnabled": false
            },
            "sku": {
                "name": "Standard_GRS",
                "tier": "Standard"
            },
            "type": "Microsoft.Storage/storageAccounts/blobServices"
        }
    }
}
```

#### Human Readable Output

> ### Azure Storage Blob Service Properties
>|Name|Account Name|Subscription ID|Resource Group|Change Feed|Delete Retention Policy|Versioning|
>|---|---|---|---|---|---|---|
>| default | account_name | subscription_id | resource_group_name | change_feed_enabled | delete_retention_policy_enabled | is_versioning_enabled |

### azure-storage-blob-service-properties-set

***
Run this command to set properties for
the blob service in a specific account storage

#### Base Command

`azure-storage-blob-service-properties-set`

#### Input

| **Argument Name**                           | **Description**                                                                                                  | **Required** |
|---------------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name                                | The name of the storage account.                                                                                 | Required     | 
| change_feed_enabled                         | Indicates whether change feed event logging is enabled for the Blob service. Possible values are: true, false.   | Optional     | 
| change_feed_retention_days                  | Indicates the duration of changeFeed retention in days.                                                          | Optional     | 
| container_delete_rentention_policy_enabled  | Indicates whether DeleteRetentionPolicy is enabled. Possible values are: true, false.                            | Optional     | 
| container_delete_rentention_policy_days     | Indicates the number of days that the deleted item should be retained.                                           | Optional     | 
| delete_rentention_policy_enabled            | Indicates whether DeleteRetentionPolicy is enabled. Possible values are: true, false.                            | Optional     | 
| delete_rentention_policy_days               | Indicates the number of days that the deleted item should be retained.                                           | Optional     | 
| versioning                                  | Versioning is enabled if set to true. Possible values are: true, false.                                          | Optional     | 
| last_access_time_tracking_policy_enabled    | When set to true last access time based tracking is enabled. Possible values are: true, false.                   | Optional     | 
| last_access_time_tracking_policy_blob_types | An array of predefined supported blob types.                                                                     | Optional     | 
| last_access_time_tracking_policy_days       | The field specifies blob object tracking granularity in days.                                                    | Optional     | 
| restore_policy_enabled                      | Blob restore is enabled if set to true. Possible values are: true, false.                                        | Optional     | 
| restore_policy_min_restore_time             | The minimum date and time that the restore can be started.                                                       | Optional     | 
| restore_policy_days                         | how long this blob can be restored.                                                                              | Optional     | 
| subscription_id                             | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name                         | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

| **Path**                                                                     | **Type** | **Description**                                                                                                                                                                                         |
|------------------------------------------------------------------------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AzureStorage.BlobServiceProperties.id                                        | String   | Fully qualified resource ID for the resource.                                                                                                                                                           | 
| AzureStorage.BlobServiceProperties.name                                      | String   | The name of the resource.                                                                                                                                                                               | 
| AzureStorage.BlobServiceProperties.type                                      | String   | The type of the resource.                                                                                                                                                                               | 
| AzureStorage.BlobServiceProperties.properties.cors.corsRules.allowedOrigins  | String   | Required if CorsRule element is present. A list of origin domains that will be allowed via CORS, or "\*" to allow all domains.                                                                          | 
| AzureStorage.BlobServiceProperties.properties.cors.corsRules.allowedMethods  | String   | Required if CorsRule element is present. A list of HTTP methods that are allowed to be executed by the origin.                                                                                          | 
| AzureStorage.BlobServiceProperties.properties.cors.corsRules.maxAgeInSeconds | Number   | Required if CorsRule element is present. The number of seconds that the client/browser should cache a preflight response.                                                                               | 
| AzureStorage.BlobServiceProperties.properties.cors.corsRules.exposedHeaders  | String   | Required if CorsRule element is present. A list of response headers to expose to CORS clients.                                                                                                          | 
| AzureStorage.BlobServiceProperties.properties.cors.corsRules.allowedHeaders  | String   | Required if CorsRule element is present. A list of headers allowed to be part of the cross-origin request.                                                                                              | 
| AzureStorage.BlobServiceProperties.properties.defaultServiceVersion          | Date     | Indicates the default version to use for requests to the Blob service if an incoming request\\u2019s version is not specified. Possible values include version 2008-10-27 and all more recent versions. | 
| AzureStorage.BlobServiceProperties.properties.deleteRetentionPolicy.enabled  | Boolean  | Indicates whether DeleteRetentionPolicy is enabled.                                                                                                                                                     | 
| AzureStorage.BlobServiceProperties.properties.deleteRetentionPolicy.days     | Number   | Indicates the number of days that the deleted item should be retained. The minimum specified value can be 1 and the maximum value can be 365.                                                           | 
| AzureStorage.BlobServiceProperties.properties.isVersioningEnabled            | Boolean  | Versioning is enabled if set to true.                                                                                                                                                                   | 
| AzureStorage.BlobServiceProperties.properties.changeFeed.enabled             | Boolean  | Indicates whether change feed event logging is enabled for the Blob service.                                                                                                                            | 
| AzureStorage.BlobServiceProperties.properties.changeFeed.retentionInDays     | Number   | Indicates the duration of changeFeed retention in days. Minimum value is 1 day and maximum value is 146000 days.                                                                                        | 
| AzureStorage.BlobServiceProperties.sku.name                                  | String   | The SKU name.                                                                                                                                                                                           | 
| AzureStorage.BlobServiceProperties.sku.tier                                  | String   | The SKU tier.                                                                                                                                                                                           | 

#### Command Example

```!azure-storage-blob-service-properties-set account_name=account_name1 delete_rentention_policy_enabled=false```

#### Context Example

```json
{
    "AzureStorage": {
        "BlobServiceProperties": {
            "id": "/subscriptions/sub_id/resourceGroups/resource_g_name/providers/Microsoft.Storage/storageAccounts/account_name/blobServices/default",
            "name": "default",
            "properties": {
                "deleteRetentionPolicy": {
                    "enabled": false
                }
            },
            "type": "Microsoft.Storage/storageAccounts/blobServices"
        }
    }
}
```

#### Human Readable Output

> ### Azure Storage Blob Service Properties
>|Name|Account Name|Subscription ID|Resource Group|Change Feed|Delete Retention Policy|Versioning|
>|---|---|---|---|---|---|---|
>| default | account_name | subscription_id | resource_group_name | change_feed_enabled | delete_retention_policy_enabled | is_versioning_enabled |

### azure-storage-blob-containers-create

***
Run this command to create a blob container.

#### Base Command

`azure-storage-blob-containers-create`

#### Input

| **Argument Name**              | **Description**                                                                                                  | **Required** |
|--------------------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name                   | The name of the storage account.                                                                                 | Required     | 
| container_name                 | The name of the container.                                                                                       | Required     | 
| default_encryption_scope       | Default the container to use specified encryption scope for all writes.                                          | Optional     | 
| deny_encryption_scope_override | Block override of encryption scope from the container default. Possible values are: true, false.                 | Optional     | 
| public_access                  | Specifies the level of access. Possible values are: Blob, Container, None.                                       | Optional     |
| subscription_id                | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name            | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     | 

#### Context Output

| **Path**                        | **Type** | **Description**                               |
|---------------------------------|----------|-----------------------------------------------|
| AzureStorage.BlobContainer.id   | String   | Fully qualified resource ID for the resource. | 
| AzureStorage.BlobContainer.name | String   | The name of the resource.                     | 
| AzureStorage.BlobContainer.type | String   | The type of the resource.                     | 

#### Command Example

```!azure-storage-blob-containers-create account_name=account_name container_name=container_name```

#### Context Example

```json
{
    "AzureStorage": {
        "BlobContainer": {
            "id": "/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Storage/storageAccounts/account_name/blobServices/default/containers/container_name",
            "name": "container_name",
            "properties": {
                "deleted": false,
                "hasImmutabilityPolicy": false,
                "hasLegalHold": false,
                "remainingRetentionDays": 0
            },
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers"
        }
    }
}
```

#### Human Readable Output

> ### Azure Storage Blob Containers Properties
>|Name|Account Name|Subscription ID|Resource Group|Public Access|
>|---|---|---|---|---|
>| container_name | account_name | subscription_id | resource_group |  |

### azure-storage-blob-containers-update

***
Run this command to update a specific
blob container.

#### Base Command

`azure-storage-blob-containers-update`

#### Input

| **Argument Name**              | **Description**                                                                                                  | **Required** |
|--------------------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name                   | The name of the storage account.                                                                                 | Required     | 
| container_name                 | The name of the container.                                                                                       | Required     | 
| default_encryption_scope       | Default the container to use specified encryption scope for all writes.                                          | Optional     | 
| deny_encryption_scope_override | Block override of encryption scope from the container default. Possible values are: true, false.                 | Optional     | 
| public_access                  | Specifies the level of access. Possible values are: Blob, Container, None.                                       | Optional     | 
| subscription_id                | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name            | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

| **Path**                                                    | **Type** | **Description**                                                                                                                                                                                                                                            |
|-------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AzureStorage.BlobContainer.id                               | String   | Fully qualified resource ID for the resource.                                                                                                                                                                                                              | 
| AzureStorage.BlobContainer.name                             | String   | The name of the resource.                                                                                                                                                                                                                                  | 
| AzureStorage.BlobContainer.type                             | String   | The type of the resource.                                                                                                                                                                                                                                  | 
| AzureStorage.BlobContainer.properties.metadata.metadata     | String   | A name-value pair to associate with the container as metadata.                                                                                                                                                                                             | 
| AzureStorage.BlobContainer.properties.publicAccess          | String   | Specifies whether data in the container may be accessed publicly and the level of access.                                                                                                                                                                  | 
| AzureStorage.BlobContainer.properties.hasImmutabilityPolicy | Boolean  | The hasImmutabilityPolicy public property is set to true by SRP if ImmutabilityPolicy has been created for this container. The hasImmutabilityPolicy public property is set to false by SRP if ImmutabilityPolicy has not been created for this container. | 
| AzureStorage.BlobContainer.properties.hasLegalHold          | Boolean  | The hasLegalHold public property is set to true by SRP if there are at least one existing tag. The hasLegalHold public property is set to false by SRP if all existing legal hold tags are cleared out.                                                    | 

#### Command Example

```!azure-storage-blob-containers-update account_name=account_name container_name=container_name```

#### Context Example

```json
{
    "AzureStorage": {
        "BlobContainer": {
            "id": "/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Storage/storageAccounts/account_name/blobServices/default/containers/container_name",
            "name": "container_name",
            "properties": {
                "deleted": false,
                "hasImmutabilityPolicy": false,
                "hasLegalHold": false,
                "remainingRetentionDays": 0
            },
            "type": "Microsoft.Storage/storageAccounts/blobServices/containers"
        }
    }
}
```

#### Human Readable Output

> ### Azure Storage Blob Containers Properties
>|Name|Account Name|Subscription ID|Resource Group|Public Access|
>|---|---|---|---|---|
>| container_name | account_name | subscription_id | resource_group |  |

### azure-storage-blob-containers-list

***
Run this command to get the all or specific blob container details.

#### Base Command

`azure-storage-blob-containers-list`

#### Input

| **Argument Name**   | **Description**                                                                                                  | **Required** |
|---------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name        | The name of the storage account.                                                                                 | Required     | 
| container_name      | The name of the container.                                                                                       | Optional     | 
| include_deleted     | Specifies whether include the properties for soft deleted blob containers. Possible values are: true, false.     | Optional     | 
| maxpagesize         | Specified maximum number of containers that can be included in the list.                                         | Optional     | 
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

| **Path**                                                    | **Type** | **Description**                                                                                                                                                                                                                                            |
|-------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| AzureStorage.BlobContainer.id                               | String   | Fully qualified resource ID for the resource.                                                                                                                                                                                                              | 
| AzureStorage.BlobContainer.name                             | String   | The name of the resource.                                                                                                                                                                                                                                  | 
| AzureStorage.BlobContainer.type                             | String   | The type of the resource.                                                                                                                                                                                                                                  | 
| AzureStorage.BlobContainer.properties.publicAccess          | String   | Specifies whether data in the container may be accessed publicly and the level of access.                                                                                                                                                                  | 
| AzureStorage.BlobContainer.properties.leaseStatus           | String   | The lease status of the container.                                                                                                                                                                                                                         | 
| AzureStorage.BlobContainer.properties.leaseState            | String   | Lease state of the container.                                                                                                                                                                                                                              | 
| AzureStorage.BlobContainer.properties.lastModifiedTime      | Date     | Returns the date and time the container was last modified.                                                                                                                                                                                                 | 
| AzureStorage.BlobContainer.properties.hasImmutabilityPolicy | Boolean  | The hasImmutabilityPolicy public property is set to true by SRP if ImmutabilityPolicy has been created for this container. The hasImmutabilityPolicy public property is set to false by SRP if ImmutabilityPolicy has not been created for this container. | 
| AzureStorage.BlobContainer.properties.hasLegalHold          | Boolean  | The hasLegalHold public property is set to true by SRP if there are at least one existing tag. The hasLegalHold public property is set to false by SRP if all existing legal hold tags are cleared out.                                                    | 

#### Command Example

```!azure-storage-blob-containers-list account_name=account_name```

#### Context Example

```json
{
    "AzureStorage": {
        "BlobContainer": [
            {
                "id": "/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Storage/storageAccounts/account_name/blobServices/default/containers/container_name",
                "name": "container_name1",
                "properties": {
                    "defaultEncryptionScope": "$account-encryption-key",
                    "deleted": false,
                    "denyEncryptionScopeOverride": false,
                    "hasImmutabilityPolicy": false,
                    "hasLegalHold": false,
                    "lastModifiedTime": "2021-03-31T06:49:57.0000000Z",
                    "leaseState": "Available",
                    "leaseStatus": "Unlocked",
                    "publicAccess": "None",
                    "remainingRetentionDays": 0
                },
                "type": "Microsoft.Storage/storageAccounts/blobServices/containers"
            },
            {
                "id": "/subscriptions/subscription_id/resourceGroups/resource_group/providers/Microsoft.Storage/storageAccounts/account_name/blobServices/default/containers/container_name",
                "name": "container_name",
                "properties": {
                    "defaultEncryptionScope": "$account-encryption-key",
                    "deleted": false,
                    "denyEncryptionScopeOverride": false,
                    "hasImmutabilityPolicy": false,
                    "hasLegalHold": false,
                    "lastModifiedTime": "2021-03-31T06:45:30.0000000Z",
                    "leaseState": "Available",
                    "leaseStatus": "Unlocked",
                    "publicAccess": "None",
                    "remainingRetentionDays": 0
                },
                "type": "Microsoft.Storage/storageAccounts/blobServices/containers"
            }
        ]
    }
}
```

#### Human Readable Output

> ### Azure Storage Blob Containers list
>|Container Name|Account Name|Subscription ID|Resource Group|Public Access|Lease State|Last Modified Time|
>|---|---|---|---|---|---|---|
>| container_name1 | account_name | subscription_id | resource_group | None | Available | 2021-03-31T06:49:57.0000000Z |
>| container_name2 | account_name | subscription_id | resource_group                             | None | Available | 2021-03-31T06:45:30.0000000Z |

### azure-storage-blob-container-delete

***
Run this command to delete a specific blob container.

#### Base Command

`azure-storage-blob-container-delete`

#### Input

| **Argument Name**   | **Description**                                                                                                  | **Required** |
|---------------------|------------------------------------------------------------------------------------------------------------------|--------------|
| account_name        | The name of the storage account.                                                                                 | Required     | 
| container_name      | The name of the container.                                                                                       | Required     | 
| subscription_id     | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'.         | Optional     |
 resource_group_name | The resource group name. Note: This argument will override the instance parameter ‘Default Resource Group Name'. | Optional     |

#### Context Output

There is no context output for this command.

#### Command Example

```!azure-storage-blob-container-delete account_name=account_name container_name=container_name```

#### Human Readable Output

> The request to delete the blob container was sent successfully.

### azure-storage-generate-login-url

***
Generate the login url used for Authorization code flow.

#### Base Command

`azure-storage-generate-login-url`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example

```azure-storage-generate-login-url```

#### Human Readable Output

> ### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
    You will be automatically redirected to a link with the following structure:
    ```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
    and paste it in your instance configuration under the **Authorization code** parameter.

### azure-storage-subscriptions-list

***
Gets all subscriptions for a tenant.

#### Base Command

`azure-storage-subscriptions-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path**                                                           | **Type** | **Description**                                                             |
|--------------------------------------------------------------------|----------|-----------------------------------------------------------------------------|
| AzureStorage.Subscription.id                                       | String   | The unique identifier of the Azure storage subscription.                    | 
| AzureStorage.Subscription.authorizationSource                      | String   | The source of authorization for the Azure storage subscription.             | 
| AzureStorage.Subscription.managedByTenants                         | Unknown  | The tenants that have access to manage the Azure storage subscription.      | 
| AzureStorage.Subscription.subscriptionId                           | String   | The ID of the Azure storage subscription.                                   | 
| AzureStorage.Subscription.tenantId                                 | String   | The ID of the tenant associated with the Azure storage subscription.        | 
| AzureStorage.Subscription.displayName                              | String   | The display name of the Azure storage subscription.                         | 
| AzureStorage.Subscription.state                                    | String   | The current state of the Azure storage subscription.                        | 
| AzureStorage.Subscription.subscriptionPolicies.locationPlacementId | String   | The ID of the location placement policy for the Azure storage subscription. | 
| AzureStorage.Subscription.subscriptionPolicies.quotaId             | String   | The ID of the quota policy for the Azure storage subscription.              | 
| AzureStorage.Subscription.subscriptionPolicies.spendingLimit       | String   | The spending limit policy for the Azure storage subscription.               | 
| AzureStorage.Subscription.count.type                               | String   | The type of the Azure storage subscription count.                           | 
| AzureStorage.Subscription.count.value                              | Number   | The value of the Azure storage subscription count.                          | 

#### Command example

```!azure-storage-subscriptions-list```

#### Context Example

```json
{
    "AzureStorage": {
        "Subscription": [
            {
                "authorizationSource": "RoleBased",
                "displayName": "Access to Azure Active Directory",
                "id": "/subscriptions/00000000000000000000",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "00000000000000000000",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "AAD_2015-09-01",
                    "spendingLimit": "On"
                },
                "tenantId": "00000000000000000"
            },
            {
                "authorizationSource": "RoleBased",
                "displayName": "Pay-As-You-Go",
                "id": "/subscriptions/000000000000",
                "managedByTenants": [],
                "state": "Enabled",
                "subscriptionId": "000000000000",
                "subscriptionPolicies": {
                    "locationPlacementId": "Public_2014-09-01",
                    "quotaId": "PayAsYouGo_2014-09-01",
                    "spendingLimit": "Off"
                },
                "tenantId": "00000000000000000"
            }
        ]
    }
}
```

#### Human Readable Output

> ### Azure Storage Subscriptions list
>|subscriptionId|tenantId|displayName|state|
>|---|---|---|---|
>| 00000000000000000000 | 00000000000000000 | Access to Azure Active Directory | Enabled |
>| 000000000000 | 00000000000000000 | Pay-As-You-Go | Enabled |

### azure-storage-resource-group-list

***
Gets all resource groups for a subscription.

#### Base Command

`azure-storage-resource-group-list`

#### Input

| **Argument Name** | **Description**                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------|--------------|
| subscription_id   | The subscription ID. Note: This argument will override the instance parameter ‘Default Subscription ID'. | Optional     | 
| limit             | Limit on the number of resource groups to return. Default value is 50. Default is 50.                    | Optional     | 
| tag               | A single tag in the form of `{"Tag Name":"Tag Value"}` to filter the list by.                            | Optional     | 

#### Context Output

| **Path**                                                 | **Type** | **Description**                                                                              |
|----------------------------------------------------------|----------|----------------------------------------------------------------------------------------------|
| AzureStorage.ResourceGroup.id                            | String   | The unique identifier of the Azure storage resource group.                                   | 
| AzureStorage.ResourceGroup.name                          | String   | The name of the Azure storage resource group.                                                | 
| AzureStorage.ResourceGroup.type                          | String   | The type of the Azure storage resource group.                                                | 
| AzureStorage.ResourceGroup.location                      | String   | The location of the Azure storage resource group.                                            | 
| AzureStorage.ResourceGroup.properties.provisioningState  | String   | The provisioning state of the Azure storage resource group.                                  | 
| AzureStorage.ResourceGroup.tags.Owner                    | String   | The owner tag of the Azure storage resource group.                                           | 
| AzureStorage.ResourceGroup.tags                          | Unknown  | The tags associated with the Azure storage resource group.                                   | 
| AzureStorage.ResourceGroup.tags.Name                     | String   | The name tag of the Azure storage resource group.                                            | 
| AzureStorage.ResourceGroup.managedBy                     | String   | The entity that manages the Azure storage resource group.                                    | 
| AzureStorage.ResourceGroup.tags.aks-managed-cluster-name | String   | The AKS managed cluster name tag associated with the Azure storage resource group.           | 
| AzureStorage.ResourceGroup.tags.aks-managed-cluster-rg   | String   | The AKS managed cluster resource group tag associated with the Azure storage resource group. | 
| AzureStorage.ResourceGroup.tags.type                     | String   | The type tag associated with the Azure storage resource group.                               | 

#### Command example

```!azure-storage-resource-group-list```

#### Context Example

```json
{
    "AzureStorage": {
        "ResourceGroup": [
            {
                "id": "/subscriptions/000000000000/resourceGroups/cloud-shell-storage-eastus",
                "location": "eastus",
                "name": "cloud-shell-storage-eastus",
                "properties": {
                    "provisioningState": "Succeeded"
                },
                "type": "Microsoft.Resources/resourceGroups"
            },
            {
                "id": "/subscriptions/000000000000/resourceGroups/demi",
                "location": "centralus",
                "name": "demisto",
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


