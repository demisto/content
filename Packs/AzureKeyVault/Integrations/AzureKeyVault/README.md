Use Key Vault to safeguard and manage cryptographic keys and secrets used by cloud applications and services.
This integration was integrated and tested with version 2019-09-01 of AzureKeyVault

## Configure AzureKeyVault on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureKeyVault.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Client ID | True |
    | Client Secret (only wheb using self-deployed Azure application) | False |
    | Use a self-deployed Azure application | False |
    | Tenant ID | True |
    | Subscription ID | True |
    | Resource Group Name | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Fetches credentials | False |
    | Key Vault names - comma seperated list of Key Vaults to fetch secrets from. | False |
    | Secret names - comma seperated list of secrets to fetch. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-key-vault-create-update
***
Create or update a key vault in the specified subscription. If the Key Vault exists, the updated properties will overwrite the existing ones.


#### Base Command

`azure-key-vault-create-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | Key Vault name. | Required | 
| location | Key Vault supported Azure location. The location cannot be changed after the Key Vault is created. Default value is 'westus'. Possible values are: eastus, eastus2, southcentralus, westus2, australiaeast, southeastasia, northeurope, uksouth, westeurope, centralus, northcentralus, westus, southafricanorth, centralindia, eastasia, japaneast, jioindiawest, koreacentral, canadacentral, francecentral, germanywestcentral, norwayeast, switzerlandnorth, uaenorth, brazilsouth, centralusstage, eastusstage, eastus2stage, northcentralusstage, southcentralusstage, westusstage, westus2stage, asia, asiapacific, australia, brazil, canada, europe, global, india, japan, uk, unitedstates, eastasiastage, southeastasiastage, centraluseuap, eastus2euap, westcentralus, westus3, southafricawest, australiacentral, australiacentral2, australiasoutheast, japanwest, koreasouth, southindia, westindia, canadaeast, francesouth, germanynorth, norwaywest, switzerlandwest, ukwest, uaecentral, brazilsoutheast. | Optional | 
| sku_name | Specify whether the key vault is a standard vault or a premium vault. Default value is 'standard'. Possible values are: standard, premium. | Optional | 
| object_id | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies: Any change in the access policy regards that object ID, will override the exists one. . | Required | 
| keys | Permissions to keys. If the Key Vault exists, you must supply the previous keys permissions inorder to keep them the same. Access policy property. Default value is [get,list,create,update,import,delete,backup,restore,recover]. . Possible values are: get, list, create, update, import, delete, backup, restore, recover, decrypt, encrypt, unwrapKey, wrapKey, verify, sign, purge. | Optional | 
| secrets | Permissions to secrets. If the Key Vault exists, you must supply the previous secrets permissions inorder to keep them the same. Access policy property. Default value is [get,list,set,delete,backup,restore,recover]. Possible values are: get, list, set, delete, recover, backup, restore, purge. | Optional | 
| certificates | Permissions to certificates. If the Key Vault exists, you must supply the previous secret permissions inorder to keep them the same. Access policy property. Default value is [get,list,update,create,import,delete,recover,backup,restore,managecontacts,manageissuers,getissuers,listissuers,setissuers,deleteissuers]. Possible values are: get, list, update, create, import, delete, recover, backup, restore, managecontacts, manageissuers, getissuers, listissuers, setissuers, deleteissuers, purge.. | Optional | 
| enabled_for_deployment | Specifies whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. If the Key Vault exists, you must supply the previous value inorder to keep it the same. Default value is True. Possible values are: true, false. | Optional | 
| enabled_for_disk_encryption | Specifies whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys.If the Key Vault exists, you must supply the previous value inorder to keep it the same. Default value is True. Possible values are: true, false. | Optional | 
| enabled_for_template_deployment | Specifies whether Azure Resource Manager is permitted to retrieve secrets from the key vault. If the Key Vault exists, you must supply the previous value inorder to keep it the same. Default value is True. Possible values are: true, false. | Optional | 
| default_action | The default action when no rule from ip_rules and from vnet_subnet_id match . For example,  If no ip_rules and vnet_subnet_id arguments are defined, the access to the key vault from any ip address or virtual network will be accrodingly to the default_action value. If you wish to allow access only from specific virtual network or ip address, use the ip_rules or the  vnet_subnet_id arguments. This is only used after the bypass property has been evaluated. Network acl property. Possible values are: Allow, Deny. | Optional | 
| bypass | Tells what traffic can bypass network rules. This can be 'AzureServices' or 'None'. For example, use 'AzureServices' if you wish to give azure services access to key vault, although the default action is 'Deny' or the access for a specific IP address. Network acl property. Default value is 'AzureServices'. Possible values are: AzureServices. | Optional | 
| vnet_subnet_id | Full resource id of a vnet subnet. For example, for the subnet ID "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/subnet1", you can access the key vault from subnet1. Network acl property. | Optional | 
| ignore_missing_vnet_service_endpoint | Specifies whether the Network Resource Provider will ignore the check if parent subnet has serviceEndpoints configured. Network Acl property. Possible values are: . Default is True. | Optional | 
| ip_rules | The list of IP address rules. Each rule governing the accessibility of a vault from a specific IP address or IP range. It can be a simple IP address "124.56.78.91" or "124.56.78.0/24" -  all addresses that start with 124.56.78. For example, for the IP addresses list: "124.56.78.91,124.56.78.92", you can access the Key Vault from "124.56.78.91" or "124.56.78.92" IP addresses. Network acl property. | Optional | 
| storage | Permissions to storage accounts. If the Key Vault exists, you must supply the previous storage permissions inorder to keep them the same. Access policy property. Default value is [get,list,set,delete,backup,restore,recover]. Possible values are: get, list, set, delete, backup, restore, recover, purge. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.KeyVault.id | String | Resource id. | 
| AzureKeyVault.KeyVault.name | String | Key Vault name. | 
| AzureKeyVault.KeyVault.type | String | Resource type in Azure. | 
| AzureKeyVault.KeyVault.location | String | Key Vault location. | 
| AzureKeyVault.KeyVault.properties.sku.family | String | SKU family name. | 
| AzureKeyVault.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. | 
| AzureKeyVault.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates. | 
| AzureKeyVault.KeyVault.properties.enabledForDeployment | Boolean | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enabledForDiskEncryption | Boolean | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. | 
| AzureKeyVault.KeyVault.properties.enabledForTemplateDeployment | Boolean | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets.

 | 
| AzureKeyVault.KeyVault.properties.provisioningState | String | The current provisioning state.

 | 


#### Command Example
```!azure-key-vault-create-update object_id=YOUR_OBJ_ID vault_name=xsoar-test-create-1 keys=create,decrypt```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": {
            "id": "/subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-create-1",
            "location": "westus",
            "name": "xsoar-test-create-1",
            "properties": {
                "accessPolicies": [
                    {
                        "objectId": "YOUR_OBJ_ID",
                        "permissions": {
                            "certificates": [
                                "get",
                                "list",
                                "update",
                                "create",
                                "import",
                                "delete",
                                "recover",
                                "backup",
                                "restore",
                                "managecontacts",
                                "manageissuers",
                                "getissuers",
                                "listissuers",
                                "setissuers",
                                "deleteissuers"
                            ],
                            "keys": [
                                "create",
                                "decrypt"
                            ],
                            "secrets": [
                                "get",
                                "list",
                                "set",
                                "delete",
                                "recover",
                                "backup",
                                "restore"
                            ]
                        },
                        "tenantId": "YOUR_TENANT_ID"
                    }
                ],
                "enableSoftDelete": true,
                "enabledForDeployment": true,
                "enabledForDiskEncryption": true,
                "enabledForTemplateDeployment": true,
                "provisioningState": "RegisteringDns",
                "sku": {
                    "family": "A",
                    "name": "standard"
                },
                "tenantId": "YOUR_TENANT_ID",
                "vaultUri": "https://xsoar-test-create-1.vault.azure.net"
            },
            "tags": {},
            "type": "Microsoft.KeyVault/vaults"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-create-1 Information
>|Id|Name|Type|Location|
>|---|---|---|---|
>| /subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-create-1 | xsoar-test-create-1 | Microsoft.KeyVault/vaults | westus |


### azure-key-vault-delete
***
Delete the specified key vault.


#### Base Command

`azure-key-vault-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | Key Vault name to delete. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-key-vault-delete vault_name=xsoar-test-45```

#### Human Readable Output

>Deleted Key Vault xsoar-test-45 successfully.

### azure-key-vault-get
***
Get the specified key vault.


#### Base Command

`azure-key-vault-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | Key Vault name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.KeyVault.id | String | Resource ID. | 
| AzureKeyVault.KeyVault.name | String | Key Vault name. | 
| AzureKeyVault.KeyVault.type | String | Resource type in Azure. | 
| AzureKeyVault.KeyVault.location | String | Key Vault location. | 
| AzureKeyVault.KeyVault.properties.sku.family | String | SKU family name. | 
| AzureKeyVault.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. | 
| AzureKeyVault.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates. | 
| AzureKeyVault.KeyVault.properties.enabledForDeployment | Boolean | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enabledForDiskEncryption | Boolean | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. | 
| AzureKeyVault.KeyVault.properties.enabledForTemplateDeployment | Boolean | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enableSoftDelete | Boolean | Property to specify whether the 'soft delete' functionality is enabled for this key vault. If it's not set to any value\(true or false\) when creating new key vault, it will be set to true by default. Once set to true, it cannot be reverted to false. | 
| AzureKeyVault.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets. This property is readonly. | 


#### Command Example
```!azure-key-vault-get vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": {
            "id": "/subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-vault",
            "location": "eastus",
            "name": "xsoar-test-vault",
            "properties": {
                "accessPolicies": [
                    {
                        "objectId": "YOUR_OBJ_ID",
                        "permissions": {
                            "certificates": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "ManageContacts",
                                "ManageIssuers",
                                "GetIssuers",
                                "ListIssuers",
                                "SetIssuers",
                                "DeleteIssuers"
                            ],
                            "keys": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ],
                            "secrets": [
                                "Get",
                                "List",
                                "Set",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ]
                        },
                        "tenantId": "YOUR_TENANT_ID"
                    }
                ],
                "enableRbacAuthorization": false,
                "enableSoftDelete": true,
                "enabledForDeployment": false,
                "enabledForDiskEncryption": false,
                "enabledForTemplateDeployment": false,
                "provisioningState": "Succeeded",
                "sku": {
                    "family": "A",
                    "name": "Standard"
                },
                "softDeleteRetentionInDays": 90,
                "tenantId": "YOUR_TENANT_ID",
                "vaultUri": "https://xsoar-test-vault.vault.azure.net/"
            },
            "tags": {},
            "type": "Microsoft.KeyVault/vaults"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-vault Information
>|Id|Name|Type|Location|
>|---|---|---|---|
>| /subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-vault | xsoar-test-vault | Microsoft.KeyVault/vaults | eastus |


### azure-key-vault-list
***
The List operation gets information about the vaults associated with the subscription. For a limit greater than 25, more than one API call will be required and the command might take longer time.


#### Base Command

`azure-key-vault-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit on the number of keys vaults to return. Default value is 50. | Optional | 
| offset | First index to retrieve from. Default value is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.KeyVault.id | String | Resource ID. | 
| AzureKeyVault.KeyVault.name | String | Key Vault name. | 
| AzureKeyVault.KeyVault.type | String | Resource type in Azure. | 
| AzureKeyVault.KeyVault.location | String | Key Vault location. | 
| AzureKeyVault.KeyVault.properties.sku.family | String | SKU family name. | 
| AzureKeyVault.KeyVault.properties.sku.name | String | SKU name to specify whether the key vault is a standard vault or a premium vault. | 
| AzureKeyVault.KeyVault.properties.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets. | 
| AzureKeyVault.KeyVault.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates. | 
| AzureKeyVault.KeyVault.properties.enabledForDeployment | Boolean | Property to specify whether Azure Virtual Machines are permitted to retrieve certificates stored as secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enabledForDiskEncryption | Boolean | Property to specify whether Azure Disk Encryption is permitted to retrieve secrets from the vault and unwrap keys. | 
| AzureKeyVault.KeyVault.properties.enabledForTemplateDeployment | Boolean | Property to specify whether Azure Resource Manager is permitted to retrieve secrets from the key vault. | 
| AzureKeyVault.KeyVault.properties.enableSoftDelete | Boolean | Property to specify whether the 'soft delete' functionality is enabled for this key vault. If it's not set to any value\(true or false\) when creating new key vault, it will be set to true by default. Once set to true, it cannot be reverted to false. | 
| AzureKeyVault.KeyVault.properties.vaultUri | String | The URI of the vault for performing operations on keys and secrets.  | 


#### Command Example
```!azure-key-vault-list limit=1```

#### Context Example
```json
{
    "AzureKeyVault": {
        "KeyVault": {
            "id": "/subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test",
            "location": "eastus",
            "name": "xsoar-test",
            "properties": {
                "accessPolicies": [
                    {
                        "objectId": "YOUR_OBJ_ID",
                        "permissions": {
                            "certificates": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore",
                                "ManageContacts",
                                "ManageIssuers",
                                "GetIssuers",
                                "ListIssuers",
                                "SetIssuers",
                                "DeleteIssuers"
                            ],
                            "keys": [
                                "Get",
                                "List",
                                "Update",
                                "Create",
                                "Import",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ],
                            "secrets": [
                                "Get",
                                "List",
                                "Set",
                                "Delete",
                                "Recover",
                                "Backup",
                                "Restore"
                            ]
                        },
                        "tenantId": "YOUR_TENANT_ID"
                    }
                ],
                "enableRbacAuthorization": false,
                "enableSoftDelete": true,
                "enabledForDeployment": false,
                "enabledForDiskEncryption": false,
                "enabledForTemplateDeployment": false,
                "provisioningState": "Succeeded",
                "sku": {
                    "family": "A",
                    "name": "Standard"
                },
                "softDeleteRetentionInDays": 90,
                "tenantId": "YOUR_TENANT_ID",
                "vaultUri": "https://xsoar-test.vault.azure.net/"
            },
            "tags": {},
            "type": "Microsoft.KeyVault/vaults"
        }
    }
}
```

#### Human Readable Output

>### Key Vaults List
>|Id|Name|Type|Location|
>|---|---|---|---|
>| /subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test | xsoar-test | Microsoft.KeyVault/vaults | eastus |


### azure-key-vault-access-policy-update
***
Update access policies in a key vault in the specified subscription. The update regards only the access policy for the specified object ID.


#### Base Command

`azure-key-vault-access-policy-update`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault to update it's access policy. | Required | 
| operation_kind | The name of the operation to do on the vault's access policy. <br/>Supports three operations: add,remove,replace. For example, to add "get", "list" permissions to the current secret permissions, use operation_kind="add" and secrets="get,list". Possible values are: add, remove, replace. | Required | 
| object_id | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The update regards only the access policy for the specified object ID. | Required | 
| keys | Permissions to keys. Possible values are: encrypt, decrypt, wrapKey, unwrapKey, sign, verify, get, list, create, update, import, delete, backup, restore, recover, purge. | Optional | 
| secrets | Permissions to secrets. Possible values are: get, list, set, delete, backup, restore, recover, purge. | Optional | 
| certificates | Permissions to certificates. Possible values are: get, list, delete, create, import, update, managecontacts, getissuers, listissuers, setissuers, deleteissuers, manageissuers, recover, purge. | Optional | 
| storage | Permissions to storage accounts. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.VaultAccessPolicy.id | String | Resource ID. | 
| AzureKeyVault.VaultAccessPolicy.type | String | Resource type in Azure. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.tenantId | String | The Azure Active Directory tenant ID that should be used for authenticating requests to the key vault. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.objectId | String | The object ID of a user, service principal or security group in the Azure Active Directory tenant for the vault. The object ID must be unique for the list of access policies. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.permissions.keys | Unknown | Permissions to keys. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.permissions.secrets | Unknown | Permissions to secrets. | 
| AzureKeyVault.VaultAccessPolicy.properties.accessPolicies.permissions.certificates | Unknown | Permissions to certificates. | 


#### Command Example
```!azure-key-vault-access-policy-update object_id=YOUR_OBJ_ID operation_kind=add vault_name=xsoar-test-create-1 keys=import,list```

#### Context Example
```json
{
    "AzureKeyVault": {
        "VaultAccessPolicy": {
            "id": "/subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-create-1/accessPolicies/",
            "properties": {
                "accessPolicies": [
                    {
                        "objectId": "YOUR_OBJ_ID",
                        "permissions": {
                            "certificates": [
                                "get",
                                "list",
                                "update",
                                "create",
                                "import",
                                "delete",
                                "recover",
                                "backup",
                                "restore",
                                "managecontacts",
                                "manageissuers",
                                "getissuers",
                                "listissuers",
                                "setissuers",
                                "deleteissuers"
                            ],
                            "keys": [
                                "create",
                                "decrypt",
                                "import",
                                "list"
                            ],
                            "secrets": [
                                "get",
                                "list",
                                "set",
                                "delete",
                                "recover",
                                "backup",
                                "restore"
                            ]
                        },
                        "tenantId": "YOUR_TENANT_ID"
                    }
                ]
            },
            "type": "Microsoft.KeyVault/vaults/accessPolicies"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-create-1 Updated Access Policy
>|Id|Type|
>|---|---|
>| /subscriptions/YOUR_SUB_ID/resourceGroups/test-group/providers/Microsoft.KeyVault/vaults/xsoar-test-create-1/accessPolicies/ | Microsoft.KeyVault/vaults/accessPolicies |


### azure-key-vault-key-get
***
Get the public part of a stored key.


#### Base Command

`azure-key-vault-key-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the key resides in. | Required | 
| key_name | Key name. | Required | 
| key_version | Adding the version parameter retrieves a specific version of a key. This URI fragment is optional. If not specified, the latest version of the key is returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Key.key.kid | String | Key identifier. | 
| AzureKeyVault.Key.key.kty | String | JsonWebKey Key Type. | 
| AzureKeyVault.Key.key.key_ops | Unknown | Supported key operations. | 
| AzureKeyVault.Key.key.n | String | RSA modulus. | 
| AzureKeyVault.Key.key.e | String | RSA public exponent. | 
| AzureKeyVault.Key.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.Key.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Key.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Key.attributes.recoveryLevel | Unknown | Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval. | 


#### Command Example
```!azure-key-vault-key-get key_name=test-key-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Key": {
            "attributes": {
                "created": "2021-08-11T12:03:16",
                "enabled": true,
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-08-11T12:03:16"
            },
            "key": {
                "e": "AQAB",
                "key_ops": [
                    "sign",
                    "verify",
                    "wrapKey",
                    "unwrapKey",
                    "encrypt",
                    "decrypt"
                ],
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-key-1/ecb2971b800842e2bda59cc9b8532d2b",
                "kty": "RSA",
                "n": "9JbwOZjuopMrpkGciWW5GKUUJ6HsQEFFX8tu46hZ1N5C1ii6VvCFhDKEBELaVBr_YsZOIvZbNMmhBI4PHmiiKFOqv84Cy_YXXtk5KsA2BkuoFJJJiAZh8U6txcl-32ZomaNKBIJbI8RpY__dEmGVlPvG5w9c64E6lyGTYhk0xvOmrFlsWh9YicZn5DTXTqCAi55BNvBhoC90O2bY2EWo3SOP9vPcrNkknHSLmd7HRBpvmvfCMh2nWAwOv1iXMfeDMAnW7BTAPJWIHWdP9SnqvSgbw8r_n5Rkq7EwkNeTwGDxGdr3FniB6ByfGi54DXpJt0q7gLVdJJnNww-xGRNrWQ"
            },
            "key_vault_name": "xsoar-test-vault",
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### test-key-1 Information
>|Key Id|Enabled|Json Web Key Type|Key Operations|Create Time|Update Time|
>|---|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/keys/test-key-1/ecb2971b800842e2bda59cc9b8532d2b | true | RSA | sign,<br/>verify,<br/>wrapKey,<br/>unwrapKey,<br/>encrypt,<br/>decrypt | 2021-08-11T12:03:16 | 2021-08-11T12:03:16 |


### azure-key-vault-key-list
***
List keys in the specified vault. For a limit greater than 25, more than one API call will be required and the command might take longer time.


#### Base Command

`azure-key-vault-key-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the keys reside in. | Required | 
| limit | Limit on the number of keys to return. Default value is 50. Default is 50. | Optional | 
| offset | First index to retrieve from. Default value is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Key.kid | String | Key identifier. | 
| AzureKeyVault.Key.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.Key.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Key.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Key.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval. | 
| AzureKeyVault.Key.attributes.recoverableDays | Number | Soft Delete data retention days. Value should be &gt;=7 and &lt;=90 when softDelete enabled, otherwise 0. | 


#### Command Example
```!azure-key-vault-key-list vault_name=xsoar-test-vault limit=1```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Key": {
            "attributes": {
                "created": "2021-08-11T12:05:48",
                "enabled": false,
                "exp": "2022-08-11T12:05:48",
                "nbf": "2021-08-11T11:55:48",
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-09-05T14:02:13"
            },
            "key_vault_name": "xsoar-test-vault",
            "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-1",
            "managed": true,
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-vault Keys List
>|Key Id|Enabled|Create Time|Update Time|Expiry Time|
>|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/keys/test-cer-1 | false | 2021-08-11T12:05:48 | 2021-09-05T14:02:13 | 2022-08-11T12:05:48 |


### azure-key-vault-key-delete
***
Delete a key of any type from storage in Azure Key vault.


#### Base Command

`azure-key-vault-key-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the key resides in. | Required | 
| key_name | Key name to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Key.recoveryId | String | The url of the recovery object, used to identify and recover the deleted key. | 
| AzureKeyVault.Key.deletedDate | Date | The time when the key was deleted, in UTC. | 
| AzureKeyVault.Key.key.kid | String | Key identifier. | 
| AzureKeyVault.Key.key.kty | String | JsonWebKey Key Type. | 
| AzureKeyVault.Key.key.key_ops | Unknown | Supported key operations. | 
| AzureKeyVault.Key.key.n | String | RSA modulus. | 
| AzureKeyVault.Key.key.e | String | RSA public exponent. | 
| AzureKeyVault.Key.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.Key.attributes.created | Number | Creation time in UTC. | 
| AzureKeyVault.Key.attributes.updated | Number | Last updated time in UTC. | 
| AzureKeyVault.Key.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for keys in the current vault. If it contains 'Purgeable' the key can be permanently deleted by a privileged user; otherwise, only the system can purge the key, at the end of the retention interval. | 


#### Command Example
```!azure-key-vault-key-delete key_name=test-key-10 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Key": {
            "attributes": {
                "created": "2021-08-18T07:07:18",
                "enabled": true,
                "exp": "2023-08-18T07:07:03",
                "nbf": "2021-08-18T07:07:03",
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-08-18T07:07:18"
            },
            "deletedDate": "2021-09-13T13:56:36",
            "key": {
                "e": "AQAB",
                "key_ops": [
                    "sign",
                    "verify",
                    "wrapKey",
                    "unwrapKey",
                    "encrypt",
                    "decrypt"
                ],
                "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-key-10/7e4cf9dad69c46e3bbfdb2c925623c9c",
                "kty": "RSA",
                "n": "p4E3D3FMdzrUlLuZs--6RPuInsTtWEYLtNOmRDaPlNvPUwfkpNfDwW_YbnNAl6HJTkExncyMzmn3rCk3wyhVggjVItJ9BkTPMzZE0FT5ocmldhFgthH6Ni9EDQkbWkP3hR7VPNu-3MBPQvhVaahRXDPNeCBVpJ6OOKGd3W7LOI_l-TE0I1mJ87iAmvEqr2pMzsslxvQt1r1c5xggsBy_ouI9ZwSPZ33tDavtlL_GwoQzLaefSMpKgiMvA9Tp_Al6rc2tF-Tj908GQ7puhTq50tL81Jl0hH1rMpmBxzRjENSBIzcvvXaDFEyksUZnGy8F-ho0sScxxrfhEi2eJ4c7tx1cNDyaKryviSPhtCnFqfb7VhX_T10cxeTbJwqHZN3IhFtjMrupjawmx9mpfoB0d_Kx06BmGIpp-Uvwh_fodDeNA4K4pmRNqpfbmzh2UPk4c3xZo2Ek31Nz5bnfgV9Wrr5CD93sj8FIZOcMUUJAEZ7nkxgQcQqfY-8SVu0m7_RR"
            },
            "key_vault_name": "xsoar-test-vault",
            "recoveryId": "https://xsoar-test-vault.vault.azure.net/deletedkeys/test-key-10",
            "scheduledPurgeDate": "2021-12-12T13:56:36",
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### Delete test-key-10
>|Key Id|Recovery Id|Deleted Date|Scheduled Purge Date|
>|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/keys/test-key-10/7e4cf9dad69c46e3bbfdb2c925623c9c | https://xsoar-test-vault.vault.azure.net/deletedkeys/test-key-10 | 2021-09-13T13:56:36 | 2021-12-12T13:56:36 |


### azure-key-vault-secret-get
***
Get a specified secret from a given key vault. The GET operation is applicable to any secret stored in Azure Key Vault. This operation requires the secrets/get permission.


#### Base Command

`azure-key-vault-secret-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the secret resides in. | Required | 
| secret_name | Secret name. | Required | 
| secret_version | Secret version.If not specified, the latest version of the secret is returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Secret.value | String | Secret value. | 
| AzureKeyVault.Secret.id | String | Secret ID. | 
| AzureKeyVault.Secret.attributes.enabled | Bolean | Determines whether the object is enabled. | 
| AzureKeyVault.Secret.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Secret.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Secret.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for secrets in the current vault. If it contains 'Purgeable', the secret can be permanently deleted by a privileged user; otherwise, only the system can purge the secret, at the end of the retention interval. | 


#### Command Example
```!azure-key-vault-secret-get secret_name=test-sec-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Secret": {
            "attributes": {
                "created": "2021-08-11T12:04:12",
                "enabled": true,
                "exp": "2023-08-11T12:04:06",
                "nbf": "2021-08-11T12:04:06",
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-08-17T16:22:57"
            },
            "contentType": "text",
            "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-sec-1/88b8c4e1dc3a4443b5847de9edb1b4a4",
            "key_vault_name": "xsoar-test-vault",
            "tags": {},
            "value": "test"
        }
    }
}
```

#### Human Readable Output

>### test-sec-1 Information
>|Secret Id|Enabled|Create Time|Update Time|Expiry Time|
>|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/secrets/test-sec-1/88b8c4e1dc3a4443b5847de9edb1b4a4 | true | 2021-08-11T12:04:12 | 2021-08-17T16:22:57 | 2023-08-11T12:04:06 |


### azure-key-vault-secret-list
***
List secrets in a specified key vault. For a limit greater than 25, more than one API call will be required and the command might take longer time.


#### Base Command

`azure-key-vault-secret-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the secrets reside in. | Required | 
| limit | Limit on the number of secrets to return. Default value is 50. | Optional | 
| offset | First index to retrieve from. Default value is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Secret.id | String | Secret ID. | 
| AzureKeyVault.Secret.attributes.enabled | Bolean | Determines whether the object is enabled. | 
| AzureKeyVault.Secret.attributes.nbf | Date | Not before date in UTC. | 
| AzureKeyVault.Secret.attributes.exp | Date | Expiry date in UTC. | 
| AzureKeyVault.Secret.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Secret.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Secret.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for secrets in the current vault. If it contains 'Purgeable', the secret can be permanently deleted by a privileged user; otherwise, only the system can purge the secret, at the end of the retention interval. | 
| AzureKeyVault.Secret.attributes.recoverableDays | Number | Soft Delete data retention days. Value should be &gt;=7 and &lt;=90 when softDelete enabled, otherwise 0. | 


#### Command Example
```!azure-key-vault-secret-list vault_name=xsoar-test-vault limit=1```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Secret": {
            "attributes": {
                "created": "2021-08-11T12:05:48",
                "enabled": false,
                "exp": "2022-08-11T12:05:48",
                "nbf": "2021-08-11T11:55:48",
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-09-05T14:02:13"
            },
            "contentType": "application/x-pkcs12",
            "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-1",
            "key_vault_name": "xsoar-test-vault",
            "managed": true,
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-vault Secrets List
>|Secret Id|Enabled|Create Time|Update Time|Expiry Time|
>|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/secrets/test-cer-1 | false | 2021-08-11T12:05:48 | 2021-09-05T14:02:13 | 2022-08-11T12:05:48 |


### azure-key-vault-secret-delete
***
Delete a secret from a specified key vault.


#### Base Command

`azure-key-vault-secret-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the secret resides in. | Required | 
| secret_name | Secret name to delete. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Secret.recoveryId | String | The URL of the recovery object, used to identify and recover the deleted secret. | 
| AzureKeyVault.Secret.deletedDate | Date | The time when the secret was deleted, in UTC. | 
| AzureKeyVault.Secret.scheduledPurgeDate | Date | The time when the secret is scheduled to be purged, in UTC. | 
| AzureKeyVault.Secret.id | String | Deleted secret ID. | 
| AzureKeyVault.Secret.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.Secret.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Secret.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Secret.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for secrets in the current vault. | 


#### Command Example
```!azure-key-vault-secret-delete secret_name=test-sec-10 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Secret": {
            "attributes": {
                "created": "2021-08-18T07:08:10",
                "enabled": true,
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-08-18T07:08:10"
            },
            "contentType": "aa",
            "deletedDate": "2021-09-13T13:56:43",
            "id": "https://xsoar-test-vault.vault.azure.net/secrets/test-sec-10/d73ad5b9a23a482991fada28c699b2f1",
            "key_vault_name": "xsoar-test-vault",
            "recoveryId": "https://xsoar-test-vault.vault.azure.net/deletedsecrets/test-sec-10",
            "scheduledPurgeDate": "2021-12-12T13:56:43",
            "tags": {}
        }
    }
}
```

#### Human Readable Output

>### Delete test-sec-10
>|Secret Id|Recovery Id|Deleted Date|Scheduled Purge Date|
>|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/secrets/test-sec-10/d73ad5b9a23a482991fada28c699b2f1 | https://xsoar-test-vault.vault.azure.net/deletedsecrets/test-sec-10 | 2021-09-13T13:56:43 | 2021-12-12T13:56:43 |


### azure-key-vault-certificate-get
***
Get information about a certificate.
Gets information about a specific certificate. This operation requires the certificates/get permission.


#### Base Command

`azure-key-vault-certificate-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the certificate resides in. | Required | 
| certificate_name | Certificate name. | Required | 
| certificate_version | The version of the certificate. If not specified, the latest version of the certificate is returned. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Certificate.id | String | Certificate ID. | 
| AzureKeyVault.Certificate.kid | String | Key ID. | 
| AzureKeyVault.Certificate.sid | String | Secret ID. | 
| AzureKeyVault.Certificate.x5t | String | Thumbprint of the certificate. | 
| AzureKeyVault.Certificate.cer | String | CER contents of x509 certificate. | 
| AzureKeyVault.Certificate.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.Certificate.attributes.exp | Date | Expiry date in UTC. | 
| AzureKeyVault.Certificate.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Certificate.attributes.updated | Date | Last updated time in UTC. | 
| AzureKeyVault.Certificate.attributes.recoveryLevel | String | Reflects the deletion recovery level currently in effect for certificates in the current vault. If it contains 'Purgeable', the certificate can be permanently deleted by a privileged user; otherwise, only the system can purge the certificate, at the end of the retention interval. | 
| AzureKeyVault.Certificate.policy | Unknown | The management policy. | 


#### Command Example
```!azure-key-vault-certificate-get certificate_name=test-cer-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Certificate": {
            "attributes": {
                "created": "2021-08-11T12:05:48",
                "enabled": false,
                "exp": "2022-08-11T12:05:48",
                "nbf": "2021-08-11T11:55:48",
                "recoverableDays": 90,
                "recoveryLevel": "Recoverable+Purgeable",
                "updated": "2021-09-05T14:02:13"
            },
            "cer": "MIIDJDCCAgygAwIBAgIQdH4YmvSvSYSuIwZ9BVSvzDANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDEwR0ZXN0MB4XDTIxMDgxMTExNTU0OFoXDTIyMDgxMTEyMDU0OFowDzENMAsGA1UEAxMEdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANQ1pdBcYbXYR6NsiX2IAL1fYpgf5RVkJ0cIEx/K77Uvv9srt5tqpdqAtygL7RTiXCGsIfTuyFbsHcQeihekKUMwoAgjkbF6Qw7y+q3h00Q5OLe8+gK+S0F7+DIrE97Yde7ETa1dUmvdOWe4ioaVkToS8h5r+DrJsK1v5rE6kkfJm2HEAQDyN5KBqD75IDn099O1739ZjL31rlVJu0wmoz2N545rZxZIN0a/L8NwNk/3jgUPjRSQiiOKHUpIkkE2d20SFo4fnS2YmExtElr6f6gOD4wreebIPeAnKGsw7gukbRsmBhqVCZs35Q0F15UrehdRCXU2Wk06gGdQVzsIszkCAwEAAaN8MHowDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFLJxh/k981tky3s7whrYPNCUzRs1MB0GA1UdDgQWBBSycYf5PfNbZMt7O8Ia2DzQlM0bNTANBgkqhkiG9w0BAQsFAAOCAQEAjbgJhP4PPp1HopnHi6Vgk+jTzd/LAMm4Im+6XkjlGIOHmmUstvHyBrFju4oyzkzp0ULnRZZLnsnxWxNnJYn23+RxklJhmc3fiy43dBdlTI1I3EzoFV31Or1khzelE8EjicyLJuFCNKWKS9947A7d8g7CbuRVFc9/rYB19uAaxv3xfA8GiIvlrnBVGMs10Baew2yLNooGNDLEiK1I85ygLeT6yVE0yDuocFFLvNiUxgntmI8cD6av9P3QE9U44UwPBmrldw3GFBgIZv0C6j1wN6EwqDUpTdyYO/D+Em9mmVXabcIz1uzFyFfqF6TDmTBTuGyf7PcIsLSxuX6922anHA==",
            "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/0102ad8275574b9c8e25b5a6608d5504",
            "key_vault_name": "xsoar-test-vault",
            "kid": "https://xsoar-test-vault.vault.azure.net/keys/test-cer-1/0102ad8275574b9c8e25b5a6608d5504",
            "pending": {
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/pending"
            },
            "policy": {
                "attributes": {
                    "created": "2021-08-11T12:05:31",
                    "enabled": true,
                    "updated": "2021-08-11T12:05:31"
                },
                "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/policy",
                "issuer": {
                    "name": "Self"
                },
                "key_props": {
                    "exportable": true,
                    "key_size": 2048,
                    "kty": "RSA",
                    "reuse_key": false
                },
                "lifetime_actions": [
                    {
                        "action": {
                            "action_type": "AutoRenew"
                        },
                        "trigger": {
                            "lifetime_percentage": 80
                        }
                    }
                ],
                "secret_props": {
                    "contentType": "application/x-pkcs12"
                },
                "x509_props": {
                    "basic_constraints": {
                        "ca": false
                    },
                    "ekus": [
                        "1.3.6.1.5.5.7.3.1",
                        "1.3.6.1.5.5.7.3.2"
                    ],
                    "key_usage": [
                        "digitalSignature",
                        "keyEncipherment"
                    ],
                    "sans": {
                        "dns_names": []
                    },
                    "subject": "CN=test",
                    "validity_months": 12
                }
            },
            "sid": "https://xsoar-test-vault.vault.azure.net/secrets/test-cer-1/0102ad8275574b9c8e25b5a6608d5504",
            "tags": {},
            "x5t": "g3E8NEflcwlsQmT-JDgO7IWuH4w"
        }
    }
}
```

#### Human Readable Output

>### test-cer-1 Information
>|Certificate Id|Enabled|Create Time|Update Time|Expiry Time|
>|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/0102ad8275574b9c8e25b5a6608d5504 | false | 2021-08-11T12:05:48 | 2021-09-05T14:02:13 | 2022-08-11T12:05:48 |


### azure-key-vault-certificate-list
***
List certificates in a specified key vault. For a limit greater than 25, more than one API call will be required and the command might take longer time.


#### Base Command

`azure-key-vault-certificate-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the certificate reside in. | Required | 
| limit | Limit on the number of certificates to return. Default value is 50. | Optional | 
| offset | First index to retrieve from. Default value is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.Certificate.id | String | Certificate ID. | 
| AzureKeyVault.Certificate.x5t | String | Thumbprint of the certificate. | 
| AzureKeyVault.Certificate.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.Certificate.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.Certificate.attributes.updated | Date | Last updated time in UTC. | 


#### Command Example
```!azure-key-vault-certificate-list vault_name=xsoar-test-vault limit=1```

#### Context Example
```json
{
    "AzureKeyVault": {
        "Certificate": {
            "attributes": {
                "created": "2021-08-11T12:05:48",
                "enabled": false,
                "exp": "2022-08-11T12:05:48",
                "nbf": "2021-08-11T11:55:48",
                "updated": "2021-09-05T14:02:13"
            },
            "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1",
            "key_vault_name": "xsoar-test-vault",
            "subject": "",
            "tags": {},
            "x5t": "g3E8NEflcwlsQmT-JDgO7IWuH4w"
        }
    }
}
```

#### Human Readable Output

>### xsoar-test-vault Certificates List
>|Certificate Id|Enabled|Create Time|Update Time|Expiry Time|
>|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1 | false | 2021-08-11T12:05:48 | 2021-09-05T14:02:13 | 2022-08-11T12:05:48 |


### azure-key-vault-certificate-policy-get
***
Get the policy of the specified certificate.


#### Base Command

`azure-key-vault-certificate-policy-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| vault_name | The name of the Key Vault where the secret resides in. | Required | 
| certificate_name | The name of the certificate to retrieve the policy from. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureKeyVault.CertificatePolicy.id | String | Policy ID. | 
| AzureKeyVault.CertificatePolicy.key_props | Unknown | Properties of the key backing a certificate. | 
| AzureKeyVault.CertificatePolicy.x509_props | Unknown | Properties of the X509 component of a certificate. | 
| AzureKeyVault.CertificatePolicy.lifetime_actions | Unknown | Actions that will be performed by Key Vault over the lifetime of a certificate. | 
| AzureKeyVault.CertificatePolicy.issuer | Unknown | Parameters for the issuer of the X509 component of a certificate. | 
| AzureKeyVault.CertificatePolicy.attributes.enabled | Boolean | Determines whether the object is enabled. | 
| AzureKeyVault.CertificatePolicy.attributes.created | Date | Creation time in UTC. | 
| AzureKeyVault.CertificatePolicy.attributes.updated | Date | Last updated time in UTC. | 


#### Command Example
```!azure-key-vault-certificate-policy-get certificate_name=test-cer-1 vault_name=xsoar-test-vault```

#### Context Example
```json
{
    "AzureKeyVault": {
        "CertificatePolicy": {
            "CertificateName": "test-cer-1",
            "attributes": {
                "created": "2021-08-11T12:05:31",
                "enabled": true,
                "updated": "2021-08-11T12:05:31"
            },
            "id": "https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/policy",
            "issuer": {
                "name": "Self"
            },
            "key_props": {
                "exportable": true,
                "key_size": 2048,
                "kty": "RSA",
                "reuse_key": false
            },
            "lifetime_actions": [
                {
                    "action": {
                        "action_type": "AutoRenew"
                    },
                    "trigger": {
                        "lifetime_percentage": 80
                    }
                }
            ],
            "secret_props": {
                "contentType": "application/x-pkcs12"
            },
            "x509_props": {
                "basic_constraints": {
                    "ca": false
                },
                "ekus": [
                    "1.3.6.1.5.5.7.3.1",
                    "1.3.6.1.5.5.7.3.2"
                ],
                "key_usage": [
                    "digitalSignature",
                    "keyEncipherment"
                ],
                "sans": {
                    "dns_names": []
                },
                "subject": "CN=test",
                "validity_months": 12
            }
        }
    }
}
```

#### Human Readable Output

>### test-cer-1 Policy Information
>|Id|Key Props|Secret Props|X509 Props|Issuer|Attributes|
>|---|---|---|---|---|---|
>| https://xsoar-test-vault.vault.azure.net/certificates/test-cer-1/policy | exportable: true<br/>kty: RSA<br/>key_size: 2048<br/>reuse_key: false | contentType: application/x-pkcs12 | subject: CN=test<br/>sans: {"dns_names": []}<br/>ekus: 1.3.6.1.5.5.7.3.1,<br/>1.3.6.1.5.5.7.3.2<br/>key_usage: digitalSignature,<br/>keyEncipherment<br/>validity_months: 12<br/>basic_constraints: {"ca": false} | name: Self | enabled: true<br/>created: 2021-08-11T12:05:31<br/>updated: 2021-08-11T12:05:31 |

