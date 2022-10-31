Manage Secrets and Protect Confidential Data using Fortanix Data Security Manager
## Configure Fortanix DSM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Fortanix DSM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Fortanix DSM server endpoint (e.g., https://amer.smartkey.io) |  | True |
    | Username / App UUID / Certificate |  | False |
    | Password / App Secret / Private Key |  | False |
    | API Key |  | False |
    | Trust any server certificate (insecure) |  | False |
    | Use system proxy settings |  | False |
    | Group UUID to list secrets from (optional) |  | False |
    | Data protection key used for encryption and decryption | Also configure the Mode | False |
    | Encryption and decryption mode |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortanix-test
***
Test the Fortanix DSM integration server connection


#### Base Command

`fortanix-test`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.DSM.version | unknown | Server version | 
| Fortanix.DSM.api_version | unknown | API  version | 
| Fortanix.DSM.mode | unknown | Server mode | 

### fortanix-list-secrets
***
List secrets from one or more specified group(s)


#### Base Command

`fortanix-list-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group UUID to list secrets from (optional, overrides integration settings). | Optional | 
| state | Current state of the secret (optional, default show all except deleted or destroyed). Possible values are: enabled, disabled, preactive, active, deactivated, compromised, deleted, destroyed. | Optional | 
| page | Page offset to return (optional, 100 results at a time). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Secret.Name | string | Secret Name | 
| Fortanix.Secret.ID | string | Secret ID \(Key ID or kid\) | 
| Fortanix.Secret.Group | unknown | Group ID | 

### fortanix-get-secret-metadata
***
Get the secret metadata without exposing its value


#### Base Command

`fortanix-get-secret-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the secret (mandatory, unless kid is specified). | Optional | 
| kid | Secret UUID (optional, unless name is unspecified). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Secret | unknown | Secret metadata, if successful | 

### fortanix-fetch-secret
***
Retrieve the secret value


#### Base Command

`fortanix-fetch-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kid | Secret UUID (mandatory). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Secret.Value | unknown | Sensitive value of the secret | 

### fortanix-new-secret
***
Import a new secret


#### Base Command

`fortanix-new-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the secret (mandatory). | Optional | 
| value | Sensitive value of the secret (mandatory). | Required | 
| group_id | Group UUID to import the secret into (optional). | Optional | 
| metadata | List of key-value pairs (optional). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Secret | unknown | Secret metadata, if successful | 

### fortanix-rotate-secret
***
Update an existing secret, which will be rotated


#### Base Command

`fortanix-rotate-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Name of the secret (mandatory). | Required | 
| value | Sensitive value of the secret (mandatory). | Required | 
| metadata | List of key-value pairs (optional). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Secret | unknown | Secret metadata, if successful | 

### fortanix-delete-secret
***
Delete the secret


#### Base Command

`fortanix-delete-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| kid | Secret UUID (mandatory). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Secret.Result | unknown | Deletion status | 

### fortanix-invoke-plugin
***
Invoke a Fortanix Plugin that is executed in a Confidential Computing enclave


#### Base Command

`fortanix-invoke-plugin`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| pid | Plugin UUID (mandatory). | Required | 
| input | Arbitrary user input based on the plugin (optional). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Plugin.Output | unknown | Plugin invocation output | 

### fortanix-encrypt
***
Protects data using key configured in Fortanix DSM


#### Base Command

`fortanix-encrypt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| data | User data (mandatory). | Required | 
| key | Key name used for protection (optional, overrides configured). | Optional | 
| mode | Encryption mode (optional, overrides configured)). Possible values are: FPE, GCM, CBC. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Data.Cipher | unknown | Encryption output | 

### fortanix-decrypt
***
Reveal data using key configured in Fortanix DSM


#### Base Command

`fortanix-decrypt`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cipher | Protected ciphertext (mandatory). | Required | 
| kid | Key UUID for decryption (optional, overrides configured). | Optional | 
| mode | Decryption mode (optional, overrides configured)). Possible values are: FPE, GCM, CBC. | Optional | 
| iv | Nonce or initialization vector (if any). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Data.Plain | unknown | Decryption output | 
