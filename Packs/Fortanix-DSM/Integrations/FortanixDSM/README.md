Manage Secrets and Protect Confidential Data using Fortanix Data Security Manager (DSM)

## Authorize Cortext XSOAR to Fortanix DSM
#### User/password or Client Certificate Auth Method
These fields accept  the *Username*  and *Password* parameters for a user or App. These credentials may also be used for mutual-TLS using a client key and certificate. The may be signed by a Trusted CA if Fortanix DSM is configured accordingly.
#### API KEY Auth Method
An easy and quick way to test the integration is to specify the *Basic Authentication token* parameter from the Fortanix DSM App's API KEY.


## Configure Fortanix DSM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fortanix DSM server endpoint | URL e.g., https://amer.smartkey.io | True |
| Username / App UUID / Certificate | If Certificate, specify PEM | False |
| Password / App Secret / Private Key | Private key cannot be encrypted | False |
| API Key | Alternative to Username and Password | False |
| Trust any server certificate (insecure) | Ignores TLS, not recommended | False |
| Use system proxy settings | Whether to use proxy settings from the Environment  | False |
| Group UUID to list secrets from | Filter the secrets accessible to a single DSM Group | False |
| Data protection key used for encryption and decryption | Also configure the Cipher Mode | False |
| Encryption and decryption mode | e.g. FPE, GCM, CBC | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### fortanix-list-secrets
***
List secrets from one or more specified group(s)


#### Base Command

`fortanix-list-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | Group UUID to list secrets from (overrides integration settings). | Optional | 
| state | Current state of the secret (default show all except deleted or destroyed). Possible values are: enabled, disabled, preactive, active, deactivated, compromised, deleted, destroyed. | Optional | 
| page | Page offset to return (100 results at a time). | Optional | 


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
| kid | Secret UUID (unless name is unspecified). | Optional | 


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
| kid | Secret UUID (obtained from the list-secrets command). | Required | 


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
| name | Name of the secret. | Required | 
| value | Sensitive value of the secret. | Required | 
| group_id | Group UUID to import the secret into. | Optional | 
| metadata | List of key-value pairs. | Optional | 


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
| name | Name of the secret. | Required | 
| value | Sensitive value of the secret. | Required | 
| metadata | List of key-value pairs. | Optional | 


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
| kid | Secret UUID. | Required | 


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
| pid | Plugin UUID. | Required | 
| input | Arbitrary user input based on the plugin. | Optional | 


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
| data | User data. | Required | 
| key | Key name used for protection (overrides configured). | Optional | 
| mode | Encryption mode (overrides configured). Possible values are: FPE, GCM, CBC. | Optional | 


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
| cipher | Protected ciphertext. | Required | 
| kid | Key UUID for decryption (overrides configured). | Optional | 
| mode | Decryption mode (overrides configured). Possible values are: FPE, GCM, CBC. | Optional | 
| iv | Nonce or initialization vector (if any). | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Fortanix.Data.Plain | unknown | Decryption output | 
