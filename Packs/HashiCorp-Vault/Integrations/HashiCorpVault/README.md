Manage Secrets and Protect Sensitive Data through HashiCorp Vault
This integration was integrated and tested with version xx of HashiCorp Vault

## Configure HashiCorp Vault on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for HashiCorp Vault.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description**                                                                                                                  | **Required** |
    |----------------------------------------------------------------------------------------------------------------------------------| --- | --- |
    | HashiCorp server URL (e.g., https://192.168.0.1:8200) | The server URL                                                                                                                   | True |
    | Use AppRole Auth Method | Set as true if you are using the approl for authentication, [more info](https://developer.hashicorp.com/vault/docs/auth/approle) | False |
    | Username / Role ID | The username for the Hashicorp Vault                                                                                             | False |
    | Password / Secret ID | The password for the Hashicorp Vault                                                                                             | False |
    | Authentication token | A token for authentication for  Hashicorp Vault(use instead of password and username)                                            | False |
    | Vault enterprise namespace | The namespace used for the vault by the user [more info](https://developer.hashicorp.com/vault/tutorials/enterprise/namespaces)  | False |
    | Trust any certificate (not secure) | Mark as true to make unverified http requests                                                                                    | False |
    | Use system proxy settings | Mark as true to use proxy                                                                                                        | False |
    | Fetches credentials | Mark as true to fetch credentials to the XSOAR credentials vault                                                                 | False |
    | CSV list of secrets engine types to fetch secrets from | Possible values are KV, Cubbyhole, AWS                                                                                           | False |
    | Concat username to credential object name | Should be used in case there are several secrets under the same folder in order to make the credential object unique.            | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hashicorp-list-secrets-engines
***
List all secrets engines that exist in HashiCorp Vault


#### Base Command

`hashicorp-list-secrets-engines`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Engine.Type | string | Secrets engine type | 
| HashiCorp.Engine.Path | string | Secrets engine path in HashiCorp | 
| HashiCorp.Engine.Description | string | Secrets engine description | 
| HashiCorp.Engine.Accessor | string | Secrets engine accessor | 

### hashicorp-list-secrets
***
List secrets (names) for a specified KV engine


#### Base Command

`hashicorp-list-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine | Engine path, e.g.,"secret/". Use the list-secrets-engines command to retrieve the engine path. command. | Required | 
| version | The version of the KV engine. Possible values are: 1, 2. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Secret.Path | string | Secret path | 

### hashicorp-get-secret-metadata
***
Returns information about a specified secret in a specified KV V2 engine 


#### Base Command

`hashicorp-get-secret-metadata`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine_path | KV Engine path, e.g., "kv/". | Required | 
| secret_path | Secret path, e.g., "secret". | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Secret.Created | date | Secret created time | 
| HashiCorp.Secret.Version.Destroyed | boolean | Is the version destroyed | 
| HashiCorp.Secret.Version.Created | number | Version creation time | 
| HashiCorp.Secret.Version.Deleted | date | Version deletion time | 
| HashiCorp.Secret.Updated | date | Secret last updated time | 
| HashiCorp.Secret.Engine | string | Secret engine type | 
| HashiCorp.Secret.CurrentVersion | number | Secret current version | 
| HashiCorp.Secret.Path | string | Secret path | 

### hashicorp-delete-secret
***
Deletes the data under a specified secret given the secret path. Performs a soft delete that allows you to run the hashicorp-undelete-secret command if necessary (for KV V2 engine)


#### Base Command

`hashicorp-delete-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_path | Secret path, e.g., "secret". | Required | 
| engine_path | Engine path, e.g.,"secret/". | Required | 
| versions | CSV list of secret versions to delete. | Required | 


#### Context Output

There is no context output for this command.
### hashicorp-undelete-secret
***
Undeletes (restores) a secret on HashiCorp (for KV V2 engine)


#### Base Command

`hashicorp-undelete-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_path | Secret path, e.g., "secret". | Required | 
| engine_path | Engine path, e.g.,"secret/". | Required | 
| versions | CSV list of secret versions to undelete (restore). | Required | 


#### Context Output

There is no context output for this command.
### hashicorp-destroy-secret
***
Permanently deletes a secret (for KV V2 engine)


#### Base Command

`hashicorp-destroy-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_path | Secret path, .e.g., "secret". | Required | 
| engine_path | Engine path, e.g.,"secret/". | Required | 
| versions | CSV list of secret versions to permanently delete. | Required | 


#### Context Output

There is no context output for this command.
### hashicorp-disable-engine
***
When a secrets engine is no longer needed, it can be disabled. All secrets under the engine are revoked and the corresponding vault data and configurations are removed.


#### Base Command

`hashicorp-disable-engine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | Path of the secrets engine to disable. | Required | 


#### Context Output

There is no context output for this command.
### hashicorp-enable-engine
***
Enables a new secrets engine at the specified path


#### Base Command

`hashicorp-enable-engine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path where the secrets engine will be mounted. | Required | 
| type | Type of backend, e.g., "aws". | Required | 
| description | Human-friendly description of the mount. | Optional | 
| default_lease_ttl | The default lease duration, specified as a string duration, e.g., "5s" or "30m". | Optional | 
| max_lease_ttl | The maximum lease duration, specified as a string duration, e.g., "5s" or "30m". | Optional | 
| force_no_cache | Disable caching. | Optional | 
| audit_non_hmac_request_keys | CSV list of keys that will not be HMAC'd by audit devices in the request data object. | Optional | 
| audit_non_hmac_response_keys | CSV list of keys that will not be HMAC'd by audit devices in the response data object. | Optional | 
| listing_visibility | Whether to show this mount in the UI-specific listing endpoint; "unauth" or "hidden", default is "hidden" Default is hidden. Possible values are: unauth, hidden. | Optional | 
| passthrough_request_headers | CSV list of headers to add to allow list and pass from the request to the backend. | Optional | 
| kv_version | KV version to mount. Set to "2" for mount KV V2. Possible values are: 1, 2. | Optional | 
| local | Specifies if the secrets engine is a local mount only. Local mounts are not replicated, nor (if a secondary) removed by replication. Supported only in Vault Enterprise. | Optional | 
| seal_wrap | Enable seal wrapping for the mount. Supported only in Vault Enterprise. | Optional | 


#### Context Output

There is no context output for this command.
### hashicorp-list-policies
***
Lists all configured policies


#### Base Command

`hashicorp-list-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Policy.Name | string | Policy name | 

### hashicorp-get-policy
***
Get information for a policy


#### Base Command

`hashicorp-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Policy.Name | string | Policy name | 
| HashiCorp.Policy.Rule.Path  | string | Policy rule path | 
| HashiCorp.Policy.Rule.Capabilities | unknown | Policy rule capabilities | 

### hashicorp-seal-vault
***
If you suspect your data has been compromised, you can seal your vault to prevent access to your secrets


#### Base Command

`hashicorp-seal-vault`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### hashicorp-unseal-vault
***
Use a single master key share to unseal the vault. If the master key shares threshold is met, vault will attempt to unseal the vault. Otherwise, this API must be called until the threshold is met.


#### Base Command

`hashicorp-unseal-vault`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Single master key . | Optional | 
| reset | Reset the unseal project. Possible values are: true. | Optional | 


#### Context Output

There is no context output for this command.
### hashicorp-configure-engine
***
Configure a secrets engine to fetch secrets from


#### Base Command

`hashicorp-configure-engine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The engine path, e.g., "secret/". | Required | 
| folder | Specific folder to fetch secrets from, e.g., "secret-folder/". (Supported only for engine type KV2). | Optional | 
| ttl | The time until we delete the generated user in AWS(seconds, max value=43200,only available for AWS engine). (Supported only for engine type AWS in assume role or federation token). | Optional | 
| type | The engine type, e.g., "KV". Possible values are: KV, Cubbyhole, AWS. | Required | 
| version | The engine version (for KV engines); "1" or "2". Possible values are: 1, 2. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!hashicorp-configure-engine type=type version=2 path=path ttl=3600```
#### Human Readable Output

>Engine configured successfully

### hashicorp-reset-configuration
***
Reset the engines configuration


#### Base Command

`hashicorp-reset-configuration`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
#### Command example
```!hashicorp-reset-configuration```
#### Human Readable Output

>Successfully reset the engines configuration

### hashicorp-create-token
***
Creates a new authentication token


#### Base Command

`hashicorp-create-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The name of the token role. | Optional | 
| policies | CSV list of policies for the token. This must be a subset of the policies belonging to the token making the request, unless root. If policies are not specified, all policies of the calling token are applied to the new token. | Optional | 
| meta | A map of string-to-string valued metadata. This is passed through to the audit devices. | Optional | 
| no_parent | If true and set by a root caller, the token will not have the parent token of the caller. This creates a token with no parent. Possible values are: true, false. | Optional | 
| no_default_policy | If true the default policy will not be included in this token's policy set; "true" or "false". Possible values are: true, false. | Optional | 
| renewable | If set to false, the token cannot be renewed past its initial TTL. If set to true, the token can be renewed up to the system/mount maximum TTL. "true" or "false". Possible values are: true, false. | Optional | 
| ttl | The TTL(lease duration) period of the token, provided as "10m" or "1h", where hour is the largest suffix. If not provided, the token is valid for the default lease TTL, or indefinitely if the root policy is used. | Optional | 
| explicit_max_ttl |  If set, the token will have an explicit max TTL applied to it. The maximum token TTL cannot be changed later, and unlike with normal tokens, updates to the system/mount max TTL value will have no effect at renewal time. The token can never be renewed or used past the value set at issue time. | Optional | 
| display_name | The display name of the token. | Optional | 
| num_uses | The maximum number of times the token can be used. Supply this argument to create a one-time-token, or limited use token. The value of 0 has no limit to the number of uses. | Optional | 
| period | If specified, the token will be periodic; it will not have a maximum TTL (unless an "explicit-max-ttl" is also set), but every renewal will use the given period. Requires a root/sudo token to use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Auth.Token | string | Authentication token | 
| HashiCorp.Auth.Policy | unknown | Authentication policies | 
| HashiCorp.Auth.LeaseDuration | number | Authentication lease duration in seconds, 0 if indefinitely  | 
