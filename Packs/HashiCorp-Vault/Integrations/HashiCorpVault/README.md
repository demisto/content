Secure, store, and tightly control access to tokens, passwords, certificates, and encryption keys for protecting secrets and other sensitive data using HashiCorp Vault. This integration fetches credentials. For more information, see [Managing Credentials](https://xsoar.pan.dev/docs/reference/articles/managing-credentials).

This integration was integrated and tested with version 1.12.2 of HashiCorp Vault.

## Authentication
The integration supports the following auth methods:
### Userpass Auth Method
You are required to fill in only the *Username / Role ID* parameter with the username and *Password / Secret ID* parameter with the password. For more details, see the [HashiCorp Vault documentation](https://www.vaultproject.io/docs/auth/userpass).
### Token Auth Method
You are required to fill in only the *Authentication token* parameter. For more details, see the [HashiCorp Vault documentation](https://www.vaultproject.io/docs/auth/token).
### AppRole Auth Method
You are required to fill in only the *Username / Role ID* parameter with the role ID and *Password / Secret ID* parameter with the secret ID, and check the *Use AppRole Auth Method* checkbox. For more details, see the [HashiCorp Vault documentation](https://www.vaultproject.io/docs/auth/approle).

## Configure HashiCorp Vault in Cortex


| **Parameter** | **Description**                                                                                                                  | **Required** |
|----------------------------------------------------------------------------------------------------------------------------------| --- | --- |
| HashiCorp server URL (e.g., https://192.168.0.1:8200) | The server URL                                                                                                                   | True |
| Use AppRole Auth Method | Set as true if you are using the [AppRole](https://developer.hashicorp.com/vault/docs/auth/approle) method for authentication. | False |
| Username / Role ID | The username for the Hashicorp vault.                                                                                            | False |
| Password / Secret ID | The password for the Hashicorp vault.                                                                                             | False |
| Authentication token | A token for authentication for the Hashicorp vault. (Use instead of password and username.)                                            | False |
| Vault enterprise namespace | The [namespace](https://developer.hashicorp.com/vault/tutorials/enterprise/namespaces) used for the vault by the user.  | False |
| Trust any certificate (not secure) | Mark as true to make unverified HTTP requests.                                                                                    | False |
| Use system proxy settings | Mark as true to use proxy settings.                                                                                                        | False |
| Fetches credentials | Mark as true to fetch credentials to the Cortex XSOAR credentials vault.                                                                 | False |
| CSV list of secrets engine types to fetch secrets from | Possible values are KV, Cubbyhole, AWS.                                                                                           | False |
| Concat username to credential object name | Should be used in case there are several secrets under the same folder in order to make the credential object unique.            | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### hashicorp-list-secrets-engines
***
List all secrets engines that exist in HashiCorp Vault.


#### Base Command

`hashicorp-list-secrets-engines`
#### Input

There are no input arguments.


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Engine.Type | string | Secrets engine type. | 
| HashiCorp.Engine.Path | string | Secrets engine path in HashiCorp. | 
| HashiCorp.Engine.Description | string | Secrets engine description. | 
| HashiCorp.Engine.Accessor | string | Secrets engine accessor. | 

#### Command example
```!hashicorp-list-secrets-engines```
### hashicorp-list-secrets
***
List secrets (names) for a specified KV engine.


#### Base Command

`hashicorp-list-secrets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| engine | Engine path, e.g.,"secret/". Use the list-secrets-engines command to retrieve the engine path. | Required | 
| version | The version of the KV engine. Possible values are: 1, 2. Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Secret.Path | string | Secret path | 
#### Command example
```!hashicorp-list-secrets```
### hashicorp-get-secret-metadata
***
Returns information about a specified secret in a specified KV V2 engine. 


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
| HashiCorp.Secret.Created | date | Secret creation time. | 
| HashiCorp.Secret.Version.Destroyed | boolean | Is the version destroyed. | 
| HashiCorp.Secret.Version.Created | number | Version creation time. | 
| HashiCorp.Secret.Version.Deleted | date | Version deletion time. | 
| HashiCorp.Secret.Updated | date | Secret last updated time. | 
| HashiCorp.Secret.Engine | string | Secret engine type. | 
| HashiCorp.Secret.CurrentVersion | number | Secret current version. | 
| HashiCorp.Secret.Path | string | Secret path. | 
#### Command example
```!hashicorp-get-secret-metadata engine_path=secret secret_path=test```
### hashicorp-delete-secret
***
Deletes the data under a specified secret given the secret path. Performs a soft delete that allows you to run the hashicorp-undelete-secret command if necessary (for KV V2 engine).


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

#### Command example
```!hashicorp-delete-secret engine_path=secret secret_path=test versions=2```
### hashicorp-undelete-secret
***
Undeletes (restores) a secret on HashiCorp (for KV V2 engine).


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
#### Command example
```!hashicorp-undelete-secret engine_path=secret secret_path=test versions=2```
### hashicorp-destroy-secret
***
Permanently deletes a secret (for KV V2 engine).


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
#### Command example
```!hashicorp-destroy-secret engine_path=secret secret_path=test versions=2```
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
#### Command example
```!hashicorp-disable-engine path=secret```
### hashicorp-enable-engine
***!hashicorp-disable-engine path=secret
Enables a new secrets engine at the specified path.


#### Base Command

`hashicorp-enable-engine`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| path | The path where the secrets engine will be mounted. | Required | 
| type | Type of backend, e.g., "aws". | Required | 
| description | Friendly description of the mount. | Optional | 
| default_lease_ttl | The default lease duration, specified as a string duration, e.g., "5s" or "30m". | Optional | 
| max_lease_ttl | The maximum lease duration, specified as a string duration, e.g., "5s" or "30m". | Optional | 
| force_no_cache | Whether to disable caching. | Optional | 
| audit_non_hmac_request_keys | CSV list of keys that will not be HMAC'd by audit devices in the request data object. | Optional | 
| audit_non_hmac_response_keys | CSV list of keys that will not be HMAC'd by audit devices in the response data object. | Optional | 
| listing_visibility | Whether to show this mount in the UI-specific listing endpoint. Default is hidden. Possible values are: unauth, hidden. | Optional | 
| passthrough_request_headers | CSV list of headers to add to allow list and pass from the request to the backend. | Optional | 
| kv_version | KV version to mount. Set to "2" for mount KV V2. Possible values are: 1, 2. | Optional | 
| local | Specifies if the secrets engine is a local mount only. Local mounts are not replicated, nor (if a secondary) removed by replication. Supported only in Vault Enterprise. | Optional | 
| seal_wrap | Enable seal wrapping for the mount. Supported only in Vault Enterprise. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!hashicorp-enable-engine path=secret type=AWS```
### hashicorp-list-policies
***
Lists all configured policies.


#### Base Command

`hashicorp-list-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Policy.Name | string | Policy name. | 
#### Command example
```hashicorp-list-policies```
### hashicorp-get-policy
***
Get information for a policy.


#### Base Command

`hashicorp-get-policy`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Policy name. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Policy.Name | string | Policy name. | 
| HashiCorp.Policy.Rule.Path  | string | Policy rule path. | 
| HashiCorp.Policy.Rule.Capabilities | unknown | Policy rule capabilities. | 
#### Command example
```!hashicorp-get-policy name=secret```
### hashicorp-seal-vault
***
If you suspect your data has been compromised, you can seal your vault to prevent access to your secrets.


#### Base Command

`hashicorp-seal-vault`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
#### Command example
```!hashicorp-seal-vault```
### hashicorp-unseal-vault
***
Use a single master key share to unseal the vault. If the master key shares threshold is met, the key will attempt to unseal the vault. Otherwise, this API must be called until the threshold is met.


#### Base Command

`hashicorp-unseal-vault`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| key | Single master key . | Optional | 
| reset | Reset the unseal project. Possible values are: true. | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!hashicorp-unseal-vault```
### hashicorp-configure-engine
***
Configure a secrets engine to fetch secrets from.


#### Base Command

`hashicorp-configure-engine`
#### Input

| **Argument Name** | **Description**                                                                                                                                               | **Required** |
| --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------| --- |
| path | The engine path, e.g., "secret/".                                                                                                                             | Required | 
| folder | Specific folder to fetch secrets from, e.g., "secret-folder/". (Supported only for engine type KV2.)                                                          | Optional | 
| type | The engine type, e.g., "KV". Possible values are: KV, Cubbyhole, AWS.                                                                                         | Required | 
| version | The engine version (for KV engines). Possible values are: 1, 2.                                                                                   | Optional | 
| aws_roles_list | A comma-delimited list of roles names to generate credentials for. If not mentioned, we will generate credentials for all roles in the path.(used for only for AWS). | Optional | 
| aws_method | A parameter to indicate which type of request we would like to use to generate credentials(used for only for AWS).                                            | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!hashicorp-configure-engine type=type version=2 path=path ttl=3600```
#### Human Readable Output

>Engine configured successfully

### hashicorp-reset-configuration
***
Reset the engine configuration.


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

>Successfully reset the engine configuration.

### hashicorp-create-token
***
Create a new authentication token.


#### Base Command

`hashicorp-create-token`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The name of the token role. | Optional | 
| policies | CSV list of policies for the token. This must be a subset of the policies belonging to the token making the request, unless root. If policies are not specified, all policies of the calling token are applied to the new token. | Optional | 
| meta | A map of string-to-string valued metadata. This is passed through to the audit devices. | Optional | 
| no_parent | If true and set by a root caller, the token will not have the parent token of the caller. This creates a token with no parent. Possible values are: true, false. | Optional | 
| no_default_policy | If true the default policy will not be included in this token's policy set. Possible values are: true, false. | Optional | 
| renewable | If set to false, the token cannot be renewed past its initial TTL. If set to true, the token can be renewed up to the system/mount maximum TTL. Possible values are: true, false. | Optional | 
| ttl | The TTL (lease duration) period of the token, provided as "10m" or "1h", where hour is the largest suffix. If not provided, the token is valid for the default lease TTL, or indefinitely if the root policy is used. | Optional | 
| explicit_max_ttl | If set, the token will have an explicit max TTL applied to it. The maximum token TTL cannot be changed later, and unlike with normal tokens, updates to the system/mount max TTL value will have no effect at renewal time. The token can never be renewed or used past the value set at issue time. | Optional | 
| display_name | The display name of the token. | Optional | 
| num_uses | The maximum number of times the token can be used. Supply this argument to create a one-time-token, or limited use token. The value of 0 has no limit to the number of uses. | Optional | 
| period | If specified, the token will be periodic. It will not have a maximum TTL (unless an "explicit-max-ttl" is also set), but every renewal will use the given period. Requires a root/sudo token to use. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.Auth.Token | string | Authentication token. | 
| HashiCorp.Auth.Policy | unknown | Authentication policies. | 
| HashiCorp.Auth.LeaseDuration | number | Authentication lease duration in seconds, 0 if indefinitely.  | 

#### Command example
```!hashicorp-create-token display_name=token explicit_max_ttl=3600 renewable=false```


### hashicorp-generate-role-secret
***
Generates and issues a new SecretID on an existing AppRole.

#### Base Command

`hashicorp-generate-role-secret`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The name of the AppRole. | Required |
| meta_data | Metadata to be tied to the SecretID. | Optional |
| cidr_list | Comma separated string or list of CIDR blocks enforcing secret IDs to be used from specific set of IP addresses. | Optional |
| token_bound_cidrs | Comma-separated string or list of CIDR blocks. | Optional |
| num_uses | Number of times this SecretID can be used, after which the SecretID expires. A value of zero will allow unlimited uses. | Optional |
| ttl_seconds | Duration in seconds after which this SecretID expires. A value of zero will allow the SecretID to not expire. | Optional |

#### Context Output
There is no context output for this command.
#### Command example
```!hashicorp-generate-role-secret role_name=my-role```

#### Human Readable Output
>SecretID:123



### hashicorp-get-role-id
***
Retrieves the AppRole ID for a specified role.


#### Base Command

`hashicorp-get-role-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_name | The name of the AppRole. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| HashiCorp.AppRole.Id | string | AppRole ID. | 
| HashiCorp.AppRole.Name | string | AppRole Name. | 

#### Command example
```!hashicorp-get-role-id role_name=my-role```

#### Human Readable Output
|Id|Name|
|---|---|
|role_id|role_name|


## Additional Information
- In order to fetch credentials from HashiCorp Vault, the relevant secrets engines must be configured with the integration so it can pull the data from them. To configure an engine with the integration, use the ***configure-engine*** command.
- The default fetch rate for fetch-credentials is 10 minutes. This is configurable with the server parameter *vault.module.cache.expire*
## Known Limitations
Currently the integration is able to fetch credentials from the following engines:  
- **K/V Versions 1,2**  
- **Cubbyhole**  
- **AWS**  

### The following commands are limited to the K/V V2 engine:

- ***hashicorp-list-secrets***
- ***hashicorp-get-secret-metadata***
- ***hashicorp-delete-secret***
- ***hashicorp-undelete-secret***
- ***hashicorp-destroy-secret***