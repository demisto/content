Centralized Control and Monitoring of Privileged Access to Sensitive Assets.
This integration was integrated and tested with version 10 of WALLIX Bastion.

## Configure WALLIX Bastion on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for WALLIX Bastion.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. localhost) | True |
    | API Auth User | True |
    | API Auth Key or user password | False |
    | Password authentication mode (false if you provided an API key) | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | API version to use. Leave the field empty to use the latest API version available. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### wab-add-session-target-to-target-group

***
Add a target account to a target group.

#### Base Command

`wab-add-session-target-to-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The group id or name to edit. | Required | 
| account | The account name. | Required | 
| domain | The domain name (for an account or scenario account). | Optional | 
| domain_type | The domain type: local or global (for an account or scenario account). | Optional | 
| device | The device name (null for an application). | Optional | 
| service | The service name (null for an application). | Optional | 
| application | The application name (null for a device). | Optional | 
| session_account_type | 'account', 'account_mapping', 'interactive_login' or 'scenario_account'. | Required | 

#### Context Output

There is no context output for this command.

### wab-add-password-target-to-target-group

***
Add a password checkout account to a target group.

#### Base Command

`wab-add-password-target-to-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The group id or name to edit. | Required | 
| account | The account name. | Required | 
| domain | The domain name. | Required | 
| domain_type | The domain type: local or global. | Required | 
| device | The device name (null for an application). | Optional | 
| application | The application name (null for a device). | Optional | 

#### Context Output

There is no context output for this command.

### wab-add-restriction-to-target-group

***
Add a restriction to a target group.

#### Base Command

`wab-add-restriction-to-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The group id or name to edit. | Required | 
| action | the restriction type: 'kill' or 'notify'. | Required | 
| rules | the restriction rules. | Required | 
| subprotocol | the restriction subprotocol: SSH_SHELL_SESSION, SSH_REMOTE_COMMAND, SSH_SCP_UP, SSH_SCP_DOWN, SFTP_SESSION, RLOGIN, TELNET, RDP. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-account-references

***
Get account references.

#### Base Command

`wab-get-account-references`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The referenced account id or name. | Required | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'key'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.account_reference_get.id | String | The account reference id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.reference_name | String | The reference name. \\ /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.description | String | The account reference description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.account | String | The referenced account name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.admin_account | String | The administrator account used to change password references Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.domain | String | The name of the domain defining the password change. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.devices.device_name | String | The device name. \\ /:\*?"&lt;&gt;|@ and space are forbidden. | 
| WAB.account_reference_get.devices.status | String | The status of the last password change on this device, or null it has never been changed. | 
| WAB.account_reference_get.devices.error_date | String | The date/time since which the status is "error", or null if the status is not "error". | 
| WAB.account_reference_get.devices.error_description | String | The description of the error, of null if the status is not "error". | 

### wab-get-account-reference

***
Get account reference.

#### Base Command

`wab-get-account-reference`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | The referenced account id or name. | Required | 
| reference_id | An account reference id or name. If specified, only this account reference is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.account_reference_get.id | String | The account reference id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.reference_name | String | The reference name. \\ /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.description | String | The account reference description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.account | String | The referenced account name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.admin_account | String | The administrator account used to change password references Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.domain | String | The name of the domain defining the password change. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_reference_get.devices.device_name | String | The device name. \\ /:\*?"&lt;&gt;|@ and space are forbidden. | 
| WAB.account_reference_get.devices.status | String | The status of the last password change on this device, or null it has never been changed. | 
| WAB.account_reference_get.devices.error_date | String | The date/time since which the status is "error", or null if the status is not "error". | 
| WAB.account_reference_get.devices.error_description | String | The description of the error, of null if the status is not "error". | 

### wab-get-all-accounts

***
Get all accounts.

#### Base Command

`wab-get-all-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_type | The account type: "global" for only global domain accounts, "device" for only device accounts, "application" for only application accounts. By default accounts of any type are returned. Cannot be used if an account_name and/or device/application is specified. | Optional | 
| application | The name of the application whose accounts must be returned. Cannot be used if an account_name and/or an account_type/device is specified. | Optional | 
| device | The name of the device whose accounts must be returned. Cannot be used if an account_name and/or an application is specified. | Optional | 
| passwords | Return credentials (passwords and SSH keys) as-is without replacing content by stars. Note: this requires the Password Manager license, the flag "Credential recovery" in the profile of the user logged on the API and the "Credential recovery" option must be enabled in REST API configuration. | Optional | 
| key_format | Format of the returned SSH public key of the account. Accepted values are 'openssh' (default value) and 'ssh.com'. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'account_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.domain | String | The domain name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.device | String | The device name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.application | String | The application name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.credentials.id | String | The credential id. | 
| WAB.account_get.credentials.type | String | The credential type. | 
| WAB.account_get.credentials.password | String | The account password. | 
| WAB.account_get.credentials.private_key | String | The account private key. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.account_get.credentials.passphrase | String | The passphrase for the private key \(only for an encrypted private key\). If provided, it must be between 4 and 1024 characters long. | 
| WAB.account_get.credentials.public_key | String | The account public key. | 
| WAB.account_get.credentials.key_type | String | The key type. | 
| WAB.account_get.credentials.key_len | Number | The key length. | 
| WAB.account_get.credentials.key_id | String | The key identity: random value used for revocation. | 
| WAB.account_get.credentials.certificate | String | The certificate. | 
| WAB.account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.auto_change_ssh_key | Boolean | Automatically change the ssh key. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.first_seen.id | String | The scan job id. | 
| WAB.account_get.first_seen.type | String | Scan type. | 
| WAB.account_get.first_seen.error | String | Error message. | 
| WAB.account_get.first_seen.status | String | Scan job status. | 
| WAB.account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.account_get.last_seen.id | String | The scan job id. | 
| WAB.account_get.last_seen.type | String | Scan type. | 
| WAB.account_get.last_seen.error | String | Error message. | 
| WAB.account_get.last_seen.status | String | Scan job status. | 
| WAB.account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.account_get.resources | String | The account resources. | 
| WAB.account_get.services | String | The account services. | 
| WAB.account_get.url | String | The API URL to the resource. | 

### wab-get-one-account

***
Get one account.

#### Base Command

`wab-get-one-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | An account id or complete name with account name, domain name and device/application name, for example: "Administrator@local@win10". | Required | 
| account_type | The account type: "global" for only global domain accounts, "device" for only device accounts, "application" for only application accounts. By default accounts of any type are returned. Cannot be used if an account_name and/or device/application is specified. | Optional | 
| application | The name of the application whose accounts must be returned. Cannot be used if an account_name and/or an account_type/device is specified. | Optional | 
| device | The name of the device whose accounts must be returned. Cannot be used if an account_name and/or an application is specified. | Optional | 
| passwords | Return credentials (passwords and SSH keys) as-is without replacing content by stars. Note: this requires the Password Manager license, the flag "Credential recovery" in the profile of the user logged on the API and the "Credential recovery" option must be enabled in REST API configuration. | Optional | 
| key_format | Format of the returned SSH public key of the account. Accepted values are 'openssh' (default value) and 'ssh.com'. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.domain | String | The domain name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.device | String | The device name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.application | String | The application name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.credentials.id | String | The credential id. | 
| WAB.account_get.credentials.type | String | The credential type. | 
| WAB.account_get.credentials.password | String | The account password. | 
| WAB.account_get.credentials.private_key | String | The account private key. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.account_get.credentials.passphrase | String | The passphrase for the private key \(only for an encrypted private key\). If provided, it must be between 4 and 1024 characters long. | 
| WAB.account_get.credentials.public_key | String | The account public key. | 
| WAB.account_get.credentials.key_type | String | The key type. | 
| WAB.account_get.credentials.key_len | Number | The key length. | 
| WAB.account_get.credentials.key_id | String | The key identity: random value used for revocation. | 
| WAB.account_get.credentials.certificate | String | The certificate. | 
| WAB.account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.auto_change_ssh_key | Boolean | Automatically change the ssh key. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.account_get.first_seen.id | String | The scan job id. | 
| WAB.account_get.first_seen.type | String | Scan type. | 
| WAB.account_get.first_seen.error | String | Error message. | 
| WAB.account_get.first_seen.status | String | Scan job status. | 
| WAB.account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.account_get.last_seen.id | String | The scan job id. | 
| WAB.account_get.last_seen.type | String | Scan type. | 
| WAB.account_get.last_seen.error | String | Error message. | 
| WAB.account_get.last_seen.status | String | Scan job status. | 
| WAB.account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.account_get.resources | String | The account resources. | 
| WAB.account_get.services | String | The account services. | 
| WAB.account_get.url | String | The API URL to the resource. | 

### wab-delete-account

***
Delete an account.

#### Base Command

`wab-delete-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | An account id or complete name with account name, domain name and device/application name, for example: "Administrator@local@win10". | Required | 

#### Context Output

There is no context output for this command.

### wab-get-application-accounts

***
Get the application accounts.

#### Base Command

`wab-get-application-accounts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'account_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.app_account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.credentials.id | String | The credential id. | 
| WAB.app_account_get.credentials.type | String | The credential type. | 
| WAB.app_account_get.credentials.password | String | The account password. | 
| WAB.app_account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.app_account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.app_account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.first_seen.id | String | The scan job id. | 
| WAB.app_account_get.first_seen.type | String | Scan type. | 
| WAB.app_account_get.first_seen.error | String | Error message. | 
| WAB.app_account_get.first_seen.status | String | Scan job status. | 
| WAB.app_account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.app_account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.app_account_get.last_seen.id | String | The scan job id. | 
| WAB.app_account_get.last_seen.type | String | Scan type. | 
| WAB.app_account_get.last_seen.error | String | Error message. | 
| WAB.app_account_get.last_seen.status | String | Scan job status. | 
| WAB.app_account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.app_account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.app_account_get.url | String | The API URL to the resource. | 

### wab-add-account-to-local-domain-of-application

***
Add an account to a local domain of an application.

#### Base Command

`wab-add-account-to-local-domain-of-application`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| app_account_post_account_name | The account name. /:*?"&lt;&gt;\|@ and space are forbidden. | Required | 
| app_account_post_account_login | The account login. | Required | 
| app_account_post_description | The account description. | Optional | 
| app_account_post_auto_change_password | Automatically change the password. It is enabled by default on a new account. | Optional | 
| app_account_post_checkout_policy | The account checkout policy. | Required | 
| app_account_post_certificate_validity | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain. | Optional | 
| app_account_post_can_edit_certificate_validity | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-application-account

***
Get the application account.

#### Base Command

`wab-get-application-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| account_id | The account id or name. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.app_account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.credentials.id | String | The credential id. | 
| WAB.app_account_get.credentials.type | String | The credential type. | 
| WAB.app_account_get.credentials.password | String | The account password. | 
| WAB.app_account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.app_account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.app_account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.app_account_get.first_seen.id | String | The scan job id. | 
| WAB.app_account_get.first_seen.type | String | Scan type. | 
| WAB.app_account_get.first_seen.error | String | Error message. | 
| WAB.app_account_get.first_seen.status | String | Scan job status. | 
| WAB.app_account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.app_account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.app_account_get.last_seen.id | String | The scan job id. | 
| WAB.app_account_get.last_seen.type | String | Scan type. | 
| WAB.app_account_get.last_seen.error | String | Error message. | 
| WAB.app_account_get.last_seen.status | String | Scan job status. | 
| WAB.app_account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.app_account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.app_account_get.url | String | The API URL to the resource. | 

### wab-edit-account-on-local-domain-of-application

***
Edit an account on a local domain of an application.

#### Base Command

`wab-edit-account-on-local-domain-of-application`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| account_id | The account id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the credentials and services, if they are supplied, are replaced, otherwise the values are added to the existing ones. | Optional | 
| app_account_put_account_name | The account name. /:*?"&lt;&gt;\|@ and space are forbidden. | Optional | 
| app_account_put_account_login | The account login. | Optional | 
| app_account_put_description | The account description. | Optional | 
| app_account_put_auto_change_password | Automatically change the password. It is enabled by default on a new account. | Optional | 
| app_account_put_checkout_policy | The account checkout policy. | Optional | 
| app_account_put_certificate_validity | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain. | Optional | 
| app_account_put_can_edit_certificate_validity | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise. | Optional | 
| app_account_put_onboard_status | Onboarding status of the account. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-account-from-local-domain-of-application

***
Delete an account from a local domain of an application.

#### Base Command

`wab-delete-account-from-local-domain-of-application`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| account_id | The account id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-applications

***
Get the applications.

#### Base Command

`wab-get-applications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'application_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.application_get.id | String | The application id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.application_name | String | The application name. \\/:\*?"&lt;&gt;| and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.description | String | The application description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.category | String | The application category. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.last_connection | String | The last connection on this application \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.parameters | String | The application parameters. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.domain_name | String | The domain name. /:\*?"&lt;&gt;|@ are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.enable_password_change | Boolean | Enable the change of password on this domain. | 
| WAB.application_get.local_domains.admin_account | String | The administrator account used to change passwords on this domain \(format: "account_name"\). | 
| WAB.application_get.local_domains.password_change_policy | String | The name of password change policy for this domain. | 
| WAB.application_get.local_domains.password_change_plugin | String | The name of plugin used to change passwords on this domain. | 
| WAB.application_get.local_domains.url | String | The API URL to the resource. | 
| WAB.application_get.tags.id | String | The tag id. | 
| WAB.application_get.tags.key | String | The tag key. Must not start or end with a space. | 
| WAB.application_get.tags.value | String | The tag value. Must not start or end with a space. | 
| WAB.application_get.connection_policy | String | The connection policy name. Usable in the "q" parameter. | 
| WAB.application_get.url | String | The API URL to the resource. | 

### wab-get-application

***
Get the application.

#### Base Command

`wab-get-application`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | An application id or name. If specified, only this application is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.application_get.id | String | The application id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.application_name | String | The application name. \\/:\*?"&lt;&gt;| and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.description | String | The application description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.category | String | The application category. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.last_connection | String | The last connection on this application \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.parameters | String | The application parameters. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.domain_name | String | The domain name. /:\*?"&lt;&gt;|@ are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.application_get.local_domains.enable_password_change | Boolean | Enable the change of password on this domain. | 
| WAB.application_get.local_domains.admin_account | String | The administrator account used to change passwords on this domain \(format: "account_name"\). | 
| WAB.application_get.local_domains.password_change_policy | String | The name of password change policy for this domain. | 
| WAB.application_get.local_domains.password_change_plugin | String | The name of plugin used to change passwords on this domain. | 
| WAB.application_get.local_domains.url | String | The API URL to the resource. | 
| WAB.application_get.tags.id | String | The tag id. | 
| WAB.application_get.tags.key | String | The tag key. Must not start or end with a space. | 
| WAB.application_get.tags.value | String | The tag value. Must not start or end with a space. | 
| WAB.application_get.connection_policy | String | The connection policy name. Usable in the "q" parameter. | 
| WAB.application_get.url | String | The API URL to the resource. | 

### wab-edit-application

***
Edit an application.

#### Base Command

`wab-edit-application`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the global_domains and tags are replaced, otherwise the values are added to the existing ones. | Optional | 
| application_put_application_name | The application name. \/:*?"&lt;&gt;\| and space are forbidden. | Optional | 
| application_put_description | The application description. | Optional | 
| application_put_parameters | The application parameters. | Optional | 
| application_put_connection_policy | The connection policy name. | Optional | 
| application_put__meters | deprecated: use application_put_parameters instead. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-application

***
Delete an application.

#### Base Command

`wab-delete-application`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| application_id | The application id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-approvals

***
Get the approvals.

#### Base Command

`wab-get-approvals`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_id | An approval id. If specified, only this approval is returned. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: '-begin'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.approval_get.id | String | The approval id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.user_name | String | The user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.target_name | String | The target name.\(example: account@domain@device:service\). | 
| WAB.approval_get.creation | String | The creation date.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.begin | String | The start date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.end | String | The end date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.duration | Number | The allowed connection time, in minutes. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.ticket | String | The ticket reference. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.comment | String | The request description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.email | String | The user email. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.language | String | The user language code \(en, fr, ...\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.status | String | The approval status. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.quorum | Number | The quorum to reach. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.answers.approver_name | String | The user name of approver. | 
| WAB.approval_get.answers.date | String | The answer date \(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.approval_get.answers.comment | String | The answer comment. | 
| WAB.approval_get.answers.approved | Boolean | Request approval \(true = accepted, false = rejected\). | 
| WAB.approval_get.timeout | Number | Timeout to initiate the first connection \(in minutes\). After that, the approval will be automatically closed. 0: no timeout. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.authorization_name | String | The authorization name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.is_active | Boolean | The approval is active. | 
| WAB.approval_get.url | String | The API URL to the resource. | 

### wab-get-approvals-for-all-approvers

***
Get the approvals for a given approver.

#### Base Command

`wab-get-approvals-for-all-approvers`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: '-begin'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.approval_get.id | String | The approval id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.user_name | String | The user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.target_name | String | The target name.\(example: account@domain@device:service\). | 
| WAB.approval_get.creation | String | The creation date.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.begin | String | The start date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.end | String | The end date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.duration | Number | The allowed connection time, in minutes. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.ticket | String | The ticket reference. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.comment | String | The request description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.email | String | The user email. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.language | String | The user language code \(en, fr, ...\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.status | String | The approval status. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.quorum | Number | The quorum to reach. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.answers.approver_name | String | The user name of approver. | 
| WAB.approval_get.answers.date | String | The answer date \(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.approval_get.answers.comment | String | The answer comment. | 
| WAB.approval_get.answers.approved | Boolean | Request approval \(true = accepted, false = rejected\). | 
| WAB.approval_get.timeout | Number | Timeout to initiate the first connection \(in minutes\). After that, the approval will be automatically closed. 0: no timeout. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.authorization_name | String | The authorization name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.is_active | Boolean | The approval is active. | 
| WAB.approval_get.url | String | The API URL to the resource. | 

### wab-reply-to-approval-request

***
Reply to an approval request (approve/reject it). Note: you can answer to an approval request only if you are in approvers groups of authorization.

#### Base Command

`wab-reply-to-approval-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_assignment_post_id | The approval id. | Required | 
| approval_assignment_post_comment | The approval comment. | Required | 
| approval_assignment_post_duration | The allowed time range to connect (in minutes). | Optional | 
| approval_assignment_post_timeout | Timeout to initiate the first connection (in minutes). After that, the approval will be automatically closed. 0: no timeout. | Optional | 
| approval_assignment_post_approved | Approve/reject the request. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-approvals-for-approver

***
Get the approvals for a given approver.

#### Base Command

`wab-get-approvals-for-approver`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_name | The name of a user (approver). | Required | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: '-begin'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.approval_get.id | String | The approval id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.user_name | String | The user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.target_name | String | The target name.\(example: account@domain@device:service\). | 
| WAB.approval_get.creation | String | The creation date.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.begin | String | The start date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.end | String | The end date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.duration | Number | The allowed connection time, in minutes. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.ticket | String | The ticket reference. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.comment | String | The request description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.email | String | The user email. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.language | String | The user language code \(en, fr, ...\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.status | String | The approval status. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.quorum | Number | The quorum to reach. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.answers.approver_name | String | The user name of approver. | 
| WAB.approval_get.answers.date | String | The answer date \(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.approval_get.answers.comment | String | The answer comment. | 
| WAB.approval_get.answers.approved | Boolean | Request approval \(true = accepted, false = rejected\). | 
| WAB.approval_get.timeout | Number | Timeout to initiate the first connection \(in minutes\). After that, the approval will be automatically closed. 0: no timeout. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.authorization_name | String | The authorization name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.is_active | Boolean | The approval is active. | 
| WAB.approval_get.url | String | The API URL to the resource. | 

### wab-cancel-accepted-approval

***
Cancel an accepted approval. Note: you can cancel an approval only if you are in approvers groups of authorization and the end date is still not reached.

#### Base Command

`wab-cancel-accepted-approval`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_assignment_cancel_post_id | The approval id. | Required | 
| approval_assignment_cancel_post_comment | The cancel comment. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-approval-request-pending-for-user

***
Get the approval request pending for this user (by default the user logged on the REST API), or the approval request with the given id.

#### Base Command

`wab-get-approval-request-pending-for-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | (1st option) The name of a user (by default the user logged on the REST API). | Optional | 
| q | (1st option) Searches for a resource matching parameters. | Optional | 
| sort | (1st option) Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: '-begin'. | Optional | 
| offset | (1st option) The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | (1st option) The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 
| approval_id | (2nd option) The approval request id (the 'id' returned when the approval was created). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.approval_get.id | String | The approval id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.user_name | String | The user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.target_name | String | The target name.\(example: account@domain@device:service\). | 
| WAB.approval_get.creation | String | The creation date.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.begin | String | The start date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.end | String | The end date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.duration | Number | The allowed connection time, in minutes. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.ticket | String | The ticket reference. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.comment | String | The request description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.email | String | The user email. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.language | String | The user language code \(en, fr, ...\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.status | String | The approval status. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.quorum | Number | The quorum to reach. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.answers.approver_name | String | The user name of approver. | 
| WAB.approval_get.answers.date | String | The answer date \(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.approval_get.answers.comment | String | The answer comment. | 
| WAB.approval_get.answers.approved | Boolean | Request approval \(true = accepted, false = rejected\). | 
| WAB.approval_get.timeout | Number | Timeout to initiate the first connection \(in minutes\). After that, the approval will be automatically closed. 0: no timeout. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.authorization_name | String | The authorization name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.approval_get.is_active | Boolean | The approval is active. | 
| WAB.approval_get.url | String | The API URL to the resource. | 

### wab-make-new-approval-request-to-access-target

***
Make a new approval request to access a target. Note: depending on the authorization settings, the fields "ticket" and "comment" may be required.

#### Base Command

`wab-make-new-approval-request-to-access-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_request_post_target_name | The target name (example: account@domain@device:service). | Required | 
| approval_request_post_authorization | The authorization name. | Optional | 
| approval_request_post_ticket | The ticket reference. | Optional | 
| approval_request_post_comment | The request comment. | Optional | 
| approval_request_post_begin | The date/time for connection (format: "yyyy-mm-dd hh:mm"), default is now. | Optional | 
| approval_request_post_duration | The allowed time range to connect (in minutes). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.approval_request_post_response_ok.id | String | The new approval id. | 

### wab-cancel-approval-request

***
Cancel an approval request.

#### Base Command

`wab-cancel-approval-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_request_cancel_post_id | The approval id. | Required | 

#### Context Output

There is no context output for this command.

### wab-notify-approvers-linked-to-approval-request

***
Notify approvers linked to an approval request by sending them an email.

#### Base Command

`wab-notify-approvers-linked-to-approval-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| approval_request_notify_post_id | The approval id. | Required | 

#### Context Output

There is no context output for this command.

### wab-check-if-approval-is-required-for-target

***
Check if an approval is required for this target (optionally for a given date in future).

#### Base Command

`wab-check-if-approval-is-required-for-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_name | The target name (for example 'account@domain@device:service'). | Required | 
| authorization | The name of the authorization (in case of multiple authorizations to access the target). | Optional | 
| begin | The date/time (in future) for the check, current date/time is used by default (format is 'yyyy-mm-dd hh:mm'). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.approval_request_target_get.approval | String | Tells whether an approval request is needed to access the target or not: not_authorized = connection is not authorized at all, not_required = connection is allowed without approval request, required = an approval request is required, pending = an approval request is pending, error = internal error. | 
| WAB.approval_request_target_get.message | String | A message with detail about the access to the target. | 
| WAB.approval_request_target_get.id | String | The approval id if an approval request is already pending for this target. | 

### wab-get-auth-domains

***
Get the auth domains.

#### Base Command

`wab-get-auth-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'domain_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.auth_domain_get.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.domain_name | String | The domain name.\\ Only alphanumeric characters, dots \(.\) and hyphens \(-\) are allowed \\ Length ranges between 3 and 63. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.type | String | The domain type. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.is_default | Boolean | The domain is used by default. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.auth_domain_name | String | The auth domain name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.external_auths | String | The external authentications. | 
| WAB.auth_domain_get.secondary_auth | String | The secondary authentications methods for the auth domain. | 
| WAB.auth_domain_get.default_language | String | The default language. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.default_email_domain | String | The default email domain. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.mappings.id | String | The mapping id. | 
| WAB.auth_domain_get.mappings.domain | String | The name of the domain for which the mapping is defined. | 
| WAB.auth_domain_get.mappings.user_group | String | The name of the Bastion users group. | 
| WAB.auth_domain_get.mappings.external_group | String | The name of the external group \(LDAP/AD: Distinguished Name, Azure AD: name or ID\), "\*" means fallback mapping. | 
| WAB.auth_domain_get.url | String | The API URL to the resource. | 

### wab-get-auth-domain

***
Get the auth domain.

#### Base Command

`wab-get-auth-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | An auth domain id or name to retrieve. If specified, only this auth domain information will be retrieved. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.auth_domain_get.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.domain_name | String | The domain name.\\ Only alphanumeric characters, dots \(.\) and hyphens \(-\) are allowed \\ Length ranges between 3 and 63. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.type | String | The domain type. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.is_default | Boolean | The domain is used by default. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.auth_domain_name | String | The auth domain name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.external_auths | String | The external authentications. | 
| WAB.auth_domain_get.secondary_auth | String | The secondary authentications methods for the auth domain. | 
| WAB.auth_domain_get.default_language | String | The default language. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.default_email_domain | String | The default email domain. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.auth_domain_get.mappings.id | String | The mapping id. | 
| WAB.auth_domain_get.mappings.domain | String | The name of the domain for which the mapping is defined. | 
| WAB.auth_domain_get.mappings.user_group | String | The name of the Bastion users group. | 
| WAB.auth_domain_get.mappings.external_group | String | The name of the external group \(LDAP/AD: Distinguished Name, Azure AD: name or ID\), "\*" means fallback mapping. | 
| WAB.auth_domain_get.url | String | The API URL to the resource. | 

### wab-get-authentications

***
Get the authentications.

#### Base Command

`wab-get-authentications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Return authentications from this date/time (format: "yyyy-mm-dd" or "yyyy-mm-dd hh:mm:ss"). | Optional | 
| to_date | Return authentications until this date/time (format: "yyyy-mm-dd" or "yyyy-mm-dd hh:mm:ss"). | Optional | 
| date_field | The field used for date comparison: "login" for the login time, "logout" for the logout time. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.authentication_get.id | String | The authentication id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.login | String | The user connection date/time \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.logout | String | The user deconnection date/time \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.username | String | The primary user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.domain | String | The user domain. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.source_ip | String | The source IP. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.diagnostic | String | The diagnostic message. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.result | Boolean | The authentication is successful. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.url | String | The API URL to the resource. | 

### wab-get-authentication

***
Get the authentication.

#### Base Command

`wab-get-authentication`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| auth_id | An authentication id. If specified, only this authentication is returned. | Required | 
| from_date | Return authentications from this date/time (format: "yyyy-mm-dd" or "yyyy-mm-dd hh:mm:ss"). | Optional | 
| to_date | Return authentications until this date/time (format: "yyyy-mm-dd" or "yyyy-mm-dd hh:mm:ss"). | Optional | 
| date_field | The field used for date comparison: "login" for the login time, "logout" for the logout time. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.authentication_get.id | String | The authentication id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.login | String | The user connection date/time \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.logout | String | The user deconnection date/time \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.username | String | The primary user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.domain | String | The user domain. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.source_ip | String | The source IP. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.diagnostic | String | The diagnostic message. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.result | Boolean | The authentication is successful. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authentication_get.url | String | The API URL to the resource. | 

### wab-get-authorizations

***
Get the authorizations.

#### Base Command

`wab-get-authorizations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.authorization_get.id | String | The authorization id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.user_group | String | The user group. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.target_group | String | The target group. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.authorization_name | String | The authorization name. \\ /:\*?"&lt;&gt;|@&amp; and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.description | String | The authorization description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.subprotocols | String | The authorization subprotocols. It is mandatory if "authorize_sessions" is enabled \(default\). | 
| WAB.authorization_get.is_critical | Boolean | Define if it's critical. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.is_recorded | Boolean | Define if it's recorded. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.authorize_password_retrieval | Boolean | Authorize password retrieval. Enabled by default. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.authorize_sessions | Boolean | Authorize sessions via proxies. Enabled by default. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.approval_required | Boolean | Approval is required to connect to targets. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.has_comment | Boolean | Comment is allowed in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.mandatory_comment | Boolean | Comment is mandatory in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.has_ticket | Boolean | Ticket is allowed in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.mandatory_ticket | Boolean | Ticket is mandatory in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.approvers | String | The approvers user groups. | 
| WAB.authorization_get.active_quorum | Number | The quorum for active periods \(-1: approval workflow with automatic approval, 0: no approval workflow \(direct connection\), &gt; 0: quorum to reach\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.inactive_quorum | Number | The quorum for inactive periods \(-1: approval workflow with automatic approval, 0: no connection allowed, &gt; 0: quorum to reach\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.single_connection | Boolean | Limit to one single connection during the approval period \(i.e. if the user disconnects, he will not be allowed to start a new session during the original requested time\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.approval_timeout | Number | Set a timeout in minutes after which the approval will be automatically closed if no connection has been initiated \(i.e. the user won't be able to connect\). 0: no timeout. Usable in the "q" parameter. | 
| WAB.authorization_get.authorize_session_sharing | Boolean | Enable Session Sharing. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.session_sharing_mode | String | The Session Sharing Mode. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.url | String | The API URL to the resource. | 

### wab-add-authorization

***
Add an authorization.

#### Base Command

`wab-add-authorization`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| authorization_post_user_group | The user group. | Required | 
| authorization_post_target_group | The target group. | Required | 
| authorization_post_authorization_name | The authorization name. \ /:*?"&lt;&gt;\|@&amp; and space are forbidden. | Required | 
| authorization_post_description | The authorization description. | Optional | 
| authorization_post_subprotocols | The authorization subprotocols. It is mandatory if "authorize_sessions" is enabled (default). | Optional | 
| authorization_post_is_critical | Define if it's critical. | Optional | 
| authorization_post_is_recorded | Define if it's recorded. | Optional | 
| authorization_post_authorize_password_retrieval | Authorize password retrieval. Enabled by default. | Optional | 
| authorization_post_authorize_sessions | Authorize sessions via proxies. Enabled by default. | Optional | 
| authorization_post_approval_required | Approval is required to connect to targets. | Optional | 
| authorization_post_has_comment | Comment is allowed in approval. | Optional | 
| authorization_post_mandatory_comment | Comment is mandatory in approval. | Optional | 
| authorization_post_has_ticket | Ticket is allowed in approval. | Optional | 
| authorization_post_mandatory_ticket | Ticket is mandatory in approval. | Optional | 
| authorization_post_approvers | The approvers user groups. | Optional | 
| authorization_post_active_quorum | The quorum for active periods (-1: approval workflow with automatic approval, 0: no approval workflow (direct connection), &gt; 0: quorum to reach). | Optional | 
| authorization_post_inactive_quorum | The quorum for inactive periods (-1: approval workflow with automatic approval, 0: no connection allowed, &gt; 0: quorum to reach). | Optional | 
| authorization_post_single_connection | Limit to one single connection during the approval period (i.e. if the user disconnects, he will not be allowed to start a new session during the original requested time). | Optional | 
| authorization_post_approval_timeout | Set a timeout in minutes after which the approval will be automatically closed if no connection has been initiated (i.e. the user won't be able to connect). 0: no timeout. | Optional | 
| authorization_post_authorize_session_sharing | Enable Session Sharing. | Optional | 
| authorization_post_session_sharing_mode | The Session Sharing Mode. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-authorization

***
Get the authorization.

#### Base Command

`wab-get-authorization`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| authorization_id | An authorization id or name. If specified, only this authorization is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.authorization_get.id | String | The authorization id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.user_group | String | The user group. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.target_group | String | The target group. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.authorization_name | String | The authorization name. \\ /:\*?"&lt;&gt;|@&amp; and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.description | String | The authorization description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.subprotocols | String | The authorization subprotocols. It is mandatory if "authorize_sessions" is enabled \(default\). | 
| WAB.authorization_get.is_critical | Boolean | Define if it's critical. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.is_recorded | Boolean | Define if it's recorded. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.authorize_password_retrieval | Boolean | Authorize password retrieval. Enabled by default. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.authorize_sessions | Boolean | Authorize sessions via proxies. Enabled by default. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.approval_required | Boolean | Approval is required to connect to targets. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.has_comment | Boolean | Comment is allowed in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.mandatory_comment | Boolean | Comment is mandatory in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.has_ticket | Boolean | Ticket is allowed in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.mandatory_ticket | Boolean | Ticket is mandatory in approval. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.approvers | String | The approvers user groups. | 
| WAB.authorization_get.active_quorum | Number | The quorum for active periods \(-1: approval workflow with automatic approval, 0: no approval workflow \(direct connection\), &gt; 0: quorum to reach\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.inactive_quorum | Number | The quorum for inactive periods \(-1: approval workflow with automatic approval, 0: no connection allowed, &gt; 0: quorum to reach\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.single_connection | Boolean | Limit to one single connection during the approval period \(i.e. if the user disconnects, he will not be allowed to start a new session during the original requested time\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.approval_timeout | Number | Set a timeout in minutes after which the approval will be automatically closed if no connection has been initiated \(i.e. the user won't be able to connect\). 0: no timeout. Usable in the "q" parameter. | 
| WAB.authorization_get.authorize_session_sharing | Boolean | Enable Session Sharing. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.session_sharing_mode | String | The Session Sharing Mode. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.authorization_get.url | String | The API URL to the resource. | 

### wab-edit-authorization

***
Edit an authorization.

#### Base Command

`wab-edit-authorization`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| authorization_id | The authorization id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of subprotocols and approvers are replaced otherwise the values are added to the existing ones. | Optional | 
| authorization_put_authorization_name | The authorization name. \ /:*?"&lt;&gt;\|@&amp; and space are forbidden. | Optional | 
| authorization_put_description | The authorization description. | Optional | 
| authorization_put_subprotocols | The authorization subprotocols. It is mandatory if "authorize_sessions" is enabled (default). | Optional | 
| authorization_put_is_critical | Define if it's critical. | Optional | 
| authorization_put_is_recorded | Define if it's recorded. | Optional | 
| authorization_put_authorize_password_retrieval | Authorize password retrieval. Enabled by default. | Optional | 
| authorization_put_authorize_sessions | Authorize sessions via proxies. Enabled by default. | Optional | 
| authorization_put_approval_required | Approval is required to connect to targets. | Optional | 
| authorization_put_has_comment | Comment is allowed in approval. | Optional | 
| authorization_put_mandatory_comment | Comment is mandatory in approval. | Optional | 
| authorization_put_has_ticket | Ticket is allowed in approval. | Optional | 
| authorization_put_mandatory_ticket | Ticket is mandatory in approval. | Optional | 
| authorization_put_approvers | The approvers user groups. | Optional | 
| authorization_put_active_quorum | The quorum for active periods (-1: approval workflow with automatic approval, 0: no approval workflow (direct connection), &gt; 0: quorum to reach). | Optional | 
| authorization_put_inactive_quorum | The quorum for inactive periods (-1: approval workflow with automatic approval, 0: no connection allowed, &gt; 0: quorum to reach). | Optional | 
| authorization_put_single_connection | Limit to one single connection during the approval period (i.e. if the user disconnects, he will not be allowed to start a new session during the original requested time). | Optional | 
| authorization_put_approval_timeout | Set a timeout in minutes after which the approval will be automatically closed if no connection has been initiated (i.e. the user won't be able to connect). 0: no timeout. | Optional | 
| authorization_put_authorize_session_sharing | Enable Session Sharing. | Optional | 
| authorization_put_session_sharing_mode | The Session Sharing Mode. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-authorization

***
Delete an authorization.

#### Base Command

`wab-delete-authorization`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| authorization_id | The authorization id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-checkout-policies

***
Get the checkout policies.

#### Base Command

`wab-get-checkout-policies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'checkout_policy_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.checkoutpolicy_get.id | String | The checkout policy id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.checkout_policy_name | String | The checkout policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.description | String | The checkout policy description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.enable_lock | Boolean | Lock on checkout. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.duration | Number | The checkout duration \(in seconds\). It is mandatory if lock on checkout is enabled. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.extension | Number | The extension duration \(in seconds\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.max_duration | Number | The max duration \(in seconds\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.change_credentials_at_checkin | Boolean | Change credentials at check-in. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.url | String | The API URL to the resource. | 

### wab-get-checkout-policy

***
Get the checkout policy.

#### Base Command

`wab-get-checkout-policy`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| checkout_policy_id | A checkout policy id or name. If specified, only this checkout policy is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.checkoutpolicy_get.id | String | The checkout policy id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.checkout_policy_name | String | The checkout policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.description | String | The checkout policy description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.enable_lock | Boolean | Lock on checkout. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.duration | Number | The checkout duration \(in seconds\). It is mandatory if lock on checkout is enabled. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.extension | Number | The extension duration \(in seconds\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.max_duration | Number | The max duration \(in seconds\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.change_credentials_at_checkin | Boolean | Change credentials at check-in. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.checkoutpolicy_get.url | String | The API URL to the resource. | 

### wab-getx509-configuration-infos

***
Get the X509 configuration infos.

#### Base Command

`wab-getx509-configuration-infos`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.config_x509_get.ca_certificate | String | Certificate Authority's certificate \(\*.cert file in PEM format\).If there's several certificate to be added, they've to be concatenated and supplied to this field, as one string. | 
| WAB.config_x509_get.server_public_key | String | Server public key \(\*.cert file in PEM format\). | 
| WAB.config_x509_get.server_private_key | String | Server private key \(\*.key file in PEM format\). | 
| WAB.config_x509_get.enable | Boolean | Enable X509 or not \(true = enabled, false = disabled\). | 
| WAB.config_x509_get.default | Boolean | Default X509 configuration or not \(true = default, false = set by user\). | 

### wab-uploadx509-configuration

***
Upload X509 configuration.

#### Base Command

`wab-uploadx509-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_x509_post_ca_certificate | Certificate Authority's certificate (*.cert file in PEM format).If there's several certificate to be added, they've to be concatenated and supplied to this field, as one string. | Optional | 
| config_x509_post_server_public_key | Server public key (*.cert file in PEM format). | Optional | 
| config_x509_post_server_private_key | Server private key (*.key file in PEM format). | Optional | 
| config_x509_post_enable | Enable X509 or not (true = enabled, false = disabled). | Optional | 

#### Context Output

There is no context output for this command.

### wab-updatex509-configuration

***
Update X509 Configuration.

#### Base Command

`wab-updatex509-configuration`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| config_x509_put_ca_certificate | Certificate Authority's certificate (*.cert file in PEM format).If there's several certificate to be added, they've to be concatenated and supplied to this field, as one string. | Optional | 
| config_x509_put_server_public_key | Server public key (*.cert file in PEM format). | Optional | 
| config_x509_put_server_private_key | Server private key (*.key file in PEM format). | Optional | 
| config_x509_put_enable | Enable X509 or not (true = enabled, false = disabled). | Optional | 

#### Context Output

There is no context output for this command.

### wab-resetx509-configuration

***
Reset X509 configuration.

#### Base Command

`wab-resetx509-configuration`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### wab-get-current-serial-configuration-number-of-bastion

***
Get current serial configuration number of the Bastion. This number can be used to know if the Bastion configuration was changed.

#### Base Command

`wab-get-current-serial-configuration-number-of-bastion`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.confignumber_get.configuration_number | Number | The current serial configuration number of the WALLIX Bastion. | 

### wab-get-all-accounts-on-device-local-domain

***
Get all accounts on a device local domain.

#### Base Command

`wab-get-all-accounts-on-device-local-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| key_format | Format of the returned SSH public key of the account. Accepted values are 'openssh' (default value) and 'ssh.com'. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'account_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.device_account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.credentials.id | String | The credential id. | 
| WAB.device_account_get.credentials.type | String | The credential type. | 
| WAB.device_account_get.credentials.password | String | The account password. | 
| WAB.device_account_get.credentials.private_key | String | The account private key. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.device_account_get.credentials.passphrase | String | The passphrase for the private key \(only for an encrypted private key\). If provided, it must be between 4 and 1024 characters long. | 
| WAB.device_account_get.credentials.public_key | String | The account public key. | 
| WAB.device_account_get.credentials.key_type | String | The key type. | 
| WAB.device_account_get.credentials.key_len | Number | The key length. | 
| WAB.device_account_get.credentials.key_id | String | The key identity: random value used for revocation. | 
| WAB.device_account_get.credentials.certificate | String | The certificate. | 
| WAB.device_account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.device_account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.auto_change_ssh_key | Boolean | Automatically change the ssh key. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.device_account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.first_seen.id | String | The scan job id. | 
| WAB.device_account_get.first_seen.type | String | Scan type. | 
| WAB.device_account_get.first_seen.error | String | Error message. | 
| WAB.device_account_get.first_seen.status | String | Scan job status. | 
| WAB.device_account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.device_account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.device_account_get.last_seen.id | String | The scan job id. | 
| WAB.device_account_get.last_seen.type | String | Scan type. | 
| WAB.device_account_get.last_seen.error | String | Error message. | 
| WAB.device_account_get.last_seen.status | String | Scan job status. | 
| WAB.device_account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.device_account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.device_account_get.url | String | The API URL to the resource. | 
| WAB.device_account_get.services | String | The account services. | 

### wab-add-account-to-local-domain-on-device

***
Add an account to a local domain on a device.

#### Base Command

`wab-add-account-to-local-domain-on-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| device_account_post_account_name | The account name. /:*?"&lt;&gt;\|@ and space are forbidden. | Required | 
| device_account_post_account_login | The account login. | Required | 
| device_account_post_description | The account description. | Optional | 
| device_account_post_auto_change_password | Automatically change the password. It is enabled by default on a new account. | Optional | 
| device_account_post_auto_change_ssh_key | Automatically change the ssh key. It is enabled by default on a new account. | Optional | 
| device_account_post_checkout_policy | The account checkout policy. | Required | 
| device_account_post_certificate_validity | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain. | Optional | 
| device_account_post_can_edit_certificate_validity | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise. | Optional | 
| device_account_post_services | The account services. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-one-account-on-device-local-domain

***
Get one account on a device local domain.

#### Base Command

`wab-get-one-account-on-device-local-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| account_id | The account id or name. | Required | 
| key_format | Format of the returned SSH public key of the account. Accepted values are 'openssh' (default value) and 'ssh.com'. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.device_account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.credentials.id | String | The credential id. | 
| WAB.device_account_get.credentials.type | String | The credential type. | 
| WAB.device_account_get.credentials.password | String | The account password. | 
| WAB.device_account_get.credentials.private_key | String | The account private key. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.device_account_get.credentials.passphrase | String | The passphrase for the private key \(only for an encrypted private key\). If provided, it must be between 4 and 1024 characters long. | 
| WAB.device_account_get.credentials.public_key | String | The account public key. | 
| WAB.device_account_get.credentials.key_type | String | The key type. | 
| WAB.device_account_get.credentials.key_len | Number | The key length. | 
| WAB.device_account_get.credentials.key_id | String | The key identity: random value used for revocation. | 
| WAB.device_account_get.credentials.certificate | String | The certificate. | 
| WAB.device_account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.device_account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.auto_change_ssh_key | Boolean | Automatically change the ssh key. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.device_account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_account_get.first_seen.id | String | The scan job id. | 
| WAB.device_account_get.first_seen.type | String | Scan type. | 
| WAB.device_account_get.first_seen.error | String | Error message. | 
| WAB.device_account_get.first_seen.status | String | Scan job status. | 
| WAB.device_account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.device_account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.device_account_get.last_seen.id | String | The scan job id. | 
| WAB.device_account_get.last_seen.type | String | Scan type. | 
| WAB.device_account_get.last_seen.error | String | Error message. | 
| WAB.device_account_get.last_seen.status | String | Scan job status. | 
| WAB.device_account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.device_account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.device_account_get.url | String | The API URL to the resource. | 
| WAB.device_account_get.services | String | The account services. | 

### wab-edit-account-on-local-domain-of-device

***
Edit an account on a local domain of a device.

#### Base Command

`wab-edit-account-on-local-domain-of-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| account_id | The account id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the credentials and services, if they are supplied, are replaced, otherwise the values are added to the existing ones. | Optional | 
| device_account_put_account_name | The account name. /:*?"&lt;&gt;\|@ and space are forbidden. | Optional | 
| device_account_put_account_login | The account login. | Optional | 
| device_account_put_description | The account description. | Optional | 
| device_account_put_auto_change_password | Automatically change the password. It is enabled by default on a new account. | Optional | 
| device_account_put_auto_change_ssh_key | Automatically change the ssh key. It is enabled by default on a new account. | Optional | 
| device_account_put_checkout_policy | The account checkout policy. | Optional | 
| device_account_put_certificate_validity | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain. | Optional | 
| device_account_put_can_edit_certificate_validity | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise. | Optional | 
| device_account_put_onboard_status | Onboarding status of the account. | Optional | 
| device_account_put_services | The account services. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-account-from-local-domain-of-device

***
Delete an account from a local domain of a device.

#### Base Command

`wab-delete-account-from-local-domain-of-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| domain_id | The local domain id or name. | Required | 
| account_id | The account id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-certificates-on-device

***
Get the certificates on a device.

#### Base Command

`wab-get-certificates-on-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| q | Search and return only certificates matching these words. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'type,address'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.device_certificates_get.type | String | The certificate type. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.address | String | The certificate address. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.port | Number | The certificate port. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.key_type | String | The certificate key type. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.fingerprint | String | The fingerprint of the certificate. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.last_modification_date | String | The last time the certificate was modified. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.url | String | The API URL to the resource. | 

### wab-get-certificate-on-device

***
Get the certificate on a device.

#### Base Command

`wab-get-certificate-on-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| cert_type | The certificate type (SSH, RDP). | Required | 
| address | The certificate address/ip. | Required | 
| port | The certificate port. | Required | 
| q | Search and return only certificates matching these words. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'type,address'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.device_certificates_get.type | String | The certificate type. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.address | String | The certificate address. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.port | Number | The certificate port. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.key_type | String | The certificate key type. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.fingerprint | String | The fingerprint of the certificate. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.last_modification_date | String | The last time the certificate was modified. Usable in the "sort" parameter. | 
| WAB.device_certificates_get.url | String | The API URL to the resource. | 

### wab-revoke-certificate-of-device

***
Revoke a certificate of a device.

#### Base Command

`wab-revoke-certificate-of-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| cert_type | The certificate type (SSH, RDP). | Required | 
| address | The certificate address/ip. | Required | 
| port | The certificate port. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-services-of-device

***
Get the services of a device.

#### Base Command

`wab-get-services-of-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'service_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.service_get.id | String | The service id. Usable in the "sort" parameter. | 
| WAB.service_get.service_name | String | The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "sort" parameter. / The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.protocol | String | The protocol. Usable in the "sort" parameter. / The protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.port | Number | The port number. Usable in the "sort" parameter. / The port number. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.connection_policy | String | The connection policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.global_domains | String | The global domains names. | 
| WAB.service_get.url | String | The API URL to the resource. | 

### wab-add-service-in-device

***
Add a service in a device.

#### Base Command

`wab-add-service-in-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| service_post_id | The service id. Usable in the "sort" parameter. | Optional | 
| service_post_service_name | The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "sort" parameter. / The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "q" parameter. Usable in the "sort" parameter. | Required | 
| service_post_protocol | The protocol. Usable in the "sort" parameter. / The protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | Required | 
| service_post_port | The port number. Usable in the "sort" parameter. / The port number. Usable in the "q" parameter. Usable in the "sort" parameter. | Required | 
| service_post_subprotocols | The sub protocols. | Required | 
| service_post_connection_policy | The connection policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | Required | 
| service_post_global_domains | The global domains names. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-service-of-device

***
Get the service of a device.

#### Base Command

`wab-get-service-of-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| service_id | The service id or name. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.service_get.id | String | The service id. Usable in the "sort" parameter. | 
| WAB.service_get.service_name | String | The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "sort" parameter. / The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.protocol | String | The protocol. Usable in the "sort" parameter. / The protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.port | Number | The port number. Usable in the "sort" parameter. / The port number. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.connection_policy | String | The connection policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.service_get.global_domains | String | The global domains names. | 
| WAB.service_get.url | String | The API URL to the resource. | 

### wab-edit-service-of-device

***
Edit a service of a device.

#### Base Command

`wab-edit-service-of-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| service_id | The service id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the subprotocols, global_domains and additional_interfaces are replaced, otherwise the values are added to the existing ones. | Optional | 
| service_put_port | The port number. | Optional | 
| service_put_connection_policy | The connection policy name. | Optional | 
| service_put_global_domains | The global domains names. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-service-from-device

***
Delete a service from a device.

#### Base Command

`wab-delete-service-from-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name. | Required | 
| service_id | The service id or name. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-devices

***
Get the devices.

#### Base Command

`wab-get-devices`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'device_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.device_get.id | String | The device id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.device_name | String | The device name. \\ /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.description | String | The device description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.alias | String | The device alias. \\ /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.host | String | The device host address. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.last_connection | String | The last connection on this device.\(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.domain_name | String | The domain name. /:\*?"&lt;&gt;|@ are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.enable_password_change | Boolean | Enable the change of password on this domain. | 
| WAB.device_get.local_domains.admin_account | String | The administrator account used to change passwords on this domain \(format: "account_name"\). | 
| WAB.device_get.local_domains.password_change_policy | String | The name of password change policy for this domain. | 
| WAB.device_get.local_domains.password_change_plugin | String | The name of plugin used to change passwords on this domain. | 
| WAB.device_get.local_domains.ca_private_key | String | The ssh private key of the signing authority for the ssh keys for accounts in the domain. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.device_get.local_domains.ca_public_key | String | The ssh public key of the signing authority for the ssh keys for accounts in the domain. | 
| WAB.device_get.local_domains.url | String | The API URL to the resource. | 
| WAB.device_get.services.id | String | The service id. Usable in the "sort" parameter. | 
| WAB.device_get.services.service_name | String | The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "sort" parameter. / The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.protocol | String | The protocol. Usable in the "sort" parameter. / The protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.port | Number | The port number. Usable in the "sort" parameter. / The port number. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.connection_policy | String | The connection policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.global_domains | String | The global domains names. | 
| WAB.device_get.services.url | String | The API URL to the resource. | 
| WAB.device_get.tags.id | String | The tag id. | 
| WAB.device_get.tags.key | String | The tag key. Must not start or end with a space. | 
| WAB.device_get.tags.value | String | The tag value. Must not start or end with a space. | 
| WAB.device_get.onboard_status | String | Onboarding status of the device Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.first_seen.id | String | The scan job id. | 
| WAB.device_get.first_seen.type | String | Scan type. | 
| WAB.device_get.first_seen.error | String | Error message. | 
| WAB.device_get.first_seen.status | String | Scan job status. | 
| WAB.device_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.device_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.device_get.last_seen.id | String | The scan job id. | 
| WAB.device_get.last_seen.type | String | Scan type. | 
| WAB.device_get.last_seen.error | String | Error message. | 
| WAB.device_get.last_seen.status | String | Scan job status. | 
| WAB.device_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.device_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.device_get.url | String | The API URL to the resource. | 

### wab-add-device

***
Add a device.

#### Base Command

`wab-add-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_post_device_name | The device name. \ /:*?"&lt;&gt;\|@ and space are forbidden. | Required | 
| device_post_description | The device description. | Optional | 
| device_post_alias | The device alias. \ /:*?"&lt;&gt;\|@ and space are forbidden. | Optional | 
| device_post_host | The device host address. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-device

***
Get the device.

#### Base Command

`wab-get-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | A device id or name. If specified, only this device is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.device_get.id | String | The device id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.device_name | String | The device name. \\ /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.description | String | The device description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.alias | String | The device alias. \\ /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.host | String | The device host address. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.last_connection | String | The last connection on this device.\(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.domain_name | String | The domain name. /:\*?"&lt;&gt;|@ are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.local_domains.enable_password_change | Boolean | Enable the change of password on this domain. | 
| WAB.device_get.local_domains.admin_account | String | The administrator account used to change passwords on this domain \(format: "account_name"\). | 
| WAB.device_get.local_domains.password_change_policy | String | The name of password change policy for this domain. | 
| WAB.device_get.local_domains.password_change_plugin | String | The name of plugin used to change passwords on this domain. | 
| WAB.device_get.local_domains.ca_private_key | String | The ssh private key of the signing authority for the ssh keys for accounts in the domain. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.device_get.local_domains.ca_public_key | String | The ssh public key of the signing authority for the ssh keys for accounts in the domain. | 
| WAB.device_get.local_domains.url | String | The API URL to the resource. | 
| WAB.device_get.services.id | String | The service id. Usable in the "sort" parameter. | 
| WAB.device_get.services.service_name | String | The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "sort" parameter. / The service name. Must start with a letter; only letters, digits and -_ are allowed. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.protocol | String | The protocol. Usable in the "sort" parameter. / The protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.port | Number | The port number. Usable in the "sort" parameter. / The port number. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.connection_policy | String | The connection policy name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.services.global_domains | String | The global domains names. | 
| WAB.device_get.services.url | String | The API URL to the resource. | 
| WAB.device_get.tags.id | String | The tag id. | 
| WAB.device_get.tags.key | String | The tag key. Must not start or end with a space. | 
| WAB.device_get.tags.value | String | The tag value. Must not start or end with a space. | 
| WAB.device_get.onboard_status | String | Onboarding status of the device Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.device_get.first_seen.id | String | The scan job id. | 
| WAB.device_get.first_seen.type | String | Scan type. | 
| WAB.device_get.first_seen.error | String | Error message. | 
| WAB.device_get.first_seen.status | String | Scan job status. | 
| WAB.device_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.device_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.device_get.last_seen.id | String | The scan job id. | 
| WAB.device_get.last_seen.type | String | Scan type. | 
| WAB.device_get.last_seen.error | String | Error message. | 
| WAB.device_get.last_seen.status | String | Scan job status. | 
| WAB.device_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.device_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.device_get.url | String | The API URL to the resource. | 

### wab-edit-device

***
Edit a device.

#### Base Command

`wab-edit-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the tags are replaced, otherwise the values are added to the existing ones. | Optional | 
| device_put_device_name | The device name. \ /:*?"&lt;&gt;\|@ and space are forbidden. | Optional | 
| device_put_description | The device description. | Optional | 
| device_put_alias | The device alias. \ /:*?"&lt;&gt;\|@ and space are forbidden. | Optional | 
| device_put_host | The device host address. | Optional | 
| device_put_onboard_status | Onboarding status of the device. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-device

***
Delete a device.

#### Base Command

`wab-delete-device`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device_id | The device id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-accounts-of-global-domain

***
Get the accounts of a global domain.

#### Base Command

`wab-get-accounts-of-global-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The global domain id or name. | Required | 
| q | Searches for a resource matching parameters. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.domain_account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.credentials.id | String | The credential id. | 
| WAB.domain_account_get.credentials.type | String | The credential type. | 
| WAB.domain_account_get.credentials.password | String | The account password. | 
| WAB.domain_account_get.credentials.private_key | String | The account private key. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.domain_account_get.credentials.passphrase | String | The passphrase for the private key \(only for an encrypted private key\). If provided, it must be between 4 and 1024 characters long. | 
| WAB.domain_account_get.credentials.public_key | String | The account public key. | 
| WAB.domain_account_get.credentials.key_type | String | The key type. | 
| WAB.domain_account_get.credentials.key_len | Number | The key length. | 
| WAB.domain_account_get.credentials.key_id | String | The key identity: random value used for revocation. | 
| WAB.domain_account_get.credentials.certificate | String | The certificate. | 
| WAB.domain_account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.domain_account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.auto_change_ssh_key | Boolean | Automatically change the ssh key. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.domain_account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.first_seen.id | String | The scan job id. | 
| WAB.domain_account_get.first_seen.type | String | Scan type. | 
| WAB.domain_account_get.first_seen.error | String | Error message. | 
| WAB.domain_account_get.first_seen.status | String | Scan job status. | 
| WAB.domain_account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.domain_account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.domain_account_get.last_seen.id | String | The scan job id. | 
| WAB.domain_account_get.last_seen.type | String | Scan type. | 
| WAB.domain_account_get.last_seen.error | String | Error message. | 
| WAB.domain_account_get.last_seen.status | String | Scan job status. | 
| WAB.domain_account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.domain_account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.domain_account_get.url | String | The API URL to the resource. | 
| WAB.domain_account_get.resources | String | The account resources. | 

### wab-add-account-in-global-domain

***
Add an account in a global domain.

#### Base Command

`wab-add-account-in-global-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The global domain id or name. | Required | 
| domain_account_post_account_name | The account name. /:*?"&lt;&gt;\|@ and space are forbidden. | Required | 
| domain_account_post_account_login | The account login. | Required | 
| domain_account_post_description | The account description. | Optional | 
| domain_account_post_auto_change_password | Automatically change the password. It is enabled by default on a new account. | Optional | 
| domain_account_post_auto_change_ssh_key | Automatically change the ssh key. It is enabled by default on a new account. | Optional | 
| domain_account_post_checkout_policy | The account checkout policy. | Required | 
| domain_account_post_certificate_validity | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain. | Optional | 
| domain_account_post_can_edit_certificate_validity | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise. | Optional | 
| domain_account_post_resources | The account resources. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-account-of-global-domain

***
Get the account of a global domain.

#### Base Command

`wab-get-account-of-global-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The global domain id or name. | Required | 
| account_id | The account id or name. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.domain_account_get.id | String | The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.account_name | String | The account name. /:\*?"&lt;&gt;|@ and space are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.account_login | String | The account login. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.description | String | The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.credentials.id | String | The credential id. | 
| WAB.domain_account_get.credentials.type | String | The credential type. | 
| WAB.domain_account_get.credentials.password | String | The account password. | 
| WAB.domain_account_get.credentials.private_key | String | The account private key. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.domain_account_get.credentials.passphrase | String | The passphrase for the private key \(only for an encrypted private key\). If provided, it must be between 4 and 1024 characters long. | 
| WAB.domain_account_get.credentials.public_key | String | The account public key. | 
| WAB.domain_account_get.credentials.key_type | String | The key type. | 
| WAB.domain_account_get.credentials.key_len | Number | The key length. | 
| WAB.domain_account_get.credentials.key_id | String | The key identity: random value used for revocation. | 
| WAB.domain_account_get.credentials.certificate | String | The certificate. | 
| WAB.domain_account_get.domain_password_change | Boolean | True if the password change is configured on the domain \(change policy and plugin are set\). | 
| WAB.domain_account_get.auto_change_password | Boolean | Automatically change the password. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.auto_change_ssh_key | Boolean | Automatically change the ssh key. It is enabled by default on a new account. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.checkout_policy | String | The account checkout policy. Usable in the "q" parameter. | 
| WAB.domain_account_get.certificate_validity | String | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.can_edit_certificate_validity | Boolean | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.onboard_status | String | Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_account_get.first_seen.id | String | The scan job id. | 
| WAB.domain_account_get.first_seen.type | String | Scan type. | 
| WAB.domain_account_get.first_seen.error | String | Error message. | 
| WAB.domain_account_get.first_seen.status | String | Scan job status. | 
| WAB.domain_account_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.domain_account_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.domain_account_get.last_seen.id | String | The scan job id. | 
| WAB.domain_account_get.last_seen.type | String | Scan type. | 
| WAB.domain_account_get.last_seen.error | String | Error message. | 
| WAB.domain_account_get.last_seen.status | String | Scan job status. | 
| WAB.domain_account_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.domain_account_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.domain_account_get.url | String | The API URL to the resource. | 
| WAB.domain_account_get.resources | String | The account resources. | 

### wab-edit-account-in-global-domain

***
Edit an account in a global domain.

#### Base Command

`wab-edit-account-in-global-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The global domain id or name. | Required | 
| account_id | The account id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the credentials and services, if they are supplied, are replaced, otherwise the values are added to the existing ones. | Optional | 
| domain_account_put_account_name | The account name. /:*?"&lt;&gt;\|@ and space are forbidden. | Optional | 
| domain_account_put_account_login | The account login. | Optional | 
| domain_account_put_description | The account description. | Optional | 
| domain_account_put_auto_change_password | Automatically change the password. It is enabled by default on a new account. | Optional | 
| domain_account_put_auto_change_ssh_key | Automatically change the ssh key. It is enabled by default on a new account. | Optional | 
| domain_account_put_checkout_policy | The account checkout policy. | Optional | 
| domain_account_put_certificate_validity | The validity duration of the signed ssh public key in the case a Certificate Authority is defined for the account's domain. | Optional | 
| domain_account_put_can_edit_certificate_validity | True if the field 'certificate_validity' can be edited based the availibility of CA certificate on the account's domain, false otherwise. | Optional | 
| domain_account_put_onboard_status | Onboarding status of the account. | Optional | 
| domain_account_put_resources | The account resources. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-account-from-global-domain

***
Delete an account from a global domain.

#### Base Command

`wab-delete-account-from-global-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The global domain id or name. | Required | 
| account_id | The account id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-delete-resource-from-global-domain-account

***
delete a resource from the global domain account.

#### Base Command

`wab-delete-resource-from-global-domain-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | The global domain id or name. | Required | 
| account_id | The account id or name. | Required | 
| resource_name | The name of the resource to remove from the account. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-global-domains

***
Get the global domains.

#### Base Command

`wab-get-global-domains`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'domain_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.domain_get.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.domain_name | String | The domain name. /:\*?"&lt;&gt;|@ are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.domain_real_name | String | The domain name used for connection to a target. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.enable_password_change | Boolean | Enable the change of password on this domain. | 
| WAB.domain_get.admin_account | String | The administrator account used to change passwords on this domain \(format: "account_name"\). | 
| WAB.domain_get.kerberos.kdc | String | IP address or hostname the KDC. | 
| WAB.domain_get.kerberos.realm | String | The Kerberos realm. | 
| WAB.domain_get.kerberos.port | Number | The Kerberos port \(88 by default\). | 
| WAB.domain_get.password_change_policy | String | The name of password change policy for this domain. | 
| WAB.domain_get.password_change_plugin | String | The name of plugin used to change passwords on this domain. | 
| WAB.domain_get.ca_private_key | String | The ssh private key of the signing authority for the ssh keys for accounts in the domain. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.domain_get.ca_public_key | String | The ssh public key of the signing authority for the ssh keys for accounts in the domain. | 
| WAB.domain_get.vault_plugin | String | The name of vault plugin used to manage all accounts defined on this domain. | 
| WAB.domain_get.is_editable | Boolean | True if the domain is editable by the user who made the query. This might be slow to compute for a domain with many accounts if the user has limitations. | 
| WAB.domain_get.url | String | The API URL to the resource. | 

### wab-get-global-domain

***
Get the global domain.

#### Base Command

`wab-get-global-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain_id | A global domain id or name. If specified, only this domain is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.domain_get.id | String | The domain id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.domain_name | String | The domain name. /:\*?"&lt;&gt;|@ are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.domain_real_name | String | The domain name used for connection to a target. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.description | String | The domain description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.domain_get.enable_password_change | Boolean | Enable the change of password on this domain. | 
| WAB.domain_get.admin_account | String | The administrator account used to change passwords on this domain \(format: "account_name"\). | 
| WAB.domain_get.kerberos.kdc | String | IP address or hostname the KDC. | 
| WAB.domain_get.kerberos.realm | String | The Kerberos realm. | 
| WAB.domain_get.kerberos.port | Number | The Kerberos port \(88 by default\). | 
| WAB.domain_get.password_change_policy | String | The name of password change policy for this domain. | 
| WAB.domain_get.password_change_plugin | String | The name of plugin used to change passwords on this domain. | 
| WAB.domain_get.ca_private_key | String | The ssh private key of the signing authority for the ssh keys for accounts in the domain. Special values are allowed to automatically generate SSH key: "generate:RSA_1024", "generate:RSA_2048", "generate:RSA_4096", "generate:RSA_8192", "generate:DSA_1024", "generate:ECDSA_256", "generate:ECDSA_384", "generate:ECDSA_521", "generate:ED25519". | 
| WAB.domain_get.ca_public_key | String | The ssh public key of the signing authority for the ssh keys for accounts in the domain. | 
| WAB.domain_get.vault_plugin | String | The name of vault plugin used to manage all accounts defined on this domain. | 
| WAB.domain_get.is_editable | Boolean | True if the domain is editable by the user who made the query. This might be slow to compute for a domain with many accounts if the user has limitations. | 
| WAB.domain_get.url | String | The API URL to the resource. | 

### wab-get-ldap-users-of-domain

***
Get the LDAP users of a given domain.

#### Base Command

`wab-get-ldap-users-of-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A LDAP domain name. All users in this domain are returned. | Required | 
| last_connection | If set to true, the date of last connection is returned for each user returned. Be careful: this can slow down the request if a lot of users are returned. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.ldapuser_get.user_name | String | The user name. | 
| WAB.ldapuser_get.login | String | The user login. | 
| WAB.ldapuser_get.display_name | String | The displayed name. Usable in the "sort" parameter. | 
| WAB.ldapuser_get.email | String | The email address. | 
| WAB.ldapuser_get.preferred_language | String | The preferred language. | 
| WAB.ldapuser_get.groups | String | The groups containing this user. | 
| WAB.ldapuser_get.domain | String | The domain name. | 
| WAB.ldapuser_get.password | String | The password \(hidden with stars or empty\). | 
| WAB.ldapuser_get.ssh_public_key | String | The SSH public key. | 
| WAB.ldapuser_get.last_connection | String | The last connection of this user \(format: "yyyy-mm-dd hh:mm:ss", returned only if query string parameter "last_connection" is set to true\). | 
| WAB.ldapuser_get.url | String | The API URL to the resource. | 

### wab-get-ldap-user-of-domain

***
Get the LDAP user of a given domain.

#### Base Command

`wab-get-ldap-user-of-domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A LDAP domain name. All users in this domain are returned. | Required | 
| user_name | A user name. If specified, only this user is returned. | Required | 
| last_connection | If set to true, the date of last connection is returned for each user returned. Be careful: this can slow down the request if a lot of users are returned. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.ldapuser_get.user_name | String | The user name. | 
| WAB.ldapuser_get.login | String | The user login. | 
| WAB.ldapuser_get.display_name | String | The displayed name. Usable in the "sort" parameter. | 
| WAB.ldapuser_get.email | String | The email address. | 
| WAB.ldapuser_get.preferred_language | String | The preferred language. | 
| WAB.ldapuser_get.groups | String | The groups containing this user. | 
| WAB.ldapuser_get.domain | String | The domain name. | 
| WAB.ldapuser_get.password | String | The password \(hidden with stars or empty\). | 
| WAB.ldapuser_get.ssh_public_key | String | The SSH public key. | 
| WAB.ldapuser_get.last_connection | String | The last connection of this user \(format: "yyyy-mm-dd hh:mm:ss", returned only if query string parameter "last_connection" is set to true\). | 
| WAB.ldapuser_get.url | String | The API URL to the resource. | 

### wab-get-information-about-wallix-bastion-license

***
Get information about the WALLIX Bastion license.

#### Base Command

`wab-get-information-about-wallix-bastion-license`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.licenseinfo_get.evaluation | Boolean | License is the default evaluation license. | 
| WAB.licenseinfo_get.revoked | Boolean | Licenses are revoked. | 
| WAB.licenseinfo_get.legacy | Boolean | License is of legacy type. | 
| WAB.licenseinfo_get.product_name | String | Licensed product name. | 
| WAB.licenseinfo_get.functional_pack | String | Name of the license type. | 
| WAB.licenseinfo_get.add_ons | String | List of Add-ons. | 
| WAB.licenseinfo_get.universal_tunneling | Boolean | RAWTCP protocol usage is enabled. | 
| WAB.licenseinfo_get.ha | Boolean | High Availibility \(2 nodes\) option is enabled. | 
| WAB.licenseinfo_get.clustering | Boolean | Clustering 3\+ nodes option is enabled. | 
| WAB.licenseinfo_get.data_leak_prevention | Boolean | Data leak prevention option is enabled. | 
| WAB.licenseinfo_get.itsm | Boolean | Information technology service management option is enabled. | 
| WAB.licenseinfo_get.enterprise | Boolean | Enterprise license. | 
| WAB.licenseinfo_get.password_manager | Boolean | Password manager is enabled. | 
| WAB.licenseinfo_get.session_manager | Boolean | Session manager is enabled. | 
| WAB.licenseinfo_get.siem_enabled | Boolean | SIEM / Remote Syslog option is enabled. | 
| WAB.licenseinfo_get.externvault_enabled | Boolean | External Vaults option is enabled. | 
| WAB.licenseinfo_get.expiration_date | String | The license expiration date. | 
| WAB.licenseinfo_get.is_valid | Boolean | License is valid. | 
| WAB.licenseinfo_get.primary | Number | The current number of primary connections. | 
| WAB.licenseinfo_get.primary_max | Number | The max number of primary connections allowed by the license. | 
| WAB.licenseinfo_get.secondary | Number | The current number of secondary connections. | 
| WAB.licenseinfo_get.secondary_max | Number | The max number of secondary connections allowed by the license. | 
| WAB.licenseinfo_get.named_user | Number | The current number of named users. | 
| WAB.licenseinfo_get.named_user_max | Number | The maximum number of named users allowed by the license. | 
| WAB.licenseinfo_get.resource | Number | The current number of resources defined. | 
| WAB.licenseinfo_get.resource_max | Number | The max number of resources allowed by the license. | 
| WAB.licenseinfo_get.web_jumphost_concurrent_users | Number | The current number of concurrent jumphost users. | 
| WAB.licenseinfo_get.web_jumphost_concurrent_users_max | Number | The max number of concurrent jumphost users allowed by the license. | 
| WAB.licenseinfo_get.waapm | Number | The current number of WAAPM license used on the last 30 days. | 
| WAB.licenseinfo_get.waapm_max | Number | The max number of WAAPM license useable on one month. | 
| WAB.licenseinfo_get.pm_target | Number | The current number of PM targets. | 
| WAB.licenseinfo_get.pm_target_max | Number | The max number of PM targets allowed by the license. | 
| WAB.licenseinfo_get.sm_target | Number | The current number of SM targets. | 
| WAB.licenseinfo_get.sm_target_max | Number | The max number of SM targets allowed by the license. | 

### wab-post-logsiem

***
Write a message in /var/log/wabaudit.log and send it to the SIEM (if configured).

#### Base Command

`wab-post-logsiem`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| logsiem_post_application | The application name. | Required | 
| logsiem_post_message | The message to write. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-notifications

***
Get the notifications.

#### Base Command

`wab-get-notifications`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'notification_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.notification_get.id | String | The notification id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.notification_name | String | The notification name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.description | String | The notification description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.enabled | Boolean | Notification is enabled. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.type | String | Notification type. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.destination | String | Destination for notification; for the type "email", this is a list of recipient emails separated by ";". Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.language | String | The notification language \(in email\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.events | String | The list of events that will trigger a notification. | 
| WAB.notification_get.url | String | The API URL to the resource. | 

### wab-add-notification

***
Add a notification.

#### Base Command

`wab-add-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notification_post_notification_name | The notification name. | Required | 
| notification_post_description | The notification description. | Optional | 
| notification_post_enabled | Notification is enabled. | Required | 
| notification_post_type | Notification type. | Required | 
| notification_post_destination | Destination for notification; for the type "email", this is a list of recipient emails separated by ";". | Required | 
| notification_post_language | The notification language (in email). | Required | 
| notification_post_events | The list of events that will trigger a notification. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-notification

***
Get the notification.

#### Base Command

`wab-get-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notification_id | A notification id or name. If specified, only this notification is returned. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.notification_get.id | String | The notification id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.notification_name | String | The notification name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.description | String | The notification description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.enabled | Boolean | Notification is enabled. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.type | String | Notification type. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.destination | String | Destination for notification; for the type "email", this is a list of recipient emails separated by ";". Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.language | String | The notification language \(in email\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.notification_get.events | String | The list of events that will trigger a notification. | 
| WAB.notification_get.url | String | The API URL to the resource. | 

### wab-edit-notification

***
Edit a notification.

#### Base Command

`wab-edit-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notification_id | The notification id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the events are replaced, otherwise the values are added to the existing ones. | Optional | 
| notification_put_notification_name | The notification name. | Optional | 
| notification_put_description | The notification description. | Optional | 
| notification_put_enabled | Notification is enabled. | Optional | 
| notification_put_type | Notification type. | Optional | 
| notification_put_destination | Destination for notification; for the type "email", this is a list of recipient emails separated by ";". | Optional | 
| notification_put_language | The notification language (in email). | Optional | 
| notification_put_events | The list of events that will trigger a notification. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-notification

***
Delete a notification.

#### Base Command

`wab-delete-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| notification_id | The notification id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-object-to-onboard

***
Get object to onboard, by type (either devices with their linked accounts or global accounts alone).

#### Base Command

`wab-get-object-to-onboard`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| object_type | The type of object, one of : 'devices', 'global_accounts'. | Required | 
| object_status | The desired object status, one of: 'to_onboard', 'hide'. | Required | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'object name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.onboarding_objects_get.id | String | The device id. Usable in the "q" parameter. Usable in the "sort" parameter. / The account id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.onboarding_objects_get.description | String | The device description. Usable in the "q" parameter. Usable in the "sort" parameter. / The account description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.onboarding_objects_get.onboard_status | String | Onboarding status of the device Usable in the "q" parameter. Usable in the "sort" parameter. / Onboarding status of the account Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.onboarding_objects_get.first_seen.id | String | The scan job id. | 
| WAB.onboarding_objects_get.first_seen.type | String | Scan type. | 
| WAB.onboarding_objects_get.first_seen.error | String | Error message. | 
| WAB.onboarding_objects_get.first_seen.status | String | Scan job status. | 
| WAB.onboarding_objects_get.first_seen.start | String | Scan job start timestamp. | 
| WAB.onboarding_objects_get.first_seen.end | String | Scan job end timestamp. | 
| WAB.onboarding_objects_get.last_seen.id | String | The scan job id. | 
| WAB.onboarding_objects_get.last_seen.type | String | Scan type. | 
| WAB.onboarding_objects_get.last_seen.error | String | Error message. | 
| WAB.onboarding_objects_get.last_seen.status | String | Scan job status. | 
| WAB.onboarding_objects_get.last_seen.start | String | Scan job start timestamp. | 
| WAB.onboarding_objects_get.last_seen.end | String | Scan job end timestamp. | 
| WAB.onboarding_objects_get.url | String | The API URL to the resource. | 

### wab-get-profiles

***
Get the profiles.

#### Base Command

`wab-get-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'profile_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.profile_get.id | String | The profile id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.profile_name | String | The profile name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.description | String | The target group description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.gui_features.wab_audit | String | wab audit. | 
| WAB.profile_get.gui_features.system_audit | String | system audit. | 
| WAB.profile_get.gui_features.users | String | users. | 
| WAB.profile_get.gui_features.user_groups | String | user groups. | 
| WAB.profile_get.gui_features.devices | String | devices. | 
| WAB.profile_get.gui_features.target_groups | String | target groups. | 
| WAB.profile_get.gui_features.dashboards | String | dashboards. | 
| WAB.profile_get.gui_features.authorizations | String | authorizations. | 
| WAB.profile_get.gui_features.profiles | String | profiles. | 
| WAB.profile_get.gui_features.wab_settings | String | wab settings. | 
| WAB.profile_get.gui_features.system_settings | String | system settings. | 
| WAB.profile_get.gui_features.backup | String | backup. | 
| WAB.profile_get.gui_features.approval | String | approval. | 
| WAB.profile_get.gui_features.credential_recovery | String | credential recovery. | 
| WAB.profile_get.gui_transmission.system_audit | String | system audit. | 
| WAB.profile_get.gui_transmission.users | String | users. | 
| WAB.profile_get.gui_transmission.user_groups | String | user groups. | 
| WAB.profile_get.gui_transmission.devices | String | devices. | 
| WAB.profile_get.gui_transmission.target_groups | String | target groups. | 
| WAB.profile_get.gui_transmission.authorizations | String | authorizations. | 
| WAB.profile_get.gui_transmission.profiles | String | profiles. | 
| WAB.profile_get.gui_transmission.wab_settings | String | wab settings. | 
| WAB.profile_get.gui_transmission.system_settings | String | system settings. | 
| WAB.profile_get.gui_transmission.backup | String | backup. | 
| WAB.profile_get.gui_transmission.approval | String | approval. | 
| WAB.profile_get.gui_transmission.credential_recovery | String | credential recovery. | 
| WAB.profile_get.ip_limitation | String | The profile ip limitation. Format is an IPv4 address, subnet or host name, for example: 192.168.1.10/24 Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.target_access | Boolean | Target access. | 
| WAB.profile_get.url | String | The API URL to the resource. | 

### wab-get-profile

***
Get the profile.

#### Base Command

`wab-get-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| profile_id | A profile id or name. If specified, only this profile is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.profile_get.id | String | The profile id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.profile_name | String | The profile name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.description | String | The target group description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.gui_features.wab_audit | String | wab audit. | 
| WAB.profile_get.gui_features.system_audit | String | system audit. | 
| WAB.profile_get.gui_features.users | String | users. | 
| WAB.profile_get.gui_features.user_groups | String | user groups. | 
| WAB.profile_get.gui_features.devices | String | devices. | 
| WAB.profile_get.gui_features.target_groups | String | target groups. | 
| WAB.profile_get.gui_features.dashboards | String | dashboards. | 
| WAB.profile_get.gui_features.authorizations | String | authorizations. | 
| WAB.profile_get.gui_features.profiles | String | profiles. | 
| WAB.profile_get.gui_features.wab_settings | String | wab settings. | 
| WAB.profile_get.gui_features.system_settings | String | system settings. | 
| WAB.profile_get.gui_features.backup | String | backup. | 
| WAB.profile_get.gui_features.approval | String | approval. | 
| WAB.profile_get.gui_features.credential_recovery | String | credential recovery. | 
| WAB.profile_get.gui_transmission.system_audit | String | system audit. | 
| WAB.profile_get.gui_transmission.users | String | users. | 
| WAB.profile_get.gui_transmission.user_groups | String | user groups. | 
| WAB.profile_get.gui_transmission.devices | String | devices. | 
| WAB.profile_get.gui_transmission.target_groups | String | target groups. | 
| WAB.profile_get.gui_transmission.authorizations | String | authorizations. | 
| WAB.profile_get.gui_transmission.profiles | String | profiles. | 
| WAB.profile_get.gui_transmission.wab_settings | String | wab settings. | 
| WAB.profile_get.gui_transmission.system_settings | String | system settings. | 
| WAB.profile_get.gui_transmission.backup | String | backup. | 
| WAB.profile_get.gui_transmission.approval | String | approval. | 
| WAB.profile_get.gui_transmission.credential_recovery | String | credential recovery. | 
| WAB.profile_get.ip_limitation | String | The profile ip limitation. Format is an IPv4 address, subnet or host name, for example: 192.168.1.10/24 Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.profile_get.target_access | Boolean | Target access. | 
| WAB.profile_get.url | String | The API URL to the resource. | 

### wab-get-scanjobs

***
Get the scanjobs.

#### Base Command

`wab-get-scanjobs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'scan_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.scanjob_get.id | String | The scan job id. Usable in the "sort" parameter. | 
| WAB.scanjob_get.type | String | Scan type Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scanjob_get.error | String | Error message. | 
| WAB.scanjob_get.status | String | Scan job status Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scanjob_get.start | String | Scan job start timestamp. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scanjob_get.end | String | Scan job end timestamp Usable in the "q" parameter. Usable in the "sort" parameter. | 

### wab-start-scan-job-manually

***
Start a scan job manually.

#### Base Command

`wab-start-scan-job-manually`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanjob_post_scan_id | Scan definition id. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-scanjob

***
Get the scanjob.

#### Base Command

`wab-get-scanjob`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanjob_id | A scan job id or name. If specified, only this scan job is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.scanjob_get.id | String | The scan job id. Usable in the "sort" parameter. | 
| WAB.scanjob_get.type | String | Scan type Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scanjob_get.error | String | Error message. | 
| WAB.scanjob_get.status | String | Scan job status Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scanjob_get.start | String | Scan job start timestamp. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scanjob_get.end | String | Scan job end timestamp Usable in the "q" parameter. Usable in the "sort" parameter. | 

### wab-cancel-scan-job

***
Cancel a scan job.

#### Base Command

`wab-cancel-scan-job`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scanjob_id | The scan id or name to edit. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-scans

***
Get the scans.

#### Base Command

`wab-get-scans`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'scan_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.scan_get.id | String | The scan id. Usable in the "sort" parameter. | 
| WAB.scan_get.name | String | Scan name Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.active | Boolean | State of the job schedule. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.periodicity | String | Periodicity of the scan, in cron notation. Usable in the "q" parameter. | 
| WAB.scan_get.description | String | Description of the scan. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.emails | String | Emails to notify when a job is finished. | 
| WAB.scan_get.last_job.id | String | UID of the job. | 
| WAB.scan_get.last_job.status | String | status. | 
| WAB.scan_get.last_job.start | String | Timestamp of the job start. | 
| WAB.scan_get.last_job.end | String | Timestamp of the job end. | 
| WAB.scan_get.type | String | Scan type Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.url | String | The API URL to the resource. | 

### wab-get-scan

***
Get the scan.

#### Base Command

`wab-get-scan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scan_id | A scan id or name. If specified, only this scan is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.scan_get.id | String | The scan id. Usable in the "sort" parameter. | 
| WAB.scan_get.name | String | Scan name Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.active | Boolean | State of the job schedule. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.periodicity | String | Periodicity of the scan, in cron notation. Usable in the "q" parameter. | 
| WAB.scan_get.description | String | Description of the scan. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.emails | String | Emails to notify when a job is finished. | 
| WAB.scan_get.last_job.id | String | UID of the job. | 
| WAB.scan_get.last_job.status | String | status. | 
| WAB.scan_get.last_job.start | String | Timestamp of the job start. | 
| WAB.scan_get.last_job.end | String | Timestamp of the job end. | 
| WAB.scan_get.type | String | Scan type Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.scan_get.url | String | The API URL to the resource. | 

### wab-get-sessionrights

***
Get current user's or the user 'user_name' session rights (connections via proxies).

#### Base Command

`wab-get-sessionrights`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| count | The default value is false. When it is set to true, the headers x-total-count and x-filtered-count are returned. | Optional | 
| q | Only a simple string to search is allowed in this resource (for example: 'q=windows'). The search is performed on the following fields only: account, account_description, device, device_alias, device_description, application, application_description, service_protocol, domain, domain_description, authorization, authorization_description. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'account,domain,device,application'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.sessionrights_get.type | String | The resource type. | 
| WAB.sessionrights_get.account | String | The account name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.account_description | String | The account description. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.domain | String | The domain name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.domain_description | String | The domain description. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.service | String | The service name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.service_protocol | String | The protocol name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.authorization_approval | Boolean | True if an approval workflow is defined in the authorization, otherwise False. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.authorization | String | The authorization name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.authorization_description | String | The authorization description. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.account_mapping | Boolean | Account mapping. | 
| WAB.sessionrights_get.account_mapping_vault | Boolean | Account mapping with a vault account. | 
| WAB.sessionrights_get.interactive_login | Boolean | Interactive login. | 
| WAB.sessionrights_get.right_fingerprint | String | The fingerprint of the right \(hash of authorization and target uid\). | 

### wab-get-sessionrights-user-name

***
Get current user's or the user 'user_name' session rights (connections via proxies).

#### Base Command

`wab-get-sessionrights-user-name`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_name | If specified, the user_name session rights is returned. | Required | 
| count | The default value is false. When it is set to true, the headers x-total-count and x-filtered-count are returned. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.sessionrights_get.type | String | The resource type. | 
| WAB.sessionrights_get.account | String | The account name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.account_description | String | The account description. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.domain | String | The domain name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.domain_description | String | The domain description. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.service | String | The service name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.service_protocol | String | The protocol name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.authorization_approval | Boolean | True if an approval workflow is defined in the authorization, otherwise False. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.authorization | String | The authorization name. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.authorization_description | String | The authorization description. Usable in the "sort" parameter. | 
| WAB.sessionrights_get.account_mapping | Boolean | Account mapping. | 
| WAB.sessionrights_get.account_mapping_vault | Boolean | Account mapping with a vault account. | 
| WAB.sessionrights_get.interactive_login | Boolean | Interactive login. | 
| WAB.sessionrights_get.right_fingerprint | String | The fingerprint of the right \(hash of authorization and target uid\). | 

### wab-get-sessions

***
Get the sessions.

#### Base Command

`wab-get-sessions`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | A session id. If specified, only this session is returned. | Optional | 
| otp | User's OTP (One Time Password) If specified, only the session initiated with the provided OTP is returned. | Optional | 
| status | Status of sessions to return: "closed" for closed sessions (default) or "current" for current sessions. | Optional | 
| from_date | Return sessions from this date/time (format: "yyyy-mm-dd" or "yyyy-mm-dd hh:mm:ss"). | Optional | 
| to_date | Return sessions until this date/time (format: "yyyy-mm-dd" or "yyyy-mm-dd hh:mm:ss"). | Optional | 
| date_field | The field used for date comparison: "begin" for the start of session, "end" for the end of session. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'end,id' when status is 'closed', 'begin,id' when status is 'current'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.session_get.id | String | The session id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.begin | String | The beginning date/time of the session \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.end | String | The end date/time of the session \(format: "yyyy-mm-dd hh:mm:ss"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.username | String | The primary user name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.source_ip | String | The source IP. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.source_protocol | String | The source protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_account | String | The target account name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_effective_login | String | The effective login. | 
| WAB.session_get.target_account_domain | String | The target account domain name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_device | String | The target device name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_port | Number | The target port number Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_host | String | The target hostname or IP. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_effective_host | String | The effective target IP. | 
| WAB.session_get.target_service | String | The target service name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_protocol | String | The target protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.target_sub_protocol | String | The target sub-protocol. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.is_application | Boolean | The session is on an application. | 
| WAB.session_get.result | Boolean | The session is successful. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.killed | Boolean | The session has been killed. | 
| WAB.session_get.diagnostic | String | The diagnostic message. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.description | String | The session description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.title | String | The session title. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.is_recorded | Boolean | The session is recorded. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.is_critical | Boolean | The session is critical. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.session_trace_size | Number | Size of the session trace file, in bytes \(if -1, there is no trace file\). | 
| WAB.session_get.session_log_size | Number | Size of the session log file \(metadata\), in bytes \(if -1, there is no metadata file\). | 
| WAB.session_get.approval.id | String | The approval id. | 
| WAB.session_get.approval.user_name | String | The user name. | 
| WAB.session_get.approval.target_name | String | The target name.\(example: account@domain@device:service\). | 
| WAB.session_get.approval.creation | String | The creation date.\(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.session_get.approval.begin | String | The start date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.session_get.approval.end | String | The end date/time for connection.\(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.session_get.approval.duration | Number | The allowed connection time, in minutes. | 
| WAB.session_get.approval.ticket | String | The ticket reference. | 
| WAB.session_get.approval.comment | String | The request description. | 
| WAB.session_get.approval.email | String | The user email. | 
| WAB.session_get.approval.language | String | The user language code \(en, fr, ...\). | 
| WAB.session_get.approval.status | String | The approval status. | 
| WAB.session_get.approval.quorum | Number | The quorum to reach. | 
| WAB.session_get.approval.answers.approver_name | String | The user name of approver. | 
| WAB.session_get.approval.answers.date | String | The answer date \(format: "yyyy-mm-dd hh:mm"\). | 
| WAB.session_get.approval.answers.comment | String | The answer comment. | 
| WAB.session_get.approval.answers.approved | Boolean | Request approval \(true = accepted, false = rejected\). | 
| WAB.session_get.approval.timeout | Number | Timeout to initiate the first connection \(in minutes\). After that, the approval will be automatically closed. 0: no timeout. | 
| WAB.session_get.approval.authorization_name | String | The authorization name. | 
| WAB.session_get.approval.is_active | Boolean | The approval is active. | 
| WAB.session_get.approval.url | String | The API URL to the resource. | 
| WAB.session_get.user_group | String | Name of the user group in authorization used to make the session. Usable in the "sort" parameter. | 
| WAB.session_get.target_group | String | Name of the target group in authorization used to make the session. Usable in the "sort" parameter. | 
| WAB.session_get.owner | String | The node id which own this session. Usable in the "sort" parameter. | 
| WAB.session_get.target_session_id | String | The RDP target session id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.session_get.shared_session.id | String | The session id. | 
| WAB.session_get.shared_session.url | String | The API URL to the resource. | 
| WAB.session_get.auditor_sessions.id | String | The session id. | 
| WAB.session_get.auditor_sessions.url | String | The API URL to the resource. | 
| WAB.session_get.url | String | The API URL to the resource. | 

### wab-edit-session

***
Edit a session.

#### Base Command

`wab-edit-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | The session id to edit. | Required | 
| action | The action on the session: 'edit' to edit the session (default), 'kill' to kill the session. | Optional | 
| session_put_edit_description | The new session description. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-session-metadata

***
Get the metadata of one or multiple sessions.

#### Base Command

`wab-get-session-metadata`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_ids | The session id, multiple IDs can be separated by commas. | Required | 
| download | The default value is false. When it is set to true, the session metadata is sent as a file instead of JSON (recommended for large metadata). The download is possible only with a single session id. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.session_metadata_get.session_id | String | The session id. | 
| WAB.session_metadata_get.metadata | String | The session metadata content. | 

### wab-get-session-sharing-requests

***
Get session sharing requests.

#### Base Command

`wab-get-session-sharing-requests`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | A request id. If specified, only this request is returned. | Optional | 
| session_id | A session id. If specified, only the request linked to this session is returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.session_request_get.id | String | The request id. Usable in the "sort" parameter. | 
| WAB.session_request_get.session_id | String | The session id. Usable in the "sort" parameter. | 
| WAB.session_request_get.mode | String | The session sharing mode. | 
| WAB.session_request_get.context | String | The request context. | 
| WAB.session_request_get.status | String | The request status. | 
| WAB.session_request_get.creation_date | String | The request creation date/time \(format: "yyyy-mm-dd hh:mm:ss"\). | 
| WAB.session_request_get.expiration_date | String | The request expiration date/time \(format: "yyyy-mm-dd hh:mm:ss"\). | 
| WAB.session_request_get.guest_session_id | String | The guest session id. Usable in the "sort" parameter. | 
| WAB.session_request_get.guest_id | String | A Guest ID \(random if unknown invited guest\) or a username \(if known Bastion user\). Usable in the "sort" parameter. | 

### wab-create-session-request

***
Create a session request.

#### Base Command

`wab-create-session-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_request_post_session_id | The session id. | Required | 
| session_request_post_mode | The session sharing mode. | Required | 

#### Context Output

There is no context output for this command.

### wab-delete-pending-or-live-session-request

***
Delete a pending or a live session request.

#### Base Command

`wab-delete-pending-or-live-session-request`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | The session sharing request to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-latest-snapshot-of-running-session

***
Get the latest snapshot of a running session.

#### Base Command

`wab-get-latest-snapshot-of-running-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | The session id. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-status-of-trace-generation

***
Get the status of a trace generation.

#### Base Command

`wab-get-status-of-trace-generation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_id | The session id. | Required | 
| date | Generate the trace from this date/time (format: "yyyy-mm-dd hh:mm:ss"). | Optional | 
| duration | Duration of the trace to generate (in seconds). | Optional | 
| download | The default value is false. When it is set to true, the session trace is sent as a file instead of JSON output with the generation status. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.session_trace_get.session_id | String | The session id. | 
| WAB.session_trace_get.date | String | The starting date/time \(format: "yyyy-mm-dd hh:mm:ss"\). | 
| WAB.session_trace_get.duration | Number | The duration \(in seconds\). | 
| WAB.session_trace_get.status | String | The generation status. | 
| WAB.session_trace_get.reason | String | The error description \(only in case of error\). | 
| WAB.session_trace_get.progress_pct | Number | Progress \(percent\). | 
| WAB.session_trace_get.eta | Number | Estimated time before end of generation \(in seconds\). | 

### wab-generate-trace-for-session

***
Generate a trace for a session.

#### Base Command

`wab-generate-trace-for-session`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| session_trace_post_session_id | The session id. | Required | 
| session_trace_post_date | The starting date/time (format: "yyyy-mm-dd hh:mm:ss"). | Optional | 
| session_trace_post_duration | The duration (in seconds). | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-wallix-bastion-usage-statistics

***
Get the WALLIX Bastion usage statistics. If no from_date or to_date are supplied it will return the statistics for the last full calendar month.

#### Base Command

`wab-get-wallix-bastion-usage-statistics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_date | Get statistics from this date at midnight (format: "yyyy-mm-dd"). | Optional | 
| to_date | Get statistics until this date at 23:59:59 (format: "yyyy-mm-dd"). | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.statistics_get.from_date | String | Beginning of the interval \(format: "yyyy-mm-dd"\). | 
| WAB.statistics_get.to_date | String | End of the interval \(format: "yyyy-mm-dd"\). | 
| WAB.statistics_get.primary_connections.min | Number | Lowest simultaneous objects. | 
| WAB.statistics_get.primary_connections.average | Number | Average simultaneous objects. | 
| WAB.statistics_get.primary_connections.max | Number | Maximum simultaneous objects. | 
| WAB.statistics_get.secondary_connections.min | Number | Lowest simultaneous objects. | 
| WAB.statistics_get.secondary_connections.average | Number | Average simultaneous objects. | 
| WAB.statistics_get.secondary_connections.max | Number | Maximum simultaneous objects. | 
| WAB.statistics_get.device_count.min | Number | Lowest simultaneous objects. | 
| WAB.statistics_get.device_count.average | Number | Average simultaneous objects. | 
| WAB.statistics_get.device_count.max | Number | Maximum simultaneous objects. | 
| WAB.statistics_get.application_count.min | Number | Lowest simultaneous objects. | 
| WAB.statistics_get.application_count.average | Number | Average simultaneous objects. | 
| WAB.statistics_get.application_count.max | Number | Maximum simultaneous objects. | 

### wab-get-target-groups

***
Get the target groups.

#### Base Command

`wab-get-target-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| device | Return only the targetgroups this device belongs to. | Optional | 
| application | Return only the targetgroups this application belongs to. | Optional | 
| domain | Return only the targetgroups this domain belongs to. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'group_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.targetgroups_get.id | String | The target group id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.targetgroups_get.group_name | String | The target group name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.targetgroups_get.description | String | The target group description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.targetgroups_get.session.accounts.id | String | The target id. | 
| WAB.targetgroups_get.session.accounts.account | String | The account name. | 
| WAB.targetgroups_get.session.accounts.domain | String | The domain name. | 
| WAB.targetgroups_get.session.accounts.domain_type | String | The domain type: local or global. | 
| WAB.targetgroups_get.session.accounts.device | String | The device name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.session.accounts.service | String | The service name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.session.accounts.application | String | The application name \(null for a device or a global domain\). | 
| WAB.targetgroups_get.session.account_mappings.id | String | The target id. | 
| WAB.targetgroups_get.session.account_mappings.device | String | The device name \(null for an application\). | 
| WAB.targetgroups_get.session.account_mappings.service | String | The service name \(null for an application\). | 
| WAB.targetgroups_get.session.account_mappings.application | String | The application name \(null for a device\). | 
| WAB.targetgroups_get.session.interactive_logins.id | String | The target id. | 
| WAB.targetgroups_get.session.interactive_logins.device | String | The device name \(null for an application\). | 
| WAB.targetgroups_get.session.interactive_logins.service | String | The service name \(null for an application\). | 
| WAB.targetgroups_get.session.interactive_logins.application | String | The application name \(null for a device\). | 
| WAB.targetgroups_get.session.scenario_accounts.id | String | The target id. | 
| WAB.targetgroups_get.session.scenario_accounts.account | String | The account name. | 
| WAB.targetgroups_get.session.scenario_accounts.domain | String | The domain name. | 
| WAB.targetgroups_get.session.scenario_accounts.domain_type | String | The domain type: local or global. | 
| WAB.targetgroups_get.session.scenario_accounts.device | String | The device name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.session.scenario_accounts.application | String | The application name \(null for a device or a global domain\). | 
| WAB.targetgroups_get.password_retrieval.accounts.id | String | The target id. | 
| WAB.targetgroups_get.password_retrieval.accounts.account | String | The account name. | 
| WAB.targetgroups_get.password_retrieval.accounts.domain | String | The domain name. | 
| WAB.targetgroups_get.password_retrieval.accounts.domain_type | String | The domain type: local or global. | 
| WAB.targetgroups_get.password_retrieval.accounts.device | String | The device name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.password_retrieval.accounts.application | String | The application name \(null for a device or a global domain\). | 
| WAB.targetgroups_get.restrictions.id | String | The restriction id. | 
| WAB.targetgroups_get.restrictions.action | String | The restriction type. | 
| WAB.targetgroups_get.restrictions.rules | String | The restriction rules. | 
| WAB.targetgroups_get.restrictions.subprotocol | String | The restriction subprotocol. | 
| WAB.targetgroups_get.url | String | The API URL to the resource. | 

### wab-add-target-group

***
Add a target group.

#### Base Command

`wab-add-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| targetgroups_post_group_name | The target group name. | Required | 
| targetgroups_post_description | The target group description. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-target-group

***
Get the target group.

#### Base Command

`wab-get-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | A target group id or name. If specified, only this target group is returned. | Required | 
| device | Return only the targetgroups this device belongs to. | Optional | 
| application | Return only the targetgroups this application belongs to. | Optional | 
| domain | Return only the targetgroups this domain belongs to. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.targetgroups_get.id | String | The target group id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.targetgroups_get.group_name | String | The target group name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.targetgroups_get.description | String | The target group description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.targetgroups_get.session.accounts.id | String | The target id. | 
| WAB.targetgroups_get.session.accounts.account | String | The account name. | 
| WAB.targetgroups_get.session.accounts.domain | String | The domain name. | 
| WAB.targetgroups_get.session.accounts.domain_type | String | The domain type: local or global. | 
| WAB.targetgroups_get.session.accounts.device | String | The device name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.session.accounts.service | String | The service name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.session.accounts.application | String | The application name \(null for a device or a global domain\). | 
| WAB.targetgroups_get.session.account_mappings.id | String | The target id. | 
| WAB.targetgroups_get.session.account_mappings.device | String | The device name \(null for an application\). | 
| WAB.targetgroups_get.session.account_mappings.service | String | The service name \(null for an application\). | 
| WAB.targetgroups_get.session.account_mappings.application | String | The application name \(null for a device\). | 
| WAB.targetgroups_get.session.interactive_logins.id | String | The target id. | 
| WAB.targetgroups_get.session.interactive_logins.device | String | The device name \(null for an application\). | 
| WAB.targetgroups_get.session.interactive_logins.service | String | The service name \(null for an application\). | 
| WAB.targetgroups_get.session.interactive_logins.application | String | The application name \(null for a device\). | 
| WAB.targetgroups_get.session.scenario_accounts.id | String | The target id. | 
| WAB.targetgroups_get.session.scenario_accounts.account | String | The account name. | 
| WAB.targetgroups_get.session.scenario_accounts.domain | String | The domain name. | 
| WAB.targetgroups_get.session.scenario_accounts.domain_type | String | The domain type: local or global. | 
| WAB.targetgroups_get.session.scenario_accounts.device | String | The device name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.session.scenario_accounts.application | String | The application name \(null for a device or a global domain\). | 
| WAB.targetgroups_get.password_retrieval.accounts.id | String | The target id. | 
| WAB.targetgroups_get.password_retrieval.accounts.account | String | The account name. | 
| WAB.targetgroups_get.password_retrieval.accounts.domain | String | The domain name. | 
| WAB.targetgroups_get.password_retrieval.accounts.domain_type | String | The domain type: local or global. | 
| WAB.targetgroups_get.password_retrieval.accounts.device | String | The device name \(null for an application or a global domain\). | 
| WAB.targetgroups_get.password_retrieval.accounts.application | String | The application name \(null for a device or a global domain\). | 
| WAB.targetgroups_get.restrictions.id | String | The restriction id. | 
| WAB.targetgroups_get.restrictions.action | String | The restriction type. | 
| WAB.targetgroups_get.restrictions.rules | String | The restriction rules. | 
| WAB.targetgroups_get.restrictions.subprotocol | String | The restriction subprotocol. | 
| WAB.targetgroups_get.url | String | The API URL to the resource. | 

### wab-edit-target-group

***
Edit a target group.

#### Base Command

`wab-edit-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The group id or name to edit. | Required | 
| force | The default value is false. When it is set to true the values of the targets are replaced, otherwise the values are added to the existing ones. | Optional | 
| targetgroups_put_group_name | The target group name. | Optional | 
| targetgroups_put_description | The target group description. | Optional | 

#### Context Output

There is no context output for this command.

### wab-delete-target-group

***
Delete a target group.

#### Base Command

`wab-delete-target-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The group id or name to delete. | Required | 

#### Context Output

There is no context output for this command.

### wab-delete-target-from-group

***
Delete a target from a group.

#### Base Command

`wab-delete-target-from-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | The group id or name to delete. | Required | 
| target_type | The type of target group, one of: 'session_accounts', 'session_account_mappings', 'session_interactive_logins', 'session_scenario_accounts', 'password_retrieval_accounts'. | Required | 
| target_id | The target id or name to remove from the group. | Required | 

#### Context Output

There is no context output for this command.

### wab-get-user-groups

***
Get the user groups.

#### Base Command

`wab-get-user-groups`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'group_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.usergroups_get.id | String | The group id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.usergroups_get.group_name | String | The group name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.usergroups_get.profile | String | The group profile. | 
| WAB.usergroups_get.description | String | The group description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.usergroups_get.timeframes | String | The group timeframe\(s\). | 
| WAB.usergroups_get.users | String | The users in the group. | 
| WAB.usergroups_get.restrictions.id | String | The restriction id. | 
| WAB.usergroups_get.restrictions.action | String | The restriction type. | 
| WAB.usergroups_get.restrictions.rules | String | The restriction rules. | 
| WAB.usergroups_get.restrictions.subprotocol | String | The restriction subprotocol. | 
| WAB.usergroups_get.url | String | The API URL to the resource. | 

### wab-get-user-group

***
Get the user group.

#### Base Command

`wab-get-user-group`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | A user group id or name. If specified, only this user group is returned. | Required | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.usergroups_get.id | String | The group id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.usergroups_get.group_name | String | The group name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.usergroups_get.profile | String | The group profile. | 
| WAB.usergroups_get.description | String | The group description. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.usergroups_get.timeframes | String | The group timeframe\(s\). | 
| WAB.usergroups_get.users | String | The users in the group. | 
| WAB.usergroups_get.restrictions.id | String | The restriction id. | 
| WAB.usergroups_get.restrictions.action | String | The restriction type. | 
| WAB.usergroups_get.restrictions.rules | String | The restriction rules. | 
| WAB.usergroups_get.restrictions.subprotocol | String | The restriction subprotocol. | 
| WAB.usergroups_get.url | String | The API URL to the resource. | 

### wab-get-users

***
Get the users.

#### Base Command

`wab-get-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| password_hash | Export password hash if true. In Configuration Options menu &gt; REST API then Advanced options, you should set User password hash and change the default Data encryption key. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'user_name'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.user_get.user_name | String | The user name. /:\*?"&lt;&gt;| are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.display_name | String | The displayed name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.email | String | The email address. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.ip_source | String | The source IP to limit access. Format is a comma-separated list of IPv4 or IPV6 addresses, subnets, ranges or domain, for example: 1.2.3.4,2001:db8::1234:5678,192.168.1.10/24,10.11.12.13-14.15.16.17,example.com Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.preferred_language | String | The preferred language. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.profile | String | The user profile. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.groups | String | The groups containing this user. | 
| WAB.user_get.user_auths | String | The authentication procedures\(s\). | 
| WAB.user_get.password | String | The password \(hidden with stars or empty\). | 
| WAB.user_get.force_change_pwd | Boolean | Force password change. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.ssh_public_key | String | The SSH public key. | 
| WAB.user_get.certificate_dn | String | The certificate DN \(for X509 authentication\). Usable in the "sort" parameter. | 
| WAB.user_get.last_connection | String | The last connection of this user. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.is_locked | Boolean | Account is locked. | 
| WAB.user_get.expiration_date | String | Account expiration date/time \(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.is_disabled | Boolean | Account is disabled. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.url | String | The API URL to the resource. | 
| WAB.user_get.gpg_public_key | String | The GPG public key fingerprint. | 

### wab-add-user

***
Add a user.

#### Base Command

`wab-add-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| password_hash | Set password hash if true. In Configuration Options menu &gt; REST API then Advanced options, you should set User password hash and change the default Data encryption key. | Optional | 
| user_post_user_name | The user name. /:*?"&lt;&gt;\| are forbidden. | Required | 
| user_post_display_name | The displayed name. | Optional | 
| user_post_email | The email address. | Required | 
| user_post_ip_source | The source IP to limit access. Format is a comma-separated list of IPv4 or IPV6 addresses, subnets, ranges or domain, for example: 1.2.3.4,2001:db8::1234:5678,192.168.1.10/24,10.11.12.13-14.15.16.17,example.com. | Optional | 
| user_post_preferred_language | The preferred language. | Optional | 
| user_post_profile | The user profile. | Required | 
| user_post_groups | The groups containing this user. | Optional | 
| user_post_user_auths | The authentication procedures(s). | Required | 
| user_post_password | The password. | Optional | 
| user_post_force_change_pwd | Force password change. | Optional | 
| user_post_ssh_public_key | The SSH public key. | Optional | 
| user_post_certificate_dn | The certificate DN (for X509 authentication). | Optional | 
| user_post_last_connection | The last connection of this user. | Optional | 
| user_post_expiration_date | Account expiration date/time (format: "yyyy-mm-dd hh:mm"). | Optional | 
| user_post_is_disabled | Account is disabled. | Optional | 
| user_post_gpg_public_key | The GPG public key (ascii output from the command: 'gpg --armor --export [USER_ID]'). | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-user

***
Get the user.

#### Base Command

`wab-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A user name. If specified, only this user is returned. | Required | 
| password_hash | Export password hash if true. In Configuration Options menu &gt; REST API then Advanced options, you should set User password hash and change the default Data encryption key. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.user_get.user_name | String | The user name. /:\*?"&lt;&gt;| are forbidden. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.display_name | String | The displayed name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.email | String | The email address. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.ip_source | String | The source IP to limit access. Format is a comma-separated list of IPv4 or IPV6 addresses, subnets, ranges or domain, for example: 1.2.3.4,2001:db8::1234:5678,192.168.1.10/24,10.11.12.13-14.15.16.17,example.com Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.preferred_language | String | The preferred language. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.profile | String | The user profile. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.groups | String | The groups containing this user. | 
| WAB.user_get.user_auths | String | The authentication procedures\(s\). | 
| WAB.user_get.password | String | The password \(hidden with stars or empty\). | 
| WAB.user_get.force_change_pwd | Boolean | Force password change. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.ssh_public_key | String | The SSH public key. | 
| WAB.user_get.certificate_dn | String | The certificate DN \(for X509 authentication\). Usable in the "sort" parameter. | 
| WAB.user_get.last_connection | String | The last connection of this user. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.is_locked | Boolean | Account is locked. | 
| WAB.user_get.expiration_date | String | Account expiration date/time \(format: "yyyy-mm-dd hh:mm"\). Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.is_disabled | Boolean | Account is disabled. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.user_get.url | String | The API URL to the resource. | 
| WAB.user_get.gpg_public_key | String | The GPG public key fingerprint. | 

### wab-get-password-for-target

***
Get the password for a given target.

#### Base Command

`wab-get-password-for-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | A target name: 'account@domain@device' for an account on a device, 'account@domain@application' for an account on an application or 'account@domain' for an account on a global domain. | Required | 
| key_format | The format of the SSH private key returned: 'openssh' (by default) or 'putty'. | Optional | 
| cert_format | The format of the returned certificate: 'openssh' (by default) or 'ssh.com'. | Optional | 
| authorization | The name of the authorization (in case of multiple authorizations to access the target). | Optional | 
| duration | Optional duration for the checkout (in seconds). It is used only in case of lock in the checkout policy, and it must be less than the checkout policy duration. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.targetpasswords_get_checkout.checkin_time | String | The date/time of automatic checkin on the account \(if no manual checkin is made until this date/time\). | 
| WAB.targetpasswords_get_checkout.locked | Boolean | True if the account has been locked \(a manual or automatic checkin is required\), False if the account is not locked \(checkin is then forbidden on this account\). | 
| WAB.targetpasswords_get_checkout.checkin_change_password | Boolean | True if the password will be automatically changed on checkin, False if the password is unchanged. | 
| WAB.targetpasswords_get_checkout.login | String | The account login. | 
| WAB.targetpasswords_get_checkout.password | String | The account password. | 
| WAB.targetpasswords_get_checkout.ssh_key | String | The account SSH private key. | 
| WAB.targetpasswords_get_checkout.ssh_certificate | String | The account SSH signed certificate. | 
| WAB.targetpasswords_get_checkout.deconnection_time | String | The date/time of automatic deconnection when the account is used in a proxy session. | 

### wab-extend-duration-time-to-get-passwords-for-target

***
Extend the duration time to get the passwords for a given target.

#### Base Command

`wab-extend-duration-time-to-get-passwords-for-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | A target name: 'account@domain@device' for an account on a device, 'account@domain@application' for an account on an application or 'account@domain' for an account on a global domain. | Required | 
| authorization | The name of the authorization (in case of multiple authorizations to access the target). | Optional | 

#### Context Output

There is no context output for this command.

### wab-release-passwords-for-target

***
Release the passwords for a given target.

#### Base Command

`wab-release-passwords-for-target`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_name | A target name: 'account@domain@device' for an account on a device, 'account@domain@application' for an account on an application or 'account@domain' for an account on a global domain. | Required | 
| authorization | The name of the authorization (in case of multiple authorizations to access the target). | Optional | 
| force | The default value is false. When it is set to true, the checkin is forced. The user connected on the REST API must have an auditor profile and the configured limitations don't prohibit access to the account. | Optional | 
| comment | A comment that is input by the auditor when an account checkin is forced. This argument is mandatory if the checkin is forced, and is ignored for a standard checkin. | Optional | 

#### Context Output

There is no context output for this command.

### wab-get-target-by-type

***
Get the target by type.

#### Base Command

`wab-get-target-by-type`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| target_type | The type of target, one of: 'session_accounts', 'session_account_mappings', 'session_interactive_logins', 'session_scenario_accounts', 'password_retrieval_accounts'. | Required | 
| group | Return only the targets in the group with this name. | Optional | 
| group_id | Return only the targets in the group with this id. | Optional | 
| q | Searches for a resource matching parameters. | Optional | 
| sort | Comma-separated list of fields used to sort results; a field starting "-" reverses the order. The default sort for this resource is: 'account,domain'. | Optional | 
| offset | The index of first item to retrieve (starts and defaults to 0). | Optional | 
| limit | The number of items to retrieve (100 by default, -1 = no limit). Note: this default value of 100 can be changed in the REST API configuration option. | Optional | 
| fields | The list of fields to return (separated by commas). By default all fields are returned. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| WAB.getTargetByType.id | String | The target id. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.getTargetByType.account | String | The device or application account name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.getTargetByType.domain | String | The domain name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.getTargetByType.domain_type | String | The domain type. | 
| WAB.getTargetByType.device | String | The device name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.getTargetByType.service | String | The service name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
| WAB.getTargetByType.application | String | The application name. Usable in the "q" parameter. Usable in the "sort" parameter. | 
