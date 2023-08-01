Active Directory Query integration enables you to access and manage Active Directory objects (users, contacts, and computers).
## Configure Active Directory Query v2 (XSOAR Engineer Training) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Active Directory Query v2 (XSOAR Engineer Training).
3. Click **Add instance** to create and configure a new integration instance.

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### ad-expire-password

***
Expires the password of an Active Directory user.

#### Base Command

`ad-expire-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required | 
| base-dn | Root (e.g., DC=domain,DC=com). | Optional | 

#### Context Output

There is no context output for this command.
### ad-unlock-account

***
Unlocks a previously locked Active Directory user account.

#### Base Command

`ad-unlock-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to unlock (sAMAccountName). | Required | 
| base-dn | Root. For example, DC=domain,DC=com. By default, the Base DN configured for the instance is used. | Optional | 

#### Context Output

There is no context output for this command.
### ad-set-new-password

***
Sets a new password for an Active Directory user. This command requires a secure connection (SSL,TLS).

#### Base Command

`ad-set-new-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to disable (sAMAccountName). | Required | 
| password | The password to set for the user. | Required | 
| base-dn | Root. For example, DC=domain,DC=com. Base DN configured for the instance is used as default. | Optional | 

#### Context Output

There is no context output for this command.
### ad-get-user

***
Retrieves detailed information about a user account. The user can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filter is specified, all users are returned.

#### Base Command

`ad-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The Distinguished Name of the user in which to return information. | Optional | 
| name | The name of the user to return information. | Optional | 
| attributes | Adds AD attributes of the resulting objects to the default attributes. | Optional | 
| custom-field-type | Queries users by custom field type. | Optional | 
| custom-field-data | Queries users by custom field data (relevant only if the `custom-field-type` argument is provided). | Optional | 
| username | Queries users by the samAccountName attribute. | Optional | 
| limit | The maximum number of objects to return. Default is 20. Default is 20. | Optional | 
| email | Queries by the user's email address. | Optional | 
| user-account-control-out | Whether to include verbose translation for UserAccountControl flags. Default is false. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Users.dn | string | The distinguished name of the user. | 
| ActiveDirectory.Users.displayName | string | The display name of the user. | 
| ActiveDirectory.Users.name | string | The common name of the user. | 
| ActiveDirectory.Users.sAMAccountName | string | The sAMAccountName of the user. | 
| ActiveDirectory.Users.userAccountControl | number | The account control flag of the user. | 
| ActiveDirectory.Users.mail | string | The email address of the user. | 
| ActiveDirectory.Users.manager | string | The manager of the user. | 
| ActiveDirectory.Users.memberOf | string | Groups for which the user is a member. | 
| Account.DisplayName | string | The display name of the user. | 
| Account.Groups | string | Groups for which the user is a member. | 
| Account.Manager | string | The manager of the user. | 
| Account.ID | string | The distinguished name of the user. | 
| Account.Username | string | The samAccountName of the user. | 
| Account.Email | string | The email address of the user. | 
