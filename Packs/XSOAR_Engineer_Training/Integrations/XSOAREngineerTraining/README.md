The XSOAR Engineer Training (XET) integration provides sample data to fetch events into Cortex XSOAR, and commands to build playbooks around.

Use for training purposes only. 

## Configure XSOAR Engineer Training on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for XSOAR Engineer Training.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Fetch incidents | False |
    | Incident type | False |
    | Incidents Fetch Interval | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### xet-get-events

***
Fetches events from the XSOAR Engineer Training (XET) integration.

#### Base Command

`xet-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### xet-ad-get-user

***
Retrieves detailed information about a user account. The user can be specified by username, email address, or as an Active Directory Distinguished Name (DN).

#### Base Command

`xet-ad-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The Distinguished Name of the user for which to return information. | Optional | 
| username | Queries users by the samAccountName attribute. | Optional | 
| email | Queries by the user's email address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Users.dn | unknown | The Distinguished Name of the user. | 
| ActiveDirectory.Users.displayName | unknown | The display name of the user. | 
| ActiveDirectory.Users.name | unknown | The common name of the user. | 
| ActiveDirectory.Users.sAMAccountName | unknown | The sAMAccountName of the user. | 
| ActiveDirectory.Users.userAccountControl | unknown | The account control flag of the user. | 
| ActiveDirectory.Users.mail | unknown | The email address of the user. | 
| ActiveDirectory.Users.manager | unknown | The manager of the user. | 
| ActiveDirectory.Users.memberOf | unknown | Groups for which the user is a member. | 
| Account.DisplayName | unknown | The display name of the user. | 
| Account.Groups | unknown | Groups for which the user is a member. | 
| Account.Manager | unknown | The manager of the user. | 
| Account.ID | unknown | The Distinguished Name of the user. | 
| Account.Username | unknown | The samAccountName of the user. | 
| Account.Email | unknown | The email address of the user. | 

### xet-ad-expire-password

***
Expires the password of an Active Directory user.

#### Base Command

`xet-ad-expire-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required | 

#### Context Output

There is no context output for this command.

### xet-ad-set-new-password

***
Sets a new password for an Active Directory user.

#### Base Command

`xet-ad-set-new-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to disable (sAMAccountName). | Required | 
| password | The password to set for the user. | Required | 

#### Context Output

There is no context output for this command.

### xet-siem-search

***
Searches the simulated SIEM for events.

#### Base Command

`xet-siem-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to execute against the SIEM. | Required | 
| result_type | Type of result to return for this SIEM integration. Possible values are: email, hosts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SIEM.Result | array | The results of the SIEM search. The results are a JSON array, in which each item is a SIEM event. | 

### xet-send-mail

***
Send an email. (Doesn't actually send an email.)

#### Base Command

`xet-send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Who to send the fake email to. | Required | 

#### Context Output

There is no context output for this command.
