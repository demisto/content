This integration provides sample data to fetch events into XSOAR, and commands to build playbooks around.

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

### xsoar-engineer-get-events

***
Fetches events for all clicks and messages relating to known threats within the specified time period. Details as per clicks/blocked.

#### Base Command

`xsoar-engineer-get-events`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.

### ad-get-user

***
Retrieves detailed information about a user account. The user can be specified by username, email address, or as an Active Directory Distinguished Name (DN).

#### Base Command

`ad-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The Distinguished Name of the user in which to return information. | Optional | 
| username | Queries users by the samAccountName attribute. | Optional | 
| email | Queries by the user's email address. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| ActiveDirectory.Users.dn | unknown | The distinguished name of the user. | 
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
| Account.ID | unknown | The distinguished name of the user. | 
| Account.Username | unknown | The samAccountName of the user. | 
| Account.Email | unknown | The email address of the user. | 

### ad-expire-password

***
Expires the password of an Active Directory user.

#### Base Command

`ad-expire-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username (samAccountName) of the user to modify. | Required | 

#### Context Output

There is no context output for this command.

### ad-set-new-password

***
Sets a new password for an Active Directory user.

#### Base Command

`ad-set-new-password`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The username of the account to disable (sAMAccountName). | Required | 
| password | The password to set for the user. | Required | 

#### Context Output

There is no context output for this command.

### siem-search

***
Searches the simulated SIEM for events.

#### Base Command

`siem-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The query to execute against the SIEM. | Required | 
| result_type | Type of result to return for this siem integration. Possible values are: email, hosts. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SIEM.Result | unknown | The results of the SIEM search. The results are a JSON array, in which each item is a SIEM event. | 

### send-mail

***
Send an email (doesn't actually send an email)

#### Base Command

`send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Who to send the fake email to. | Required | 

#### Context Output

There is no context output for this command.
