The XSOAR Engineer Training (XET) integration provides sample data to fetch events into Cortex XSOAR, and commands to build playbooks around.

Use for training purposes only.
This integration was integrated and tested with versions 6.9+ and 8.3 of XSOAR.

## Configure XSOAR Engineer Training in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Fetch incidents | False |
| Incident type | False |
| Incidents Fetch Interval | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
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
#### Command example
```!xet-get-events```
#### Human Readable Output

>### Training Events
>|eventID|occurred|sourceIP|sourceUser|type|url|urlCategory|userAgent|
>|---|---|---|---|---|---|---|---|
>| 4218 | 2023-10-04T21:30:06Z | 10.8.8.8 | m@xsoar.local | url blocked | https:<span>//</span>xsoar.pan.dev/52/download.zip | MALWARE | Mozilla/5.0(WindowsNT6.1;WOW64;rv:27.0)Gecko/20100101Firefox/27.0 |


### xet-ad-get-user

***
Retrieves detailed information about a user account. The user can be specified by username, email address, or as an Active Directory Distinguished Name (DN).

#### Base Command

`xet-ad-get-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| dn | The Distinguished Name of the user in which to return information. | Optional | 
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

#### Command example
```!xet-ad-get-user email="james.bond@xsoar.local"```
#### Context Example
```json
{
    "Account": {
        "DisplayName": [
            "James Bond"
        ],
        "Email": [
            "james.bond@xsoar.local"
        ],
        "Groups": [
            "CN=Agents,CN=Users,DC=xsoar,DC=local"
        ],
        "ID": "CN=James Bond,CN=Users,DC=xsoar,DC=local",
        "Manager": [
            "CN=M,CN=Users,DC=xsoar,DC=local"
        ],
        "Type": "AD",
        "Username": [
            "XSOAR007"
        ]
    },
    "ActiveDirectory": {
        "Users": {
            "displayName": [
                "James Bond"
            ],
            "dn": "CN=James Bond,CN=Users,DC=xsoar,DC=local",
            "mail": [
                "james.bond@xsoar.local"
            ],
            "manager": [
                "CN=M,CN=Users,DC=xsoar,DC=local"
            ],
            "memberOf": [
                "CN=Agents,CN=Users,DC=xsoar,DC=local"
            ],
            "name": [
                "James Bond"
            ],
            "sAMAccountName": [
                "XSOAR007"
            ],
            "userAccountControl": [
                512
            ]
        }
    }
}
```

#### Human Readable Output

>### Active Directory - Get Users
>|displayName|dn|mail|manager|memberOf|name|sAMAccountName|userAccountControl|
>|---|---|---|---|---|---|---|---|
>| James Bond | CN=James Bond,CN=Users,DC=xsoar,DC=local | james.bond@xsoar.local | CN=M,CN=Users,DC=xsoar,DC=local | CN=Agents,CN=Users,DC=xsoar,DC=local | James Bond | XSOAR007 | 512 |


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
#### Command example
```!xet-ad-expire-password username="XSOAR007"```
#### Human Readable Output

>Expired password successfully

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
#### Command example
```!xet-ad-set-new-password username="XSOAR007" password="bondjamesbond"```
#### Human Readable Output

>User password successfully set

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
| SIEM.Result | unknown | The results of the SIEM search. The results are a JSON array, in which each item is a SIEM event. | 

#### Command example
```!xet-siem-search query="host:crossiscoming81"```
#### Human Readable Output

>### SIEM Search results for query: host:crossiscoming81
>**No entries.**


### xet-send-mail

***
Send an email. (Doesn't actually send an email.)

#### Base Command

`xet-send-mail`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| to | Who to send the fake email to. | Required | 
| body | The body of the fake email that we are not actually sending. | Required | 

#### Context Output

There is no context output for this command.
#### Command example
```!xet-send-mail to="james.bond@xsoar.local" body="shaken or stirred?"```
#### Human Readable Output

>XSOAR Engineer Training: fake email notification not sent