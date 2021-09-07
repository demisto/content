Integrates with the PingOne Management API to unlock, create, delete and update users.  
This integration was integrated and tested with version xx of PingOne

## Configure PingOne on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for PingOne.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your PingOne Environment ID | Environment ID is available under the PingOne Dashboard-&amp;gt;Environment Properties | True |
    | PingOne Region | PingOne has 3 regions, US, EU and Asia | True |
    | Client ID |  | True |
    | Client Secret |  | True |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). | False |
    | Use system proxy settings | Use system proxy settings. | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### pingone-unlock-user
***
Unlock an user's account


#### Base Command

`pingone-unlock-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to unlock. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-unlock-user username=emma.sharp```

#### Human Readable Output

>### emma.sharp unlocked

### pingone-deactivate-user
***
Deactivate an user's account


#### Base Command

`pingone-deactivate-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to deactivate . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-deactivate-user username=emma.sharp```

#### Human Readable Output

>### User emma.sharp deactivated

### pingone-activate-user
***
Activate an user's account


#### Base Command

`pingone-activate-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username to activate . | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-activate-user username=emma.sharp```

#### Human Readable Output

>### emma.sharp is active now

### pingone-set-password
***
Sets an user's password


#### Base Command

`pingone-set-password`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Required | 
| password | Password. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-set-password username=emma.sharp password=OnePing123!```

#### Human Readable Output

>emma.sharp password was updated.

### pingone-add-to-group
***
Add user to group


#### Base Command

`pingone-add-to-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username . | Optional | 
| groupName | Group Name. | Optional | 
| groupId | Group ID. | Optional | 
| userId | User ID. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-add-to-group username=richard.smith groupName=Sales```

#### Human Readable Output

>User: f21a29b8-cae1-4729-8e73-635b426efba7 added to group: Sales successfully

### pingone-remove-from-group
***
Remove user from group


#### Base Command

`pingone-remove-from-group`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| groupName | Group Name. | Optional | 
| userId | User ID. | Optional | 
| groupId | Group ID. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-remove-from-group username=richard.smith groupName=Sales```

#### Human Readable Output

>User: f21a29b8-cae1-4729-8e73-635b426efba7 was removed from group: Sales successfully

### pingone-get-groups
***
Returns user's group memberships


#### Base Command

`pingone-get-groups`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.Group | unknown | PingOne groups of the user | 
| Account.ID | string | PingOne account ID | 
| Account.Type | string | PingOne account type | 
| Account.Group.ID | string | Unique ID for the group | 
| Account.Group.Name | unknown | Name of the group | 


#### Command Example
```!pingone-get-groups username=emma.sharp```

#### Context Example
```json
{
    "Account": {
        "Group": [],
        "ID": "emma.sharp",
        "Type": "PingOne"
    }
}
```

#### Human Readable Output

>PingOne groups for user: emma.sharp
> ### Groups
>**No entries.**


### pingone-get-user
***
Returns a PingOne user


#### Base Command

`pingone-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| userId | User ID. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | string | PingOne account ID | 
| Account.Username | string | PingOne account username | 
| Account.DisplayName | string | PingOne account display name | 
| Account.Email | string | PingOne account email | 
| Account.Enabled | boolean | PingOne account enabled status | 
| Account.CreatedAt | date | PingOne account create date | 
| Account.UpdatedAt | date | PingOne account updated date | 


#### Command Example
```!pingone-get-user username=emma.sharp```

#### Context Example
```json
{
    "Account": {
        "CreatedAt": "2021-09-03T18:04:03.916Z",
        "DisplayName": "Emma Sharp",
        "Email": "emma.sharp@example.com",
        "Enabled": true,
        "ID": "a8890eb9-38ea-469a-bc00-b64be7903633",
        "UpdatedAt": "2021-09-07T22:26:47.370Z",
        "Username": "emma.sharp"
    }
}
```

#### Human Readable Output

>### User:emma.sharp
>|AccountStatus|CreatedAt|Email|Enabled|Environment|First Name|ID|Last Name|PopulationID|UpdatedAt|Username|
>|---|---|---|---|---|---|---|---|---|---|---|
>| OK | 2021-09-03T18:04:03.916Z | emma.sharp@example.com | true | b4f5e266-a946-4f77-9cc5-5dc91b046431 | Emma | a8890eb9-38ea-469a-bc00-b64be7903633 | Sharp | 4cd45bdb-0eb2-42fe-8475-4bcd908269f1 | 2021-09-07T22:26:47.370Z | emma.sharp |
> 

### pingone-create-user
***
Create a PingOne user 


#### Base Command

`pingone-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Required | 
| populationId | PingOne population ID where the new user will be created. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Account.ID | string | PingOne account ID | 
| Account.Username | string | PingOne account username | 
| Account.DisplayName | string | PingOne account display name | 
| Account.Email | string | PingOne account email | 
| Account.Enabled | boolean | PingOne account enabled status | 
| Account.CreatedAt | date | PingOne account create date | 
| Account.UpdatedAt | date | PingOne account updated date | 


#### Command Example
```!pingone-create-user username=richard.smith populationId=4cd45bdb-0eb2-42fe-8475-4bcd908269f1```

#### Context Example
```json
{
    "Account": {
        "CreatedAt": "2021-09-07T22:26:54.960Z",
        "DisplayName": null,
        "Email": null,
        "Enabled": true,
        "ID": "f21a29b8-cae1-4729-8e73-635b426efba7",
        "UpdatedAt": "2021-09-07T22:26:54.960Z",
        "Username": "richard.smith"
    }
}
```

#### Human Readable Output

>### PingOne user created: richard.smith
>|AccountStatus|CreatedAt|Email|Enabled|Environment|First Name|ID|Last Name|PopulationID|UpdatedAt|Username|
>|---|---|---|---|---|---|---|---|---|---|---|
>| OK | 2021-09-07T22:26:54.960Z |  | true | b4f5e266-a946-4f77-9cc5-5dc91b046431 |  | f21a29b8-cae1-4729-8e73-635b426efba7 |  | 4cd45bdb-0eb2-42fe-8475-4bcd908269f1 | 2021-09-07T22:26:54.960Z | richard.smith |


### pingone-update-user
***
Update a PingOne user


#### Base Command

`pingone-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Required | 
| formatted | Formatted PingOne name. | Optional | 
| given | Given name. | Optional | 
| middle | Middle name. | Optional | 
| family | Family name. | Optional | 
| nickname | Nickname. | Optional | 
| title | Title. | Optional | 
| locale | Locale. | Optional | 
| email | Email. | Optional | 
| primaryPhone | Primary phone number. | Optional | 
| mobilePhone | Mobile phone number. | Optional | 
| streetAddress | Street address. | Optional | 
| locality | Locality. | Optional | 
| region | Region. | Optional | 
| postalCode | Zip code. | Optional | 
| countryCode | Country code. | Optional | 
| Type | Account type. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-update-user username=richard.smith phoneNumber=604-998-7766```

#### Human Readable Output

>### PingOne user updated: richard.smith
>**No entries.**


### pingone-delete-user
***
Delete a PingOne user


#### Base Command

`pingone-delete-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username. | Optional | 
| userId | User ID. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!pingone-delete-user username=richard.smith```

#### Human Readable Output

>User: f21a29b8-cae1-4729-8e73-635b426efba7 was Deleted successfully
