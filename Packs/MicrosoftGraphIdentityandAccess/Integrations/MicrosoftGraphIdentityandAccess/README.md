Use the Microsoft Graph Identity and Access integration to manage roles and members.
## Configure MicrosoftGraphIdentityandAccess on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for MicrosoftGraphIdentityandAccess.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Application ID | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-identity-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.

### msgraph-identity-auth-complete
***
Run this command to complete the authorization process.
Should be used after running the msgraph-identity-auth-start command.

### msgraph-identity-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.

### msgraph-identity-auth-test
***
Tests connectivity to Microsoft.



### msgraph-identity-directory-roles-list
***
Lists the roles in the directory.


#### Base Command

`msgraph-identity-directory-roles-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to fetch. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.Role.deletedDateTime | Date | The time when a role was deleted. Displays only if a role was deleted. | 
| MSGraphIdentity.Role.description | String | The description of the directory role. | 
| MSGraphIdentity.Role.displayName | String | The display name of the directory role. | 
| MSGraphIdentity.Role.id | String | The unique identifier of the directory role. | 
| MSGraphIdentity.Role.roleTemplateId | String | The ID of the directory role template on which the role is based. | 


#### Command Example
```!msgraph-identity-directory-roles-list limit=1```

#### Context Example
```json
{
    "MSGraphIdentity": {
        "Role": {
            "deletedDateTime": null,
            "description": "Can create and manage all aspects of app registrations and enterprise apps.",
            "displayName": "Application Administrator",
            "id": ":id:",
            "roleTemplateId": "role-template-id"
        }
    }
}
```

#### Human Readable Output

>### Directory roles:
>|id|displayName|description|roleTemplateId|
>|---|---|---|---|
>| id | Application Administrator | Can create and manage all aspects of app registrations and enterprise apps. | role-template-id |


### msgraph-identity-directory-role-activate
***
Activates a role by its template ID.


#### Base Command

`msgraph-identity-directory-role-activate`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_template_id | ID of the role template to activate. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.Role.deletedDateTime | Date | The time when the role was deleted. Displays only if the role was deleted. | 
| MSGraphIdentity.Role.description | String | The description of the directory role. | 
| MSGraphIdentity.Role.displayName | String | The display name of the directory role. | 
| MSGraphIdentity.Role.id | String | The unique identifier of the directory role. | 
| MSGraphIdentity.Role.roleTemplateId | String | The ID of the directory role template on which this role is based. | 


#### Command Example
```!msgraph-identity-directory-role-activate role_template_id=role-template-id```

#### Context Example
```json
{
    "MSGraphIdentity": {
        "Role": {
            "deletedDateTime": null,
            "description": "Can create and manage all aspects of app registrations and enterprise apps.",
            "displayName": "Application Administrator",
            "id": ":id:",
            "roleTemplateId": "role-template-id"
        }
    }
}
```

#### Human Readable Output

>### Role has been activated
>|id|roleTemplateId|displayName|description|deletedDateTime|
>|---|---|---|---|---|
>| id | role-template-id | Application Administrator | Can create and manage all aspects of app registrations and enterprise apps. |  |


### msgraph-identity-directory-role-members-list
***
Gets all members in a role ID.


#### Base Command

`msgraph-identity-directory-role-members-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The ID of the application for which to get its role members list. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required | 
| limit | The maximum number of members to fetch. Default is 10. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.RoleMember.user_id | String | The unique identifier of the user in the role. | 
| MSGraphIdentity.RoleMember.role_id | String | The unique identifier of the role specified in the input. | 


#### Command Example
```!msgraph-identity-directory-role-members-list role_id=:role:```

#### Context Example
```json
{
    "MSGraphIdentity": {
        "RoleMember": {
            "role_id": ":role:",
            "user_id": [
                "70585180-517a-43ea-9403-2d80b97ab19d",
                "5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de"
            ]
        }
    }
}
```

#### Human Readable Output

>### Role ':role:' members:
>|role_id|user_id|
>|---|---|
>| :role: | 70585180-517a-43ea-9403-2d80b97ab19d,<br/>5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de,<br/>"id",<br/>a7cedb37-c4e5-4cfb-a327-7bafb34a1f49 |


### msgraph-identity-directory-role-member-add
***
Adds a user to a role.


#### Base Command

`msgraph-identity-directory-role-member-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The ID of the role to add the user to. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required | 
| user_id | The ID of the user to add to the role. Can be retrieved using the msgraph-identity-directory-role-members-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-identity-directory-role-member-add role_id=:role: user_id=:id:```

#### Human Readable Output

>User ID :id: has been added to role :role:

### msgraph-identity-directory-role-member-remove
***
Removes a user from a role.


#### Base Command

`msgraph-identity-directory-role-member-remove`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | ID of the role from which to remove the user. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required | 
| user_id | ID of the user to remove from the role. Can be retrieved using the msgraph-identity-directory-role-members-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!msgraph-identity-directory-role-member-remove role_id=:role: user_id=:id:```

#### Human Readable Output

>User ID :id: has been removed from role :role:
