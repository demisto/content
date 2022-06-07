Use the Azure Active Directory Identity And Access integration to manage roles and members.
## Configure Azure Active Directory Identity and Access on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Active Directory Identity and Access.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Application ID | True |
    | Azure AD endpoint | False |
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

### msgraph-identity-ip-named-locations-create
***
Creates an ip named location.


#### Base Command

`msgraph-identity-ip-named-locations-create`
#### Input

| **Argument Name** | **Description**                                        | **Required** |
|-------------------|--------------------------------------------------------| --- |
| display_name      | The display name for the ip named location.            | Required |
| is_trusted        | A boolean to show if the ip named location is trusted. | Required |
| ips               | The ip ranges for the ip named location.               | Required |


#### Context Output

| **Path**                                                    | **Type** | **Description** |  
|-------------------------------------------------------------| --- | --- |
| MSGraph.conditionalAccess.namedIpLocations.time_created     | Date | The time of the ip named location creation. |
| MSGraph.conditionalAccess.namedIpLocations.time_modified    | Date | The time the ip named location was last modified. |
| MSGraph.conditionalAccess.namedIpLocations.display_name     | String | The ip named location display name. |
| MSGraph.conditionalAccess.namedIpLocations.id               | String | The unique identifier of the ip named location. |
| MSGraph.conditionalAccess.namedIpLocations.is_trusted       | String | The ip named location trust status. |
| MSGraph.conditionalAccess.namedIpLocations.ip_ranges        | Array | The ip named location ip ranges. |


#### Command Example
```!msgraph-identity-ip-named-locations-create ips=12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63 display_name=test is_trusted=True:```

#### Human Readable Output

>created Ip named location 'ID': :ipNamedLocation:  

### msgraph-identity-ip-named-locations-get
***
Gets an ip named location.


#### Base Command

`msgraph-identity-ip-named-locations-get`


#### Input

| **Argument Name** | **Description**                         | **Required** |
|-------------------|-----------------------------------------| --- |
| ip_id             | The id of the ip named location to get. | Required |


#### Context Output

| **Path**                                                 | **Type** | **Description** |
|----------------------------------------------------------| --- | --- |
| MSGraph.conditionalAccess.namedIpLocations.time_created  | Date | The time of the ip named location creation. |
| MSGraph.conditionalAccess.namedIpLocations.time_modified | Date | The time the ip named location was last modified. |
| MSGraph.conditionalAccess.namedIpLocations.display_name  | String | The ip named location display name. |
| MSGraph.conditionalAccess.namedIpLocations.id            | String | The unique identifier of the ip named location. |
| MSGraph.conditionalAccess.namedIpLocations.is_trusted    | String | The ip named location trust status. |
| MSGraph.conditionalAccess.namedIpLocations.ip_ranges     | Array | The ip named location ip ranges. |


#### Command Example
```!msgraph-identity-ip-named-locations-get ip_id=03f8c56f-2ffd-4699-84af-XXXXXXXCX```

#### Human Readable Output

>Ip named location 'ID': :ipNamedLocation:


### msgraph-identity-ip-named-locations-delete
***
Deletes an ip named location.


#### Base Command

`msgraph-identity-ip-named-locations-delete`
#### Input

| **Argument Name** | **Description**                            | **Required** |
|-------------------|--------------------------------------------| --- |
| ip_id             | The id of the ip named location to delete. | Required |


#### Context Output

No context output


#### Command Example
```!msgraph-identity-ip-named-locations-delete ip_id=03f8c56f-2ffd-4699-84af-XXXXXXXCX```

#### Human Readable Output

>Successfully deleted IP named location 'X-X-X-X'


### msgraph-identity-ip-named-locations-update
***
Updates an ip named location.


#### Base Command

`msgraph-identity-ip-named-locations-update`
#### Input

| **Argument Name** | **Description**                                        | **Required** |
|-------------------|--------------------------------------------------------| --- |
| ip_id             | The id of the ip named location to delete.             | Required |
| display_name      | The display name for the ip named location.            | Required |
| is_trusted        | A boolean to show if the ip named location is trusted. | Required |
| ips               | The ip ranges for the ip named location.               | Required |


#### Context Output

No context output


#### Command Example
```!msgraph-identity-ip-named-locations-update ips=12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63 display_name=test is_trusted=True ip_id=098699fc-10ad-420e-9XXXXXXXXXX```

#### Human Readable Output

>Successfully updated IP named location '006cc9bf-8391-4ff3-8cff-ee87f06b7b02'


## msgraph-identity-ip-named-locations-list
***
Lists an ip named locations.


#### Base Command

`msgraph-identity-ip-named-locations-list`
#### Input

| **Argument Name** | **Description**                | **Required** |
|-------------------|--------------------------------|--------------|
| limit             | The get request results limit. | Optional     |


#### Context Output

| **Path** | **Type** | **Description** |
| -- | --- | --- |
| MSGraph.conditionalAccess.namedIpLocations.ip_named_locations | Array | List of ip named locations. |


#### Command Example
```!msgraph-identity-ip-named-locations-list```
