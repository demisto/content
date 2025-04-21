Manage teams and members in Microsoft Teams.

## Authorization
In both options below, the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code) is used.

In order to connect to the Azure Network Security Group using either Cortex XSOAR Azure App or the Self-Deployed Azure App:
1. Fill in the required parameters.
2. Run the ***!microsoft-teams-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!microsoft-teams-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.

#### Cortex XSOAR Azure App

In order to use the Cortex XSOAR Azure application, use the default application ID (3307a0ab-612c-47af-b3b5-8208247562db).

You only need to fill in your subscription ID and resource group name. For more details, follow [Azure Integrations Parameters](https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication#azure-integrations-params).

#### Self-Deployed Azure App

To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal, with mobile and desktop flows enabled.

Required Permissions
* Group.ReadWrite.All - Application
* Team.ReadBasic.All - Application
* TeamMember.ReadWrite.All - Application


## Configure Microsoft Teams Management in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Application ID |  | False |
| Azure AD endpoint | Azure AD endpoint associated with a national cloud. | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Authentication Type | Type of authentication - could be Client Credentials Authorization Flow \(recommended\) or Device Flow | False |
| Tenant ID (for Client Credentials mode) |  | False |
| Client Secret (for Client Credentials mode) |  | False |
| Azure Managed Identities Client ID | The Managed Identities client id for authentication - relevant only if the integration is running on Azure VM. | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### microsoft-teams-auth-test
***
Tests the connectivity to Microsoft.


#### Base Command

`microsoft-teams-auth-test`
#### Input

There are no input arguments for this command.

#### Human Readable Output
>✅ Success!

### microsoft-teams-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.


#### Base Command

`microsoft-teams-auth-start`
#### Input

There are no input arguments for this command.

#### Human Readable Output
>### Authorization instructions
>        1. To sign in, use a web browser to open the page:
>            [https://microsoft.com/devicelogin](https://microsoft.com/devicelogin)
>           and enter the code **XXXXXXXX** to authenticate.
>        2. Run the ***!microsoft-teams-auth-complete*** command in the War Room.


### microsoft-teams-auth-complete
***
Run this command to complete the authorization process. Should be used after running the ***microsoft-teams-auth-start*** command.


#### Base Command

`microsoft-teams-auth-complete`
#### Input

There are no input arguments for this command.

#### Human Readable Output
>✅ Authorization completed successfully.

### microsoft-teams-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`microsoft-teams-auth-reset`
#### Input

There are no input arguments for this command.

#### Human Readable Output

>Authorization was reset successfully. You can now run ***!microsoft-teams-auth-start*** and ***!microsoft-teams-auth-complete***.
### microsoft-teams-team-create
***
Creates a new team.


#### Base Command

`microsoft-teams-team-create`

##### Required Permissions

`Team.Create`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The name of the team. | Required | 
| description | Description of the team. | Optional | 
| visibility | The visibility of the group and team. Possible values are: "public" and "private". Default is "public". Possible values are: public, private. Default is public. | Optional | 
| allow_guests_create_channels | Whether guests can add and update channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_guests_delete_channels | Whether guests can delete channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_create_private_channels | Whether members can add and update private channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_create_channels | Whether members can add and update channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_delete_channels | Whether members can delete channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_add_remove_apps | Whether members can add and remove apps. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_add_remove_tabs | Whether members can add, update, and remove tabs. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_add_remove_connectors | Whether members can add, update, and remove connectors. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_user_edit_messages | Whether users can edit their messages. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_user_delete_messages | Whether users can delete their messages. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_owner_delete_messages | Whether owners can delete any message. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_team_mentions | Whether @team mentions are allowed. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_channel_mentions | Whether @channel mentions are allowed. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| owner | ID of the user to be the team owner (e.g., 0040b377-61d8-43db-94f5-81374122dc7e). | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-create display_name="Sample Engineering Team" owner=3fa9f28b-eb0e-463a-ba7b-8089fe9991e2```

#### Human Readable Output

>Team Sample Engineering Team was created successfully.

### microsoft-teams-team-create-from-group
***
Create a new team under a group. In order to create a team, the group must have a least one owner and the group cannot be of type Security.


#### Base Command

`microsoft-teams-team-create-from-group`

##### Required Permissions

`Group.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| group_id | ID of group to create team from. Can be retrieved by running the msgraph-groups-list-groups command. | Required | 
| display_name | The name of the team. | Optional | 
| description | Description of the team. | Optional | 
| visibility | The visibility of the group and team. Possible values are: "public" and "private". Default is "public". Possible values are: public, private. Default is public. | Optional | 
| allow_guests_create_channels | Whether guests can add and update channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_guests_delete_channels | Whether guests can delete channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_create_private_channels | Whether members can add and update private channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_create_channels | Whether members can add and update channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_delete_channels | Whether members can delete channels. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_add_remove_apps | Whether members can add and remove apps. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_add_remove_tabs | Whether members can add, update, and remove tabs. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_members_add_remove_connectors | Whether members can add, update, and remove connectors. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_user_edit_messages | Whether users can edit their messages. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_user_delete_messages | Whether users can delete their messages. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_owner_delete_messages | Whether owners can delete any message. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_team_mentions | Whether @team mentions are allowed. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 
| allow_channel_mentions | Whether @channel mentions are allowed. Possible values are: "true" and "false". Default is "false". Possible values are: false, true. Default is false. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-create-from-group group_id=7bc73bf4-c88e-4e0c-a927-6b52d19ca3e6```

#### Human Readable Output

>The team was created from group 7bc73bf4-c88e-4e0c-a927-6b52d19ca3e6 successfully.

### microsoft-teams-teams-list
***
Returns all the groups that have teams in an organization.


#### Base Command

`microsoft-teams-teams-list`

##### Required Permissions

`GroupMember.Read.All`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.Team.securityEnabled | Boolean | Specifies whether the group is a security group. | 
| MicrosoftTeams.Team.preferredDataLocation | String | The preferred data location for the group. | 
| MicrosoftTeams.Team.resourceProvisioningOptions | String | Specifies the group resources that are provisioned as part of Microsoft 365 group creation, that are not normally part of default group creation. Possible value is Team. | 
| MicrosoftTeams.Team.createdDateTime | String | Timestamp of when the group was created. The value cannot be modified and is automatically populated when the group is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MicrosoftTeams.Team.mailNickname | String | The alias of the group in an Exchange organization. | 
| MicrosoftTeams.Team.securityIdentifier | String | Security identifier of the group, used in Windows scenarios. | 
| MicrosoftTeams.Team.mailEnabled | Boolean | Specifies whether the group is mail-enabled. | 
| MicrosoftTeams.Team.displayName | String | The display name for the group. | 
| MicrosoftTeams.Team.visibility | String | Specifies the visibility of a Microsoft 365 group. Possible values are: Private, Public, or Hiddenmembership. Blank values are treated as public. | 
| MicrosoftTeams.Team.proxyAddresses | String | Email addresses for the group that direct to the same group mailbox. For example: \["SMTP: bob@demisto.com", "smtp: bob@sales.demisto.com"\] | 
| MicrosoftTeams.Team.mail | String | The SMTP address for the group, for example, "serviceadmins@contoso.onmicrosoft.com". | 
| MicrosoftTeams.Team.id | String | The unique identifier for the group. | 
| MicrosoftTeams.Team.description | String | An optional description for the group. | 


#### Command Example
```!microsoft-teams-teams-list```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "Team": [
            {
                "description": "Welcome to the HR Taskforce team.",
                "displayName": "HR Taskforce",
                "groupTypes": [
                    "Unified"
                ],
                "id": "02bd9fd6-8f93-4758-87c3-1fb73740a315",
                "mailEnabled": true,
                "mailNickname": "HRTaskforce",
                "resourceBehaviorOptions": [],
                "resourceProvisioningOptions": [
                    "Team"
                ],
                "securityEnabled": false,
                "visibility": "Private"
            },
            {
                "description": "Welcome to the team that we've assembled to launch our product.",
                "displayName": "X1050 Launch Team",
                "groupTypes": [
                    "Unified"
                ],
                "id": "8090c93e-ba7c-433e-9f39-08c7ba07c0b3",
                "mailEnabled": true,
                "mailNickname": "X1050LaunchTeam",
                "resourceBehaviorOptions": [],
                "resourceProvisioningOptions": [
                    "Team"
                ],
                "securityEnabled": false,
                "visibility": "Private"
            }
        ]
    }
}
```

#### Human Readable Output

>### Microsoft Teams List
>|id|displayName|createdDateTime|description|
>|---|---|---|---|
>| 02bd9fd6-8f93-4758-87c3-1fb73740a315 | HR Taskforce | 2014-01-01T00:00:00Z | Welcome to the HR Taskforce team. |
>| 8090c93e-ba7c-433e-9f39-08c7ba07c0b3 | X1050 Launch Team | 2014-01-01T00:00:00Z | Welcome to the team that we've assembled to launch our product. |

### microsoft-teams-team-get
***
Retrieve the properties and relationships of the specified team.


#### Base Command

`microsoft-teams-team-get`

##### Required Permissions

`Team.ReadBasic.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of team to get. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.Team.createdDateTime | Date | Timestamp of when the group was created. The value cannot be modified and is automatically populated when the group is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MicrosoftTeams.Team.classification | String | Typically describes the data or business sensitivity of the team. | 
| MicrosoftTeams.Team.isArchived | Boolean | Whether this team is in read-only mode. | 
| MicrosoftTeams.Team.displayName | String | The display name for the group. | 
| MicrosoftTeams.Team.visibility | String | Specifies the visibility of a Microsoft 365 group. Possible values are: Private, Public, or Hiddenmembership; blank values are treated as public. | 
| MicrosoftTeams.Team.id | String | The unique identifier for the group. | 
| MicrosoftTeams.Team.description | String | An optional description for the group. | 


#### Command Example
```!microsoft-teams-team-get team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "Team": [
            {
                "id": "489080f2-98c3-4993-84ec-fa0aac622b2e",
                "discoverySettings": {
                    "showInTeamsSearchAndSuggestions": true
                },
                "funSettings": {
                    "allowCustomMemes": true,
                    "allowGiphy": true,
                    "allowStickersAndMemes": true,
                    "giphyContentRating": "strict"
                },
                "guestSettings": {
                    "allowCreateUpdateChannels": true,
                    "allowDeleteChannels": true
                },
                "isArchived": false,
                "memberSettings": {
                    "allowAddRemoveApps": true,
                    "allowCreateUpdateChannels": true,
                    "allowCreateUpdateRemoveConnectors": true,
                    "allowCreateUpdateRemoveTabs": true,
                    "allowDeleteChannels": true
                },
                "messagingSettings": {
                    "allowChannelMentions": true,
                    "allowOwnerDeleteMessages": true,
                    "allowTeamMentions": true,
                    "allowUserDeleteMessages": true,
                    "allowUserEditMessages": true
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Team 489080f2-98c3-4993-84ec-fa0aac622b2e
>|discoverySettings|funSettings|guestSettings|isArchived|memberSettings|messagingSettings|
>|---|---|---|---|---|---|
>| showInTeamsSearchAndSuggestions: true | allowGiphy: true\<br/\>giphyContentRating: strict\<br/\>allowStickersAndMemes: true\<br/\>allowCustomMemes: true | allowCreateUpdateChannels: true\<br/\>allowDeleteChannels: true | false | allowCreateUpdateChannels: true\<br/\>allowDeleteChannels: true\<br/\>allowAddRemoveApps: true\<br/\>allowCreateUpdateRemoveTabs: true\<br/\>allowCreateUpdateRemoveConnectors: true | allowUserEditMessages: true\<br/\>allowUserDeleteMessages: true\<br/\>allowOwnerDeleteMessages: true\<br/\>allowTeamMentions: true\<br/\>allowChannelMentions: true |

### microsoft-teams-team-update
***
Update the properties of the specified team.


#### Base Command

`microsoft-teams-team-update`

##### Required Permissions

`TeamSettings.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to update. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 
| display_name | The name of the team. | Optional | 
| description | Description of the team. | Optional | 
| visibility | The visibility of the group and team. Possible values are: "public" and "private". Possible values are: public, private. | Optional | 
| allow_guests_create_channels | Whether guests can add and update channels. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_guests_delete_channels | Whether guests can delete channels. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_members_create_private_channels | Whether members can add and update private channels. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_members_create_channels | Whether members can add and update channels. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_members_delete_channels | Whether members can delete channels. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_members_add_remove_apps | Whether members can add and remove apps. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_members_add_remove_tabs | Whether members can add, update, and remove tabs. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_members_add_remove_connectors | Whether members can add, update, and remove connectors. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_user_edit_messages | Whether users can edit their messages. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_user_delete_messages | Whether users can delete their messages. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_owner_delete_messages | Whether owners can delete any message. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_team_mentions | Whether @team mentions are allowed. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 
| allow_channel_mentions | Whether @channel mentions are allowed. Possible values are: "true" and "false". Possible values are: false, true. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-update team_id=489080f2-98c3-4993-84ec-fa0aac622b2e description=NewDescription```

#### Human Readable Output

>Team 489080f2-98c3-4993-84ec-fa0aac622b2e was updated successfully.

### microsoft-teams-team-delete
***
Deletes a group. Note: it might take time for the team to disappear from the teams list.


#### Base Command

`microsoft-teams-team-delete`

##### Required Permissions

`Group.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to delete. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-delete team_id=8d64be1b-590f-4afd-9bac-0b31b3703300```

#### Human Readable Output

>Team 8d64be1b-590f-4afd-9bac-0b31b3703300 was deleted successfully.

### microsoft-teams-members-list
***
Returns the members of the specified team.


#### Base Command

`microsoft-teams-members-list`

##### Required Permissions

`TeamMember.Read.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to get the member of. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.teamId | String | The unique identifier for the group. |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-members-list team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "TeamMember": [
            {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "displayName": "Adele Vance",
                "email": "AdeleV@M365x987948.OnMicrosoft.com",
                "id": "ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk=",
                "roles": [],
                "userId": "73761f06-2ac9-469c-9f10-279a8cc267f9"
            },
            {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "displayName": "MOD Administrator",
                "email": "admin@M365x987948.OnMicrosoft.com",
                "id": "ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM1OThlZmNkNC1lNTQ5LTQwMmEtOTYwMi0wYjUwMjAxZmFlYmU=",
                "roles": [
                    "owner"
                ],
                "userId": "598efcd4-e549-402a-9602-0b50201faebe"
            },
            {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "displayName": "Harry Johnson",
                "email": "harry@M365x987948.OnMicrosoft.com",
                "id": "MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyM3NTJmNTBiNy0yNTZmLTQ1MzktYjc3NS1jNGQxMmYyZTQ3MjI=",
                "roles": [],
                "userId": "752f50b7-256f-4539-b775-c4d12f2e4722"
            }
        ]
    }
}
```

#### Human Readable Output

>### Team 489080f2-98c3-4993-84ec-fa0aac622b2e Members List
>|id|displayName|email|roles|
>|---|---|---|---|
>| ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk= | Adele Vance | AdeleV@M365x987948.OnMicrosoft.com |  |
>| ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM1OThlZmNkNC1lNTQ5LTQwMmEtOTYwMi0wYjUwMjAxZmFlYmU= | MOD Administrator | admin@M365x987948.OnMicrosoft.com | owner |
>| MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyM3NTJmNTBiNy0yNTZmLTQ1MzktYjc3NS1jNGQxMmYyZTQ3MjI= | Harry Johnson | harry@M365x987948.OnMicrosoft.com |  |

### microsoft-teams-member-get
***
Gets a member of a team.


#### Base Command

`microsoft-teams-member-get`

##### Required Permissions

`TeamMember.Read.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership_id | ID of member to get. Can be retrieved by running the microsoft-teams-members-list command. | Required | 
| team_id | ID of the team to get the member of. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.teamId | String | The unique identifier for the group. |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-member-get membership_id=NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTI= team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "TeamMember": [
            {
                "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#teams('ece6f0a1-7ca4-498b-be79-edf6c8fc4d82')/members/microsoft.graph.aadUserConversationMember/$entity",
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "displayName": "John Doe",
                "email": null,
                "id": "NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTI=",
                "roles": [
                    "owner"
                ],
                "userId": "8b081ef6-4792-4def-b2c9-c363a1bf41d5"
            }
        ]
    }
}
```

#### Human Readable Output

>### Team Member NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTI= Details
>|id|displayName|email|roles|
>|---|---|---|---|
>| /ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk= | John Doe |  | owner |

### microsoft-teams-member-add
***
Add a user to be a team member.


#### Base Command

`microsoft-teams-member-add`

##### Required Permissions

`TeamMember.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to add the user to. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 
| user_id | Email address or ID of the user to add to the team. The ID can be retrieved by running the microsoft-teams-members-list command. | Required | 
| is_owner | Whether to add the member with the owner role. Possible values are: "false" and "true". Default is "false". Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-member-add user_id=2827c1e7-edb6-4529-b50d-25984e968637 team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "TeamMember": {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "displayName": "Cameron White",
            "email": "CameronW@M365x987948.OnMicrosoft.com",
            "id": "ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk=",
            "roles": [
                "owner"
            ],
            "userId": "2827c1e7-edb6-4529-b50d-25984e968637"
        }
    }
}
```

#### Human Readable Output

>### User 2827c1e7-edb6-4529-b50d-25984e968637 was added to the team 489080f2-98c3-4993-84ec-fa0aac622b2e successfully.
>|id|displayName|email|roles|
>|---|---|---|---|
>| ZWUwZjVhZTItOGJjNi00YWU1LTg0NjYtN2RhZWViYmZhMDYyIyM3Mzc2MWYwNi0yYWM5LTQ2OWMtOWYxMC0yNzlhOGNjMjY3Zjk= | Cameron White | CameronW@M365x987948.OnMicrosoft.com | owner |


### microsoft-teams-member-remove
***
Remove a member from the team.


#### Base Command

`microsoft-teams-member-remove`

##### Required Permissions

`TeamMember.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to remove the user from. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 
| membership_id | ID of the member to remove from the team. Can be retrieved by running the microsoft-teams-members-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-member-remove team_id=489080f2-98c3-4993-84ec-fa0aac622b2e membership_id=NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMxZTc2NTVhNC02ZThmLTQ2NjUtYWMxNS03ZWJhMmJmOGQ4ODY=```

#### Human Readable Output

>Team member NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMxZTc2NTVhNC02ZThmLTQ2NjUtYWMxNS03ZWJhMmJmOGQ4ODY= was removed from the team 489080f2-98c3-4993-84ec-fa0aac622b2e successfully.

### microsoft-teams-member-update
***
Updates a team member.


#### Base Command

`microsoft-teams-member-update`

##### Required Permissions

`TeamMember.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to update the member in. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 
| membership_id | ID of the team member to update. Can be retrieved by running the microsoft-teams-members-list command. | Required | 
| is_owner | Whether to set the member with the owner role. Possible values are: "false" and "true". Default is "false". Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-member-update membership_id=NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyM4OTE4YzM5MC0zNWI4LTQyYzMtODNmMS04MzUyZTBlOWRmNjU= team_id=489080f2-98c3-4993-84ec-fa0aac622b2e is_owner=true```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "TeamMember": {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#teams('ece6f0a1-7ca4-498b-be79-edf6c8fc4d82')/members/microsoft.graph.aadUserConversationMember/$entity",
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "displayName": "John Doe",
            "email": null,
            "id": "NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyM4OTE4YzM5MC0zNWI4LTQyYzMtODNmMS04MzUyZTBlOWRmNjU=",
            "roles": [
                "owner"
            ],
            "userId": "8b081ef6-4792-4def-b2c9-c363a1bf41d5"
        }
    }
}
```

#### Human Readable Output

>### Team member NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyM4OTE4YzM5MC0zNWI4LTQyYzMtODNmMS04MzUyZTBlOWRmNjU= was updated successfully.
>|id|displayName|email|roles|
>|---|---|---|---|
>| NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyM4OTE4YzM5MC0zNWI4LTQyYzMtODNmMS04MzUyZTBlOWRmNjU= | John Doe |  | owner |

### microsoft-teams-team-archive
***
Archive the specified team. When a team is archived, users can no longer send or like messages on any channel in the team, edit the team's name, description, or other settings, or in general make most changes to the team. Membership changes to the team continue to be allowed. Archiving is an async operation. A team is archived once the async operation completes successfully, which may occur subsequent to a response from this command. In order to archive a team, the team and group must have an owner.


#### Base Command

`microsoft-teams-team-archive`

##### Required Permissions

`TeamSettings.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to archive. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-archive team_id=d74944a4-8dca-4cc5-9892-b1f73b4a4419```

#### Human Readable Output

>Team d74944a4-8dca-4cc5-9892-b1f73b4a4419 was archived successfully.

### microsoft-teams-team-unarchive
***
Restore an archived team. This restores the users' ability to send messages and edit the team, abiding by tenant and team settings. Unarchiving is an async operation. A team is unarchived once the async operation completes successfully, which may occur subsequent to a response from this command.


#### Base Command

`microsoft-teams-team-unarchive`

##### Required Permissions

`TeamSettings.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to unarchive. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-unarchive team_id=d74944a4-8dca-4cc5-9892-b1f73b4a4419```

#### Human Readable Output

>Team d74944a4-8dca-4cc5-9892-b1f73b4a4419 was unarchived successfully.

### microsoft-teams-team-clone
***
Create a copy of a team. This operation also creates a copy of the corresponding group. Cloning is a long-running operation.


#### Base Command

`microsoft-teams-team-clone`

##### Required Permissions

`Group.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to clone. Can be retrieved by running the microsoft-teams-teams-list command. | Required | 
| display_name | The name of the team. | Required | 
| description | Description of the team. | Optional | 
| visibility | The visibility of the group and team. Possible values are: "public" and "private". Default is "public". Possible values are: public, private. Default is public. | Optional | 
| clone_apps | Whether to copy Microsoft Teams apps that are installed in the team. Possible values are: "false" and "true". Default is "true". Possible values are: false, true. Default is true. | Optional | 
| clone_tabs | Whether to copy the tabs within channels. Possible values are: "false" and "true". Default is "true". Possible values are: false, true. Default is true. | Optional | 
| clone_settings | Whether to copy all settings within the team, along with key group settings. Possible values are: "false" and "true". Default is "true". Possible values are: false, true. Default is true. | Optional | 
| clone_channels | Whether to copy the channel structure (but not the messages in the channel). Possible values are: "false" and "true". Default is "true". Possible values are: false, true. Default is true. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-team-clone team_id=6e0d7429-4736-4373-bfb7-a1b59e3c463a display_name=Cloned```

#### Human Readable Output

>Team 6e0d7429-4736-4373-bfb7-a1b59e3c463a was cloned successfully.

### microsoft-teams-teams-list-joined
***
Get the teams in Microsoft Teams that the user is a direct member of.


#### Base Command

`microsoft-teams-teams-list-joined`

##### Required Permissions

`Team.ReadBasic.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | ID of the user (e.g., 2827c1e7-edb6-4529-b50d-25984e968637). Can be retrieved by running the msgraph-user-list command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.Team.createdDateTime | Date | Timestamp of when the group was created. The value cannot be modified and is automatically populated when the group is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. | 
| MicrosoftTeams.Team.classification | String | Typically describes the data or business sensitivity of the team. | 
| MicrosoftTeams.Team.isArchived | Boolean | Whether this team is in read-only mode. | 
| MicrosoftTeams.Team.displayName | String | The display name for the group. | 
| MicrosoftTeams.Team.visibility | String | Specifies the visibility of a Microsoft 365 group. Possible values are: Private, Public, or Hiddenmembership; blank values are treated as public. | 
| MicrosoftTeams.Team.id | String | The unique identifier for the group. | 
| MicrosoftTeams.Team.description | String | An optional description for the group. | 


#### Command Example
```!microsoft-teams-teams-list-joined user_id=3fa9f28b-eb0e-463a-ba7b-8089fe9991e2```

#### Context Example
```json
{
    "MicrosoftTeams": {
        "Team": [
            {
                "displayName": "MyGreatTeam",
                "groupTypes": [
                    "Unified"
                ],
                "id": "02bd9fd6-8f93-4758-87c3-1fb73740a315",
                "mailEnabled": true,
                "resourceBehaviorOptions": [],
                "resourceProvisioningOptions": [
                    "Team"
                ],
                "securityEnabled": false,
                "visibility": "Private",
                "description": "desc"
            },
            {
                "displayName": "WooahTeam",
                "groupTypes": [
                    "Unified"
                ],
                "id": "8090c93e-ba7c-433e-9f39-08c7ba07c0b3",
                "mailEnabled": true,
                "mailNickname": "X1050LaunchTeam",
                "resourceBehaviorOptions": [],
                "resourceProvisioningOptions": [
                    "Team"
                ],
                "securityEnabled": false,
                "visibility": "Private",
                "description": "desc"
            }
        ]
    }
}
```

#### Human Readable Output

>### User 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 Teams
>|id|displayName|description|
>|---|---|---|
>| 02bd9fd6-8f93-4758-87c3-1fb73740a315 | MyGreatTeam | desc |
>| 8090c93e-ba7c-433e-9f39-08c7ba07c0b3 | WooahTeam | desc |