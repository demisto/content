Send messages, create rooms and more, via the Cisco Spark API.
This integration was integrated and tested with version 6.2.0 of Cisco Spark

## Configure Cisco Webex Teams in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Server URL (e.g. https://192.168.0.1) | True |
| API Key | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### cisco-spark-list-people

***
List people

#### Base Command

`cisco-spark-list-people`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| email | List people with this email address. For non-admin requests, either this or displayName are required. | Optional | 
| displayName | List people whose name starts with this string. For non-admin requests, either this or email are required. | Optional | 
| orgId | List people in this organization. Only admin users of another organization (such as partners) may use this parameter. | Optional | 
| max | Limit the maximum number of people in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.People | unknown | The list of people. | 

### cisco-spark-create-person

***
Create a new user account for a given organization. Only an admin can create a new user account.

#### Base Command

`cisco-spark-create-person`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| emails | Email addresses of the person (comma separated). | Optional | 
| displayName | Full name of the person. | Optional | 
| firstName | First name of the person. | Optional | 
| lastName | Last name of the person. | Optional | 
| avatar | URL to the person's avatar in PNG format. | Optional | 
| orgId | ID of the organization to which this person belongs. | Optional | 
| roles | Roles of the person (comma separated). | Optional | 
| licenses | Licenses allocated to the person. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-person-details

***
Shows details for a person, by ID.

#### Base Command

`cisco-spark-get-person-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| personId | The person ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-update-person

***
Update details for a person, by ID. Only an admin can update a person details.

#### Base Command

`cisco-spark-update-person`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| emails | Email addresses of the person (comma separated). | Optional | 
| displayName | Full name of the person. | Optional | 
| firstName | First name of the person. | Optional | 
| lastName | Last name of the person. | Optional | 
| avatar | URL to the person's avatar in PNG format. | Optional | 
| orgId | ID of the organization to which this person belongs. | Optional | 
| roles | Roles of the person (comma separated). | Optional | 
| licenses | Licenses allocated to the person (comma separated). | Optional | 
| personId | The person ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-person

***
Remove a person from the system. Only an admin can remove a person.

#### Base Command

`cisco-spark-delete-person`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| personId | The person ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-own-details

***
Show the profile for the authenticated user.

#### Base Command

`cisco-spark-get-own-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### cisco-spark-list-rooms

***
List rooms.

#### Base Command

`cisco-spark-list-rooms`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| teamId | Limit the rooms to those associatedwith a team, by ID. | Optional | 
| max | Limit the maximum number of rooms in the response. | Optional | 
| type | Available values: direct and group. direct returns all 1-to-1 rooms. group returns all group rooms. If not specified or values not matched, will return all room types. Possible values are: direct, group. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Rooms | unknown | The list of rooms. | 

### cisco-spark-create-room

***
Creates a room.

#### Base Command

`cisco-spark-create-room`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| title | A user-friendly name for the room. | Required | 
| teamId | The ID for the team with which this room is associated. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-room-details

***
Shows details for a room, by ID.

#### Base Command

`cisco-spark-get-room-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | The room ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-update-room

***
 Updates details for a room, by ID.

#### Base Command

`cisco-spark-update-room`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | The room ID. | Required | 
| title | A user-friendly name for the room. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-room

***
Deletes a room, by ID. Deleted rooms cannot be recovered.

#### Base Command

`cisco-spark-delete-room`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | The room ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-memberships

***
Lists all room memberships. Use either personId or personEmail to filter the results.

#### Base Command

`cisco-spark-list-memberships`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | Limit results to a specific room, by ID. | Optional | 
| personId | Limit results to a specific person, by ID. | Optional | 
| personEmail | Limit results to a specific person, by email address. | Optional | 
| max | Limit the maximum number of items in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Memberships | unknown | List of memberships. | 

### cisco-spark-create-membership

***
Add someone to a room by Person ID or email address; optionally making them a moderator.

#### Base Command

`cisco-spark-create-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | The room ID. | Required | 
| personId | The person ID. | Optional | 
| personEmail | The email address of the person. | Optional | 
| isModerator | Set to true to make the person a room moderator. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-membership-details

***
Get details for a membership by ID.

#### Base Command

`cisco-spark-get-membership-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membershipId | The membership ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-update-membership

***
Updates properties for a membership by ID.

#### Base Command

`cisco-spark-update-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membershipId | The membership ID. | Required | 
| isModerator | Set to true to make the person a room moderator. Possible values are: true, false. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-membership

***
Deletes a membership by ID.

#### Base Command

`cisco-spark-delete-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membershipId | The membership ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-messages

***
Lists all messages in a room.

#### Base Command

`cisco-spark-list-messages`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | List messages for a room, by ID. | Required | 
| mentionedPeople | List messages where the caller is mentioned by specifying "me" or the caller personId. | Optional | 
| before | List messages sent before a date and time, in ISO8601 format. | Optional | 
| beforeMessage | List messages sent before a message, by ID. | Optional | 
| max | Limit the maximum number of messages in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Messages | unknown | List of messages, by roomId. | 

### cisco-spark-create-message

***
Posts a plain text message, and optionally, a media content attachment, to a room.

#### Base Command

`cisco-spark-create-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roomId | The room ID. | Optional | 
| toPersonId | The ID of the recipient when sending a private 1:1 message. | Optional | 
| toPersonEmail | The email address of the recipient when sending a private 1:1 message. | Optional | 
| text | The message, in plain text. If markdown is specified this parameter may be optionally used to provide alternate text forUI clients that do not support rich text. | Optional | 
| markdown | The message, in markdown format. | Optional | 
| files | The public URL to a binary file to be posted into the room. Only one file is allowed per message. Uploaded files are automatically converted into a format that all Spark clients can render. For the supported media types and the behavior of uploads, see the Message AttachmentsGuide. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-message-details

***
Shows details for a message, by message ID.

#### Base Command

`cisco-spark-get-message-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messageId | The message ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-message

***
Deletes a message, by message ID.

#### Base Command

`cisco-spark-delete-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| messageId | The message ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-teams

***
Lists teams to which the authenticated user belongs.

#### Base Command

`cisco-spark-list-teams`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max | Limit the maximum number of teams in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Teams | unknown | List of teams. | 

### cisco-spark-create-team

***
Creates a team. The authenticated user is automatically added as a member of the team.

#### Base Command

`cisco-spark-create-team`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A user-friendly name for the team. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-team-details

***
Shows details for a team, by ID.

#### Base Command

`cisco-spark-get-team-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| teamId | The team ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-update-team

***
Updates details for a team, by ID.

#### Base Command

`cisco-spark-update-team`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| teamId | The team ID. | Required | 
| name | A user-friendly name for the team. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-team

***
Deletes a team, by ID.

#### Base Command

`cisco-spark-delete-team`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| teamId | The team ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-team-memberships

***
Lists all team memberships for a given team, specified by the teamId query parameter.

#### Base Command

`cisco-spark-list-team-memberships`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| teamId | List team memberships for a team, by ID. | Required | 
| max | Limit the maximum number of items in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.TeamMemberships | unknown | List of team memberships. | 

### cisco-spark-create-team-membership

***
Add someone to a team by Person ID or email address; optionally making them a moderator.

#### Base Command

`cisco-spark-create-team-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| teamId | The team ID. | Required | 
| personId | The person ID. | Optional | 
| personEmail | The email address of the person. | Optional | 
| isModerator | Set to true to make the person a team moderator. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-team-membership-details

***
Shows details for a team membership, by ID.

#### Base Command

`cisco-spark-get-team-membership-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membershipId | The membership ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-update-team-membership

***
Updates a team membership, by ID.

#### Base Command

`cisco-spark-update-team-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membershipId | The membership ID. | Required | 
| isModerator | Set to true to make the person a team moderator. Possible values are: true, false. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-team-membership

***
Deletes a team membership, by ID.

#### Base Command

`cisco-spark-delete-team-membership`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membershipId | The membership ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-webhooks

***
Lists all of your webhooks.

#### Base Command

`cisco-spark-list-webhooks`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max | Limit the maximum number of webhooks in the response. Setting this to greater than 100 will return an error. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Webhooks | unknown | List of webhooks. | 

### cisco-spark-create-webhook

***
Creates a webhook.

#### Base Command

`cisco-spark-create-webhook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | A user-friendly name for this webhook. | Required | 
| targetUrl | The URL that receives POST requests for each event. | Required | 
| resource | The resource type for the webhook. Creating a webhook requires 'read' scope on the resource the webhook is for. | Required | 
| event | The event type for the webhook. | Required | 
| filter | The filter that defines the webhook scope. | Optional | 
| secret | Secret used to generate payload signature. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-get-webhook-details

***
Shows details for a webhook, by ID.

#### Base Command

`cisco-spark-get-webhook-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| webhookId | The webhook ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-update-webhook

***
Updates a webhook, by ID.

#### Base Command

`cisco-spark-update-webhook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| webhookId | The webhook ID. | Required | 
| name | A user-friendly name for this webhook. | Required | 
| targetUrl | The URL that receives POST requests for each event. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-delete-webhook

***
Deletes a webhook, by ID.

#### Base Command

`cisco-spark-delete-webhook`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| webhookId | The webhook ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-organizations

***
List all organizations visible by your account.

#### Base Command

`cisco-spark-list-organizations`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max | Limit the maximum number of entries in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Organizations | unknown | List of organizations. | 

### cisco-spark-get-organization-details

***
Shows details for an organization, by ID.

#### Base Command

`cisco-spark-get-organization-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | The organization ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-licenses

***
List all licenses for a given organization. If no orgId is specified, the default is the organization of the authenticated user.

#### Base Command

`cisco-spark-list-licenses`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| orgId | Specify the organization. | Optional | 
| max | Limit the maximum number of entries in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Licenses | unknown | List of licenses. | 

### cisco-spark-get-license-details

***
Shows details for a license, by ID.

#### Base Command

`cisco-spark-get-license-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| licenseId | The license ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-list-roles

***
List all roles.

#### Base Command

`cisco-spark-list-roles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| max | Limit the maximum number of entries in the response. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CiscoSpark.Roles | unknown | List of roles. | 

### cisco-spark-get-role-details

***
Shows details for a role, by ID.

#### Base Command

`cisco-spark-get-role-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleId | The role ID. | Required | 

#### Context Output

There is no context output for this command.
### cisco-spark-send-message-to-person

***
Sends a message to a person, by email or person ID.

#### Base Command

`cisco-spark-send-message-to-person`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| toPersonEmail | Email address of the recipient. | Optional | 
| toPersonId | The personId of the recipient. | Optional | 
| text | The message, in plain text. If markdown is specified this parameter may be optionally used to provide alternate text forUI clients that do not support rich text. | Optional | 
| markdown | The message, in markdown format. | Optional | 
| files | The public URL to a binary file to be posted into the room. Only one file is allowed per message. Uploaded files are automatically converted into a format that all Spark clients can render. For the supported media types and the behavior of uploads, see the Message AttachmentsGuide. | Optional | 

#### Context Output

There is no context output for this command.
### cisco-spark-send-message-to-room

***
Sends a message to a room, by name or room ID.

#### Base Command

`cisco-spark-send-message-to-room`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| toRoomName | The room name. | Optional | 
| roomId | The room ID. | Optional | 
| text | The message, in plain text. If markdown is specified this parameter may be optionally used to provide alternate text forUI clients that do not support rich text. | Optional | 
| markdown | The message, in markdown format. | Optional | 
| files | The public URL to a binary file to be posted into the room. Only one file is allowed per message. Uploaded files are automatically converted into a format that all Spark clients can render. For the supported media types and the behavior of uploads, see the Message AttachmentsGuide. | Optional | 

#### Context Output

There is no context output for this command.