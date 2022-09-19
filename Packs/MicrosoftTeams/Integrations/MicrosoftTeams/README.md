Send messages and notifications to your team members.
This integration was integrated and tested with version xx of Microsoft Teams

## Configure Microsoft Teams on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Teams.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Bot ID |  | True |
    | Bot Password |  | True |
    | Tenant ID |  | False |
    | Default team |  | True |
    | Notifications channel |  | True |
    | Certificate (Required for HTTPS) |  | False |
    | Private Key (Required for HTTPS) |  | False |
    | Minimum incident severity to send notifications to Teams by |  | False |
    | Disable Automatic Notifications | Whether to disable automatic notifications to the configured notifications channel. | False |
    | Allow external users to create incidents via direct message |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Long running instance |  | False |
    | Listen port, e.g. 7000 (Required for investigation mirroring and direct messages) |  | False |
    | Incident type |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### send-notification
***
Sends a message to the specified teams.
To mention a user in the message, add a semicolon ";" at the end of the user mention. For example: @Bruce Willis;


#### Base Command

`send-notification`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel to which to send messages. | Optional | 
| message | The message to send to the channel or team member. | Optional | 
| team_member | Display name or email address of the team member to send the message to. | Optional | 
| team | The team in which the specified channel exists. The team must already exist, and this value will override the default channel configured in the integration parameters. | Optional | 
| adaptive_card | The Microsoft Teams adaptive card to send. | Optional | 
| to | The team member to which to send the message. | Optional | 


#### Context Output

There is no context output for this command.
### mirror-investigation
***
Mirrors the XSOAR investigation to the specified Microsoft Teams channel.


#### Base Command

`mirror-investigation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mirror_type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. Possible values are: all, chat, none. Default is all. | Optional | 
| autoclose | Whether to auto-close the channel when the incident is closed in XSOAR. If "true", the channel will be auto-closed. Default is "true". Possible values are: true, false. Default is true. | Optional | 
| direction | The mirroring direction. Can be "FromDemisto", "ToDemisto", or "Both". Possible values are: Both, FromDemisto, ToDemisto. Default is both. | Optional | 
| team | The team in which to mirror the XSOAR investigation. If not specified, the default team configured in the integration parameters will be used. | Optional | 
| channel_name | The name of the channel. The default is "incident-&lt;incidentID&gt;". | Optional | 


#### Context Output

There is no context output for this command.
### close-channel
***
Deletes the specified Microsoft Teams channel.


#### Base Command

`close-channel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The name of the channel to close. | Optional | 


#### Context Output

There is no context output for this command.
### microsoft-teams-integration-health
***
Returns real-time and historical data on the integration status.


#### Base Command

`microsoft-teams-integration-health`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

There is no context output for this command.
### microsoft-teams-ring-user
***
Ring a user's Teams account. Note: This is a ring only! no media will play in case the generated call is answered. To use this make sure your Bot has the following permissions - Calls.Initiate.All and Calls.InitiateGroupCall.All


#### Base Command

`microsoft-teams-ring-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The display name of the member to call. | Required | 


#### Context Output

There is no context output for this command.
### microsoft-teams-add-user-to-channel
***
Adds a member (user) to a private channel.


#### Base Command

`microsoft-teams-add-user-to-channel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel to which to add the member. | Required | 
| team | The channel's team. | Required | 
| member | The display name of the member to add to the channel. | Required | 


#### Context Output

There is no context output for this command.
### microsoft-teams-create-channel
***
Creates a new channel in a Microsoft Teams team.


#### Base Command

`microsoft-teams-create-channel`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_name | The name of the channel. | Required | 
| description | The description of the channel. | Optional | 
| team | The team in which to create the channel. | Required | 


#### Context Output

There is no context output for this command.
### microsoft-teams-create-meeting
***
Creates a new meeting in Microsoft Teams.


#### Base Command

`microsoft-teams-create-meeting`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| start_time | The meeting start time in ISO 8601 format e.g., "2019-07-12T14:30:34.2444915-07:00". | Optional | 
| end_time | The meeting end time in ISO 8601 format e.g., "2019-07-12T14:30:34.2444915-07:00". | Optional | 
| subject | The meeting subject. | Required | 
| member | Display name/mail/UPN of user who created the meeting, e.g., Adam Smith. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.CreateMeeting.creationDateTime | Date | Meeting creation time. | 
| MicrosoftTeams.CreateMeeting.threadId | String | Meeting thread ID. | 
| MicrosoftTeams.CreateMeeting.messageId | String | Meeting message ID. | 
| MicrosoftTeams.CreateMeeting.id | String | Meeting ID. | 
| MicrosoftTeams.CreateMeeting.joinWebUrl | String | The URL to join the meeting. | 
| MicrosoftTeams.CreateMeeting.participantId | String | The meeting participants. | 
| MicrosoftTeams.CreateMeeting.participantDisplayName | String | The display name of the participants. | 
