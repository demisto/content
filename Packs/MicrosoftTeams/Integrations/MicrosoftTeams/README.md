Use the Microsoft Teams integration to send messages and notifications to your team members.
This integration was integrated and tested with version 1.0 of Microsoft Teams.

## Integration Architecture
Data is passed between Microsoft Teams and Demisto through the bot that you will configure in Microsoft Teams. A webhook (which you will configure) receives the data from Teams and passes it to the messaging endpoint. The web server on which the integration runs in Demisto listens to the messaging endpoint and processes the data from Teams. You can use an engine for communication between Teams and the Demisto server. In order to mirror messages from Teams to Demisto, the bot must be mentioned, using the @ symbol, in the message.

The web server for the integration runs within a long-running Docker container. Demisto maps the Docker port to which the server listens, to the host port (to which Teams posts messages). For more information, see [our documentation](https://xsoar.pan.dev/docs/integrations/long-running#invoking-http-integrations-via-cortex-xsoar-servers-route-handling) and [Docker documentation](https://docs.docker.com/config/containers/container-networking/).
### Protocol Diagram
![image](https://raw.githubusercontent.com/demisto/content/b222375925eb13feaaa28cd8b1c814b4d212f2e4/Integrations/MicrosoftTeams/doc_files/MicrosoftTeamsProtocalDiagram.png)

## Important Information
 - The messaging endpoint must be either the URL of the Demisto server, including the configured port, or the proxy that redirects the messages received from Teams to the Demisto server. 
 - It's important that the port is opened for outside communication and that the port is not being used, meaning that no service is listening on it. Therefore, the default port, 443, should not be used.
 - For additional security, we recommend placing the Teams integration webserver behind a reverse proxy (such as nginx).
 - By default, the web server that the integration starts provides services in HTTP. For communication to be in HTTPS you need to provide a certificate and private key in the following format:
 ```
 `-----BEGIN CERTIFICATE-----`
 `...`
 `-----END CERTIFICATE-----`
```
 ```
 `-----BEGIN PRIVATE KEY-----`
 `...`
 `-----END PRIVATE KEY-----`
```

## Prerequisites

Before you can create an instance of the Microsoft Teams integration in Demisto, you need to complete the following procedures.

1. [Create the Demisto Bot in Microsoft Teams](#create-the-demisto-bot-in-microsoft-teams)
2. [Grant the Demisto Bot Permissions in Microsoft Graph](#grant-the-demisto-bot-permissions-in-microsoft-graph)
3. [Configure Microsoft Teams on Demisto](#configure-microsoft-teams-on-demisto)
4. [Add the Demisto Bot to a Team](#add-the-demisto-bot-to-a-team)

### Create the Demisto Bot in Microsoft Teams

1. Download the ZIP file located at the bottom of this article.
2. In Microsoft Teams, access the Store.
3. Search for and click **App Studio**.
4. Click the **Open** button.
5. For the **Bot** option, click **Open**.
6. Click the **Manifest editor** tab.
7. Click the **Import an existing app** button, and select the ZIP file that you downloaded.
8. Click the app widget, and in the **Identification** section, click the **Generate** button to generate a unique App ID.  The following parameters are automatically populated in the ZIP file, use this information for reference.
  - **Short name**: Demisto Bot
  - **App ID**: the App ID for configuring in Demisto.
  - **Package name**: desmisto.bot (this is a unique identifier for the app in the Store)
  - **Version**: 1.0.0 (this is a unique identifier for the app in the Store)
  - **Short description**: Mechanism for mirroring between Demisto and Microsoft Teams.
  - **Long description**: Demisto Bot is the mechanism that enables messaging team members and channels, executing Demisto commands directly from Teams, and mirroring investigation data between Demisto and Microsoft Teams

9. From the left-side navigation pane, under Capabilities, click **Bots > Set up**.
10. Configure the settings under the **Scope** section, and click **Create bot**.
  - In the **Name** field, enter *Demisto Bot*.
  - Select all checkboxes.

11. Record the **Bot ID**, which you will need when configuring the integration in Demisto.
![image](https://raw.githubusercontent.com/demisto/content/b222375925eb13feaaa28cd8b1c814b4d212f2e4/Integrations/MicrosoftTeams/doc_files/MSTeams-BotID.png)
12. Click **Generate new password**. Record the password, which you will need when configuring the integration in Demisto.
13. In the **Messaging endpoints** section, enter the URL to which messages will be sent (to the Demisto Bot).
  - To enable calling capabilities on the Bot enter the same URL to the **Calling endpoints** section.
14. From the left-side navigation pane, under Finish, click **Test and distribute**.
15. To download the new bot file, which now includes App Details, click **Download**.
16. Navigate to Store, and click **Upload a custom app > Upload for <yourOrganization>**, and select the ZIP file you downloaded.

### Grant the Demisto Bot Permissions in Microsoft Graph

1. Go to your Microsoft Azure portal, and from the left navigation pane select **Azure Active Directory > App registrations**.
2. Search for and click **Demisto Bot**.
3. Click **API permissions > Add a permission > Microsoft Graph > Application permissions**.
4. For the following permissions, search for,  select the checkbox and click **Add permissions**.
  - User.ReadWrite.All
  - Directory.ReadWrite.All
  - Group.ReadWrite.All
  - Calls.Initiate.All
  - Calls.InitiateGroupCall.All

5. Verify that all permissions were added, and click **Grant admin consent for Demisto**.
6. When prompted to verify granting permissions, click **Yes**, and verify that permissions were successfully added.



### Configure Microsoft Teams on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Teams.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| bot_id | Bot ID | True |
| bot_password | Bot Password | True |
| team | Default team - team to which messages and notifications are sent. If a team is specified as a command argument, it overrides this parameter | True |
| incident_notifications_channel | Notifications channel | True |
| certificate | Certificate (Required for HTTPS) | False |
| key | Private Key (Required for HTTPS) | False |
| min_incident_severity | Minimum incident severity to send notifications to Teams by | False |
| allow_external_incidents_creation | Allow external users to create incidents via direct message | False |
| insecure | Trust any certificate (not secure) | False |
| proxy | Use system proxy settings | False |
| longRunning | Long running instance | False |
| longRunningPort | Listen port, e.g. 7000 (Required for investigation mirroring and direct messages) | False |
| incidentType | Incident type | False |

4. Click **Test** to validate the URLs, token, and connection.

### Add the Demisto Bot to a Team

1. In Microsoft Teams, access the Store.
2. Search for **Demisto Bot** and click the Demisto Bot widget.
3. Click the arrow on the **Open** button and select **Add to a team**.
4. In the search box, type the name of the team to which to add the bot.
5. Click **Set up** and configure the new app.

## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### Send a message to teams
***
Sends a message to the specified teams.
To mention a user in the message, add a semicolon ";" at the end of the user mention. For example: @Bruce Willis;


##### Base Command

`send-notification`

##### Required Permissions

`Group.ReadWrite.All`
`User.ReadWrite.All`
`Directory.ReadWrite.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel to which to send messages. | Optional | 
| message | The message to send to the channel or team member. | Optional | 
| team_member | The team member to which to send the message. | Optional | 
| team | The team in which the specified channel exists. The team must already exist, and this value will override the default channel configured in the integration parameters. | Optional | 
| adaptive_card | The Microsoft Teams adaptive card to send. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!sent-notification channel=General message="hello world!" team=DemistoTeam```

##### Human Readable Output
Message was sent successfully.

### Mirror an investigation to a Microsoft Teams channel
***
Mirrors the Demisto investigation to the specified Microsoft Teams channel.


##### Base Command

`mirror-investigation`

##### Required Permissions

`Group.ReadWrite.All`
`User.ReadWrite.All`
`Directory.ReadWrite.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mirror_type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. | Optional | 
| autoclose | Whether to auto-close the channel when the incident is closed in Demisto. If "true", the channel will be auto-closed. Default is "true". | Optional | 
| direction | The mirroring direction. Can be "FromDemisto", "ToDemisto", or "Both". | Optional | 
| team | The team in which to mirror the Demisto investigation. If not specified, the default team configured in the integration parameters will be used. | Optional | 
| channel_name | The name of the channel. The default is "incident-<incidentID>". | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mirror-investigation mirror_type=all autoclose=true direction=Both```


##### Human Readable Output
Investigation mirrored successfully in channel incident-100.

### Delete a channel
***
Deletes the specified Microsoft Teams channel.


##### Base Command

`close-channel`

##### Required Permissions

`Group.ReadWrite.All`
`User.ReadWrite.All`
`Directory.ReadWrite.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The name of the channel to close. | Optional | 


##### Context Output

There is no context output for this command.

##### Command Example
```!close-channel channel="example channel"```


##### Human Readable Output
Channel was successfully closed.

### Get information on the integration status
***
Returns real-time and historical data on the integration status.


##### Base Command

`microsoft-teams-integration-health`
##### Input

There are no input arguments for this command.

##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-integration-health```


##### Human Readable Output
### Microsoft API Health
|Bot Framework API Health|Graph API Health|
|---|---|
| Operational | Operational |
No mirrored channels.

### Ring a user's Team account
***
Rings a user's Teams account. Note: This is a ring only! no media will play in case the generated call is answered. To use this make sure your Bot has the following premissions - Calls.Initiate.All and Calls.InitiateGroupCall.All


##### Base Command

`microsoft-teams-ring-user`

##### Required Permissions

`Calls.Initiate.All`
`Calls.InitiateGroupCall.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | The display name of the member to call. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-ring-user username="Avishai Brandeis"```


##### Human Readable Output
Calling Avishai Brandeis

### Add a user to a channel
***
Adds a member (user) to a private channel.


##### Base Command

`microsoft-teams-add-user-to-channel`

##### Required Permissions

`Group.ReadWrite.All`
`User.ReadWrite.All`
`Directory.ReadWrite.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel to which to add the add the member to this channel | Required | 
| team | The channel's team. | Required | 
| member | The display name of the member to add to the channel. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-add-user-to-channel channel="example channel" member=itayadmin team=DemistoTeam```

##### Human Readable Output
The User "itayadmin" has been added to channel "example channel" successfully.

### Create a channel
***
Creates a new channel in a Microsoft Teams team.


##### Base Command

`microsoft-teams-create-channel`

##### Required Permissions

`Group.ReadWrite.All`
`User.ReadWrite.All`
`Directory.ReadWrite.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_name | The name of the channel. | Required | 
| description | The description of the channel. | Optional | 
| team | The team in which to create the channel. | Required | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-create-channel channel_name="example channel" team=DemistoTeam description="this is my new channel"```


##### Human Readable Output
The channel "example channel" was created successfully

[Demisto Bot zip](https://raw.githubusercontent.com/demisto/content/b222375925eb13feaaa28cd8b1c814b4d212f2e4/Integrations/MicrosoftTeams/doc_files/DemistoBot.zip)
