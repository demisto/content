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
 - For additional security, we recommend placing the Teams integration webserver behind a reverse proxy (such as NGINX).
 - By default, the web server that the integration starts provides services in HTTP. For communication to be in HTTPS you need to provide a certificate and private key in the following format:
    ```
     -----BEGIN CERTIFICATE-----
     ...
     -----END CERTIFICATE-----
    ```
    ```
     -----BEGIN PRIVATE KEY-----
     ...
     -----END PRIVATE KEY-----
    ```
 - Microsoft does not support self-signed certificates and requires a chain-trusted certificate issued by a trusted CA.
 
## Setup Examples

### 1. Using Cortex XSOAR rerouting
In this configuration, we will use Cortex XSOAR functionality, which reroutes HTTPS requests that hit the default port (443) to the web server that the integration spins up.

The messaging endpoint needs to be: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`, e.g. `https://my.demisto.live/instance/execute/teams`

The integration instance name, `teams` in this example, needs to be configured in the [Configure Microsoft Teams on Demisto](#configure-microsoft-teams-on-demisto) step.

The port to be configured in [Configure Microsoft Teams on Demisto](#configure-microsoft-teams-on-demisto) step should be any available port that is not used by another service.

In addition, make sure ***Instance execute external*** is enabled. 

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** (`instance.execute.external.teams` in this example) key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.

 - Note: This option is available from Cortex XSOAR v5.5.0 and later.

### 2. Using NGINX as reverse proxy
In this configuration, the inbound connection, from Microsoft Teams to Cortex XSOAR, goes through a reverse proxy (e.g. NGINX) which relays the HTTPS requests posted from Microsoft Teams
to the Cortex XSOAR server on HTTP.

On NGINX, configure the following:
 - SSL certificate under `ssl_certificate` and `ssl_certificate_key`
 - The Cortex XSOAR server (including the port) under `proxy_pass`, e.g. `http://mydemistoinstance.com:7000`
 
Follow [Configuring Upstream Servers NGINX guide](https://docs.nginx.com/nginx/admin-guide/security-controls/securing-http-traffic-upstream/#configuring-upstream-servers) for more details.

The port (`7000` in this example), to which the reverse proxy should forward the traffic on HTTP, should be the same port you specify in the integration instance configuration, as the webserver the integration spins up, listens on that port.

![image](https://github.com/demisto/content/raw/fa322765a440f8376bbf7ac85f0400beb720f712/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/RP-NGINX.png)

![image](https://github.com/demisto/content/raw/fa322765a440f8376bbf7ac85f0400beb720f712/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/InstanceConfig7000.png)

### 3. Using Apache reverse proxy and Cortex XSOAR engine
In this configuration, the inbound connection, from Microsoft Teams to Cortex XSOAR, goes through a reverse proxy (e.g. [Apache](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html)) and possibly a load balancer, which relays the HTTPS requests posted from Microsoft Teams
to a Cortex XSOAR engine, which can be put in a DMZ, on HTTP.

The port (`7000` in this example), to which the reverse proxy should forward the traffic on HTTP, should be the same port you specify in the integration instance configuration, as the webserver the integration spins up, listens on that port.

![image](https://github.com/demisto/content/raw/fa322765a440f8376bbf7ac85f0400beb720f712/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/RP-Engine.png)

![image](https://github.com/demisto/content/raw/fa322765a440f8376bbf7ac85f0400beb720f712/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/InstanceConfig7000.png)


### 4. Using Cloudflare
In this configuration, we will use [Cloudflare proxy](https://support.cloudflare.com/hc/en-us/articles/360039824852-Cloudflare-and-the-Cloud-Conceptual-overview-videos).

The messaging endpoint should be the Cortex XSOAR URL, which need to be hosted on Cloudflare, with the port to which Cloudflare proxy directs the HTTPS traffic, e.g. `https://mysite.com:8443`

In the [Configure Microsoft Teams on Demisto](#configure-microsoft-teams-on-demisto) step, the following need to be configured:
 - The port selected above.
 - A certificate and key for configuring HTTPS webserver. This certificate can be self-signed.

The proxy intercepts HTTPS traffic, presents a public CA certificate, then proxies it to the webserver.

All HTTPS traffic that will hit the selected messaging endpoint will be directed to the HTTPS webserver the integration spins up, and will then be processed.

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
  - In the **Scope** section, select the following checkboxes: `Personal`, `Team`, and `Group Chat`. 

11. Record the **Bot ID**, which you will need when configuring the integration in Demisto.
![image](https://raw.githubusercontent.com/demisto/content/b222375925eb13feaaa28cd8b1c814b4d212f2e4/Integrations/MicrosoftTeams/doc_files/MSTeams-BotID.png)
12. Click **Generate new password**. Record the password, which you will need when configuring the integration in Demisto.
13. In the **Messaging endpoints** section, enter the URL to which messages will be sent (to the Demisto Bot).
  - To enable calling capabilities on the Bot enter the same URL to the **Calling endpoints** section.
14. From the left-side navigation pane, under Finish, click **Test and distribute**.
15. To download the new bot file, which now includes App Details, click **Download**.
16. Navigate to Store, and click **Upload a custom app > Upload for ORGANIZATION-NAME**, and select the ZIP file you downloaded.

### Grant the Demisto Bot Permissions in Microsoft Graph

1. Go to your Microsoft Azure portal, and from the left navigation pane select **Azure Active Directory > App registrations**.
2. Search for and click **Demisto Bot**.
3. Click **API permissions > Add a permission > Microsoft Graph > Application permissions**.
4. For the following permissions, search for,  select the checkbox and click **Add permissions**.
  - User.Read.All
  - Group.ReadWrite.All
  - Calls.Initiate.All
  - Calls.InitiateGroupCall.All
  - TeamMember.ReadWrite.All

5. Verify that all permissions were added, and click **Grant admin consent for Demisto**.
6. When prompted to verify granting permissions, click **Yes**, and verify that permissions were successfully added.



### Configure Microsoft Teams on Demisto

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Teams.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Name | The integration instance name.<br />If using Cortex XSOAR rerouting configuration, insert here the instance name you configured in the messaging endpoint. | True |
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

  - Note: the following need to be done after configuring the integration on Cortex XSOAR (the previous step).
  
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

`Group.Read.All`

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
```!send-notification channel=General message="hello world!" team=DemistoTeam```

##### Human Readable Output
Message was sent successfully.

### Mirror an investigation to a Microsoft Teams channel
***
Mirrors the Demisto investigation to the specified Microsoft Teams channel.


##### Base Command

`mirror-investigation`

##### Required Permissions

`Group.ReadWrite.All`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| mirror_type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. | Optional | 
| autoclose | Whether to auto-close the channel when the incident is closed in Demisto. If "true", the channel will be auto-closed. Default is "true". | Optional | 
| direction | The mirroring direction. Can be "FromDemisto", "ToDemisto", or "Both". | Optional | 
| team | The team in which to mirror the Demisto investigation. If not specified, the default team configured in the integration parameters will be used. | Optional | 
| channel_name | The name of the channel. The default is "incident-INCIDENTID". | Optional | 


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

`User.Read.All`
`ChannelMember.ReadWrite.All`

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

### microsoft-teams-create-team
***
Creates a new team.


#### Base Command

`microsoft-teams-create-team`

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
```!microsoft-teams-create-team display_name="Sample Engineering Team" owner=3fa9f28b-eb0e-463a-ba7b-8089fe9991e2```

#### Human Readable Output

>Team Sample Engineering Team was created successfully.

### microsoft-teams-create-team-from-group
***
Create a new team under a group. In order to create a team, the group must have a least one owner and the group cannot be of type Security.


#### Base Command

`microsoft-teams-create-team-from-group`

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
```!microsoft-teams-create-team-from-group group_id=7bc73bf4-c88e-4e0c-a927-6b52d19ca3e6```

#### Human Readable Output

>The team was created from group 7bc73bf4-c88e-4e0c-a927-6b52d19ca3e6 successfully.

### microsoft-teams-list-teams
***
Returns all the groups that have teams in an organization.


#### Base Command

`microsoft-teams-list-teams`

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
```!microsoft-teams-list-teams```

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

### microsoft-teams-get-team
***
Retrieve the properties and relationships of the specified team.


#### Base Command

`microsoft-teams-get-team`

##### Required Permissions

`Team.ReadBasic.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of team to get. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 


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
```!microsoft-teams-get-team team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

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

### microsoft-teams-update-team
***
Update the properties of the specified team.


#### Base Command

`microsoft-teams-update-team`

##### Required Permissions

`TeamSettings.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to update. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 
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
```!microsoft-teams-update-team team_id=489080f2-98c3-4993-84ec-fa0aac622b2e description=NewDescription```

#### Human Readable Output

>Team 489080f2-98c3-4993-84ec-fa0aac622b2e was updated successfully.

### microsoft-teams-delete-team
***
Deletes a group. Note: it might take time for the team to disappear from the teams list.


#### Base Command

`microsoft-teams-delete-team`

##### Required Permissions

`Group.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to delete. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-delete-team team_id=8d64be1b-590f-4afd-9bac-0b31b3703300```

#### Human Readable Output

>Team 8d64be1b-590f-4afd-9bac-0b31b3703300 was deleted successfully.

### microsoft-teams-list-members
***
Returns the members of the specified team.


#### Base Command

`microsoft-teams-list-members`

##### Required Permissions

`TeamMember.Read.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to get the member of. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-list-members team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

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

### microsoft-teams-get-member
***
Gets a member of a team.


#### Base Command

`microsoft-teams-get-member`

##### Required Permissions

`TeamMember.Read.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| membership_id | ID of member to get. Can be retrieved by running the microsoft-teams-list-members command. | Required | 
| team_id | ID of the team to get the member of. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-get-member membership_id=NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMzZmE5ZjI4Yi1lYjBlLTQ2M2EtYmE3Yi04MDg5ZmU5OTkxZTI= team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

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

### microsoft-teams-add-member
***
Add a user to be a team member.


#### Base Command

`microsoft-teams-add-member`

##### Required Permissions

`TeamMember.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to add the user to. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 
| user_id | ID of the user to add to the team. Can be retrieved by running the microsoft-teams-list-members command. | Required | 
| is_owner | Whether to add the member with the owner role. Possible values are: "false" and "true". Default is "false". Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-add-member user_id=2827c1e7-edb6-4529-b50d-25984e968637 team_id=489080f2-98c3-4993-84ec-fa0aac622b2e```

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


### microsoft-teams-remove-member
***
Remove a member from the team.


#### Base Command

`microsoft-teams-remove-member`

##### Required Permissions

`TeamMember.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to remove the user from. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 
| membership_id | ID of the member to remove from the team. Can be retrieved by running the microsoft-teams-list-members command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-remove-member team_id=489080f2-98c3-4993-84ec-fa0aac622b2e membership_id=NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMxZTc2NTVhNC02ZThmLTQ2NjUtYWMxNS03ZWJhMmJmOGQ4ODY=```

#### Human Readable Output

>Team member NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyMxZTc2NTVhNC02ZThmLTQ2NjUtYWMxNS03ZWJhMmJmOGQ4ODY= was removed from the team 489080f2-98c3-4993-84ec-fa0aac622b2e successfully.

### microsoft-teams-update-member
***
Updates a team member.


#### Base Command

`microsoft-teams-update-member`

##### Required Permissions

`TeamMember.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to update the member in. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 
| membership_id | ID of the team member to update. Can be retrieved by running the microsoft-teams-list-members command. | Required | 
| is_owner | Whether to set the member with the owner role. Possible values are: "false" and "true". Default is "false". Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.TeamMember.displayName | String | The display name of the user. | 
| MicrosoftTeams.TeamMember.email | String | The email of the user. | 
| MicrosoftTeams.TeamMember.id | String | Unique ID of the user. | 
| MicrosoftTeams.TeamMember.roles | String | The roles for that user. | 


#### Command Example
```!microsoft-teams-update-member membership_id=NDg5MDgwZjItOThjMy00OTkzLTg0ZWMtZmEwYWFjNjIyYjJlIyM4OTE4YzM5MC0zNWI4LTQyYzMtODNmMS04MzUyZTBlOWRmNjU= team_id=489080f2-98c3-4993-84ec-fa0aac622b2e is_owner=true```

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

### microsoft-teams-archive-team
***
Archive the specified team. When a team is archived, users can no longer send or like messages on any channel in the team, edit the team's name, description, or other settings, or in general make most changes to the team. Membership changes to the team continue to be allowed. Archiving is an async operation. A team is archived once the async operation completes successfully, which may occur subsequent to a response from this command. In order to archive a team, the team and group must have an owner.


#### Base Command

`microsoft-teams-archive-team`

##### Required Permissions

`TeamSettings.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to archive. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-archive-team team_id=d74944a4-8dca-4cc5-9892-b1f73b4a4419```

#### Human Readable Output

>Team d74944a4-8dca-4cc5-9892-b1f73b4a4419 was archived successfully.

### microsoft-teams-unarchive-team
***
Restore an archived team. This restores the users' ability to send messages and edit the team, abiding by tenant and team settings. Unarchiving is an async operation. A team is unarchived once the async operation completes successfully, which may occur subsequent to a response from this command.


#### Base Command

`microsoft-teams-unarchive-team`

##### Required Permissions

`TeamSettings.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to unarchive. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!microsoft-teams-unarchive-team team_id=d74944a4-8dca-4cc5-9892-b1f73b4a4419```

#### Human Readable Output

>Team d74944a4-8dca-4cc5-9892-b1f73b4a4419 was unarchived successfully.

### microsoft-teams-clone-team
***
Create a copy of a team. This operation also creates a copy of the corresponding group. Cloning is a long-running operation.


#### Base Command

`microsoft-teams-clone-team`

##### Required Permissions

`Group.ReadWrite.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_id | ID of the team to clone. Can be retrieved by running the microsoft-teams-list-teams command. | Required | 
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
```!microsoft-teams-clone-team team_id=6e0d7429-4736-4373-bfb7-a1b59e3c463a display_name=Cloned```

#### Human Readable Output

>Team 6e0d7429-4736-4373-bfb7-a1b59e3c463a was cloned successfully.

### microsoft-teams-list-joined-teams
***
Get the teams in Microsoft Teams that the user is a direct member of.


#### Base Command

`microsoft-teams-list-joined-teams`

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
```!microsoft-teams-list-joined-teams user_id=3fa9f28b-eb0e-463a-ba7b-8089fe9991e2```

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

## Running commands from Microsoft Teams
You can run Cortex XSOAR commands, according to the user permissions, from Microsoft Teams in a mirrored investigation channel.

Note: Like every message in a mirrored channel, in order for it to be passed to the bot, the bot must be mentioned.

For example, in order to check the reputation of the IP address 8.8.8.8, run the following: `@Demisto Bot !ip ip=8.8.8.8`

![image](https://raw.githubusercontent.com/demisto/content/c7d516e68459f04102fd31ebfadd6574d775f436/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/cmd.png)

## Direct messages commands
You can chat with the bot in direct messages in order to retrieve data (list incidents and tasks) and run operations (create incident and mirror an investigation) related to Cortex XSOAR.

You can send the message `help` in order to see the supported commands:

![image](https://raw.githubusercontent.com/demisto/content/c7d516e68459f04102fd31ebfadd6574d775f436/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/dm.png)

## Troubleshooting

1. The integration works by spinning up a webserver that listens to events and data posted to it from Microsoft Teams.

    If you see the error message `Did not receive tenant ID from Microsoft Teams, verify the messaging endpoint is configured correctly.`, then it means that the tenant ID was never posted to the webserver, which should happen for the first time when the bot is added to the configured team.
    
    This probably means that there is a connection issue, and the webserver does not intercept the HTTPS queries from Microsoft Teams.
    
    In order to troubleshoot, first verify the Docker container is up and running and publish the configured port to the outside world:
    
    From the Cortex XSOAR / Cortex XSOAR engine machine run: `docker ps | grep teams`
    
    You should see the following, assuming port 7000 is used:
    
    `988fdf341127        demisto/teams:1.0.0.6483      "python /tmp/pyrunne…"   6 seconds ago       Up 4 seconds        0.0.0.0:7000->7000/tcp   demistoserver_pyexecLongRunning-b60c04f9-754e-4b68-87ed-8f8113419fdb-demistoteams1.0.0.6483--26` 
     
    If the Docker container is up and running, try running cURL queries, to verify the webserver is up and running and listens on the configured URL:
    
     - To the messaging endpoint from a separate box.
     - From the Cortex XSOAR machine to localhost.
     
       - Note: The webserver supports only POST method queries.
       
    If the cURL queries were sent successfully, you should see in Cortex XSOAR logs the following line: `Finished processing Microsoft Teams activity successfully`


2. If you see the following error message: `Error in API call to Microsoft Teams: [403] - UnknownError`, then it means the AAD application has insufficient permissions.

3. Since the integration works based on Docker port mapping, it can't function if the Docker is set to run with the host networking (`--network=host`). For more details, refer to the [Docker documentation](https://docs.docker.com/network/host/).

## Download Demisto Bot

[Demisto Bot zip](https://raw.githubusercontent.com/demisto/content/b222375925eb13feaaa28cd8b1c814b4d212f2e4/Integrations/MicrosoftTeams/doc_files/DemistoBot.zip)
