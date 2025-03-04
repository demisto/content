Use the Microsoft Teams integration to send messages and notifications to your team members and create meetings.
This integration was integrated and tested with version 1.0 of Microsoft Teams.

**Note:** 
- This integration is supported in Cortex XSOAR 8 and up and Cortex XSIAM without using an engine.
- The integration has the ability to run built-in Cortex XSOAR commands, through a mirrored channel. Make sure to pass the command in the chat exactly as typed in the CORTEX XSOAR CLI. For example: `!DeleteContext all=yes`. Use the command `mirror-investigation` to mirror/create a mirrored channel.
- For use cases where it is only needed to send messages to a specific channel, we recommend checking the [Microsoft Teams via Webhook Integration](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams-via-webhook), which has a simpler setup.

## Integration Architecture
Data is passed between Microsoft Teams and Cortex XSOAR through the bot that you will configure in Microsoft Teams. A webhook (that you will configure) receives the data from Teams and passes it to the messaging endpoint. The web server on which the integration runs in Cortex XSOAR listens to the messaging endpoint and processes the data from Teams. You can use an engine for communication between Teams and the Cortex XSOAR server. In order to mirror messages from Teams to Cortex XSOAR, the bot must be mentioned, using the @ symbol, in the message.

The web server for the integration runs within a long-running Docker container. Cortex XSOAR maps the Docker port to which the server listens, to the host port (to which Teams posts messages). For more information, see [our documentation](https://xsoar.pan.dev/docs/integrations/long-running#invoking-http-integrations-via-cortex-xsoar-servers-route-handling) and [Docker documentation](https://docs.docker.com/config/containers/container-networking/).
### Protocol Diagram
![image](../../doc_files/MicrosoftTeamsProtocalDiagram.png)

## Important Information
 - The messaging endpoint must be one of the following:
 	- the URL of the Cortex XSOAR server, including the configured port
 	- the Cortex XSOAR rerouting URL that you've defined for your Microsoft Teams instance (see the [Using Cortex XSOAR or Cortex XSIAM rerouting](#1-using-cortex-xsoar-or-cortex-xsiam-rerouting) section for more details)
 	- a proxy that redirects the messages received from Teams to the Cortex XSOAR or Cortex XSIAM server (see the [Using NGINX as reverse proxy](#2-using-nginx-as-reverse-proxy) section for more details)
 - Microsoft Teams will send events to the messaging endpoints via HTTPS request, which means the messaging endpoint must be accessible for Microsoft Teams to reach to it. As follows, the messaging endpoint can not contain private IP address or any DNS that will block the request from Microsoft Teams.
In order to verify that the messaging endpoint is open as expected, you can surf to the messaging endpoint from a browser in an environment which is disconnected from the Cortex XSOAR environment.
 - It's important that the port is opened for outside communication and that the port is not being used, meaning that no service is listening on it. Therefore, the default port, 443, should not be used.
 - For additional security, we recommend placing the Teams integration web server behind a reverse proxy (such as NGINX).
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
 - You must not set a certificate and/or private key if you are using the Cortex XSOAR rerouting setup.
 - Microsoft does not support self-signed certificates and requires a chain-trusted certificate issued by a trusted CA.
 In order to verify which certificate is used, run the following (replace {MESSAGING-ENDPOINT} with the messaging endpoint):
    ```
     curl {MESSAGING-ENDPOINT} -vI
    ```
     Make sure the output does not contain the following:
    ```
     curl: (60) SSL certificate problem: self signed certificate
    ```
 - The following domains are used by this integration:
    - microsoft.com
    - botframework.com
    - microsoftonline.com
When [installing the bot in Microsoft Teams](#add-the-demisto-bot-to-a-team), according to [Microsoft](https://learn.microsoft.com/en-us/answers/questions/1600179/ms-teams-custom-app-takes-very-long-time-to-show-u), it usually takes up to 3-5 business days for the app to reflect in the "built for your org" section.

## First time setup

Refer to the [Setup Video](#setup-video) and the [Prerequisites](#prerequisites) sections for detailed steps to configure the teams bot and instance for the first time.

**Important notes:**

- The steps should be performed in order to ensure no communication between the services is lost.
- Refer to the [Setup Examples](#setup-examples) for information regarding advanced setups.

## Setup Examples

### 1. Using Cortex XSOAR or Cortex XSIAM rerouting
In this configuration, we will use Cortex XSOAR/Cortex XSIAM functionality, which reroutes HTTPS requests that hit the default port (443) to the web server that the integration spins up.

The messaging endpoint needs to be:

For Cortex XSOAR version 6.x: `<CORTEX-XSOAR-URL>/instance/execute/<INTEGRATION-INSTANCE-NAME>`, e.g., `https://my.demisto.live/instance/execute/teams`.

For Cortex XSOAR version 8 and Cortex XSIAM: `https://ext-<CORTEXT-XSOAR-SERVER-ADDRESSS>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`, e.g., `https://ext-my.demisto.live/xsoar/instance/execute/teams`.

The integration instance name, `teams` in this example, needs to be configured in the [Configure Microsoft Teams on Cortex XSOAR](#configure-microsoft-teams-on-cortex-xsoar) step. Make sure to set the instance name in all lowercase letters and as one word.

- Note: You can use the `microsoft-teams-create-messaging-endpoint` command to generate the messaging endpoint, based on the server URL, the server version, and the instance configurations. For more information, see -[microsoft-teams-create-messaging-endpoint documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#microsoft-teams-create-messaging-endpoint).

The port to be configured in [Configure Microsoft Teams on Cortex XSOAR](#configure-microsoft-teams-on-cortex-xsoar) step should be any available port that is not used by another service.

In addition, make sure ***Instance execute external*** is enabled (for Cortex XSOAR 6.x).

1. In Cortex XSOAR, go to **Settings > About > Troubleshooting**.
2. In the **Server Configuration** section, verify that the ***instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>*** (`instance.execute.external.teams` in this example) key is set to *true*. If this key does not exist, click **+ Add Server Configuration** and add the *instance.execute.external.\<INTEGRATION-INSTANCE-NAME\>* and set the value to *true*. See the following [reference article](https://xsoar.pan.dev/docs/reference/articles/long-running-invoke) for further information.


### 2. Using NGINX as reverse proxy
In this configuration, the inbound connection, from Microsoft Teams to Cortex XSOAR/Cortex XSIAM, goes through a reverse proxy (e.g., NGINX) which relays the HTTPS requests posted from Microsoft Teams
to the Cortex XSOAR/Cortex XSIAM server on HTTP.

On NGINX, configure the following:
 - SSL certificate under `ssl_certificate` and `ssl_certificate_key`
 - The Cortex XSOAR server (including the port) under `proxy_pass`, e.g. `http://mydemistoinstance.com:7000`

Follow [Configuring Upstream Servers NGINX guide](https://docs.nginx.com/nginx/admin-guide/security-controls/securing-http-traffic-upstream/#configuring-upstream-servers) for more details.

The port (`7000` in this example), to which the reverse proxy should forward the traffic on HTTP, should be the same port you specify in the integration instance configuration, as the web server the integration spins up, listens on that port.

![image](../../doc_files/RP-NGINX.png)

![image](../../doc_files/InstanceConfig7000.png)

### 3. Using Apache reverse proxy and Cortex XSOAR engine
In this configuration, the inbound connection, from Microsoft Teams to Cortex XSOAR/Cortex XSIAM, goes through a reverse proxy (e.g., [Apache](https://httpd.apache.org/docs/2.4/howto/reverse_proxy.html)) and possibly a load balancer, which relays the HTTPS requests posted from Microsoft Teams
to a Cortex XSOAR/Cortex XSIAM engine, which can be put in a DMZ, on HTTP.

The port (`7000` in this example), to which the reverse proxy should forward the traffic on HTTP, should be the same port you specify in the integration instance configuration, as the web server the integration spins up, listens on that port.

![image](../../doc_files/RP-Engine.png)

![image](../../doc_files/InstanceConfig7000.png)


### 4. Using Cloudflare
In this configuration, we will use [Cloudflare proxy](https://support.cloudflare.com/hc/en-us/articles/360039824852-Cloudflare-and-the-Cloud-Conceptual-overview-videos).

The messaging endpoint should be the Cortex XSOAR/Cortex XSIAM URL, which needs to be hosted on Cloudflare, with the port to which Cloudflare proxy directs the HTTPS traffic, e.g., `https://mysite.com:8443`

In the [Configure Microsoft Teams on Cortex XSOAR](#configure-microsoft-teams-on-cortex-xsoar) step, the following need to be configured:
 - The port selected above.
 - A certificate and key for configuring HTTPS web server. This certificate can be self-signed.

The proxy intercepts HTTPS traffic, presents a public CA certificate, then proxies it to the web server.

All HTTPS traffic that will hit the selected messaging endpoint will be directed to the HTTPS web server the integration spins up, and will then be processed.

## Setup Video
The information in this video is for Cortex XSOAR 6 but mostly still applies to XSOAR 8, refer to the [Prerequisites](#prerequisites) section for the latest instructions.

<video controls>
    <source src="https://github.com/demisto/content-assets/blob/master/Assets/MicrosoftTeams/FullConfigVideo.mp4?raw=true"
            type="video/mp4"/>
    Sorry, your browser doesn't support embedded videos. You can download the video at: https://github.com/demisto/content-assets/blob/master/Assets/MicrosoftTeams/FullConfigVideo.mov?raw=true
</video>

## Prerequisites

Before you can create an instance of the Microsoft Teams integration in Cortex XSOAR/Cortex XSIAM, you need to complete the following procedures.

1. [Create the Demisto Bot in Microsoft Teams](#create-the-demisto-bot-in-microsoft-teams)
2. [Grant the Demisto Bot Permissions in Microsoft Graph](#grant-the-demisto-bot-permissions-in-microsoft-graph)
3. [Configure Microsoft Teams on Cortex XSOAR or Cortex XSIAM](#configure-microsoft-teams-on-cortex-xsoar)
4. [Add the Demisto Bot to a Team](#add-the-demisto-bot-to-a-team)

### Create the Demisto Bot in Microsoft Teams

#### Creating the Demisto Bot using Microsoft Azure Portal

1. Navigate to the [Create an Azure Bot page](https://portal.azure.com/#create/Microsoft.AzureBot).
2. In the Bot Handle field, type **Demisto Bot**.
3. Fill in the required Subscription and Resource Group, relevant links: [Subscription](https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/create-subscription), [Resource Groups](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/manage-resource-groups-portal).
4. For Type of App, select **Multi Tenant**.
5. For Creation type, select **Create new Microsoft App ID** for Creation Type if you don't already have an app registration, otherwise, select **Use existing app registration**, and fill in you App ID.
6. Click **Review + Create**, and wait for the validation to pass.
7. Click **create** if the validation has passed, and wait for the deployment to finish.
8. Under Next Steps, click **Go to resource**.
9. Navigate to **Settings -> Configuration** on the left bar, and fill in the **Messaging Endpoint**.

    - To get the correct messaging endpoint based on the server URL, the server version, and the instance configurations. use the `microsoft-teams-create-messaging-endpoint`command.
**Note:** Using this command requires an active integration instance. This step can be done after completing the [instance configuration](#configure-microsoft-teams-on-cortex-xsoar) section.

10. Store the **Microsoft App ID** value for the next steps, and navigate to **Manage** next to it.
11. Click **New Client Secret**, fill in the **Description** and **Expires** fields as desired. Then click **Add**.
12. Copy the client secret from the **value** field and store it for the next steps.
13. Go back to the previous page, and navigate to **Channels** in the left bar.
14. Click **Microsoft Teams** under **Available Channels**, click the checkbox, click **Agree**, then click **Apply**.

Note: in step 5, if you choose **Use existing app registration**, make sure to delete the previous created bot with the same app id, remove it from the team it was added to as well.  


### Grant the Demisto Bot Permissions in Microsoft Graph

In order to connect to Microsoft Teams use one of the following authentication methods:

1. *Client Credentials Flow*
2. *Authorization Code Flow*

#### Client Credentials Flow

Note: [The chat commands](#chat-commands) are only supported when using the `Authorization Code flow`.

Executing commands when using client credentials requires **Application Permissions**.
Perform the following steps to add the needed permissions:

1. Go to your Microsoft Azure portal, and from the left navigation pane select **Azure Active Directory > App registrations**.
2. Search for and click **Demisto Bot**.
3. Click **API permissions > Add a permission > Microsoft Graph > Application permissions**.
4. For each permission, search for the permission, select the checkbox, and click **Add permissions**.
   **Application permissions required to use all credential flow supported commands:**

    - `User.Read.All`
    - `GroupMember.Read.All`
    - `Channel.ReadBasic.All`
    - `ChannelMember.ReadWrite.All`
    - `Channel.Create`
    - `Channel.Delete.All`
    - `OnlineMeetings.ReadWrite.All`
    - `Calls.Initiate.All`

    Alternatively, check each relevant command section below for the minimum permissions it requires.

5. Verify that all the needed permissions were added, and click **Grant admin consent**.
6. When prompted to verify granting permissions, click **Yes**, and verify that permissions were successfully added.

#### Authorization Code Flow

Note: The [microsoft-teams-ring-user](https://learn.microsoft.com/en-us/graph/api/application-post-calls?view=graph-rest-1.0&tabs=http) command is only supported when using the `Client Credentials flow` due to a limitation in Microsoft's permissions system.

Executing commands when using an authorization code requires **Delegated Permissions**.
Perform the following steps to add the needed permissions:

1. Go to your Microsoft Azure portal, and from the left navigation pane select **Azure Active Directory > App registrations**.
2. Search for and click **Demisto Bot**.
3. Click **API permissions > Add a permission > Microsoft Graph > Delegated permissions**.
4. For each permission, search for the permission, select the checkbox, and click **Add permissions**.
   **Delegated permissions required to use all auth code flow supported commands:**

    - `User.Read.All`
    - `GroupMember.Read.All`
    - `Channel.ReadBasic.All`
    - `ChannelMember.ReadWrite.All`
    - `Channel.Create`
    - `Channel.Delete.All`
    - `OnlineMeetings.ReadWrite.All`
    - `Chat.ReadWrite`
    - `AppCatalog.Read.All`
    - `TeamsAppInstallation.ReadWriteSelfForChat`

    Alternatively, check each relevant command section below for the minimum permissions it requires.

5. Verify that all permissions were added, and click **Grant admin consent**.
6. When prompted to verify granting permissions, click **Yes**, and verify that permissions were successfully added.
7. Click **Expose an API** and add **Application ID URI**
8. Click **Authentication > Platform configurations > Add a platform.** Choose **Web** and add Redirect URIs: <https://login.microsoftonline.com/common/oauth2/nativeclient>

### Configure Microsoft Teams on Cortex XSOAR

For more detailed instructions, refer to the [Configuring the instance with the chosen authentication flow](#configuring-the-instance-with-the-chosen-authentication-flow) section.

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Microsoft Teams.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Name | The integration instance name.<br />If using Cortex XSOAR rerouting configuration, insert here the instance name you configured in the messaging endpoint. | True |
    | Bot ID | Bot ID. | True |
    | Bot Password | Bot Password. | True |
    | Authentication Type |  | True |
    | Application redirect URI (for Authorization Code mode) |  | False |
    | Authorization code | For Authorization Code flow mode. Received from the authorization step. See the Detailed Instructions \(?\) section | False |
    | Default team | The team to which messages and notifications are sent. If a team is specified as a command argument, it overrides this parameter. | True |
    | Notifications channel |  | True |
    | Certificate (Required for HTTPS) |  | False |
    | Private Key (Required for HTTPS) |  | False |
    | Minimum incident severity to send notifications to Teams by |  | False |
    | Disable Automatic Notifications | Whether to disable automatic notifications to the configured notifications channel. | False |
    | Allow external users to create incidents via direct message |  | False |
    | The header of an external form hyperlink. |  | False |
    | Trust any certificate (not secure) | Do not check for Cortex XSOAR version 8 and Cortex XSIAM. | False |
    | Use system proxy settings |  | False |
    | Long running instance |  | True |
    | Listen port, e.g., 7000 (Required for investigation mirroring and direct messages) | longRunningPort | False |
    | Incident type | Incident type. | False |

4. Click **Test** to validate the URLs, token, and connection.
5. Click the **Save & exit** button.

#### Configuring the instance with the chosen authentication flow

##### Authentication Using the Client Credentials Flow

1. Choose the 'Client Credentials' option in the *Authentication Type* parameter.
2. Enter your Client/Application ID in the *Bot ID* parameter.
3. Enter your Client Secret in the *Bot Password* parameter.
4. Set the *Default team* and the *Notifications channel* parameters.
5. Set the *Long running instance* parameter to 'True'.
6. Save the instance.
7. Click **Test** to validate the URLs, token, and connection.
8. Configure the messaging endpoint if you haven't done so already (Step #9 in the [Bot Creation](#creating-the-demisto-bot-using-microsoft-azure-portal) section).
9. [Add the Demisto Bot to a Team](#add-the-demisto-bot-to-a-team)

##### Authentication Using the Authorization Code Flow

1. Choose the 'Authorization Code' option in the *Authentication Type* parameter.
2. Enter your Client/Application ID in the *Bot ID* parameter.
3. Enter your Client Secret in the *Bot Password* parameter.
4. Enter your Application redirect URI in the *Application redirect URI* parameter.
5. Set the *Default team* and the *Notifications channel* parameters.
6. Set the *Long running instance* parameter to 'True'.
7. Save the instance.
8. Configure the messaging endpoint if you haven't done so already (Step #9 in the [Bot Creation](#creating-the-demisto-bot-using-microsoft-azure-portal) section).
9. [Add the Demisto Bot to a Team](#add-the-demisto-bot-to-a-team)
10. Run the ***!microsoft-teams-generate-login-url*** command in the War Room and follow the instructions.
11. Save the instance.
12. Run the ***!microsoft-teams-auth-test*** command. A 'Success' message should be printed to the War Room.

### Add the Demisto Bot to a Team

**Notes:**

- The following needs to be done after configuring the integration on Cortex XSOAR/Cortex XSIAM (the previous step).
- According to [Microsoft](https://learn.microsoft.com/en-us/answers/questions/1600179/ms-teams-custom-app-takes-very-long-time-to-show-u) it usually takes up to 3-5 business days for the app to reflect in the "built for your org" section.

1. Download the ZIP file located at the bottom of this article.
2. Uncompress the ZIP file. You should see 3 files (`manifest.json`, `color.png` and `outline.png`).
3. Open the `manifest.json` file that was extracted from the ZIP file.
4. Update the following values to use the *Bot ID* from step 5 of the [Create the Demisto Bot in Microsoft Teams](#creating-the-demisto-bot-using-microsoft-azure-portal) section:

    1. The `id` field.
    2. The `BotId` attribute in the `bots` list.
    3. The `id` attribute in the `webApplicationInfo` field.

5. Compress the 3 files (the modified `manifest.json` file, `color.png` and `outline.png`).
6. Navigate to [Manage Apps in the Microsoft Teams admin center](https://admin.teams.microsoft.com/policies/manage-apps).
7. Click the **Actions** button and then the **+ Upload new app** button.
8. In the pop-up window, click the **Upload** button.
9. Browse for the ZIP file you created in step 7, open it, and wait a few seconds until it loads.
10. Search for **Demisto Bot**.
11. In the line where `Demisto Bot` shows under **Name**, tick the V on the left.
12. Click the **Add to team** button.
13. In the search box, type the name of the team to which you want to add the bot.
14. Click the **Add** button on the wanted team and then click the **Apply** button.

## Migration from Cortex XSOAR 6 to Cortex XSOAR 8 and Cortex XSIAM

### Using Cortex XSOAR or Cortex XSIAM rerouting

1. For Cortex XSOAR 8, set the messaging endpoint in the Azure bot to be `https://ext-<CORTEXT-XSOAR-SERVER-ADDRESSS>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`, e.g., `https://ext-my.demisto.live/xsoar/instance/execute/teams`.
2. For Cortex XSIAM, set the messaging endpoint in the Azure bot to be `https://ext-<CORTEXT-XSIAM-SERVER-ADDRESSS>/xsoar/instance/execute/<INTEGRATION-INSTANCE-NAME>`, and replace the `xdr` in the url to `crtx`.
3. Check the **long running instance** parameter in the integration instance configuration.
4. Set the **port** parameter. It's under the Connect section in the integration instance configuration.
5. If using the same bot from the XSOAR 6 instance, make sure to remove the bot from the team and to add it back:
    1. Go to the Microsoft Teams app.
    2. Go to your team, and click the three dots next to the name.
    3. Go to **manage team** > **apps**.
    4. Find your bot, and click the three dots in the same row.
    5. Click **remove**.
    6. Add the bot to the team.

## Known Limitations
---
- In some cases, you might encounter a problem, where no communication is created between Teams and the messaging endpoint, when adding a bot to the team. You can work around this problem by adding any member to the team the bot was added to. It will trigger a communication and solve the issue.
- The [microsoft-teams-ring-user](https://learn.microsoft.com/en-us/graph/api/application-post-calls?view=graph-rest-1.0&tabs=http) command is only supported when using the `Client Credentials flow` due to a limitation in Microsoft's permissions system. 
- In addition, the chat commands are only supported when using the `Authorization Code flow`.
- Posting a message or adaptive card to a private/shared channel is currently not supported in the ***send-notification*** command. Thus, also the ***mirror_investigation*** command does not support private/shared channels. For more information, see [Microsoft General known issues and limitations](https://learn.microsoft.com/en-us/connectors/teams/#general-known-issues-and-limitations).
- In case of multiple chats/users sharing the same name, the first one will be taken.
- See Microsoft documentation for [Limits and specifications for Microsoft Teams](https://learn.microsoft.com/en-us/microsoftteams/limits-specifications-teams).
- If a non-Cortex XSOAR user ran the `new incident` command in the chat with the bot, the owner of the created incident would be the logged in Cortex XSOAR user, not the external user who ran the command.


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### send-notification

***
Sends a message to the specified teams.
To mention a user in the message, add a semicolon ";" at the end of the user mention. For example: @Bruce Willis;.

If sending a reply to a message, the message ID must be provided and the reply will be sent via the Graph API which means
the message will appear from the account used to authorize the integration instance and not the bot. Setting the account's name
and picture to match the bot will make it appear to be from the same source.

##### Base Command

`send-notification`

##### Required Permissions

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.ReadBasic.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel to which to send messages. Supports only standard channels. | Optional | 
| message | The message to send to the channel or team member. | Optional | 
| team_member | Display name or email address of the team member to send the message to. | Optional | 
| team | The team in which the specified channel exists. The team must already exist, and this value will override the default channel configured in the integration parameters. | Optional | 
| message_id | ID of the message to send the notification to as a reply when sending to a channel. | Optional | 
| adaptive_card | The Microsoft Teams adaptive card to send. | Optional | 
| to | The team member to which to send the message. | Optional | 
| external_form_url_header | The header of an external form hyperlink. Default is Microsoft Teams Form. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.Message.ID | String | ID of the message sent. | 

##### Command Example
```!send-notification channel=General message="hello world!" team=DemistoTeam```

##### Human Readable Output
Message was sent successfully.

### mirror-investigation
***
Mirrors the Cortex XSOAR/Cortex XSIAM investigation to the specified Microsoft Teams channel. Supports only standard channels.

**Note**: Mirrored channels could be used to run Cortex XSOAR/Cortex XSIAM built-in commands.


##### Base Command

`mirror-investigation`

##### Required Permissions

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.ReadBasic.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.Create` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.Delete.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description**                                                                                                                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| mirror_type       | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. Possible values are: all, chat, none. Default is all. | Optional     | 
| autoclose         | Whether to auto-close the channel when the incident is closed in Cortex XSOAR. If "true", the channel will be auto-closed. Possible values are: true, false. Default is true.                            | Optional     | 
| direction         | The mirroring direction. Possible values are: Both, FromDemisto, ToDemisto. Default is both.                                                                                                             | Optional     | 
| team              | The team in which to mirror the Cortex XSOAR investigation. If not specified, the default team configured in the integration parameters will be used.                                                    | Optional     | 
| channel_name      | The name of the channel. The default is "incident-INCIDENTID".                                                                                                                                           | Optional     | 


##### Context Output

There is no context output for this command.

##### Command Example
```!mirror-investigation mirror_type=all autoclose=true direction=Both```


##### Human Readable Output
Investigation mirrored successfully in channel incident-100.

### close-channel
***
Deletes the specified Microsoft Teams channel.


##### Base Command

`close-channel`

##### Required Permissions

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.ReadBasic.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.Delete.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description**                   | **Required** |
|-------------------|-----------------------------------|--------------|
| channel           | The name of the channel to close. | Optional     | 
| team              | The channel's team.               | Optional     | 


##### Context Output

There is no context output for this command.

##### Command Example
```!close-channel channel="example channel"```


##### Human Readable Output
Channel was successfully closed.

### microsoft-teams-integration-health
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
>### Microsoft API Health
>| Bot Framework API Health | Graph API Health |
>|--------------------------|------------------|
>| Operational              | Operational      |
>No mirrored channels.

### microsoft-teams-ring-user
***
Rings a user's Teams account. Note: This is a ring only! no media will play in case the generated call is answered. To use this make sure your Bot has the following permissions - Calls.Initiate.All and Calls.InitiateGroupCall.All


##### Base Command

`microsoft-teams-ring-user`

##### Required Permissions

`User.Read.All` - *Application*

`Calls.Initiate.All` - *Application*

##### Input

| **Argument Name** | **Description**                         | **Required** |
|-------------------|-----------------------------------------|--------------|
| username          | The display name of the member to call. | Required     | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-ring-user username="Avishai Brandeis"```


##### Human Readable Output
Calling Avishai Brandeis

### microsoft-teams-add-user-to-channel
***
Adds a member (user) to a private/shared channel.
For a comparison of Teams features for each channel type, see the Microsoft documentation:  [Channel feature comparison](https://learn.microsoft.com/en-us/MicrosoftTeams/teams-channels-overview#channel-feature-comparison).


##### Base Command

`microsoft-teams-add-user-to-channel`

##### Required Permissions

`User.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`ChannelMember.ReadWrite.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.ReadBasic.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description**                                                    | **Required** |
|-------------------|--------------------------------------------------------------------|--------------|
| channel           | The channel to which to add the member.                            | Required     | 
| team              | The channel's team.                                                | Required     | 
| member            | The display name of the member to add to the channel.              | Required     | 
| owner             | Whether to add the member with the owner role.  Default is 'false' | Optional     | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-add-user-to-channel channel="example channel" member=itayadmin team=DemistoTeam```

##### Human Readable Output
The User "itayadmin" has been added to channel "example channel" successfully.

### microsoft-teams-create-channel
***
Creates a new channel in a Microsoft Teams team.
For more information about the channels types, see the Microsoft documentation: [standard, private, or shared channels](https://support.microsoft.com/en-us/office/teams-can-have-standard-private-or-shared-channels-de3e20b0-7494-439c-b7e5-75899ebe6a0e)
See also [Channel feature comparison](https://learn.microsoft.com/en-us/MicrosoftTeams/teams-channels-overview#channel-feature-comparison).


##### Base Command

`microsoft-teams-create-channel`

##### Required Permissions

`User.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.Create` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description**                                                                               | **Required** |
|-------------------|-----------------------------------------------------------------------------------------------|--------------|
| channel_name      | The name of the channel.                                                                      | Required     | 
| description       | The description of the channel.                                                               | Optional     | 
| team              | The team in which to create the channel.                                                      | Required     | 
| membership_type   | The type of the channel. Possible values are: private, standard, shared. Default is standard. | Optional     | 
| owner_user        | The channel owner (Display name/mail/UPN)                                                     | Optional     | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-create-channel channel_name="example channel" team=DemistoTeam description="this is my new channel"```


##### Human Readable Output
The channel "example channel" was created successfully

### microsoft-teams-create-meeting
***
Creates a new meeting in Microsoft Teams.


##### Base Command

`microsoft-teams-create-meeting`

##### Required Permissions

`OnlineMeetings.ReadWrite.All` - *Application (Client Credentials)*

`OnlineMeetings.ReadWrite` - *Delegated (Authorization Code)*

When using `Client Credentials Flow`:
Besides setting up this permission, in order to create a meeting, the Azure admin needs to configure application access policy
and grant users permissions to create meetings.
The script *ConfigureAzureApplicationAccessPolicy* was created to support the needed commands.
For more information:
[Allow applications to access online meetings on behalf of a user](https://docs.microsoft.com/en-us/graph/cloud-communication-online-meeting-application-access-policy)

When using `Authorization Code Flow`:
The authentication process is conducted on behalf of the specific user who initiated the login request. Therefore, the given `member` must be the same user.

##### Input

| **Argument Name** | **Description**                                                                      | **Required** |
|-------------------|--------------------------------------------------------------------------------------|--------------|
| start_time        | The meeting start time in ISO 8601 format e.g., "2019-07-12T14:30:34.2444915-07:00". | Optional     | 
| end_time          | The meeting end time in ISO 8601 format e.g., "2019-07-12T14:30:34.2444915-07:00".   | Optional     | 
| subject           | The meeting subject.                                                                 | Required     | 
| member            | Display name/mail/UPN of user who created the meeting, e.g., Adam Smith.             | Required     | 


##### Context Output

| **Path**                                            | **Type** | **Description**                       |
|-----------------------------------------------------|----------|---------------------------------------|
| MicrosoftTeams.CreateMeeting.creationDateTime       | Date     | Meeting creation time.                | 
| MicrosoftTeams.CreateMeeting.threadId               | String   | Meeting thread ID.                    | 
| MicrosoftTeams.CreateMeeting.messageId              | String   | Meeting message ID.                   | 
| MicrosoftTeams.CreateMeeting.id                     | String   | Meeting ID.                           | 
| MicrosoftTeams.CreateMeeting.joinWebUrl             | String   | The URL to join the meeting.          | 
| MicrosoftTeams.CreateMeeting.participantId          | String   | The meeting participants.             | 
| MicrosoftTeams.CreateMeeting.participantDisplayName | String   | The display name of the participants. | 


##### Command Example
``` !microsoft-teams-create-meeting member="example user" subject="Important meeting" ```

##### Human Readable Output
The meeting "Important meeting" was created successfully

### microsoft-teams-user-remove-from-channel
***
Removes a member (user) from a private/shared channel.


##### Base Command

`microsoft-teams-user-remove-from-channel`

##### Required Permissions

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.ReadBasic.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`ChannelMember.ReadWrite.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description**                                            | **Required** |
|-------------------|------------------------------------------------------------|--------------|
| channel_name      | The name of the channel.                                   | Required     | 
| team              | The name of the channel's team.                            | Required     | 
| member            | The display name of the member to remove from the channel. | Required     | 


##### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-user-remove-from-channel channel_name="example channel" member=itayadmin team=DemistoTeam```

##### Human Readable Output
The User "itayadmin" has been removed from channel "example channel" successfully.

### microsoft-teams-channel-user-list
***
Retrieves a list of members from a channel.


##### Base Command

`microsoft-teams-channel-user-list`

##### Required Permissions

`GroupMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`Channel.ReadBasic.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

`ChannelMember.Read.All` - *Application (Client Credentials) / Delegated (Authorization Code)*

##### Input

| **Argument Name** | **Description**                 | **Required** |
|-------------------|---------------------------------|--------------|
| channel_name      | The name of the channel.        | Required     | 
| team              | The name of the channel's team. | Required     | 


##### Context Output

| **Path**                                                       | **Type** | **Description**                                                                                      |
|----------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------|
| MicrosoftTeams.ChannelList.channelId                           | String   | The channel ID.                                                                                      | 
| MicrosoftTeams.ChannelList.channelName                         | String   | The name of the channel.                                                                             | 
| MicrosoftTeams.ChannelList.members.displayName                 | String   | The display name of the members.                                                                     | 
| MicrosoftTeams.ChannelList.members.email                       | String   | The email of the members.                                                                            | 
| MicrosoftTeams.ChannelList.members.id                          | String   | The ID of the members.                                                                               | 
| MicrosoftTeams.ChannelList.members.roles                       | String   | The roles of the members.                                                                            | 
| MicrosoftTeams.ChannelList.members.tenantId                    | String   | The tenant ID of the members.                                                                        | 
| MicrosoftTeams.ChannelList.members.userId                      | String   | The user ID of the members.                                                                          | 
| MicrosoftTeams.ChannelList.members.visibleHistoryStartDateTime | String   | The timestamp denoting how far back a conversation's history is shared with the conversation member. | 

##### Command Example
```!microsoft-teams-channel-user-list channel_name="example channel" team=DemistoTeam```

##### Human Readable Output
##### Channel 'example channel' Members List:
| User Id                              | Email          | Tenant Id                            | Membership id                                                                                        | User roles | Display Name | Start DateTime       |
|--------------------------------------|----------------|--------------------------------------|------------------------------------------------------------------------------------------------------|------------|--------------|----------------------|
| 359d2c3c-162b-414c-b2eq-386461e5l050 | test@gmail.com | pbae9ao6-01ql-249o-5me3-4738p3e1m941 | MmFiOWM3OTYtMjkwMi00NWY4LWI3MTItN2M1YTYzY2Y0MWM0IyNlZWY5Y2IzNi0wNmRlLTQ2OWItODdjZC03MGY0Y2JlMzJkMTQ= | owner      | itayadmin    | 0001-01-01T00:00:00Z |


### Chat Commands

### microsoft-teams-chat-create
***
Creates a new chat. 


Notes:
- Only one oneOnOne chat can exist between two members. If a oneOnOne chat already exists, it will be returned.
- This command works with the consent user, not with the bot. Which means, the chat is created between the consent user and the user provided in the command's argument.
- This command may fail if the bot app has not yet appeared in the "built for your org" section in teams.


##### Base Command

`microsoft-teams-chat-create`

##### Required Permissions

`User.Read.All` - *Delegated*

`Chat.Create` - *Delegated*

`AppCatalog.Read.All` - *Delegated*

`TeamsAppInstallation.ReadWriteSelfForChat` - *Delegated*

##### Input

| **Argument Name** | **Description**                                                                          | **Required** |
|-------------------|------------------------------------------------------------------------------------------|--------------|
| chat_type         | Specifies the type of chat. Possible values are: group, oneOnOne. Default is group.      | Required     | 
| member            | Display name/mail/UPN of user that should be added to the chat. Can be an array.         | Optional     | 
| chat_name         | The title of the chat. The chat title can be provided only if the chat is of group type. | Optional     | 


##### Context Output

| **Path**                                    | **Type** | **Description**                                                                                                         |
|---------------------------------------------|----------|-------------------------------------------------------------------------------------------------------------------------|
| MicrosoftTeams.ChatList.chatId              | String   | The chat's unique identifier.                                                                                           | 
| MicrosoftTeams.ChatList.topic               | String   | Subject or topic for the chat. Only available for group chats.                                                          | 
| MicrosoftTeams.ChatList.createdDateTime     | String   | Date and time at which the chat was created.                                                                            | 
| MicrosoftTeams.ChatList.lastUpdatedDateTime | String   | Date and time at which the chat was renamed or list of members were last changed.                                       | 
| MicrosoftTeams.ChatList.chatType            | String   | Specifies the type of chat.                                                                                             | 
| MicrosoftTeams.ChatList.webUrl              | String   | The URL for the chat in Microsoft Teams. The URL should be treated as an opaque blob, and not parsed.                   | 
| MicrosoftTeams.ChatList.tenantId            | String   | The identifier of the tenant in which the chat was created.                                                             | 
| MicrosoftTeams.ChatList.viewpoint           | String   | Represents caller-specific information about the chat, such as last message read date and time.                         | 
| MicrosoftTeams.ChatList.onlineMeetingInfo   | String   | Represents details about an online meeting. If the chat isn't associated with an online meeting, the property is empty. | 

##### Command Example
```!microsoft-teams-chat-create chat_type=group member="itayadmin, Bruce Willis" chat_name="example chat"```

##### Human Readable Output
##### The chat 'example chat' was created successfully
| Chat Id                                       | Chat name    | Created Date Time       | Last Updated Date Time  | webUrl | Tenant Id                            |
|-----------------------------------------------|--------------|-------------------------|-------------------------|--------|--------------------------------------|
| 19:2da4c29f6d7041eca70b638b43d45437@thread.v2 | example chat | 2023-01-08T07:51:53.07Z | 2023-01-08T07:51:53.07Z | webUrl | pbae9ao6-01ql-249o-5me3-4738p3e1m941 |

### microsoft-teams-message-send-to-chat
***
Sends a new chat message in the specified chat.

Notes:

- This command works with the consent user, not with the bot. Which means, the message is sent to the given chat by the consent user, not the bot.
- This command may fail if the bot app has not yet appeared in the "built for your org" section in teams.

##### Base Command

`microsoft-teams-message-send-to-chat`

##### Required Permissions

`User.Read.All` - *Delegated*

`Chat.Create` - *Delegated*

`ChatMessage.Send` - *Delegated*

`AppCatalog.Read.All` - *Delegated*

`TeamsAppInstallation.ReadWriteSelfForChat` - *Delegated*

Note: Chat.Create is needed only when sending to one-on-one chats.

##### Input

| **Argument Name** | **Description**                                                                  | **Required** |
|-------------------|----------------------------------------------------------------------------------|--------------|
| chat              | The chat ID / group chat name (topic) / oneOnOne member (Display name/mail/UPN). | Required     | 
| content           | The content of the chat message.                                                 | Required     | 
| content_type      | The message content type. Possible values are: text, html. Default is text.      | Optional     | 
| message_type      | The type of chat message. Default is message.                                    | Optional     | 


#### Context Output

| **Path**                                              | **Type** | **Description**                                                                                                                        |
|-------------------------------------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------------|
| MicrosoftTeams.ChatList.chatId                        | String   | The chat's unique identifier.                                                                                                          | 
| MicrosoftTeams.ChatList.messages.id                   | String   | Unique ID of the message.                                                                                                              | 
| MicrosoftTeams.ChatList.messages.replyToId            | String   | ID of the parent chat message or root chat message of the thread.                                                                      | 
| MicrosoftTeams.ChatList.messages.etag                 | String   | Version number of the chat message.                                                                                                    | 
| MicrosoftTeams.ChatList.messages.messageType          | String   | The type of chat message.                                                                                                              | 
| MicrosoftTeams.ChatList.messages.createdDateTime      | String   | Timestamp of when the chat message was created.                                                                                        | 
| MicrosoftTeams.ChatList.messages.lastModifiedDateTime | String   | Timestamp when the chat message is created \(initial setting\) or modified, including when a reaction is added or removed.             | 
| MicrosoftTeams.ChatList.messages.lastEditedDateTime   | String   | Timestamp when edits to the chat message were made. Triggers an "Edited" flag in the Teams UI. If no edits are made the value is null. | 
| MicrosoftTeams.ChatList.messages.deletedDateTime      | String   | Timestamp at which the chat message was deleted, or null if not deleted.                                                               | 
| MicrosoftTeams.ChatList.messages.subject              | String   | The subject of the chat message, in plaintext.                                                                                         | 
| MicrosoftTeams.ChatList.messages.summary              | String   | Summary text of the chat message that could be used for push notifications and summary views or fall back views.                       | 
| MicrosoftTeams.ChatList.messages.chatId               | String   | If the message was sent in a chat, represents the identity of the chat.                                                                | 
| MicrosoftTeams.ChatList.messages.importance           | String   | The importance of the chat message.                                                                                                    | 
| MicrosoftTeams.ChatList.messages.locale               | String   | Locale of the chat message set by the client.                                                                                          | 
| MicrosoftTeams.ChatList.messages.webUrl               | String   | Link to the message in Microsoft Teams.                                                                                                | 
| MicrosoftTeams.ChatList.messages.channelIdentity      | String   | If the message was sent in a channel, represents identity of the channel.                                                              | 
| MicrosoftTeams.ChatList.messages.policyViolation      | String   | Defines the properties of a policy violation set by a data loss prevention \(DLP\) application.                                        | 
| MicrosoftTeams.ChatList.messages.eventDetail          | String   | If present, represents details of an event that happened in a chat, a channel, or a team, for example, adding new members.             | 
| MicrosoftTeams.ChatList.messages.from                 | String   | Details of the sender of the chat message.                                                                                             | 
| MicrosoftTeams.ChatList.messages.body                 | String   | Plaintext/HTML representation of the content of the chat message. Representation is specified by the contentType inside the body.      | 
| MicrosoftTeams.ChatList.messages.attachments          | String   | References to attached objects like files, tabs, meetings etc.                                                                         | 
| MicrosoftTeams.ChatList.messages.mentions             | String   | List of entities mentioned in the chat message.                                                                                        | 
| MicrosoftTeams.ChatList.messages.reactions            | String   | Reactions for this chat message \(for example, Like\).                                                                                 | 

##### Command Example
```!microsoft-teams-message-send-to-chat chat="example chat" content="Hello World"```

##### Human Readable Output
>### Message was sent successfully in the 'example chat' chat.
>| Chat Id                                       | Created DateTime        | Etag          | From user | From user id                         | From user userIdentityType | Importance | Message Content | Message Type | Message contentType | Message id    | lastModified DateTime   |
>|-----------------------------------------------|-------------------------|---------------|-----------|--------------------------------------|----------------------------|------------|-----------------|--------------|---------------------|---------------|-------------------------|
>| 19:2da4c29f6d7041eca70b638b43d45437@thread.v2 | 2021-03-29T04:17:43.15Z | 1616991463150 | itayadmin | 8ea0e38b-efb3-4757-924a-5f94061cf8c2 | aadUser                    | normal     | Hello World     | message      | text                | 1616991463150 | 2021-03-29T04:17:43.15Z |

### microsoft-teams-chat-add-user
***
Adds a member (user) to a group chat.


#### Base Command

`microsoft-teams-chat-add-user`

##### Required Permissions

`Chat.ReadBasic` - *Delegated*

`ChatMember.ReadWrite` - *Delegated*

#### Input

| **Argument Name** | **Description**                                                                                    | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------|--------------|
| chat              | The chat ID or group chat name (topic) to which to add the member.                                 | Required     | 
| member            | Display name/mail/UPN of user that should be added to the chat. Can be an array.                   | Required     | 
| share_history     | Whether to share the whole history of the chat. Possible values are: true, false. Default is True. | Optional     | 


#### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-chat-add-user chat="example chat" member="Bruce Willis" share_history=false```

##### Human Readable Output
The User "Bruce Willis" has been added to chat "example chat" successfully.

### microsoft-teams-chat-member-list
***
Retrieves a list of members from a chat.


#### Base Command

`microsoft-teams-chat-member-list`

##### Required Permissions

`User.Read.All` - *Delegated*

`Chat.ReadBasic` - *Delegated*

`Chat.Create` - *Delegated*

Note: Chat.Create is needed only when listing one-on-one chats.

#### Input

| **Argument Name** | **Description**                                                                  | **Required** |
|-------------------|----------------------------------------------------------------------------------|--------------|
| chat              | The chat ID / group chat name (topic) / oneOnOne Member (Display name/mail/UPN). | Required     | 


#### Context Output

| **Path**                                                    | **Type** | **Description**                                                                                      |
|-------------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------|
| MicrosoftTeams.ChatList.chatId                              | String   | The chat's unique identifier.                                                                        | 
| MicrosoftTeams.ChatList.members.displayName                 | String   | The display name of the members.                                                                     | 
| MicrosoftTeams.ChatList.members.email                       | String   | The email of the members.                                                                            | 
| MicrosoftTeams.ChatList.members.id                          | String   | The ID of the members.                                                                               | 
| MicrosoftTeams.ChatList.members.roles                       | String   | The roles of the members.                                                                            | 
| MicrosoftTeams.ChatList.members.tenantId                    | String   | The tenant ID of the members.                                                                        | 
| MicrosoftTeams.ChatList.members.userId                      | String   | The user ID of the members.                                                                          | 
| MicrosoftTeams.ChatList.members.visibleHistoryStartDateTime | String   | The timestamp denoting how far back a conversation's history is shared with the conversation member. | 

##### Command Example
```!microsoft-teams-chat-member-list chat="example chat"```

##### Human Readable Output
>### Chat "example chat" Members List:
>| User Id                              | User roles | Name         | Email          | Tenant Id                            |
>|--------------------------------------|------------|--------------|----------------|--------------------------------------|
>| 359d2c3c-162b-414c-b2eq-386461e5l050 | owner      | itayadmin    | test@gmail.com | dcd219dd-bc68-4b9b-bf0b-4a33a796be35 |
>| 48d31887-5fad-4d73-a9f5-3c356e68a038 | owner      | Bruce Willis | test@gmail.com | dcd219dd-bc68-4b9b-bf0b-4a33a796be35 |

### microsoft-teams-chat-list
***
Retrieves a list of chats that the user is part of. If 'chat' is specified - retrieves this chat only.


#### Base Command

`microsoft-teams-chat-list`

##### Required Permissions

`User.Read.All` - *Delegated*

`Chat.ReadBasic` - *Delegated*

`Chat.Create` - *Delegated*

Note: Chat.Create is needed only when listing one-on-one chats.

#### Input

| **Argument Name** | **Description**                                                                                                                                          | **Required** |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| chat              | The chat ID / group chat name (topic) / oneOnOne member (Display name/mail/UPN).                                                                         | Optional     | 
| filter            | Filters results. For example: topic eq 'testing'. For more query examples, see https://learn.microsoft.com/en-us/graph/filter-query-parameter?tabs=http. | Optional     | 
| expand            | Expands the results to include members or lastMessagePreview properties. Possible values are: members, lastMessagePreview.                               | Optional     | 
| limit             | The number of results to retrieve. Default is 50.                                                                                                        | Optional     | 
| next_link         | A link that specifies a starting point to use for subsequent calls.                                                                                      | Optional     | 
| page_size         | Number of results to return per page. Default is 50.                                                                                                     | Optional     | 


#### Context Output

| **Path**                                    | **Type** | **Description**                                                                                                                                            |
|---------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| MicrosoftTeams.ChatList.chatId              | String   | The chat's unique identifier.                                                                                                                              | 
| MicrosoftTeams.ChatList.topic               | String   | Subject or topic for the chat. Only available for group chats.                                                                                             | 
| MicrosoftTeams.ChatList.createdDateTime     | String   | Date and time at which the chat was created.                                                                                                               | 
| MicrosoftTeams.ChatList.lastUpdatedDateTime | String   | Date and time at which the chat was renamed or list of members were last changed.                                                                          | 
| MicrosoftTeams.ChatList.chatType            | String   | Specifies the type of chat.                                                                                                                                | 
| MicrosoftTeams.ChatList.webUrl              | String   | The URL for the chat in Microsoft Teams. The URL should be treated as an opaque blob, and not parsed.                                                      | 
| MicrosoftTeams.ChatList.tenantId            | String   | The identifier of the tenant in which the chat was created.                                                                                                | 
| MicrosoftTeams.ChatList.viewpoint           | String   | Represents caller-specific information about the chat, such as last message read date and time.                                                            | 
| MicrosoftTeams.ChatList.onlineMeetingInfo   | String   | Represents details about an online meeting. If the chat isn't associated with an online meeting, the property is empty.                                    | 
| MicrosoftTeams.ChatListNextLink             | String   | Used if an operation returns partial results. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 

##### Command Example
```!microsoft-teams-chat-list filter="topic eq 'testing'"```

##### Human Readable Output
>### Chats List:
>| Chat Id                                       | Chat name | Created Date Time        | Last Updated Date Time   | Chat Type | webUrl | Tenant Id | Last Message Read Date Time |
>|-----------------------------------------------|-----------|--------------------------|--------------------------|-----------|--------|-----------|-----------------------------|
>| 19:561082c0f3f847a58069deb8eb300807@thread.v2 | testing   | 2023-01-08T14:15:45.412Z | 2023-01-08T14:15:45.412Z | group     | webUrl | tenantId  | 2023-01-08T14:16:48.662Z    |
>| 19:2da4c29f6d7041eca70b638b43d45437@thread.v2 | testing   | 2022-12-29T11:10:49.173Z | 2022-12-29T11:10:49.173Z | group     | webUrl | tenantId  | 2022-12-29T12:00:07.317Z    |

### microsoft-teams-chat-message-list
***
Retrieves a list of messages in a chat.


#### Base Command

`microsoft-teams-chat-message-list`

##### Required Permissions

`User.Read.All` - *Delegated*

`Chat.Read` - *Delegated*

`Chat.Create` - *Delegated*

Note: Chat.Create is needed only when listing one-on-one chats.

#### Input

| **Argument Name** | **Description**                                                                                                                                                                       | **Required** |
|-------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------|
| chat              | The chat ID / group chat name (topic) / oneOnOne member (Display name/mail/UPN).                                                                                                      | Required     | 
| limit             | The number of results to retrieve. Default is 50.                                                                                                                                     | Optional     | 
| order_by          | Orders results by lastModifiedDateTime (default) or createdDateTime in descending order. Possible values are: lastModifiedDateTime, createdDateTime. Default is lastModifiedDateTime. | Optional     | 
| next_link         | A link that specifies a starting point to use for subsequent calls.                                                                                                                   | Optional     | 
| page_size         | Number of results to return per page. Default is 50.                                                                                                                                  | Optional     | 


#### Context Output

| **Path**                                              | **Type** | **Description**                                                                                                                                            |
|-------------------------------------------------------|----------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| MicrosoftTeams.ChatList.chatId                        | String   | The chat's unique identifier.                                                                                                                              | 
| MicrosoftTeams.ChatList.messages.id                   | String   | Unique ID of the message.                                                                                                                                  | 
| MicrosoftTeams.ChatList.messages.replyToId            | String   | ID of the parent chat message or root chat message of the thread.                                                                                          | 
| MicrosoftTeams.ChatList.messages.etag                 | String   | Version number of the chat message.                                                                                                                        | 
| MicrosoftTeams.ChatList.messages.messageType          | String   | The type of chat message.                                                                                                                                  | 
| MicrosoftTeams.ChatList.messages.createdDateTime      | String   | Timestamp of when the chat message was created.                                                                                                            | 
| MicrosoftTeams.ChatList.messages.lastModifiedDateTime | String   | Timestamp when the chat message is created \(initial setting\) or modified, including when a reaction is added or removed.                                 | 
| MicrosoftTeams.ChatList.messages.lastEditedDateTime   | String   | Timestamp when edits to the chat message were made. Triggers an "Edited" flag in the Teams UI. If no edits are made the value is null.                     | 
| MicrosoftTeams.ChatList.messages.deletedDateTime      | String   | Timestamp at which the chat message was deleted, or null if not deleted.                                                                                   | 
| MicrosoftTeams.ChatList.messages.subject              | String   | The subject of the chat message, in plaintext.                                                                                                             | 
| MicrosoftTeams.ChatList.messages.summary              | String   | Summary text of the chat message that could be used for push notifications and summary views or fall back views.                                           | 
| MicrosoftTeams.ChatList.messages.chatId               | String   | If the message was sent in a chat, represents the identity of the chat.                                                                                    | 
| MicrosoftTeams.ChatList.messages.importance           | String   | The importance of the chat message.                                                                                                                        | 
| MicrosoftTeams.ChatList.messages.locale               | String   | Locale of the chat message set by the client.                                                                                                              | 
| MicrosoftTeams.ChatList.messages.webUrl               | String   | Link to the message in Microsoft Teams.                                                                                                                    | 
| MicrosoftTeams.ChatList.messages.channelIdentity      | String   | If the message was sent in a channel, represents identity of the channel.                                                                                  | 
| MicrosoftTeams.ChatList.messages.policyViolation      | String   | Defines the properties of a policy violation set by a data loss prevention \(DLP\) application.                                                            | 
| MicrosoftTeams.ChatList.messages.eventDetail          | String   | If present, represents details of an event that happened in a chat, a channel, or a team, for example, adding new members.                                 | 
| MicrosoftTeams.ChatList.messages.from                 | String   | Details of the sender of the chat message.                                                                                                                 | 
| MicrosoftTeams.ChatList.messages.body                 | String   | Plaintext/HTML representation of the content of the chat message. Representation is specified by the contentType inside the body.                          | 
| MicrosoftTeams.ChatList.messages.attachments          | String   | References to attached objects like files, tabs, meetings etc.                                                                                             | 
| MicrosoftTeams.ChatList.messages.mentions             | String   | List of entities mentioned in the chat message.                                                                                                            | 
| MicrosoftTeams.ChatList.messages.reactions            | String   | Reactions for this chat message \(for example, Like\).                                                                                                     | 
| MicrosoftTeams.MessageListNextLink                    | String   | Used if an operation returns partial results. If a response contains a NextLink element, its value specifies a starting point to use for subsequent calls. | 

##### Command Example
```!!microsoft-teams-chat-message-list chat="example chat" order_by=createdDateTime```

##### Human Readable Output
>### Messages list in "example chat" chat:
>| Chat Id                                       | Created DateTime        | Etag          | From user | From user id                         | From user userIdentityType | Importance | Message Content | Message Type | Message contentType | Message id    | lastModified DateTime   |
>|-----------------------------------------------|-------------------------|---------------|-----------|--------------------------------------|----------------------------|------------|-----------------|--------------|---------------------|---------------|-------------------------|
>| 19:2da4c29f6d7041eca70b638b43d45437@thread.v2 | 2021-03-29T04:17:43.15Z | 1616991463150 | itayadmin | 8ea0e38b-efb3-4757-924a-5f94061cf8c2 | aadUser                    | normal     | Hello World     | message      | text                | 1616991463150 | 2021-03-29T04:17:43.15Z |

### microsoft-teams-chat-update
***
Updates the chat name. It can only be set for group chats.


#### Base Command

`microsoft-teams-chat-update`

##### Required Permissions

`User.Read.All` - *Delegated*

`Chat.ReadWrite` - *Delegated*

#### Input

| **Argument Name** | **Description**                                                                 | **Required** |
|-------------------|---------------------------------------------------------------------------------|--------------|
| chat              | The chat ID / group chat name (topic).                                          | Required     | 
| chat_name         | The new chat name. Maximum length is 250 characters. Use of ':' is not allowed. | Required     | 


#### Context Output

There is no context output for this command.

##### Command Example
```!microsoft-teams-chat-update chat="example chat" chat_name="update chat_name"```

##### Human Readable Output
The name of chat 'example chat' has been successfully changed to 'update chat_name'.

### microsoft-teams-auth-test
***
Tests the connectivity to MicrosoftTeams.

##### Base Command

`microsoft-teams-auth-test`

##### Input
There are no input arguments for this command.

##### Context Output
There is no context output for this command.

##### Command Example
```!microsoft-teams-auth-test```

##### Human Readable Output
>✅ Success!

### microsoft-teams-generate-login-url
***
Generate the login url used for Authorization code flow.  
Note: Authorization codes are short-lived. Typically, they expire after about 10 minutes.

#### Base Command

`microsoft-teams-generate-login-url`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
#### Command example
```!microsoft-teams-generate-login-url```
#### Human Readable Output

>### Authorization instructions
>1. Click on the [login URL]() to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
>You will be automatically redirected to a link with the following structure:
>```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
>2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
>and paste it in your instance configuration under the **Authorization code** parameter.
>

### microsoft-teams-auth-reset

***
Run this command if for some reason you need to rerun the graph authentication process.
Notes:
- After making changes to permissions in the Azure Portal, reset the authentication to ensure that the token reflects the updated permissions.
- This command is triggered automatically when an authentication flow type switch is detected. The auto resetting ensures the integration uses the appropriate token.
- When switching the authentication type to the `Authorization Code Flow`, this command will be triggered automatically. Then you will need to regenerate the **Authorization code** parameter by running the ***microsoft-teams-generate-login-url*** command, and to verify the authentication by running the ***!microsoft-teams-auth-test*** command.

#### Base Command

`microsoft-teams-auth-reset`

#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

### microsoft-teams-token-permissions-list
***
Retrieves the API permissions associated with the used graph access token. 

Use this command if you encounter insufficient permissions error when attempting to execute an integration command. Compare the permissions list obtained for the token with the permissions required for the desired command (can be found in the integration documentation). If there are missing API permissions, add them to your application, and then run the `microsoft-teams-auth-reset` command (as described here - [microsoft-teams-auth-reset docs](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#microsoft-teams-auth-reset)).

##### Base Command

`microsoft-teams-token-permissions-list`

##### Input
There are no input arguments for this command.

##### Context Output
There is no context output for this command.

##### Command Example
```!microsoft-teams-token-permissions-list```

##### Human Readable Output
>### The API permissions obtained for the used graph access token are:
>| Permission          |
>|---------------------|
>| Group.ReadWrite.All |
>| User.Read.All       |
>| Channel.Create      |


### microsoft-teams-create-messaging-endpoint
***
Generates the messaging endpoint, based on the server URL, the server version, and the instance configurations. 

The messaging endpoint should be added to the Demisto bot configuration in Microsoft Teams as part of the prerequisites of the integration's setup. For more information see - [Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#create-the-demisto-bot-in-microsoft-teams).

##### Base Command

`microsoft-teams-create-messaging-endpoint`

##### Input

| **Argument Name**   | **Description**                                                                 | **Required** |
|---------------------|---------------------------------------------------------------------------------|--------------|
| engine_url          | If your instance configuration involves a Cortex XSOAR engine, provide the engine's IP (or DNS name) and the port in use in the following format - `https://IP:port` or `http://IP:port`. For example - `https://my-engine.name:443`, `http://1.1.1.1:443`. | Optional     | 

##### Context Output
There is no context output for this command.

##### Command Example
```!microsoft-teams-create-messaging-endpoint```

##### Human Readable Output
>### The messaging endpoint is: 
>|```https://ext-viso-test.crtx-qa-uat.us.paloaltonetworks.com/xsoar/instance/execute/teams-instance```
>
> The messaging endpoint should be added to the Demisto bot configuration in Microsoft Teams as part of the prerequisites of the integration's setup.
> For more information see: [Integration Documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#create-the-demisto-bot-in-microsoft-teams)."

### microsoft-teams-message-update

***
Updates a message.

##### Base Command

`microsoft-teams-message-update`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message_id | ID of the message to update. Also referred to as Activity ID. | Required | 
| team | The team in which the specified message exists. | Optional | 
| channel | The channel in which the specified message exists. | Optional | 
| message | The new message content. | Optional | 
| team_member | The team member the message to be edited was sent to. | Optional | 
| format_as_card | Whether or not an adaptive card is being updated. | Optional | 

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicrosoftTeams.Message.ID | String | ID of the message sent. | 


##### Command Example
```!microsoft-teams-message-update message_id=1737151779 team=MyTeam channel=General message="New message"```

##### Human Readable Output
Message was sent successfully.

## Running commands from Microsoft Teams
You can run Cortex XSOAR/Cortex XSIAM commands, according to the user permissions, from Microsoft Teams in a mirrored investigation channel.

## Direct messages commands
You can chat with the bot in direct messages in order to retrieve data (list incidents and tasks) and run operations (create incident and mirror an investigation) related to Cortex XSOAR.

You can send the message `help` in order to see the supported commands:

![image](../../doc_files/dm.png)

Note: To enrich an incident created via the Demisto BOT (`new incident` command) with extra information received with the request, as in regular `fetch-incidents` process users may create custom mappers and map the desired values.  

## Troubleshooting

1. The integration works by spinning up a web server that listens to events and data posted to it from Microsoft Teams.

    If you see the error message `Did not receive tenant ID from Microsoft Teams, verify the messaging endpoint is configured correctly.`, then it means that the tenant ID was never posted to the web server, which should happen for the first time when the bot is added to the configured team.

    This probably means that there is a connection issue, and the web server does not intercept the HTTPS queries from Microsoft Teams.

    To troubleshoot:
   1. Verify that the messaging endpoint is configured correctly according to the method you chose in the [Setup Examples](#setup-examples) step. If the configuration method you have chosen is rerouting, use the `microsoft-teams-create-messaging-endpoint`command ([microsoft-teams-create-messaging-endpoint documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#microsoft-teams-create-messaging-endpoint)) to get the correct messaging endpoint based on the server URL, the server version, and the instance configurations.
   2. Verify the Docker container is up and running and publish the configured port to the outside world:

       From the Cortex XSOAR / Cortex XSOAR engine machine run: `docker ps | grep teams`

       You should see the following, assuming port 7000 is used:

       `988fdf341127        demisto/teams:1.0.0.6483      "python /tmp/pyrunne…"   6 seconds ago       Up 4 seconds        0.0.0.0:7000->7000/tcp   demistoserver_pyexecLongRunning-b60c04f9-754e-4b68-87ed-8f8113419fdb-demistoteams1.0.0.6483--26`

       If the Docker container is up and running, try running cURL queries to verify the web server is up and running and listens on the configured URL:

        - To the messaging endpoint from a separate box.
        - From the Cortex XSOAR machine to localhost.
          - Note: The web server supports only POST method queries. 
        
   3. If the cURL queries were sent successfully, you should see the following line in Cortex XSOAR logs: `Finished processing Microsoft Teams activity successfully`.

   4. If you're working with secured communication (HTTPS), make sure that you provided a valid certificate. (Not for Cortex XSOAR/Cortex XSIAM Rerouting ).
       1. Run `openssl s_client -connect <domain.com>:443` .
       2. Verify that the returned value of the `Verify return code` field is `0 (ok)`, otherwise, it's not a valid certificate.
    
   5. Try inserting your configured message endpoint in a browser and click **Enter**. If `Method Not Allowed` is returned, the endpoint is valid and ready to communicate, otherwise, it needs to be handled according to the returned error's message. (Not for Cortex XSOAR 8 OR Cortex XSIAM).

   6. In some cases, a connection is not created between Teams and the messaging endpoint when adding a bot to the team. You can work around this problem by adding any member to the team the bot was added to (the bot should be already added to the team). This will trigger a connection and solve the issue. You can then remove the member that was added.

2. If you see the following error message: `Error in API call to Microsoft Teams: [403] - UnknownError`, it means the AAD application has insufficient permissions. 
To retrieves the API permissions associated with the used graph access token you can run the `microsoft-teams-token-permissions-list` command ([microsoft-teams-token-permissions-list documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#microsoft-teams-token-permissions-list)).
Compare the permissions list obtained for the token with the permissions required for the command you wish to execute (can be found in the command documentation). If there are missing API permissions, add them to your application, and then run the `microsoft-teams-auth-reset` command (as described here - [microsoft-teams-auth-reset documentation](https://xsoar.pan.dev/docs/reference/integrations/microsoft-teams#microsoft-teams-auth-reset)). 
If your authentication type is the `Authorization Code Flow`, after running the `microsoft-teams-auth-reset` command you will need to regenerate the **Authorization code** parameter by running the ***microsoft-teams-generate-login-url*** command, and to verify the authentication by running the ***!microsoft-teams-auth-test*** command.

3. Since the integration works based on Docker port mapping, it can't function if the Docker is set to run with the host networking (`--network=host`). For more details, refer to the [Docker documentation](https://docs.docker.com/network/host/).

4. The integration stores in cache metadata about the teams, members and channels. Starting from Cortex XSOAR version 6.1.0, you can clear the integration cache in the integration instance config:

   <img height="75" src="../../doc_files/cache.png" />

   First, make sure to remove the bot from the team (only via the Teams app), before clearing the integration cache, and add it back after done.
   If the bot belongs to multiple teams, make sure to remove it from all the teams it was added to, and then clear the cache.
5. If the previous step did not work, remove the bot from the team, go to the Microsoft Teams admin center > Manage apps and hard refresh the page!(cmd+ shift + R), then add the bot to the team again.
6. If you are receiving repeated `Connection reset by peer` errors, the requests might be getting blocked temporarily by Azure due to repeated permission errors. Ensure you are not missing any permissions that might cause constant failures and eventually leading to server timeouts.

## Download Demisto Bot

[Demisto Bot zip](https://github.com/demisto/content/raw/2d9804da7ff94bc1243fe083f280e44602bd1738/Packs/MicrosoftTeams/Integrations/MicrosoftTeams/doc_files/DemistoBot.zip)
