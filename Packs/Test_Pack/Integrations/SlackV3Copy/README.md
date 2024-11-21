Send messages and notifications to your Slack team.
## Configure SlackV3_copy on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SlackV3_copy.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Bot Token |  | False |
    | User Token |  | False |
    | App Token |  | False |
    | Dedicated Slack channel to receive notifications |  | False |
    | Minimum incident severity by which to send messages to Slack |  | False |
    | Types of Notifications to Send. | By default, externalFormSubmit is enabled in order to allow Ask tasks to be sent correctly. | False |
    | Type of incidents created in Slack |  | False |
    | Allow external users to create incidents via DM |  | False |
    | Ignore event retries | In some cases, events may not be processed fast enough. If you want to attempt to retry the event, select \`false\`. Note that this can result in some responses being double-posted. | False |
    | Use system proxy settings |  | False |
    | Trust any certificate (not secure) | Trust any certificate \(not secure\). Make sure to mark this parameter if you want the SlackBlockBuilder script to send a response back to the incident context. | False |
    | Enable Incident Mirroring |  | False |
    | Enable Outbound File Mirroring | Whether to enable mirroring only from xsoar to slack, mark it if file mirroring is required in investigations. | False |
    | Long running instance. Required for investigation mirroring and direct messages. | If your organization does not require incident mirroring, or data collection, it is possible to disable the \`longRunning\` parameter. For those organizations who do want to use these features, the parameter should be set to \`True\` to enable the long-running container. | False |
    | Bot display name in Slack |  | False |
    | Bot icon in Slack - Image URL (Cortex XSOAR icon by default) |  | False |
    | Maximum time to wait for a rate limiting call in seconds |  | False |
    | Number of objects to return in each paginated call |  | False |
    | Comma-separated list of tags to filter the messages sent from Cortex XSOAR. | Only supported in Cortex XSOAR V6.1 and above. | False |
    | XSOAR API Key | Adding an API key will enable the integration to handle blocks that contain a state and is necessary for the SlackBlockBuilder script. | False |
    | Enable DMs to the bot |  | False |
    | Disable Caching of Users and Channels | This parameter prevents this integration from storing Users and Channels in the integration context. This parameter also prevents paginated calls which can result in timeout errors for large workspaces. | False |
    | Extensive Logging | This parameter will write additional data to the logs and should only be used when you are directed to by XSOAR support. | False |
    | Common Channels | For workspaces where a handful of channels are consistently being used, you may add them as a CSV in the format ChannelName:ChannelID. | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mirror-investigation

***
Mirrors the investigation between Slack and the Cortex XSOAR War Room.

#### Base Command

`mirror-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. Possible values are: all, chat, none. Default is all. | Optional | 
| autoclose | Whether the channel is auto-closed when an investigation is closed. Can be "true" or "false". Default is "true". Possible values are: true, false. Default is true. | Optional | 
| direction | The mirroring direction. Possible values are: Both, FromDemisto, ToDemisto. Default is Both. | Optional | 
| mirrorTo | The channel type. Possible values are: channel, group. Default is group. | Optional | 
| channelName | The name of the channel. The default is "incident-&lt;incidentID&gt;". | Optional | 
| channelTopic | The topic of the channel. | Optional | 
| kickAdmin | Whether to remove the Slack administrator (channel creator) from the mirrored channel. Possible values are: true, false. Default is false. | Optional | 
| private | Whether the mirrored channel should be private or not (true by default). Possible values are: true, false. Default is true. | Optional | 

#### Context Output

There is no context output for this command.
### send-notification

***
Sends a message to a user, group, or channel.

#### Base Command

`send-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message content. When mentioning another Slack user, make sure to do so in the following format: &lt;@user_name&gt;. | Optional | 
| to | The user to whom to send the message. Can be either the username or email address. | Optional | 
| channel | The name of the Slack channel to which to send the message. | Optional | 
| channel_id | The ID of the Slack channel to which to send the message. | Optional | 
| entry | An entry ID to send as a link. | Optional | 
| ignoreAddURL | Whether to include a URL to the relevant component in Cortex XSOAR. Possible values are: true, false. Default is false. | Optional | 
| threadID | The ID of the thread to which to reply. Can be retrieved from a previous send-notification command. | Optional | 
| blocks | A JSON string of Slack blocks to send in the message. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.Thread.ID | String | The Slack thread ID. | 

### close-channel

***
Archives a Slack channel.

#### Base Command

`close-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The name of the channel to archive. If not provided, the mirrored investigation channel is archived (if the channel exists). | Optional | 
| channel_id | The ID of the channel to archive. If not provided, the mirrored investigation channel is archived (if the channel exists). | Optional | 

#### Context Output

There is no context output for this command.
### slack-send-file

***
Sends a file to a user, channel, or group. If not specified, the file is sent to the mirrored investigation channel (if the channel exists).

#### Base Command

`slack-send-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | The ID of the file entry to send. | Required | 
| to | The user to whom to send the file. Can be the username or the email address. | Optional | 
| group | The name of the Slack group (private channel) to which to send the file. | Optional | 
| channel | The name of the Slack channel to which to send the file. | Optional | 
| channel_id | The ID of the Slack channel to which to send the file. | Optional | 
| threadID | The ID of the thread to which to reply. Can be retrieved from a previous send-notification command. | Optional | 
| comment | A comment to add to the file. | Optional | 

#### Context Output

There is no context output for this command.
### slack-set-channel-topic

***
Sets the topic for a channel.

#### Base Command

`slack-set-channel-topic`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel name. If not specified, the topic of the mirrored investigation channel is set (if the channel exists). | Optional | 
| channel_id | The channel ID. If not specified, the topic of the mirrored investigation channel is set (if the channel exists). | Optional | 
| topic | The topic for the channel. | Required | 

#### Context Output

There is no context output for this command.
### slack-create-channel

***
Creates a channel in Slack.

#### Base Command

`slack-create-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The channel type. Possible values are: private, public. Default is private. | Optional | 
| name | The name of the channel. | Required | 
| users | A CSV list of user names or email addresses to invite to the channel. For example: "user1, user2...". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.Channel.ID | String | The ID of the channel. | 
| Slack.Channel.Name | String | The name of the channel. | 

### slack-invite-to-channel

***
Invites users to join a channel.

#### Base Command

`slack-invite-to-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| users | A CSV list of usernames or email addresses to invite to join the channel. For example: "user1, user2...". | Required | 
| channel | The name of the channel to which to invite the users. If the name of the channel is not specified, the name of the mirrored investigation channel is used (if the channel exists). | Optional | 
| channel_id | The ID of the channel to which to invite the users. If the ID of the channel is not specified, the ID of the mirrored investigation channel is used (if the channel exists). | Optional | 

#### Context Output

There is no context output for this command.
### slack-kick-from-channel

***
Removes users from the specified channel.

#### Base Command

`slack-kick-from-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| users | A CSV list of usernames or email addresses to remove from the a channel. For example: "user1, user2...". | Required | 
| channel | The name of the channel from which to remove the users. If the name of the channel is not specified, the mirrored investigation channel is used (if the channel exists). | Optional | 
| channel_id | The ID of the channel from which to remove the users. If the ID of the channel is not specified, the mirrored investigation channel is used (if the channel exists). | Optional | 

#### Context Output

There is no context output for this command.
### slack-rename-channel

***
Renames a channel in Slack.

#### Base Command

`slack-rename-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The new name of the channel. | Required | 
| channel | The current name of the channel. If the name of the channel is not specified, the mirrored investigation channel is used (if the channel exists). | Optional | 
| channel_id | The current ID of the channel. If the ID of the channel is not specified, the mirrored investigation channel is used (if the channel exists). | Optional | 

#### Context Output

There is no context output for this command.
### slack-get-user-details

***
Get details about a specified user.

#### Base Command

`slack-get-user-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | The Slack user (username or email). | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.User.ID | String | The ID of the user. | 
| Slack.User.Username | String | The username of the user. | 
| Slack.User.Name | String | The actual name of the user. | 
| Slack.User.DisplayName | String | The display name of the user. | 
| Slack.User.Email | String | The email address of the user. | 

### slack-get-integration-context

***
Returns the integration context as a file. Use this command for debug purposes only.

#### Base Command

`slack-get-integration-context`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### slack-pin-message

***
Pins a selected message to the given channel.

#### Base Command

`slack-pin-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel containing the message. | Optional | 
| threadID | The ID of the thread of which to pin. Can be retrieved from a previous send-notification command. | Required | 
| channel_id | The ID for the channel containing the message. | Optional | 

#### Context Output

There is no context output for this command.
### slack-edit-message

***
Edit an existing Slack message.

#### Base Command

`slack-edit-message`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel | The channel the message is posted in. | Optional | 
| channel_id | The ID for the channel the message is posted in. | Optional | 
| threadID | The ID of the thread of which to edit. Can be retrieved from a previous send-notification command. | Required | 
| message | The updated message. | Optional | 
| blocks | A JSON string of the block to send. | Optional | 
| ignore_add_url | Whether to include a URL to the relevant component in XSOAR. Can be "true" or "false". Default value is "false". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.Thread.ID | String | The timestamp identifier for the message. | 
| Slack.Thread.Channel | String | The channel ID the message was posted in. | 
| Slack.Thread.Text | String | The text the message was updated with. | 

### slack-user-session-reset

***
Reset user session token in Slack.

#### Base Command

`slack-user-session-reset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user id of the user. | Required | 

#### Context Output

There is no context output for this command.
### slack-list-channels

***
List all of the channels in the organization workspace. This command required scopes depend on the type of channel-like object you're working with. To use the command, you'll need at least one of the channels:, groups:, im: or mpim: scopes corresponding to the conversation type you're working with.

#### Base Command

`slack-list-channels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name_filter | Supply this argument to only return channels with this name. | Optional | 
| channel_types | You can provide a comma separated list of other channels to include in your results. Possible options are: "public_channel", "private_channel", "mpim", and "im".  Including these options may require changes to your Bot's OAuth scopes in order to read channels like private, group message, or personal messages. Default is public_channel. | Optional | 
| exclude_archived | Default is true (exclude archived channels). This setting allows the command to read channels that have been archived. Default is true. | Optional | 
| limit | Set this argument to specify how many results to return. If you have more results than the limit you set, you will need to use the cursor argument to paginate your results. Default is 100. | Optional | 
| cursor | Default is the first page of results. If you have more results than your limit, you need to paginate your results with this argument.  This is found with the next_cursor attribute returned by a previous request's response_metadata. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Slack.Channels.ID | string | The ID for the channel. | 
| Slack.Channels.Name | string | Name of the channel. | 
| Slack.Channels.Created | number | Epoch timestamp when the channel was created. | 
| Slack.Channels.Creator | string | ID for the creator of the channel. | 
| Slack.Channels.Purpose | string | The purpose, or description, of the channel. | 

### slack-get-conversation-history

***
Fetches a conversation's history of messages and events.

#### Base Command

`slack-get-conversation-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_id | The channel ID associated with the Slack channel. | Required | 
| limit | Set this argument to specify how many results to return. If you have more results than the limit you set, you will need to use the cursor argument to paginate your results. Default is 100. | Optional | 
| conversation_id | The conversation ID. | Optional | 

#### Context Output

There is no context output for this command.
### slack-get-conversation-replies

***
Retrieves replies to specific messages, regardless of whether it's from a public or private channel, direct message, or otherwise.

#### Base Command

`slack-get-conversation-replies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| channel_id | ID of the channel. | Required | 
| thread_timestamp | The timestamp of the thread, that can be extracted using "slack-get-conversation-history" command. | Required | 
| limit | Set this argument to specify how many results to return. Default is 100. | Optional | 

#### Context Output

There is no context output for this command.
