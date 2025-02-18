Mattermost is an open-source, self-hostable online chat service with file sharing, search, and integrations. It is designed as an internal chat for organizations and companies.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous version of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---mattermost-v2).

## Configure Mattermost v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Bot Access Token | The Bot Access Token to use for connection. | True |
| Personal Access Token | The Personal Access Token to use for connection. | True |
| Team Name |  | True |
| Default Notifications Channel | If Notifications Channel name is not specified, will send notification to incidentNotificationChannel channel. | False |
| Enable Incident Mirroring |  | False |
| Allow external users to create incidents via DM. |  | False |
| Types of Notifications to Send | Notifications of type 'externalAskSubmit' or 'externalFormSubmit' are not configurable because they are required to allow Ask tasks to be sent correctly. | False |
| Long running instance. Required for investigation mirroring and direct messages. |  | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### mattermost-get-team

***
Gets a team's details.

#### Required Permissions

Must be authenticated and have the view_team permission.

#### Base Command

`mattermost-get-team`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_name | The name of the team to retrieve. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mattermost.Team.id | String | The ID of the team. | 
| Mattermost.Team.create_at | Unknown | When was the team created. | 
| Mattermost.Team.update_at | Unknown | When was the team updated. | 
| Mattermost.Team.delete_at | Unknown | When was the team deleted. | 
| Mattermost.Team.display_name | String | The display name of the team. | 
| Mattermost.Team.name | String | The name of the team. | 
| Mattermost.Team.description | String | The description of the team. | 
| Mattermost.Team.email | String | The email of the team. | 
| Mattermost.Team.type | String | The type of the team. | 
| Mattermost.Team.company_name | String | The company name of the team. | 
| Mattermost.Team.allowed_domains | String | The allowed domains of the team. | 
| Mattermost.Team.invite_id | String | The allowed domains of the team. | 
| Mattermost.Team.allow_open_invite | Unknown | Does the team allow open invites. | 
| Mattermost.Team.scheme_id | String | The scheme ID of the team. | 
| Mattermost.Team.policy_id | String | The policy ID of the team. | 

#### Command example

```!mattermost-get-team team_name=panw```

#### Context Example

```json
{
    "Mattermost": {
        "Team": {
            "allow_open_invite": false,
            "allowed_domains": "",
            "cloud_limits_archived": false,
            "company_name": "",
            "create_at": 1696486762638,
            "delete_at": 0,
            "description": "",
            "display_name": "PANW",
            "email": "rrapoport@paloaltonetworks.com",
            "group_constrained": false,
            "id": "6ie46zmi4fdqiqqe7p5gfki9hr",
            "invite_id": "ocoh4fcrw7dzxgfu5bdtqpy7cr",
            "name": "panw",
            "policy_id": null,
            "scheme_id": "",
            "type": "O",
            "update_at": 1696486762638
        }
    }
}
```

#### Human Readable Output

>### Team details:

>|allow_open_invite|allowed_domains|cloud_limits_archived|company_name|create_at|delete_at|description|display_name|email|group_constrained|id|invite_id|name|policy_id|scheme_id|type|update_at|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false |  | false |  | 1696486762638 | 0 |  | PANW | email | false | id | id | panw |  |  | O | 1696486762638 |


### mattermost-list-channels

***
Lists channels.

#### Required Permissions

manage_system

#### Base Command

`mattermost-list-channels`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | The name of the team to list channels from. Default is the team name from the integration configuration. | Optional | 
| include_private_channels | Whether to include private channels. Default is false. Possible values are: true, false. | Optional | 
| page | The page number to retrieve. Default value is 0. | Optional | 
| page_size | The size of the page to retrieve. Default value is 50. | Optional | 
| limit | How many results to retrieve. Will override the page and page_size arguments if given. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mattermost.Channel.id | String | The ID of the channel. | 
| Mattermost.Channel.create_at | Unknown | When was the channel created. | 
| Mattermost.Channel.update_at | Unknown | When was the channel updated. | 
| Mattermost.Channel.delete_at | Unknown | When was the channel deleted. | 
| Mattermost.Channel.display_name | String | The display name of the channel. | 
| Mattermost.Channel.name | String | The name of the channel. | 
| Mattermost.Channel.description | String | The description of the channel. | 
| Mattermost.Channel.header | String | The header of the channel. | 
| Mattermost.Channel.purpose | String | The purpose of the channel. | 
| Mattermost.Channel.last_post_at | Unknown | When was the last post to the channel made. | 
| Mattermost.Channel.total_msg_count | Unknown | The total massage count of the channel. | 
| Mattermost.Channel.extra_update_at | Unknown | When was the channel updated. | 
| Mattermost.Channel.creator_id | String | The creator ID of the channel. | 

#### Command example

```!mattermost-list-channels limit=2 include_private_channels=true```

#### Context Example

```json
{
    "Mattermost": {
        "Channel": [
            {
                "create_at": 1697024204532,
                "creator_id": "creator_id",
                "delete_at": 0,
                "display_name": "Name",
                "extra_update_at": 0,
                "group_constrained": null,
                "header": "",
                "id": "id",
                "last_post_at": 1712503619042,
                "last_root_post_at": 1712503619042,
                "name": "name",
                "policy_id": null,
                "props": null,
                "purpose": "",
                "scheme_id": null,
                "shared": null,
                "team_id": "team_id",
                "total_msg_count": 58,
                "total_msg_count_root": 56,
                "type": "O",
                "update_at": 1697024204532
            },
            {
                "create_at": 1696486762650,
                "creator_id": "",
                "delete_at": 0,
                "display_name": "Off-Topic",
                "extra_update_at": 0,
                "group_constrained": null,
                "header": "",
                "id": "id",
                "last_post_at": 1712501916866,
                "last_root_post_at": 1712501916866,
                "name": "off-topic",
                "policy_id": null,
                "props": null,
                "purpose": "",
                "scheme_id": null,
                "shared": null,
                "team_id": "team_id",
                "total_msg_count": 4,
                "total_msg_count_root": 4,
                "type": "O",
                "update_at": 1696486762650
            }
        ]
    }
}
```

#### Human Readable Output

>### Channels:

>|name|display_name|type|id|
>|---|---|---|---|
>| name | Display_Name | O | id |
>| off-topic | Off-Topic | O | id |


### mattermost-create-channel

***
Creates a channel.

#### Required Permissions

If creating a public channel, create_public_channel permission is required. If creating a private channel, create_private_channel permission is required.

#### Base Command

`mattermost-create-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| display_name | The display name of the channel to create. | Required | 
| name | The name of the channel to create. | Required | 
| type | The type of the channel to create. Possible values are: public, private. Default is public. | Optional | 
| purpose | The purpose of the channel to create. | Optional | 
| header | The header of the channel to create. | Optional | 
| team | The team name of the channel to create. Default is the team name from the integration configuration. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mattermost.Channel.id | String | The ID of the channel. | 
| Mattermost.Channel.create_at | Unknown | When was the channel created. | 
| Mattermost.Channel.update_at | Unknown | When was the channel updated. | 
| Mattermost.Channel.delete_at | Unknown | When was the channel deleted. | 
| Mattermost.Channel.display_name | String | The display name of the channel. | 
| Mattermost.Channel.name | String | The name of the channel. | 
| Mattermost.Channel.description | String | The description of the channel. | 
| Mattermost.Channel.header | String | The header of the channel. | 
| Mattermost.Channel.purpose | String | The purpose of the channel. | 
| Mattermost.Channel.last_post_at | Unknown | When was the last post to the channel made. | 
| Mattermost.Channel.total_msg_count | Unknown | The total massage count of the channel. | 
| Mattermost.Channel.extra_update_at | Unknown | When was the channel updated. | 
| Mattermost.Channel.creator_id | String | The creator ID of the channel. | 
| Mattermost.Channel.scheme_id | String | The scheme ID of the channel. | 

#### Command example

```!mattermost-create-channel display_name=channel_name name=channel_name type=Private```

#### Context Example

```json
{
    "Mattermost": {
        "Channel": {
            "create_at": 1712649608411,
            "creator_id": "creator_id",
            "delete_at": 0,
            "display_name": "channel_name",
            "extra_update_at": 0,
            "group_constrained": null,
            "header": "",
            "id": "id",
            "last_post_at": 1712649608426,
            "last_root_post_at": 1712649608426,
            "name": "channel_name",
            "policy_id": null,
            "props": null,
            "purpose": "",
            "scheme_id": null,
            "shared": null,
            "team_id": "team_id",
            "total_msg_count": 0,
            "total_msg_count_root": 0,
            "type": "P",
            "update_at": 1712649608411
        }
    }
}
```

#### Human Readable Output

>Channel channel_name was created successfully.

### mattermost-add-channel-member

***
Adds a channel member.

#### Required Permissions

No permissions required.

#### Base Command

`mattermost-add-channel-member`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | The team name of the channel to add the user to. Default is the team name from the integration configuration. | Optional | 
| channel | The name of the channel to add the user to. | Required | 
| user_id | The ID of the user to add. Use the command 'mattermost-list-users' to fetch the user ID. | Required | 

#### Context Output

There is no context output for this command.

### mattermost-remove-channel-member

***
Removes a channel member.

#### Required Permissions

manage_public_channel_members permission if the channel is public. manage_private_channel_members permission if the channel is private.

#### Base Command

`mattermost-remove-channel-member`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team | The team name of the channel to add the user to. Default is the team name from the integration configuration. | Optional | 
| channel | The channel name of the channel to remove the user from. | Required | 
| user_id | The ID of the user to remove. Use the command 'mattermost-list-users' to fetch the user ID. | Required | 

#### Context Output

There is no context output for this command.

### mattermost-list-users

***
Lists users.

#### Required Permissions

Requires an active session and (if specified) membership to the channel or team being selected from.

#### Base Command

`mattermost-list-users`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_name | The name of the team to filter users by. | Optional | 
| channel | The name of the channel to filters users by. If mentioned, a team name must be mentioned as well. | Optional | 
| page | The page number to retrieve. Should be provided with the page_size argument. Default value is 0. | Optional | 
| page_size | The size of the page to retrieve. Should be provided with the page argument. Default value is 50. | Optional | 
| limit | How many results to retrieve. If provided, overrides the page and page_size arguments. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Mattermost.User.id | String | The ID of the user. | 
| Mattermost.User.create_at | Unknown | When was the user created. | 
| Mattermost.User.update_at | Unknown | When was the user updated. | 
| Mattermost.User.delete_at | Unknown | When was the user deleted. | 
| Mattermost.User.username | String | The username of the user. | 
| Mattermost.User.auth_data | String | The authorization data of the user. | 
| Mattermost.User.auth_service | String | The authorization service of the user. | 
| Mattermost.User.email | String | The email of the user. | 
| Mattermost.User.nickname | String | The nickname of the user. | 
| Mattermost.User.first_name | Unknown | The first name of the user. | 
| Mattermost.User.last_name | Unknown | The last name of the user. | 
| Mattermost.User.position | Unknown | The position of the user. | 
| Mattermost.User.roles | String | The roles of the channel. | 
| Mattermost.User.locale | String | The locale of the channel. | 
| Mattermost.User.timezone | Unknown | The timezone of the user. | 

#### Command example

```!mattermost-list-users limit=2 team_name=panw```

#### Context Example

```json
{
    "Mattermost": {
        "User": [
            {
                "auth_data": "",
                "auth_service": "",
                "create_at": 1696486752272,
                "delete_at": 0,
                "disable_welcome_email": false,
                "email": "email",
                "first_name": "",
                "id": "id",
                "last_name": "",
                "locale": "en",
                "nickname": "",
                "position": "",
                "roles": "system_admin system_user",
                "timezone": {
                    "automaticTimezone": "Asia/Jerusalem",
                    "manualTimezone": "",
                    "useAutomaticTimezone": "true"
                },
                "update_at": 1696486762658,
                "username": "admin"
            },
            {
                "auth_data": "",
                "auth_service": "",
                "create_at": 1696500307646,
                "delete_at": 0,
                "disable_welcome_email": false,
                "email": "email",
                "first_name": "",
                "id": "id",
                "last_name": "",
                "locale": "en",
                "nickname": "",
                "position": "",
                "roles": "system_user system_admin",
                "timezone": {
                    "automaticTimezone": "Asia/Jerusalem",
                    "manualTimezone": "",
                    "useAutomaticTimezone": "true"
                },
                "update_at": 1697354262697,
                "username": "username"
            }
        ]
    }
}
```

#### Human Readable Output

>### Users:

>|username|email|role|id|
>|---|---|---|---|
>| admin | admin@admin.com |  | 8a6t7whumbdbxrawretujh6rre |
>| dev | admin@ddev.com |  | o9hpcwz73fdwxe9adue8jxo16o |


### mattermost-send-file

***
Sends a file.

#### Required Permissions

Must have upload_file permission.

#### Base Command

`mattermost-send-file`

#### Command example

```!mattermost-send-file message=check entry_id=85@109 channel=test```

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_name | The team name of the channel to send the file to. Default is the team name from the integration configuration. | Optional | 
| channel | The channel name of the channel to send the file to. Cannot be combined with the to argument. | Optional | 
| message | The message to send to the channel along with the file. | Required | 
| entry_id | The entry ID of the file. | Required | 
| to | The username or email of the user to send the file to. | Optional | 

#### Context Output

There is no context output for this command.

#### Human Readable Output

file test.txt was successfully sent to channel test

### send-notification

***
Send a message using a chatbot app.

#### Required Permissions

Must have create_post permission for the channel the post is being created in.

#### Base Command

`send-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message to send. | Required | 
| channel | The channel name to send the notification to. Default value is the channel configuration parameter. | Optional | 
| entry | An entry ID to send as a link. | Optional | 
| to | The username or email of the user to send the file to. | Optional | 
| ignoreAddURL | Adds the War Room link to the message. Possible values are: true, false. | Optional | 
| mattermost_ask | The message as a JSON for asking questions to the user. Default value is false. Possible values are: true, false. | Optional | 

#### Context Output

There is no context output for this command.

### mattermost-close-channel

***
Closes a channel.

#### Required Permissions

delete_public_channel permission if the channel is public. delete_private_channel permission if the channel is private, or has manage_system permission.

#### Base Command

`mattermost-close-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_name | The team name of the channel to close. Default value is the team name from the integration configuration. | Optional | 
| channel | The channel name of the channel to close. If not provided, the mirrored investigation channel is archived (if the channel exists). | Optional | 

#### Context Output

There is no context output for this command.

### close-channel

***
Closes a mirrored MatterMost channel. If not provided, the mirrored investigation channel is archived (if the channel exists).

#### Required Permissions

delete_public_channel permission if the channel is public. delete_private_channel permission if the channel is private, or has manage_system permission.

#### Base Command

`close-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_name | The team name of the channel to delete. Default value is the team name from the integration configuration. | Optional | 
| channel | The channel name of the channel to close. | Optional | 

#### Context Output

There is no context output for this command.

### mirror-investigation

***
Mirrors the investigation between Mattermost and the Cortex XSOAR War Room.

#### Required Permissions

No permissions required.

#### Base Command

`mirror-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. Possible values are: all, chat, none. Default is all. | Optional | 
| autoclose | Whether the channel is auto-closed when an investigation is closed. Possible values are: true, false. Default is true. | Optional | 
| direction | The mirroring direction. Possible values are: Both, FromDemisto, ToDemisto. Default is Both. | Optional | 
| channel | The name of the channel. The default is "incident-&lt;incidentID&gt;". | Optional | 
| kickAdmin | Whether to remove the admin from the newly created channel. Default value is false. Possible values are: true, false. Default is false. | Optional | 
| mirrorTo | Mirrors the investigation to a group (private channel) or a public channel. Default is group. Possible values are: group, channel. Default is group. | Optional | 

#### Context Output

There is no context output for this command.

### close-channel

***
Closes a mirrored Mattermost channel. If not provided, the mirrored investigation channel is archived (if the channel exists).

#### Base Command

`close-channel`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| team_name | The team name of the channel to delete. Default value is the team name from the integration configuration. | Optional | 
| channel_name | The channel name of the channel to delete. | Optional | 

#### Context Output

There is no context output for this command.

### mattermost-mirror-investigation

***
Mirrors the investigation between Mattermost and the Cortex XSOAR War Room.

#### Required Permissions

No permissions channel.

#### Base Command

`mattermost-mirror-investigation`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| type | The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring. Possible values are: all, chat, none. Default is all. | Optional | 
| autoclose | Whether the channel is auto-closed when an investigation is closed. Possible values are: true, false. Default is true. | Optional | 
| direction | The mirroring direction. Possible values are: Both, FromDemisto, ToDemisto. Default is Both. | Optional | 
| channel | The name of the channel. The default is "incident-&lt;incidentID&gt;". | Optional | 
| kickAdmin | Whether to remove the admin from the newly created channel. Default value is false. Possible values are: true, false. Default is false. | Optional | 
| mirrorTo | Mirrors the investigation to a group (private channel) or a public channel. Possible values are: group, channel. Default is group. | Optional | 

#### Context Output

There is no context output for this command.

## Breaking changes from the previous version of this integration - Mattermost v2

A new required configuration parameters was added: *Bot Access Token*.