Google Chat integration allows you to send messages and conduct surveys.

This integration was integrated and tested with version xx of GoogleChat.

## Configure Google Chat on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Google Chat.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Google Chat Space ID |  | True |
    | Google Chat Space Key |  | False |
    | Google Chat Service Account JSON |  | False |
    | Long running instance | Enable in order to use GoogleChat-ask. | False |
    | Listen Port | Listener port number.<br/> Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. | False |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.

### Server configuration (XSOAR 6.x)

In the Server Configuration section, verify that the value for the `instance.execute.external.INTEGRATION-INSTANCE-NAME` key is set to true. If this key does not exist:

1. Click **+ Add Server Configuration**.
2. Add **instance.execute.external.integration-instance-name** and set the value to true.

## Create Google Chat App

1. Navigate to [here](https://console.cloud.google.com) and authenticate with your google user.
2. On top left click on the dropdown.
3. In the popup click on **NEW PROJECT** > fill in the form and click on create.
4. Select the project which was created.
5. Navigate to [here](https://console.cloud.google.com/apis/credentials/consent), Select the user type for your app, then click Create.
6. Navigate to **API's & Services** > **Credentials**.
7. Click on **+ CREATE CREDENTIALS** and add the following:
    - API key.
    - OAuth client ID.
    - Service Account:
        - Under the **Grant this service account** section set the role to owner.
        - After is was created click on **manage service account** > actions > manage keys > ADD KEY > create new key- save the json which is automatically downloaded.
8. Navigate to [here](https://console.cloud.google.com/apis/api/chat.googleapis.com) and enable the Google Chat API.
9. Under the Enabled APIs & service click on the Google Chat API
10. Click the CONFIGURATION tab:
    - Under **Functionality**, select one or both of the following checkboxes:
        - Receive 1:1 messages: Lets users interact with your Chat app in direct messages (DM) spaces. Your Chat app receives interaction events any time a user sends a message in the DM space.
        - Join spaces and group conversations: Lets users add and remove your Chat app to spaces with more than one person. Your Chat app receives interaction events whenever it's added or removed from the space, and whenever users @mention or use a slash command in the space.
    - Under **Connection settings** select the App URL button and insert your XSOAR URL according to the guide bellow:
        - For Cortex XSOAR 6.x: `<CORTEX-XSOAR-URL\>/instance/execute/<INTEGRATION-INSTANCE-NAME\>`. For example, `https://my.xsoar6.server/instance/execute/google-chat-instance-1`.<br/> Note that the string instance does not refer to the name of your XSOAR instance, but rather is part of the URL.
        - For Cortex XSOAR 8.x / XSIAM: you need to run using external engine: `https://<Engine URL\>:<port\>`. For example, `https://my-engine-url:7001`.
    - Under **Visibility** - choose your desired option.

## Add the Google Chat App to your Google Chat
1. Click on New chat > search for the app which was created in the previous step.
2. Click on New chat > create a space.
3. Under the space which was created click on the dropdown > Apps & integrations > + Add apps > choose the app which was created in the previous step.


## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### send-notification

***
Send messages through google chat

#### Base Command

`send-notification`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| message | The message content. | Required | 
| to | The recipient of the message. | Optional | 
| space_id | The ID of the space to which to send the message. | Required | 
| thread_id | If replying to a thread, use this argument to specify the thread name to reply to. | Optional | 
| adaptive_card | Card to send. See Card Builder [here](https://addons.gsuite.google.com/uikit/builder). | Optional | 
| entitlement | Full entitlement for GoogleChatAsk script. | Optional | 
| expiry | Expiry time for waiting to the user response. | Optional | 
| default_reply | Default reply if the expiration time of the message has exceeded. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GoogleChat.sender.name | unknown | Display the sender name. | 
| GoogleChat.sender.displayName | unknown | Display the sender display name. | 
| GoogleChat.sender.type | unknown | Display the sender type. | 
| GoogleChat.space.name | unknown | Display the space name. | 
| GoogleChat.space.displayName | unknown | Display the space display name. | 
| GoogleChat.space.type | unknown | Display the space type. | 
| GoogleChat.thread.name | unknown | Display the thread name. | 
| GoogleChat.thread.threadKey | unknown | Display the thread key. | 

#### Command example
```!send-notification message=`hi from the test` space_id=AAAAAAAAAA```
#### Context Example
```json
{
    "GoogleChatWebhook": {
        "Message": {
            "argumentText": "hi from the test",
            "createTime": "2024-07-10T13:13:36.046495Z",
            "formattedText": "hi from the test",
            "name": "spaces/AAAAAAAAAA/messages/11111111.11111111",
            "sender": {
                "displayName": "mySpace",
                "name": "users/123456789",
                "type": "BOT"
            },
            "space": {
                "createTime": "2024-07-10T12:56:33.360356Z",
                "displayName": "myNewProject",
                "externalUserAllowed": true,
                "name": "spaces/AAAAAAAAAA",
                "spaceHistoryState": "HISTORY_ON",
                "spaceThreadingState": "THREADED_MESSAGES",
                "spaceType": "SPACE",
                "spaceUri": "https://chat.google.com/room/AAAAAAAAAA?cls=**",
                "type": "ROOM"
            },
            "text": "hi from the test",
            "thread": {
                "name": "spaces/AAAAAAAAAA/threads/1"
            }
        }
    }
}
```

#### Human Readable Output

>### The Message that was sent:
>|Message Name|Sender Name|Sender Display Name|Sender Type|Space Display Name|Space Name|Space Type|Thread Name|
>|---|---|---|---|---|---|---|---|
>| spaces/AAAAAAAAAA/messages/11111111.11111111 | users/12345678 | mySpace | BOT | myNewProject | spaces/AAAAAAAAAA | ROOM | spaces/AAAAAAAAAA/threads/1 |

