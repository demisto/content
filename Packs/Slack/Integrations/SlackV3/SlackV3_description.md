## Configuring Slack V3
Slack V3 utilizes "Socket Mode" to enable the integration to communicate directly with Slack for mirroring. This requires a dedicated Slack app to be created for the XSOAR integration.
 
 ### Creating a Custom App
 1. Navigate to the following [link](https://api.slack.com/apps/).
 2. Click **Create an App**.
 3. Click **From scratch**.
 4. Enter an *App Name* and select the workspace in which your app will reside.
 5. Click **Create App**. 
 6. Click **Socket Mode** found on the left-hand side of the menu. 
 7. Click **Enable Socket Mode**. This will create an app level token with the required scope for connecting. 
 8. Enter a name for the token.
 9. Click **Generate**.
 
 You will receive a token starting with `xapp`. Copy this token and use it for the `app_token` parameter when creating an instance of the integration.
 
 ### Defining Events
 For Slack V3 to be able to mirror incidents, you must enable the Events feature. 
 1. Navigate to *Event Subscriptions* found under the Features menu. 
 2. Enable Events by clicking the toggle switch.
 
 Enabling the Events API will present various events that the app may subscribe to. Currently, Slack V3 only uses the following message events:
 
 | Event Name | What it's used for |
 | --- | --- |
 | `message.channel` | Allows the app to receive messages which were posted in a channel. Used for Mirror In. |
 | `message.mpim` | Allows the app to receive messages which were posted to a group. Used for Mirror In. |
 | `message.groups` | Allows the app to receive messages which were posted to a private channel. Used for Mirror In. |
 | `message.im` | Allows the app to receive direct messages. |
 
 These message events are available for both "Bot Events" and "Events on behalf of users". In order to use mirroring and handle bot questions, Cortex XSOAR recommends enabling these event scopes for both bot and user events.
 
 ### OAuth Scopes
 
 In order to utilize the full functionality of the Slack integration, Cortex XSOAR recommends the following OAuth scopes for the bot token:

| OAuth Scope | Description |
| --- | --- |
| `channels:history` | View messages and other content in public channels that the app has been added to. |
| `channels:read` | View basic information about public channels in a workspace. |
| `chat:write` | Send messages as the bot. |
| `files:write` | Upload, edit, and delete files as the bot. |
| `groups:history` | View messages and other content in private channels that the bot has been added to. |
| `groups:read` | View basic information about private channels that the bot has been added to. |
| `groups:write` | Manage private channels that the bot has been added to and create new ones. |
| `im:history` | View messages and other content in direct messages that the bot has been added to. |
| `im:read` | View basic information about direct messages that the bot has been added to. |
| `im:write` | Start direct messages with people. |
| `mpim:history` | View messages and other content in group direct messages that the bot has been added to. |
| `mpim:read` | View basic information about group direct messages that the bot has been added to. |
| `mpim:write` | Start group direct messages with people. |
| `users:read` | View people in a workspace. |

The app token requires the `connections:write` scope in order to open the socket connection and is required for the Events and Questions functionality. It's important to note that when configuring Socket Mode, this scope will automatically be created for you.

## Backwards Compatibility with Slack V2
Slack V3 currently contains improvements to enhance the stability of the integration as well as the circumvention of OProxy. This version is intended to provide customers with more granular control over the Slack integration by enabling the Bring-Your-Own-App model and customizable scope-based authentication.

All commands are fully compatible with Slack V2 playbooks as their inputs and outputs have remained the same. As a customer, you should notice no significant change in the behavior of the Slack integration with your existing playbooks.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.