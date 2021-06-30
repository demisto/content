## Configuring Slack V3
Slack V3 utilizes "Socket Mode" to enable the integration to communicate directly with Slack for mirroring. This will require a dedicated Slack app to be created for the XSOAR integration.
 
 ### Creating a Custom App
 In order to create a custom app, first navigate to the following [link](https://api.slack.com/apps/) and click "Create New App".
 Next click "From Scratch" and enter an *App Name*, select the workspace your app will reside and lastly click "Create App". 
 
 Afterwards, click "Socket Mode" found on the left-hand side of the menu. Then click "Enable Socket Mode". This will create an app level token with the required scope for connecting. A *Token Name* is required, lastly, click "Generate".
 
 You will be given a token starting with `xapp`. Please copy this token and apply it to the `app_token` parameter.
 
 ### Defining Events
 For Slack V3 to be able to mirror incidents, we must enable the Events feature. To do so, please navigate to "Event Subscriptions" found under the Features menu. Enable Events by clicking the toggle switch.
 
 Enabling the Events API will present various events which the app may subscribe to. Currently, Slack V3 only requires the following scopes:
 
 | Event Name | What it's used for |
 | --- | --- |
 | `message.channel` | Allows the App to recieve messages which were posted in a channel. Used for Mirror In |
 | `message.mpim` | Allows the App to recieve messages which were posted to a group. Used for Mirror In |
 | `message.groups` | Allows the App to recieve messages which were posted to a private channel. Used for Mirror In |
 | `message.im` | Allows the App to recieve Direct Messages |
 
 These permissions are available for both "Bot Events" and "Events on behalf of users". In order to use mirroring and handle bot questions, we recommend enabling these event scopes for both bot and user events.
 
 ### OAuth Scopes
 
 In order to utilize the full functionality of the Slack integration, we recommend the following OAuth scopes for the Bot token:

| OAuth Scope | Description |
| --- | --- |
| `channels:history` | View messages and other content in public channels that the app has been added to |
| `channels:read` | View basic information about public channels in a workspace |
| `chat:write` | Send messages as the bot |
| `files:write` | Upload, edit, and delete files as the bot |
| `groups:history` | View messages and other content in private channels that the bot has been added to |
| `groups:read` | View basic information about private channels that the bot has been added to |
| `im:history` | View messages and other content in direct messages that the bot has been added to |
| `im:read` | View basic information about direct messages that the bot has been added to |
| `mpim:history` | View messages and other content in group direct messages that the bot has been added to |
| `mpim:read` | View basic information about group direct messages that the bot has been added to |
| `users:read` | View people in a workspace |

The App token requires the `connections:write` scope in order to open the socket connection and is required for the Events and Questions functionality. It's important to note that when configuring Socket Mode, this scope will automatically be created for you.

## Backwards Compatibility with Slack V2
Slack V3 currently contains improvements to enhance the stability of the integration as well as the circumvention of OProxy. This version is intended to provide customers with more granular control over the Slack integration by enabling the Bring-Your-Own-App model and customizable scope based authentication.

All commands are fully compatible with Slack V2 playbooks as their inputs and outputs have remained the same. As a customer, you should notice no significant change in the behavior of the Slack integration with your existing playbooks.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
