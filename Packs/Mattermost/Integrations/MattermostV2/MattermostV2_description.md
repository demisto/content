## To use the Mattermost integration:

1. Create a new bot to access Mattermost on behalf of a user, as described in the [instructions](https://developers.mattermost.com/integrate/reference/bot-accounts/):

* Go to **System Console** > **Integrations** > **Bot Accounts**.
* Set Enable Bot Account Creation to **true**.
* Once set, the system administrator can create bot accounts for integrations using the **Integrations** > **Bot Accounts** link in the description provided.

1. Under **Manage Members**, make it a System Admin.
2. Create a Personal Access Token for the new account [(Detailed Instruction)](https://developers.mattermost.com/integrate/reference/personal-access-token/)

### For sending messages using the ChatBot app and mirroring

To enable a direct communication with Mattermost for mirroring and sending messages by a Mattermost chatbot, make sure both the *Long running instance* and *Enable Incident Mirroring* parameters are checked.

## Sending notifications with Mattermost

To enable various notifications to be sent to Mattermost, make sure to select all of the relevant notification types in the *Types of Notifications to Send* parameter.