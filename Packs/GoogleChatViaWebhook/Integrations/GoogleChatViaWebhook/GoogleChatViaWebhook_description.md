Use the Google Chat Webhook integration to send messages/notifications, as well as customizable cards, to Spaces configured with an incoming webhook. 

**Note**: When using the `!send-google-chat-custom-card` integration command, we highly recommend using the [UI Kit Builder](https://addons.gsuite.google.com/uikit/builder) provided by Google to properly format and copy the JSON blocks required for the _blocks_ argument.
​
## Create an Incoming Webhook on the Space in Google Chat.  
For information, see the [Build a Google Chat app as a webhook](https://developers.google.com/workspace/chat/quickstart/webhooks) Documentation
​
To create an instance of the Google Chat Webhook in Cortex XSOAR, complete the following steps below:
​
1. [Register the Google Chat Webhook](https://developers.google.com/workspace/chat/quickstart/webhooks#register_the_incoming_webhook) and copy the webhook URL per the instructions.

2. Add an instance of the integration and use the following webhook URL as an example to configure the integration parameters below:

**Example URL**: https://chat.googleapis.com/v1/spaces/`SPACE_ID`/messages?key=`KEY`&token=`TOKEN`

  - **Google Chat Space ID**: In your webhook URL, locate the value for the **SPACE_ID** placeholder displayed in the example URL and copy/paste this value into the **Google Chat Space ID** integration parameter.

- **Google Chat Space Key**: In your webhook URL, locate the value for the **KEY** placeholder displayed in the example URL and copy/paste this value into the **Google Chat Space Key** integration parameter.

- **Google Chat Space Token**: In your webhook URL, locate the value for the **TOKEN** placeholder displayed in the example URL and copy/paste this value into the **Google Chat Space Token_* integration parameter.

3. Test the integration. If successful, you'll see a test message in the space and a success message on the test screen.
​
For more information, see the [integration documentation]<PLACEHOLDER>
---
[View Integration Documentation]<PLACEHOLDER>