This section describes how to receive and process interaction events for your Chat app.

- In the Google Cloud console, open the Google Chat API page [here](https://console.cloud.google.com/apis/api/chat.googleapis.com).
- Click the Configuration tab.
- In the Interactive features section, click the Enable interactive features toggle to the on position.
- In **Functionality**, select one or both of the following checkboxes:
    - Receive 1:1 messages: Lets users interact with your Chat app in direct messages (DM) spaces. Your Chat app receives interaction events any time a user sends a message in the DM space.
    - Join spaces and group conversations: Lets users add and remove your Chat app to spaces with more than one person. Your Chat app receives interaction events whenever it's added or removed from the space, and whenever users @mention or use a slash command in the space.
- In **Connection settings** click on App URL > and set the App URL as followed `<your-xsoar-url>/instance/execute/<name-of-your-integration-instance>`