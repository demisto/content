<p>
  Send messages and notifications to your Slack Team.
  This integration was integrated and tested with version 4.0.1 of Slack, and is available from Demisto 5.0.
</p>
<h2>Use Cases</h2>
<ul>
<li>Mirror Demisto investigations War Room to Slack channels and vice-versa.</li>
<li>Send notifications, message and files from Demisto to Slack.</li>
<li>Get notifications in Slack about events in Demisto.</li>
<li>Manage Demisto incidents via direct messages to the Demisto bot.</li>
<li>Manage Slack channels (create, edit, invite, kick, close).</li>
</ul><h2>Detailed Description</h2>
<ul>
<li>To allow us access to Slack, the Demisto app has to be added to the relevant workspace. Do so by clicking on the following [link](https://oproxy.demisto.ninja/slack).</li>
<li> After adding the Demisto app, you will get an Access Token and Bot Token, which should be inserted in the integration instance configuration's corresponding fields.</li>
</ul>
<h2>Configure SlackV2 on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for SlackV2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
      <li><strong>Slack API access token</strong>: A token received by adding the application (Starts with xoxp).</li>
      <li><strong>Slack API bot token</strong>: A token received by adding the application (Starts with xoxb).</li>
      <li><strong>Dedicated Slack channel to receive notifications</strong></li>
      <li><strong>Send notifications about incidents to the dedicated channel</strong></li>
      <li><strong>Minimum incident severity to send messages to slack by</strong></li>
      <li><strong>Type of incidents created in Slack</strong></li>
      <li><strong>Allow external users to create incidents via DM</strong></li>
      <li><strong>Use system proxy settings</strong></li>
      <li><strong>Trust any certificate (not secure)</strong></li>
      <li><strong>Long running instance. Required for investigation mirroring and direct messages.</strong></li>
      <li><strong>Bot display name in Slack (Demisto Integration by default)</strong></li>
      <li><strong>Bot icon in Slack - Image URL (Demisto icon by default)</strong></li>
      <li><strong>Maximum time to wait for a rate limited call in seconds - 60 by default</strong></li>
      <li><strong>Number of objects to return in each paginated call - 200 by default</strong></li>
    </ul>
  </li>
</ol>
<ol start="4">
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>mirror-investigation: mirror-investigation</li>
  <li>send-notification: send-notification</li>
  <li>close-channel: close-channel</li>
  <li>slack-send-file: slack-send-file</li>
  <li>slack-set-channel-topic: slack-set-channel-topic</li>
  <li>slack-create-channel: slack-create-channel</li>
  <li>slack-invite-to-channel: slack-invite-to-channel</li>
  <li>slack-kick-from-channel: slack-kick-from-channel</li>
  <li>slack-rename-channel: slack-rename-channel</li>
  <li>slack-get-user-details: slack-get-user-details</li>
</ol>
<h3>1. mirror-investigation</h3>
<!-- <hr> -->
<p>Mirrors the investigation between Slack and the Demisto War Room.</p>
<h5>Base Command</h5>
<p>
  <code>mirror-investigation</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>type</td>
      <td>The mirroring type. Can be "all", which mirrors everything, "chat", which mirrors only chats (not commands), or "none", which stops all mirroring.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>autoclose</td>
      <td>Whether the channel is auto-closed when an investigation is closed. Can be "true" or "false". Default is "true".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>direction</td>
      <td>The mirroring direction. Can be "FromDemisto", "ToDemisto", or "Both". Default value is "Both".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>mirrorTo</td>
      <td>The channel type. Can be "channel" or "group". The default value is "group".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>channelName</td>
      <td>The name of the channel. The default is "incident-<incidentID>".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>channelTopic</td>
      <td>The topic of the channel.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>kickAdmin</td>
      <td>Whether to remove the Slack administrator (channel creator) from the mirrored channel.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mirror-investigation type=all autoclose=true direction=Both channelName=my-mirror channelTopic=my-incident</code>
</p>

<h5>Human Readable Output</h5>
<p>
Investigation mirrored successfully, channel: my-mirror
</p>

<h3>2. send-notification</h3>
<!-- <hr> -->
<p>Sends a message to a user, group, or channel.</p>
<h5>Base Command</h5>
<p>
  <code>send-notification</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>message</td>
      <td>The message content.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>to</td>
      <td>The user to whom to send the message. Can be either the username or email address.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>channel</td>
      <td>The name of the Slack channel to which to send the message.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>entry</td>
      <td>An entry ID to send as a link.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ignoreAddURL</td>
      <td>Whether to include a URL to the relevant component in Demisto. Can be "true" or "false". Default value is "false".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threadID</td>
      <td>The ID of the thread to which to reply - can be retrieved from a previous send-notification command.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>blocks</td>
      <td>A JSON string of Slack blocks to send in the message.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Slack.Thread.ID</td>
      <td>String</td>
      <td>b'The Slack thread ID.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!send-notification channel=general message="I love Demisto"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Slack.Thread": {
        "ID": "1567407432.000500"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Message sent to Slack successfully.
Thread ID is: 1567407432.000500
</p>
</p>

<h3>3. close-channel</h3>
<!-- <hr> -->
<p>Archives a Slack channel.</p>
<h5>Base Command</h5>
<p>
  <code>close-channel</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>channel</td>
      <td>The name of the channel to archive. If not provided, the mirrored investigation channel is archived (if the channel exists).</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!close-channel</code>
</p>

<h5>Human Readable Output</h5>
<p>
Channel successfully archived.
</p>

<h3>4. slack-send-file</h3>
<!-- <hr> -->
<p>Sends a file to a user, channel, or group. If not specified, the file is sent to the mirrored investigation channel (if the channel exists).</p>
<h5>Base Command</h5>
<p>
  <code>slack-send-file</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>file</td>
      <td>The ID of the file entry to send.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>to</td>
      <td>The user to whom to send the file. Can be the username or the email address.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>group</td>
      <td>The name of the Slack group (private channel) to which to send the file.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>channel</td>
      <td>The name of the Slack channel to which to send the file.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threadID</td>
      <td>The ID of the thread to which to reply - can be retrieved from a previous send-notification command.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>A comment to add to the file.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-send-file file=1@2 channel=general</code>
</p>

<h5>Human Readable Output</h5>
<p>
File sent to Slack successfully.
</p>

<h3>5. slack-set-channel-topic</h3>
<!-- <hr> -->
<p>Sets the topic for a channel.</p>
<h5>Base Command</h5>
<p>
  <code>slack-set-channel-topic</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>channel</td>
      <td>The channel name. If not specified, the topic of the mirrored investigation channel is set (if the channel exists).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>topic</td>
      <td>The topic for the channel.</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-set-channel-topic channel=general topic="Demisto rocks"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Topic successfully set.
</p>
</p>

<h3>6. slack-create-channel</h3>
<!-- <hr> -->
<p>Creates a channel in Slack.</p>
<h5>Base Command</h5>
<p>
  <code>slack-create-channel</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>type</td>
      <td>The channel type. Can be "private" or "public".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The name of the channel.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>users</td>
      <td>A CSV list of user names or email addresses to invite to the channel. For example: "user1, user2...".</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-create-channel name=my-channel topic=cool-topic type=private users=demisto_integration</code>
</p>

<h5>Human Readable Output</h5>
<p>
Successfully created the channel my-channel.
</p>

<h3>7. slack-invite-to-channel</h3>
<!-- <hr> -->
<p>Invites users to join a channel.</p>
<h5>Base Command</h5>
<p>
  <code>slack-invite-to-channel</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>users</td>
      <td>A CSV list of usernames or email addresses to invite to join the channel. For example: "user1, user2...".</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>channel</td>
      <td>The name of the channel to which to invite the users. If the name of the channel is not specified, the name of the mirrored investigation channel is used (if the channel exists).</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-invite-to-channel channel=my-channel users=cool-user</code>
</p>

<h5>Human Readable Output</h5>
<p>
Successfully invited users to the channel.
</p>

<h3>8. slack-kick-from-channel</h3>
<!-- <hr> -->
<p>Removes users from the specified channel.</p>
<h5>Base Command</h5>
<p>
  <code>slack-kick-from-channel</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>users</td>
      <td>A CSV list of usernames or email addresses to remove from the a channel. For example: "user1, user2..."</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>channel</td>
      <td>The name of the channel from which to remove the users. If the name of the channel is not specified, the mirrored investigation channel is used (if the channel exists).</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-kick-from-channel channel=my-channel users=cool-user</code>
</p>

<h5>Human Readable Output</h5>
<p>
Successfully kicked users from the channel.
</p>

<h3>9. slack-rename-channel</h3>
<!-- <hr> -->
<p>Renames a channel in Slack.</p>
<h5>Base Command</h5>
<p>
  <code>slack-rename-channel</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>name</td>
      <td>The new name of the channel.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>channel</td>
      <td>The current name of the channel. If the name of the channel is not specified, the mirrored investigation channel is used (if the channel exists).</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-rename-channel channel=my-channel name=your-channel</code>
</p>

<h5>Human Readable Output</h5>
<p>
Channel renamed successfully.
</p>

<h3>10. slack-get-user-details</h3>
<!-- <hr> -->
<p>Get details about a specified user.</p>
<h5>Base Command</h5>
<p>
  <code>slack-get-user-details</code>
</p>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>user</td>
      <td>The Slack user (username or email).</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Slack.User.ID</td>
      <td>String</td>
      <td>b'The ID of the user.'</td>
    </tr>
    <tr>
      <td>Slack.User.Username</td>
      <td>String</td>
      <td>b'The username of the user.'</td>
    </tr>
    <tr>
      <td>Slack.User.Name</td>
      <td>String</td>
      <td>b'The actual name of the user.'</td>
    </tr>
    <tr>
      <td>Slack.User.DisplayName</td>
      <td>String</td>
      <td>b'The display name of the user.'</td>
    </tr>
    <tr>
      <td>Slack.User.Email</td>
      <td>String</td>
      <td>b'The email address of the user.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!slack-get-user-details user="cool_user"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Slack.User": {
        "ID": "UXXXXXXXX",
        "Name": "Cool User",
        "Username": "cool_user",
        "Email": "cool_user@coolorg.com"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Details for Slack user: cool_user</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>ID</strong></th>
      <th><strong>Username</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Email</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>UXXXXXXXX</td>
      <td>cool_user</td>
      <td>Cool User</td>
      <td>cool_user@coolorg.com</td>
    </tr>
  </tbody>
</table>

</p>
<h2>Additional Information</h2>
<h3>Direct messages</h3>
<p>You may send direct messages to the Demisto app on Slack using the following commands:</p>
<pre>
list incidents [page x]
list my incidents [page x]
list my tasks
list closed incidents
new incident [details]
mirror incident-id
</pre>
<h3>Notifications</h3>
<p>The integration sends notifications according to the configured notification settings found in the user preferences page in Demisto, and additionally to the pre determined channel dedicated for incident notifications (according to the integration configuration).</p>
<h3>Blocks and interactve components</h3>
<span>The integration supports sending "blocks" to Slack. Blocks are a series of components that can be combined to create visually rich and compellingly interactive messages. In the integration, they can be sent as an array of JSON. More infortmation about that <a href="https://api.slack.com/reference/block-kit/blocks">here.</a> You can experiment with and build your own blocks <a href="https://api.slack.com/tools/block-kit-builder">here.</a>
The integration also allows some level of interactivity. When a user interacts with an element in a Slack message, Slack sends a request with the relevant information. 
This request is processed and stored by a dedicated endpoint outside of Demisto in the address: <code>https://oproxy.demisto.ninja</code>. What the integration currently allows is polling this endpoint for user interactions that contain entitlement strings(these are used to perform actions in Demisto by outside users, see the <code>SlackAsk</code> script for an example). What that means is that in order to enable interactivity using the integration, connection to this endpoint has to be enabled.</span>
<h4>Important! The interactions work only with the Demisto Integration bot - the only application that's allowed to send requests to the dedicated endpoint(for security reasons). They will not work with another application.</h4>
<h2>Known Limitations</h2>
<ul>
  <li>Due to limitations of the `aiohttp` library, only http proxies are supported.</li>
  <li>Channels are created by the Slack user who authorized the application. Thus, this user will be in every channel that the integration creates. You cannot kick this user, but they can leave.</li>
  <li>The integration can only manage channels that the application is a member of. Otherwise those channels will not be found.</li>
  <li>Currently, the integration does not support working without verifying SSL certificates. The parameter applies only to the endpoint for interactive responses.</li>
</ul>
<h2>Troubleshooting</h2>
<p>If messages are not mirrored in Demisto, or direct messages are not handled properly, check the integration status on the integration page:</p>
<img alt="" src="https://user-images.githubusercontent.com/35098543/66030151-6dbbc780-e509-11e9-9c21-c5c7ceb1f039.png"/>
<br>
<span>If you're having further issues, contact us at <a href="mailto:support@demisto.com">support@demisto.com</a> and attach the server logs.</span>
