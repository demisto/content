<p>
  Sends a message (question) to either user (in a direct message) or to a channel. The message includes predefined reply options. The response can also close a task (might be conditional) in a playbook.
</p>
<h2>Use Case</h2>
<p>This automation allows you to ask users in Slack(including external to Cortex XSOAR) questions, have them respond and 
reflect the answer back to Cortex XSOAR.</p>
<h2>Prerequisites</h2>
<p>Requires an instance of the Slack v2 integration.</p>
<h3>Inputs</h3>
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
      <td>The Slack user to which to send the message. Can be either an email address or a Slack user name.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>channel</td>
      <td>The Slack channel to which to send the message.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>message</td>
      <td>The message to send to the user or channel.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>option1</td>
      <td>The first reply option. The default is "Yes" with a green button. To change the color of the button, add the pound sign (#) followed by the name of the new color (green, red, or black). The default color is "green". For example, "Yes#green".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>option2</td>
      <td>The second reply option. The default is "No" with a red button. To change the button color, add the pound sign (#) followed by the name of the new color (green, red, or black). The default color is "red". For example, "No#red".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>task</td>
      <td>The task number or task tag to close with the reply. If empty, then no playbook tasks will be closed. We recommend using a task tag, as task number might change between playbook (or sub-playbook) executions.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>replyEntriesTag</td>
      <td>Tag to add to email reply entries.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>responseType</td>
      <td>How the user should respond to the question. Default is "buttons".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>additionalOptions</td>
      <td>A comma-separated list of additional options in the format of "option#color", for example, "maybe#red". The default color is "black".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>reply</td>
      <td>The reply to send to the user. Use the templates {user} and {response} to incorporate these in the reply (i.e. "Thank you {user}. You have answered {response}."). Default is "Thank you for your response.".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>lifetime</td>
      <td>Time until the question expires. For example - 1 day. When it expires, a default response is sent.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>defaultResponse</td>
      <td>Default response in case the question expires. Default is "NoResponse".</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>
<h3>Guide</h3>
<span>
The automation is most useful in a playbook to determine the outcome of a conditional task - which will be one of the provided options.
It uses a mechanism that allows external users to respond in Cortex XSOAR(per investigation) with entitlement strings embedded within the message contents.
<img alt="" src="../../doc_files/66044107-7de39f00-e529-11e9-8099-049502b4d62f.png"/>
<br>
The automation can utilize the interactive capabilities of Slack to send a form with buttons - 
this requires the external endpoint for interactive responses to be available for connection (See the Slack v2 intergation documentation for more information).
You can also utilize threads instead, simply by specifying the <code>responseType</code> argument.

</span>

