<p>
  Sends a message (question) to a user through Slack to ask for feedback about a DLP incident. The message includes predefined reply options. The response can also close a task (might be conditional) in a playbook.
</p>
<h2>Use Case</h2>
<p>This automation allows you to ask users in Slack(including external to Cortex XSOAR) to give feedback on blocked uploads, have them respond and 
reflect the answer back to Cortex XSOAR.</p>
<h2>Prerequisites</h2>
<p>Requires an instance of the Slack v3 integration.</p>
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
      <td>file_name</td>
      <td>The name of the file that the user tried to upload.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>data_profile_name</td>
      <td>The name of the data profile that detected the violation.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>snippets</td>
      <td>The violation snippets.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>task</td>
      <td>The task number or task tag to close with the reply. If empty, then no playbook tasks will be closed. We recommend using a task tag, as task number might change between playbook (or sub-playbook) executions.</td>
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
<br>
The automation utilizes the interactive capabilities of Slack to send a form with buttons -
this requires the external endpoint for interactive responses to be available for connection (See the Slack v2 intergation documentation for more information).

</span>

