<p>Microsoft Graph allows Demisto authorized access to a user's Outlook mail data in a personal or organization account. This integration was tested with version 1.0 of Microsoft Graph Mail Single User.</p>
<h2>Use Cases</h2>
<ul>
<li>Monitor a specific email account and create incidents from incoming emails to the defined folder.</li>
<li>Send and reply to emails.</li>
</ul>

<h2>Fetch Incidents</h2>
<p>The integration imports email messages from the destination folder in the target mailbox as incidents. If the message contains any attachments, they are uploaded to the War Room as files. If the attachment is an email (item attachment), Demisto fetches information about the attached email and downloads all of its attachments (if there are any) as files. To use Fetch incidents, configure a new instance and select the Fetches incidents option in the instance settings.</p>

<h2>Authentication</h2>
For more details about the authentication used in this integration, see <a href="https://xsoar.pan.dev/docs/reference/articles/microsoft-integrations---authentication">Microsoft Integrations - Authentication</a>.

<h3>Required Permissions</h3>
The following permissions are required for all commands:
<ul>
 <li>Mail.ReadWrite - Delegated</li>
 <li>Mail.Send - Delegated</li>
 <li>User.Read - Delegated</li>
</ul>
<h2>Configure Microsoft Graph Mail Single User on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Microsoft Graph Mail Single User.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>ID or Client ID - see Detailed Instructions (?)</strong></li>
   <li><strong>Token or Tenant ID - see Detailed Instructions (?)</strong></li>
   <li><strong>Key or Client Secret - see Detailed Instructions (?)</strong></li>
   <li><strong>Authorization code (required for self-deployed Azure app)</strong></li>
   <li><strong>Application redirect URI (required for self-deployed Azure app)</strong></li>
   <li><strong>Fetch incidents</strong></li>
   <li><strong>Email address from which to fetch incidents  (e.g. "example@demisto.com")</strong></li>
   <li><strong>Name of the folder from which to fetch incidents (supports Folder ID and sub-folders e.g. Inbox/Phishing)</strong></li>
   <li><strong>First fetch timestamp (<number> <time unit>, e.g., 12 hours, 7 days)</strong></li>
   <li><strong>Maximum number of emails to pull per fetch.</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
    </ul>
  </li>
  <li>
    Run&nbsp;<strong>!msgraph-mail-test</strong>&nbsp;command in CLI(instead of test button) to validate the new instance.
  </li>
</ol>

<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#msgraph-mail-create-draft" target="_self">Creates a draft message in a user's mailbox: msgraph-mail-create-draft</a></li>
  <li><a href="#send-mail" target="_self">Sends an email using Microsoft Graph: send-mail</a></li>
  <li><a href="#msgraph-mail-reply-to" target="_self">The replies to the recipients of a message: msgraph-mail-reply-to</a></li>
  <li><a href="#msgraph-mail-send-draft" target="_self">Sends a draft email using Microsoft Graph: msgraph-mail-send-draft</a></li>
  <li><a href="#msgraph-mail-test" target="_self">Tests connectivity of the email: msgraph-mail-test</a></li>
</ol>
<h3 id="msgraph-mail-create-draft">1. msgraph-mail-create-draft</h3>
<hr>
<p>Creates a draft message in a user's mailbox.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-mail-create-draft</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mail.ReadWrite</li>
    <li>Mail.Send</li>
    <li>User.Read</li>
</ul>
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
      <td>to</td>
      <td>A comma separated list of email addresses for the 'to' field.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>cc</td>
      <td>A comma separated list of email addresses for the 'cc' field.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>bcc</td>
      <td>A comma separated list of email addresses for the 'bcc' field.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subject</td>
      <td>The subject for the draft.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>body</td>
      <td>The contents (body) of the draft.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>body_type</td>
      <td>The body type of the email. Can be: "text", or "HTML".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>flag</td>
      <td>The flag value that indicates the status for the draft. Can be: "notFlagged", "complete", or "flagged".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>importance</td>
      <td>The importance of the draft. Can be: "Low", "Normal", or "High".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>headers</td>
      <td>A comma separated list of additional headers in the format, headerName:headerValue. For example, "headerName1:headerValue1,headerName2:headerValue2".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attach_ids</td>
      <td>A comma separated list of War Room entry IDs that contain files, which are used to attach files to the draft. For example, attachIDs=15@8,19@8.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attach_names</td>
      <td>A comma separated list of names of attachments to be displayed in the draft. Must be the same number of elements as attachIDs.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attach_cids</td>
      <td>A comma separated list of CIDs to embed attachments within the email itself.</td>
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
      <td>MicrosoftGraph.Draft.Cc</td>
      <td>String</td>
      <td>Cc of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.IsRead</td>
      <td>String</td>
      <td>Is read status of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.Bcc</td>
      <td>String</td>
      <td>The Bcc of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.Body</td>
      <td>String</td>
      <td>The body of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.MessageID</td>
      <td>String</td>
      <td>The message id of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.SentTime</td>
      <td>Date</td>
      <td>The created time of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.Headers</td>
      <td>String</td>
      <td>The headers of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.From</td>
      <td>String</td>
      <td>The from of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.Subject</td>
      <td>String</td>
      <td>The subject of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.ReceivedTime</td>
      <td>String</td>
      <td>The received time of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.Importance</td>
      <td>String</td>
      <td>The importance status of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.CreatedTime</td>
      <td>String</td>
      <td>The created time of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.Sender</td>
      <td>String</td>
      <td>The sender of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.ModifiedTime</td>
      <td>Date</td>
      <td>The modified time of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.IsDraft</td>
      <td>Boolean</td>
      <td>Indicates whether it is a draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.ID</td>
      <td>String</td>
      <td>The ID of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.To</td>
      <td>String</td>
      <td>The to recipients of the draft.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.BodyType</td>
      <td>Unknown</td>
      <td>The body type of the draft email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Draft.ConversationID</td>
      <td>String</td>
      <td>The conversation ID of the draft email.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-mail-create-draft subject="Test Subject" flag=flagged importance=Normal to=test@demistodev.onmicrosoft.com</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "MicrosoftGraph.Draft": {
        "Bcc": [],
        "Body": "",
        "BodyType": "text",
        "Cc": [],
        "ConversationID": "conversation_id",
        "CreatedTime": "2019-12-01T08:25:34Z",
        "From": "",
        "Headers": [],
        "ID": "unique_id",
        "Importance": "normal",
        "IsDraft": true,
        "IsRead": true,
        "MessageID": "<message_id>",
        "ModifiedTime": "2019-12-01T08:25:34Z",
        "ReceivedTime": "2019-12-01T08:25:34Z",
        "Sender": "",
        "SentTime": "2019-12-01T08:25:34Z",
        "Subject": "Test Subject",
        "To": [
            "test@demistodev.onmicrosoft.com"
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Created draft with id: unique_id</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Bcc</strong></th>
      <th><strong>Body</strong></th>
      <th><strong>BodyType</strong></th>
      <th><strong>Cc</strong></th>
      <th><strong>ConversationID</strong></th>
      <th><strong>CreatedTime</strong></th>
      <th><strong>From</strong></th>
      <th><strong>Headers</strong></th>
      <th><strong>ID</strong></th>
      <th><strong>Importance</strong></th>
      <th><strong>IsDraft</strong></th>
      <th><strong>IsRead</strong></th>
      <th><strong>MessageID</strong></th>
      <th><strong>ModifiedTime</strong></th>
      <th><strong>ReceivedTime</strong></th>
      <th><strong>Sender</strong></th>
      <th><strong>SentTime</strong></th>
      <th><strong>Subject</strong></th>
      <th><strong>To</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>  </td>
      <td>  </td>
      <td> text </td>
      <td>  </td>
      <td> convesation_id </td>
      <td> 2019-12-01T08:25:34Z </td>
      <td>  </td>
      <td>  </td>
      <td> unique_id </td>
      <td> normal </td>
      <td> true </td>
      <td> true </td>
      <td> <message_id> </td>
      <td> 2019-12-01T08:25:34Z </td>
      <td> 2019-12-01T08:25:34Z </td>
      <td>  </td>
      <td> 2019-12-01T08:25:34Z </td>
      <td> Test Subject </td>
      <td> test@demistodev.onmicrosoft.com </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="send-mail">2. send-mail</h3>
<hr>
<p>Sends an email using Microsoft Graph.</p>
<h5>Base Command</h5>
<p>
  <code>send-mail</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mail.ReadWrite</li>
    <li>Mail.Send</li>
    <li>User.Read</li>
</ul>
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
      <td>to</td>
      <td>A comma separated list of email addresses for the 'to' field.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>cc</td>
      <td>A comma separated list of email addresses for the 'cc' field.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>bcc</td>
      <td>A comma separated list of email addresses for the 'bcc' field.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subject</td>
      <td>The subject of the email.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>body</td>
      <td>The contents (body) of the email.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>body_type</td>
      <td>The body type of the email. Can be: "text", or "HTML".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>flag</td>
      <td>The flag value that indicates the status for the email. Can be: "notFlagged", "complete", or "flagged".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>importance</td>
      <td>The importance of the email. Can be: "Low", "Normal", or "High".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>headers</td>
      <td>A comma separated list of additional headers in the format: headerName:headerValue. For example: "headerName1:headerValue1,headerName2:headerValue2".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attach_ids</td>
      <td>A comma separated list of War Room entry IDs that contain files, which are used to attach files for the email to send. For example, attachIDs=15@8,19@8.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attach_names</td>
      <td>A comma separated list of names of attachments to be displayed in the email to send. Must be the same number of elements as attachIDs.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attach_cids</td>
      <td>A comma separated list of CIDs to embed attachments within the email.</td>
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
      <td>MicrosoftGraph.Email.internetMessageHeaders</td>
      <td>String</td>
      <td>The email headers.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.body</td>
      <td>String</td>
      <td>The body of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.bodyPreview</td>
      <td>String</td>
      <td>The body preview of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.subject</td>
      <td>String</td>
      <td>The subject of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.flag</td>
      <td>String</td>
      <td>The flag status of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.importance</td>
      <td>String</td>
      <td>The importance status of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.toRecipients</td>
      <td>String</td>
      <td>The to recipients of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.ccRecipients</td>
      <td>String</td>
      <td>The cc recipients of the email.</td>
    </tr>
    <tr>
      <td>MicrosoftGraph.Email.bccRecipients</td>
      <td>String</td>
      <td>The bcc recipients of the email.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!send-mail subject="Test Subject" flag=flagged importance=Normal to=test@demistodev.onmicrosoft.com body_type=HTML attach_ids=attach_id attach_cids=attach_cid attach_names=a1.rtf body="&lt;h1&gt;Added inline&lt;/h1&gt; &lt;img src=\"cid:a2.png\" height=\"50\" width=\"50\"&gt; &lt;h1&gt;End&lt;/h1&gt;" headers="x-custom:testheader"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "MicrosoftGraph.Email": {
        "bccRecipients": [],
        "body": {
            "content": "html_body",
            "contentType": "HTML"
        },
        "bodyPreview": "body_preview",
        "ccRecipients": [],
        "flag": {
            "flagStatus": "flagged"
        },
        "importance": "Normal",
        "internetMessageHeaders": [
            {
                "name": "x-custom",
                "value": "testheader"
            }
        ],
        "subject": "Test Subject",
        "toRecipients": [
            {
                "emailAddress": {
                    "address": "test@demistodev.onmicrosoft.com"
                }
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Email was sent successfully.</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>bccRecipients</strong></th>
      <th><strong>body</strong></th>
      <th><strong>bodyPreview</strong></th>
      <th><strong>ccRecipients</strong></th>
      <th><strong>flag</strong></th>
      <th><strong>importance</strong></th>
      <th><strong>internetMessageHeaders</strong></th>
      <th><strong>subject</strong></th>
      <th><strong>toRecipients</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>  </td>
      <td> content: <h1>Added inline</h1><br>contentType: HTML </td>
      <td> <h1>Added inline</h1></td>
      <td>  </td>
      <td> flagStatus: flagged </td>
      <td> Normal </td>
      <td> {'name': 'x-custom', 'value': 'testheader'} </td>
      <td> Test Subject </td>
      <td> {'emailAddress': {'address': 'test@demistodev.onmicrosoft.com'}} </td>
    </tr>
  </tbody>
</table>

<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="msgraph-mail-reply-to">3. msgraph-mail-reply-to</h3>
<hr>
<p>The replies to the recipients of a message.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-mail-reply-to</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mail.ReadWrite</li>
    <li>Mail.Send</li>
    <li>User.Read</li>
</ul>
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
      <td>message_id</td>
      <td>The ID of the message.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>The comment of the replied message.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>to</td>
      <td>A comma separated list of email addresses for the 'to' field.</td>
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
  <code>!msgraph-mail-reply-to message_id=message_id comment="Reply message" to=test@demistodev.onmicrosoft.com</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>Replied to: test@demistodev.onmicrosoft.com with comment: Reply message</h3>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="msgraph-mail-send-draft">4. msgraph-mail-send-draft</h3>
<hr>
<p>Sends a draft email using Microsoft Graph.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-mail-send-draft</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mail.ReadWrite</li>
    <li>Mail.Send</li>
    <li>User.Read</li>
</ul>
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
      <td>draft_id</td>
      <td>The ID of the draft email.</td>
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
  <code>!msgraph-mail-send-draft draft_id=message_id</code>
</p>

<h5>Human Readable Output</h5>
<p>
<h3>Draft with: message_id id was sent successfully.</h3>
<!-- remove the following comments to manually add an image: -->
<!--
<a href="insert URL to your image" target="_blank" rel="noopener noreferrer"><img src="insert URL to your image"
 alt="image" width="749" height="412"></a>
 -->
</p>

<h3 id="msgraph-mail-test">5. msgraph-mail-test</h3>
<hr>
<p>Tests connectivity of the email.</p>
<h5>Base Command</h5>
<p>
  <code>msgraph-mail-test</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mail.ReadWrite</li>
    <li>Mail.Send</li>
    <li>User.Read</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!msgraph-mail-test</code>
</p>

<h5>Human Readable Output</h5>
<p>
✅ Success!
</p>