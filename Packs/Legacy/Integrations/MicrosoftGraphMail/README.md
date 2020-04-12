<!-- HTML_DOC -->
<p>Microsoft Graph lets your app get authorized access to a user’s Outlook mail data in a personal or organization account.</p>
<h2>Generate Authentication Parameters</h2>
<p>To use this integration, you have to grant access to Demisto from Microsoft Graph.</p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Microsoft Graph Mail.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.</li>
<li>Click the question mark button in the upper-right corner and read the information, and click the link.</li>
<li>Click the <strong>Start Authorization Process</strong> button.</li>
<li>Log in with Microsoft admin user credentials.</li>
<li>Authorize Demisto application to access data.</li>
<li>When you are redirected, copy the parameter values, which you will need when configuring the integration instance in Demisto.
<ul>
<li>ID</li>
<li>Key</li>
<li>Token</li>
</ul>
</li>
</ol>
<h2>Configure Microsoft Graph Mail on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for MicrosoftGraphMail.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL</strong></li>
<li><strong>ID you received from the admin consent</strong></li>
<li><strong>Key you received from the admin consent</strong></li>
<li><strong>Token you received from the admin consent</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Required Permissions</h2>
<p>The following permissions are required for all commands:</p>
<ul>
<li>Mail.ReadWrite</li>
<li>Directory.Read.All</li>
<li>User.Read</li>
</ul>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_cd3b24a2-22a0-4dbb-8a05-3fbd4dadff3c" target="_self">Get a list of emails for a user: msgraph-mail-list-emails</a></li>
<li><a href="#h_c981218c-d172-46f7-a603-d48e96011101" target="_self">Get email information: msgraph-mail-get-email</a></li>
<li><a href="#h_adfe17ce-1ced-48f9-b4c0-a2d32d0abc88" target="_self">Delete an email: msgraph-mail-delete-email</a></li>
<li><a href="#h_d26f8111-bd58-4fe1-a6fb-7baaf90edbc4" target="_self">Get a list of email attachments: msgraph-mail-list-attachments</a></li>
<li><a href="#h_03de5e7a-ffb1-4200-bc54-9921ac59aaba" target="_self">Get an email attachment: msgraph-mail-get-attachment</a></li>
</ol>
<h3 id="h_cd3b24a2-22a0-4dbb-8a05-3fbd4dadff3c">1. Get email properties</h3>
<p>Gets a list of emails for a user.</p>
<h5>Base Command</h5>
<p><code>msgraph-mail-list-emails</code></p>
<h5>Required Permissions</h5>
<p>This command requires the following permissions.</p>
<ul>
<li>Mail.ReadWrite</li>
<li>Directory.Read.All</li>
<li>User.Read</li>
</ul>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 160px;"><strong>Argument Name</strong></th>
<th style="width: 509px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">user_id</td>
<td style="width: 509px;">User ID from which to pull mails (can be principal ID (email address)).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">folder_id</td>
<td style="width: 509px;">A CSV list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160px;">odata</td>
<td style="width: 509px;">Add an OData query. For example:<br> odata=`?$filter=contains(Subject,'Test') and from/emailAddress/address eq 'user@example.com'</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160px;">search</td>
<td style="width: 509px;">The term for which to search. This argument cannot contain reserved characters such as: !, $, #, @, etc.<br> For further information, see https://tools.ietf.org/html/rfc3986#section-2.2</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160px;">pages_to_pull</td>
<td style="width: 509px;">The number of pages of emails to pull (maximum is 10 emails per page).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 375px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">MSGraphMail.ID</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">ID of the email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Created</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time the email was created.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.LastModifiedTime</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time the email was last modified.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.ReceivedTime</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time the email was received.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.SendTime</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time of sending email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Categories</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Categories of email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.HasAttachments</td>
<td style="width: 61px;">Boolean</td>
<td style="width: 375px;">Whether there are any email attachments.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Subject</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Subject of the email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.IsDraft</td>
<td style="width: 61px;">Boolean</td>
<td style="width: 375px;">Whether the email is a draft.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Body</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Body of the email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Sender.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Name of the sender.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Sender.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email address of the sender.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.From.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Name of the "from" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.From.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email address of the "from" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.CCRecipients.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Names of recipients of the CC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.CCRecipients.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email addresses of recipients of the CC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.BCCRecipients.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Names of recipients of the BCC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.BCCRecipients.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email addresses of recipients of the BCC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.ReplyTo.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Name of the "reply to" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.ReplyTo.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email address of the "reply to" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.UserID</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">ID of the user.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>msgraph-mail-list-emails user_id=ex@example.com</pre>
<h5>Context Example</h5>
<pre>  { "MSGraphMail": [ { "CCRecipients": null, "From": { "Name": "Oren Zohar", "Address":
              "ex@example.com" }, "Sender": { "Name": "Oren Zohar", "Address": "ex@example.com"
              }, "Created": "2019-04-24T13:58:22Z", "HasAttachments": false, "ReceivedTime":
              "2019-04-24T13:58:23Z", "UserID": "or@example.com", "IsDraft": false, "ReplyTo":
              null, "BCCRecipients": null, "LastModifiedTime": "2019-04-24T13:58:24Z", "Subject":
              "jn", "ID": "AAMkADMzZWNjMjBNFPVsAqlO3YRKNFAAAF0dZUAAA=", "Categories": [], "SendTime":
              "2019-04-24T13:58:22Z" }, { "CCRecipients": null, "From": { "Name": "Oren Zohar",
              "Address": "ex@example.com" }, "Sender": { "Name": "Oren Zohar", "Address": "ex@example.com"
              }, "Created": "2019-04-24T13:57:05Z", "HasAttachments": false, "ReceivedTime":
              "2019-04-24T13:57:06Z", "UserID": "ex@example.com", "IsDraft": false, "ReplyTo":
              null, "BCCRecipients": null, "LastModifiedTime": "2019-04-24T13:57:07Z", "Subject":
              "this is test 2", "ID": "AAMkADMzoON8u7AAAF0dZTAAA=", "Categories": [], "SendTime":
              "2019-04-24T13:57:06Z" }, { "CCRecipients": null, "From": { "Name": "Oren Zohar",
              "Address": "ex@example.com" }, "Sender": { "Name": "Oren Zohar", "Address": "ex@example.com"
              }, "Created": "2019-04-24T13:54:50Z", "HasAttachments": false, "ReceivedTime":
              "2019-04-24T13:55:21Z", "UserID": "ex@example.com", "IsDraft": false, "ReplyTo":
              null, "BCCRecipients": null, "LastModifiedTime": "2019-04-24T13:55:22Z", "Subject":
              "this is a test", "ID": "AAMkADMzZ8u7AAAF0dZSAAA=", "Categories": [], "SendTime":
              "2019-04-24T13:55:20Z" }, { "CCRecipients": null, "From": { "Name": "Oren Zohar",
              "Address": "ex@example.com" }, "Sender": { "Name": "Oren Zohar", "Address": "ex@example.com"
              }, "Created": "2019-04-24T13:47:57Z", "HasAttachments": false, "ReceivedTime":
              "2019-04-24T13:47:57Z", "UserID": "ex@example.com", "IsDraft": false, "ReplyTo":
              null, "BCCRecipients": null, "LastModifiedTime": "2019-04-24T13:47:58Z", "Subject":
              "dasdas", "ID": "AAMkADMzZWu7AAAF0Z_AAAA=", "Categories": [], "SendTime": "2019-04-24T13:47:56Z"
              }, { "CCRecipients": null, "From": { "Name": "Oren Zohar", "Address": "ex@example.com"
              }, "Sender": { "Name": "Oren Zohar", "Address": "ex@example.com" }, "Created":
              "2019-04-24T13:47:56Z", "HasAttachments": false, "ReceivedTime": "2019-04-24T13:47:57Z",
              "UserID": "ex@example.com", "IsDraft": false, "ReplyTo": null, "BCCRecipients":
              null, "LastModifiedTime": "2019-04-24T13:47:58Z", "Subject": "dasdas", "ID":
              "AAMkADMzZWNj3YRKNF6ZoON8u7AAAF0dZRAAA=", "Categories": [], "SendTime": "2019-04-24T13:47:56Z"
              }, { "CCRecipients": null, "From": { "Name": "Bar Hochman", "Address": "se@example.com"
              }, "Sender": { "Name": "Bar Hochman", "Address": "se@example.com" }, "Created":
              "2019-04-24T06:42:01Z", "HasAttachments": true, "ReceivedTime": "2019-04-24T06:42:02Z",
              "UserID": "ex@example.com", "IsDraft": false, "ReplyTo": null, "BCCRecipients":
              null, "LastModifiedTime": "2019-04-24T06:48:35Z", "Subject": "\u05e7\u05d1\u05dc
              \u05e7\u05d5\u05d1\u05e5 \u05e8\u05e0\u05d3\u05d5\u05de\u05d0\u05dc\u05d9", "ID":
              "AAMkADMzZWNjMjiMgBGAAAAAAC7AAAF0Z9-AAA=", "Categories": [], "SendTime": "2019-04-24T06:41:56Z"
              } ] }
            </pre>
<h5>Human Readable Output</h5>
<h3>### Total of 6 of mails received</h3>
<table style="width: 748px;">
<tbody>
<tr>
<th style="width: 158px;"><strong>Subject</strong></th>
<th style="width: 511px;"><strong>From</strong></th>
<th style="width: 71px;"><strong>SendTime</strong></th>
</tr>
<tr>
<td style="width: 158px;">jn</td>
<td style="width: 511px;">Name: Or Zoh<br> Address: ex@example.com</td>
<td style="width: 71px;">2019-04-24T13:58:22Z</td>
</tr>
<tr>
<td style="width: 158px;">this is test 2</td>
<td style="width: 511px;">Name: Or Zoh<br> Address: ex@example.com</td>
<td style="width: 71px;">2019-04-24T13:57:06Z</td>
</tr>
<tr>
<td style="width: 158px;">this is a test</td>
<td style="width: 511px;">Name: Or Zohr<br> Address: ex@example.com</td>
<td style="width: 71px;">2019-04-24T13:55:20Z</td>
</tr>
<tr>
<td style="width: 158px;">dasdas</td>
<td style="width: 511px;">Name: Or Zoh<br> Address: ex@example.com</td>
<td style="width: 71px;">2019-04-24T13:47:56Z</td>
</tr>
<tr>
<td style="width: 158px;">dasdas </td>
<td style="width: 511px;">Name: Or Zoh<br> Address: ex@example.com</td>
<td style="width: 71px;">2019-04-24T13:47:56Z</td>
</tr>
<tr>
<td style="width: 158px;">Get a random file </td>
<td style="width: 511px;">Name: Ba Hoc<br> Address: se@example.com</td>
<td style="width: 71px;">2019-04-24T06:41:56Z</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_c981218c-d172-46f7-a603-d48e96011101">2. Get email information</h3>
<p>Gets the properties of an email.</p>
<h5>Base Command</h5>
<p><code>msgraph-mail-get-email</code></p>
<h5>Required Permissions</h5>
<p>This command requires the following permissions.</p>
<ul>
<li>Mail.ReadWrite</li>
<li>Directory.Read.All</li>
<li>User.Read</li>
</ul>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 160px;"><strong>Argument Name</strong></th>
<th style="width: 509px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">user_id</td>
<td style="width: 509px;">User ID or principal ID (mostly email address).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">message_id</td>
<td style="width: 509px;">Message ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">folder_id</td>
<td style="width: 509px;">A CSV list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160px;">odata</td>
<td style="width: 509px;">OData. Fore more information about the OData parameter and how to build OData, see the <a href="https://docs.microsoft.com/he-il/graph/query-parameters" target="_blank" rel="noopener">Microsoft documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 160px;">get_body</td>
<td style="width: 509px;">Whether the message body should be returned.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 375px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">MSGraphMail.ID</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">ID of the email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Created</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time the email was created.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.LastModifiedTime</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time the email was last modified.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.ReceivedTime</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time the email was received.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.SendTime</td>
<td style="width: 61px;">Date</td>
<td style="width: 375px;">Time of sending email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Categories</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Categories of email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.HasAttachments</td>
<td style="width: 61px;">Boolean</td>
<td style="width: 375px;">Whether there are any email attachments.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Subject</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Subject of the email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.IsDraft</td>
<td style="width: 61px;">Boolean</td>
<td style="width: 375px;">Whether the email is a draft.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Body</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Body of the email.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Sender.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Name of the sender.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.Sender.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email address of the sender.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.From.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Name of the "from" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.From.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email address of the "from" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.CCRecipients.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Names of recipients of the CC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.CCRecipients.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email addresses of recipients of the CC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.BCCRecipients.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Names of recipients of the BCC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.BCCRecipients.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email addresses of recipients of the BCC field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.ReplyTo.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Name of the "reply to" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.ReplyTo.Address</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">Email address of the "reply to" field.</td>
</tr>
<tr>
<td style="width: 304px;">MSGraphMail.UserID</td>
<td style="width: 61px;">String</td>
<td style="width: 375px;">ID of the user.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !msgraph-mail-get-email message_id=AAMkADMzZWNjMgBGAAAAZoON8u7AAAF0Z9-AAA= user_id=ex@example.com
              get_body=true
            </pre>
<h5>Context Example</h5>
<pre>  <span id="s-1" class="sBrace structure-1">{  </span><br>   <span id="s-2" class="sObjectK">"MSGraphMail"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBrace structure-2">{  </span><br>      <span id="s-5" class="sObjectK">"Body"</span><span id="s-6" class="sColon">:</span><span id="s-7" class="sObjectV"><span class="error">"&lt;html&gt;\r\n&lt;head&gt;\r\n&lt;meta http-equiv=\"Content-Type\" <br>  content=\"text/html; charset=utf-8\"&gt;\r\n&lt;meta content=\"text/html; charset=utf-8\"&gt;\r\n&lt;meta <br>  name=\"Generator\" content=\"Microsoft Word 15 (filtered medium)\"&gt;\r\n&lt;style&gt;\r\n&lt;!--\r\n@font-face\r\n\t{font-family:\"Cambria <br>  Math\"}\r\n@font-face\r\n\t{font-family:Calibri}\r\np.MsoNormal, li.MsoNormal, <br>  div.MsoNormal\r\n\t{margin:0cm;\r\n\tmargin-bottom:.0001pt;\r\n\tfont-size:12.0pt;\r\n\tfont-family:\"Calibri\",sans-serif}\r\na:link, <br>  span.MsoHyperlink\r\n\t{color:#0563C1;\r\n\ttext-decoration:underline}\r\na:visited, <br>  span.MsoHyperlinkFollowed\r\n\t{color:#954F72;\r\n\ttext-decoration:underline}\r\nspan.EmailStyle17\r\n\t{font-family:\"Calibri\",sans-serif;\r\n\tcolor:windowtext}\r\n.MsoChpDefault\r\n\t{font-family:\"Calibri\",sans-serif}\r\n@page <br>  WordSection1\r\n\t{margin:72.0pt 72.0pt 72.0pt 72.0pt}\r\ndiv.WordSection1\r\n\t{}\r\n--&gt;\r\n&lt;/style&gt;\r\n&lt;/head&gt;\r\n&lt;body <br>  lang=\"EN-US\" link=\"#0563C1\" vlink=\"#954F72\"&gt;\r\n&lt;div class=\"WordSection1\"&gt;\r\n&lt;p <br>  class=\"MsoNormal\"&gt;&lt;span lang=\"HE\" dir=\"RTL\" style=\"font-size:11.0pt; <br>  font-family:&amp;quot;Arial&amp;quot;,sans-serif\"&gt;\u05d4\u05e0\u05d4 \u05e7\u05d5\u05d1\u05e5&lt;/span&gt;&lt;span <br>  style=\"font-size:11.0pt\"&gt;&lt;/span&gt;&lt;/p&gt;\r\n&lt;/div&gt;\r\n&lt;/body&gt;\r\n&lt;/html&gt;\r\n"</span></span><span id="s-8" class="sComma">,</span><br>      <span id="s-9" class="sObjectK">"CCRecipients"</span><span id="s-10" class="sColon">:</span><span id="s-11" class="sObjectV">null</span><span id="s-12" class="sComma">,</span><br>      <span id="s-13" class="sObjectK">"From"</span><span id="s-14" class="sColon">:</span><span id="s-15" class="sBrace structure-3">{  </span><br>         <span id="s-16" class="sObjectK">"Name"</span><span id="s-17" class="sColon">:</span><span id="s-18" class="sObjectV">"Bar Hochman"</span><span id="s-19" class="sComma">,</span><br>         <span id="s-20" class="sObjectK">"Address"</span><span id="s-21" class="sColon">:</span><span id="s-22" class="sObjectV">"se@example.com"</span><br>      <span id="s-23" class="sBrace structure-3">}</span><span id="s-24" class="sComma">,</span><br>      <span id="s-25" class="sObjectK">"Sender"</span><span id="s-26" class="sColon">:</span><span id="s-27" class="sBrace structure-3">{  </span><br>         <span id="s-28" class="sObjectK">"Name"</span><span id="s-29" class="sColon">:</span><span id="s-30" class="sObjectV">"Bar Hochman"</span><span id="s-31" class="sComma">,</span><br>         <span id="s-32" class="sObjectK">"Address"</span><span id="s-33" class="sColon">:</span><span id="s-34" class="sObjectV">"se@example.com"</span><br>      <span id="s-35" class="sBrace structure-3">}</span><span id="s-36" class="sComma">,</span><br>      <span id="s-37" class="sObjectK">"Created"</span><span id="s-38" class="sColon">:</span><span id="s-39" class="sObjectV">"2019-04-24T06:42:01Z"</span><span id="s-40" class="sComma">,</span><br>      <span id="s-41" class="sObjectK">"HasAttachments"</span><span id="s-42" class="sColon">:</span><span id="s-43" class="sObjectV">true</span><span id="s-44" class="sComma">,</span><br>      <span id="s-45" class="sObjectK">"ReceivedTime"</span><span id="s-46" class="sColon">:</span><span id="s-47" class="sObjectV">"2019-04-24T06:42:02Z"</span><span id="s-48" class="sComma">,</span><br>      <span id="s-49" class="sObjectK">"UserID"</span><span id="s-50" class="sColon">:</span><span id="s-51" class="sObjectV">"ex@example.com"</span><span id="s-52" class="sComma">,</span><br>      <span id="s-53" class="sObjectK">"IsDraft"</span><span id="s-54" class="sColon">:</span><span id="s-55" class="sObjectV">false</span><span id="s-56" class="sComma">,</span><br>      <span id="s-57" class="sObjectK">"ReplyTo"</span><span id="s-58" class="sColon">:</span><span id="s-59" class="sObjectV">null</span><span id="s-60" class="sComma">,</span><br>      <span id="s-61" class="sObjectK">"BCCRecipients"</span><span id="s-62" class="sColon">:</span><span id="s-63" class="sObjectV">null</span><span id="s-64" class="sComma">,</span><br>      <span id="s-65" class="sObjectK">"LastModifiedTime"</span><span id="s-66" class="sColon">:</span><span id="s-67" class="sObjectV">"2019-04-24T06:48:35Z"</span><span id="s-68" class="sComma">,</span><br>      <span id="s-69" class="sObjectK">"Subject"</span><span id="s-70" class="sColon">:</span><span id="s-71" class="sObjectV"><span class="error">"\u05e7\u05d1\u05dc <br>  \u05e7\u05d5\u05d1\u05e5 \u05e8\u05e0\u05d3\u05d5\u05de\u05d0\u05dc\u05d9"</span></span><span id="s-72" class="sComma">,</span><br>      <span id="s-73" class="sObjectK">"ID"</span><span id="s-74" class="sColon">:</span><span id="s-75" class="sObjectV">"AAMkADMzZWNjMjBkZoON8u7AAAF0Z9-AAA="</span><span id="s-76" class="sComma">,</span><br>      <span id="s-77" class="sObjectK">"Categories"</span><span id="s-78" class="sColon">:</span><span id="s-79" class="sBracket structure-3">[  </span><br><br>      <span id="s-80" class="sBracket structure-3">]</span><span id="s-81" class="sComma">,</span><br>      <span id="s-82" class="sObjectK">"SendTime"</span><span id="s-83" class="sColon">:</span><span id="s-84" class="sObjectV">"2019-04-24T06:41:56Z"</span><br>   <span id="s-85" class="sBrace structure-2">}</span><br><span id="s-86" class="sBrace structure-1">}</span>
            </pre>
<h5>Human Readable Output</h5>
<h3>Results for message ID AAMkADMzZCPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA=</h3>
<table style="width: 880px;">
<tbody>
<tr>
<th style="width: 160px;">ID</th>
<th style="width: 521px;">Subject</th>
<th style="width: 68px;">SendTime</th>
<th style="width: 62px;">Sender</th>
<th style="width: 66px;">From</th>
<th style="width: 70px;">HasAttachments</th>
<th style="width: 77px;">Body</th>
</tr>
<tr>
<td style="width: 160px;">AAMkADMzZWF0Z9-AAA=</td>
<td style="width: 521px;">Get a random file</td>
<td style="width: 68px;">2019-04-24T06:41:56Z</td>
<td style="width: 62px;">Name: Ba Hoch<br> Address: se@example.com</td>
<td style="width: 66px;">Name: Ba Hoch<br> Address: se@example.com</td>
<td style="width: 70px;">true</td>
<td style="width: 77px;">File goes here</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_adfe17ce-1ced-48f9-b4c0-a2d32d0abc88">3. Delete an email</h3>
<p>Deletes an email.</p>
<h5>Base Command</h5>
<p><code>msgraph-mail-delete-email</code></p>
<h5>Required Permissions</h5>
<p>This command requires the following permissions.</p>
<ul>
<li>Mail.ReadWrite</li>
<li>Directory.Read.All</li>
<li>User.Read</li>
</ul>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">user_id</td>
<td style="width: 501px;">User ID or principal ID (mostly email address).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">message_id</td>
<td style="width: 501px;">Message ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">folder_id</td>
<td style="width: 501px;">A CSV list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>  !msgraph-mail-delete-email user_id=ex@example.com message_id=4jn43h2%$@nf=
            </pre>
<h3 id="h_d26f8111-bd58-4fe1-a6fb-7baaf90edbc4">4. Get a list of email attachments</h3>
<p>Lists all of the attachments of given email</p>
<h5>Base Command</h5>
<p><code>msgraph-mail-list-attachments</code></p>
<h5>Required Permissions</h5>
<p>This command requires the following permissions.</p>
<ul>
<li>Mail.ReadWrite</li>
<li>Directory.Read.All</li>
<li>User.Read</li>
</ul>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">user_id</td>
<td style="width: 510px;">User ID or principal ID (mostly email address).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">message_id</td>
<td style="width: 510px;">Message ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">folder_id</td>
<td style="width: 510px;">A CSV list of folder IDs, in the format: (mail_box,child_mail_box,child_mail_box).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table>
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>MSGraphMailAttachment.ID</td>
<td>String</td>
<td>Email ID.</td>
</tr>
<tr>
<td>MSGraphMailAttachment.Attachment.ID</td>
<td>String</td>
<td>ID of the attachment.</td>
</tr>
<tr>
<td>MSGraphMailAttachment.Attachment.Name</td>
<td>String</td>
<td>Name of the attachment.</td>
</tr>
<tr>
<td>MSGraphMailAttachment.Attachment.Type</td>
<td>String</td>
<td>Type of the attachment.</td>
</tr>
<tr>
<td>MSGraphMailAttachment.UserID</td>
<td>String</td>
<td>ID of the user.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  msgraph-mail-list-attachments user_id=ex@example.com message_id=AAMkADMzZWNjMjBkLTE2PVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA=
            </pre>
<h5>Context Example</h5>
<pre>  <span id="s-1" class="sBrace structure-1">{  </span><br>   <span id="s-2" class="sObjectK">"MSGraphMailAttachment"</span><span id="s-3" class="sColon">:</span><span id="s-4" class="sBrace structure-2">{  </span><br>      <span id="s-5" class="sObjectK">"UserID"</span><span id="s-6" class="sColon">:</span><span id="s-7" class="sObjectV">"ex@example.com"</span><span id="s-8" class="sComma">,</span><br>      <span id="s-9" class="sObjectK">"Attachment"</span><span id="s-10" class="sColon">:</span><span id="s-11" class="sBracket structure-3">[  </span><br>         <span id="s-12" class="sBrace structure-4">{  </span><br>            <span id="s-13" class="sObjectK">"Type"</span><span id="s-14" class="sColon">:</span><span id="s-15" class="sObjectV">"image/png"</span><span id="s-16" class="sComma">,</span><br>            <span id="s-17" class="sObjectK">"ID"</span><span id="s-18" class="sColon">:</span><span id="s-19" class="sObjectV">"AAMkADMzZWNjMjBkLTE2ZGQqF1VbAHI="</span><span id="s-20" class="sComma">,</span><br>            <span id="s-21" class="sObjectK">"Name"</span><span id="s-22" class="sColon">:</span><span id="s-23" class="sObjectV">"download-1.png"</span><br>         <span id="s-24" class="sBrace structure-4">}</span><br>      <span id="s-25" class="sBracket structure-3">]</span><span id="s-26" class="sComma">,</span><br>      <span id="s-27" class="sObjectK">"ID"</span><span id="s-28" class="sColon">:</span><span id="s-29" class="sObjectV">"AAMkADMzZWNjMjBkLTE2ZGQtNDN8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA="</span><br>   <span id="s-30" class="sBrace structure-2">}</span><br><span id="s-31" class="sBrace structure-1">}</span>
            </pre>
<h5>Human Readable Output</h5>
<h3>Total of 1 attachments found in message AAMkADMzZWNjMjBkLTENF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA= from user <a href="mailto:ex@example.com">ex@example.com</a>
</h3>
<table border="2">
<thead>
<tr>
<th>File names</th>
</tr>
</thead>
<tbody>
<tr>
<td>download-1.png</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_03de5e7a-ffb1-4200-bc54-9921ac59aaba">5. Get an email attachment</h3>
<p>Gets an attachment from the email.</p>
<h5>Base Command</h5>
<p><code>msgraph-mail-get-attachment</code></p>
<h5>Required Permissions</h5>
<p>This command requires the following permissions.</p>
<ul>
<li>Mail.ReadWrite</li>
<li>Directory.Read.All</li>
<li>User.Read</li>
</ul>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 72px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">user_id</td>
<td style="width: 521px;">User ID or principal ID (mostly email address).</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">message_id</td>
<td style="width: 521px;">Message ID.</td>
<td style="width: 72px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">folder_id</td>
<td style="width: 521px;">CSV list of folder IDs, for example: (mailFolders,childFolders,childFolders…).</td>
<td style="width: 72px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">attachment_id</td>
<td style="width: 521px;">ID of the attachment.</td>
<td style="width: 72px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 219px;"><strong>Path</strong></th>
<th style="width: 132px;"><strong>Type</strong></th>
<th style="width: 389px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 219px;">File.Size</td>
<td style="width: 132px;">Number</td>
<td style="width: 389px;">Size of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.SHA1</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">SHA1 hash of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.SHA256</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.Name</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">Name of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.SSDeep</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">ssdeep hash of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.EntryID</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">Entry ID of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.Info</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">Details of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.Type</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">Type of file.</td>
</tr>
<tr>
<td style="width: 219px;">File.MD5</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">MD5 hash of the file.</td>
</tr>
<tr>
<td style="width: 219px;">File.Extension</td>
<td style="width: 132px;">String</td>
<td style="width: 389px;">Extension of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !msgraph-mail-get-attachment user_id=ex@example.com message_id=!msgraph-mail-get-attachment
              user_id=ex@example.com message_id=AAMkADMzZWNjO3YRKNF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAA=
              attachment_id=AAMkADCPVsAqlO3YRKNF6ZoON8u7AAAAAAEMAACPVsAqlO3YRKNF6ZoON8u7AAAF0Z9-AAABEgAQAFBdvAbOjGxNvBHqF1VbAHI=<span style="white-space: normal;">
            </span></pre>