<!-- HTML_DOC -->
<p>This integration enables sending e-mails from within Demisto. You can do this from any SMTP email address. </p>
<p>To set up the integration on Demisto:</p>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate ‘Mail Sender’ by searching for it using the search box on the top of the page.</li>
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:<br><strong>Name</strong>: A textual name for the integration instance. <br>
<div class="field required error"><label>Mail server hostname or IP address - The hostname or IP address used for the email.<br><strong>SMTP Port</strong>: The SMTP port used for the mail. <br></label></div>
<div id="credentials-box" class="credentials-box">
<div class="user-password-input">
<div class="field"><label><strong>Credentials and Password:</strong> <label>The </label>account and password to use. </label></div>
</div>
</div>
<div class="field required">
<label><label><strong>Sender address: </strong><label>The </label>email address that will appear as the sender of the email. <br></label></label>
<div class="field">
<div class="demisto-checkbox ui checkbox ">
<label class="checkbox-label" title="Use TLS for connection"><label class="checkbox-label" title="Use TLS for connection"><strong>Use TLS for connection:</strong> </label></label> <label>The </label>Transport Layer Security (<strong>TLS</strong>) protocol to use.<br>
<div class="field">
<div class="demisto-checkbox ui checkbox ">
<label class="checkbox-label" title="Do not validate server certificate (insecure)"><strong>Do not validate server certificate (insecure):</strong>  Select to avoid server certification validation. You may want to do this in case Demisto cannot validate the integration server certificate (due to missing CA certificate).<br><strong>Demisto engine:</strong> If relevant, select the engine that acts as a proxy to the server. Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Demisto server from accessing the remote networks. For more information on Demisto engines see: <a style="background-color: #ffffff;" href="https://support.demisto.com/hc/en-us/articles/226274727-Settings-Integrations-Engines" rel="nofollow">https://demisto.zendesk.com/hc/en-us/articles/226274727-Settings-Integrations-Engines<br></a></label><strong>Require users to enter additional password:</strong> Select whether you’d like an additional step where users are required to authenticate themselves with a password.</div>
<div class="demisto-checkbox ui checkbox "> </div>
</div>
</div>
</div>
</div>
</li>
<li>Press the ‘Test’ button to validate connection.<br>If you are experiencing issues with the service configuration, please contact Demisto support at <a href="mailto:support@demisto.com">support@demisto.com</a>
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3> Top Use-cases:</h3>
<ul>
<li>Sending notifications to external users.</li>
<li>Send an email asking for a response to be returned as part of a Playbook. <br>See <a href="https://support.demisto.com/hc/en-us/articles/115005287087-Automation-Receiving-an-email-reply" target="_blank" rel="noopener">Receiving an email reply</a>.</li>
</ul>
<h3> Commands:</h3>
<ul>
<li style="font-family: courier;">
<strong>send-mail</strong> </li>
</ul>
<p class="wysiwyg-indent6">Input:</p>
<table style="margin-left: 70px; width: 713px;">
<tbody>
<tr>
<td style="width: 713px;">
<p><strong>attachIDs</strong> - A comma-separated list of IDs of war room entries that contain the files that should be attached to the email.<br><strong>to</strong> - Email addresses for the 'To' field.<br><strong>bcc</strong> - Email addresses for the 'Bcc' field.<br><strong>subject</strong> - Subject for the email to be sent.<br><strong>body</strong> - The contents (body) of the email to be sent.<br><strong>cc</strong> - Email addresses for the 'Cc' field.<br><strong>attachNames</strong> - A comma-separated list to rename file-names of corresponding attachments IDs. (e.g. rename first two files - attachNames=file_name1,file_name2. rename first and third file - attachNames=file_name1,,file_name3)<br><strong>transientFile</strong> - Desired name for attached file. Multiple files are supported. (e.g. transientFile.1="t1.txt" transientFileContent.1="test 2" transientFile.2="t3.txt" transientFileContent.2="test 3")<br><strong>transientFileContent</strong> - Content for attached file. Multiple files are supported. (e.g. transientFile.1="t1.txt" transientFileContent.1="test 2" transientFile.2="t3.txt" transientFileContent.2="test 3")<br><strong>htmlBody</strong> - The contents (body) of the email to be sent in HTML format.<br><strong>replyTo</strong> - Address that should be used to reply to the message.</p>
<div class="main-description" title="A comma-separated list of IDs of war room entries that contain files. Used to attach files to the outgoing email. Example: attachIDs=15@8,19@8">
<div class="main-description" title="Email addresses for the 'bcc' field">
<div class="main-description" title="Email addresses for the 'cc' field">
<div class="argument-item-data">
<div class="ui two column left aligned padded grid">
<div class="seven wide column">
<div class="argument-name ellipsis semi-bold" title="noteEntryID">
<div class="item-header ellipsis" title="replyTo"> </div>
</div>
</div>
</div>
</div>
</div>
</div>
</div>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px; width: 713px;">
<tbody>
<tr>
<td style="width: 713px;">
<p>none</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px; width: 713px;">
<tbody>
<tr>
<td style="width: 713px;">
<p>none</p>
</td>
</tr>
</tbody>
</table>