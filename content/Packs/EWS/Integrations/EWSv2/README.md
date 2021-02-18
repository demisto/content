<!-- HTML_DOC -->
<p>Exchange Web Services (EWS) provides the functionality to enable client applications to communicate with the Exchange server. EWS provides access to much of the same data that is made available through Microsoft OfficeOutlook.</p>
<p>The EWS v2 integration implants EWS leading services. The integration allows getting information on emails and activities in a target mailbox, and some active operations on the mailbox such as deleting emails and attachments or moving emails from folder to folder.</p>
<h2>EWS v2 Playbook</h2>
<ul>
<li>Office 365 Search and Delete</li>
<li>Search And Delete Emails - EWS</li>
<li>Get Original Email - EWS</li>
<li>Process Email - EWS</li>
</ul>
<h2>Use Cases</h2>
<p>The EWS integration can be used for the following use cases.</p>
<ul>
<li>
<p>Monitor a specific email account and create incidents from incoming emails to the defined folder.<br> Follow the instructions in the Fetched Incidents Data section.</p>
</li>
<li>
<p>Search for an email message across mailboxes and folders.<br> This can be achieved in the following ways:</p>
<ol>
<li>Use the <code>ews-search-mailboxes</code> command to search for all emails in a specific scope of mailboxes.<br> Use the filter argument to narrow the search for emails sent from a specific account and more.</li>
<li>Use the <code>ews-search-mailbox</code> command to search for all emails in a specific folder within the target mailbox.<br> Use the query argument to narrow the search for emails sent from a specific account and more.</li>
</ol>
<ul>
<li>Both of these commands retrieve the <em>ItemID</em> field for each email item listed in the results. The<span> </span><code>ItemID</code><span> </span>can be used in the<span> </span><code>ews-get-items</code><span> </span>command in order to get more information about the email item itself.</li>
<li>For instance, use the <code>ews-search-mailboxes</code> command to hunt for emails that were marked as malicious in prior investigations, across organization mailboxes. Focus your hunt on emails sent from a specific mail account, emails with a specific subject and more.</li>
</ul>
</li>
<li>
<p>Get email attachment information.<br> Use the<span> </span><code>ews-get-attachment</code><span> </span>command to retrieve information on one attachment or all attachments of a message at once. It supports both file attachments and item attachments (e.g., email messages).</p>
</li>
<li>
<p>Delete email items from a mailbox.<br> First, make sure you obtain the email item ID. The item ID can be obtained with one of the integration’s search commands.<br> Use the<span> </span><code>ews-delete-items</code><span> command </span>to delete one or more items from the target mailbox in a single action.<br> A less common use case is to remove emails that were marked as malicious from a user’s mailbox.<br> You can delete the items permanently (hard delete), or delete the items (soft delete), so they can be recovered by running the<span> </span><code>ews-recover-messages</code> command.</p>
</li>
</ul>
<h2>Configure EWS v2 on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for EWS v2.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Email address</strong><span> </span>The email address</li>
<li>
<strong>Password</strong><span> </span>The password of the account. Use the API Key if working with Multi-Factor Authentication.</li>
<li>
<strong>Email address from which to fetch incidents</strong><span> </span>This argument can take various user accounts in your organization. Usually is used as phishing mailbox.<br> Note: To use this functionality, your account must have impersonation rights or delegation for the account specified. In the case of impersonation, make sure to check the<span> </span><code>Has impersonation rights</code><span> </span>checkbox in the instance settings. For more information on impersonation rights see ‘Additional Info’ section below.</li>
<li><strong>Name of the folder from which to fetch incidents (supports Exchange Folder ID and sub-folders e.g. Inbox/Phishing)</strong></li>
<li><strong>Public Folder</strong></li>
<li><strong>Has impersonation rights</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Mark fetched emails as read</strong></li>
<li>
<strong>Incident type</strong><br> ┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉<br> ‎ Manual Mode<br> <code>In case the auto-discovery process failed, you will need to configure manually the exchange server endpoint, domain\username for exchange on-premise and enter exchange server version</code>
</li>
<li>
<strong>Exchange Server Hostname or IP address</strong><span> </span>For office 365 use<span> </span><code>https://outlook.office365.com/EWS/Exchange.asmx/</code><span> </span>and for exchange on-premise<span> </span><code>https://&lt;ip&gt;/EWS/Exchange.asmx/</code>
</li>
<li><strong>DOMAIN\USERNAME (e.g. DEMISTO.INT\admin)</strong></li>
<li><strong>Exchange Server Version (On-Premise only. Supported versions: 2007, 2010, 2010_SP2, 2013, and 2016)</strong></li>
<li>
<strong>Trust any certificate (not secure)</strong><br> ┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉┉<br> ‎ Advanced Mode<br> Override Authentication Type (NTLM, Basic, or Digest)._</li>
<li><strong>Timeout (in seconds) for HTTP requests to Exchange Server</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Fetched Incidents Data</h2>
<p>The integration imports email messages from the destination folder in the target mailbox as incidents. If the message contains any attachments, they are uploaded to the War Room as files. If the attachment is an email, Demisto fetches information about the attached email and downloads all of its attachments (if there are any) as files.</p>
<p>To use Fetch incidents, configure a new instance and select the<span> </span><code>Fetches incidents</code><span> </span>option in the instance settings.</p>
<p>IMPORTANT: The initial fetch interval is the previous 10 minutes. If no emails were fetched before from the destination folder- all emails from 10 minutes prior to the instance configuration and up to the current time will be fetched. Additionally moving messages manually to the destination folder will not trigger fetch incident. Define rules on phishing/target mailbox instead of moving messages manually.</p>
<p>Pay special attention to the following fields in the instance settings:</p>
<p><code>Email address from which to fetch incidents</code><span> </span>– mailbox to fetch incidents from.<br> <code>Name of the folder from which to fetch incidents</code><span> </span>– use this field to configure the destination folder from where emails should be fetched. The default is Inbox folder. Please note, if Exchange is configured with an international flavor `Inbox` will be named according to the configured language.<br> <code>Has impersonation rights</code><span> </span>– mark this option if you set the target mailbox to an account different than your personal account. Otherwise Delegation access will be used instead of Impersonation.<br> Find more information on impersonation or delegation rights at ‘Additional Info’ section below.</p>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_22ec0bbb-12b3-4f1c-9159-b1a4daa114c7" target="_self">Get the attachments of an item: ews-get-attachment</a></li>
<li><a href="#h_cae18768-1dd5-4cd1-b2c9-abfd0e7787f3" target="_self">Delete the attachments of an item: ews-delete-attachment</a></li>
<li><a href="#h_7bdec9fe-e3d9-4645-8da4-337ee3798a84" target="_self">Get a list of searchable mailboxes: ews-get-searchable-mailboxes</a></li>
<li><a href="#h_fa3bd755-beb9-4c98-a020-6210f3179d3c" target="_self">Search mailboxes: ews-search-mailboxes</a></li>
<li><a href="#h_0661f657-850a-430a-8fe1-aacf7e3ce40b" target="_self">Move an item to a different folder: ews-move-item</a></li>
<li><a href="#h_712791a3-5937-4641-8e02-1fd773ab3211" target="_self">Delete an item from a mailbox: ews-delete-items</a></li>
<li><a href="#h_2b4fd205-165c-489f-b58c-3bb77a86acfc" target="_self">Search a single mailbox: ews-search-mailbox</a></li>
<li><a href="#h_3b6dc53b-4c1a-4479-a529-0ff3300dc4f5" target="_self">Get the contacts for a mailbox: ews-get-contacts</a></li>
<li><a href="#h_b592e5fe-af2a-4d3c-90aa-b933e69a7526" target="_self">Get the out-of-office status for a mailbox: ews-get-out-of-office</a></li>
<li><a href="#h_212102bb-4ad8-4bb8-9c05-1b1197e2a9c9" target="_self">Recover soft-deleted messages: ews-recover-messages</a></li>
<li><a href="#h_4ab168b9-21e9-4ce1-b18c-56bc22c0e0bd" target="_self">Create a folder: ews-create-folder</a></li>
<li><a href="#h_01b093ea-bc1c-46a3-b694-8cd45effeaa0" target="_self">Mark an item as junk: ews-mark-item-as-junk</a></li>
<li><a href="#h_3f9e1f1e-e634-4f92-b2a2-cdca5ca662eb" target="_self">Search for folders: ews-find-folders</a></li>
<li><a href="#h_0035899d-fdd0-43b7-bf7b-11a38a2e575a" target="_self">Get items of a folder: ews-get-items-from-folder</a></li>
<li><a href="#h_e8f449a2-aecf-4d65-8d04-a38c6d4bfe62" target="_self">Get items: ews-get-items</a></li>
<li><a href="#h_88c0edd5-09b0-42a1-a671-b36b73772898" target="_self">Move an item to a different mailbox: ews-move-item-between-mailboxes</a></li>
<li><a href="#h_87ca72d4-d98a-462e-9829-c940321663c2" target="_self">Get a folder: ews-get-folder</a></li>
<li><a href="#h_9e97c090-dd51-4775-9286-d5ce0005a4a7" target="_self">Initiate a compliance search: ews-o365-start-compliance-search</a></li>
<li><a href="#h_94cf108b-10cd-452b-90f1-42caace65edb" target="_self">Get the status and results of a compliance search: ews-o365-get-compliance-search</a></li>
<li><a href="#h_dae1d9a7-d618-4cee-9104-1ac1e7b55076" target="_self">Purge compliance search results: ews-o365-purge-compliance-search-results</a></li>
<li><a href="#h_628a65d3-ced0-44ff-94f5-e76de66fab82" target="_self">Remove a compliance search: ews-o365-remove-compliance-search</a></li>
<li><a href="#h_acedbb5d-c8a1-4ca0-910c-3ccfebbb90f9" target="_self">Get the purge status of a compliance search: ews-o365-get-compliance-search-purge-status</a></li>
<li><a href="#h_02b7cb8e-f9c9-44a9-a0c7-6989b9232b46" target="_self">Get auto-discovery information: ews-get-autodiscovery-config</a></li>
<li><a href="#h_d91ca450-7004-4a19-a88d-840389b21556" target="_self">Expand a distribution list: ews-expand-group</a></li>
<li><a href="#h_e278dc88-b4b0-4330-b849-3069b770e5ba" target="_self">Mark items as read: ews-mark-items-as-read</a></li>
</ol>
<h3 id="h_22ec0bbb-12b3-4f1c-9159-b1a4daa114c7">1. Get the attachments of an item</h3>
<hr>
<p>Retrieves the actual attachments from an item (email message). To get all attachments for a message, only specify the item-id argument.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-get-attachment</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 155px;"><strong>Argument Name</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 155px;">item-id</td>
<td style="width: 514px;">The ID of the email message for which to get the attachments.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 155px;">target-mailbox</td>
<td style="width: 514px;">The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise, the user might require impersonation rights to this mailbox.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 155px;">attachment-ids</td>
<td style="width: 514px;">The attachments ids to get. If none - all attachments will be retrieved from the message. Support multiple attachments with comma-separated value or array.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 479px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 200px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 479px;">EWS.Items.FileAttachments.attachmentId</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The attachment ID. Used for file attachments only.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.FileAttachments.attachmentName</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The attachment name. Used for file attachments only.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.FileAttachments.attachmentSHA256</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The SHA256 hash of the attached file.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.FileAttachments.attachmentLastModifiedTime</td>
<td style="width: 61px;">date</td>
<td style="width: 200px;">The attachment last modified time. Used for file attachments only.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.datetimeCreated</td>
<td style="width: 61px;">date</td>
<td style="width: 200px;">The created time of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.datetimeReceived</td>
<td style="width: 61px;">date</td>
<td style="width: 200px;">The received time of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.datetimeSent</td>
<td style="width: 61px;">date</td>
<td style="width: 200px;">The sent time of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.receivedBy</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The received by address of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.subject</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The subject of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.textBody</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The body of the attached email (as text).</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.headers</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 200px;">The headers of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.hasAttachments</td>
<td style="width: 61px;">boolean</td>
<td style="width: 200px;">Whether the attached email has attachments.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.itemId</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The attached email item ID.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.toRecipients</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 200px;">A list of recipient email addresses for the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.body</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">The body of the attached email (as HTML).</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.attachmentSHA256</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">SHA256 hash of the attached email (as EML file).</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.FileAttachments.attachmentSHA256</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">SHA256 hash of the attached files inside of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.ItemAttachments.attachmentSHA256</td>
<td style="width: 61px;">string</td>
<td style="width: 200px;">SHA256 hash of the attached emails inside of the attached email.</td>
</tr>
<tr>
<td style="width: 479px;">EWS.Items.ItemAttachments.isRead</td>
<td style="width: 61px;">String</td>
<td style="width: 200px;">The read status of the attachment.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-attachment item-id=BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAA= target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "ItemAttachments": {
                "originalItemId": "BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAA=", 
                "attachmentSize": 2956, 
                "receivedBy": "test@demistodev.onmicrosoft.com", 
                "size": 28852, 
                "author": "test2@demistodev.onmicrosoft.com", 
                "attachmentLastModifiedTime": "2019-08-11T15:01:30+00:00", 
                "subject": "Moving Email between mailboxes", 
                "body": "Some text inside", 
                "datetimeCreated": "2019-08-11T15:01:47Z", 
                "importance": "Normal", 
                "attachmentType": "ItemAttachment", 
                "toRecipients": [
                    "test@demistodev.onmicrosoft.com"
                ], 
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "isRead": false, 
                "attachmentIsInline": false, 
                "datetimeSent": "2019-08-07T12:50:19Z", 
                "lastModifiedTime": "2019-08-11T15:01:30Z", 
                "sender": "test2@demistodev.onmicrosoft.com", 
                "attachmentName": "Moving Email between mailboxes", 
                "datetimeReceived": "2019-08-07T12:50:20Z", 
                "attachmentSHA256": "119e27b28dc81bdfd4f498d44bd7a6d553a74ee03bdc83e6255a53", 
                "hasAttachments": false, 
                "headers": [
                    {
                        "name": "Subject", 
                        "value": "Moving Email between mailboxes"
                    }
		...
                ], 
                "attachmentId": "BBFDShfdafFSDF3FADR3434DFASDFADAFDADFADFCJebinpkUAAAfxuiVAAABEgAQAOpEfpzDB4dFkZ+/K4XSj44=", 
                "messageId": "&lt;message_id&gt;"
            }
        }
    }
</pre>
<h3 id="h_cae18768-1dd5-4cd1-b2c9-abfd0e7787f3">2. Delete the attachments of an item</h3>
<hr>
<p>Deletes the attachments of an item (email message).</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-delete-attachment</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 147px;"><strong>Argument Name</strong></th>
<th style="width: 522px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 147px;">item-id</td>
<td style="width: 522px;">The ID of the email message for which to delete attachments.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 147px;">target-mailbox</td>
<td style="width: 522px;">The mailbox in which this attachment was found. If empty, the default mailbox is used. Otherwise, the user might require impersonation rights to this mailbox.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 147px;">attachment-ids</td>
<td style="width: 522px;">A CSV list (or array) of attachment IDs to delete. If empty, all attachments will be deleted from the message.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 310px;"><strong>Path</strong></th>
<th style="width: 37px;"><strong>Type</strong></th>
<th style="width: 393px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 310px;">EWS.Items.FileAttachments.attachmentId</td>
<td style="width: 37px;">string</td>
<td style="width: 393px;">The ID of the deleted attachment, in case of file attachment.</td>
</tr>
<tr>
<td style="width: 310px;">EWS.Items.ItemAttachments.attachmentId</td>
<td style="width: 37px;">string</td>
<td style="width: 393px;">The ID of the deleted attachment, in case of other attachment (for example, "email").</td>
</tr>
<tr>
<td style="width: 310px;">EWS.Items.FileAttachments.action</td>
<td style="width: 37px;">string</td>
<td style="width: 393px;">The deletion action in case of file attachment. This is a constant value: 'deleted'.</td>
</tr>
<tr>
<td style="width: 310px;">EWS.Items.ItemAttachments.action</td>
<td style="width: 37px;">string</td>
<td style="width: 393px;">The deletion action in case of other attachment (for example, "email"). This is a constant value: 'deleted'.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-delete-attachment item-id=AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAA= target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>action</th>
<th>attachmentId</th>
</tr>
</thead>
<tbody>
<tr>
<td>deleted</td>
<td>AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAABEgAQAIUht2vrOdErec33=</td>
</tr>
</tbody>
</table>
<p> </p>
<h3>Context Example</h3>
<pre>{
    "EWS": {
        "Items": {
            "FileAttachments": {
                "action": "deleted",
                "attachmentId": "AAMkADQ0NmwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJjfaljfAFDVSDinpkUAAAfxxd9AAABEgAQAIUht2vrOdErec33="
            }
        }
    }
}
</pre>
<h3 id="h_7bdec9fe-e3d9-4645-8da4-337ee3798a84">3. Get a list of searchable mailboxes</h3>
<hr>
<p>Returns a list of searchable mailboxes.</p>
<h5>Required Permissions</h5>
<p>Requires eDiscovery permissions to the Exchange Server. For more information see the <a href="https://technet.microsoft.com/en-us/library/dd298059(v=exchg.160).aspx" target="_blank" rel="nofollow noopener">Microsoft documentation</a>.</p>
<h5>Base Command</h5>
<p><code>ews-get-searchable-mailboxes</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 326px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 346px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 326px;">EWS.Mailboxes.mailbox</td>
<td style="width: 68px;">string</td>
<td style="width: 346px;">Addresses of the searchable mailboxes.</td>
</tr>
<tr>
<td style="width: 326px;">EWS.Mailboxes.mailboxId</td>
<td style="width: 68px;">string</td>
<td style="width: 346px;">IDs of the searchable mailboxes.</td>
</tr>
<tr>
<td style="width: 326px;">EWS.Mailboxes.displayName</td>
<td style="width: 68px;">string</td>
<td style="width: 346px;">The email display name.</td>
</tr>
<tr>
<td style="width: 326px;">EWS.Mailboxes.isExternal</td>
<td style="width: 68px;">boolean</td>
<td style="width: 346px;">Whether the mailbox is external.</td>
</tr>
<tr>
<td style="width: 326px;">EWS.Mailboxes.externalEmailAddress</td>
<td style="width: 68px;">string</td>
<td style="width: 346px;">The external email address.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-searchable-mailboxes</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>displayName</th>
<th>isExternal</th>
<th>mailbox</th>
<th>mailboxId</th>
</tr>
</thead>
<tbody>
<tr>
<td>test</td>
<td>false</td>
<td>test@demistodev.onmicrosoft.com</td>
<td>/o=Exchange***/ou=Exchange Administrative Group ()/cn=<strong>/cn=</strong>-**</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Mailboxes": [
            {
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "displayName": "test", 
                "mailboxId": "/o=Exchange***/ou=Exchange Administrative Group ()/cn=**/cn=**-**", 
                "isExternal": "false"
            }
            ...
        ]
    }
}
</pre>
<h3 id="h_fa3bd755-beb9-4c98-a020-6210f3179d3c">4. Search mailboxes</h3>
<hr>
<p>Searches over multiple mailboxes or all Exchange mailboxes. The maximum number of mailboxes that can be searched is 20,000. Use either the mailbox-search-scope command or the email-addresses command to search specific mailboxes.</p>
<h5>Required Permissions</h5>
<p>Requires eDiscovery permissions to the Exchange Server. For more information, see the <a href="https://technet.microsoft.com/en-us/library/dd298059(v=exchg.160).aspx" target="_blank" rel="nofollow noopener">Microsoft documentation</a>.</p>
<h5>Base Command</h5>
<p><code>ews-search-mailboxes</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 174px;"><strong>Argument Name</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
<th style="width: 78px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174px;">filter</td>
<td style="width: 488px;">The filter query to search.</td>
<td style="width: 78px;">Required</td>
</tr>
<tr>
<td style="width: 174px;">mailbox-search-scope</td>
<td style="width: 488px;">The mailbox IDs to search. If empty, all mailboxes are searched.</td>
<td style="width: 78px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">limit</td>
<td style="width: 488px;">Maximum number of results to return.</td>
<td style="width: 78px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">email_addresses</td>
<td style="width: 488px;">CSV list or array of email addresses.</td>
<td style="width: 78px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 242px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 410px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 242px;">EWS.Items.itemId</td>
<td style="width: 88px;">string</td>
<td style="width: 410px;">The item ID.</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.mailbox</td>
<td style="width: 88px;">string</td>
<td style="width: 410px;">The mailbox address where the item was found.</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.subject</td>
<td style="width: 88px;">string</td>
<td style="width: 410px;">The subject of the email.</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.toRecipients</td>
<td style="width: 88px;">Unknown</td>
<td style="width: 410px;">List of recipient email addresses.</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.sender</td>
<td style="width: 88px;">string</td>
<td style="width: 410px;">Sender email address.</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.hasAttachments</td>
<td style="width: 88px;">boolean</td>
<td style="width: 410px;">Whether the email has attachments?</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.datetimeSent</td>
<td style="width: 88px;">date</td>
<td style="width: 410px;">Sent time of the email.</td>
</tr>
<tr>
<td style="width: 242px;">EWS.Items.datetimeReceived</td>
<td style="width: 88px;">date</td>
<td style="width: 410px;">Received time of the email.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-search-mailboxes filter="subject:Test" limit=1</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>datetimeReceived</th>
<th>datetimeSent</th>
<th>hasAttachments</th>
<th>itemId</th>
<th>mailbox</th>
<th>sender</th>
<th>subject</th>
<th>toRecipients</th>
</tr>
</thead>
<tbody>
<tr>
<td>2019-08-11T11:00:28Z</td>
<td>2019-08-11T11:00:28Z</td>
<td>false</td>
<td>AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGACASFAACYCKjWAnXDFrfsdhdnfkanpAAA=</td>
<td><a href="mailto:test2@demistodev.onmicrosoft.com">test2@demistodev.onmicrosoft.com</a></td>
<td>John Smith</td>
<td>test report</td>
<td><a href="mailto:dem@demistodev.onmicrosoft.com">dem@demistodev.onmicrosoft.com</a></td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "itemId": "AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NmZhLWQ5MGY1YjIyNzBkNABGACASFAACYCKjWAnXDFrfsdhdnfkanpAAA=", 
            "sender": "John Smith", 
            "datetimeReceived": "2019-08-11T11:00:28Z", 
            "hasAttachments": "false", 
            "toRecipients": [
                "dem@demistodev.onmicrosoft.com"
            ], 
            "mailbox": "test2@demistodev.onmicrosoft.com", 
            "datetimeSent": "2019-08-11T11:00:28Z", 
            "subject": "test report "
        }
    }
}
</pre>
<h3 id="h_0661f657-850a-430a-8fe1-aacf7e3ce40b">5. Move an item to a different folder</h3>
<hr>
<p>Move an item to a different folder in the mailbox.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-move-item</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 153px;"><strong>Argument Name</strong></th>
<th style="width: 516px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 153px;">item-id</td>
<td style="width: 516px;">The ID of the item to move.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">target-folder-path</td>
<td style="width: 516px;">The path to the folder to which to move the item. Complex paths are supported, for example, "Inbox\Phishing".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">target-mailbox</td>
<td style="width: 516px;">The mailbox on which to run the command.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">is-public</td>
<td style="width: 516px;">Whether the target folder is a public folder.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 226px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 450px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 226px;">EWS.Items.newItemID</td>
<td style="width: 64px;">string</td>
<td style="width: 450px;">The item ID after the move.</td>
</tr>
<tr>
<td style="width: 226px;">EWS.Items.messageID</td>
<td style="width: 64px;">string</td>
<td style="width: 450px;">The item message ID.</td>
</tr>
<tr>
<td style="width: 226px;">EWS.Items.itemId</td>
<td style="width: 64px;">string</td>
<td style="width: 450px;">The original item ID.</td>
</tr>
<tr>
<td style="width: 226px;">EWS.Items.action</td>
<td style="width: 64px;">string</td>
<td style="width: 450px;">The action taken. The value will be "moved".</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-move-item item-id=VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA= target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>action</th>
<th>itemId</th>
<th>messageId</th>
<th>newItemId</th>
</tr>
</thead>
<tbody>
<tr>
<td>moved</td>
<td>VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA</td>
<td>&lt;message_id&gt;</td>
<td>AAVAAAVN2NkLThmZjdmNTZjNTMxFFFFJTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVfafainpkUAAAfxxd+AAA=</td>
</tr>
</tbody>
</table>
<h5>Context Example</h5>
<pre><code>{
    "EWS": {
        "Items": {
            "action": "moved", 
            "itemId": "VDAFNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU34cSCSSSfBJebinpkUAAAAAAEMAACyyVyFtlsUQZfBJebinpkUAAAfxuiRAAA", 
            "newItemId": "AAVAAAVN2NkLThmZjdmNTZjNTMxFFFFJTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVfafainpkUAAAfxxd+AAA=", 
            "messageId": "&lt;message_id&gt;"
        }
    }
}
</code></pre>
<h3 id="h_712791a3-5937-4641-8e02-1fd773ab3211">6. Delete an item from a mailbox</h3>
<hr>
<p>Delete items from mailbox.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-delete-items</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 456px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">item-ids</td>
<td style="width: 456px;">The item IDs to delete.</td>
<td style="width: 100px;">Required</td>
</tr>
<tr>
<td style="width: 184px;">delete-type</td>
<td style="width: 456px;">Deletion type. Can be "trash", "soft", or "hard".</td>
<td style="width: 100px;">Required</td>
</tr>
<tr>
<td style="width: 184px;">target-mailbox</td>
<td style="width: 456px;">The mailbox on which to run the command.</td>
<td style="width: 100px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 164px;"><strong>Path</strong></th>
<th style="width: 38px;"><strong>Type</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">EWS.Items.itemId</td>
<td style="width: 38px;">string</td>
<td style="width: 538px;">The deleted item ID.</td>
</tr>
<tr>
<td style="width: 164px;">EWS.Items.messageId</td>
<td style="width: 38px;">string</td>
<td style="width: 538px;">The deleted message ID.</td>
</tr>
<tr>
<td style="width: 164px;">EWS.Items.action</td>
<td style="width: 38px;">string</td>
<td style="width: 538px;">The deletion action. Can be 'trash-deleted', 'soft-deleted', or 'hard-deleted'.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-delete-items item-ids=VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA= delete-type=soft target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>action</th>
<th>itemId</th>
<th>messageId</th>
</tr>
</thead>
<tbody>
<tr>
<td>soft-deleted</td>
<td>VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA=</td>
<td>&lt;message_id&gt;</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "action": "soft-deleted", 
            "itemId": "VWAFA3hmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyw+kAAA=", 
            "messageId": "&lt;messaage_id&gt;"
        }
    }
}
</pre>
<h3 id="h_2b4fd205-165c-489f-b58c-3bb77a86acfc">7. Search a single mailbox</h3>
<hr>
<p>Searches for items in the specified mailbox. Specific permissions are needed for this operation to search in a target mailbox other than the default.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-search-mailbox</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 537px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">query</td>
<td style="width: 537px;">The search query string. For more information about the query syntax, see the <a href="https://msdn.microsoft.com/en-us/library/ee693615.aspx" target="_blank" rel="noopener">Microsoft documentation</a>.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">folder-path</td>
<td style="width: 537px;">The folder path in which to search. If empty, searches all the folders in the mailbox.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">limit</td>
<td style="width: 537px;">Maximum number of results to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">target-mailbox</td>
<td style="width: 537px;">The mailbox on which to apply the search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">is-public</td>
<td style="width: 537px;">Whether the folder is a Public Folder?</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 132px;">message-id</td>
<td style="width: 537px;">The message ID of the email. This will be ignored if a query argument is provided.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 346px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 318px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 346px;">EWS.Items.itemId</td>
<td style="width: 76px;">string</td>
<td style="width: 318px;">The email item ID.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.hasAttachments</td>
<td style="width: 76px;">boolean</td>
<td style="width: 318px;">Whether the email has attachments.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.datetimeReceived</td>
<td style="width: 76px;">date</td>
<td style="width: 318px;">Received time of the email.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.datetimeSent</td>
<td style="width: 76px;">date</td>
<td style="width: 318px;">Sent time of the email.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.headers</td>
<td style="width: 76px;">Unknown</td>
<td style="width: 318px;">Email headers (list).</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.sender</td>
<td style="width: 76px;">string</td>
<td style="width: 318px;">Sender email address of the email.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.subject</td>
<td style="width: 76px;">string</td>
<td style="width: 318px;">Subject of the email.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.textBody</td>
<td style="width: 76px;">string</td>
<td style="width: 318px;">Body of the email (as text).</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.size</td>
<td style="width: 76px;">number</td>
<td style="width: 318px;">Email size.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.toRecipients</td>
<td style="width: 76px;">Unknown</td>
<td style="width: 318px;">List of email recipients addresses.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.receivedBy</td>
<td style="width: 76px;">Unknown</td>
<td style="width: 318px;">Email received by address.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.messageId</td>
<td style="width: 76px;">string</td>
<td style="width: 318px;">Email message ID.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.body</td>
<td style="width: 76px;">string</td>
<td style="width: 318px;">Body of the email (as HTML).</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.FileAttachments.attachmentId</td>
<td style="width: 76px;">unknown</td>
<td style="width: 318px;">Attachment ID of the file attachment.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.ItemAttachments.attachmentId</td>
<td style="width: 76px;">unknown</td>
<td style="width: 318px;">Attachment ID of the item attachment.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.FileAttachments.attachmentName</td>
<td style="width: 76px;">unknown</td>
<td style="width: 318px;">Attachment name of the file attachment.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.ItemAttachments.attachmentName</td>
<td style="width: 76px;">unknown</td>
<td style="width: 318px;">Attachment name of the item attachment.</td>
</tr>
<tr>
<td style="width: 346px;">EWS.Items.isRead</td>
<td style="width: 76px;">String</td>
<td style="width: 318px;">The read status of the email.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-search-mailbox query="subject:"Get Attachment Email" target-mailbox=test@demistodev.onmicrosoft.com limit=1</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>sender</th>
<th>subject</th>
<th>hasAttachments</th>
<th>datetimeReceived</th>
<th>receivedBy</th>
<th>author</th>
<th>toRecipients</th>
</tr>
</thead>
<tbody>
<tr>
<td>test2@demistodev.onmicrosoft.com</td>
<td>Get Attachment Email</td>
<td>true</td>
<td>2019-08-11T10:57:37Z</td>
<td>test@demistodev.onmicrosoft.com</td>
<td>test2@demistodev.onmicrosoft.com</td>
<td>test@demistodev.onmicrosoft.com</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "body": "&lt;html&gt;\r\n&lt;head&gt;\r\n&lt;meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"&gt;\r\n&lt;style type=\"text/css\" style=\"display:none;\"&gt;&lt;!-- P {margin-top:0;margin-bottom:0;} --&gt;&lt;/style&gt;\r\n&lt;/head&gt;\r\n&lt;body dir=\"ltr\"&gt;\r\n&lt;div id=\"divtagrapper\" style=\"font-size:12pt;color:#000000;font-family:Calibri,Helvetica,sans-serif;\" dir=\"ltr\"&gt;\r\n&lt;p style=\"margin-top:0;margin-bottom:0\"&gt;Some text inside email&lt;/p&gt;\r\n&lt;/div&gt;\r\n&lt;/body&gt;\r\n&lt;/html&gt;\r\n", 
            "itemId": "AAMkADQ0NmFFijer3FFmNTZjNTMxNwBGAAAAAAFSAAfxw+jAAA=", 
            "toRecipients": [
                "test@demistodev.onmicrosoft.com"
            ], 
            "datetimeCreated": "2019-08-11T10:57:37Z", 
            "datetimeReceived": "2019-08-11T10:57:37Z", 
            "author": "test2@demistodev.onmicrosoft.com", 
            "hasAttachments": true, 
            "size": 30455, 
            "subject": "Get Attachment Email", 
            "FileAttachments": [
                {
                    "attachmentName": "atta1.rtf", 
                    "attachmentSHA256": "csfd81097bc049fbcff6e637ade0407a00308bfdfa339e31a44a1c4e98f28ce36e4f", 
                    "attachmentType": "FileAttachment", 
                    "attachmentSize": 555, 
                    "attachmentId": "AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAfxw+jAAABEgAQAEyq1TB2nKBLpKUiFUJ5Geg=", 
                    "attachmentIsInline": false, 
                    "attachmentLastModifiedTime": "2019-08-11T11:06:02+00:00", 
                    "attachmentContentLocation": null, 
                    "attachmentContentType": "text/rtf", 
                    "originalItemId": "AAMkADQ0NmFFijer3FFmNTZjNTMxNwBGAAAAAAFSAAfxw+jAAA=", 
                    "attachmentContentId": null
                }
            ], 
            "headers": [
                {
                    "name": "Subject", 
                    "value": "Get Attachment Email"
                }, 
                ...
            ], 
            "isRead": true, 
            "messageId": "&lt;mesage_id&gt;", 
            "receivedBy": "test@demistodev.onmicrosoft.com", 
            "datetimeSent": "2019-08-11T10:57:36Z", 
            "lastModifiedTime": "2019-08-11T11:13:59Z", 
            "mailbox": "test@demistodev.onmicrosoft.com", 
            "importance": "Normal", 
            "textBody": "Some text inside email\r\n", 
            "sender": "test2@demistodev.onmicrosoft.com"
        }
    }
}
</pre>
<h3 id="h_3b6dc53b-4c1a-4479-a529-0ff3300dc4f5">8. Get the contacts for a mailbox</h3>
<hr>
<p>Retrieves contacts for a specified mailbox.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-get-contacts</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 174px;"><strong>Argument Name</strong></th>
<th style="width: 466px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174px;">target-mailbox</td>
<td style="width: 466px;">The mailbox for which to retrieve the contacts.</td>
<td style="width: 100px;">Optional</td>
</tr>
<tr>
<td style="width: 174px;">limit</td>
<td style="width: 466px;">Maximum number of results to return.</td>
<td style="width: 100px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 412px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 264px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 412px;">Account.Email.EwsContacts.displayName</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 264px;">The contact name.</td>
</tr>
<tr>
<td style="width: 412px;">Account.Email.EwsContacts.lastModifiedTime</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 264px;">The time that the contact was last modified.</td>
</tr>
<tr>
<td style="width: 412px;">Account.Email.EwsContacts.emailAddresses</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 264px;">Phone numbers of the contact.</td>
</tr>
<tr>
<td style="width: 412px;">Account.Email.EwsContacts.physicalAddresses</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 264px;">Physical addresses of the contact.</td>
</tr>
<tr>
<td style="width: 412px;">Account.Email.EwsContacts.phoneNumbers.phoneNumber</td>
<td style="width: 64px;">Unknown</td>
<td style="width: 264px;">Email addresses of the contact.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-contacts limit="1"</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>changekey</th>
<th>culture</th>
<th>datetimeCreated</th>
<th>datetimeReceived</th>
<th>datetimeSent</th>
<th>displayName</th>
<th>emailAddresses</th>
<th>fileAs</th>
<th>fileAsMapping</th>
<th>givenName</th>
<th>id</th>
<th>importance</th>
<th>itemClass</th>
<th>lastModifiedName</th>
<th>lastModifiedTime</th>
<th>postalAddressIndex</th>
<th>sensitivity</th>
<th>subject</th>
<th>uniqueBody</th>
<th>webClientReadFormQueryString</th>
</tr>
</thead>
<tbody>
<tr>
<td>EABYACAADcsxRwRjq/zTrN6vWSzKAK1Dl3N</td>
<td>en-US</td>
<td>2019-08-05T12:35:36Z</td>
<td>2019-08-05T12:35:36Z</td>
<td>2019-08-05T12:35:36Z</td>
<td>Contact Name</td>
<td>some@dev.microsoft.com</td>
<td>Contact Name</td>
<td>LastCommaFirst</td>
<td>Contact Name</td>
<td>AHSNNK3NQNcasnc3SAS/zTrN6vWSzK4OWAAAAAAEOAADrxRwRjq/zTrNFSsfsfVWAAK1KsF3AAA=</td>
<td>Normal</td>
<td>IPM.Contact</td>
<td>John Smith</td>
<td>2019-08-05T12:35:36Z</td>
<td>None</td>
<td>Normal</td>
<td>Contact Name</td>
<td> </td>
<td>https://outlook.office365.com/owa/?ItemID=***</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Account.Email": [
        {
            "itemClass": "IPM.Contact", 
            "lastModifiedName": "John Smith", 
            "displayName": "Contact Name", 
            "datetimeCreated": "2019-08-05T12:35:36Z", 
            "datetimeReceived": "2019-08-05T12:35:36Z", 
            "fileAsMapping": "LastCommaFirst", 
            "importance": "Normal", 
            "sensitivity": "Normal", 
            "postalAddressIndex": "None", 
            "webClientReadFormQueryString": "https://outlook.office365.com/owa/?ItemID=***", 
            "uniqueBody": "&lt;html&gt;&lt;body&gt;&lt;/body&gt;&lt;/html&gt;", 
            "fileAs": "Contact Name", 
            "culture": "en-US", 
            "changekey": "EABYACAADcsxRwRjq/zTrN6vWSzKAK1Dl3N", 
            "lastModifiedTime": "2019-08-05T12:35:36Z", 
            "datetimeSent": "2019-08-05T12:35:36Z", 
            "emailAddresses": [
                "some@dev.microsoft.com"
            ], 
            "givenName": "Contact Name", 
            "id": "AHSNNK3NQNcasnc3SAS/zTrN6vWSzK4OWAAAAAAEOAADrxRwRjq/zTrNFSsfsfVWAAK1KsF3AAA=", 
            "subject": "Contact Name"
        }
    ]
}
</pre>
<h3 id="h_b592e5fe-af2a-4d3c-90aa-b933e69a7526">9. Get the out-of-office status for a mailbox</h3>
<hr>
<p>Retrieves the out-of-office status for a specified mailbox.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-get-out-of-office</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 164px;"><strong>Argument Name</strong></th>
<th style="width: 483px;"><strong>Description</strong></th>
<th style="width: 93px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 164px;">target-mailbox</td>
<td style="width: 483px;">The mailbox for which to get the out-of-office status.</td>
<td style="width: 93px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 311px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.state</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office state. The result can be: "Enabled", "Scheduled", or "Disabled".</td>
</tr>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.externalAudience</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office external audience. Can be "None", "Known", or "All".</td>
</tr>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.start</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office start date.</td>
</tr>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.end</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office end date.</td>
</tr>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.internalReply</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office internal reply.</td>
</tr>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.externalReply</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office external reply.</td>
</tr>
<tr>
<td style="width: 311px;">Account.Email.OutOfOffice.mailbox</td>
<td style="width: 68px;">Unknown</td>
<td style="width: 361px;">Out-of-office mailbox.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-out-of-office target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>end</th>
<th>externalAudience</th>
<th>mailbox</th>
<th>start</th>
<th>state</th>
</tr>
</thead>
<tbody>
<tr>
<td>2019-08-12T13:00:00Z</td>
<td>All</td>
<td>test@demistodev.onmicrosoft.com</td>
<td>2019-08-11T13:00:00Z</td>
<td>Disabled</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "Account": {
        "Email": {
            "OutOfOffice": {
                "start": "2019-08-11T13:00:00Z", 
                "state": "Disabled", 
                "mailbox": "test@demistodev.onmicrosoft.com", 
                "end": "2019-08-12T13:00:00Z", 
                "externalAudience": "All"
            }
        }
    }
}
</pre>
<h3 id="h_212102bb-4ad8-4bb8-9c05-1b1197e2a9c9">10. Recover soft-deleted messages</h3>
<hr>
<p>Recovers messages that were soft-deleted.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-recover-messages</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 532px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">message-ids</td>
<td style="width: 532px;">A CSV list of message IDs. Run the py-ews-delete-items command to retrieve the message IDs</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">target-folder-path</td>
<td style="width: 532px;">The folder path to recover the messages to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">target-mailbox</td>
<td style="width: 532px;">The mailbox in which the messages found. If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">is-public</td>
<td style="width: 532px;">Whether the target folder is a Public Folder.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 179px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 481px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">EWS.Items.itemId</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 481px;">The item ID of the recovered item.</td>
</tr>
<tr>
<td style="width: 179px;">EWS.Items.messageId</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 481px;">The message ID of the recovered item.</td>
</tr>
<tr>
<td style="width: 179px;">EWS.Items.action</td>
<td style="width: 80px;">Unknown</td>
<td style="width: 481px;">The action taken on the item. The value will be 'recovered'.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-recover-messages message-ids=&lt;DFVDFmvsCSCS.com&gt; target-folder-path=Moving target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>action</th>
<th>itemId</th>
<th>messageId</th>
</tr>
</thead>
<tbody>
<tr>
<td>recovered</td>
<td>AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA=</td>
<td>&lt;DFVDFmvsCSCS.com&gt;</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "action": "recovered", 
            "itemId": "AAVCSVS1hN2NkLThmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed33wX3aBwCyyVyFtlsUQZfBJebinpkUAAAa2bUBAACyyVyFtlscfxxd/AAA=", 
            "messageId": "&lt;DFVDFmvsCSCS.com&gt;"
        }
    }
}
</pre>
<h3 id="h_4ab168b9-21e9-4ce1-b18c-56bc22c0e0bd">11. Create a folder</h3>
<hr>
<p>Creates a new folder in a specified mailbox.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-create-folder</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 78px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">new-folder-name</td>
<td style="width: 518px;">The name of the new folder.</td>
<td style="width: 78px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">folder-path</td>
<td style="width: 518px;">Path to locate the new folder. Exchange folder ID is also supported.</td>
<td style="width: 78px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">target-mailbox</td>
<td style="width: 518px;">The mailbox in which to create the folder.</td>
<td style="width: 78px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!ews-create-folder folder-path=Inbox new-folder-name="Created Folder" target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<p>Folder Inbox\Created Folder created successfully</p>
<h3 id="h_01b093ea-bc1c-46a3-b694-8cd45effeaa0">12. Mark an item as junk</h3>
<hr>
<p>Marks an item as junk. This is commonly used to block an email address. For more information, see the <a href="https://msdn.microsoft.com/en-us/library/office/dn481311(v=exchg.150).aspx" target="_blank" rel="noopener">Microsoft documentation</a>.<span> </span></p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-mark-item-as-junk</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">item-id</td>
<td style="width: 526px;">The item ID to mark as junk.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">move-items</td>
<td style="width: 526px;">Whether to move the item from the original folder to the junk folder.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">target-mailbox</td>
<td style="width: 526px;">If empty, will use the default mailbox. If you specify a different mailbox, you might need impersonation rights to the mailbox.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!ews-mark-item-as-junk item-id=AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA= move-items=yes target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>action</th>
<th>itemId</th>
</tr>
</thead>
<tbody>
<tr>
<td>marked-as-junk</td>
<td>AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA=</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "action": "marked-as-junk", 
            "itemId": "AAMkcSQ0NmFkOhmZjdmNTZjNTMxNwBGAAAAAAA4kxh+ed3JTJPMPXU3wX3aBwCyyVyFtlsUcsBJebinpkUAAAAAAEMASFDkUAAAfxuiSAAA="
        }
    }
}
</pre>
<h3 id="h_3f9e1f1e-e634-4f92-b2a2-cdca5ca662eb">13. Search for folders</h3>
<hr>
<p>Retrieves information for the folders of the specified mailbox. Only folders with read permissions will be returned. Your visual folders on the mailbox, such as "Inbox", are under the folder "Top of Information Store".</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-find-folders</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 177px;"><strong>Argument Name</strong></th>
<th style="width: 461px;"><strong>Description</strong></th>
<th style="width: 102px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">target-mailbox</td>
<td style="width: 461px;">The mailbox on which to apply the command.</td>
<td style="width: 102px;">Optional</td>
</tr>
<tr>
<td style="width: 177px;">is-public</td>
<td style="width: 461px;">Whether to find Public Folders.</td>
<td style="width: 102px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 296px;"><strong>Path</strong></th>
<th style="width: 96px;"><strong>Type</strong></th>
<th style="width: 348px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">EWS.Folders.name</td>
<td style="width: 96px;">string</td>
<td style="width: 348px;">Folder name.</td>
</tr>
<tr>
<td style="width: 296px;">EWS.Folders.id</td>
<td style="width: 96px;">string</td>
<td style="width: 348px;">Folder ID.</td>
</tr>
<tr>
<td style="width: 296px;">EWS.Folders.totalCount</td>
<td style="width: 96px;">Unknown</td>
<td style="width: 348px;">Number of items in the folder.</td>
</tr>
<tr>
<td style="width: 296px;">EWS.Folders.unreadCount</td>
<td style="width: 96px;">number</td>
<td style="width: 348px;">Number of unread items in the folder.</td>
</tr>
<tr>
<td style="width: 296px;">EWS.Folders.changeKey</td>
<td style="width: 96px;">number</td>
<td style="width: 348px;">Folder change key.</td>
</tr>
<tr>
<td style="width: 296px;">EWS.Folders.childrenFolderCount</td>
<td style="width: 96px;">number</td>
<td style="width: 348px;">Number of sub-folders.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-find-folders target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<pre>root
├── AllContacts
├── AllItems
├── Common Views
├── Deferred Action
├── ExchangeSyncData
├── Favorites
├── Freebusy Data
├── Location
├── MailboxAssociations
├── My Contacts
├── MyContactsExtended
├── People I Know
├── PeopleConnect
├── Recoverable Items
│ ├── Calendar Logging
│ ├── Deletions
│ ── Purges
│ └── Versions
├── Reminders
├── Schedule
├── Sharing
├── Shortcuts
├── Spooler Queue
├── System
├── To-Do Search
├── Top of Information Store
│ ├── Calendar
│ ├── Contacts
│ │ ├── GAL Contacts
│ │ ├── Recipient Cache
│ ├── Conversation Action Settings
│ ├── Deleted Items
│ │ └── Create1
│ ├── Drafts
│ ├── Inbox
...
</pre>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Folders": [    
            {
                "unreadCount": 1, 
                "name": "Inbox", 
                "childrenFolderCount": 1, 
                "totalCount": 44, 
                "changeKey": "**********fefsduQi0", 
                "id": "*******VyFtlFDSAFDSFDAAA="
            }
            ...
        ]
    }
}
</pre>
<h3 id="h_0035899d-fdd0-43b7-bf7b-11a38a2e575a">14. Get items of a folder</h3>
<hr>
<p>Retrieves items from a specified folder in a mailbox. The items are ordered by the item created time, most recent is first.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-get-items-from-folder</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 491px;"><strong>Description</strong></th>
<th style="width: 91px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">folder-path</td>
<td style="width: 491px;">The folder path from which to get the items.</td>
<td style="width: 91px;">Required</td>
</tr>
<tr>
<td style="width: 158px;">limit</td>
<td style="width: 491px;">Maximum number of items to return.</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 158px;">target-mailbox</td>
<td style="width: 491px;">The mailbox on which to apply the command.</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 158px;">is-public</td>
<td style="width: 491px;">Whether the folder is a Public Folder. Default is 'False'.</td>
<td style="width: 91px;">Optional</td>
</tr>
<tr>
<td style="width: 158px;">get-internal-items</td>
<td style="width: 491px;">If the email item contains another email as an attachment (EML or MSG file), whether to retrieve the EML/MSG file attachment. Can be "yes" or "no". Default is "no".</td>
<td style="width: 91px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 349px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 318px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 349px;">EWS.Items.itemId</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">The item ID of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.hasAttachments</td>
<td style="width: 73px;">boolean</td>
<td style="width: 318px;">Whether the email has attachments.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.datetimeReceived</td>
<td style="width: 73px;">date</td>
<td style="width: 318px;">Received time of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.datetimeSent</td>
<td style="width: 73px;">date</td>
<td style="width: 318px;">Sent time of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.headers</td>
<td style="width: 73px;">Unknown</td>
<td style="width: 318px;">Email headers (list).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.sender</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Sender mail address of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.subject</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Subject of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.textBody</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Body of the email (as text).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.size</td>
<td style="width: 73px;">number</td>
<td style="width: 318px;">Email size.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.toRecipients</td>
<td style="width: 73px;">Unknown</td>
<td style="width: 318px;">Email recipients addresses (list).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.receivedBy</td>
<td style="width: 73px;">Unknown</td>
<td style="width: 318px;">Received by address of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.messageId</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Email message ID.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.body</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Body of the email (as HTML).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.FileAttachments.attachmentId</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment ID of file attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.ItemAttachments.attachmentId</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment ID of the item attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.FileAttachments.attachmentName</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment name of the file attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.ItemAttachments.attachmentName</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment name of the item attachment.</td>
</tr>
<tr>
<td style="width: 349px;">Email.Items.ItemAttachments.attachmentName</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment name of the item attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.isRead</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The read status of the email.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-items-from-folder folder-path=Test target-mailbox=test@demistodev.onmicrosoft.com limit=1</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>sender</th>
<th>subject</th>
<th>hasAttachments</th>
<th>datetimeReceived</th>
<th>receivedBy</th>
<th>author</th>
<th>toRecipients</th>
<th>itemId</th>
</tr>
</thead>
<tbody>
<tr>
<td>test2@demistodev.onmicrosoft.com</td>
<td>Get Attachment Email</td>
<td>true</td>
<td>2019-08-11T10:57:37Z</td>
<td>test@demistodev.onmicrosoft.com</td>
<td>test2@demistodev.onmicrosoft.com</td>
<td>test@demistodev.onmicrosoft.com</td>
<td>AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "body": "&lt;html&gt;\r\n&lt;head&gt;\r\n&lt;meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"&gt;\r\n&lt;style type=\"text/css\" style=\"display:none;\"&gt;&lt;!-- P {margin-top:0;margin-bottom:0;} --&gt;&lt;/style&gt;\r\n&lt;/head&gt;\r\n&lt;body dir=\"ltr\"&gt;\r\n&lt;div id=\"divtagdefaultwrapper\" style=\"font-size:12pt;color:#000000;font-family:Calibri,Helvetica,sans-serif;\" dir=\"ltr\"&gt;\r\n&lt;p style=\"margin-top:0;margin-bottom:0\"&gt;Some text inside email&lt;/p&gt;\r\n&lt;/div&gt;\r\n&lt;/body&gt;\r\n&lt;/html&gt;\r\n", 
            "itemId": "AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=", 
            "toRecipients": [
                "test@demistodev.onmicrosoft.com"
            ], 
            "datetimeCreated": "2019-08-11T10:57:37Z", 
            "datetimeReceived": "2019-08-11T10:57:37Z", 
            "author": "test2@demistodev.onmicrosoft.com", 
            "hasAttachments": true, 
            "size": 21435, 
            "subject": "Get Attachment Email", 
            "FileAttachments": [
                {
                    "attachmentName": "atta1.rtf", 
                    "attachmentSHA256": "cd81097bcvdiojf3407a00308b48039e31a44a1c4fdnfkdknce36e4f", 
                    "attachmentType": "FileAttachment", 
                    "attachmentSize": 535, 
                    "attachmentId": "AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAABEgAQAEyq1TB2nKBLpKUiFUJ5Geg=", 
                    "attachmentIsInline": false, 
                    "attachmentLastModifiedTime": "2019-08-11T11:06:02+00:00", 
                    "attachmentContentLocation": null, 
                    "attachmentContentType": "text/rtf", 
                    "originalItemId": "AAFSFSFFtlsUQZfBJebinpkUAAABjKMGAACyyVyFtlsUQZfBJebinpkUAAAsfw+jAAA=", 
                    "attachmentContentId": null
                }
            ], 
            "headers": [
                {
                    "name": "Subject", 
                    "value": "Get Attachment Email"
                },
                ...
                            ], 
            "isRead": true, 
            "messageId": "&lt;message_id&gt;", 
            "receivedBy": "test@demistodev.onmicrosoft.com", 
            "datetimeSent": "2019-08-11T10:57:36Z", 
            "lastModifiedTime": "2019-08-11T11:13:59Z", 
            "mailbox": "test@demistodev.onmicrosoft.com", 
            "importance": "Normal", 
            "textBody": "Some text inside email\r\n", 
            "sender": "test2@demistodev.onmicrosoft.com"
        }
    }
}
</pre>
<h3 id="h_e8f449a2-aecf-4d65-8d04-a38c6d4bfe62">15. Get items</h3>
<hr>
<p>Retrieves items by item ID.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-get-items</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 183px;"><strong>Argument Name</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183px;">item-ids</td>
<td style="width: 457px;">A CSV list of item IDs.</td>
<td style="width: 100px;">Required</td>
</tr>
<tr>
<td style="width: 183px;">target-mailbox</td>
<td style="width: 457px;">The mailbox on which to run the command on.</td>
<td style="width: 100px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 349px;"><strong>Path</strong></th>
<th style="width: 73px;"><strong>Type</strong></th>
<th style="width: 318px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 349px;">EWS.Items.itemId</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">The email item ID.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.hasAttachments</td>
<td style="width: 73px;">boolean</td>
<td style="width: 318px;">Whether the email has attachments.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.datetimeReceived</td>
<td style="width: 73px;">date</td>
<td style="width: 318px;">Received time of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.datetimeSent</td>
<td style="width: 73px;">date</td>
<td style="width: 318px;">Sent time of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.headers</td>
<td style="width: 73px;">Unknown</td>
<td style="width: 318px;">Email headers (list).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.sender</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Sender mail address of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.subject</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Subject of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.textBody</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Body of the email (as text).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.size</td>
<td style="width: 73px;">number</td>
<td style="width: 318px;">Email size.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.toRecipients</td>
<td style="width: 73px;">Unknown</td>
<td style="width: 318px;">Email recipients addresses (list).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.receivedBy</td>
<td style="width: 73px;">Unknown</td>
<td style="width: 318px;">Received by address of the email.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.messageId</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Email message ID.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.body</td>
<td style="width: 73px;">string</td>
<td style="width: 318px;">Body of the email (as HTML).</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.FileAttachments.attachmentId</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment ID of the file attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.ItemAttachments.attachmentId</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment ID of the item attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.FileAttachments.attachmentName</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment name of the file attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.ItemAttachments.attachmentName</td>
<td style="width: 73px;">unknown</td>
<td style="width: 318px;">Attachment name of the item attachment.</td>
</tr>
<tr>
<td style="width: 349px;">EWS.Items.isRead</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The read status of the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.CC</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">Email addresses CC'ed to the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.BCC</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">Email addresses BCC'ed to the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.To</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The recipient of the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.From</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The sender of the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.Subject</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The subject of the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.Text</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The plain-text version of the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.HTML</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The HTML version of the email.</td>
</tr>
<tr>
<td style="width: 349px;">Email.HeadersMap</td>
<td style="width: 73px;">String</td>
<td style="width: 318px;">The headers of the email.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-items item-ids=AAMkADQ0NmFkODFkLWQ4MDEtNDFDFZjNTMxNwBGAAAAAAA4kxhFFAfxw+jAAA= target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<p>Identical outputs to<span> </span><code>ews-get-items-from-folder</code><span> </span>command.</p>
<h3 id="h_88c0edd5-09b0-42a1-a671-b36b73772898">16. Move an item to a different mailbox</h3>
<hr>
<p>Moves an item from one mailbox to a different mailbox.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-move-item-between-mailboxes</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 130px;"><strong>Argument Name</strong></th>
<th style="width: 539px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 130px;">item-id</td>
<td style="width: 539px;">The item ID to move.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 130px;">destination-folder-path</td>
<td style="width: 539px;">The folder in the destination mailbox to which to move the item. You can specify a complex path, for example, "Inbox\Phishing".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 130px;">destination-mailbox</td>
<td style="width: 539px;">The mailbox to which to move the item.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 130px;">source-mailbox</td>
<td style="width: 539px;">The mailbox from which to move the item (conventionally called the "target-mailbox", the target mailbox on which to run the command).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 130px;">is-public</td>
<td style="width: 539px;">Whether the destination folder is a Public Folder. Default is "False".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 224px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 463px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 224px;">EWS.Items.movedToMailbox</td>
<td style="width: 53px;">string</td>
<td style="width: 463px;">The mailbox to which the item was moved.</td>
</tr>
<tr>
<td style="width: 224px;">EWS.Items.movedToFolder</td>
<td style="width: 53px;">string</td>
<td style="width: 463px;">The folder to which the item was moved.</td>
</tr>
<tr>
<td style="width: 224px;">EWS.Items.action</td>
<td style="width: 53px;">string</td>
<td style="width: 463px;">The action taken on the item. The value will be "moved".</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-move-item-between-mailboxes item-id=AAMkAGY3OTQyMzMzLWYxNjktNDE0My05NFSFSyNzBkNABGAAAAAACYCKjWAjq/zTrN6vWSzK4OWAAK2ISFSA= destination-folder-path=Moving destination-mailbox=test@demistodev.onmicrosoft.com source-mailbox=test2@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<p>Item was moved successfully.</p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "movedToMailbox": "test@demistodev.onmicrosoft.com", 
            "movedToFolder": "Moving"
        }
    }
}
</pre>
<h3 id="h_87ca72d4-d98a-462e-9829-c940321663c2">17. Get a folder</h3>
<hr>
<p>Retrieves a single folder.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-get-folder</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 175px;"><strong>Argument Name</strong></th>
<th style="width: 494px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 175px;">target-mailbox</td>
<td style="width: 494px;">The mailbox on which to apply the search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">folder-path</td>
<td style="width: 494px;">The path of the folder to retrieve. If empty, will retrieve the folder "AllItems".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 175px;">is-public</td>
<td style="width: 494px;">Whether the folder is a Public Folder. Default is "False".</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>EWS.Folders.id</td>
<td>string</td>
<td>Folder ID.</td>
</tr>
<tr>
<td>EWS.Folders.name</td>
<td>string</td>
<td>Folder name.</td>
</tr>
<tr>
<td>EWS.Folders.changeKey</td>
<td>string</td>
<td>Folder change key.</td>
</tr>
<tr>
<td>EWS.Folders.totalCount</td>
<td>number</td>
<td>Total number of emails in the folder.</td>
</tr>
<tr>
<td>EWS.Folders.childrenFolderCount</td>
<td>number</td>
<td>Number of sub-folders.</td>
</tr>
<tr>
<td>EWS.Folders.unreadCount</td>
<td>number</td>
<td>Number of unread emails in the folder.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-get-folder folder-path=demistoEmail target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>changeKey</th>
<th>childrenFolderCount</th>
<th>id</th>
<th>name</th>
<th>totalCount</th>
<th>unreadCount</th>
</tr>
</thead>
<tbody>
<tr>
<td>***yFtCdJSH</td>
<td>0</td>
<td>AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NlsjflsjfSF=</td>
<td>demistoEmail</td>
<td>1</td>
<td>0</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Folders": {
            "unreadCount": 0, 
            "name": "demistoEmail", 
            "childrenFolderCount": 0, 
            "totalCount": 1, 
            "changeKey": "***yFtCdJSH", 
            "id": "AAMkADQ0NmFkODFkLWQ4MDEtNDE4Mi1hN2NlsjflsjfSF="
        }
    }
}
</pre>
<h3 id="h_9e97c090-dd51-4775-9286-d5ce0005a4a7">18. Initiate a compliance search</h3>
<hr>
<p>Starts a new compliance search. For additional information about new compliance searches, see the Additional Information section.</p>
<h5>Required Permissions</h5>
<p>You need to be assigned permissions in the Office 365 Security &amp; Compliance Center before you can use these commands. For more information, see<span> </span><a href="https://go.microsoft.com/fwlink/p/?LinkId=511920" rel="nofollow">Permissions in Office 365 Security &amp; Compliance Center</a>.</p>
<h5>Base Command</h5>
<p><code>ews-o365-start-compliance-search</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 233px;"><strong>Argument Name</strong></th>
<th style="width: 373px;"><strong>Description</strong></th>
<th style="width: 134px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">query</td>
<td style="width: 373px;">Query to use to find emails.</td>
<td style="width: 134px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 297px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 297px;">EWS.ComplianceSearch.Name</td>
<td style="width: 72px;">string</td>
<td style="width: 371px;">The name of the compliance search.</td>
</tr>
<tr>
<td style="width: 297px;">EWS.ComplianceSearch.Status</td>
<td style="width: 72px;">string</td>
<td style="width: 371px;">The status of the compliance search.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-o365-start-compliance-search query="subject:"Wanted Email""</pre>
<h5>Human Readable Output</h5>
<p>Search started: DemistoSearch67e67371d0004c46bebfa3219b5a14bf</p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "ComplianceSearch": {
            "Status": "Starting", 
            "Name": "DemistoSearch67e67371d0004c46bebfa3219b5a14bf"
        }
    }
}
</pre>
<h3 id="h_94cf108b-10cd-452b-90f1-42caace65edb">19. Get the status and results of a compliance search</h3>
<hr>
<p>Returns the status and results of a compliance search. For additional information about new compliance searches, see the Additional Information section.</p>
<h5>Required Permissions</h5>
<p>You need to be assigned permissions in the Office 365 Security &amp; Compliance Center before you can use this cmdlet. For more information, see<span> </span><a href="https://go.microsoft.com/fwlink/p/?LinkId=511920" rel="nofollow">Permissions in Office 365 Security &amp; Compliance Center</a>.</p>
<h5>Base Command</h5>
<p><code>ews-o365-get-compliance-search</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 201px;"><strong>Argument Name</strong></th>
<th style="width: 422px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 201px;">search-name</td>
<td style="width: 422px;">The name of the compliance search.</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 288px;"><strong>Path</strong></th>
<th style="width: 98px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 288px;">EWS.ComplianceSearch.Status</td>
<td style="width: 98px;">Unknown</td>
<td style="width: 354px;">The status of the compliance search.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-o365-get-compliance-search search-name=DemistoSearch67e67371d0004c46bebfa3219b5a14bf</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>Location</th>
<th>Item count</th>
<th>Total size</th>
</tr>
</thead>
<tbody>
<tr>
<td>test@demistodev.onmicrosoft.com</td>
<td>0</td>
<td>0</td>
</tr>
<tr>
<td>...</td>
<td> </td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "ComplianceSearch": {
            "Status": "Completed", 
            "Name": "DemistoSearch67e67371d0004c46bebfa3219b5a14bf"
        }
    }
}
</pre>
<h3 id="h_dae1d9a7-d618-4cee-9104-1ac1e7b55076">20. Purge compliance search results</h3>
<hr>
<p>Purges the results found in the compliance search. For additional information about new compliance searches, see the Additional Information section.</p>
<h5>Required Permissions</h5>
<p>You need to be assigned permissions in the Office 365 Security &amp; Compliance Center before you can use this cmdlet. For more information, see<span> </span><a href="https://go.microsoft.com/fwlink/p/?LinkId=511920" rel="nofollow">Permissions in Office 365 Security &amp; Compliance Center</a>.</p>
<h5>Base Command</h5>
<p><code>ews-o365-purge-compliance-search-results</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 202px;"><strong>Argument Name</strong></th>
<th style="width: 421px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 202px;">search-name</td>
<td style="width: 421px;">The name of the compliance search.</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 307px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 307px;">EWS.ComplianceSearch.Status</td>
<td style="width: 62px;">string</td>
<td style="width: 371px;">The status of the compliance search.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-o365-purge-compliance-search-results search-name=DemistoSearch67e67371d0004c46bebfa3219b5a14bf</pre>
<h5>Human Readable Output</h5>
<p>Search DemistoSearch67e67371d0004c46bebfa3219b5a14bf status: Purging</p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "ComplianceSearch": {
            "Status": "Purging", 
            "Name": "DemistoSearch67e67371d0004c46bebfa3219b5a14bf"
        }
    }
}
</pre>
<h3 id="h_628a65d3-ced0-44ff-94f5-e76de66fab82">21. Remove a compliance search</h3>
<hr>
<p>Removes the compliance search. For additional information about new compliance searches, see the Additional Information section.</p>
<h5>Required Permissions</h5>
<p>You need to be assigned permissions in the Office 365 Security &amp; Compliance Center before you can use this cmdlet. For more information, see<span> </span><a href="https://go.microsoft.com/fwlink/p/?LinkId=511920" rel="nofollow">Permissions in Office 365 Security &amp; Compliance Center</a>.</p>
<h5>Base Command</h5>
<p><code>ews-o365-remove-compliance-search</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 205px;"><strong>Argument Name</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 205px;">search-name</td>
<td style="width: 418px;">The name of the compliance search.</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">EWS.ComplianceSearch.Status</td>
<td style="width: 65px;">string</td>
<td style="width: 371px;">The status of the compliance search.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-o365-remove-compliance-search search-name=DemistoSearch67e67371d0004c46bebfa3219b5a14bf</pre>
<h5>Human Readable Output</h5>
<p>Search DemistoSearch67e67371d0004c46bebfa3219b5a14bf status: Removed</p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "ComplianceSearch": {
            "Status": "Removed", 
            "Name": "DemistoSearch67e67371d0004c46bebfa3219b5a14bf"
        }
    }
}
</pre>
<h3 id="h_acedbb5d-c8a1-4ca0-910c-3ccfebbb90f9">22. Get the purge status of a compliance search</h3>
<hr>
<p>Checks the status of the purge operation on the compliance search. For additional information about new compliance searches, see the Additional Information section.</p>
<h5>Required Permissions</h5>
<p>You need to be assigned permissions in the Office 365 Security &amp; Compliance Center before you can use this cmdlet. For more information, see<span> </span><a href="https://go.microsoft.com/fwlink/p/?LinkId=511920" rel="nofollow">Permissions in Office 365 Security &amp; Compliance Center</a>.</p>
<h5>Base Command</h5>
<p><code>ews-o365-get-compliance-search-purge-status</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 202px;"><strong>Argument Name</strong></th>
<th style="width: 421px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 202px;">search-name</td>
<td style="width: 421px;">The name of the compliance search.</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 291px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">EWS.ComplianceSearch.Status</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 354px;">The status of the compliance search.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-o365-get-compliance-search-purge-status search-name=DemistoSearch67e67371d0004c46bebfa3219b5a14bf</pre>
<h5>Human Readable Output</h5>
<p>Search DemistoSearch67e67371d0004c46bebfa3219b5a14bf status: Purged</p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "ComplianceSearch": {
            "Status": "Purged", 
            "Name": "DemistoSearch67e67371d0004c46bebfa3219b5a14bf"
        }
    }
}
</pre>
<h3 id="h_02b7cb8e-f9c9-44a9-a0c7-6989b9232b46">23. Get auto-discovery information</h3>
<hr>
<p>Returns the auto-discovery information. Can be used to manually configure the Exchange Server.</p>
<h5>Base Command</h5>
<p><code>ews-get-autodiscovery-config</code></p>
<h5>Input</h5>
<p>There are no input arguments for this command.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!ews-get-autodiscovery-config</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>api_version</th>
<th>auth_type</th>
<th>build</th>
<th>service_endpoint</th>
</tr>
</thead>
<tbody>
<tr>
<td>Exchange2016</td>
<td>###</td>
<td>
<strong>.</strong>.****.**</td>
<td>https://outlook.office365.com/EWS/Exchange.asmx</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_d91ca450-7004-4a19-a88d-840389b21556">24. Expand a distribution list</h3>
<hr>
<p>Expands a distribution list to display all members. By default, expands only the first layer of the distribution list. If recursive-expansion is "True", the command expands nested distribution lists and returns all members.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights required. In order to perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-expand-group</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 482px;"><strong>Description</strong></th>
<th style="width: 85px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">email-address</td>
<td style="width: 482px;">Email address of the group to expand.</td>
<td style="width: 85px;">Required</td>
</tr>
<tr>
<td style="width: 173px;">recursive-expansion</td>
<td style="width: 482px;">Whether to enable recursive expansion. Default is "False".</td>
<td style="width: 85px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!ews-expand-group email-address="TestPublic" recursive-expansion="False"</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>displayName</th>
<th>mailbox</th>
<th>mailboxType</th>
</tr>
</thead>
<tbody>
<tr>
<td>John Wick</td>
<td>john@wick.com</td>
<td>Mailbox</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS.ExpandGroup": {
        "name": "TestPublic", 
        "members": [
            {
                "mailboxType": "Mailbox", 
                "displayName": "John Wick", 
                "mailbox": "john@wick.com"
            }
        ]
    }
}
</pre>
<h3 id="h_e278dc88-b4b0-4330-b849-3069b770e5ba">25. Mark items as read</h3>
<hr>
<p>Marks items as read or unread.</p>
<h5>Required Permissions</h5>
<p>Impersonation rights are required. To perform actions on the target mailbox of other users, the service account must be part of the ApplicationImpersonation role.</p>
<h5>Base Command</h5>
<p><code>ews-mark-items-as-read</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 167px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">item-ids</td>
<td style="width: 502px;">A CSV list of item IDs.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 167px;">operation</td>
<td style="width: 502px;">How to mark the item. Can be "read" or "unread". Default is "read".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">target-mailbox</td>
<td style="width: 502px;">The mailbox on which to run the command. If empty, the command will be applied on the default mailbox.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 231px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 231px;">EWS.Items.action</td>
<td style="width: 66px;">String</td>
<td style="width: 443px;">The action that was performed on the item.</td>
</tr>
<tr>
<td style="width: 231px;">EWS.Items.itemId</td>
<td style="width: 66px;">String</td>
<td style="width: 443px;">The ID of the item.</td>
</tr>
<tr>
<td style="width: 231px;">EWS.Items.messageId</td>
<td style="width: 66px;">String</td>
<td style="width: 443px;">The message ID of the item.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!ews-mark-items-as-read item-ids=AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= operation=read target-mailbox=test@demistodev.onmicrosoft.com</pre>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>action</th>
<th>itemId</th>
<th>messageId</th>
</tr>
</thead>
<tbody>
<tr>
<td>marked-as-read</td>
<td>AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA=</td>
<td>&lt;message_id&gt;</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Example</h5>
<pre>{
    "EWS": {
        "Items": {
            "action": "marked-as-read", 
            "itemId": "AAMkADQ0NFSffU3wX3aBwCyyVyFtlsUQZfBJebinpkUAAABjKMnpkUAAAfxw+jAAA= ", 
            "messageId": "&lt;message_id&gt;"
        }
    }
}
</pre>
<h2>Additional Information</h2>
<hr>
<h4>EWS Permissions</h4>
<p>To perform actions on mailboxes of other users, and to execute searches on the Exchange server, you need specific permissions. For a comparison between Delegate and Impersonation permissions, see the<span> </span><a href="https://blogs.msdn.microsoft.com/exchangedev/2009/06/15/exchange-impersonation-vs-delegate-access/" rel="nofollow">Microsoft documentation</a>.</p>
<table style="width: 750px;">
<thead>
<tr>
<th>Permission</th>
<th>Use Case</th>
<th>How to Configure</th>
</tr>
</thead>
<tbody>
<tr>
<td>Delegate</td>
<td>One-to-one relationship between users.</td>
<td>Read more<span> </span><a href="https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/delegate-access-and-ews-in-exchange" rel="nofollow">here</a>.</td>
</tr>
<tr>
<td>Impersonation</td>
<td>A single account needs to access multiple mailboxes.</td>
<td>Read more<span> </span><a href="https://docs.microsoft.com/en-us/exchange/client-developer/exchange-web-services/how-to-configure-impersonation" rel="nofollow">here</a>.</td>
</tr>
<tr>
<td>eDiscovery</td>
<td>Search the Exchange server.</td>
<td>Read more<span> </span><a href="https://docs.microsoft.com/en-us/Exchange/policy-and-compliance/ediscovery/assign-permissions?view=exchserver-2019" rel="nofollow">here</a>.</td>
</tr>
<tr>
<td>Compliance Search</td>
<td>Perform searches across mailboxes and get an estimate of the results.</td>
<td>Read more<span> </span><a href="https://docs.microsoft.com/en-us/office365/securitycompliance/permissions-in-the-security-and-compliance-center" rel="nofollow">here</a>.</td>
</tr>
</tbody>
</table>
<p> </p>
<h4>New-Compliance Search</h4>
<p>The EWS v2 integration uses remote ps-session to run commands of compliance search as part of Office 365. To check if your account can connect to Office 365 Security &amp; Compliance Center via powershell, check the following<span> </span><a href="https://docs.microsoft.com/en-us/powershell/exchange/office-365-scc/connect-to-scc-powershell/connect-to-scc-powershell?view=exchange-ps" rel="nofollow">steps</a>. New-Compliance search is a long-running task which has no limitation of searched mailboxes and therefore the suggestion is to use<span> </span><code>Office 365 Search and Delete</code>playbook. New-Compliance search returns statistics of matched content search query and doesn't return preview of found emails in contrast to<span> </span><code>ews-search-mailboxes</code><span> </span>command.</p>
