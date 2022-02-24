<p>
Mimecast unified email management offers cloud email services for email security, continuity and archiving emails. Please read detailed instructions in order to understand how to set the integration's parameters.
</p>
<h2>Use Cases</h2>
<ul>
<li>Mimecast account administration.</li>
</ul><h2>Detailed Description</h2>
<ul>
<li>1. In order to refresh token / discover auth types of the account / create new access & secret keys, you are required to provide: App ID, Account email address & password.
These parameters support the following integration commands:
mimecast-login -> fetches new access key & secret key
mimecast-discover -> lists supported auth types of user
mimecast-refresh-token -> refreshes the validity duration of access key & secret key (3 days)
<li>2. In order to use the rest of the commands, you are required to provide: App ID, App Key, Access Key, and Secret
 Key. For detailed information about creating these fields, please refer to the <a href="https://integrations.mimecast.com/documentation/api-overview/authentication-and-authorization/" target="_self">Mimecast Documentation</a>.</li>
<li>3. Fetch Incidents - the integration has the ability to fetch 3 types of incidents: url, attachment & impersonation.
In order to activate them first tick "fetch incidents" box, then tick the relevant boxes for each fetch type you want.
</ul><h2>Fetch Incidents</h2>
<p>Populate this section with Fetch incidents data</p>
<h2>Configure MimecastV2 on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for MimecastV2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>BaseUrl - API url including region, For example https://eu-api.mimecast.com</strong></li>
   <li><strong>App ID</strong></li>
   <li><strong>User Email Address (Use for auto token refresh)</strong></li>
   <li><strong>Password</strong></li>
   <li><strong>App key</strong></li>
   <li><strong>AccessKey</strong></li>
   <li><strong>SecretKey</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Use system proxy settings</strong></li>
   <li><strong>Fetch incidents</strong></li>
   <li><strong>Fetch URL incidents</strong></li>
   <li><strong>Fetch attachment incidents</strong></li>
   <li><strong>Fetch impersonation incidents</strong></li>
   <li><strong>Incident type</strong></li>
   <li><strong>Hours before first fetch to retrieve incidents</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li><a href="#mimecast-query" target="_self">Query mimecast emails: mimecast-query</a></li>
  <li><a href="#mimecast-list-blocked-sender-policies" target="_self">List all existing mimecast blocked sender policies: mimecast-list-blocked-sender-policies</a></li>
  <li><a href="#mimecast-get-policy" target="_self">Get a blocked sender policy by ID: mimecast-get-policy</a></li>
  <li><a href="#mimecast-create-policy" target="_self">Create a Blocked Sender Policy: mimecast-create-policy</a></li>
  <li><a href="#mimecast-delete-policy" target="_self">Delete a Blocked Sender Policy: mimecast-delete-policy</a></li>
  <li><a href="#mimecast-manage-sender" target="_self">Permit or block a specific sender: mimecast-manage-sender</a></li>
  <li><a href="#mimecast-list-managed-url" target="_self">Get a list of all managed URLs: mimecast-list-managed-url</a></li>
  <li><a href="#mimecast-create-managed-url" target="_self">Create a managed URL on Mimecast: mimecast-create-managed-url</a></li>
  <li><a href="#mimecast-list-messages" target="_self">Get a list of messages for a given user: mimecast-list-messages</a></li>
  <li><a href="#mimecast-get-attachment-logs" target="_self">Returns Attachment Protect logs for a Mimecast customer account: mimecast-get-attachment-logs</a></li>
  <li><a href="#mimecast-get-url-logs" target="_self">Returns URL protect logs for a Mimecast customer account: mimecast-get-url-logs</a></li>
  <li><a href="#mimecast-get-impersonation-logs" target="_self">Returns Impersonation Protect logs for a Mimecast customer account: mimecast-get-impersonation-logs</a></li>
  <li><a href="#mimecast-url-decode" target="_self">Decodes a given url from mimecast: mimecast-url-decode</a></li>
  <li><a href="#mimecast-discover" target="_self">discover authentication types that are supported for your account and which base URL to use for the requesting user: mimecast-discover</a></li>
  <li><a href="#mimecast-refresh-token" target="_self">Refresh access key validity: mimecast-refresh-token</a></li>
  <li><a href="#mimecast-login" target="_self">Login to generate Access Key and  Secret Key: mimecast-login</a></li>
  <li><a href="#mimecast-get-message" target="_self">Get the contents or metadata of a given message: mimecast-get-message</a></li>
  <li><a href="#mimecast-download-attachments" target="_self">Download attachments from a specified message: mimecast-download-attachments</a></li>
  <li><a href="#mimecast-find-groups" target="_self">Returns the list of groups according to the specified query: mimecast-find-groups</a></li>
  <li><a href="#mimecast-get-group-members" target="_self">Returns the members list for the specified group: mimecast-get-group-members</a></li>
  <li><a href="#mimecast-add-group-member" target="_self">Adds a user to a group. The email_address and domain_adddress arguments are optional, but one of them must be supplied: mimecast-add-group-member</a></li>
  <li><a href="#mimecast-remove-group-member" target="_self">Removes a user from a group. The email_address and domain_adddress arguments are optional, but one of them must be supplied: mimecast-remove-group-member</a></li>
  <li><a href="#mimecast-create-group" target="_self">Creates a new Mimecast group: mimecast-create-group</a></li>
  <li><a href="#mimecast-update-group" target="_self">Updates an existing Mimecast group: mimecast-update-group</a></li>
  <li><a href="#mimecast-create-remediation-incident" target="_self">Creates a new Mimecast remediation incident: mimecast-create-remediation-incident</a></li>
  <li><a href="#mimecast-get-remediation-incident" target="_self">Returns a Mimecast remediation incident: mimecast-get-remediation-incident</a></li>
  <li><a href="#mimecast-search-file-hash" target="_self">Searches for one or more file hashes in the account. Maximum is 100: mimecast-search-file-hash</a></li>
  <li><a href="#mimecast-update-policy" target="_self">Update a Blocked Sender Policy: mimecast-update-policy</a></li>

</ol>
<h3 id="mimecast-query">1. mimecast-query</h3>
<hr>
<p>Query mimecast emails</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-query</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Archive/Search/Read.</li>
    <li>or Mimecast user with delegate permissions to address or user.</li>
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
      <td>queryXml</td>
      <td>The query string xml for the search using Mimecast Unified Search Experience (MUSE) - read more on https://community.mimecast.com/docs/DOC-2262, using this will override other query arguments</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>text</td>
      <td>Search for this text in messages</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>dryRun</td>
      <td>Will not execute the query, but just return the query string built</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>date</td>
      <td>Search in specific dates only (default is all mails fomr)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>dateFrom</td>
      <td>Search emails from date, format YYYY-MM-DDTHH:MM:SZ (e.g. 2015-09-21T23:00:00Z)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>dateTo</td>
      <td>Search emails to date, format YYYY-MM-DDTHH:MM:SZ (e.g. 2015-09-21T23:00:00Z)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>sentTo</td>
      <td>Filter on messages to a specific address</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>sentFrom</td>
      <td>Filter on messages from a specific address</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subject</td>
      <td>Search email by subject, will override the text argument</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attachmentType</td>
      <td>These are the attachment types available: optional - messages with and without attachments any - messages with any attachment documents - messages with doc, dot, docx, docm, dotx, dotm, pdf, rtf, html attachments spreadsheets - messages with xls, xlt, xlsx, xlsm, xltx, xltm, xlsb, xlam, csv attachments presentations - messages with ppt, pptx, pptm, potx, potm, ppam, ppsx, ppsm, sldx, sldm, thms, pps attachments text - messages with txt, text, html, log attachments images - messages with jpg, jpeg, png, bmp, gif, psd, tif, tiff attachments media - messages with mp3, mp4, m4a, mpg, mpeg, avi, wav, aac, wma, mov attachments zips - messages with zip, rar, cab, gz, gzip, 7z attachments none - No attachments are to be present in the results</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>attachmentText</td>
      <td>Search for text in attachments</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>body</td>
      <td>Search email by text in body, will override the text and subject arguments</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>pageSize</td>
      <td>Sets the number of results to return per page (default 25)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>startRow</td>
      <td>Sets the result to start returning results (default 0)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>active</td>
      <td>Defines if the search should query recently received messages that are not fully processed yet (default false). You can search by mailbox and date time across active messages</td>
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
      <td>Mimecast.Message.ID</td>
      <td>string</td>
      <td>Message ID</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Subject</td>
      <td>string</td>
      <td>Message subject</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Sender</td>
      <td>string</td>
      <td>Message sender address</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Recipient</td>
      <td>string</td>
      <td>Message recipient address</td>
    </tr>
    <tr>
      <td>Mimecast.Message.RecievedDate</td>
      <td>date</td>
      <td>Message received date</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Size</td>
      <td>number</td>
      <td>The size of the message in bytes</td>
    </tr>
    <tr>
      <td>Mimecast.Message.AttachmentCount</td>
      <td>number</td>
      <td>Message attachments count</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Status</td>
      <td>string</td>
      <td>Message status</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-query</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-list-blocked-sender-policies">2. mimecast-list-blocked-sender-policies</h3>
<hr>
<p>List all existing mimecast blocked sender policies</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-list-blocked-sender-policies</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Gateway/Policies/Read.</li>
</ul>
<h5>Input</h5>
There are no input arguments for this command.
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
      <td>Mimecast.Policy.ID</td>
      <td>string</td>
      <td>Policy ID</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Address</td>
      <td>string</td>
      <td>Block Sender by email address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Domain</td>
      <td>string</td>
      <td>Block Sender by domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Group</td>
      <td>string</td>
      <td>Block Sender by group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Bidirectional</td>
      <td>boolean</td>
      <td>Blocked policy is Bidirectional or not</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Address</td>
      <td>string</td>
      <td>Block emails to Receiver type address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Domain</td>
      <td>string</td>
      <td>Block emails to Receiver type domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Group</td>
      <td>string</td>
      <td>Block emails to Receiver type group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.FromDate</td>
      <td>date</td>
      <td>Policy validation start date</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.ToDate</td>
      <td>date</td>
      <td>Policy expiration date</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Type</td>
      <td>string</td>
      <td>Block emails to Sender type</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Type</td>
      <td>string</td>
      <td>Block emails to Receiver type</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-list-blocked-sender-policies
</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-get-policy">3. mimecast-get-policy</h3>
<hr>
<p>Get a blocked sender policy by ID</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-policy</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
   <li>Mimecast administrator with at least one of the following permissions: Gateway/Policies/Read.</li>
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
      <td>policyID</td>
      <td>Filter by policy ID</td>
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
      <td>Mimecast.Policy.ID</td>
      <td>string</td>
      <td>Policy ID</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Address</td>
      <td>string</td>
      <td>Block Sender by email address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Domain</td>
      <td>string</td>
      <td>Block Sender by domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Group</td>
      <td>string</td>
      <td>Block Sender by group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Bidirectional</td>
      <td>boolean</td>
      <td>Blocked policy is Bidirectional or not</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Address</td>
      <td>string</td>
      <td>Block emails to Receiver type address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Domain</td>
      <td>string</td>
      <td>Block emails to Receiver type domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Group</td>
      <td>string</td>
      <td>Block emails to Receiver type group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Fromdate</td>
      <td>date</td>
      <td>Policy validation start date</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Todate</td>
      <td>date</td>
      <td>Policy expiration date</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-policy policyID=XXXX </code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-create-policy">4. mimecast-create-policy</h3>
<hr>
<p>Create a Blocked Sender Policy</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-create-policy</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Gateway/Policies/Edit.</li>
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
      <td>description</td>
      <td>Policy description</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>fromPart</td>
      <td>Addresses based on</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromType</td>
      <td>Blocked Sender type</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>fromValue</td>
      <td>Required if fromType is one of email domain, profile group, individual email address. Expected values: If fromType is email_domain, a domain name without the @ symbol. If fromType is profile_group, the ID of the profile group. If fromType is individual_email_address, an email address.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>toType</td>
      <td>Receiver type</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>toValue</td>
      <td>Required if fromType is one of email domain, profile group, individual email address. Expected values: If toType is email_domain, a domain name without the @ symbol. If toType is profile_group, the ID of the profile group. If toType is individual_email_address, an email address.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>option</td>
      <td>The block option, must be one of: no_action, block_sender.</td>
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
      <td>Mimecast.Policy.ID</td>
      <td>string</td>
      <td>Policy ID</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Address</td>
      <td>string</td>
      <td>Block Sender by email address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Domain</td>
      <td>string</td>
      <td>Block Sender by domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Group</td>
      <td>string</td>
      <td>Block Sender by group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Bidirectional</td>
      <td>boolean</td>
      <td>Blocked policy is Bidirectional or not</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Address</td>
      <td>string</td>
      <td>Block emails to Receiver type address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Domain</td>
      <td>string</td>
      <td>Block emails to Receiver type domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Group</td>
      <td>string</td>
      <td>Block emails to Receiver type group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Fromdate</td>
      <td>date</td>
      <td>Policy validation start date</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Todate</td>
      <td>date</td>
      <td>Policy expiration date</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-create-policy fromType=email_domain description="Description for group" option=block_sender toType=address_attribute_value</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-delete-policy">5. mimecast-delete-policy</h3>
<hr>
<p>Delete a Blocked Sender Policy</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-delete-policy</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Gateway/Policies/Edit.</li>
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
      <td>policyID</td>
      <td>Policy ID</td>
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
      <td>Mimecast.Policy.ID</td>
      <td>string</td>
      <td>Policy ID</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-delete-policy policyID=XXXX</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-manage-sender">6. mimecast-manage-sender</h3>
<hr>
<p>Permit or block a specific sender</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-manage-sender</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Gateway/Managed Senders/Edit.</li>
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
      <td>sender</td>
      <td>The email address of sender to permit or block</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>recipient</td>
      <td>The email address of recipient to permit or block</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>action</td>
      <td>Choose to either "permit" (to bypass spam checks) or "block" (to reject the email)</td>
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
      <td>Mimecast.Managed.Sender</td>
      <td>string</td>
      <td>The email address of the sender</td>
    </tr>
    <tr>
      <td>Mimecast.Managed.Recipient</td>
      <td>string</td>
      <td>The email address of the recipient</td>
    </tr>
    <tr>
      <td>Mimecast.Managed.Action</td>
      <td>string</td>
      <td>Chosen action</td>
    </tr>
    <tr>
      <td>Mimecast.Managed.ID</td>
      <td>string</td>
      <td>The Mimecast secure ID of the managed sender object.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-manage-sender action=block recipient=recipient@demisto.com sender=sender@demisto.com</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-list-managed-url">7. mimecast-list-managed-url</h3>
<hr>
<p>Get a list of all managed URLs</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-list-managed-url</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Services/
    Targeted Threat Protection - URL Protect /Edit.</li>
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
      <td>url</td>
      <td>Filter results by specific URL</td>
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
      <td>Mimecast.URL.Domain</td>
      <td>string</td>
      <td>The managed domain</td>
    </tr>
    <tr>
      <td>Mimecast.URL.Disablelogclick</td>
      <td>boolean</td>
      <td>If logging of user clicks on the URL is disabled</td>
    </tr>
    <tr>
      <td>Mimecast.URL.Action</td>
      <td>string</td>
      <td>Either block of permit</td>
    </tr>
    <tr>
      <td>Mimecast.URL.Path</td>
      <td>string</td>
      <td>The path of the managed URL</td>
    </tr>
    <tr>
      <td>Mimecast.URL.matchType</td>
      <td>string</td>
      <td>Either explicit - applies to the full URL or domain - applies to all URL values in the domain</td>
    </tr>
    <tr>
      <td>Mimecast.URL.ID</td>
      <td>string</td>
      <td>The Mimecast secure ID of the managed URL</td>
    </tr>
    <tr>
      <td>Mimecast.URL.disableRewrite</td>
      <td>boolean</td>
      <td>If rewriting of this URL in emails is disabled</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-list-managed-url</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-create-managed-url">8. mimecast-create-managed-url</h3>
<hr>
<p>Create a managed URL on Mimecast</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-create-managed-url</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Services/
    Targeted Threat Protection - URL Protect /Edit.</li>
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
      <td>url</td>
      <td>The URL to block or permit. Do not include a fragment (#).</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>action</td>
      <td>Set to "block" to block list the URL, "permit" to add to allow list</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>matchType</td>
      <td>Set to "explicit" to block or permit only instances of the full URL. Set to "domain" to block or permit any URL with the same domain</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>disableRewrite</td>
      <td>Disable rewriting of this URL in emails. Applies only if action = "permit". Default false</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>comment</td>
      <td>Add a comment about the managed URL</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>disableUserAwareness</td>
      <td>Disable User Awareness challenges for this URL. Applies only if action = "permit". Default false</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>disableLogClick</td>
      <td>Disable logging of user clicks on the URL. Default is false</td>
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
      <td>Mimecast.URL.Domain</td>
      <td>string</td>
      <td>The managed domain</td>
    </tr>
    <tr>
      <td>Mimecast.URL.Action</td>
      <td>string</td>
      <td>Either block of permit</td>
    </tr>
    <tr>
      <td>Mimecast.URL.disableLogClick</td>
      <td>string</td>
      <td>If logging of user clicks on the URL is disabled</td>
    </tr>
    <tr>
      <td>Mimecast.URL.matchType</td>
      <td>string</td>
      <td>Either explicit - applies to the full URL or domain - applies to all URL values in the domain</td>
    </tr>
    <tr>
      <td>Mimecast.URL.ID</td>
      <td>string</td>
      <td>The Mimecast secure ID of the managed URL</td>
    </tr>
    <tr>
      <td>Mimecast.URL.disableRewrite</td>
      <td>boolean</td>
      <td>If rewriting of this URL in emails is disabled</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-create-managed-url action=block url="www.not-demisto.com"</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-list-messages">9. mimecast-list-messages</h3>
<hr>
<p>Get a list of messages for a given user</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-list-messages</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Archive/Search/Read.</li>
    <li>or Mimecast user with delegate permissions to address or user.</li>
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
      <td>mailbox</td>
      <td>The email address to return the message list for</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>startTime</td>
      <td>The start date of messages to return, in the following format, 2015-11-16T14:49:18+0000. Default is the last calendar month</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>endTime</td>
      <td>The end date of messages to return, in the following format, 2015-11-16T14:49:18+0000. Default is the end of the current day</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>view</td>
      <td>The message list type, must be one of: inbox or sent, default is inbox</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>subject</td>
      <td>Filter by message subject</td>
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
      <td>Mimecast.Message.Subject</td>
      <td>string</td>
      <td>Message Subject</td>
    </tr>
    <tr>
      <td>Mimecast.Message.ID</td>
      <td>string</td>
      <td>Message ID</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Size</td>
      <td>number</td>
      <td>The size of the message in bytes</td>
    </tr>
    <tr>
      <td>Mimecast.Message.RecievedDate</td>
      <td>date</td>
      <td>The date the message was received</td>
    </tr>
    <tr>
      <td>Mimecast.Message.From</td>
      <td>string</td>
      <td>The mail Sender</td>
    </tr>
    <tr>
      <td>Mimecast.Message.AttachmentCount</td>
      <td>string</td>
      <td>The number of attachments on the message</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-list-messages</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-get-attachment-logs">10. mimecast-get-attachment-logs</h3>
<hr>
<p>Returns Attachment Protect logs for a Mimecast customer account</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-attachment-logs</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Monitoring/Attachment Protection/Read.</li>
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
      <td>resultsNumber</td>
      <td>The number of results to request. Default is all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromDate</td>
      <td>Start date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is the start of the current day</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>toDate</td>
      <td>End date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is time of request</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>resultType</td>
      <td>Filters logs by scan result, default is malicious</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of results to return.</td>
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
      <td>Mimecast.AttachmentLog.Result</td>
      <td>string</td>
      <td>The result of the attachment analysis: clean, malicious, unknown, or timeout</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.Date</td>
      <td>date</td>
      <td>The time at which the attachment was released from the sandbox</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.Sender</td>
      <td>string</td>
      <td>The sender of the attachment</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.FileName</td>
      <td>string</td>
      <td>The file name of the original attachment</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.Action</td>
      <td>string</td>
      <td>The action triggered for the attachment</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.Recipient</td>
      <td>string</td>
      <td>The address of the user that received the attachment</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.FileType</td>
      <td>string</td>
      <td>The file type of the attachment</td>
    </tr>
    <tr>
      <td>Mimecast.AttachmentLog.Route</td>
      <td>string</td>
      <td>The route of the original email containing the attachment, either: inbound, outbound, internal, or external</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-attachment-logs</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-get-url-logs">11. mimecast-get-url-logs</h3>
<hr>
<p>Returns URL protect logs for a Mimecast customer account</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-url-logs</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Monitoring/URL Protection/Read.</li>
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
      <td>resultsNumber</td>
      <td>The number of results to request. Default is all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromDate</td>
      <td>Start date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is the start of the current day</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>toDate</td>
      <td>End date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is time of request</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>resultType</td>
      <td>Filters logs by scan result, default is all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of results to return.</td>
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
      <td>Mimecast.UrlLog.Category</td>
      <td>string</td>
      <td>The category of the URL clicked</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.UserAddress</td>
      <td>string</td>
      <td>The email address of the user who clicked the link</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.URL</td>
      <td>string</td>
      <td>The url clicked</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.Awareness</td>
      <td>string</td>
      <td>The action taken by the user if user awareness was applied</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.AdminOverride</td>
      <td>string</td>
      <td>The action defined by the administrator for the URL</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.Date</td>
      <td>date</td>
      <td>The date that the URL was clicked</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.Result</td>
      <td>string</td>
      <td>The result of the URL scan</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.Action</td>
      <td>string</td>
      <td>The action that was taken for the click</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog.Route</td>
      <td>string</td>
      <td>The route of the original email containing the attachment, either: inbound, outbound, internal, or external</td>
    </tr>
    <tr>
      <td>Mimecast.UrlLog. userOverride</td>
      <td>string</td>
      <td>The action requested by the user.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-url-logs</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-get-impersonation-logs">12. mimecast-get-impersonation-logs</h3>
<hr>
<p>Returns Impersonation Protect logs for a Mimecast customer account</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-impersonation-logs</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Monitoring/Impersonation Protection/Read.</li>
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
      <td>resultsNumber</td>
      <td>The number of results to request. Default is all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>taggedMalicious</td>
      <td> Filters for messages tagged malicious (true) or not tagged malicious (false). Omit for no tag filtering. default is true</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>searchField</td>
      <td>The field to search,Defaults to all (meaning all of the preceding fields)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query</td>
      <td>Required if searchField exists. A character string to search for in the logs.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>identifiers</td>
      <td>Filters logs by identifiers, can include any of newly_observed_domain, internal_user_name, repy_address_mismatch, and targeted_threat_dictionary. you can choose more then one identifier separated by comma.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromDate</td>
      <td>Start date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is the start of the current day</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>toDate</td>
      <td>End date of logs to return in the following format 2015-11-16T14:49:18+0000. Default is time of request</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>actions</td>
      <td>Filters logs by action, you can choose more then one action separated by comma.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of results to return.</td>
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
      <td>Mimecast.Impersonation.ResultCount</td>
      <td>number</td>
      <td>The total number of IMPERSONATION log lines found for the request</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Hits</td>
      <td>number</td>
      <td>The number of identifiers that the message triggered</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Malicious</td>
      <td>boolean</td>
      <td>Whether the message was tagged as malicious</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.SenderIP</td>
      <td>string</td>
      <td>The source IP address of the message</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.SenderAddress</td>
      <td>string</td>
      <td>The email address of the sender of the message</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Subject</td>
      <td>string</td>
      <td>The subject of the email</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Identifiers</td>
      <td>string</td>
      <td>The properties of the message that triggered the action: similar_internal_domain, newly_observed_domain, internal_user_name, reply_address_mismatch, and/or targeted_threat_dictionary</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Date</td>
      <td>date</td>
      <td>The time at which the log was recorded</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Action</td>
      <td>string</td>
      <td> The action triggered by the email</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.Policy</td>
      <td>string</td>
      <td>The name of the policy definition that triggered the log</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.ID</td>
      <td>string</td>
      <td>Impersonation Log ID</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.RecipientAddress</td>
      <td>string</td>
      <td>The email address of the recipient of the email</td>
    </tr>
    <tr>
      <td>Mimecast.Impersonation.External</td>
      <td>boolean</td>
      <td>Whether the message was tagged as coming from an external address</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-impersonation-logs</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-url-decode">13. mimecast-url-decode</h3>
<hr>
<p>Decodes a given url from mimecast</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-url-decode</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Account/Dashboard/Read.</li>
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
      <td>url</td>
      <td>URL to decode</td>
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
      <td>URL.Data</td>
      <td>string</td>
      <td>The encoded url to parse</td>
    </tr>
    <tr>
      <td>URL.Mimecast.DecodedURL</td>
      <td>string</td>
      <td>Parsed url</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-url-decode url=XXXX</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-discover">14. mimecast-discover</h3>
<hr>
<p>discover authentication types that are supported for your account and which base URL to use for the requesting user.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-discover</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
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
      <td>Mimecast.Authentication.AuthenticationTypes</td>
      <td>string</td>
      <td>List of authentication types available to the user</td>
    </tr>
    <tr>
      <td>Mimecast.Authentication.EmailAddress</td>
      <td>string</td>
      <td>Email address of the request sender</td>
    </tr>
    <tr>
      <td>Mimecast.Authentication.EmailToken</td>
      <td>string</td>
      <td>Email token of the request sender</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-discover</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-refresh-token">15. mimecast-refresh-token</h3>
<hr>
<p>Refresh access key validity</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-refresh-token</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-refresh-token</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-login">16. mimecast-login</h3>
<hr>
<p>Login to generate Access Key and  Secret Key</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-login</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-login</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-get-message">17. mimecast-get-message</h3>
<hr>
<p>Get the contents or metadata of a given message</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-message</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Archive/Search Content View.</li>
    <li>or Mimecast user with delegate permissions to address or user.</li>
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
      <td>messageID</td>
      <td>Message ID</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>context</td>
      <td>Defines which copy of the message part to return, must be one of: "delievered" the copy that has been processed by the Mimecast MTA with policies such as URL rewriting applied, OR "received" - the copy of the message that Mimecast originally received. (Only relevant for part argument = message or all)</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>type</td>
      <td>The message type to return. (Only relevant for part argument = message or all)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>part</td>
      <td>Define what message part to return - download message, get metadata or both.</td>
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
      <td>Mimecast.Message.ID</td>
      <td>string</td>
      <td>Message ID</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Subject</td>
      <td>string</td>
      <td>The message subject.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.HeaderDate</td>
      <td>date</td>
      <td>The date of the message as defined in the message headers.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Size</td>
      <td>number</td>
      <td>The message size.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.From</td>
      <td>string</td>
      <td>Sender of the message as defined in the message header.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.To.EmailAddress</td>
      <td>string</td>
      <td>Recipient of the message.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.ReplyTo</td>
      <td>string</td>
      <td>The value of the Reply-To header.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.CC.EmailAddress</td>
      <td>string</td>
      <td>Each CC recipient of the message.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.EnvelopeFrom</td>
      <td>string</td>
      <td>Sender of the message as defined in the message envelope.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Headers.Name</td>
      <td>string</td>
      <td>Header's name.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Headers.Values</td>
      <td>string</td>
      <td>Header's value.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Attachments.FileName</td>
      <td>string</td>
      <td>Message attachment's file name.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Attachments.SHA256</td>
      <td>string</td>
      <td>Message attachment's SHA256.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Attachments.ID</td>
      <td>string</td>
      <td>Message attachment's ID.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Attachments.Size</td>
      <td>number</td>
      <td>Message attachment's file size.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.Processed</td>
      <td>date</td>
      <td>The date the message was processed by Mimecast in ISO 8601 format.</td>
    </tr>
    <tr>
      <td>Mimecast.Message.HasHtmlBody</td>
      <td>boolean</td>
      <td>If the message has an HTML body part.</td>
    </tr>
    <tr>
      <td>File.Size</td>
      <td>number</td>
      <td>File Size</td>
    </tr>
    <tr>
      <td>File.SHA1</td>
      <td>string</td>
      <td>SHA1 hash of the file</td>
    </tr>
    <tr>
      <td>File.SHA256</td>
      <td>string</td>
      <td>SHA256 hash of the file</td>
    </tr>
    <tr>
      <td>File.Name</td>
      <td>string</td>
      <td>The sample name</td>
    </tr>
    <tr>
      <td>File.SSDeep</td>
      <td>string</td>
      <td>SSDeep hash of the file</td>
    </tr>
    <tr>
      <td>File.EntryID</td>
      <td>string</td>
      <td>War-Room Entry ID of the file</td>
    </tr>
    <tr>
      <td>File.Info</td>
      <td>string</td>
      <td>Basic information of the file</td>
    </tr>
    <tr>
      <td>File.Type</td>
      <td>string</td>
      <td>File type e.g. "PE"</td>
    </tr>
    <tr>
      <td>File.MD5</td>
      <td>string</td>
      <td>MD5 hash of the file</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-message context=DELIVERED messageID=XXXX</code>
</p>

<h5>Human Readable Output</h5>

<h3 id="mimecast-download-attachments">18. mimecast-download-attachments</h3>
<hr>
<p>Download attachments from a specified message</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-download-attachments</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Archive/Search Content View.</li>
    <li>or Mimecast user with delegate permissions to address or user.</li>
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
      <td>attachmentID</td>
      <td>The Mimecast ID of the message attachment to return. (Can be retrieved from mimecast-get-message)</td>
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
      <td>File.Size</td>
      <td>number</td>
      <td>File Size</td>
    </tr>
    <tr>
      <td>File.SHA1</td>
      <td>string</td>
      <td>SHA1 hash of the file</td>
    </tr>
    <tr>
      <td>File.SHA256</td>
      <td>string</td>
      <td>SHA256 hash of the file</td>
    </tr>
    <tr>
      <td>File.Name</td>
      <td>string</td>
      <td>The sample name</td>
    </tr>
    <tr>
      <td>File.SSDeep</td>
      <td>string</td>
      <td>SSDeep hash of the file</td>
    </tr>
    <tr>
      <td>File.EntryID</td>
      <td>string</td>
      <td>War-Room Entry ID of the file</td>
    </tr>
    <tr>
      <td>File.Info</td>
      <td>string</td>
      <td>Basic information of the file</td>
    </tr>
    <tr>
      <td>File.Type</td>
      <td>string</td>
      <td>File type e.g. "PE"</td>
    </tr>
    <tr>
      <td>File.MD5</td>
      <td>string</td>
      <td>MD5 hash of the file</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-download-attachments attachmentID=XXXX</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-find-groups">19. mimecast-find-groups</h3>
<hr>
<p>Returns the list of groups according to the specified query.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-find-groups</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Directories/Groups/Edit.</li>
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
      <td>query_string</td>
      <td>The string to query.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query_source</td>
      <td>The group source by which to filter. Can be "cloud" or "ldap".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of results to return.</td>
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
      <td>Mimecast.Group.Name</td>
      <td>String</td>
      <td>The name of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Source</td>
      <td>String</td>
      <td>The source of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.ID</td>
      <td>String</td>
      <td>The Mimecast ID of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.NumberOfUsers</td>
      <td>Number</td>
      <td>The number of members in the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.ParentID</td>
      <td>String</td>
      <td>The Mimecast ID of the group's parent.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.NumberOfChildGroups</td>
      <td>Number</td>
      <td>The number of child groups.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-find-groups</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-get-group-members">20. mimecast-get-group-members</h3>
<hr>
<p>Returns the members list for the specified group.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-group-members</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Directories/Groups/Read.</li>
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
      <td>group_id</td>
      <td>The Mimecast ID of the group to return.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of results to return.</td>
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
      <td>Mimecast.Group.Users.Name</td>
      <td>String</td>
      <td>The user's display name.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.EmailAddress</td>
      <td>String</td>
      <td>The user's email address.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.Domain</td>
      <td>String</td>
      <td>The domain name of the user's email address.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.Type</td>
      <td>String</td>
      <td>The user type.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.InternalUser</td>
      <td>Boolean</td>
      <td>Whether the user is internal.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.IsRemoved</td>
      <td>Boolean</td>
      <td>Whether the user is part of the group.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-group-members group_id=XXXX</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-add-group-member">21. mimecast-add-group-member</h3>
<hr>
<p>Adds a user to a group. The email_address and domain_adddress arguments are optional, but one of them must be supplied.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-add-group-member</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Directories/Groups/Edit.</li>
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
      <td>group_id</td>
      <td>The Mimecast ID of the group to add the user to.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>email_address</td>
      <td>The email address of the user to add to a group.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>domain_address</td>
      <td>A domain to add to a group.</td>
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
      <td>Mimecast.Group.Users.EmailAddress</td>
      <td>String</td>
      <td>The user's email address.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.IsRemoved</td>
      <td>Boolean</td>
      <td>Whether the user is part of the group.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-add-group-member group_id=XXXX domain_address=YYYY</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-remove-group-member">22. mimecast-remove-group-member</h3>
<hr>
<p>Removes a user from a group. The email_address and domain_adddress arguments are optional, but one of them must be supplied.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-remove-group-member</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Directories/Groups/Edit.</li>
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
      <td>group_id</td>
      <td>The Mimecast ID of the group from which to remove the user.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>email_address</td>
      <td>The email address of the user to remove from the group.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>domain_address</td>
      <td>A domain of the user to remove from a group.</td>
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
      <td>Mimecast.Group.Users.EmailAddress</td>
      <td>String</td>
      <td>The user's email address.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Users.IsRemoved</td>
      <td>Boolean</td>
      <td>Whether the user part of the group.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-remove-group-member group_id=XXXX domain_address=YYYY</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-create-group">23. mimecast-create-group</h3>
<hr>
<p>Creates a new Mimecast group.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-create-group</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Directories/Groups/Edit.</li>
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
      <td>group_name</td>
      <td>The name of the new group.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>parent_id</td>
      <td>The Mimecast ID of the new group's parent. Default will be root level.</td>
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
      <td>Mimecast.Group.Name</td>
      <td>String</td>
      <td>The name of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.Source</td>
      <td>String</td>
      <td>The source of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.ID</td>
      <td>String</td>
      <td>The Mimecast ID of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.NumberOfUsers</td>
      <td>Number</td>
      <td>The number of members in the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.ParentID</td>
      <td>String</td>
      <td>The Mimecast ID of the group's parent.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.NumberOfChildGroups</td>
      <td>Number</td>
      <td>The number of child groups.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-create-group group_name=TTTT parent_id=XXXX</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-update-group">24. mimecast-update-group</h3>
<hr>
<p>Updates an existing Mimecast group.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-update-group</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Directories/Groups/Edit.</li>
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
      <td>group_name</td>
      <td>The new name for the group.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>group_id</td>
      <td>The Mimecast ID of the group to update.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>parent_id</td>
      <td>The new parent group.</td>
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
      <td>Mimecast.Group.Name</td>
      <td>String</td>
      <td>The name of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.ID</td>
      <td>String</td>
      <td>The Mimecast ID of the group.</td>
    </tr>
    <tr>
      <td>Mimecast.Group.ParentID</td>
      <td>String</td>
      <td>The Mimecast ID of the group's parent.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-update-group group_id=XXXX group_name=ZZZZ</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-create-remediation-incident">25. mimecast-create-remediation-incident</h3>
<hr>
<p>Creates a new Mimecast remediation incident.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-create-remediation-incident</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Services/Threat Remediation/Edit.</li>
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
      <td>hash_message_id</td>
      <td>The file hash or messageId value.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>reason</td>
      <td>The reason for creating the remediation incident.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>search_by</td>
      <td>The message component by which to search. Can be "hash" or "messagId". Default is "hash".</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>start_date</td>
      <td>The startt date of messages to remediate. Default value is the previous month. (Format: yyyy-mm-ddThh:mm:ss+0000)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>end_date</td>
      <td>Theend date of messages to remediate. Default value is the end of the current day. (Format: yyyy-mm-ddThh:mm:ss+0000)</td>
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
      <td>Mimecast.Incident.ID</td>
      <td>String</td>
      <td>The secure Mimecast remediation ID.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.Code</td>
      <td>String</td>
      <td>The incident code generated at creation.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.Type</td>
      <td>String</td>
      <td>The incident type.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.Reason</td>
      <td>String</td>
      <td>The reason provided at the creation of the remediation incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.IdentifiedMessages</td>
      <td>Number</td>
      <td>The number of messages identified based on the search criteria.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SuccessfullyRemediatedMessages</td>
      <td>Number</td>
      <td>The number successfully remediated messages.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.FailedRemediatedMessages</td>
      <td>Number</td>
      <td>The number of messages that failed to remediate.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.MessagesRestored</td>
      <td>Number</td>
      <td>The number of messages that were restored from the incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.LastModified</td>
      <td>String</td>
      <td>The date and time that the incident was last modified.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.From</td>
      <td>String</td>
      <td>The sender email address or domain.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.To</td>
      <td>String</td>
      <td>The recipient email address or domain.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.MessageID</td>
      <td>String</td>
      <td>The message ID used when creating the remediation incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.FileHash</td>
      <td>String</td>
      <td>The file hash used when creating the remediation incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.StartDate</td>
      <td>String</td>
      <td>The start date of included messages.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.EndDate</td>
      <td>String</td>
      <td>The end date of included messages.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-create-remediation-incident hash_message_id=XXXX reason=YYYY</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-get-remediation-incident">26. mimecast-get-remediation-incident</h3>
<hr>
<p>Returns a Mimecast remediation incident.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-get-remediation-incident</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Services/Threat Remediation/Read.</li>
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
      <td>incident_id</td>
      <td>The Mimecast ID for a remediation incident.</td>
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
      <td>Mimecast.Incident.ID</td>
      <td>String</td>
      <td>The secure Mimecast remediation ID.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.Code</td>
      <td>String</td>
      <td>The incident code generated at creation.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.Type</td>
      <td>String</td>
      <td>The incident type.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.Reason</td>
      <td>String</td>
      <td>The reason provided when the remediation incident was created.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.IdentifiedMessages</td>
      <td>Number</td>
      <td>The number of messages identified based on the search criteria.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SuccessfullyRemediatedMessages</td>
      <td>Number</td>
      <td>The number of successfully remediated messages.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.FailedRemediatedMessages</td>
      <td>Number</td>
      <td>The number of messages that failed to remediate.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.MessagesRestored</td>
      <td>Number</td>
      <td>The number of messages that were restored from the incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.LastModified</td>
      <td>String</td>
      <td>The date and time that the incident was last modified.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.From</td>
      <td>String</td>
      <td>The sender email address or domain.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.To</td>
      <td>String</td>
      <td>The recipient email address or domain.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.MessageID</td>
      <td>String</td>
      <td>The message ID used when creating the remediation incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.FileHash</td>
      <td>String</td>
      <td>The file hash used when creating the remediation incident.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.StartDate</td>
      <td>String</td>
      <td>The start date of included messages.</td>
    </tr>
    <tr>
      <td>Mimecast.Incident.SearchCriteria.EndDate</td>
      <td>String</td>
      <td>The end date of included messages.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-get-remediation-incident incident_id=XXXX</code>
</p>

<h5>Human Readable Output</h5>
<h3 id="mimecast-search-file-hash">27. mimecast-search-file-hash</h3>
<hr>
<p>Searches for one or more file hashes in the account. Maximum is 100.</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-search-file-hash</code>
</p>

<h5>Required Permissions</h5>
<p>The following permissions are required for this command.</p>
<ul>
    <li>Mimecast administrator with at least one of the following permissions: Services/Threat Remediation/Read.</li>
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
      <td>hashes_to_search</td>
      <td>List of file hashes to check if they have been seen within an account.</td>
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
      <td>Mimecast.Hash.HashValue</td>
      <td>String</td>
      <td>The file hash value.</td>
    </tr>
    <tr>
      <td>Mimecast.Hash.Detected</td>
      <td>Boolean</td>
      <td>Whether the hash was found in the account.</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-search-file-hash hashes_to_search=XXXX</code>
</p>

<h5>Human Readable Output</h5>
<p>
</p>
<h3 id="mimecast-update-policy">28. mimecast-update-policy</h3>
<hr>
<p>update policy</p>
<h5>Base Command</h5>
<p>
  <code>mimecast-update-policy</code>
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
      <td>policy_id</td>
      <td>Policy id</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>description</td>
      <td>Policy description</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromType</td>
      <td>Blocked Sender type. Most times you will have to change fromValue according to fromType</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>toType</td>
      <td>Blocked Receiver type. Most times you will have to change fromValue according to fromType</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>option</td>
      <td>The block option, must be one of: no_action, block_sender.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromValue</td>
      <td>Blocked Sender value. FromValue depends on fromType</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>toValue</td>
      <td>Blocked Receiver value. ToValue depends on toType</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fromPart</td>
      <td>Addresses based on</td>
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
      <td>Mimecast.Policy.ID</td>
      <td>string</td>
      <td>Policy ID</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Address</td>
      <td>string</td>
      <td>Block Sender by email address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Domain</td>
      <td>string</td>
      <td>Block Sender by domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Group</td>
      <td>string</td>
      <td>Block Sender by group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Bidirectional</td>
      <td>boolean</td>
      <td>Blocked policy is Bidirectional or not</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Address</td>
      <td>string</td>
      <td>Block emails to Receiver type address</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Domain</td>
      <td>string</td>
      <td>Block emails to Receiver type domain</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Group</td>
      <td>string</td>
      <td>Block emails to Receiver type group</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Fromdate</td>
      <td>date</td>
      <td>Policy validation start date</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Todate</td>
      <td>date</td>
      <td>Policy expiration date</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Sender.Type</td>
      <td>String</td>
      <td>The sender type</td>
    </tr>
    <tr>
      <td>Mimecast.Policy.Receiver.Type</td>
      <td>String</td>
      <td>The Receiver type</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!mimecast-update-policy policyID=XXXX toType=address_attribute_value</code>
</p>

<h5>Human Readable Output</h5>
<img src="https://github.com/demisto/content/raw/a44c6b00e1c50155eecf6af577b5ae8512e747dd/Packs/Mimecast/Integrations/MimecastV2/doc_files/mimecast-update-policy.jpg" alt="image">
