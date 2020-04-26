<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Microsoft Graph integration to connect to and interact with user objects on Microsoft Platforms. This integration was integrated and tested with Microsoft Graph v1.0.</p>
</div>
<div class="cl-preview-section">
<h2>Generate Authentication Parameters</h2>
<p>To use this integration, you have to grant access to Demisto from Microsoft Graph.</p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Microsoft Graph User.</li>
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
</div>
<div class="cl-preview-section">
<h2 id="configure-microsoft-graph-user-on-demisto">Configure Microsoft Graph User on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Microsoft Graph User.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Host URL (e.g., <a href="https://graph.microsoft.com/">https://graph.microsoft.com</a>)</strong></li>
<li><strong>ID you received from the admin consent</strong></li>
<li><strong>Key you received from the admin consent</strong></li>
<li><strong>Token you received from the admin consent</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#terminate-a-user-session" target="_self">Terminate a user session: msgraph-user-terminate-session</a></li>
<li><a href="#unblock-a-user" target="_self">Unblock a user: msgraph-user-unblock</a></li>
<li><a href="#update-properties-of-a-user-object" target="_self">Update properties of a user object: msgraph-user-update</a></li>
<li><a href="#delete-a-user" target="_self">Delete a user: msgraph-user-delete</a></li>
<li><a href="#create-a-user" target="_self">Create a user: msgraph-user-create</a></li>
<li><a href="#get-new-updated-or-deleted-user-information" target="_self">Get new, updated, or deleted user information: msgraph-user-get-delta</a></li>
<li><a href="#get-user-object-information" target="_self">Get user object information: msgraph-user-get</a></li>
<li><a href="#get-a-list-of-user-objects" target="_self">Get a list of user objects: msgraph-user-list</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="terminate-a-user-session">1. Terminate a user session</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Terminates a user’s session from all Office 365 applications, and prevents sign in.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-terminate-session</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 243px;"><strong>Argument Name</strong></th>
<th style="width: 367px;"><strong>Description</strong></th>
<th style="width: 130px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 243px;">user</td>
<td style="width: 367px;">User ID or userPrincipalName.</td>
<td style="width: 130px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-terminate-session user="oren@demistodev.onmicrosoft.com"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>user: <a href="mailto:%22oren@demistodev.onmicrosoft.com">"oren@demistodev.onmicrosoft.com</a>" session has been terminated successfully</p>
</div>
<div class="cl-preview-section">
<h3 id="unblock-a-user">2. Unblock a user</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Unblocks a user.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-unblock</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 225px;"><strong>Argument Name</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
<th style="width: 129px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 225px;">user</td>
<td style="width: 386px;">User ID or userPrincipalName.</td>
<td style="width: 129px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-unblock user="ore@demistdev.onmicrosoft.com"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><a href="mailto:%22oren@demistodev.onmicrosoft.com">"ore@demistdev.onmicrosoft.com</a>" unblocked. It might take several minutes for the changes to take affect across all applications.</p>
</div>
<div class="cl-preview-section">
<h3 id="update-properties-of-a-user-object">3. Update properties of a user object</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates the properties of a user object.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-update</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 84px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">user</td>
<td style="width: 497px;">User ID or userPrincipalName for which to update properties.</td>
<td style="width: 84px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">updated_fields</td>
<td style="width: 497px;">User fields to update (in JSON format).</td>
<td style="width: 84px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">MSGraphUser.ID</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s ID.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.DisplayName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s display name.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.GivenName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s given name.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.BusinessPhones</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s business phone numbers.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.JobTitle</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s job title.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.Mail</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s mail address.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.MobilePhone</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s mobile phone number.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.OfficeLocation</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s office location.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.PreferredLanguage</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s preferred language.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.Surname</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s surname.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.UserPrincipalName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s principal name.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-update user="graph@demistodev.onmicrosoft.com" updated_fields="mobilePhone=050505050"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "MSGraphUser": {
        "Surname": null, 
        "DisplayName": "Graph Test - DELETE", 
        "MobilePhone": "050505050", 
        "PreferredLanguage": null, 
        "JobTitle": "Test", 
        "UserPrincipalName": "graph@demistodev.onmicrosoft.com", 
        "OfficeLocation": null, 
        "BusinessPhones": [], 
        "Mail": null, 
        "GivenName": null, 
        "ID": "57a820e9-90bc-4692-a22e-27bd170699cb"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="graphdemistodev.onmicrosoft.com-data">graph@demistodev.onmicrosoft.com data</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 105px;">Display Name</th>
<th style="width: 47px;">Job Title</th>
<th style="width: 81px;">Mobile Phone</th>
<th style="width: 261px;">User Principal Name</th>
<th style="width: 138px;">ID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 105px;">Graph Test - DELETE</td>
<td style="width: 47px;">Test</td>
<td style="width: 81px;">050505050</td>
<td style="width: 261px;">graph@demistodev.onmicrosoft.com</td>
<td style="width: 138px;">57a820e9-90bc-4692-a22e-27bd170699cb</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="delete-a-user">4. Delete a user</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes an existing user.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-delete</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 193px;"><strong>Argument Name</strong></th>
<th style="width: 436px;"><strong>Description</strong></th>
<th style="width: 111px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">user</td>
<td style="width: 436px;">User ID or userPrincipalName to delete.</td>
<td style="width: 111px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-delete user="graph@demistodev.onmicrosoft.com"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>user: "graph@demistodev.onmicrosoft.com" was deleted successfully</p>
</div>
<div class="cl-preview-section">
<h3 id="create-a-user">5. Create a user</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates a new user.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-create</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 206px;"><strong>Argument Name</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">account_enabled</td>
<td style="width: 363px;">If "true", the account is enabled. If "false", the account is disabled.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 206px;">display_name</td>
<td style="width: 363px;">The name to display in the address book.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 206px;">on_premises_immutable_id</td>
<td style="width: 363px;">Only needs to be specified when creating a new user account if you are using a federated domain for the user’s userPrincipalName (UPN) property.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 206px;">mail_nickname</td>
<td style="width: 363px;">The mail alias for the user.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 206px;">password</td>
<td style="width: 363px;">The password profile for the user.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 206px;">user_principal_name</td>
<td style="width: 363px;">The user principal name, for example: someuser@contoso.com.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 206px;">other_properties</td>
<td style="width: 363px;">Optional properties for the user, for example: “displayName=name,mobilePhone=phone-num”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 332px;"><strong>Path</strong></th>
<th style="width: 86px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332px;">MSGraphUser.ID</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s ID.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.DisplayName</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s display name.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.GivenName</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s given name.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.BusinessPhones</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s business phone numbers.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.JobTitle</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s job title.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.Mail</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s mail address.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.MobilePhone</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s mobile phone number.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.OfficeLocation</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s office location.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.PreferredLanguage</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s preferred language.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.Surname</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s surname.</td>
</tr>
<tr>
<td style="width: 332px;">MSGraphUser.UserPrincipalName</td>
<td style="width: 86px;">unknown</td>
<td style="width: 322px;">User’s principal name.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-create display_name="Graph Test - DELETE" mail_nickname="graph" password="Aa123456" user_principal_name="graph@demistodev.onmicrosoft.com" other_properties="jobTitle=Test,city=Tel Aviv"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "MSGraphUser": {
        "Surname": null, 
        "DisplayName": "Graph Test - DELETE", 
        "MobilePhone": null, 
        "PreferredLanguage": null, 
        "JobTitle": "Test", 
        "UserPrincipalName": "graph@demistodev.onmicrosoft.com", 
        "OfficeLocation": null, 
        "BusinessPhones": [], 
        "Mail": null, 
        "GivenName": null, 
        "ID": "57a820e9-90bc-4692-a22e-27bd170699cb"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="graphdemistodev.onmicrosoft.com-was-created-successfully">graph@demistodev.onmicrosoft.com was created successfully:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 120px;">Display Name</th>
<th style="width: 54px;">Job Title</th>
<th style="width: 263px;">User Principal Name</th>
<th style="width: 198px;">ID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 120px;">Graph Test - DELETE</td>
<td style="width: 54px;">Test</td>
<td style="width: 263px;">graph@demistodev.onmicrosoft.com</td>
<td style="width: 198px;">57a820e9-90bc-4692-a22e-27bd170699cb</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-new-updated-or-deleted-user-information">6. Get new, updated, or deleted user information</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deprecated. This command only returns a single page. Use the msgraph-user-list command instead, which gets newly created, updated, or deleted users without performing a full read of the entire user collection.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-get-delta</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 648px;">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 428px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">properties</td>
<td style="width: 428px;">A CSV list of properties by which to filter the results, for example: “displayName,jobTitle,mobilePhone”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">MSGraphUser.ID</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s ID.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.DisplayName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s display name.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.GivenName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s given name.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.BusinessPhones</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s business phone numbers.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.JobTitle</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s job title.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.Mail</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s mail address.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.MobilePhone</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s mobile phone.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.OfficeLocation</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s office location.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.PreferredLanguage</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s preferred language.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.Surname</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s surname.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.UserPrincipalName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s principal name.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-get-delta properties="mobilePhone"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "MSGraphUser": [
        {
            "ID": "2827c1e7-edb6-4529-b50d-25984e968637", 
            "UserPrincipalName": "dev@demisto.works"
        }, 
        {
            "ID": "c788ab51-6b4f-42cc-8b50-0759a8701c0b", 
            "UserPrincipalName": "donaldt@demistodev.onmicrosoft.com"
        }, 
        {
            "UserPrincipalName": "test@demistodev.onmicrosoft.com", 
            "ID": "00df702c-cdae-460d-a442-46db6cecca29", 
            "MobilePhone": "*********"
        }, 
        {
            "Status": "deleted", 
            "ID": "28a1b242-4737-4bb8-a855-a9519d8e6a28"
        }, 
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-graph-users">All Graph Users</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 97px;">Mobile Phone</th>
<th style="width: 287px;">ID</th>
<th style="width: 254px;">User Principal Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 97px;">1245678900</td>
<td style="width: 287px;">670edadc-0197-45b0-90e6-ee061e25ab73</td>
<td style="width: 254px;">test2@demistodev.onmicrosoft.com</td>
</tr>
<tr>
<td style="width: 97px;">0525399092</td>
<td style="width: 287px;">00df702c-cdae-460d-a442-46db6cecca29</td>
<td style="width: 254px;">ore@demisodev.onmicrosoft.com</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-user-object-information">7. Get user object information</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves the properties and relationships of user objects. For more information, see the <a href="https://docs.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0" target="_blank" rel="noopener">Microsoft Graph User documentation</a>.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-get</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">user</td>
<td style="width: 523px;">User ID or userPrincipalName.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">properties</td>
<td style="width: 523px;">A CSV list of properties by which to filter the results, for example: “displayName,jobTitle,mobilePhone”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 334px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 334px;">MSGraphUser.ID</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s ID.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.DisplayName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s display name.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.GivenName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s given name.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.BusinessPhones</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s business phone numbers.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.JobTitle</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s job title.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.Mail</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s mail address.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.MobilePhone</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s mobile phone number.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.OfficeLocation</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s office location.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.PreferredLanguage</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s preferred language.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.Surname</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s surname.</td>
</tr>
<tr>
<td style="width: 334px;">MSGraphUser.UserPrincipalName</td>
<td style="width: 84px;">unknown</td>
<td style="width: 322px;">User’s principal name.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-get user="graph@demistodev.onmicrosoft.com"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "MSGraphUser": {
        "Surname": null, 
        "DisplayName": "Graph Test - DELETE", 
        "MobilePhone": null, 
        "PreferredLanguage": null, 
        "JobTitle": "Test", 
        "UserPrincipalName": "graph@demistodev.onmicrosoft.com", 
        "OfficeLocation": null, 
        "BusinessPhones": [], 
        "Mail": null, 
        "GivenName": null, 
        "ID": "57a820e9-90bc-4692-a22e-27bd170699cb"
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="graphdemistodev.onmicrosoft.com-data-1">graph@demistodev.onmicrosoft.com data</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 648px;" border="2">
<thead>
<tr>
<th style="width: 120px;">Display Name</th>
<th style="width: 54px;">Job Title</th>
<th style="width: 264px;">User Principal Name</th>
<th style="width: 197px;">ID</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 120px;">Graph Test - DELETE</td>
<td style="width: 54px;">Test</td>
<td style="width: 264px;">graph@demistodev.onmicrosoft.com</td>
<td style="width: 197px;">57a820e9-90bc-4692-a22e-27bd170699cb</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-user-objects">8. Get a list of user objects</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a list of user objects.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>msgraph-user-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">properties</td>
<td style="width: 530px;">A CSV list of properties by which to filter the results, for example: “displayName,jobTitle,mobilePhone”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">next_page</td>
<td style="width: 530px;">The URL for the next page in the list.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 323px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 323px;">MSGraphUser.ID</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s ID.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.DisplayName</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s display name.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.GivenName</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s given name.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.BusinessPhones</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s business phone numbers.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.JobTitle</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s job title.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.Mail</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s mail address.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.MobilePhone</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s mobile phone number.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.OfficeLocation</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s office location.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.PreferredLanguage</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s preferred language.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.Surname</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s surname.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.UserPrincipalName</td>
<td style="width: 95px;">unknown</td>
<td style="width: 322px;">User’s principal name.</td>
</tr>
<tr>
<td style="width: 323px;">MSGraphUser.NextPage</td>
<td style="width: 95px;">string</td>
<td style="width: 322px;">A token pass to the next list command to retrieve additional results.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>msgraph-user-list properties="id,userPrincipalName"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "MSGraphUser": [
        {
            "ID": "2827c1e7-edb6-4529-b50d-25984e968637", 
            "UserPrincipalName": "dev@demisto.works"
        }, 
        {
            "ID": "c788ab51-6b4f-42cc-8b50-0759a8701c0b", 
            "UserPrincipalName": "donaldt@demistodev.onmicrosoft.com"
        }, 
        {
            "ID": "57a820e9-90bc-4692-a22e-27bd170699cb", 
            "UserPrincipalName": "graph@demistodev.onmicrosoft.com"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-graph-users-1">All Graph Users</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 627px;" border="2">
<thead>
<tr>
<th style="width: 347px;">ID</th>
<th style="width: 281px;">User Principal Name</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 347px;">2827c1e7-edb6-4529-b50d-25984e968637</td>
<td style="width: 281px;">dev@demisto.works</td>
</tr>
<tr>
<td style="width: 347px;">c788ab51-6b4f-42cc-8b50-0759a8701c0b</td>
<td style="width: 281px;">donaldt@demistodev.onmicrosoft.com</td>
</tr>
<tr>
<td style="width: 347px;">57a820e9-90bc-4692-a22e-27bd170699cb</td>
<td style="width: 281px;">graph@demistodev.onmicrosoft.com</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<p><img src="https://user-images.githubusercontent.com/37335599/56651529-e92f6800-6691-11e9-8bd1-8779a59cf51d.png" alt="Screen Shot 2019-04-24 at 12 13 05"></p>
</div>