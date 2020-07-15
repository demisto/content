<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the Active Directory Query integration to access and manage Active Directory objects (users, contacts, and computers) and run AD queries.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<h5 id="query-for-active-directory-objects">Query for Active Directory objects</h5>
</div>
<div class="cl-preview-section">
<ul>
<li>Use the <code>!ad-search</code> command to run a query for Active Directory objects (users, contacts, computers, and so on). This command enables you to determine which data fields should be returned for the objects.</li>
</ul>
</div>
<div class="cl-preview-section">
<h5 id="manage-users-and-contacts">Manage users and contacts</h5>
</div>
<div class="cl-preview-section">
<ul>
<li>The integration enables you to create, update and delete users and contacts in Active Directory using the following commands:
<ul>
<li><code>ad-create-user</code></li>
<li><code>ad-create-contact</code></li>
<li><code>ad-update-user</code></li>
<li><code>ad-update-contact</code></li>
<li>
<code>ad-delete-user</code> (to delete both users and contacts)</li>
</ul>
</li>
<li>Add or remove users from groups using the following commands:
<ul>
<li><code>ad-add-to-group</code></li>
<li><code>ad-remove-from-group</code></li>
</ul>
</li>
<li>Enable or disable a user account using the following commands:
<ul>
<li><code>ad-enable-account</code></li>
<li><code>ad-disable-user-account</code></li>
</ul>
</li>
</ul>
</div>
<div class="cl-preview-section">
<h5 id="manage-computers">Manage Computers</h5>
</div>
<div class="cl-preview-section">
<ul>
<li>Modify computer organizational unit using the ‘ad-modify-computer-ou’ command.</li>
<li>Add or remove a computer from a group using the following commands:
<ul>
<li><code>ad-add-to-group</code></li>
<li><code>ad-remove-from-group</code></li>
</ul>
</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-active-directory-query-v2-on-demisto">Configure Active Directory Query v2 on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Active Directory Query v2.</li>
</ol>
</ol>
<hr>
<ol>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Server IP address (e.g., 192.168.0.1)</strong>: The Server IP that should be used to access Active Directory.</li>
<li>
<strong>Port</strong>: Server port. If not specified, default the port is 389, or 636 for LDAPS</li>
<li>
<strong>Credentials</strong>: User credentials.</li>
<li>
<strong>NTLM authentication</strong>: Indicates whether to use NTLM authentication.</li>
<li>
<strong>Base DN (for example “dc=company,dc=com”)</strong>: The basic hierarchical path of objects in the active directory.</li>
<li>
<strong>Page size</strong>: The number of results to be returned, per page (page - response content from AD server), from a query. This may effect query run time.</li>
<li>
<strong>Secure Connection</strong>: Use SSL secure connection or ‘None’ (communication over clear-text).</li>
<li>
<strong>Trust any certificate (not secure)</strong>:Select to avoid server certification validation. You may want to do this in case Demisto cannot validate the integration server certificate (due to missing CA certificate)</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#expire-a-password" target="_self">Expire a password: ad-expire-password</a></li>
<li><a href="#create-an-ad-user" target="_self">Create an AD user: ad-create-user</a></li>
<li><a href="#perform-a-search-in-active-directory" target="_self">Perform a search in AD: ad-search</a></li>
<li><a href="#add-an-ad-user-or-computer-to-a-group" target="_self">Add an AD user or computer to a group: ad-add-to-group</a></li>
<li><a href="#remove-an-ad-user-or-computer-from-a-group" target="_self">Remove an AD user or computer from a group: ad-remove-from-group</a></li>
<li><a href="#update-attributes-for-an-ad-user" target="_self">Update attributes of an AD user: ad-update-user</a></li>
<li><a href="#delete-an-ad-user" target="_self">Delete an AD user: ad-delete-user</a></li>
<li><a href="#create-an-ad-contact" target="_self">Create an AD contact: ad-create-contact</a></li>
<li><a href="#update-attributes-of-an-ad-contact" target="_self">Update attributes of an AD contact: ad-update-contact</a></li>
<li><a href="#disable-an-ad-user-account" target="_self">Disable an AD user account: ad-disable-account</a></li>
<li><a href="#enable-an-ad-user-account" target="_self">Enable an AD user account: ad-enable-account</a></li>
<li><a href="#unlock-an-ad-user-account" target="_self">Unlock an AD user account: ad-unlock-account</a></li>
<li><a href="#set-a-new-password-for-an-ad-user-account" target="_self">Set a new password for an AD user: ad-set-new-password</a></li>
<li><a href="#modify-the-computer-organizational-unit-in-a-domain" target="_self">Modify the computer organizational unit in a domain: ad-modify-computer-ou</a></li>
<li><a href="#get-information-for-an-ad-user-account" target="_self">Get information for an AD user account: ad-get-user</a></li>
<li><a href="#get-information-for-a-computer-account" target="_self">Get information for a computer account: ad-get-computer</a></li>
<li><a href="#get-a-list-of-users-or-computers-for-a-group" target="_self">Get a list of users or computers for a group: ad-get-group-members</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="expire-a-password">1. Expire a password</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Expires the password of an Active Directory user.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-expire-password</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 167px;"><strong>Argument Name</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
<th style="width: 89px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">username</td>
<td style="width: 484px;">The username (samAccountName) of the user to modify.</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 167px;">base-dn</td>
<td style="width: 484px;">Root (e.g., DC=domain,DC=com).</td>
<td style="width: 89px;">Optional</td>
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
<h3 id="create-an-ad-user">2. Create an AD user</h3>
</div>
<hr>
<div class="cl-preview-section">
<p>Creates a new user in Active Directory.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-create-user</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">username</td>
<td style="width: 538px;">The username (samAccountName) of the user to modify.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">password</td>
<td style="width: 538px;">The initial password to set for the user. The user will be asked to change the password after the initial login.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">user-dn</td>
<td style="width: 538px;">The user’s DN.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">display-name</td>
<td style="width: 538px;">The user’s display name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">description</td>
<td style="width: 538px;">A short description of the user.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">email</td>
<td style="width: 538px;">The user’s email address.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">telephone-number</td>
<td style="width: 538px;">The user’s telephone number.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">title</td>
<td style="width: 538px;">The user’s job title.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">custom-attributes</td>
<td style="width: 538px;">
<p>Sets basic or custom attributes of the user object. For example,<br> custom-attributes="{\"notes\":\"a note about the contact\",\"company\":\"company<br> name\"}"</p>
</td>
<td style="width: 71px;">Optional</td>
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
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-create-user username="jack" password="1q2w3e4r!" user-dn="cn=jack,dc=demisto,dc=int" display-name="Samurai Jack"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Created user with DN: cn=jack,dc=demisto,dc=int</p>
</div>
<div class="cl-preview-section">
<h3 id="perform-a-search-in-active-directory">3. Perform a search in Active Directory</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Runs queries in Active Directory. </p>
<p>For more information on the query syntax see the <a href="https://docs.microsoft.com/en-us/windows/desktop/adsi/search-filter-syntax" target="_blank" rel="noopener">Microsoft documentation</a>.</p>
<p>For more information on LDAP filters, see the <a href="https://ldap.com/ldap-filters/" target="_blank" rel="noopener">LDAP documentation</a>.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-search</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 525px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">filter</td>
<td style="width: 525px;">
<p>Defines search criteria in the Query Active Directory using Active Directory syntax. For example, the following query searches for all user objects, except Andy: "(&amp;(objectCategory=person)(objectClass=user)(!(cn=andy)))".</p>
<p>NOTE if you have special characters such as "*","(",or "\" the character must be preceded by two backslashes "\\". For example, to use "*",<br> type "\\*". For more information about search filters, see<br><a href="https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax" target="_blank" rel="noopener">Microsoft documentation</a>.</p>
<p> </p>
</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">base-dn</td>
<td style="width: 525px;">Root (e.g. DC=domain,DC=com). By default, the Base DN configured for the instance that will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">attributes</td>
<td style="width: 525px;">A CSV list of the object attributes to return, e.g., “dn,memberOf”. To get all object attributes, specify ‘ALL’.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">size-limit</td>
<td style="width: 525px;">The maximum number of records to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">time-limit</td>
<td style="width: 525px;">The maximum time to pull records (in seconds).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">context-output</td>
<td style="width: 525px;">If “no”, will not output the search results to the context.</td>
<td style="width: 71px;">Optional</td>
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
<th style="width: 244px;"><strong>Path</strong></th>
<th style="width: 70px;"><strong>Type</strong></th>
<th style="width: 426px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 244px;">ActiveDirectory.Search.dn</td>
<td style="width: 70px;">string</td>
<td style="width: 426px;">The distinguished names that match the query.</td>
</tr>
<tr>
<td style="width: 244px;">ActiveDirectory.Search</td>
<td style="width: 70px;">unknown</td>
<td style="width: 426px;">Result of the search.</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-search filter="(&amp;(objectCategory=person)(objectClass=user)(!(cn=andy)))"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "ActiveDirectory.Search": [
        {
            "dn": "CN=demistoadmin,CN=Users,DC=demisto,DC=int"
        }, 
        {
            "dn": "CN=Guest,CN=Users,DC=demisto,DC=int"
        } 
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="active-directory-search">Active Directory Search</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>dn</th>
</tr>
</thead>
<tbody>
<tr>
<td>CN=demistoadmin,CN=Users,DC=demisto,DC=int</td>
</tr>
<tr>
<td>CN=Guest,CN=Users,DC=demisto,DC=int</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-an-ad-user-or-computer-to-a-group">4. Add an AD user or computer to a group</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds an Active Directory user or computer to a group.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-add-to-group</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 152px;"><strong>Argument Name</strong></th>
<th style="width: 517px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 152px;">username</td>
<td style="width: 517px;">The username of the user to add to the group. If this argument is not specified, the computer name argument must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">computer-name</td>
<td style="width: 517px;">The name of the computer to add to the group. If this argument is not specified, the username argument must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 152px;">group-cn</td>
<td style="width: 517px;">The name of the group to add the user to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 152px;">base-dn</td>
<td style="width: 517px;">Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
<td style="width: 71px;">Optional</td>
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
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-add-to-group username="Jack" group-cn="Users"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Object with dn CN=jack,DC=demisto,DC=int was added to group Users</p>
</div>
<div class="cl-preview-section">
<h3 id="remove-an-ad-user-or-computer-from-a-group">5. Remove an AD user or computer from a group</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Removes an Active Directory user or computer from a group.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-remove-from-group</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">username</td>
<td style="width: 526px;">The name of the user to remove from the group. If this argument is not specified, the computer name argument must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">computer-name</td>
<td style="width: 526px;">The name of the computer to remove from the group. If this argument is not specified, the username argument must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">group-cn</td>
<td style="width: 526px;">The name of the group to remove the user from</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">base-dn</td>
<td style="width: 526px;">Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
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
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-remove-from-group username="jack" group-cn="Users"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Object with dn CN=jack,DC=demisto,DC=int removed from group Users</p>
</div>
<div class="cl-preview-section">
<h3 id="update-attributes-for-an-ad-user">6. Update attributes for an AD user</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates attributes of an existing Active Directory user.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-update-user</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 179px;"><strong>Argument Name</strong></th>
<th style="width: 490px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 179px;">username</td>
<td style="width: 490px;">The username of the account to update (sAMAccountName)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">attribute-name</td>
<td style="width: 490px;">The name of the attribute to modify (e.g., sn, displayName, mail, etc.).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">attribute-value</td>
<td style="width: 490px;">The value the attribute should be changed to.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 179px;">base-dn</td>
<td style="width: 490px;">Root (e.g. DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
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
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-update-user attribute-name=description attribute-value=Samurai username=jack</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><code>Updated user's description to Samurai</code></p>
</div>
<div class="cl-preview-section">
<h3 id="delete-an-ad-user">7. Delete an AD user</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes an Active Directory user.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-delete-user</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 243px;"><strong>Argument Name</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
<th style="width: 131px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 243px;">user-dn</td>
<td style="width: 366px;">The DN of the user to delete.</td>
<td style="width: 131px;">Required</td>
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
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-delete-user user-dn="cn=jack,dc=demisto,dc=int"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><code>Deleted object with dn cn=jack,dc=demisto,dc=int</code></p>
</div>
<div class="cl-preview-section">
<h3 id="create-an-ad-contact">8. Create an AD contact</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Creates an Active Directory contact.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-create-contact</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
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
<td style="width: 153px;">contact-dn</td>
<td style="width: 516px;">The contact’s DN.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 153px;">display-name</td>
<td style="width: 516px;">The contact’s display name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">description</td>
<td style="width: 516px;">A short description of the contact.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">email</td>
<td style="width: 516px;">The contact’s email address.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">telephone-number</td>
<td style="width: 516px;">The contact’s telephone number.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">custom-attributes</td>
<td style="width: 516px;">Sets basic or custom attributes of the user object. For example,<br> custom-attributes="{\"notes\":\"a note about the contact\",\"company\":\"companyname\"}"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 153px;">title</td>
<td style="width: 516px;">The contact’s job title.</td>
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
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-create-contact contact-dn="cn=jack,dc=demisto,dc=int" description="Samurai" email=jack@company.com</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><code>Created contact with DN: cn=jack,dc=demisto,dc=int</code></p>
</div>
<div class="cl-preview-section">
<h3 id="update-attributes-of-an-ad-contact">9. Update attributes of an AD contact</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates attributes of an existing Active Directory contact.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-update-contact</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 223px;"><strong>Argument Name</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
<th style="width: 116px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 223px;">contact-dn</td>
<td style="width: 401px;">The contact’s DN.</td>
<td style="width: 116px;">Required</td>
</tr>
<tr>
<td style="width: 223px;">attribute-name</td>
<td style="width: 401px;">The name of the attribute to update.</td>
<td style="width: 116px;">Required</td>
</tr>
<tr>
<td style="width: 223px;">attribute-value</td>
<td style="width: 401px;">The attribute value to update.</td>
<td style="width: 116px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-update-contact contact-dn="cn=Jack,dc=demisto,dc=int" attribute-name="displayName" attribute-value="Jack H."</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Updated contact’s displayName to: Jack H.</p>
</div>
<div class="cl-preview-section">
<h3 id="disable-an-ad-user-account">10. Disable an AD user account</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Disables an Active Directory user account.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-disable-account</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">username</td>
<td style="width: 520px;">The username of the account to disable (sAMAccountName).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">base-dn</td>
<td style="width: 520px;">Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-disable-account username="jack"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>User “CN=jack,DC=demisto,DC=int” has been disabledUser jack was disabled</p>
</div>
<div class="cl-preview-section">
<h3 id="enable-an-ad-user-account">11. Enable an AD user account</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Enables a previously disabled Active Directory account.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-enable-account</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">username</td>
<td style="width: 497px;">The username of the account to enable (sAMAccountName).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">base-dn</td>
<td style="width: 497px;">Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-enable-account username="jack"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>User jack was enabledUser “CN=jack,DC=demisto,DC=int” has been enabled</p>
</div>
<div class="cl-preview-section">
<h3 id="unlock-an-ad-user-account">12. Unlock an AD user account</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Unlocks a previously locked Active Directory user account.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-unlock-account</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">username</td>
<td style="width: 524px;">The username of the account to unlock (sAMAccountName).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">base-dn</td>
<td style="width: 524px;">Root (e.g., DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-10">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-unlock-account username=mooncake</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-10">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><code>User "CN=mooncake,CN=Users,DC=demisto,DC=int" has been unlocked</code></p>
</div>
<div class="cl-preview-section">
<h3 id="set-a-new-password-for-an-ad-user-account">13. Set a new password for an AD user account</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Sets a new password for an Active Directory user. This command requires a secure connection (SSL,TLS).</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-set-new-password</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 524px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">username</td>
<td style="width: 524px;">The username of the account to set a new password for.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">password</td>
<td style="width: 524px;">The new password to set for the user.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">base-dn</td>
<td style="width: 524px;">Root (e.g. DC=domain,DC=com). By default, the Base DN configured for the instance will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-11">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-set-new-password username="NoaCo" password="noni1q2w3e!"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-11">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><code>User password successfully set</code></p>
</div>
<div class="cl-preview-section">
<h3 id="modify-the-computer-organizational-unit-in-a-domain">14. Modify the computer organizational unit in a domain</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Modifies the computer organizational unit within a domain.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-13">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-modify-computer-ou</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-13">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
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
<td style="width: 159px;">computer-name</td>
<td style="width: 510px;">The name of the computer to modify.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">full-superior-dn</td>
<td style="width: 510px;">Superior DN, e.g., OU=computers,DC=domain,DC=com (The specified domain must be the same as the current computer domain).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-13">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-modify-computer-ou computer-name=mike full-superior-dn=OU=Sarah,DC=demisto,DC=int</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-output-14">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p><code>"mike" was successfully moved to "OU=Sarah,DC=demisto,DC=int"</code></p>
</div>
<div class="cl-preview-section">
<h3 id="get-information-for-an-ad-user-account">15. Get information for an AD user account</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves detailed information about a user account. The user can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filter is specified, all users are returned.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-14">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-get-user</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-14">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 531px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">dn</td>
<td style="width: 531px;">The Distinguished Name of the user to get information for.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">name</td>
<td style="width: 531px;">The name of the user to get information for.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">attributes</td>
<td style="width: 531px;">Include these AD attributes of the resulting objects in addition to the default attributes.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">custom-field-type</td>
<td style="width: 531px;">Query users by this custom field type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">custom-field-data</td>
<td style="width: 531px;">Query users by this custom field data (relevant only if the <code>custom-field-type</code> argument is provided).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">username</td>
<td style="width: 531px;">Query users by the samAccountName attribute</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">limit</td>
<td style="width: 531px;">Maximum number of objects to return (default is 20).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">email</td>
<td style="width: 531px;">Query by the user’s email address.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">user-account-control-out</td>
<td style="width: 531px;">Include verbose translation for UserAccountControl flags.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-15">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 375px;"><strong>Path</strong></th>
<th style="width: 81px;"><strong>Type</strong></th>
<th style="width: 284px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.dn</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s distinguished name</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.displayName</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s display name</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.name</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s common name</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.sAMAccountName</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s sAMAccountName</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.userAccountControl</td>
<td style="width: 81px;">number</td>
<td style="width: 284px;">The user’s account control flag</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.mail</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s email address</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.manager</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s manager</td>
</tr>
<tr>
<td style="width: 375px;">ActiveDirectory.Users.memberOf</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">Groups the user is member of</td>
</tr>
<tr>
<td style="width: 375px;">Account.DisplayName</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s display name</td>
</tr>
<tr>
<td style="width: 375px;">Account.Groups</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">Groups the user is member of</td>
</tr>
<tr>
<td style="width: 375px;">Account.Manager</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s manager</td>
</tr>
<tr>
<td style="width: 375px;">Account.ID</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s distinguished name</td>
</tr>
<tr>
<td style="width: 375px;">Account.Username</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s samAccountName</td>
</tr>
<tr>
<td style="width: 375px;">Account.Email</td>
<td style="width: 81px;">string</td>
<td style="width: 284px;">The user’s email address</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-13">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-get-user name=*</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-13">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="active-directory---get-users">Active Directory - Get Users</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>dn</th>
<th>displayName</th>
<th>mail</th>
<th>manager</th>
<th>memberOf</th>
<th>name</th>
<th>sAMAccountName</th>
<th>userAccountControl</th>
</tr>
</thead>
<tbody>
<tr>
<td>CN=demistoadmin,CN=Users,DC=demisto,DC=int</td>
<td>demistoadmin</td>
<td>demistoadmin@demisto.int</td>
<td> </td>
<td>CN=Discovery Management,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int,<br> CN=Organization Management,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int,<br> CN=Group Policy Creator Owners,CN=Users,DC=demisto,DC=int,<br> CN=Domain Admins,CN=Users,DC=demisto,DC=int,<br> CN=Enterprise Admins,CN=Users,DC=demisto,DC=int,<br> CN=Schema Admins,CN=Users,DC=demisto,DC=int,<br> CN=Administrators,CN=Builtin,DC=demisto,DC=int</td>
<td>demistoadmin</td>
<td>demistoadmin</td>
<td>66048</td>
</tr>
<tr>
<td>CN=Guest,CN=Users,DC=demisto,DC=int</td>
<td> </td>
<td> </td>
<td> </td>
<td>CN=Guests,CN=Builtin,DC=demisto,DC=int</td>
<td>Guest</td>
<td>Guest</td>
<td>66082</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-information-for-a-computer-account">16. Get information for a computer account</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves detailed information about a computer account. The computer can be specified by name, email address, or as an Active Directory Distinguished Name (DN). If no filters are provided, all computers are returned.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-15">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-get-computer</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-15">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">dn</td>
<td style="width: 521px;">The computer’s DN.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">name</td>
<td style="width: 521px;">The name of the computer to get information for.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">attributes</td>
<td style="width: 521px;">Include these AD attributes of the resulting objects in addition to the default attributes.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">custom-field-data</td>
<td style="width: 521px;">Search computers by this custom field data (relevant only if the <code>customFieldType</code> argument is provided).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">custom-field-type</td>
<td style="width: 521px;">The custom field type to search by.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-16">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 296px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 366px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">ActiveDirectory.Computers.dn</td>
<td style="width: 78px;">unknown</td>
<td style="width: 366px;">The computer distinguished name</td>
</tr>
<tr>
<td style="width: 296px;">ActiveDirectory.Computers.memberOf</td>
<td style="width: 78px;">unknown</td>
<td style="width: 366px;">Groups the computer is listed as a member</td>
</tr>
<tr>
<td style="width: 296px;">ActiveDirectory.Computers.name</td>
<td style="width: 78px;">unknown</td>
<td style="width: 366px;">The computer name</td>
</tr>
<tr>
<td style="width: 296px;">Endpoint.ID</td>
<td style="width: 78px;">unknown</td>
<td style="width: 366px;">The computer DN</td>
</tr>
<tr>
<td style="width: 296px;">Endpoint.Hostname</td>
<td style="width: 78px;">unknown</td>
<td style="width: 366px;">The computer name</td>
</tr>
<tr>
<td style="width: 296px;">Endpoint.Groups</td>
<td style="width: 78px;">unknown</td>
<td style="width: 366px;">Groups the computer is listed as a member of</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-14">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>ad-get-computer name=noapc</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "ActiveDirectory.Computers": [
        {
            "dn": "CN=noapc,OU=Shani,DC=demisto,DC=int", 
            "memberOf": [
                "CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int"
            ], 
            "name": [
                "noapc"
            ]
        }
    ], 
    "Endpoint": [
        {
            "Hostname": [
                "noapc"
            ], 
            "Type": "AD", 
            "ID": "CN=noapc,OU=Shani,DC=demisto,DC=int", 
            "Groups": [
                "CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int"
            ]
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-14">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="active-directory---get-computers">Active Directory - Get Computers</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>dn</th>
<th>memberOf</th>
<th>name</th>
</tr>
</thead>
<tbody>
<tr>
<td>CN=noapc,OU=Shani,DC=demisto,DC=int</td>
<td>CN=Exchange Servers,OU=Microsoft Exchange Security Groups,DC=demisto,DC=int</td>
<td>noapc</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-users-or-computers-for-a-group">17. Get a list of users or computers for a group</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves the list of users or computers that are members of the specified group.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-16">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>ad-get-group-members</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-16">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 519px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">group-dn</td>
<td style="width: 519px;">Group’s Active Directory Distinguished Name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 150px;">member-type</td>
<td style="width: 519px;">The member type to query by.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 150px;">attributes</td>
<td style="width: 519px;">A CSV list of attributes to include in the results (in addition to the default attributes).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 150px;">time_limit</td>
<td style="width: 519px;">Time limit (in seconds) for the search to run.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-17">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 350px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 330px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 350px;">ActiveDirectory.Groups.dn</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">The group DN.</td>
</tr>
<tr>
<td style="width: 350px;">ActiveDirectory.Groups.members.dn</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">The group member DN.</td>
</tr>
<tr>
<td style="width: 350px;">ActiveDirectory.Groups.members.category</td>
<td style="width: 60px;">string</td>
<td style="width: 330px;">The category ("person" or "computer".</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-15">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!ad-get-group-members group-dn="CN=Group124,OU=DemistoMng,DC=demisto,DC=int"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Account": [
        {
            "DisplayName": [
                "User 671 User 671"
            ],
            "Email": null,
            "Groups": [
                "CN=Group124,OU=DemistoMng,DC=demisto,DC=int",
                "CN=Group2,OU=DemistoMng,DC=demisto,DC=int"
            ],
            "ID": "CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int",
            "Managr": [],
            "Type": "AD",
            "Username": null
        }
    ],
    "ActiveDirectory": {
        "Groups": {
            "dn": "CN=Group124,OU=DemistoMng,DC=demisto,DC=int",
            "members": [
                {
                    "category": "person",
                    "dn": "CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int"
                }
            ]
        },
        "Users": {
            "displayName": [
                "User 671 User 671"
            ],
            "dn": "CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int",
            "mail": [
                "test@demisto.int"
            ],
            "manager": [],
            "memberOf": [
                "CN=Group124,OU=DemistoMng,DC=demisto,DC=int",
                "CN=Group2,OU=DemistoMng,DC=demisto,DC=int"
            ],
            "name": [
                "User 671 User 671"
            ],
            "sAMAccountName": [
                "User 671User 671"
            ],
            "userAccountControl": [
                514
            ]
        }
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-15">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="active-directory---get-group-members">Active Directory - Get Group Members</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>dn</th>
<th>displayName</th>
<th>mail</th>
<th>manager</th>
<th>memberOf</th>
<th>name</th>
<th>sAMAccountName</th>
<th>userAccountControl</th>
</tr>
</thead>
<tbody>
<tr>
<td>CN=User 671 User 671,OU=DemistoMng,DC=demisto,DC=int</td>
<td>User 671 User 671</td>
<td>test@demisto.int</td>
<td> </td>
<td>CN=Group124,OU=DemistoMng,DC=demisto,DC=int,<br> CN=Group2,OU=DemistoMng,DC=demisto,DC=int</td>
<td>User 671 User 671</td>
<td>User 671User 671</td>
<td>514</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h2 id="additional-information">Additional Information</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>LDAP attributes: <a href="https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx">https://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx</a>
</li>
<li>Distinguished Names explanation and examples: <a href="https://ldap.com/ldap-dns-and-rdns/">https://ldap.com/ldap-dns-and-rdns/</a>
</li>
</ul>
</div>
