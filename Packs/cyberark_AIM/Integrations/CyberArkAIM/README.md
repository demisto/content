<!-- HTML_DOC -->
<p>Deprecated. Use the CyberArk AIM v2 integration instead.</p>
<h2>Configure CyberArkAIM on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for CyberArkAIM.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://192.168.0.1/" rel="nofollow">https://192.168.0.1</a>)</strong></li>
<li><strong>Port</strong></li>
<li><strong>AppID as configured in AIM</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Folder to search in safe</strong></li>
<li><strong>Safe to search in</strong></li>
<li><strong>isFetchCredentials</strong></li>
<li><strong>API Username</strong></li>
<li><strong>API Password</strong></li>
<li><strong>Credential names - comma-seperated list of credentials names in vault</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_30574870731547476172583">Search for credentials: cyber-ark-aim-query</a></li>
<li><a href="#h_632417558321547476178860">Get a list of credentials: list-credentials</a></li>
<li><a href="#h_626986714621547476184885">Reset account password: reset-credentials</a></li>
<li><a href="#h_983844657911547476190726">Get information for an account: account-details</a></li>
</ol>
<h3 id="h_30574870731547476172583">1. Search for credentials</h3>
<hr>
<p>Search credentials in CyberArk AIM. Only one result is returned.</p>
<h5>Base Command</h5>
<p><code>cyber-ark-aim-query</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 151px;"><strong>Argument Name</strong></th>
<th style="width: 518px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">username</td>
<td style="width: 518px;">Username to query</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">address</td>
<td style="width: 518px;">Address to query</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">safe</td>
<td style="width: 518px;">Safe to query</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">folder</td>
<td style="width: 518px;">Folder to query</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">object</td>
<td style="width: 518px;">Object to query</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">query</td>
<td style="width: 518px;">Defines a free query using account properties, including Safe, folder, and object. When this method is specified, all other search criteria are ignored</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">queryFormat</td>
<td style="width: 518px;">Defines the query format, which can optionally use regular expressions</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">reason</td>
<td style="width: 518px;">The reason for retrieving the password. This reason will be audited in the Credential Provider audit log.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 151px;">database</td>
<td style="width: 518px;">Defines search criteria according to the database account property</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 383px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 281px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 383px;">CyberArk.AIM.Folder</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account folder</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.PasswordChangeInProcess</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Is password change in process</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.Content</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account content</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.CreationMethod</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account creation method</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.Name</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account name</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.PolicyID</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account policy ID</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.CPMDisabled</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account CPM disabled</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.Address</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account address</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.Safe</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account safe</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.UserName</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account username</td>
</tr>
<tr>
<td style="width: 383px;">CyberArk.AIM.DeviceType</td>
<td style="width: 76px;">unknown</td>
<td style="width: 281px;">Account device type</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h3 id="h_632417558321547476178860">2. Get a list of all credentials</h3>
<hr>
<p>Lists all credentials available.</p>
<h5>Base Command</h5>
<p><code>list-credentials</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 487px;"><strong>Description</strong></th>
<th style="width: 92px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">identifier</td>
<td style="width: 487px;">When used, command will return a specific credential</td>
<td style="width: 92px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h3 id="h_626986714621547476184885">3. Reset account password</h3>
<hr>
<p>Resets the password for the specified account with a random password.</p>
<h5>Base Command</h5>
<p><code>reset-credentials</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 178px;"><strong>Argument Name</strong></th>
<th style="width: 391px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 178px;">immediateChangeByCPM</td>
<td style="width: 391px;">Flag the CPM that the change is effective immediately</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 178px;">accountId</td>
<td style="width: 391px;">Account ID to reset password</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.<code>
</code></p>
<h3 id="h_983844657911547476190726">4. Get information for an account</h3>
<hr>
<p>This method returns information about an account. If more than one account meets the search criteria, only the first account will be returned.</p>
<h5>Base Command</h5>
<p><code>account-details</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 183px;"><strong>Argument Name</strong></th>
<th style="width: 452px;"><strong>Description</strong></th>
<th style="width: 105px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 183px;">keywords</td>
<td style="width: 452px;">Keywords matching the account</td>
<td style="width: 105px;">Required</td>
</tr>
<tr>
<td style="width: 183px;">safe</td>
<td style="width: 452px;">Specify a safe instead of a specific instance</td>
<td style="width: 105px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>