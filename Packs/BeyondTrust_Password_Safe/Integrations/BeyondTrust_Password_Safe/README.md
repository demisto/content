<!-- HTML_DOC -->
<p>Unified password and session management for seamless accountability and control over privileged accounts. </p>
<p>Each command is assigned a role. Users will not be able to run commands for which they are not assigned to the specific role for a command.</p>
<h2>Fetch Incidents</h2>
<p>For the fetch incidents function to work properly, you need to create a new asset, managed system, and managed account in BeyondTrust.</p>
<ol>
<li>In the BeyondTrust platform, create a new asset.</li>
<li>Create a managed system.<br>The name of the system should be the name of the integration (service/platform) you want to use, which will make it easier to filter credentials.</li>
<li>In the managed system, create a managed account.<br>The name of the managed account will be the username/email (depending on how the instance is configured) and the password will be the password of the integration (when creating an instance).</li>
</ol>
<h2>Create a BeyondTrust API Key</h2>
<p><span>To configure an integration instance, you need your BeyondTrust API key. The API key is generated after you configure an API Registration. For detailed instructions, see the </span><a href="https://www.beyondtrust.com/docs/archive/password-safe-beyondinsight/6-9/ps-admin-6-9-0.pdf" rel="nofollow">BeyondTrust Password Safe Admin Guide</a><span>.</span></p>
<h2>Configure BeyondTrust Password Safe on Demisto</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for BeyondTrust Password Safe.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span>https://192.168.0.1)</strong></li>
<li><strong>Username</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Fetch credentials</strong></li>
<li><strong>System Name (optional for fetch credentials)</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<p>Each command is assigned a role. Users will not be able to run commands for which they are not assigned to the specific role for a command.</p>
<ol>
<li><a href="#h_87ed0533-b4aa-4acb-9b40-3f31ac7ff37c" target="_self">Get a list of managed accounts for the current user: beyondtrust-get-managed-accounts</a></li>
<li><a href="#h_7f66120b-105c-4def-ac79-5b6ea1f1ca20" target="_self">Get a list of managed systems: beyondtrust-get-managed-systems</a></li>
<li><a href="#h_691cb7de-f1d4-4cfa-b732-ede383ed5435" target="_self">Create a new credentials release request: beyondtrust-create-release-request</a></li>
<li><a href="#h_e18a6f4e-77b7-443c-96cf-c25a634be2a7" target="_self">Check in or release a request: beyondtrust-check-in-credentials</a></li>
<li><a href="#h_1052f1ec-814b-4563-863e-780379a3d0b1" target="_self">Get credential for an approved credentials release request: beyondtrust-get-credentials</a></li>
<li><a href="#h_7e528ef9-336c-4b9d-bc6a-26141cfa1e2b" target="_self">Update credentials for a managed account: beyondtrust-change-credentials</a></li>
</ol>
<h3 id="h_87ed0533-b4aa-4acb-9b40-3f31ac7ff37c">1. Get a list of managed accounts for the current user</h3>
<hr>
<p>Returns a list of managed accounts that the current user has permissions to request.</p>
<h5>Base Command</h5>
<p><code>beyondtrust-get-managed-accounts</code></p>
<h5>Input</h5>
<p>There are no inputs for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 340px;"><strong>Path</strong></th>
<th style="width: 54px;"><strong>Type</strong></th>
<th style="width: 346px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 340px;">BeyondTrust.Account.PlatformID</td>
<td style="width: 54px;">Number</td>
<td style="width: 346px;">ID of the managed system platform.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.SystemID</td>
<td style="width: 54px;">Number</td>
<td style="width: 346px;">ID of the managed system.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.SystemName</td>
<td style="width: 54px;">String</td>
<td style="width: 346px;">Name of the managed system.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.DomainName</td>
<td style="width: 54px;">Number</td>
<td style="width: 346px;">ID of the managed account.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.AccountName</td>
<td style="width: 54px;">String</td>
<td style="width: 346px;">Name of the managed account.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.InstanceName</td>
<td style="width: 54px;">String</td>
<td style="width: 346px;">Database instance name of a database-type managed system.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.DefualtReleaseDuration</td>
<td style="width: 54px;">Number</td>
<td style="width: 346px;">Default release duration.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.MaximumReleaseDuration</td>
<td style="width: 54px;">Number</td>
<td style="width: 346px;">Maximum release duration.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.LastChangeDate</td>
<td style="width: 54px;">Date</td>
<td style="width: 346px;">The date and time of the last password change.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.NexeChangeDate</td>
<td style="width: 54px;">Date</td>
<td style="width: 346px;">The date and time of the next scheduled password change.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.IsChanging</td>
<td style="width: 54px;">Boolean</td>
<td style="width: 346px;">True if the account credentials are in the process of changing, otherwise false.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.IsISAAccess</td>
<td style="width: 54px;">Boolean</td>
<td style="width: 346px;">True if the account is for Information Systems Administrator (ISA) access, otherwise false.</td>
</tr>
<tr>
<td style="width: 340px;">BeyondTrust.Account.AccountID</td>
<td style="width: 54px;">Number</td>
<td style="width: 346px;">ID of the managed account.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!beyondtrust-get-managed-accounts</pre>
<h5>Human Readable Output</h5>
<h3>BeyondTrust Managed Accounts</h3>
<table border="2">
<thead>
<tr>
<th>AccountName</th>
<th>AccountID</th>
<th>AssetName</th>
<th>AssetID</th>
<th>LastChangeDate</th>
<th>NextChangeDate</th>
</tr>
</thead>
<tbody>
<tr>
<td>demisto</td>
<td>1</td>
<td>Demisto-lab-server</td>
<td>1</td>
<td>2019-05-30T07:30:48.16</td>
<td>2019-07-01T21:00:00,</td>
</tr>
<tr>
<td>Test</td>
<td>2</td>
<td>Demisto-lab-server</td>
<td>1</td>
<td>2019-05-30T12:05:06.683</td>
<td>2019-07-01T21:00:00,</td>
</tr>
<tr>
<td>shelly</td>
<td>3</td>
<td>shelly-test</td>
<td>2</td>
<td>2019-05-30T12:59:12.313</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7f66120b-105c-4def-ac79-5b6ea1f1ca20">2. Get a list of managed systems</h3>
<hr>
<p>Returns a list of managed systems.</p>
<h5>Base Command</h5>
<p><code>beyondtrust-get-managed-systems</code></p>
<h5>Input</h5>
<p>There are no inputs for this command.</p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 417px;"><strong>Path</strong></th>
<th style="width: 53px;"><strong>Type</strong></th>
<th style="width: 270px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 417px;">BeyondTrust.System.Port</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">The port used to connect to the host. If null and the related Platform.PortFlag is true, Password Safe uses Platform.DefaultPort for communication.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.Timeout</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">Connection timeout – Length of time in seconds before a slow or unresponsive connection to the system fails.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ResetPasswordOnMismatchFlag</td>
<td style="width: 53px;">Boolean</td>
<td style="width: 270px;">True to queue a password change when scheduled password test fails, otherwise false.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ChangeFrequencyDays</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">When ChangeFrequencyType is “xdays”, the frequency with which the password changes (between 1-90 days).</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ISAReleaseDuration</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">Default Information Systems Administrator (ISA) release duration.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.FunctionalAccountID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the functional account used for local Managed Account password changes.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ChangeFrequencyType</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">The change frequency for scheduled password changes: "first"– Changes are scheduled for the first day of the month; "last"– Changes are scheduled for the last day of the month; "xdays"– Changes are scheduled every "x" days (see ChangeFrequencyDays)</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.DirectoryID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the directory. Is set if the Managed System is a Directory.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ManagedAssetID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the Managed System.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.AssetID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the asset. Is set if the Managed System is an Asset or a Database.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.PlatformID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the Managed System Platform.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ElevationCommand</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">Elevation command to use (sudo, pbrun, or pmrun).</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.CheckPasswordFlag</td>
<td style="width: 53px;">Boolean</td>
<td style="width: 270px;">True to enable password testing, otherwise false.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.CloudID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the Cloud System. Is set if the Managed System is a Cloud System.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.DSSKeyRuleID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the default DSS Key Rule assigned to Managed Accounts that were created under this Managed System.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.PasswordRuleID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the default Password Rule assigned to Managed Accounts that were created under this Managed System.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.NetBiosName</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">Domain NetBIOS name. Setting this value will allow Password Safe to fall back to the NetBIOS name, if needed.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.DatabaseID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the database. Is set if the Managed System is a Database.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.MaxReleaseDuration</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">Default maximum release duration.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ChangePasswordAfterAnyReleaseFlag</td>
<td style="width: 53px;">Boolean</td>
<td style="width: 270px;">True to change passwords on release of a request, otherwise false.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.SystemName</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">Name of the related entity (Asset, Directory, Database, or Cloud).</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ReleaseDuration</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">Default release duration.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ContactEmail</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">Email address of the user that manages the system.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.Description</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">The description of the system.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.ChangeTime</td>
<td style="width: 53px;">String</td>
<td style="width: 270px;">Time (UTC) that password changes are scheduled to occur.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.AutoManagementFlag</td>
<td style="width: 53px;">Boolean</td>
<td style="width: 270px;">True if password auto-management is enabled, otherwise false.</td>
</tr>
<tr>
<td style="width: 417px;">BeyondTrust.System.LoginAccountID</td>
<td style="width: 53px;">Number</td>
<td style="width: 270px;">ID of the Functional Account used for SSH session logins.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!beyondtrust-get-managed-systems</pre>
<h5>Human Readable Output</h5>
<h3>BeyondTrust Managed Accounts</h3>
<table border="2">
<thead>
<tr>
<th>ManagedAssetID</th>
<th>ChangeFrequencyDays</th>
<th>AssetID</th>
<th>AssetName</th>
<th>PlatformID</th>
<th>Port</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>30</td>
<td>2</td>
<td>Demisto-lab-server</td>
<td>2</td>
<td>22,</td>
</tr>
<tr>
<td>2</td>
<td>30</td>
<td>3</td>
<td>shelly-test</td>
<td>2</td>
<td>22,</td>
</tr>
<tr>
<td>3</td>
<td>30</td>
<td>4</td>
<td>integration-test</td>
<td>2</td>
<td>22,</td>
</tr>
<tr>
<td>4</td>
<td>30</td>
<td>5</td>
<td>Cybereason</td>
<td>2</td>
<td>22</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_691cb7de-f1d4-4cfa-b732-ede383ed5435">3. Create a new credentials release request</h3>
<hr>
<p>Creates a new credentials release request. This command <span>gets the credentials (password) of the account for which the request was made. The outputs will show the credentials that were created for the account requested as plain text in the War Room,  so we recommend that after you run this command, you also run the <a href="#h_7e528ef9-336c-4b9d-bc6a-26141cfa1e2b" target="_self">beyondtrust-change-credentials</a> command.</span></p>
<h5>Base Command</h5>
<p><code>beyondtrust-create-release-request</code></p>
<h5>Input</h5>
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
<td style="width: 172px;">access_type</td>
<td style="width: 497px;">The type of access requested (View, RDP, SSH). Defualt is "View".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">system_id</td>
<td style="width: 497px;">ID of the Managed System to request. Get the ID from get-managed accounts command</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">account_id</td>
<td style="width: 497px;">ID of the Managed Account to request. Get the ID from get-managed accounts command</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">duration_minutes</td>
<td style="width: 497px;">The request duration (in minutes).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">reason</td>
<td style="width: 497px;">The reason for the request.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">conflict_option</td>
<td style="width: 497px;">The conflict resolution option to use if an existing request is found for the same user, system and account ("reuse" or "renew").</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 318px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 351px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 318px;">BeyondTrust.Request.Credentials</td>
<td style="width: 71px;">String</td>
<td style="width: 351px;">The credentials for the requested ID.</td>
</tr>
<tr>
<td style="width: 318px;">BeyondTrust.Request.RequestID</td>
<td style="width: 71px;">Number</td>
<td style="width: 351px;">The request ID.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!beyondtrust-create-release-request account_id=8 duration_minutes=2 system_id=3\</pre>
<h5>Human Readable Output</h5>
<h3 id="h_e18a6f4e-77b7-443c-96cf-c25a634be2a7">4. Check in or release a request</h3>
<hr>
<p>Checks-in/releases a request before it expires.</p>
<h5>Base Command</h5>
<p><code>beyondtrust-check-in-credentials</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 481px;"><strong>Description</strong></th>
<th style="width: 89px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">request_id</td>
<td style="width: 481px;">ID of the request to release.</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 170px;">reason</td>
<td style="width: 481px;">A reason or comment why the request is being released.</td>
<td style="width: 89px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!beyondtrust-check-in-credentials request_id=295\</pre>
<h5>Human Readable Output</h5>
<p>The release was successfully checked-in/released</p>
<h3 id="h_1052f1ec-814b-4563-863e-780379a3d0b1">5. Get credential for an approved credentials release request</h3>
<hr>
<p>Retrieves the credentials for an approved and active (not expired) credentials release request.</p>
<h5>Base Command</h5>
<p><code>beyondtrust-get-credentials</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 478px;"><strong>Description</strong></th>
<th style="width: 92px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">request_id</td>
<td style="width: 478px;">ID of the Request for which to retrieve the credentials</td>
<td style="width: 92px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!beyondtrust-get-credentials request_id=294\</pre>
<h5>Human Readable Output</h5>
<p>The credentials for BeyondTrust request: shelly</p>
<h3 id="h_7e528ef9-336c-4b9d-bc6a-26141cfa1e2b">6. Update credentials for a managed account</h3>
<hr>
<p>Updates the credentials for a Managed Account, optionally applying the change to the Managed System.</p>
<h5>Base Command</h5>
<p><code>beyondtrust-change-credentials</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 530px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">account_id</td>
<td style="width: 530px;">ID of the account for which to set the credentials.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 139px;">password</td>
<td style="width: 530px;">The new password to set. If not given, generates a new, random password.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">public_key</td>
<td style="width: 530px;">The new public key to set on the host. This is required if PrivateKey is given and updateSystem=true.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">private_key</td>
<td style="width: 530px;">The private key to set (provide Passphrase if encrypted).</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">pass_phrase</td>
<td style="width: 530px;">The passphrase to use for an encrypted private key.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">update_system</td>
<td style="width: 530px;">Whether to update the credentials on the referenced system.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!beyondtrust-change-credentials account_id=8</pre>
<h5>Human Readable Output</h5>
<p>The password has been changed</p>
