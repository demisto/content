<!-- HTML_DOC -->
<p>Use the Symantec Endpoint Protection integration to manage your organization’s endpoints.</p>
<h2>Use Cases</h2>
<ul>
<ul>
<li>Scan/Quarantine/content-update an endpoint.</li>
<li>Assign policy to an endpoint.</li>
<li>Move client to different group.</li>
</ul>
</ul>
<p><strong>Unsupported use cases in the API:</strong></p>
<ul>
<ul>
<li>Get scan results</li>
<li>Get reports/logs</li>
<li>Receive system alerts</li>
</ul>
</ul>
<h2>Required Permissions</h2>
<p>The following role is required to use the Symantec Endpoint Protection API:</p>
<ul>
<li>sysadmin</li>
</ul>
<h2>Configure Symantec Endpoint Protection V2 on Demisto</h2>
<ul>
<ul>
</ul>
</ul><ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Symantec Endpoint Protection V2.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
</ul>
</li>
</ol>
<ol start="4">
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>


<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<ul>
</ul>
</ul><ol>
<li><a href="#h_d78f2bc4-2301-415f-a38f-82392f2ecd3d" target="_self">Get endpoint information: sep-endpoints-info</a></li>
<li><a href="#h_8712e8d6-9700-4f38-b5be-31a9839b82bb" target="_self">Get group information: sep-groups-info</a></li>
<li><a href="#h_ed8ebbd3-b99c-4ff7-91e4-1b570fd22307" target="_self">Get system information: sep-system-info</a></li>
<li><a href="#h_ff841874-a4d7-4b06-9276-a4a79394d536" target="_self">Get the status of a comment: sep-command-status</a></li>
<li><a href="#h_724d8a8f-4d71-4bb6-b00d-4d8424d71a62" target="_self">Get a client's content: sep-client-content</a></li>
<li><a href="#h_68b59fcc-df96-4eb4-a3d9-a1f6db7432e3" target="_self">Get a list of all policies: sep-list-policies</a></li>
<li><a href="#h_6dd260f4-b605-4642-abbc-bbb9364e90d4" target="_self">Assign a policy: sep-assign-policy</a></li>
<li><a href="#h_c0f37a51-3739-4f20-a956-4465824ed0e3" target="_self">Get a list of location IDs for a group: sep-list-locations</a></li>
<li><a href="#h_a94940c8-6662-4557-b878-2c59e6c4af89" target="_self">Quarantine an endpoint: sep-endpoint-quarantine</a></li>
<li><a href="#h_74d2ac85-1b26-41a3-b6f3-d66cb57af74b" target="_self">Scan an endpoint: sep-scan-endpoint</a></li>
<li><a href="#h_da2481d9-a52c-4dc9-9a04-935321ff282d" target="_self">Update an endpoint's content: sep-update-endpoint-content</a></li>
<li><a href="#h_685c3737-08dd-4b75-a0b3-8400f3f57646" target="_self">Move a client to a group: sep-move-client-to-group</a></li>
<li><a href="#h_1f33c82e-9a16-446f-86fe-a200996cf2db" target="_self">Get endpoints for a running version: sep-identify-old-clients</a></li>
</ol>


<h3 id="h_d78f2bc4-2301-415f-a38f-82392f2ecd3d">1. Get endpoint information</h3>
<hr>
<p>Returns information about endpoints.</p>
<h5>Base Command</h5>
<p><code>sep-endpoints-info</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 166px;"><strong>Argument Name</strong></th>
<th style="width: 471px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 166px;">columns</td>
<td style="width: 471px;">A CSV list of the displayed columns.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">computerName</td>
<td style="width: 471px;">Filters by the host name of the computer. A wild card search can be done using '*' at the end of the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">lastUpdate</td>
<td style="width: 471px;">Indicates when a computer's status was last updated. The default is "0", which returns all results.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">os</td>
<td style="width: 471px;">The operating system by which to filter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">pageSize</td>
<td style="width: 471px;">The number of results to include on each page. The default is 20.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 166px;">groupName</td>
<td style="width: 471px;">The name of the group to which the endpoint belongs. A wild card search can be done using '*' at the end of the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 259px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 386px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 259px;">SEPM.Endpoint.Hostname</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The hostname of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.Domain</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The domain of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.IPAddresses</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The IP addresses of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.OS</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The OS information of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.Description</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The description of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.MACAddresses</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.BIOSVersion</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The BIOS version of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.DHCPServer</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The DHCP server address of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.HardwareKey</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The hardware key of the client to be moved.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.LastScanTime</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The last scan time of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.RunningVersion</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The running version of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.TargetVersion</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The target version of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">IP.Address</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">IP.Host</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The IP host of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.Hostname</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 386px;">The hostname of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.MACAddress</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 386px;">The MAC address of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.Domain</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 386px;">The domain of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.IPAddress</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 386px;">The IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.DHCPServer</td>
<td style="width: 63px;">Unknown</td>
<td style="width: 386px;">The DHCP server of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.OS</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The OS of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.OSVersion</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The OS version of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.BIOSVersion</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The BIOS version of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.Memory</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The memory of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">Endpoint.Processors</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The processors that the endpoint uses.</td>
</tr>
<tr>
<td style="width: 259px;">IP.Hostname</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The hostname that is mapped to this IP address.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.Group</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The group of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.PatternIdx</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The PatternIdx of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.OnlineStatus</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The online status of the endpoint.</td>
</tr>
<tr>
<td style="width: 259px;">SEPM.Endpoint.UpdateTime</td>
<td style="width: 63px;">String</td>
<td style="width: 386px;">The update time of the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-endpoints-info</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_1.png" alt="Human_Readable_Output_1.png"></p>
<h3 id="h_8712e8d6-9700-4f38-b5be-31a9839b82bb">2. Get group information</h3>
<hr>
<p>Returns information about groups.</p>
<h5>Base Command</h5>
<p><code>sep-groups-info</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 188px;"><strong>Argument Name</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
<th style="width: 102px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188px;">columns</td>
<td style="width: 418px;">The column by which the results are sorted.</td>
<td style="width: 102px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 311px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 339px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 311px;">SEPM.Groups</td>
<td style="width: 58px;">Unknown</td>
<td style="width: 339px;">The list of groups.</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.created</td>
<td style="width: 58px;">number</td>
<td style="width: 339px;">The time of creation time (in Epoch).</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.fullPathName</td>
<td style="width: 58px;">string</td>
<td style="width: 339px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.id</td>
<td style="width: 58px;">string</td>
<td style="width: 339px;">The ID of the group.</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.numberOfPhysicalComputers</td>
<td style="width: 58px;">number</td>
<td style="width: 339px;">The number of physical computers in the group.</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.numberOfRegisteredUsers</td>
<td style="width: 58px;">number</td>
<td style="width: 339px;">The number of registered users in the group.</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.policyDate</td>
<td style="width: 58px;">number</td>
<td style="width: 339px;">The date of the policy (in Epoch).</td>
</tr>
<tr>
<td style="width: 311px;">SEPM.Groups.policySerialNumber</td>
<td style="width: 58px;">number</td>
<td style="width: 339px;">The serial number of the policy.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-groups-info</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_2.png" alt="Human_Readable_Output_2.png"></p>
<h3 id="h_ed8ebbd3-b99c-4ff7-91e4-1b570fd22307">3. Get system information</h3>
<hr>
<p>Returns information about the system, such as version or AV definition.</p>
<h5>Base Command</h5>
<p><code>sep-system-info</code></p>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 302px;"><strong>Path</strong></th>
<th style="width: 54px;"><strong>Type</strong></th>
<th style="width: 352px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 302px;">SEPM.ServerAVDefVersion</td>
<td style="width: 54px;">string</td>
<td style="width: 352px;">
<div>
<div>
<span>The version or anti-virus definition of the server</span>.</div>
</div>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-system-info</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_3.png" alt="Human_Readable_Output_3.png"></p>
<h3 id="h_ff841874-a4d7-4b06-9276-a4a79394d536">4. Get the status of a command</h3>
<hr>
<p>Retrieves the status of a command.</p>
<h5>Base Command</h5>
<p><code>sep-command-status</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 264px;"><strong>Argument Name</strong></th>
<th style="width: 303px;"><strong>Description</strong></th>
<th style="width: 141px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 264px;">commandId</td>
<td style="width: 303px;">The ID of the command.</td>
<td style="width: 141px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 355px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 279px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 355px;">SEPM.LastCommand.CommandDetails</td>
<td style="width: 74px;">string</td>
<td style="width: 279px;">The details of the command.</td>
</tr>
<tr>
<td style="width: 355px;">SEPM.LastCommand.CommandId</td>
<td style="width: 74px;">string</td>
<td style="width: 279px;">The ID of the command.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-command-status commandId=04A68CA5952B4726AAFEB421E0EB436C</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_4.png" alt="Human_Readable_Output_4.png"></p>
<h3 id="h_724d8a8f-4d71-4bb6-b00d-4d8424d71a62">5. Get a client's content</h3>
<hr>
<p>Retrieves the content of the client.</p>
<h5>Base Command</h5>
<p><code>sep-client-content</code></p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 267px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 367px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 267px;">SEPM.ClientContentVersions</td>
<td style="width: 74px;">string</td>
<td style="width: 367px;">Displays the versions for each client.</td>
</tr>
<tr>
<td style="width: 267px;">SEPM.LastUpdated</td>
<td style="width: 74px;">string</td>
<td style="width: 367px;">
<div>
<div><span>The last time that the client's content was updated.</span></div>
</div>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-client-content</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_5.png" alt="Human_Readable_Output_5.png"></p>
<h3 id="h_68b59fcc-df96-4eb4-a3d9-a1f6db7432e3">6. Get a list of all policies</h3>
<hr>
<p>Retrieves a list of existing policies.</p>
<h5>Base Command</h5>
<p><code>sep-list-policies</code></p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 304px;"><strong>Path</strong></th>
<th style="width: 100px;"><strong>Type</strong></th>
<th style="width: 304px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.PolicyName</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The name of the policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.Type</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The type of the policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.ID</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The ID of the policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.Description</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The description of the policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.Enabled</td>
<td style="width: 100px;">boolean</td>
<td style="width: 304px;">Whether the list of polices is enabled. Enabled if "True".</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.AssignedLocations.GroupID</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The ID of the group of the locations assigned to this policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.AssignedLocations.Locations</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The list of location IDs assigned to this policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.AssignedCloudGroups.GroupID</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The ID of the cloud group of the locations assigned to this policy.</td>
</tr>
<tr>
<td style="width: 304px;">SEPM.PoliciesList.AssignedCloudGroups.Locations</td>
<td style="width: 100px;">string</td>
<td style="width: 304px;">The list of location IDs belonging to a cloud group assigned to this policy.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-list-policies</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_6.png" alt="Human_Readable_Output_6.png"></p>
<h3 id="h_6dd260f4-b605-4642-abbc-bbb9364e90d4">7. Assign a policy</h3>
<hr>
<p>Assigns an existing policy to a specified location.</p>
<h5>Base Command</h5>
<p><code>sep-assign-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 190px;"><strong>Argument Name</strong></th>
<th style="width: 426px;"><strong>Description</strong></th>
<th style="width: 92px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 190px;">groupID</td>
<td style="width: 426px;">The ID of the group to which the endpoint belongs.</td>
<td style="width: 92px;">Required</td>
</tr>
<tr>
<td style="width: 190px;">locationID</td>
<td style="width: 426px;">The ID of the location of the endpoint.</td>
<td style="width: 92px;">Required</td>
</tr>
<tr>
<td style="width: 190px;">policyType</td>
<td style="width: 426px;">The type of policy to be assigned.</td>
<td style="width: 92px;">Required</td>
</tr>
<tr>
<td style="width: 190px;">policyID</td>
<td style="width: 426px;">The ID of the policy to be assigned.</td>
<td style="width: 92px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-assign-policy groupID=44BE96AFC0A8010B0CFACB30929326C2 locationID=50FEEA3FC0A8010B739E49CB0C321A7E policyID=A00ADE188AA148D7AD319CBCA1FA2F23 policyType=hi</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_7.png" alt="Human_Readable_Output_7.png"></p>
<h3 id="h_c0f37a51-3739-4f20-a956-4465824ed0e3">8. Get a list of location IDs for a group</h3>
<hr>
<p>Retrieves a list of location IDs for a specified group.</p>
<h5>Base Command</h5>
<p><code>sep-list-locations</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 203px;"><strong>Argument Name</strong></th>
<th style="width: 396px;"><strong>Description</strong></th>
<th style="width: 109px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 203px;">groupID</td>
<td style="width: 396px;">The group ID for which to list locations.</td>
<td style="width: 109px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 247px;"><strong>Path</strong></th>
<th style="width: 148px;"><strong>Type</strong></th>
<th style="width: 313px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 247px;">SEPM.Locations.ID</td>
<td style="width: 148px;">Unknown</td>
<td style="width: 313px;">The ID of the location.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-list-locations groupID=44BE96AFC0A8010B0CFACB30929326C2</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_8.png" alt="Human_Readable_Output_8.png"></p>
<h3 id="h_a94940c8-6662-4557-b878-2c59e6c4af89">9. Quarantine an endpoint</h3>
<hr>
<p>Quarantines an endpoint according to its policy.</p>
<h5>Base Command</h5>
<p><code>sep-endpoint-quarantine</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 186px;"><strong>Argument Name</strong></th>
<th style="width: 424px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 186px;">endpoint</td>
<td style="width: 424px;">The IP or hostname of the endpoint.</td>
<td style="width: 98px;">Required</td>
</tr>
<tr>
<td style="width: 186px;">actionType</td>
<td style="width: 424px;">Adds or removes an endpoint from quarantine.</td>
<td style="width: 98px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 220px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 220px;">SEPM.Quarantine.CommandID</td>
<td style="width: 59px;">string</td>
<td style="width: 429px;">The ID of the command that was run.</td>
</tr>
<tr>
<td style="width: 220px;">SEPM.Quarantine.Action</td>
<td style="width: 59px;">string</td>
<td style="width: 429px;">The type of the action type. Can be "Add" or "Remove".</td>
</tr>
<tr>
<td style="width: 220px;">SEPM.Quarantine.Endpoint</td>
<td style="width: 59px;">string</td>
<td style="width: 429px;">The IP or hostname of the identifier of the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-endpoint-quarantine actionType=add endpoint=demisto-PC</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_9.png" alt="Human_Readable_Output_9.png"></p>
<h3 id="h_74d2ac85-1b26-41a3-b6f3-d66cb57af74b">10. Scan an endpoint</h3>
<hr>
<p>Scans an endpoint.</p>
<h5>Base Command</h5>
<p><code>sep-scan-endpoint</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 171px;"><strong>Argument Name</strong></th>
<th style="width: 466px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 171px;">endpoint</td>
<td style="width: 466px;">The IP address or hostname of the endpoint.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 171px;">scanType</td>
<td style="width: 466px;">The scan type of the endpoint. Can be "ScanNow_Quick", "ScanNow_Full", or "ScanNow_Custom".</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 177px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 177px;">SEPM.Scan.CommandID</td>
<td style="width: 61px;">string</td>
<td style="width: 470px;">The ID of the command that was run.</td>
</tr>
<tr>
<td style="width: 177px;">SEPM.Scan.Type</td>
<td style="width: 61px;">string</td>
<td style="width: 470px;">The type of the scan. Can be "ScanNow_Quick", "ScanNow_Full", or "ScanNow_Custom".</td>
</tr>
<tr>
<td style="width: 177px;">SEPM.Scan.Endpoint</td>
<td style="width: 61px;">Unknown</td>
<td style="width: 470px;">The IP or hostname of the identifier of the endpoint.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-scan-endpoint endpoint=demisto-PC scanType=ScanNow_Quick</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_10.png" alt="Human_Readable_Output_10.png"></p>
<h3 id="h_da2481d9-a52c-4dc9-9a04-935321ff282d">11. Update an endpoint's content</h3>
<hr>
<p>Updates the content of a specified client.</p>
<h5>Base Command</h5>
<p><code>sep-update-endpoint-content</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 193px;"><strong>Argument Name</strong></th>
<th style="width: 414px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">endpoint</td>
<td style="width: 414px;">The IP address or hostname of the endpoint.</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">SEPM.Update.Endpoint</td>
<td style="width: 61px;">String</td>
<td style="width: 441px;">The endpoint that is being updated.</td>
</tr>
<tr>
<td style="width: 206px;">SEPM.Update.CommandID</td>
<td style="width: 61px;">String</td>
<td style="width: 441px;">The ID of the command for which to check the status.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-update-endpoint-content endpoint=demisto-PC</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_11.png" alt="Human_Readable_Output_11.png"></p>
<h3 id="h_685c3737-08dd-4b75-a0b3-8400f3f57646">12. Move a client to a group</h3>
<hr>
<p>Moves a client to a group.</p>
<h5>Base Command</h5>
<p><code>sep-move-client-to-group</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 181px;"><strong>Argument Name</strong></th>
<th style="width: 431px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 181px;">groupID</td>
<td style="width: 431px;">The ID of the group to which to move the client.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 181px;">hardwareKey</td>
<td style="width: 431px;">The hardware key of the client to be moved.</td>
<td style="width: 96px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-move-client-to-group groupID=AA51516BC0A8010B3BFBBE37F7B71214 hardwareKey=269CE816FDB1BA25A2505D0A5A59294C</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_112.png" alt="Human_Readable_Output_112.png"></p>
<h3 id="h_1f33c82e-9a16-446f-86fe-a200996cf2db">13. Get endpoints for a running version</h3>
<hr>
<p>Get endpoints for a running version that is different than the target version or the desired version (if specified).</p>
<h5>Base Command</h5>
<p><code>sep-identify-old-clients</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">columns</td>
<td style="width: 453px;">Sets which columns will be displayed.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">computerName</td>
<td style="width: 453px;">Filters by the hostname of the computer. A wild card search can be done using '*' at the end of the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">lastUpdate</td>
<td style="width: 453px;">Indicates when a computer's status was last updated. The default is "0", which returns all results.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">os</td>
<td style="width: 453px;">The operating system by which to filter.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">pageSize</td>
<td style="width: 453px;">The number of results to include on each page. The default is 20.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">groupName</td>
<td style="width: 453px;">The name of the group to which the endpoint belongs. A wild card search can be done using '*'at the end of the query.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">desiredVersion</td>
<td style="width: 453px;">desiredVersion</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!sep-identify-old-clients desiredVersion=10</pre>
<h5>Human Readable Output</h5>
<p><img src="https://raw.githubusercontent.com/demisto/content/master/docs/images/Integrations/SymantecEndpointProtection_V2_Human_Readable_Output_13.png" alt="Human_Readable_Output_13.png"></p>
<h2>Known Limitations</h2>
<ul>
<li>SEPM REST- API currently exposes statistics, but does not expose extended information about Risks, Application and Device control, and Network logs.</li>
<li>SEPM REST- API currently does not support an operation to get Host Names or IP addresses of clients who don’t have an update content version.</li>
<li>SEPM REST- API currently does not support an operation to create or download reports.</li>
</ul>
