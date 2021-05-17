<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the Fortinet FortiGate integration to manage firewall settings and groups.</p>
<p>We recommend that users have an API account that is set to root vdom in order to access all commands.</p>
<p>This integration was integrated and tested with FortiOS 5.6.8</p>
<h2>Configure FortiGate on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for FortiGate.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. 192.168.0.1)</strong></li>
<li><strong>Account username</strong></li>
<li><strong>Account password</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, username + password, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_90934042941543315010414">Get all address objects from the firewall: fortigate-get-addresses</a></li>
<li><a href="#h_251291621171543315015519">Get information about service groups: fortigate-get-service-groups</a></li>
<li><a href="#h_2511153492291543315020336">Update a service group: fortigate-update-service-group</a></li>
<li><a href="#h_549888813401543315025030">Delete a service group: fortigate-delete-service-group</a></li>
<li><a href="#h_2658967384501543315029859">Get service information: fortigate-get-firewall-service</a></li>
<li><a href="#h_4649504885591543315036188">Create a firewall service: fortigate-create-firewall-service</a></li>
<li><a href="#h_6602236946671543315041059">Get firewall policy information: fortigate-get-policy</a></li>
<li><a href="#h_8412979427741543315053679">Update a firewall policy: fortigate-update-policy</a></li>
<li><a href="#h_1422688068801543315066050">Create a firewall policy: fortigate-create-policy</a></li>
<li><a href="#h_4085733299851543315074230">Relocate a firewall policy: fortigate-move-policy</a></li>
<li><a href="#h_24259910811861543315086356">Delete a firewall policy: fortigate-delete-policy</a></li>
<li><a href="#h_2455845312891543315091313">Get information for address groups: fortigate-get-address-groups</a></li>
<li><a href="#h_71275394613911543315098969">Update an address group: fortigate-update-address-group</a></li>
<li><a href="#h_90703567814921543315103725">Create an address group: fortigate-create-address-group</a></li>
<li><a href="#h_57698000216851543315108111">Delete an address group: fortigate-delete-address-group</a></li>
<li><a href="#h_97579068-1993-4df6-9b15-e0d83d9dc003" target="_self">Add an address to a banned list: fortigate-ban-ip</a></li>
<li><a href="#h_dcbeef7c-2cfa-45b2-b677-cf1f4ea09895" target="_self">Clear a list of banned addresses: fortigate-unban-ip</a></li>
<li><a href="#h_09f6b36f-9215-42e9-9e86-e075c485f534" target="_self">Get a list of banned addresses: fortigate-get-banned-ips</a></li>
</ol>
<h3 id="h_90934042941543315010414">1. Get all address objects from the firewall</h3>
<hr>
<p>Returns all address objects from your firewall.</p>
<h5>Base Command</h5>
<p><code>fortigate-get-addresses</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 210px;"><strong>Argument Name</strong></th>
<th style="width: 374px;"><strong>Description</strong></th>
<th style="width: 124px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 210px;">address</td>
<td style="width: 374px;">Filter by address (IP or domain)</td>
<td style="width: 124px;">Optional</td>
</tr>
<tr>
<td style="width: 210px;">name</td>
<td style="width: 374px;">Filter by address name</td>
<td style="width: 124px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 280px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 352px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280px;">Fortigate.Address.Name</td>
<td style="width: 76px;">string</td>
<td style="width: 352px;">Address name</td>
</tr>
<tr>
<td style="width: 280px;">Fortigate.Address.Subnet</td>
<td style="width: 76px;">string</td>
<td style="width: 352px;">Address subnet</td>
</tr>
<tr>
<td style="width: 280px;">Fortigate.Address.StartIP</td>
<td style="width: 76px;">string</td>
<td style="width: 352px;">Address object start IP address</td>
</tr>
<tr>
<td style="width: 280px;">Fortigate.Address.EndIP</td>
<td style="width: 76px;">string</td>
<td style="width: 352px;">Address object end IP address</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-get-addresses</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 2 items<br>Address:[] 8 items<br>0:{} 4 items<br>EndIP:0.0.0.0<br>Name:FIREWALL_AUTH_PORTAL_ADDRESS<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-0.0.0.0<br>1:{} 4 items<br>EndIP:10.212.134.210<br>Name:SSLVPN_TUNNEL_ADDR1<br>StartIP:10.212.134.200<br>Subnet:10.212.134.200-10.212.134.210<br>2:{} 4 items<br>EndIP:0.0.0.0<br>Name:all<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-0.0.0.0<br>3:{} 4 items<br>EndIP:0.0.0.0<br>Name:autoupdate.opera.com<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-0.0.0.0<br>4:{} 4 items<br>EndIP:0.0.0.0<br>Name:google-play<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-0.0.0.0<br>5:{} 4 items<br>EndIP:255.255.255.255<br>Name:none<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-255.255.255.255<br>6:{} 4 items<br>EndIP:0.0.0.0<br>Name:swscan.apple.com<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-0.0.0.0<br>7:{} 4 items<br>EndIP:0.0.0.0<br>Name:update.microsoft.com<br>StartIP:0.0.0.0<br>Subnet:0.0.0.0-0.0.0.0</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055026-d9087f00-f1fe-11e8-8026-45f8ed443944.png" width="749" height="225"></p>
<h3 id="h_251291621171543315015519">2. Get information about service groups</h3>
<hr>
<p>Returns information about FortiGate service groups.</p>
<h5>Base Command</h5>
<p><code>fortigate-get-service-groups</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 255px;"><strong>Argument Name</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
<th style="width: 151px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">name</td>
<td style="width: 302px;">Filter by group name</td>
<td style="width: 151px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 333px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 306px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 333px;">Fortigate.ServiceGroup.Name</td>
<td style="width: 69px;">string</td>
<td style="width: 306px;">Service group name</td>
</tr>
<tr>
<td style="width: 333px;">Fortigate.ServiceGroup.Members</td>
<td style="width: 69px;">string</td>
<td style="width: 306px;">Service group member name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-get-service-groups</pre>
<h5>Context Example</h5>
<pre>ServiceGroup:[] 5 items<br>0:{} 2 items<br>Members:[] 7 items<br>0:DNS<br>1:IMAP<br>2:IMAPS<br>3:POP3<br>4:POP3S<br>5:SMTP<br>6:SMTPS<br>Name:Email Access<br>1:{} 2 items<br>Members:[] 3 items<br>0:DCE-RPC<br>1:DNS<br>2:HTTPS<br>Name:Exchange Server<br>2:{} 2 items<br>Members:[] 1 item<br>0:SMB<br>Name:Maya<br>3:{} 2 items<br>Members:[] 3 items<br>0:DNS<br>1:HTTP<br>2:HTTPS<br>Name:Web Access<br>4:{} 2 items<br>Members:[] 7 items<br>0:DCE-RPC<br>1:DNS<br>2:KERBEROS<br>3:LDAP<br>4:LDAP_UDP<br>5:SAMBA<br>6:SMB<br>Name:Windows AD</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055027-d9087f00-f1fe-11e8-80b2-fa516df50343.png" width="752" height="295"></p>
<h3 id="h_2511153492291543315020336">3. Update a service group</h3>
<hr>
<p>Updates a FortiGate service group.</p>
<h5>Base Command</h5>
<p><code>fortigate-update-service-group</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 166px;"><strong>Argument Name</strong></th>
<th style="width: 445px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 166px;">groupName</td>
<td style="width: 445px;">Group name of group to update</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">serviceName</td>
<td style="width: 445px;">Service name to update from the group. If you specify data argument, the value does not matter.</td>
<td style="width: 97px;">Required</td>
</tr>
<tr>
<td style="width: 166px;">data</td>
<td style="width: 445px;">Pass a raw-data object (e.g., {'member': [{'name': 'Test'}]}), will override the service name argument.</td>
<td style="width: 97px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 315px;"><strong>Path</strong></th>
<th style="width: 55px;"><strong>Type</strong></th>
<th style="width: 338px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 315px;">Fortigate.ServiceGroup.Name</td>
<td style="width: 55px;">string</td>
<td style="width: 338px;">Service group name</td>
</tr>
<tr>
<td style="width: 315px;">Fortigate.ServiceGroup.ServiceName</td>
<td style="width: 55px;">string</td>
<td style="width: 338px;">Service name</td>
</tr>
<tr>
<td style="width: 315px;">Fortigate.ServiceGroup.Action</td>
<td style="width: 55px;">string</td>
<td style="width: 338px;">Action taken on the updated service group</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-update-service-group groupName=Maya serviceName=HTTP</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 2 items<br>AddressGroup:{} 3 items<br>ServiceGroup:{} 2 items<br>Member:{} 1 item<br>Name:[] 1 item<br>0:HTTP<br>Name:Maya</pre>
<h3 id="h_549888813401543315025030">4. Delete a service group</h3>
<hr>
<p>Deletes a service group from FortiGate.</p>
<h5>Base Command</h5>
<p><code>fortigate-delete-service-group</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 170px;"><strong>Argument Name</strong></th>
<th style="width: 444px;"><strong>Description</strong></th>
<th style="width: 94px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 170px;">groupName</td>
<td style="width: 444px;">Group name of the group to delete</td>
<td style="width: 94px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 330px;"><strong>Path</strong></th>
<th style="width: 94px;"><strong>Type</strong></th>
<th style="width: 284px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 330px;">Fortigate.ServiceGroup.Name</td>
<td style="width: 94px;">string</td>
<td style="width: 284px;">Service group name</td>
</tr>
<tr>
<td style="width: 330px;">Fortigate.ServiceGroup.Deleted</td>
<td style="width: 94px;">boolean</td>
<td style="width: 284px;">Whether the service group was deleted</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-delete-service-group groupName="sdfsdf"</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 4 items<br>ServiceGroup:[] 6 items<br>5:{} 1 item<br>Name:sdfsdf<br>Deleted:true</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055028-d9087f00-f1fe-11e8-963e-d4fabd02fda8.png" width="754" height="93"></p>
<h3 id="h_2658967384501543315029859">5. Get service information</h3>
<hr>
<p>Returns information about a service from FortiGate Firewall.</p>
<h5>Base Command</h5>
<p><code>fortigate-get-firewall-service</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 298px;"><strong>Argument Name</strong></th>
<th style="width: 234px;"><strong>Description</strong></th>
<th style="width: 176px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 298px;">serviceName</td>
<td style="width: 234px;">Service name</td>
<td style="width: 176px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 258px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 258px;">Fortigate.Service.Name</td>
<td style="width: 69px;">string</td>
<td style="width: 381px;">Service name</td>
</tr>
<tr>
<td style="width: 258px;">Fortigate.Service.Ports.TCP</td>
<td style="width: 69px;">string</td>
<td style="width: 381px;">TCP port range included for the service</td>
</tr>
<tr>
<td style="width: 258px;">Fortigate.Service.Ports.UDP</td>
<td style="width: 69px;">string</td>
<td style="width: 381px;">UDP port range included for the service</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-get-firewall-service</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 3 items<br>Address:[] 8 items<br>Service:[] 87 items<br>0:{} 2 items<br>Name:ALL<br>Ports:{} 2 items<br>TCP:<br>UDP:<br>1:{} 2 items<br>Name:ALL_TCP<br>Ports:{} 2 items<br>TCP:1-65535<br>UDP:</pre>
<h5>Human Readable Output</h5>
<h3 id="h_4649504885591543315036188">6. Create a firewall service</h3>
<hr>
<p>Creates a service in FortiGate firewall</p>
<h5>Base Command</h5>
<p><code>fortigate-create-firewall-service</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">serviceName</td>
<td style="width: 497px;">Service name</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 140px;">tcpRange</td>
<td style="width: 497px;">TCP port range for the service, e.g., 100-120, or a single port</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 140px;">udpRange</td>
<td style="width: 497px;">UDP port range for the service, e.g., 100-120, or a single port</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 261px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 381px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 261px;">Fortigate.Service.Name</td>
<td style="width: 66px;">string</td>
<td style="width: 381px;">Service name</td>
</tr>
<tr>
<td style="width: 261px;">Fortigate.Service.Ports.TCP</td>
<td style="width: 66px;">string</td>
<td style="width: 381px;">TCP port range included for the service</td>
</tr>
<tr>
<td style="width: 261px;">Fortigate.Service.Ports.UDP</td>
<td style="width: 66px;">string</td>
<td style="width: 381px;">UDP port range included for the service</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-create-firewall-service serviceName=TEST1990 tcpRange=3 udpRange=4</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 2 items<br>AddressGroup:[] 5 items<br>Service:{} 2 items<br>Name:TEST1990<br>Ports:{} 2 items<br>TCP:3<br>UDP:4</pre>
<h5>Human Readable Output</h5>
<h3 id="h_6602236946671543315041059">7. Get policy information</h3>
<hr>
<p>Returns information about a firewall policy on FortiGate.</p>
<h5>Base Command</h5>
<p><code>fortigate-get-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 302px;"><strong>Argument Name</strong></th>
<th style="width: 226px;"><strong>Description</strong></th>
<th style="width: 180px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 302px;">policyName</td>
<td style="width: 226px;">Policy name</td>
<td style="width: 180px;">Optional</td>
</tr>
<tr>
<td style="width: 302px;">policyID</td>
<td style="width: 226px;">Policy ID</td>
<td style="width: 180px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 410px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">Fortigate.Policy.Name</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Policy name</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.ID</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Policy ID</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Description</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Policy description</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Status</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">The status of the policy (Enabled or Disabled)</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Source</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Source address</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Destination</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Destination address</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Service</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Service for the policy (e.g., HTTP)</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Action</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Policy action (Allow, Block)</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Log</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Does the policy log the traffic or not</td>
</tr>
<tr>
<td style="width: 241px;">Fortigate.Policy.Security</td>
<td style="width: 57px;">string</td>
<td style="width: 410px;">Policy attached security profile</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-get-policy</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 4 items<br>Policy:[] 6 items<br>0:{} 10 items<br>Security:[] 3 items<br>0:certificate-inspection<br>1:default<br>2:single<br>Log:all<br>Name:allow_any_to_any<br>Destination:all<br>Status:enable<br>Service:ALL<br>Action:accept<br>Source:all<br>ID:6<br>Description:<br>1:{} 9 items<br>Log:disable<br>Name:Allow ICMP<br>Destination:all<br>Status:disable<br>Service:ALL_ICMP<br>Action:accept<br>Source:all<br>ID:1<br>Description:maya test policy<br>2:{} 9 items<br>Log:utm<br>Name:allow dns<br>Destination:all<br>Status:disable<br>Service:DNS<br>Action:accept<br>Source:all<br>ID:2<br>Description:<br>3:{} 9 items<br>Log:utm<br>Name:allow github<br>Destination:swscan.apple.com<br>Status:disable<br>Service:HTTP<br>Action:accept<br>Source:all<br>ID:3<br>Description:</pre>
<h5> </h5>
<h3 id="h_8412979427741543315053679">8. Update a firewall</h3>
<hr>
<p>Updates a firewall policy on FortiGate.</p>
<h5>Base Command</h5>
<p><code>fortigate-update-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 235px;"><strong>Argument Name</strong></th>
<th style="width: 336px;"><strong>Description</strong></th>
<th style="width: 137px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 235px;">policyID</td>
<td style="width: 336px;">Policy ID</td>
<td style="width: 137px;">Required</td>
</tr>
<tr>
<td style="width: 235px;">field</td>
<td style="width: 336px;">Field parameter to update</td>
<td style="width: 137px;">Required</td>
</tr>
<tr>
<td style="width: 235px;">value</td>
<td style="width: 336px;">Value of the field parameter to update</td>
<td style="width: 137px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 234px;"><strong>Path</strong></th>
<th style="width: 74px;"><strong>Type</strong></th>
<th style="width: 400px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 234px;">Fortigate.Policy.Name</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Policy name</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.ID</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Policy ID</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Description</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Policy description</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Status</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">The status of the policy (Enabled or Disabled)</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Source</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Source address</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Destination</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Destination address</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Service</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Service for the policy (e.g., HTTP)</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Action</td>
<td style="width: 74px;">string</td>
<td style="width: 400px;">Policy action (Allow, Block)</td>
</tr>
<tr>
<td style="width: 234px;">Fortigate.Policy.Log</td>
<td style="width: 74px;">boolean</td>
<td style="width: 400px;">Does the policy log the traffic or not</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-update-policy field=nat policyID=6 value=disable</pre>
<h5>Context Example</h5>
<pre>context:<br>Fortigate:{} 4 items<br>AddressGroup:[] 5 items<br>Policy:{} 11 items<br>Security:[] 3 items<br>0:certificate-inspection<br>1:default<br>2:single<br>NAT:disable<br>Log:all<br>Name:allow_any_to_any<br>Destination:all<br>Status:enable<br>Service:ALL<br>Action:accept<br>Source:all<br>ID:6</pre>
<h3 id="h_1422688068801543315066050">9. Create a firewall policy</h3>
<hr>
<p>Creates a firewall policy (rule) on FortiGate.</p>
<h5>Base Command</h5>
<p><code>fortigate-create-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">policyName</td>
<td style="width: 501px;">Policy name</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">description</td>
<td style="width: 501px;">Description for the policy</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">sourceIntf</td>
<td style="width: 501px;">Source interface (e.g., port1/port2/port3)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">dstIntf</td>
<td style="width: 501px;">Destination interface (e.g., port1/port2/port3)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">source</td>
<td style="width: 501px;">Source IP address, range or domain (e.g., all/update.microsoft.com)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">destination</td>
<td style="width: 501px;">Destination IP address, range or domain (e.g., all/update.microsoft.com)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">service</td>
<td style="width: 501px;">Service for the policy (e.g., HTTP)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">action</td>
<td style="width: 501px;">Action to take</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">status</td>
<td style="width: 501px;">Policy status</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">log</td>
<td style="width: 501px;">Whether the policy will log the traffic</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">schedule</td>
<td style="width: 501px;">Recurring or one time schedule for the policy</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">nat</td>
<td style="width: 501px;">Enable/disable NAT</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 281px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 362px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 281px;">Fortigate.Policy.Name</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Policy name</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Description</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Policy description</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Status</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">The status of the policy (Enabled or Disabled)</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Source.Address</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Source address</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Destination.Address</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Destination address</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Service</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Service for the policy (e.g., HTTP)</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Action</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Policy action (Allow, Block)</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Log</td>
<td style="width: 65px;">boolean</td>
<td style="width: 362px;">Does the policy log the traffic or not</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Source.Intf</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Source interface</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Destination.Intf</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Destination interface</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.Schedule</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Policy schedule</td>
</tr>
<tr>
<td style="width: 281px;">Fortigate.Policy.NAT</td>
<td style="width: 65px;">string</td>
<td style="width: 362px;">Policy NAT</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-create-policy action="accept" destination="all" dstIntf="port2" schedule=always policyName="LOLZ9" service="HTTP" source="all" sourceIntf="port2" status="enable" description="bloob" log="enable"</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 4 items<br>Policy:[] 7 items<br>0:{} 10 items<br>1:{} 9 items<br>2:{} 9 items<br>3:{} 9 items<br>4:{} 9 items<br>5:{} 9 items<br>6:{} 10 items<br>Security:g-default<br>Log:enable<br>Name:LOLZ9<br>Destination:{} 2 items<br>Address:all<br>Interface:port2<br>Status:enable<br>Service:HTTP<br>Action:accept<br>Schedule:always<br>Source:{} 2 items<br>Address:all<br>Interface:port2<br>Description:bloob</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055029-d9087f00-f1fe-11e8-95b1-c756b919d26d.png" width="750" height="482"></p>
<h3 id="h_4085733299851543315074230">10. Relocate a firewall policy</h3>
<hr>
<p>Moves a firewall policy rule to a different position.</p>
<h5>Base Command</h5>
<p><code>fortigate-move-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 156px;"><strong>Argument Name</strong></th>
<th style="width: 463px;"><strong>Description</strong></th>
<th style="width: 89px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">policyID</td>
<td style="width: 463px;">Policy ID</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 156px;">position</td>
<td style="width: 463px;">Position for the policy (before or after)</td>
<td style="width: 89px;">Required</td>
</tr>
<tr>
<td style="width: 156px;">neighbor</td>
<td style="width: 463px;">The ID of the policy being used as a positional anchor</td>
<td style="width: 89px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 252px;"><strong>Path</strong></th>
<th style="width: 103px;"><strong>Type</strong></th>
<th style="width: 353px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 252px;">Fortigate.Policy.ID</td>
<td style="width: 103px;">string</td>
<td style="width: 353px;">Policy ID</td>
</tr>
<tr>
<td style="width: 252px;">Fortigate.Policy.Moved</td>
<td style="width: 103px;">boolean</td>
<td style="width: 353px;">Was the policy moved successfully</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-move-policy policyID=31 neighbour=33 position=after</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 1 item<br>Policy:{} 2 items<br>ID:26<br>Moved:true</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055030-d9a11580-f1fe-11e8-8cc2-b9df23a90c78.png" width="752" height="184"></p>
<h3 id="h_24259910811861543315086356">11. Delete a firewall policy</h3>
<hr>
<p>Deletes a policy from FortiGate firewall.</p>
<h5>Base Command</h5>
<p><code>fortigate-delete-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 301px;"><strong>Argument Name</strong></th>
<th style="width: 227px;"><strong>Description</strong></th>
<th style="width: 180px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">policyID</td>
<td style="width: 227px;">Policy ID</td>
<td style="width: 180px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 236px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 377px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 236px;">Fortigate.Policy.ID</td>
<td style="width: 95px;">string</td>
<td style="width: 377px;">Policy ID</td>
</tr>
<tr>
<td style="width: 236px;">Fortigate.Policy.Moved</td>
<td style="width: 95px;">boolean</td>
<td style="width: 377px;">Was the policy deleted successfully</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-delete-policy policyID=22</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 1 item<br>Policy:[] 2 items<br>1:{} 2 items<br>Deleted:true<br>ID:22</pre>
<h5>Human Readable Output</h5>
<p><img src="https://user-images.githubusercontent.com/12241410/49055031-d9a11580-f1fe-11e8-88a0-7936c88b2e14.png" width="750" height="185"></p>
<h3 id="h_2455845312891543315091313">12. Get information for address groups</h3>
<hr>
<p>Returns information about address groups from FortiGate</p>
<h5>Base Command</h5>
<p><code>fortigate-get-address-groups</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 254px;"><strong>Argument Name</strong></th>
<th style="width: 303px;"><strong>Description</strong></th>
<th style="width: 151px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 254px;">groupName</td>
<td style="width: 303px;">Filter by group name</td>
<td style="width: 151px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 360px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 289px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 360px;">Fortigate.AddressGroup.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 289px;">Address group name</td>
</tr>
<tr>
<td style="width: 360px;">Fortigate.AddressGroup.Member.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 289px;">Address group member name</td>
</tr>
<tr>
<td style="width: 360px;">Fortigate.AddressGroup.UUID</td>
<td style="width: 59px;">string</td>
<td style="width: 289px;">Address group UUID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-get-address-groups groupName="Test address group"</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 1 item<br>AddressGroup:{} 3 items<br>Member:{} 1 item<br>Name:[] 2 items<br>0:autoupdate.opera.com<br>1:swscan.apple.com<br>Name:Test address group<br>UUID:f492fcec-ee51-51e8-83f1-1d451b04c051</pre>
<h5>Human Readable Output</h5>
<h3 id="h_71275394613911543315098969">13. Update an address group</h3>
<hr>
<p>Updates an address group on FortiGate firewall</p>
<h5>Base Command</h5>
<p><code>fortigate-update-address-group</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">groupName</td>
<td style="width: 504px;">Group name</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">address</td>
<td style="width: 504px;">An address to add or remove from the group</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">data</td>
<td style="width: 504px;">Pass a raw-data object (e.g., {'member': [{'name': 'Test'}]}), will override the address argument.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 378px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 250px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 378px;">Fortigate.AddressGroup.Name</td>
<td style="width: 80px;">string</td>
<td style="width: 250px;">Address group name</td>
</tr>
<tr>
<td style="width: 378px;">Fortigate.AddressGroup.Address</td>
<td style="width: 80px;">string</td>
<td style="width: 250px;">Address name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-update-address-group address=google-play groupName=YARDEN</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 1 item<br>AddressGroup:[] 5 items<br>0:{} 3 items<br>1:{} 2 items<br>2:{} 2 items<br>3:{} 3 items<br>4:{} 2 items<br>Address:google-play<br>Name:YARDEN</pre>
<h5>Human Readable Output</h5>
<h3 id="h_90703567814921543315103725">14. Create an address group</h3>
<hr>
<p>Creates an address group in FortiGate firewall.</p>
<h5>Base Command</h5>
<p><code>fortigate-create-address-group</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 193px;"><strong>Argument Name</strong></th>
<th style="width: 402px;"><strong>Description</strong></th>
<th style="width: 113px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193px;">groupName</td>
<td style="width: 402px;">Group name</td>
<td style="width: 113px;">Required</td>
</tr>
<tr>
<td style="width: 193px;">address</td>
<td style="width: 402px;">Address member to add to the group</td>
<td style="width: 113px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 317px;"><strong>Path</strong></th>
<th style="width: 69px;"><strong>Type</strong></th>
<th style="width: 322px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 317px;">Fortigate.AddressGroup.Name</td>
<td style="width: 69px;">string</td>
<td style="width: 322px;">Address group name</td>
</tr>
<tr>
<td style="width: 317px;">Fortigate.AddressGroup.Address</td>
<td style="width: 69px;">string</td>
<td style="width: 322px;">Address group member address</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-create-address-group address=all groupName="YARDEN2"</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 1 item<br>AddressGroup:[] 2 items<br>0:{} 3 items<br>1:{} 2 items<br>Address:all<br>Name:YARDEN2</pre>
<h5>Human Readable Output</h5>
<h3 id="h_57698000216851543315108111">15. Delete an address group</h3>
<hr>
<p>Deletes an address group from FortiGate firewall</p>
<h5>Base Command</h5>
<p><code>fortigate-delete-address-group</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 260px;"><strong>Argument Name</strong></th>
<th style="width: 297px;"><strong>Description</strong></th>
<th style="width: 151px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 260px;">name</td>
<td style="width: 297px;">Address group name</td>
<td style="width: 151px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 332px;"><strong>Path</strong></th>
<th style="width: 90px;"><strong>Type</strong></th>
<th style="width: 286px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 332px;">Fortigate.AddressGroup.Name</td>
<td style="width: 90px;">string</td>
<td style="width: 286px;">Address group name</td>
</tr>
<tr>
<td style="width: 332px;">Fortigate.AddressGroup.Deleted</td>
<td style="width: 90px;">boolean</td>
<td style="width: 286px;">Whether the address group was deleted</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!fortigate-delete-address-group name=YARDEN4</pre>
<h5>Context Example</h5>
<pre>Fortigate:{} 1 item<br>AddressGroup:[] 5 items<br>0:{} 3 items<br>1:{} 2 items<br>2:{} 2 items<br>3:{} 3 items<br>Address:all<br>Deleted:true<br>Name:YARDEN4</pre>
<h3 id="h_97579068-1993-4df6-9b15-e0d83d9dc003">16. Add an address to a banned list</h3>
<hr>
<p>Adds an IP address to a banned list.</p>
<h5>Base Command</h5>
<p><code>fortigate-ban-ip</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145.333px;"><strong>Argument Name</strong></th>
<th style="width: 489.667px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145.333px;">ip_address</td>
<td style="width: 489.667px;">CSV list of IP addresses to ban. IPv4 and IPv6 addresses are supported. For example, "1.1.1.1,6.7.8.9".</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145.333px;">expiry</td>
<td style="width: 489.667px;">Time until ban expires in seconds. 0 for indefinite ban.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context outputs for this command.</p>
<p> </p>
<h5>Command Example</h5>
<pre>  !fortigate-ban-ip ip_address=8.8.8.8</pre>
<h3 id="h_dcbeef7c-2cfa-45b2-b677-cf1f4ea09895">17. Clears a list of banned addresses</h3>
<hr>
<p>Clears a list of specific banned IP addresses.</p>
<h5>Base Command</h5>
<p><code>fortigate-unban-ip</code></p>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138.667px;"><strong>Argument Name</strong></th>
<th style="width: 494.333px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138.667px;">ip_address</td>
<td style="width: 494.333px;">CSV list of banned user IP addresses to clear. IPv4 and IPv6 addresses are supported. For example, "1.1.1.1,6.7.8.9".</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context outputs for this command.</p>
<p> </p>
<h5>Command Example</h5>
<pre>  !fortigate-unban-ip ip_address=8.8.8.8 </pre>
<h3 id="h_09f6b36f-9215-42e9-9e86-e075c485f534">18. Get a list of banned addresses</h3>
<hr>
<p>Returns a list of banned IP addresses.</p>
<h5>Base Command</h5>
<p><code>fortigate-get-banned-ips</code></p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 214.667px;"><strong>Path</strong></th>
<th style="width: 50.3333px;"><strong>Type</strong></th>
<th style="width: 442px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 214.667px;">Fortigate.BannedIP.IP</td>
<td style="width: 50.3333px;">string</td>
<td style="width: 442px;">The IP address.</td>
</tr>
<tr>
<td style="width: 214.667px;">Fortigate.BannedIP.Created</td>
<td style="width: 50.3333px;">string</td>
<td style="width: 442px;">Date/time the IP address was added to the banned list.</td>
</tr>
<tr>
<td style="width: 214.667px;">Fortigate.BannedIP.Expires</td>
<td style="width: 50.3333px;">string</td>
<td style="width: 442px;">Date/time the IP address expires from the banned list.</td>
</tr>
<tr>
<td style="width: 214.667px;">Fortigate.BannedIP.Source</td>
<td style="width: 50.3333px;">string</td>
<td style="width: 442px;">Source of the ban.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>  !fortigate-get-banned-ips </pre>
