<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the Fortinet FortiGuard integration to Fetch Malicious Indicators & Get URL Categories.</p>
<p>This integration was integrated and tested by Mostafa A. Mohamed "Aceilies"</p>
<h2>Configure FortiGuard on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for FortiGuard.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Account API Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, username + password, and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_2511153492291543315020336">Gets a List of Indicators from FortiGuard: fortiguard-get-indicators</a></li>
<li><a href="#h_549888813401543315025030">Return Domain Information and reputation: url</a></li>

</ol>
<h3 id="h_2511153492291543315020336">1. Gets a List of Indicators from FortiGuard</h3>
<hr>
<p>Returns a file containing available IoCs.</p>
<h5>Base Command</h5>
<p><code>fortiguard-get-indicators</code></p>
<p> </p>
<h5>Context Output</h5>
<p> Returns a file containing the IoCs. </p>
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
