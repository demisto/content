<!-- HTML_DOC -->
<p>Use the Netskope integration to manage your Netskope events and alerts.</p>
<p>This integration was integrated and tested with Netskope v51.</p>
<h2>Prerequisites</h2>
<p>You need to obtain the following Netskope information.</p>
<ul>
<li>Netskope tenant URL</li>
<li>Tenant API token</li>
</ul>
<h2>Configure the Netskope Integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Netskope.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong><font style="vertical-align: inherit;">URL of Netskope Tenant</font></strong><font style="vertical-align: inherit;">: for example, https://tenant.goskope.com</font>
</li>
<li>
<strong>Tenant API Token</strong>: paste the token that you copied.</li>
<li><strong>Do not validate server certificate (unsecure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_14972060461528040126380">Get Netskope events: netskope-events</a></li>
<li><a href="#h_491251660251528040135707">Get Netskope alerts: netskope-alerts</a></li>
</ol>
<h3 id="h_14972060461528040126380">1. Get Netskope events: netskope-events</h3>
<hr>
<p>Retrieve events from your Netskope environment.</p>
<h5>Command Example</h5>
<p><code>!netskope-events type=application timeperiod=Last24Hours</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 667px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Input Parameter</strong></td>
<td style="width: 479px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">query</td>
<td style="width: 479px;">Filter query, for example, foo@test.com</td>
</tr>
<tr>
<td style="width: 161px;">timeperiod</td>
<td style="width: 479px;">Query time period (for example, last 60 minutes, last 24 hours)</td>
</tr>
<tr>
<td style="width: 161px;">starttime</td>
<td style="width: 479px;">Query start time: timestamp or dd-mm-yyyyTHH:MM:SSZ (e.g., 31-12-1999T11:59:59Z)
<p> </p>
</td>
</tr>
<tr>
<td style="width: 161px;">endtime</td>
<td style="width: 479px;">
<p>Query end time: timestamp or dd-mm-yyyyTHH:MM:SSZ (e.g., 31-12-1999T11:59:59Z)</p>
</td>
</tr>
<tr>
<td style="width: 161px;">type</td>
<td style="width: 479px;">
<p>Event type</p>
<ul>
<li>Application</li>
<li>Page</li>
<li>Audit</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 161px;">limit</td>
<td style="width: 479px;">
<p>Maximum number of events returned (useful for pagination in combination with skip)</p>
<p>Must be an integer less than 5,000.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">skip</td>
<td style="width: 479px;">Skip over specific events (useful for pagination in combination with limit)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 306px; width: 666px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 246px;"><strong>Path</strong></td>
<td style="width: 393px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.App</td>
<td style="width: 393px;">Application name</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.Timestamp</td>
<td style="width: 393px;">Event timestamp</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.Activity</td>
<td style="width: 393px;">Event activity</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.Object</td>
<td style="width: 393px;">Document/object from the event</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.hostname</td>
<td style="width: 393px;">Device hostname</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.AppCategory</td>
<td style="width: 393px;">Netskope application category (for example, Cloud Storage, Webmail, and so on)</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.device_classification</td>
<td style="width: 393px;">Device classification (for example, managed vs. unmanaged)</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.User</td>
<td style="width: 393px;">User</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.from_user</td>
<td style="width: 393px;">Login IDs for cloud applications</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.to_user</td>
<td style="width: 393px;">Destination user IDs</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.SourceIP</td>
<td style="width: 393px;">Source IP</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.AccessMethod</td>
<td style="width: 393px;">Access method (for example, client, reverse proxy, Secure Forwarder, and so on)</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.url</td>
<td style="width: 393px;">URL</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Events.ID</td>
<td style="width: 393px;">Event ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "AccessMethod":"API Connector",
   "Activity":"HeadBucket",
   "App":"Amazon Web Services",
   "AppCategory":"IaaS/PaaS",
   "DeviceClassification":null,
   "FromUser":null,
   "Hostname":null,
   "ID":"1382a493090c36ba14bfc2bc",
   "Object":"nstrail",
   "SourceIP":"8.36.116.16",
   "Timestamp":"Mon May 21 2018 13:26:30 GMT+0300 (IDT)",
   "ToUser":null,
   "URL":null,
   "User":"assumed-role/ctaudit/AssumeRoleSession1"
}</pre>
<h3 id="h_491251660251528040135707">2. Get Netskope alerts: netskope-alerts</h3>
<hr>
<p>Retrieve alerts from your Netskope environment.</p>
<h5>Command Example</h5>
<p><code>!netskope-alerts type=Malware timeperiod=Last60Days</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 667px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Input Parameter</strong></td>
<td style="width: 479px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">type</td>
<td style="width: 479px;">Alert type</td>
</tr>
<tr>
<td style="width: 161px;">timeperiod</td>
<td style="width: 479px;">Query time period (for example, last 60 minutes, last 24 hours)</td>
</tr>
<tr>
<td style="width: 161px;">starttime</td>
<td style="width: 479px;">
<p>Query start time: timestamp or dd-mm-yyyyTHH:MM:SSZ (e.g., 31-12-1999T11:59:59Z)</p>
</td>
</tr>
<tr>
<td style="width: 161px;">endtime</td>
<td style="width: 479px;">
<p>Query end time: timestamp or dd-mm-yyyyTHH:MM:SSZ (e.g., 31-12-1999T11:59:59Z)</p>
</td>
</tr>
<tr>
<td style="width: 161px;">query</td>
<td style="width: 479px;">Valid event query described in the query language document</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 306px; width: 666px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 246px;"><strong>Path</strong></td>
<td style="width: 393px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Alerts.App</td>
<td style="width: 393px;">Application name</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Alerts.Timestamp</td>
<td style="width: 393px;">Alert timestamp</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Alerts.Policy</td>
<td style="width: 393px;">Name of policy triggered</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Alerts.DLPFile</td>
<td style="width: 393px;">Name of DLP file that triggered</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Alerts.Hostname</td>
<td style="width: 393px;">Hostname</td>
</tr>
<tr>
<td style="width: 246px;">Netskope.Alerts.ID</td>
<td style="width: 393px;">Alert ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "App":"Microsoft Office 365 OneDrive for Business",
   "DLPFile":null,
   "DLPProfile":null,
   "Hostname":"Ashutosh’s MacBook Pro",
   "ID":"f95e5638432f538365d5b256",
   "Policy":null,
   "Timestamp":"Mon May 21 2018 13:29:34 GMT+0300 (IDT)"
}</pre>