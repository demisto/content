<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Aella Starlight integration to get detailed information for security events detected by Aella Breach Detection software.</p>
<p>This integration was integrated and tested with Aella Startlight v2.2.1.</p>
<h2>Use cases</h2>
<hr>
<ul>
<li>Monitor security events and get event details<br>Periodically fetch new security events detected by Aella Starlight. Each security event will have a unique <em>event_id</em>, which you can pass to the |<code>aella-get-event</code> command to get the detailed information for. You can perform a follow-up action, such as sending a notification to security staff.</li>
</ul>
<h2>Fetched Incidents Data</h2>
<hr>
<p><strong>name</strong>: Incident name<br><strong>label</strong>: "Starlight event"<br><strong>aella_eid</strong>: Aella event ID<br><strong>aella_event</strong>: Aella event name<br><strong>event_severity</strong>: Severity of the event</p>
<h2>Configure Aella Starlight on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Aella Star Light.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>You should configure the following settings:</li>
</ol>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g. <a href="https://starlight.companyname.com:8889/" rel="nofollow">https://starlight.companyname.com:8889</a>)</strong></li>
<li><strong>User name</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Fetching interval in minutes (default is 15, minimum is 15 )</strong></li>
<li><strong>The specific security event to look for. Default is all events</strong></li>
<li><strong>Security event severity threshold, between 0-100</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
<ol start="4">
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br>After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_61742644851535971799167">Get event details: aella-get-event</a></li>
</ol>
<h3 id="h_61742644851535971799167">1. Get event details</h3>
<hr>
<p>Get details for a specific Startlight event.</p>
<h5>Base Command</h5>
<p><code>aella-get-event</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 195px;"><strong>Argument Name</strong></th>
<th style="width: 398px;"><strong>Description</strong></th>
<th style="width: 115px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 195px;">event_id</td>
<td style="width: 398px;">Event ID from the Starlight incident</td>
<td style="width: 115px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 285px;"><strong>Path</strong></th>
<th style="width: 104px;"><strong>Type</strong></th>
<th style="width: 319px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 285px;">Aella.Event.event_name</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Event name</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.severity</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Severity score</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.dstip</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Destination IP</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.srcip</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Source IP</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.tenantid</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Tenant ID</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.srcip_reputation</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Source IP reputation</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.dstip_reputation</td>
<td style="width: 104px;">string</td>
<td style="width: 319px;">Destination IP reputation</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.dstip_geo</td>
<td style="width: 104px;">unknown</td>
<td style="width: 319px;">Destination IP geolocation</td>
</tr>
<tr>
<td style="width: 285px;">Aella.Event.srcip_geo</td>
<td style="width: 104px;">unknown</td>
<td style="width: 319px;">Source IP geolocation</td>
</tr>
</tbody>
</table>