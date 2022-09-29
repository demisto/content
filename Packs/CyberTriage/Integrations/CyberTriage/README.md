<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Cyber Triage integration to collect and analyze endpoint data</p>
<p>This integration requires Team version of Cyber Triage (not the Standalone desktop version).</p>
<p>This integration was integrated and tested with Cyber Triage v2.4.0.</p>
<p> </p>
<h2>Configure Cyber Triage on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Cyber Triage.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Hostname of Cyber Triage server (e.g. 192.168.1.2)</strong> : the ip or hostname where the Cyber Triage server is setup.</li>
<li>
<strong>REST Port</strong> : REST port for Cyber Triage server. 9443 is the default port and currently cannot be changed in Cyber Triage.</li>
<li>
<strong>API Key</strong> : can be retrieved from the Cyber Triage server by going to Options -&gt; Deployment Mode -&gt; REST API Key.</li>
<li>
<strong>Username</strong> : the username and password of a Windows account with administrative privileges on all endpoints that need to be investigated.</li>
<li>
<strong>Use proxy</strong> : select if you have a proxy setup in your environment and need to use it to reach the Cyber Triage server.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2> </h2>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_62899400271539496080241">Initiate a collection on an endpoint: ct-triage-endpoint</a></li>
</ol>
<h3 id="h_62899400271539496080241">Initiate a collection on an endpoint</h3>
<hr>
<p>Initiates a Cyber Triage collection on an endpoint.</p>
<h5>Base Command</h5>
<pre><code>ct-triage-endpoint</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 475px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">endpoint</td>
<td style="width: 475px;">IP or hostname of a Windows endpoint</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">full_scan</td>
<td style="width: 475px;">Scan the entire file system for suspicious files</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">malware_hash_upload</td>
<td style="width: 475px;">Send MD5 hashes to an external malware analysis service</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">malware_file_upload</td>
<td style="width: 475px;">Send unknown files to an external malware analysis service. Hash upload must be enabled to execute file uploads.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 186px;"><strong>Path</strong></th>
<th style="width: 55px;"><strong>Type</strong></th>
<th style="width: 467px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 186px;">CyberTriage.SessionId</td>
<td style="width: 55px;">string</td>
<td style="width: 467px;">The session ID for the newly created session</td>
</tr>
<tr>
<td style="width: 186px;">Endpoint.IPAddress</td>
<td style="width: 55px;">string</td>
<td style="width: 467px;">The endpoint IP address that Cyber Triage investigated</td>
</tr>
<tr>
<td style="width: 186px;">Endpoint.Hostname</td>
<td style="width: 55px;">string</td>
<td style="width: 467px;">The endpoint hostname that Cyber Triage investigated</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!ct-triage-endpoint endpoint=ct-win10-01 full_scan=no</pre>
<h5>Context Example</h5>
<p>CyberTriage.SessionID: ct-win10-01|1538074422288<br>CyberTriage.Hostname: ct-win10-01</p>
<h5>Human Readable Output</h5>
<p>A collection has been scheduled for ct-win10-01</p>
<p> </p>