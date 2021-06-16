<!-- HTML_DOC -->
<p>Use Symantec Messaging Gateway (SMG) to block and unblock domains, email addresses, and IP addresses.</p>
<p>This integration was integrated and tested with Symantec Messaging Gateway v10.6.4.</p>
<h2>Use Cases</h2>
<ul>
<li>Block and unblock domains, email addresses and IP addresses.</li>
<li>Get blocked domains and blocked IP addresses.</li>
</ul>
<h2>Known limitations</h2>
<ul>
<li>SMG does not have a REST API, therefore the integration parses HTML response using the Beautiful Soup package. It also sends and gets data through it.</li>
<li>The integration adds and removes IoCs to the relevant default Bad Sender lists, and not custom ones.</li>
</ul>
<h2>Configure Symantec Messaging Gateway on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Symantec Messaging Gateway.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance</li>
<li>
<strong>Server URL</strong> (for example, https://192.168.0.1:20013)</li>
<li><strong>Username</strong></li>
<li>Do not validate server certificate (not secure)</li>
<li>Use system proxy settings</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate URLs and connection. </li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_18389780861530522674047">Block an email address: smg-block-email</a></li>
<li><a href="#h_59612418551530522681308">Block a domain: smg-block-domain</a></li>
<li><a href="#h_2881098651031530522691472">Block an IP address: smg-block-ip</a></li>
<li><a href="#h_3354682141501530522700739">Unblock an email address: smg-unblock-email</a></li>
<li><a href="#h_2689340341961530522712183">Unblock a domain: smg-unblock-domain</a></li>
<li><a href="#h_5145046882411530522721647">Unblock an IP address: smg-unblock-ip</a></li>
<li><a href="#h_1206792472851530522732698">Get blocked Domains: smg-get-blocked-domains</a></li>
<li><a href="#h_4296736673281530522744011">Get blocked IP addresses: smg-get-blocked-ips</a></li>
</ol>
<h3 id="h_18389780861530522674047">1. Block an email address</h3>
<hr>
<p>Blocks an email address.</p>
<h5>Base Command</h5>
<p><code>smg-block-email</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>email</td>
<td>Email address to block</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>Email.Address</td>
<td>Email address that was blocked</td>
</tr>
<tr>
<td>Email.Blocked</td>
<td>True if blocked, False if unblocked</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>Email address admin@example.com was blocked successfully.</pre>
<p> </p>
<h3 id="h_59612418551530522681308">2. Block a domain</h3>
<hr>
<p>Block a domain.</p>
<h5>Base Command</h5>
<p><code>smg-block-domain</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>domain</td>
<td>Domain to block</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>Domain.Name</td>
<td>Name of the domain that was blocked</td>
</tr>
<tr>
<td>Domain.Blocked</td>
<td>True if blocked, False if unblocked</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>Domain google.com was blocked successfully.</pre>
<p> </p>
<h3 id="h_2881098651031530522691472">3. Block an IP address</h3>
<hr>
<p>Blocks an IP address.</p>
<h5>Base Command</h5>
<p><code>smg-block-ip</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>ip</td>
<td> IP address to block</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>IP.Address</td>
<td>IP address that was blocked</td>
</tr>
<tr>
<td>IP.Blocked</td>
<td>True if blocked, False if unblocked</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>IP address 8.8.8.8 was blocked successfully.</pre>
<p> </p>
<h3 id="h_3354682141501530522700739">4. Unblock an email address</h3>
<hr>
<p>Unblock an email address.</p>
<h5>Base Command</h5>
<p><code>smg-unblock-email</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>email</td>
<td>Email address to unblock</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>Email.Address</td>
<td>Email address that was unblocked</td>
</tr>
<tr>
<td>Email.Blocked</td>
<td>True if blocked, False if unblocked</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>Email address admin@example.com was unblocked successfully.</pre>
<p> </p>
<h3 id="h_2689340341961530522712183">5. Unblock a domain</h3>
<hr>
<p>Unblock a domain.</p>
<h5>Base Command</h5>
<p><code>smg-unblock-domain</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>domain</td>
<td>Domain to unblock</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>Domain.Name</td>
<td>Name of the domain that was blocked</td>
</tr>
<tr>
<td>Domain.Blocked</td>
<td>True if blocked, False if unblocked</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>Domain google.com was unblocked successfully.</pre>
<p> </p>
<h3 id="h_5145046882411530522721647">6. Unblock an IP address</h3>
<hr>
<p>Unblock an IP address.</p>
<h5>Base Command</h5>
<p><code>smg-unblock-ip</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>ip</td>
<td> IP address to unblock</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>IP.Address</td>
<td>IP address that was unblocked</td>
</tr>
<tr>
<td>IP.Blocked</td>
<td>True if blocked, False if unblocked</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<p><code>IP address 8.8.8.8 was unblocked successfully.</code></p>
<p> </p>
<hr>
<h3 id="h_1206792472851530522732698">7. Get a list of blocked domains</h3>
<p>Returns a list of blocked domains.</p>
<h5>Base Command</h5>
<p><code>smg-get-blocked-domains</code></p>
<h5>Input</h5>
<p>There is no input.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw Output</h5>
<pre>### SMG Blocked domains:
- abc.net
- abc.org
</pre>
<p> </p>
<hr>
<h3 id="h_4296736673281530522744011">8. Get blocked IP addresses</h3>
<p>Get blocked IP addresses.</p>
<h5>Base Command</h5>
<p><code>smg-get-blocked-ips</code></p>
<h5>Input</h5>
<p>There is no input.</p>
<h5>Context Output</h5>
<p>There is no context output for this command..</p>
<h5>Raw Output</h5>
<pre>### SMG Blocked IP addresses:
- 1.2.3.4
- 8.8.8.8
</pre>
