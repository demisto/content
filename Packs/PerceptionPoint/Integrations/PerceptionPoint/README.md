<!-- HTML_DOC -->
<p>Use the Perception Point integration to resend falsely quarantined emails.</p>
<h2>Get your Perception Point API token</h2>
<p>To get an API token, contact PerceptionPoint support.</p>
<h4>API token use cases</h4>
<p>To set the number of results to return, specify the parameter "Number of API loops". Each loop returns a maximum of 20 items.</p>
<ul>
<li>View and manage your incidents list. This list will be updated automatically in the Incidents dashboard.</li>
<li>Release emails from quarantine and resend them to their recipients, by passing the scan ID as an argument.</li>
</ul>
<h2>Configure PerceptionPoint on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for Perception Point.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Token to use Perception Point's API</strong></li>
<li><strong>No. of API loops</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Fetch blocked incidents</strong></li>
<li><strong>Fetch spam incidents</strong></li>
<li><strong>Fetch malicious incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Trust any certificate (insecure)</strong></li>
<li><strong>Use system proxy</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2> </h2>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br> After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_86b37f8f-af11-4764-9053-224f65e33a4e" target="_self">Resend a falsely quarantined email: pp-release-email</a></li>
</ol>
<h3 id="h_86b37f8f-af11-4764-9053-224f65e33a4e">1. Resend a falsely quarantined email</h3>
<hr>
<p>Resends an email that was falsely quarantined, using the scan ID.</p>
<h5>Base Command</h5>
<p><code>pp-release-email</code></p>
<h5>Input</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 242px;"><strong>Argument Name</strong></th>
<th style="width: 365px;"><strong>Description</strong></th>
<th style="width: 133px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 242px;">scan_id</td>
<td style="width: 365px;">The PP scan ID of the email.</td>
<td style="width: 133px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 169px;"><strong>Path</strong></th>
<th style="width: 101px;"><strong>Type</strong></th>
<th style="width: 470px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">PP.Released</td>
<td style="width: 101px;">number</td>
<td style="width: 470px;">The scan ID of the released email.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>pp-release-email scan_id="80052041"</pre>
<h5>Context Example</h5>
<pre>{
    "PP.Released": "80052041"
}
</pre>
<h5>Human Readable Output</h5>
<p>Email with id 80052041 was released Successfully!</p>