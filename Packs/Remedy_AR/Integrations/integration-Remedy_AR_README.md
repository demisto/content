<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the BMC Remedy AR System integration to get server details by using queries.</p>
<p>This integration was integrated and tested with version 9.0.01.001 Patch 1 for Service Pack 1 of BMC Remedy AR System.</p>
<hr>
<h2>Prerequisites</h2>
<p>Make sure you have the following BMC Remedy AR information.</p>
<ul>
<li>Server URL</li>
<li>Credentials</li>
</ul>
<hr>
<h2>Configure the BMC Remedy AR Integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for the BMC Remedy AR integration.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>You should configure the following settings:<br><strong>Name</strong>: a textual name for the integration instance.<br><strong>Server URL:</strong> URL or IP address of the server<br><strong>Instance name:</strong> Name of the instance you are connecting to. <br><strong>Credentials</strong>: Username and password for accessing the integration. <br><strong>Do not validate server certificate</strong>: Select to bypass validating the server certification. You might want to do this in case Cortex XSOAR cannot validate the integration server certificate (due to missing CA certificate).<br><strong>Use system proxy settings:</strong> Specify whether to communicate with the integration using the system proxy server.<br><strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the IMAP server.  <br>Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.</li>
<li>Click the <strong>Test</strong> button to validate the URLs, instance name, and credentials.</li>
</ol>
<hr>
<h2>Use Cases</h2>
<ul>
<li>Get server details by different filters such as name and IP address.</li>
</ul>
<hr>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ul>
<li><a href="#h_58134278761527707461309">Get server details: remedy-get-server-details</a></li>
</ul>
<hr>
<h3 id="h_58134278761527707461309">Get server details: remedy-get-server-details</h3>
<h5>Command Example</h5>
<p><code>!remedy-get-server-details qualification="'400127400'=\"BMC.ASSET\" AND 'Company'!=\"Realtor.com\" AND 'NC_IOPs'=\"10.238.89.39\""</code></p>
<h5>Input</h5>
<table style="height: 43px; width: 724px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 168px;"><strong>Parameter</strong></td>
<td style="width: 551px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 168px;">qualification</td>
<td style="width: 551px;">Search qualification for details such as: 'key1'="value1" AND 'key2'!="value2".</td>
</tr>
<tr>
<td style="width: 168px;">fields</td>
<td style="width: 551px;">Parts of the entry object you want to retrieve, in CSV format (for example, fields=Company,Name).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Important Notes for Command Inputs</h5>
<ul>
<li>When you use quotation marks in the value of a <code>qualification</code> argument, you must escape the quotation marks with a backslash.</li>
</ul>
<h5>Context Output</h5>
<table style="height: 43px; width: 718px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 344px;"><strong>Path</strong></td>
<td style="width: 375px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 344px;">Remedy.ServerDetails.Reconciliation Identity</td>
<td style="width: 375px;">Server reconciliation identity</td>
</tr>
<tr>
<td style="width: 344px;">Remedy.ServerDetails.Short Description</td>
<td style="width: 375px;">Server description</td>
</tr>
<tr>
<td style="width: 344px;">Remedy.ServerDetails.Company</td>
<td style="width: 375px;">Company name</td>
</tr>
<tr>
<td style="width: 344px;">Remedy.ServerDetails.NC_IOPs</td>
<td style="width: 375px;">Server NC IOPs</td>
</tr>
<tr>
<td style="width: 344px;">Remedy.ServerDetails.Name</td>
<td style="width: 375px;">Server name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw output:</h5>
<pre>{  
   Company:,
   NC_IOPs:10.238.89.39,
   Name:brx1-printa-01,
   Reconciliation Identity:REGAA5V0G7L20AO40ILZO34NH92SPW,
   Short Description:Clustered Honeywell System controls press 1 &amp; 3 press functionality under Maintech Service Contract
}</pre>