<!-- HTML_DOC -->
<p>OpsGenie is an alerting and on-call management solution for dev &amp; ops teams. It provides tools needed to design actionable alerts, manage on-call schedules &amp; escalations, and ensure that the right people are notified at the right time, using multiple notification methods.</p>
<p>The OpsGenie-XSOAR integration allows querying specific on-call schedules and determining the right resource of who is currently (or in future time) on call.</p>
<h3>To set up OpsGenie to work with Cortex XSOAR:</h3>
<ol>
<li>From main OpsGenie screen, go to the Integrations page, and select to add API (first box).</li>
<li>In the new API integration, do the following:
<ul>
<li>Enter name: Demisto</li>
<li>Copy the API Key presented in the page to use for the Demisto set up below.</li>
<li>Make sure Enabled checkbox is marked.</li>
<li>You can check the Restrict Access and Limit to Read Only check boxes as well (not mandatory)</li>
<li>Click on Save Integration</li>
</ul>
</li>
</ol>
<h3>To set up the integration on Cortex XSOAR:</h3>
<ol>
<li>Go to ‘Settings &gt; Integrations &gt; Servers &amp; Services’</li>
<li>Locate the OpsGenie integration by searching for it using the search box on the top of the page.</li>
</ol>
<ol start="3">
<li>Click ‘Add instance’ to create and configure a new integration. You should configure the following settings:<br><strong>Name</strong>: A textual name for the integration instance.<br> <strong>Base URL</strong>: The base OpsGenie service URL. The default value should be used (https://api.opsgenie.com/v2), unless otherwise instructed by Cortex XSOAR.<br><strong>API Key</strong>: The API Key acquired from the OpsGenie interface in the previous step.<br><strong>Use system proxy configuration</strong>: Check this box in case there is a proxy server configures on the platform.<br><strong>Cortex XSOAR engine</strong>: If relevant, select the engine that acts as a proxy to the server. Engines are used when you need to access a remote network segments and there are network devices such as proxies, firewalls, etc. that prevent the Cortex XSOAR server from accessing the remote networks.</li>
</ol>
<p class="wysiwyg-indent4">For more information on Cortex XSOAR engines see:<br><a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Engines">Cortex XSOAR 6.13 - Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines">Cortex XSOAR 8 Cloud- Engines</a><br> <a href="https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Engines">Cortex XSOAR 8.7 On-prem - Engines</a><br> Require users to enter additional password: Select whether you’d like an additional step where users are required to authenticate themselves with a password.</p>
<ol start="4">
<li>Press the ‘Test’ button to validate connection.
</li>
<li>After completing the test successfully, press the ‘Done’ button.</li>
</ol>
<h3>Fetched incidents data:</h3>
<p>This integration does not fetch incidents </p>
<h3>
Use-cases:</h3>
<ul>
<li>
<strong>Assigning an analyst based on the current on-call schedule</strong><br>When an incident enters Cortex XSOAR, a playbook task can get the current on-call analyst, based on the on-call schedule.<br>This can be done by using the opsgenie-get-on-call command, using the SOC analysts rotation schedule in OpsGenie.</li>
<li>
<strong>Setting handover path based on future on-call rotation</strong><br>As part of the incident playbook, the next shift analyst can also be queries for heads-up notification if needed, using the opsgenie-get-on-call command, using the schedule name, and the date to query based upon</li>
</ul>
<h3>Commands:</h3>
<div class="row top-padded">
<div class="five wide break-word column integration-command-name">
<ul>
<li style="font-family: courier;">
<strong>opsgenie-get-on-call &lt;schedule&gt; [&lt;date&gt;] - </strong>Get current on-call users of a given Schedule.<br> The Schedule name is used to query for the specific on-call. The Date can be provided to check future on-call assignments.</li>
<li style="font-family: courier;">
<strong>opsgenie-get-schedule-timeline &lt;schedule&gt; - </strong>Get the schedule timeline information of the given schedule name.</li>
<li style="font-family: courier;">
<strong>opsgenie-get-schedules - </strong>Get all schedules listed in the system.</li>
<li style="font-family: courier;">
<strong>opsgenie-get-user &lt;user&gt; - </strong>Get user information based on the given user ID (email)</li>
</ul>
</div>
</div>
<p>Example of commands:</p>
<ul>
<li style="font-family: courier;"><strong>!opsgenie-get-on-call schedule="OnCAll" </strong></li>
<li style="font-family: courier;"><strong>!opsgenie-get-on-call schedule="OnCAll" date=2018-01-01</strong></li>
<li style="font-family: courier;"><strong>!opsgenie-get-user email@company.com</strong></li>
</ul>
<p>Example of commands with outputs:</p>
<ul>
<li style="font-family: courier;"><strong>!opsgenie-get-on-call schedule="SOC"  </strong></li>
</ul>
<p class="wysiwyg-indent6">War room output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>OpsGenie On-Call Schedule SOC<br>Currently on-call for SOC schedule:<br>John Doe (john@company.com)</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>OnCall:[] 1 item<br>0:{} 2 items<br>email:john@company.com<br>name:John Doe</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>root:[] 1 item<br>0:{} 3 items<br>id:&lt;ID&gt;<br>name:john@company.com<br>type:user </p>
</td>
</tr>
</tbody>
</table>
<ul>
<li>
<strong>!opsgenie-get-on-call schedule="SOC"  date="2018-01-01"</strong>
<p>War room output:</p>
</li>
</ul>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>OpsGenie On-Call Schedule SOC<br>Currently on-call for SOC schedule:<br>Jane Doe (jane@company.com)</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>OnCall:[] 1 item<br>0:{} 2 items<br>email:jane@company.com<br>name:Jane Doe</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>root:[] 1 item<br>0:{} 3 items<br>id:&lt;ID&gt;<br>name:jane@company.com<br>type:user </p>
</td>
</tr>
</tbody>
</table>
<ul>
<li style="font-family: courier;"><strong>!opsgenie-get-user userID="john@company.com"  </strong></li>
</ul>
<p class="wysiwyg-indent6">War room output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>OpsGenie      User Info<br>Key              Value<br>createdAt      2017-10-08T05:27:28.535Z<br>fullName       Gilad Shriki<br>id                 6297fa63-7816-4cd6-93e4-404a9ab6a3cf<br>locale           en_US<br>role.id          Owner<br>role.name     Owner<br>timeZone      Israel<br>username     shriki@demisto.com<br>verified         true</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Context output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>None</p>
</td>
</tr>
</tbody>
</table>
<p class="wysiwyg-indent6">Raw output:</p>
<table style="margin-left: 70px;">
<tbody>
<tr>
<td>
<p>root:{} 10 items<br>blocked:false<br>createdAt:2017-10-08T05:27:28.535Z<br>fullName:John Doe<br>id:&lt;ID&gt;<br>locale:en_US<br>role:{} 2 items<br>id:Owner<br>name:Owner<br>timeZone:US-E<br>userAddress:{} 5 items<br>city:<br>country:<br>line:<br>state:<br>zipCode:<br>username:john@company.com<br>verified:true</p>
</td>
</tr>
</tbody>
</table>
<h3>Troubleshooting</h3>
<ul>
<li>Make sure to have the web-proxy open to the OpsGenie API URL (https://api.opsgenie.com/v2)</li>
<li>Make sure API Key is enabled in the OpsGenie interface, and it is copies correctly</li>
<li>Make sure API Key is created with a user that has access to the relevant on call schedules.</li>
</ul>
<div class="row top-padded"> </div>