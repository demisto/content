<!-- HTML_DOC -->
<p>Use the C2sec irisk integration to scan domains and return scan results.</p>
<h2>
<a id="C2sec_irisk_Playbook_2"></a>C2sec irisk Playbooks</h2>
<ul>
<li>
<strong>C2SEC-Domain Scan</strong><span> </span>- scans domains and waits for the full response from the C2sec irisk service.</li>
</ul>
<h2>
<a id="Configure_C2sec_irisk_on_Demisto_6"></a>Configure C2sec irisk on Cortex XSOAR</h2>
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for C2sec irisk.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>API URL (e.g.<span> </span><a href="https://api.c2sec.com/api">https://api.c2sec.com/api</a>)</strong></li>
<li><strong>API Key</strong></li>
<li><strong>Default domain name</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
<h2>
<a id="Commands_20"></a>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_d792fb42-2504-4bc4-b174-6422ccdfa7a6" target="_self">Add a domain to a portfolio: irisk-add-domain</a></li>
<li><a href="#h_93a605e6-1ab9-4349-80c9-5968792eea44" target="_self">Get the status of a scan: irisk-get-scan-status</a></li>
<li><a href="#h_b8bb719e-d7a3-4032-8827-e358b59f6288" target="_self">Re-scan a domain: irisk-rescan-domain</a></li>
<li><a href="#h_cc2d5cfe-b44d-4489-a1cb-df741e9d682d" target="_self">Get the issues for a domain: irisk-get-domain-issues</a></li>
<li><a href="#h_496fd318-3fe1-49d8-b03a-51ba5bbbbed1" target="_self">Get the results of a scan: irisk-get-scan-results</a></li>
</ol>
<h3 id="h_d792fb42-2504-4bc4-b174-6422ccdfa7a6">
<a id="1_Add_a_domain_to_a_portfolio_27"></a>1. Add a domain to a portfolio</h3>
<hr>
<p>Adds a domain to a portfolio.</p>
<h5>
<a id="Base_Command_30"></a>Base Command</h5>
<p><code>irisk-add-domain</code></p>
<h5>
<a id="Input_33"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">domain</td>
<td style="width: 523px;">Domain to add to the portfolio. If empty, the default domain will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">newscan</td>
<td style="width: 523px;">Flag to indicate whether a new scan is always initiated for the specified domain.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_41"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 230px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 451px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 230px;">C2Sec.Domain.result</td>
<td style="width: 59px;">string</td>
<td style="width: 451px;">Result status of adding the new company.</td>
</tr>
<tr>
<td style="width: 230px;">C2Sec.Domain.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 451px;">The name of the searched domain.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_49"></a>Command Example</h5>
<pre>!irisk-add-domain newscan=false domain=demisto.com</pre>
<h5>
<a id="Human_Readable_Output_52"></a>Human Readable Output</h5>
<p><img src="../../doc_files/61213135-cf3f7780-a70c-11e9-8a13-09c6f2701b43.png" alt="image"></p>
<h3 id="h_93a605e6-1ab9-4349-80c9-5968792eea44">
<a id="2_Get_the_status_of_a_scan_56"></a>2. Get the status of a scan</h3>
<hr>
<p>Queries the status of a scan.</p>
<h5>
<a id="Base_Command_59"></a>Base Command</h5>
<p><code>irisk-get-scan-status</code></p>
<h5>
<a id="Input_62"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 180px;"><strong>Argument Name</strong></th>
<th style="width: 464px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 180px;">id</td>
<td style="width: 464px;">Domain workitemid for which to check the status.</td>
<td style="width: 96px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_69"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 252px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 427px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 252px;">C2sec.Domain.Scan.domain</td>
<td style="width: 61px;">string</td>
<td style="width: 427px;">The name of the scanned domain.</td>
</tr>
<tr>
<td style="width: 252px;">C2sec.Domain.Scan.workitemid</td>
<td style="width: 61px;">number</td>
<td style="width: 427px;">The ID of the current scan.</td>
</tr>
<tr>
<td style="width: 252px;">C2sec.Domain.Scan.completeTime</td>
<td style="width: 61px;">date</td>
<td style="width: 427px;">The time that the scan was completed.</td>
</tr>
<tr>
<td style="width: 252px;">C2sec.Domain.Scan.creationTime</td>
<td style="width: 61px;">date</td>
<td style="width: 427px;">The time that the scan was initiated.</td>
</tr>
<tr>
<td style="width: 252px;">C2sec.Domain.Scan.status</td>
<td style="width: 61px;">number</td>
<td style="width: 427px;">The status of the current scan (“processing”/“completed”).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_80"></a>Command Example</h5>
<pre>!irisk-get-scan-status id=1247</pre>
<h5>
<a id="Human_Readable_Output_83"></a>Human Readable Output</h5>
<p><img src="../../doc_files/61213344-758b7d00-a70d-11e9-8f4d-57227824201b.png" alt="image"></p>
<h3 id="h_b8bb719e-d7a3-4032-8827-e358b59f6288">
<a id="3_Rescan_a_domain_87"></a>3. Re-scan a domain</h3>
<hr>
<p>Initiates a re-scan for a domain within a portfolio.</p>
<h5>
<a id="Base_Command_90"></a>Base Command</h5>
<p><code>irisk-rescan-domain</code></p>
<h5>
<a id="Input_93"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 156px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">domain</td>
<td style="width: 501px;">Domain to re-scan. If empty, the default domain will be used.</td>
<td style="width: 83px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_100"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 315px;"><strong>Path</strong></th>
<th style="width: 82px;"><strong>Type</strong></th>
<th style="width: 343px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 315px;">C2sec.Domain.Scan.domain</td>
<td style="width: 82px;">string</td>
<td style="width: 343px;">The name of the scanned domain.</td>
</tr>
<tr>
<td style="width: 315px;">C2sec.Domain.Scan.workitemid</td>
<td style="width: 82px;">number</td>
<td style="width: 343px;">Scan ID.</td>
</tr>
<tr>
<td style="width: 315px;">C2sec.Domain.Scan.result</td>
<td style="width: 82px;">string</td>
<td style="width: 343px;">The scan result status.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_109"></a>Command Example</h5>
<pre>!irisk-rescan-domain domain=demisto.com</pre>
<h5>
<a id="Human_Readable_Output_112"></a>Human Readable Output</h5>
<p><img src="../../doc_files/61213321-6278ad00-a70d-11e9-8d2d-7e05f7c5e955.png" alt="image"></p>
<h3 id="h_cc2d5cfe-b44d-4489-a1cb-df741e9d682d">
<a id="4_Get_the_issues_for_a_domain_116"></a>4. Get the issues for a domain</h3>
<hr>
<p>Returns the issues located under the specified domain.</p>
<h5>
<a id="Base_Command_119"></a>Base Command</h5>
<p><code>irisk-get-domain-issues</code></p>
<h5>
<a id="Input_122"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 150px;"><strong>Argument Name</strong></th>
<th style="width: 510px;"><strong>Description</strong></th>
<th style="width: 80px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">domain</td>
<td style="width: 510px;">The domain to query. If empty, the default domain it will be used.</td>
<td style="width: 80px;">Optional</td>
</tr>
<tr>
<td style="width: 150px;">severity</td>
<td style="width: 510px;">Filter query results by issue severity…</td>
<td style="width: 80px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_130"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 281px;"><strong>Path</strong></th>
<th style="width: 46px;"><strong>Type</strong></th>
<th style="width: 413px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 281px;">C2sec.Domain.Name</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">The name of the domain against which it was checked.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.ID</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">Issue ID.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.Asset</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">Asset associated with the issues. For example, IP addresses, website URLs, and so on.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.Component</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">The component used in the issue.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.ComponentDisplay</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">The display name of the component being used.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.Details</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">The details for the issue.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.Issue</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">The name of the issue.</td>
</tr>
<tr>
<td style="width: 281px;">C2sec.Domain.Issue.Severity</td>
<td style="width: 46px;">string</td>
<td style="width: 413px;">The severity of the issue.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_144"></a>Command Example</h5>
<pre>!irisk-get-domain-issues domain=google.com</pre>
<h5>
<a id="Human_Readable_Output_147"></a>Human Readable Output</h5>
<p><img src="../../doc_files/61213286-496ffc00-a70d-11e9-97dc-ad932cad733c.png" alt="image"></p>
<h3 id="h_496fd318-3fe1-49d8-b03a-51ba5bbbbed1">
<a id="5_Get_the_results_of_a_scan_150"></a>5. Get the results of a scan</h3>
<hr>
<p>Queries data for a specific component for companies in the portfolio.</p>
<h5>
<a id="Base_Command_153"></a>Base Command</h5>
<p><code>irisk-get-scan-results</code></p>
<h5>
<a id="Input_156"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 160px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 85px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">domain</td>
<td style="width: 495px;">The domain to query. If empty, default domain will be used.</td>
<td style="width: 85px;">Required</td>
</tr>
<tr>
<td style="width: 160px;">component</td>
<td style="width: 495px;">The component to query.</td>
<td style="width: 85px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Context_Output_164"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 301px;"><strong>Path</strong></th>
<th style="width: 46px;"><strong>Type</strong></th>
<th style="width: 393px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">C2sec.Domain.application.result</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Query status.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.application.Domain</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">The domain name being queried.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.application.data.appdetail</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Details about the application being checked.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.application.data.info</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Information regarding the data being processed.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.application.data.website</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Website address being processed.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.credential.result</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Query status.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.credential.Domain</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">The domain name being queried.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.credential.data.user</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">User name.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.credential.data.pw</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">User password.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.result</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Query status.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.Domain</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">The domain name being queried.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.firewall</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Firewall status.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.port</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Port number.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.IP</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">IP address.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.Name</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Name of the user.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.service</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Name of the service being used.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.protocol</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">Name of the protocol being used.</td>
</tr>
<tr>
<td style="width: 301px;">C2sec.Domain.network.data.state</td>
<td style="width: 46px;">string</td>
<td style="width: 393px;">State of the network application (“open” or “closed”).</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>
<a id="Command_Example_188"></a>Command Example</h5>
<pre>!irisk-get-scan-results component=application domain=demisto.com</pre>
<h5>
<a id="Human_Readable_Output_191"></a>Human Readable Output</h5>
<p><img src="../../doc_files/61213200-06ae2400-a70d-11e9-93b0-d7fd5ff7a763.png" alt="image"></p>