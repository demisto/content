<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Minerva’s Threat Prevention Platform is an agent based solution that protects servers and workstations from real-world threats that evade existing security controls, protecting both modern operating systems and embedded low-resources operating systems as well.</p>
</div>
<div class="cl-preview-section">
<p>Minerva modular design enables customers and partners to use Minerva-provided solutions or customize their Minerva deployment to fit their existing defense architecture.</p>
</div>
<div class="cl-preview-section">
<p>Using the Cortex XSOAR platform, enterprises and service providers can now have automated visibility into prevented anomalies across endpoints and servers in the network, while processing them using built-in playbooks.</p>
<p><br> Minerva Labs’ Endpoint Malware Vaccination enables incident response teams to immunize endpoints in seconds and neutralize attacks by simulating infection markers, rather than creating them, allowing Minerva to contain outbreaks without impacting performance. The combined interlock of Cortex XSOAR and Minerva offers orchestration of an instant deployment of malware vaccinations thus preventing outbreaks of known network worms, by simulating their infection markers and preventing the malicious code installation.</p>
</div>
<div class="cl-preview-section">
<p>This integration was integrated and tested with version 3.0 of Minerva Labs Anti-Evasion Platform.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Fetch events from Minerva platform into Cortex XSOAR Playground</li>
<li>List, add and delete vaccination artifacts to Minerva platform</li>
<li>List, add and delete exclusions in order to handle FPs</li>
<li>Search for events according to criteria</li>
<li>Search for endpoints according to criteria</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-minerva-labs-anti-evasion-platform-on-demisto">Configure Minerva Labs Anti-Evasion Platform on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>
<p>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</p>
</li>
<li>
<p>Search for Minerva Labs Anti-Evasion Platform.</p>
</li>
<li>
<p>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.</p>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Minerva Management Console URL</strong>, for example: https://SERVER/OWL
</li>
<li><strong>Username</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Fetch incidents</strong></li>
</ul>
</li>
<li>
<p>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</p>
</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="fetched-incidents-data">Fetched Incidents Data</h2>
</div>
<div class="cl-preview-section">
<p>The integration imports events from Minerva Management Console as incidents in Cortex XSOAR.<br> As each incident represents malicious activity, it contains all the available information gathered by Minerva for further analysis.</p>
</div>
<div class="cl-preview-section">
<p>To use Fetch Incidents, configure a new instance and select the ‘Fetch-incidents’ option in the instance settings.</p>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Add exclusions: minerva-add-exclusion</li>
<li>Add a vaccination: minerva-add-vaccine</li>
<li>Search for processes: minerva-search-process</li>
<li>Search for an endpoint: minerva-search-endpoint</li>
<li>Get all groups: minerva-get-groups</li>
<li>Get mutex vaccines: minerva-get-vaccines</li>
<li>Delete a vaccine: minerva-delete-vaccine</li>
<li>Get all exclusions: minerva-get-exclusions</li>
<li>Delete an exclusion: minerva-delete-exclusion</li>
<li>Move all events from Archive to New event state: minerva-unarchive-events</li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="add-exclusions">1. Add exclusions</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds exclusions to Minerva Console.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-add-exclusion</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 460px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">data</td>
<td style="width: 460px;">Exclusion data.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 184px;">type</td>
<td style="width: 460px;">The exclusion type.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 184px;">appliedGroupsIds</td>
<td style="width: 460px;">A list of group IDs to which this exclusion applies.</td>
<td style="width: 96px;">Optional</td>
</tr>
<tr>
<td style="width: 184px;">description</td>
<td style="width: 460px;">A description of the exclusion.</td>
<td style="width: 96px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 310px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 310px;">Minerva.Exclusion.Id</td>
<td style="width: 59px;">string</td>
<td style="width: 371px;">Exclusion ID.</td>
</tr>
<tr>
<td style="width: 310px;">Minerva.Exclusion.Type</td>
<td style="width: 59px;">string</td>
<td style="width: 371px;">Exclusion type.</td>
</tr>
<tr>
<td style="width: 310px;">Minerva.Exclusion.Data</td>
<td style="width: 59px;">string</td>
<td style="width: 371px;">Exclusion data.</td>
</tr>
<tr>
<td style="width: 310px;">Minerva.Exclusion.Description</td>
<td style="width: 59px;">string</td>
<td style="width: 371px;">A description of the exclusion.</td>
</tr>
<tr>
<td style="width: 310px;">Minerva.Exclusion.lastModifiedBy</td>
<td style="width: 59px;">string</td>
<td style="width: 371px;">The user that last modified this exclusion.</td>
</tr>
<tr>
<td style="width: 310px;">Minerva.Exclusion.lastModifiedOn</td>
<td style="width: 59px;">date</td>
<td style="width: 371px;">The date this exclusion was last modified.</td>
</tr>
<tr>
<td style="width: 310px;">Minerva.Exclusion.appliedGroupsIds</td>
<td style="width: 59px;">string</td>
<td style="width: 371px;">Group IDs to which this exclusion applies.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-add-exclusion type="hash" description="cmd.exe hash" data="d0ceb18272966ab62b8edff100e9b4a6a3cb5dc0f2a32b2b18721fea2d9c09a5" appliedGroupsIds="All Groups"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Last Modified On</th>
<th>Description</th>
<th>Type</th>
<th>Applied Groups Ids</th>
<th>Last Modified By</th>
<th>Data</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>2019-04-04T08:43:51.9441116Z</td>
<td>cmd.exe hash</td>
<td>hash</td>
<td>All Groups</td>
<td>admin</td>
<td>d0ceb18272966ab62b8edff100e9b4a6a3cb5dc0f2a32b2b18721fea2d9c09a5</td>
<td>86238d3e-dc99-4f62-b580-92fc4deb0184</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="add-a-vaccination">2. Add a vaccination</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds a vaccination.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-add-vaccine</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 212px;"><strong>Argument Name</strong></th>
<th style="width: 403px;"><strong>Description</strong></th>
<th style="width: 125px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 212px;">name</td>
<td style="width: 403px;">Name of the mutex.</td>
<td style="width: 125px;">Required</td>
</tr>
<tr>
<td style="width: 212px;">description</td>
<td style="width: 403px;">A description of the vaccination.</td>
<td style="width: 125px;">Optional</td>
</tr>
<tr>
<td style="width: 212px;">isMonitorOnly</td>
<td style="width: 403px;">Whether it is only monitored.</td>
<td style="width: 125px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 254px;"><strong>Path</strong></th>
<th style="width: 68px;"><strong>Type</strong></th>
<th style="width: 418px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 254px;">Minerva.Vaccine.Name</td>
<td style="width: 68px;">string</td>
<td style="width: 418px;">Name of the mutex vaccination.</td>
</tr>
<tr>
<td style="width: 254px;">Minerva.Vaccine.Description</td>
<td style="width: 68px;">string</td>
<td style="width: 418px;">A description of the mutex vaccination.</td>
</tr>
<tr>
<td style="width: 254px;">Minerva.Vaccine.isMonitorOnly</td>
<td style="width: 68px;">boolean</td>
<td style="width: 418px;">Whether this mutex vaccination is only monitored.</td>
</tr>
<tr>
<td style="width: 254px;">Minerva.Vaccine.lastModifiedBy</td>
<td style="width: 68px;">string</td>
<td style="width: 418px;">The user that last modified this mutex vaccination.</td>
</tr>
<tr>
<td style="width: 254px;">Minerva.Vaccine.lastModifiedOn</td>
<td style="width: 68px;">date</td>
<td style="width: 418px;">The date this mutex vaccination was last modified.</td>
</tr>
<tr>
<td style="width: 254px;">Minerva.Vaccine.Id</td>
<td style="width: 68px;">string</td>
<td style="width: 418px;">Mutex vaccination ID.</td>
</tr>
<tr>
<td style="width: 254px;">Minerva.Vaccine.Type</td>
<td style="width: 68px;">string</td>
<td style="width: 418px;">Vaccine type, for example: Mutex.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-add-vaccine name="Local\SomeMaliciousMutex" description="Made up mutex name" isMonitorOnly=True
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Last Modified On</th>
<th>Is Monitor Only</th>
<th>Name</th>
<th>Last Modified By</th>
<th>Type</th>
<th>Id</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>2019-05-13T09:48:51.6194895Z</td>
<td>true</td>
<td>Local\SomeMaliciousMutex</td>
<td>admin</td>
<td>Mutex</td>
<td>711db7ed-d4c9-459b-a4bd-e23c077d4acc</td>
<td>Made up mutex name</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="search-for-processes">3. Search for processes</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Search processes with Minerva.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-search-process</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 527px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">param</td>
<td style="width: 527px;">Parameter to search for.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">condition</td>
<td style="width: 527px;">A condition to apply to the search (“equalTo”, “notEqualTo”, “contain”,“notContain”, “startWith”, “endWith”).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">value</td>
<td style="width: 527px;">Value.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 243px;"><strong>Path</strong></th>
<th style="width: 56px;"><strong>Type</strong></th>
<th style="width: 441px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 243px;">Minerva.Process.Endpoint</td>
<td style="width: 56px;">string</td>
<td style="width: 441px;">The name of the endpoint on which the process was run.</td>
</tr>
<tr>
<td style="width: 243px;">Minerva.Process.SHA256</td>
<td style="width: 56px;">string</td>
<td style="width: 441px;">The SHA256 hash of the process.</td>
</tr>
<tr>
<td style="width: 243px;">Minerva.Process.CommandLine</td>
<td style="width: 56px;">string</td>
<td style="width: 441px;">The process command line.</td>
</tr>
<tr>
<td style="width: 243px;">Minerva.Process.Username</td>
<td style="width: 56px;">string</td>
<td style="width: 441px;">The user name with which the process was executed.</td>
</tr>
<tr>
<td style="width: 243px;">Minerva.Process.Createtime</td>
<td style="width: 56px;">date</td>
<td style="width: 441px;">The time the process was created.</td>
</tr>
<tr>
<td style="width: 243px;">Minerva.Process.Pid</td>
<td style="width: 56px;">number</td>
<td style="width: 441px;">The process ID.</td>
</tr>
<tr>
<td style="width: 243px;">Minerva.Process.Name</td>
<td style="width: 56px;">string</td>
<td style="width: 441px;">The process name.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-search-process param="processName" condition="endWith" value="explorer.exe"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Username</th>
<th>Process Id</th>
<th>Endpoint</th>
<th>File Hash</th>
<th>Process Command Line</th>
<th>Process Name</th>
<th>Depth</th>
<th>Start Time</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>DaniK@MVDEV</td>
<td>21736</td>
<td>danik.MVDev.local</td>
<td>cef64201a97e08834f5c8952907a1719531a7d99b53309cb2e2956f40cff3486</td>
<td>C:\WINDOWS\explorer.exe /factory,{ceff45ee-c862-41de-aee2-a022c81eda92} -Embedding</td>
<td>C:\Windows\explorer.exe</td>
<td>0</td>
<td>2019-05-08T07:28:29.009</td>
<td>f502aede-f4f6-4397-a760-0e08248506dc</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="search-for-an-endpoint">4. Search for an endpoint</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Search Minerva for an endpoint.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-search-endpoint</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 533px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">param</td>
<td style="width: 533px;">Parameter to search for.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">condition</td>
<td style="width: 533px;">A condition to apply to the search (“equalTo”, “notEqualTo”, “contain”, “notContain”, “startWith”, “endWith”).</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">value</td>
<td style="width: 533px;">Value.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 247px;"><strong>Path</strong></th>
<th style="width: 64px;"><strong>Type</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 247px;">Minerva.Endpoint.Group</td>
<td style="width: 64px;">string</td>
<td style="width: 429px;">The group to which the endpoint belongs.</td>
</tr>
<tr>
<td style="width: 247px;">Minerva.Endpoint.Name</td>
<td style="width: 64px;">string</td>
<td style="width: 429px;">The endpoint name.</td>
</tr>
<tr>
<td style="width: 247px;">Minerva.Endpoint.Users</td>
<td style="width: 64px;">string</td>
<td style="width: 429px;">The list of logged-on users.</td>
</tr>
<tr>
<td style="width: 247px;">Minerva.Endpoint.IP</td>
<td style="width: 64px;">string</td>
<td style="width: 429px;">The reported IP address.</td>
</tr>
<tr>
<td style="width: 247px;">Minerva.Endpoint.OS</td>
<td style="width: 64px;">string</td>
<td style="width: 429px;">The endpoint operating system.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-search-endpoint param="operatingSystem" condition="equalTo" value="Windows"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Is Armor Version Supported</th>
<th>First Seen Online</th>
<th>Updated</th>
<th>Endpoint</th>
<th>Group</th>
<th>Operating System</th>
<th>Reported Ip Address</th>
<th>Anti Virus Signature Age</th>
<th>Logged On Users</th>
<th>Last Seen Online</th>
<th>Armor Version</th>
<th>Anti Virus Status</th>
<th>Agent Status</th>
<th>Days Registered</th>
<th>Id</th>
<th>Received Ip Address</th>
</tr>
</thead>
<tbody>
<tr>
<td>true</td>
<td>2019-05-07T11:18:38.2782338</td>
<td>false</td>
<td>WIN2k16-ELIR-OWL</td>
<td>Default Group</td>
<td>Windows</td>
<td>172.16.0.182</td>
<td> </td>
<td>Administrator</td>
<td>2019-05-13T09:48:48.6032188</td>
<td>2.8.0.5173</td>
<td>N/A</td>
<td>Online</td>
<td>5</td>
<td>{6368a324-139b-4765-98f5-5f8417fb296c}</td>
<td>172.16.0.182</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-all-groups">5. Get all groups</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Fetches all the groups defined in Minerva Management Console.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-get-groups</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 292px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 368px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 292px;">Minerva.Group.Id</td>
<td style="width: 80px;">string</td>
<td style="width: 368px;">The ID of the group.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.Name</td>
<td style="width: 80px;">string</td>
<td style="width: 368px;">The name of the group.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.Policy</td>
<td style="width: 80px;">string</td>
<td style="width: 368px;">The policy applied to the group.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.PolicyVersion</td>
<td style="width: 80px;">string</td>
<td style="width: 368px;">The policy version applied to the group.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.EndpointSettings</td>
<td style="width: 80px;">string</td>
<td style="width: 368px;">The settings applied to the group.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.Endpoints</td>
<td style="width: 80px;">number</td>
<td style="width: 368px;">The number of endpoints in the group.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.Comment</td>
<td style="width: 80px;">string</td>
<td style="width: 368px;">The comment the group creator added.</td>
</tr>
<tr>
<td style="width: 292px;">Minerva.Group.CreationTime</td>
<td style="width: 80px;">date</td>
<td style="width: 368px;">The time the group was created.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-get-groups
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>Creation Time</th>
<th>Events</th>
<th>Endpoint Settings</th>
<th>Policy</th>
<th>Endpoints</th>
<th>Id</th>
<th>Policy Version</th>
</tr>
</thead>
<tbody>
<tr>
<td>Default Group</td>
<td>0001-01-01T00:00:00+00:00</td>
<td>0</td>
<td>Fully Simulating</td>
<td>Main</td>
<td>2</td>
<td>DefaultAgentGroup</td>
<td>Version-946</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-mutex-vaccines">6. Get mutex vaccines</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves the mutex vaccines.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-get-vaccines</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 218px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 462px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">Minerva.Vaccine.Name</td>
<td style="width: 60px;">string</td>
<td style="width: 462px;">Mutex vaccination name.</td>
</tr>
<tr>
<td style="width: 218px;">Minerva.Vaccine.Description</td>
<td style="width: 60px;">string</td>
<td style="width: 462px;">Mutex vaccination description.</td>
</tr>
<tr>
<td style="width: 218px;">Minerva.Vaccine.isMonitorOnly</td>
<td style="width: 60px;">boolean</td>
<td style="width: 462px;">Whether this mutex vaccination is only monitored without simulation.</td>
</tr>
<tr>
<td style="width: 218px;">Minerva.Vaccine.lastModifiedBy</td>
<td style="width: 60px;">string</td>
<td style="width: 462px;">The user that last modified this mutex vaccination.</td>
</tr>
<tr>
<td style="width: 218px;">Minerva.Vaccine.lastModifiedOn</td>
<td style="width: 60px;">date</td>
<td style="width: 462px;">The date this mutex vaccination was last modified.</td>
</tr>
<tr>
<td style="width: 218px;">Minerva.Vaccine.Id</td>
<td style="width: 60px;">string</td>
<td style="width: 462px;">Mutex vaccination ID.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>minerva-get-vaccines
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Last Modified On</th>
<th>Is Monitor Only</th>
<th>Name</th>
<th>Last Modified By</th>
<th>Type</th>
<th>Id</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>2019-05-14T07:36:21.6655031Z</td>
<td>true</td>
<td>Local\SomeVaccination</td>
<td>admin</td>
<td>Mutex</td>
<td>9fef012d-b066-4dc3-a912-8f6613e5bef0</td>
<td>A sample vaccination with local scope</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="delete-a-vaccine">7. Delete a vaccine</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a vaccine by the vaccine ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-delete-vaccine</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 219px;"><strong>Argument Name</strong></th>
<th style="width: 395px;"><strong>Description</strong></th>
<th style="width: 126px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 219px;">vaccine_id</td>
<td style="width: 395px;">The ID of the specified vaccine.</td>
<td style="width: 126px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-6">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-delete-vaccine vaccine_id=VACCINE_ID
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Cortex XSOAR outputs:<span> </span><code>"Vaccine '9fef012d-b066-4dc3-a912-8f6613e5bef0' was deleted"</code></p>
</div>
<div class="cl-preview-section">
<h3 id="get-all-exclusions">8. Get all exclusions</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves all exclusions.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-get-exclusions</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 313px;"><strong>Path</strong></th>
<th style="width: 56px;"><strong>Type</strong></th>
<th style="width: 371px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 313px;">Minerva.Exclusion.Id</td>
<td style="width: 56px;">string</td>
<td style="width: 371px;">Exclusion ID.</td>
</tr>
<tr>
<td style="width: 313px;">Minerva.Exclusion.Type</td>
<td style="width: 56px;">string</td>
<td style="width: 371px;">Exclusion type.</td>
</tr>
<tr>
<td style="width: 313px;">Minerva.Exclusion.Data</td>
<td style="width: 56px;">string</td>
<td style="width: 371px;">Exclusion data.</td>
</tr>
<tr>
<td style="width: 313px;">Minerva.Exclusion.Description</td>
<td style="width: 56px;">string</td>
<td style="width: 371px;">Exclusion description.</td>
</tr>
<tr>
<td style="width: 313px;">Minerva.Exclusion.lastModifiedBy</td>
<td style="width: 56px;">string</td>
<td style="width: 371px;">The user that last modified this exclusion.</td>
</tr>
<tr>
<td style="width: 313px;">Minerva.Exclusion.lastModifiedOn</td>
<td style="width: 56px;">date</td>
<td style="width: 371px;">The date this exclusion was last modified.</td>
</tr>
<tr>
<td style="width: 313px;">Minerva.Exclusion.appliedGroupsIds</td>
<td style="width: 56px;">string</td>
<td style="width: 371px;">Group IDs to which this exclusion applies.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-get-exclusions
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Last Modified On</th>
<th>Description</th>
<th>Type</th>
<th>Applied Groups Ids</th>
<th>Last Modified By</th>
<th>Data</th>
<th>Id</th>
</tr>
</thead>
<tbody>
<tr>
<td>2019-05-13T09:39:38.2410566Z</td>
<td>Excluding explorer.exe by hash</td>
<td>hash</td>
<td>All Groups</td>
<td>admin</td>
<td>[“cef64201a97e08834f5c8952907a1719531a7d99b53309cb2e2956f40cff3486”,“cef64201a97e08834f5c8952907a1719531a7d99b53309cb2e2956f40cff3486”,“cef64201a97e08834f5c8952907a1719531a7d99b53309cb2e2956f40cff3486”]</td>
<td>a2ea76c5-95f5-4f40-88f6-bac40ce6d685</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="delete-an-exclusion">9. Delete an exclusion</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes an exclusion by the exclusion ID.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-delete-exclusion</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 302px;"><strong>Argument Name</strong></th>
<th style="width: 265px;"><strong>Description</strong></th>
<th style="width: 173px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 302px;">id</td>
<td style="width: 265px;">Exclusion ID.</td>
<td style="width: 173px;">Required</td>
</tr>
<tr>
<td style="width: 302px;">type</td>
<td style="width: 265px;">Exclusion type.</td>
<td style="width: 173px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-delete-exclusion id=EXCLUSION_ID type=hash
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Cortex XSOAR outputs:<span> </span><code>"Exclusion a2ea76c5-95f5-4f40-88f6-bac40ce6d685 was deleted"</code></p>
</div>
<div class="cl-preview-section">
<h3 id="move-all-events-from-archive-to-new-event-state">10. Move all events from Archive to New event state</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Moves all the events from Archive state to New event state.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>minerva-unarchive-events</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!minerva-unarchive-events
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Cortex XSOAR outputs:<span> </span><code>"Events were un-archived"</code></p>
</div>
<div class="cl-preview-section">
<h2 id="known-limitations">Known Limitations</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Users can’t add an already existing vaccination.</li>
<li>Fetched events are archived in Minerva Console.</li>
</ul>
</div>