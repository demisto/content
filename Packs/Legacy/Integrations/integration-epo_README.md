<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the McAfee EPO integration to manage security threats and responses.</p>
<p>This integration was integrated and tested with McAfee ePO v5.3.2.</p>
<p> </p>
<h2>Configure McAfee ePO on Demisto</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for McAfee ePO.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>https://</strong><strong>:port</strong>
</li>
<li><strong>Username</strong></li>
<li>
<strong>Trust any certificate (unsecure)</strong> Mark to trust Certificate Authority.</li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_4398436244661540822555265">Print help for ePO commands: epo-help</a></li>
<li><a href="#h_5938196955391540822561798">Get the latest DAT file: epo-get-latest-dat</a></li>
<li><a href="#h_5725046776121540822569407">Check the current DAT file version: epo-get-current-dat</a></li>
<li><a href="#h_8013574706831540822575472">Update the DAT file: epo-update-client-dat</a></li>
<li><a href="#h_1440750507531540822580480">Update a repository: epo-update-repository</a></li>
<li><a href="#h_390906368211540822586465">Get system tree groups: epo-get-system-tree-group</a></li>
<li><a href="#h_3033287078891540822593526">Find systems in the system tree: epo-find-systems</a></li>
<li><a href="#h_154933902521540822159645">epo-command</a></li>
<li><a href="#h_9218526581221540822164106">epo-advanced-command</a></li>
<li><a href="#h_5053745251931540822169351">Wake up an agent: epo-wakeup-agent</a></li>
<li><a href="#h_1127645753261540822174777">Apply a tag: epo-apply-tag</a></li>
<li><a href="#h_5840863013931540822180185">Clear a tag: epo-clear-tag</a></li>
<li><a href="#h_842978555611540984657127">Query an ePO table: epo-query-table</a></li>
<li><a href="#h_2075553172141540984662098">Get an ePO table: epo-get-table</a></li>
<li><a href="#h_426180010731542121106347">Get the ePO version: epo-get-version</a></li>
<li><a href="#h_3170511881611542121112987">Find systems in the system tree: epo-find-system</a></li>
<li><a href="#h_834b11c9-e2d0-47a0-a9bd-5e20e062dee4" target="_self">Move a system to a different group: epo-move-system</a></li>
</ol>
<h3 id="h_4398436244661540822555265">1. Print help for ePO commands</h3>
<hr>
<p><span>Prints help (information) for ePO commands. If no command argument is specified, returns all ePO commands.</span></p>
<h5>Base Command</h5>
<pre><code>epo-help</code></pre>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206.4px;"><strong>Argument Name</strong></th>
<th style="width: 382.6px;"><strong>Description</strong></th>
<th style="width: 118px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206.4px;">search</td>
<td style="width: 382.6px;"><span>String to search for in help.</span></td>
<td style="width: 118px;">Optional</td>
</tr>
<tr>
<td style="width: 206.4px;">command</td>
<td style="width: 382.6px;">Command for which to print help.</td>
<td style="width: 118px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p>!epo-help search="agent"</p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/44625852-d013c300-a91a-11e8-839e-b4f139ab893d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/44625852-d013c300-a91a-11e8-839e-b4f139ab893d.png" alt="screen shot 2018-08-26 at 10 28 00" width="750" height="334"></a></p>
<h3 id="h_5938196955391540822561798">2. Get the latest DAT file</h3>
<hr>
<p>Checks for the latest DAT file in the McAfee repository.</p>
<h5>Base Command</h5>
<pre><code>epo-get-latest-dat</code></pre>
<h5>Input</h5>
<p>There is no input for this command. </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 262.8px;"><strong>Path</strong></th>
<th style="width: 88.2px;"><strong>Type</strong></th>
<th style="width: 356px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 262.8px;">McAfee.ePO.latestDAT</td>
<td style="width: 88.2px;">Number</td>
<td style="width: 356px;">Latest McAfee DAT file version.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!epo-get-latest-dat</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/44625740-2b44b600-a919-11e8-9d18-ecca5185ffef.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/44625740-2b44b600-a919-11e8-9d18-ecca5185ffef.png" alt="screen shot 2018-08-26 at 10 15 58"></a></p>
<h3 id="h_5725046776121540822569407">3. Check the current DAT file version</h3>
<hr>
<p><span>Checks the existing DAT file version in ePO.</span></p>
<h5>Base Command</h5>
<pre><code>epo-get-current-dat</code></pre>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 203.2px;"><strong>Path</strong></th>
<th style="width: 65.8px;"><strong>Type</strong></th>
<th style="width: 439px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 203.2px;">McAfee.ePO.epoDAT</td>
<td style="width: 65.8px;">number</td>
<td style="width: 439px;">Current McAfee DAT file in the ePO repository.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!epo-get-current-dat</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/44625764-7bbc1380-a919-11e8-9959-1090d30f1db3.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/44625764-7bbc1380-a919-11e8-9959-1090d30f1db3.png" alt="screen shot 2018-08-26 at 10 18 36"></a></p>
<h3 id="h_8013574706831540822575472">4. Update the DAT file</h3>
<hr>
<p>Run client task to update the DAT file.</p>
<p>To run this command, you need to create a task on the ePO server with a specific name.</p>
<ol>
<li>Log on to the ePO server.</li>
<li>Select <strong>System Tree</strong>.</li>
<li>Select <strong>Assigned Client Tasks</strong> &gt; <strong>Actions</strong> &gt; <strong>New Client Task Assignment</strong>.</li>
<li>Configure the <strong>Select Task</strong> section.<br>
<table style="height: 86px;" border="2" width="542" cellpadding="6">
<tbody>
<tr style="height: 21px;">
<td style="width: 267px; height: 21px;"><strong>Field</strong></td>
<td style="width: 268px; height: 21px;"><strong>Value</strong></td>
</tr>
<tr style="height: 24.45px;">
<td style="width: 267px; height: 24.45px;">Product</td>
<td style="width: 268px; height: 24.45px;">McAfee Agent</td>
</tr>
<tr style="height: 21px;">
<td style="width: 267px; height: 21px;">Task Type</td>
<td style="width: 268px; height: 21px;">Product Update</td>
</tr>
<tr style="height: 21px;">
<td style="width: 267px; height: 21px;">Task Name</td>
<td style="width: 268px; height: 21px;">DAT Update</td>
</tr>
</tbody>
</table>
</li>
<li>Select <strong>Create New Task</strong>.<br>
<table style="height: 114px; width: 539px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 264.6px;"><strong>Field</strong></td>
<td style="width: 269.4px;"><strong>Value</strong></td>
</tr>
<tr>
<td style="width: 264.6px;">Task Name</td>
<td style="width: 269.4px;">VSEContentUpdateDemisto</td>
</tr>
<tr>
<td style="width: 264.6px;">Package Selection</td>
<td style="width: 269.4px;">Selected packages</td>
</tr>
<tr>
<td style="width: 264.6px;">Signatures and Engines</td>
<td style="width: 269.4px;">DAT</td>
</tr>
</tbody>
</table>
</li>
</ol>
<h5>Base Command</h5>
<pre><code>epo-update-client-dat</code></pre>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 173.6px;"><strong>Argument Name</strong></th>
<th style="width: 463.4px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173.6px;">systems</td>
<td style="width: 463.4px;"><span>A CSV list of IP addresses or system names.</span></td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 173.6px;">retryAttempts</td>
<td style="width: 463.4px;"><span>Number of times the server will attempt to send the task to the client. Default is 1 retry.</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173.6px;">retryIntervalInSeconds</td>
<td style="width: 463.4px;">Retry interval in seconds. Default is 30 seconds.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173.6px;">abortAfterMinutes</td>
<td style="width: 463.4px;"><span>The threshold (in minutes) after which attempts to send the task to the client are aborted. Default is 5.</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173.6px;">stopAfterMinutes</td>
<td style="width: 463.4px;"><span>The threshold (in minutes) that the client task is allowed to run. Defaults to 20.</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 173.6px;">randomizationInterval</td>
<td style="width: 463.4px;">Duration (in minutes) over which to randomly spread task execution. Default is 0 (executes on all clients immediately).</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!epo-update-client-dat systems=ADMIN-PC</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/44625952-9d6aca00-a91c-11e8-92b7-2a42b2b618d6.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/44625952-9d6aca00-a91c-11e8-92b7-2a42b2b618d6.png" alt="screen shot 2018-08-26 at 10 41 04"></a></p>
<h3 id="h_1440750507531540822580480">5. Update a repository</h3>
<hr>
<p><span>Triggers a server task in specific ePO servers to retrieve the latest signatures from the update server.</span></p>
<h5>Base Command</h5>
<pre><code>epo-update-repository</code></pre>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!epo-update-repository</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/44625662-65ad5380-a917-11e8-8120-5e6211e148bd.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/44625662-65ad5380-a917-11e8-8120-5e6211e148bd.png" alt="screen shot 2018-08-26 at 10 00 40" width="751" height="272"></a></p>
<h3 id="h_390906368211540822586465">6. Get system tree groups</h3>
<hr>
<p><span>Returns system tree groups.</span></p>
<h5>Base Command</h5>
<p><code>epo-get-system-tree-group</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 189.4px;"><strong>Argument Name</strong></th>
<th style="width: 417.6px;"><strong>Description</strong></th>
<th style="width: 100px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 189.4px;">search</td>
<td style="width: 417.6px;">String to search for in the system tree group.</td>
<td style="width: 100px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 395px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 234px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 395px;">McAfee.ePO.SystemTreeGroups.groupId</td>
<td style="width: 78px;">number</td>
<td style="width: 234px;">System tree group ID.</td>
</tr>
<tr>
<td style="width: 395px;">McAfee.ePO.SystemTreeGroups.groupPath</td>
<td style="width: 78px;">string</td>
<td style="width: 234px;">System tree group path.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/44625635-d0aa5a80-a916-11e8-826d-15bae934412c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/44625635-d0aa5a80-a916-11e8-826d-15bae934412c.png" alt="screen shot 2018-08-26 at 9 59 49" width="747" height="305"></a></p>
<h3 id="h_3033287078891540822593526">7. Find systems in the system tree</h3>
<hr>
<p>Find systems in the System Tree - by group ID or by search</p>
<h5>Base Command</h5>
<p><code>epo-find-systems</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 193.4px;"><strong>Argument Name</strong></th>
<th style="width: 395.6px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 193.4px;">groupId</td>
<td style="width: 395.6px;">System tree group ID.</td>
<td style="width: 117px;">Required</td>
</tr>
<tr>
<td style="width: 193.4px;">verbose</td>
<td style="width: 395.6px;">Whether to return all system data.</td>
<td style="width: 117px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 362.2px;"><strong>Path</strong></th>
<th style="width: 90.8px;"><strong>Type</strong></th>
<th style="width: 255px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 362.2px;">Endpoint.Name</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint name.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.Domain</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint domain.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.Hostname</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint hostname.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.IPAddress</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.OS</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint OS.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.OSVersion</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint OS version.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.Processor</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Processor model.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.Processors</td>
<td style="width: 90.8px;">number</td>
<td style="width: 255px;">Number of processors.</td>
</tr>
<tr>
<td style="width: 362.2px;">Endpoint.Memory</td>
<td style="width: 90.8px;">number</td>
<td style="width: 255px;">Endpoint memory.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.Name</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint name.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.Domain</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint domain.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.Hostname</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint hostname.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.IPAddress</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.OS</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint OS.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.OSVersion</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Endpoint OS version.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.Processor</td>
<td style="width: 90.8px;">string</td>
<td style="width: 255px;">Processor model.</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.Processors</td>
<td style="width: 90.8px;">number</td>
<td style="width: 255px;">Number of processors</td>
</tr>
<tr>
<td style="width: 362.2px;">McAfee.ePO.Endpoint.Memory</td>
<td style="width: 90.8px;">number</td>
<td style="width: 255px;">Endpoint memory.</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_154933902521540822159645">8. epo-command</h3>
<hr>
<p><span>Executes the ePO command. Receives the mandatory ''command'' argument, and other optional arguments. </span></p>
<p><span>To get a list of available commands, run the ''epo-help'' command to get a list of available commands. You can also specify the ''headers'' argument to filter table headers. Example/:/ !epo-command command=system.find searchText=10.0.0.1 headers=EPOBranchNode.AutoID,EPOComputerProperties.ComputerName</span></p>
<h5>Base Command</h5>
<pre>epo-command</pre>
<h5>Command Example</h5>
<pre>!epo-command command=system.find searchText=10.0.0.1</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/46333148-e1da3b80-c627-11e8-82cf-40970f8e5aab.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/46333148-e1da3b80-c627-11e8-82cf-40970f8e5aab.png" alt="screen shot 2018-10-02 at 9 44 34" width="754" height="111"></a></p>
<p>!epo-command command=agentmgmt.listAgentHandlers</p>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/46333232-37164d00-c628-11e8-91a7-1be03063edb0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/46333232-37164d00-c628-11e8-91a7-1be03063edb0.png" alt="screen shot 2018-10-02 at 9 46 00" width="752" height="415"></a></p>
<h3 id="h_9218526581221540822164106">9. epo-advanced-command</h3>
<hr>
<p><span>Executes the ePO command. </span></p>
<p><span>To get a list of available commands, run the ''epo-help'' command. For example/:/ !epo-advanced-command command=clienttask.find commandArgs=searchText:On-demand. You can also specify the ''headers'' argument to filter table headers, for example/:/ !epo-command command=system.find searchText=10.0.0.1 headers=EPOBranchNode.AutoID,EPOComputerProperties.ComputerName.</span></p>
<h5>Base Command</h5>
<pre><code>epo-advanced-command</code></pre>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 144.6px;"><strong>Argument Name</strong></th>
<th style="width: 492.4px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144.6px;">command</td>
<td style="width: 492.4px;"><span>The command to execute. Run either the core.help command or the !epo-help to get all available commands.</span></td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144.6px;">commandArgs</td>
<td style="width: 492.4px;"><span>CSV list of key value pairs as additional arguments to pass, for example, "argName1:argValue1,argName2:argValue2".</span></td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p> There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!epo-advanced-command command="clienttask.find" commandArgs="searchText:On-demand"</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/47647276-27cee480-db7f-11e8-9430-b3685d914cde.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/47647276-27cee480-db7f-11e8-9430-b3685d914cde.png" alt="screen shot 2018-10-29 at 13 31 53" width="750" height="123"></a></p>
<h3 id="h_5053745251931540822169351">10. Wake up an agent</h3>
<hr>
<p>Wakes up an agent.</p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 284px;"><strong>Argument Name</strong></th>
<th style="width: 258px;"><strong>Description</strong></th>
<th style="width: 165px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 284px;">names</td>
<td style="width: 258px;">Agent hostname.</td>
<td style="width: 165px;">Required</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_1127645753261540822174777">11. Apply a tag</h3>
<hr>
<p>Applies a tag to hostnames.</p>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 235px;"><strong>Argument Name</strong></th>
<th style="width: 340px;"><strong>Description</strong></th>
<th style="width: 132px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 235px;">names</td>
<td style="width: 340px;">Hostnames on which to apply tags.</td>
<td style="width: 132px;">Required</td>
</tr>
<tr>
<td style="width: 235px;">tagName</td>
<td style="width: 340px;">Tag name.</td>
<td style="width: 132px;">Required</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Command Example</h4>
<pre>!epo-apply-tag names="ADMIN-PC" tagName="Compromised"</pre>
<h3 id="h_5840863013931540822180185">12. Clear a tag</h3>
<hr>
<p>Clears a tag from hostnames.</p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 232.4px;"><strong>Argument Name</strong></th>
<th style="width: 343.6px;"><strong>Description</strong></th>
<th style="width: 132px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 232.4px;">names</td>
<td style="width: 343.6px;">Hostnames from which to clear tags.</td>
<td style="width: 132px;">Required</td>
</tr>
<tr>
<td style="width: 232.4px;">tagName</td>
<td style="width: 343.6px;">Tag name.</td>
<td style="width: 132px;">Required</td>
</tr>
</tbody>
</table>
<h4> </h4>
<h4>Command Example</h4>
<pre>!epo-clear-tag names="ADMIN-PC" tagName="Compromised"</pre>
<p> </p>
<h3 id="h_842978555611540984657127">13. Query an ePO table</h3>
<hr>
<p>Queries an ePO table.</p>
<h5>Base Command</h5>
<pre><code>epo-query-table</code></pre>
<h5>Input</h5>
<table style="width: 742px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 146.2px;"><strong>Argument Name</strong></th>
<th style="width: 489.8px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146.2px;">target</td>
<td style="width: 489.8px;">Table name.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 146.2px;">select</td>
<td style="width: 489.8px;">The columns to select, in SQUID syntax. Example: "(select EPOEvents.AutoID EPOEvents.DetectedUTC EPOEvents.ReceivedUTC)".</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146.2px;">where</td>
<td style="width: 489.8px;"><span>Filter results, in SQUID syntax. Example: "(where ( eq ( OrionTaskLogTask .UserName "ga" )))".</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146.2px;">order</td>
<td style="width: 489.8px;"><span>Order in which to return the results, in SQUID syntax. Example: "(order (asc OrionTaskLogTask.StartDate) )").</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146.2px;">group</td>
<td style="width: 489.8px;"><span>Group the results, in SQUID Syntax. Example: "(group EPOBranchNode.NodeName)".</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146.2px;">joinTables</td>
<td style="width: 489.8px;"><span>Perform join, in SQUID syntax.</span></td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 146.2px;">query_name</td>
<td style="width: 489.8px;">Name for the query to appear in the context.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 396.8px;"><strong>Path</strong></th>
<th style="width: 324.2px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 396.8px;">McAfee.ePO.Query</td>
<td style="width: 324.2px;">Query result.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Human Readable Output</h5>
<pre>!epo-query-table target=EPOLeafNode select="(select EPOLeafNode.NodeName EPOLeafNode.Tags EPOBranchNode.NodeName)" where="(hasTag EPOLeafNode.AppliedTags 4)"</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/47652110-bf3b3400-db8d-11e8-934d-56542c178b6f.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/47652110-bf3b3400-db8d-11e8-934d-56542c178b6f.png" alt="screen shot 2018-10-29 at 15 17 18" width="751" height="159"></a></p>
<pre>!epo-query-table target=EPOLeafNode select="(select (top 3) EPOLeafNode.NodeName EPOLeafNode.Tags EPOBranchNode.NodeName)"</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/47652140-d417c780-db8d-11e8-819b-542dcc01c925.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/47652140-d417c780-db8d-11e8-819b-542dcc01c925.png" alt="screen shot 2018-10-29 at 15 17 43" width="750" height="181"></a></p>
<pre>!epo-query-table target="EPOEvents" select="(select EPOEvents.AutoID EPOEvents.DetectedUTC EPOEvents.ReceivedUTC)" order="(order(desc EPOEvents.DetectedUTC))"</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/47656891-b734c180-db98-11e8-9c65-1b58fd4c8268.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/47656891-b734c180-db98-11e8-9c65-1b58fd4c8268.png" alt="screen shot 2018-10-29 at 16 35 41" width="752" height="307"></a></p>
<pre>!epo-query-table target="EPExtendedEvent" select="(select (top 250) EPOEvents.ThreatName EPOEvents.AutoID EPExtendedEvent.EventAutoID EPExtendedEvent.TargetHash EPExtendedEvent.TargetPath EPOEvents.SourceHostName)" order="(order(desc EPExtendedEvent.TargetHash))" joinTables="EPOEvents"where="(where(eq EPOEvents.ThreatName "real Protect-LS!d5435f1fea5e"))"</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/47773949-4b676b80-dcf4-11e8-9562-c67fced9176c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/47773949-4b676b80-dcf4-11e8-9562-c67fced9176c.png" alt="screen shot 2018-10-31 at 10 03 49" width="752" height="272"></a></p>
<h3 id="h_2075553172141540984662098">14. Get an ePO table</h3>
<hr>
<p>Returns an ePO table.</p>
<h5>Base Command</h5>
<pre><code>epo-get-tables</code></pre>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 280.4px;"><strong>Argument Name</strong></th>
<th style="width: 267.6px;"><strong>Description</strong></th>
<th style="width: 160px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 280.4px;">table</td>
<td style="width: 267.6px;">Name of the table to return.</td>
<td style="width: 160px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!epo-get-tables</pre>
<h5>Human Readable Output</h5>
<h5><a href="https://user-images.githubusercontent.com/37335599/47652211-06292980-db8e-11e8-8075-87a415c92b20.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/47652211-06292980-db8e-11e8-8075-87a415c92b20.png" alt="screen shot 2018-10-29 at 15 19 13" width="749" height="373"></a></h5>
<h3 id="h_426180010731542121106347">15. Get the ePO version</h3>
<hr>
<p>Gets the ePO version. This command requires global admin permissions.</p>
<h5>Base Command</h5>
<pre><code>epo-get-version</code></pre>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 349.4px;"><strong>Path</strong></th>
<th style="width: 121.6px;"><strong>Type</strong></th>
<th style="width: 237px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 349.4px;">McAfee.ePO.Version</td>
<td style="width: 121.6px;">string</td>
<td style="width: 237px;">ePO version.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Human Readable Output</h5>
<pre>!epo-get-version</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/48068154-b58f7d00-e1da-11e8-97c1-410d77954d6d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/48068154-b58f7d00-e1da-11e8-97c1-410d77954d6d.png" alt="screen shot 2018-11-06 at 15 43 18" width="751" height="102"></a></p>
<h3 id="h_3170511881611542121112987">16. Find systems in the system tree</h3>
<hr>
<p>Finds systems in the system tree.</p>
<h5>Base Command</h5>
<pre><code>epo-find-system</code></pre>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 254.6px;"><strong>Argument Name</strong></th>
<th style="width: 306.4px;"><strong>Description</strong></th>
<th style="width: 147px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 254.6px;">searchText</td>
<td style="width: 306.4px;">Hostname to search.</td>
<td style="width: 147px;">Optional</td>
</tr>
<tr>
<td style="width: 254.6px;">verbose</td>
<td style="width: 306.4px;">Print all system data</td>
<td style="width: 147px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 320.2px;"><strong>Path</strong></th>
<th style="width: 73.8px;"><strong>Type</strong></th>
<th style="width: 314px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 320.2px;">Endpoint.Name</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint name.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.Domain</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint domain.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.Hostname</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint hostname.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.IPAddress</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.OS</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint OS.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.OSVersion</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint OS version.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.Processor</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Processor model.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.Processors</td>
<td style="width: 73.8px;">number</td>
<td style="width: 314px;">Number of processors.</td>
</tr>
<tr>
<td style="width: 320.2px;">Endpoint.Memory</td>
<td style="width: 73.8px;">number</td>
<td style="width: 314px;">Endpoint memory.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.Name</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint name.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.Domain</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint domain.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.Hostname</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint hostname.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.IPAddress</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint IP address.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.OS</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint OS.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.OSVersion</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Endpoint OS version.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.Processor</td>
<td style="width: 73.8px;">string</td>
<td style="width: 314px;">Processor model.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.Processors</td>
<td style="width: 73.8px;">number</td>
<td style="width: 314px;">Number of processors.</td>
</tr>
<tr>
<td style="width: 320.2px;">McAfee.ePO.Endpoint.Memory</td>
<td style="width: 73.8px;">number</td>
<td style="width: 314px;">Endpoint memory.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Human Readable Output</h5>
<pre>!epo-find-system searchText=mar</pre>
<p><br> <a href="https://user-images.githubusercontent.com/37335599/48068300-1fa82200-e1db-11e8-9b4c-1df113f5934d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/48068300-1fa82200-e1db-11e8-9b4c-1df113f5934d.png" alt="screen shot 2018-11-06 at 15 46 12" width="751" height="425"></a></p>
<h3 id="h_834b11c9-e2d0-47a0-a9bd-5e20e062dee4">17. Move a system to a different group</h3>
<hr>
<p>Moves a system to a different group.</p>
<h5>Base Command</h5>
<p><code>epo-move-system</code></p>
<h5>Input</h5>
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 319.8px;"><strong>Argument Name</strong></th>
<th style="width: 236.2px;"><strong>Description</strong></th>
<th style="width: 184px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 319.8px;">names</td>
<td style="width: 236.2px;">Asset name.</td>
<td style="width: 184px;">Required</td>
</tr>
<tr>
<td style="width: 319.8px;">parentGroupId</td>
<td style="width: 236.2px;">Group ID.</td>
<td style="width: 184px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!epo-move-system names=tie parentGroupId=3</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/62196720-30ab4b80-b387-11e9-93e2-56f5821cd34c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/62196720-30ab4b80-b387-11e9-93e2-56f5821cd34c.png" alt="Screen Shot 2019-07-31 at 11 34 28" width="580"></a></p>