<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the VMware Carbon Black EDR (Live Response API) integration (formerly known as Carbon Black Enterprise Live Response) to enable security operators to collect information and take action on remote endpoints in real time.</p>
<p>VMware Carbon Black EDR (Live Response API) Integration is configurable with both<strong> VMware Carbon Black EDR (formerly known as Carbon Black Response)</strong> and <strong> VMware Carbon Black Endpoint Standard (formerly known as Carbon Black Defense)</strong>.</p>
<h2>Use Cases</h2>
<ul>
<li>Upload, download, and remove files.</li>
<li>Retrieve and remove registry entries.</li>
<li>Dump contents of physical memory.</li>
<li>Execute and terminate processes.</li>
</ul>
<h2>Playbooks</h2>
<ul>
<li>Carbonblackliveresponse playbook</li>
<li>Carbon Black Live Response - Wait until command complete</li>
<li>Carbon Black Live Response - Create active session</li>
<li>Carbon Black Live Response - Download file</li>
</ul>
<h2>Prerequisites</h2>
<p>This integration can be used on either VMware Carbon Black EDR (formerly known as Carbon Black Response) or VMware Carbon Black Endpoint Standard (formerly known as Carbon Black Defense)<strong>.</strong></p>
<h3>Carbon Black Live Response</h3>
<p>Enable the Live Response API and get an API key. Live Response is disabled by default. If you attempt to use the Live Response integration before enabling it you receive a code 412 error message.</p>
<ol>
<li>In the <code>/etc/cb/cb.conf</code> file, set <em>CbLREnabled=True,</em> to enable Live Response in your Carbon Black Response server.</li>
<li>Restart the Carbon Black Enterprise services to activate the changes.</li>
</ol>
<h3>Get an API key</h3>
<p>Each user in VMware Carbon Black EDR has a personal API key. The API key confers all rights and capabilities assigned to that user to anyone with access to that API key. Therefore, treat your API key as you would your password.</p>
<p>If the API Token is missing or compromised, you can reset the API key to generate a new token and revoke any previous API keys issued to a user.</p>
<ol>
<li>Log in to the Carbon Black console.</li>
<li>Click the username in the upper right and select <strong>Profile info</strong>.</li>
<li>Click <strong>API Token</strong> on the left hand side to reveal your API token. If there is no API token displayed, click <strong>Reset</strong> to create a new one.</li>
</ol>
<h3>VMware Carbon Black Endpoint Standard</h3>
<p>Retrieve an apiKey and connectorId from the Carbon Black environment. </p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Connector.</strong>
</li>
<li>Set up a VMware API Connector. This gives you access to the apiKey and connectorId<strong>.</strong>
</li>
</ol>
<h2>Configure VMware Carbon Black EDR (Live Response API) on Demisto</h2>
<p>You can set up the integration to work with either VMware Carbon Black EDR or VMware Carbon Black Endpoint Standard<strong>.</strong></p>
<p>Set the required fields to suit your instance ONLY.</p>
<h3>To set up the integration to work with VMware Carbon Black EDR:</h3>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for carbonblackliveresponse.</li>
<li>Click _<strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: The hostname or IP address and port of the VMware Carbon Black EDR server used.</li>
<li>
<strong>API Token (CB Response)</strong>: The VMware Carbon Black EDR API token.</li>
</ul>
</li>
</ol>
<ol start="4">
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h3>To set up the integration to work with VMware Carbon Black Endpoint Standard:</h3>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for carbonblackliveresponse.</li>
<li>Click _<strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: The hostname or IP address and port of the VMware Carbon Black Endpoint Standard server used.</li>
<li>
<strong>API Token (CB Defense)</strong>: The VMware Carbon Black Endpoint Standard API token.</li>
<li>
<strong>Connector ID (CB Defense)</strong>: The VMware Carbon Black Endpoint Standard connector ID.</li>
</ul>
</li>
</ol>
<ol start="4">
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<p> </p>
<h2>Using Live Response Integration</h2>
<p>Establish a session with the sensor, to enable commands to be sent to an endpoint.</p>
<p>A sensor with an active session will keep an open connection to the Carbon Black server for as long as the session is active. Sessions are kept for a timeout period, and then recycled.</p>
<p>When executing Live response commands, you can either establish a new session with the sensor or execute commands without session management.</p>
<h3>Establish a new session with the sensor and execute commands</h3>
<ul>
<li>Enables you to execute multiple commands on the endpoint with one continues session. </li>
<li>Faster execution time per command.</li>
<li>Requires session management.</li>
</ul>
<h4>Establish a new session with a specified sensor</h4>
<p>Create a new session using <code>cb-session-create</code> or <code>cb-session-create-and-wait</code> (for the session data to be returned only once active).<br> In the data returned you can find the session ID. This ID will be used to execute Live Response commands on the sensor and retrieve session information when needed.<br> Only one active session per sensor is allowed at a given time.</p>
<h4>Execute Live Response commands providing the session ID</h4>
<p>For example, <code>!cb-directory-listing path="c:\" session=1234 wait-timeout=120</code></p>
<p>Command information will be returned once the command status is <em>active</em> or the <em>wait-timeout</em> has expired (in this case, the command status remains as <em>pending</em>).</p>
<p>In the case of timeout, you may inquire command status and retrieve the command data using <code>cb-command-info</code>.</p>
<p>You may run multiple Live Response commands on one running session, but note that each session has a timeout. This is the timeout that a sensor should wait between commands. If no command is issued over this timeout the sensor will quit.<br> <strong>To avoid session timeout:</strong><br> - Set a longer timeout when creating a new session.<br> - Run the <a href="#h_44260355833921541321220783"><code>cb-keepalive</code></a> command to reset session timeout.</p>
<p><strong>Close the session</strong> using the <a href="#h_63487902757971541332115887"><code>cb-session-close</code></a> command.</p>
<h3>Execute commands without session management</h3>
<ul>
<li>Session management is automated.</li>
<li>Longer execution time per command.</li>
</ul>
<ol>
<li>
<strong>Execute Live Response commands</strong> providing the sensor ID, e.g. !cb-directory-listing path="c:\" sensor=1 wait-timeout=120<br> This will automatically establish a new session with the endpoint, execute the command on the sensor and finally close the session.<br> Command information will be returned once the command status is <em>active</em> or the <code>wait-timeout</code> has expired (in this case, the command status remains <em>pending</em>).<br> In the case of timeout, you may inquire command status and retrieve the command data using <code>cb-command-info</code>.</li>
</ol>
<h2>Known Limitations</h2>
<p><strong>Session Limitations</strong><br> Only one session per sensor is allowed at a given time. An error will occur when trying to open a new session for a sensor with existing active session.</p>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_984625453191541320806517">Archive a session: cb-archive</a></li>
<li><a href="#h_8239514313281541320813075">Cancel a pending command: cb-command-cancel</a></li>
<li><a href="#h_7266081226381541320863194">Display information for a command: cb-command-info</a></li>
<li><a href="#h_86986130412521541321056425">Delete a file: cb-file-delete</a></li>
<li><a href="#h_84104270518651541321162601">Download a file: cb-file-get</a></li>
<li><a href="#h_98933204721751541321179584">Get a file's metadata: cb-file-info</a></li>
<li><a href="#h_66243703230841541321201349">Upload a file to the Carbon Black server: cb-file-upload</a></li>
<li><a href="#h_44260355833921541321220783">Keep a session alive: cb-keepalive</a></li>
<li><a href="#h_36578877936981541321283778">List existing command instances for a session: cb-list-commands</a></li>
<li><a href="#h_23514693443001541331956718">List files: cb-list-files</a></li>
<li><a href="#h_32320574151981541332064168">List all sessions: cb-list-sessions</a></li>
<li><a href="#h_63487902757971541332115887">Close a session: cb-session-close</a></li>
<li><a href="#h_47996079263941541332614096">Create a new session: cb-session-create</a></li>
<li><a href="#h_19771795072861541332696812">Create a new session and wait: cb-session-create-and-wait</a></li>
<li><a href="#h_88417855675911541332795275">Get information about a session: cb-session-info</a></li>
<li><a href="#h_8091131581881541333003941">Terminate a process: cb-process-kill</a></li>
<li><a href="#h_85680905287911541333134540">List directories on the endpoint: cb-directory-listing</a></li>
<li><a href="#h_547321474108831541333344651">Run an executable on an endpoint: cb-process-execute</a></li>
<li><a href="#h_894139734117801541333380560">Endpoint memory dump: cb-memdump</a></li>
<li><a href="#h_696629611123791541333655660">Create a command: cb-command-create</a></li>
<li><a href="#h_688812215129761541333716647">Create a command and wait: cb-command-create-and-wait</a></li>
<li><a href="#h_358153233135701541333863539">Terminate a process: cb-terminate-process</a></li>
<li><a href="#h_757732769141641541333979374">Delete a file from an endpoint: cb-file-delete-from-endpoint</a></li>
<li><a href="#h_275333432150541541334039951">Enumerate registry values: cb-registry-get-values</a></li>
<li><a href="#h_987425608159391541334112772">Query for a registry value: cb-registry-query-value</a></li>
<li><a href="#h_967989363162391541334169756">Create a new registry key: cb-registry-create-key</a></li>
<li><a href="#h_485208221168281541334199010">Delete a registry key: cb-registry-delete-key</a></li>
<li><a href="#h_280293840174151541334261891">Delete a registry value: cb-registry-delete-value</a></li>
<li><a href="#h_924942710182881541334303802">Set a registry value: cb-registry-set-value</a></li>
<li><a href="#h_725204070188751541334456592">Get a list of processes running on an endpoint: cb-process-list</a></li>
<li><a href="#h_990945715194681541334532882">Get a file from an endpoint: cb-get-file-from-endpoint</a></li>
<li><a href="#h_229737590200581541334677178">Save a file to an endpoint: cb-push-file-to-endpoint</a></li>
</ol>
<h3 id="h_984625453191541320806517">1. Archive a session</h3>
<p>Archives the specified session. If the session has no content the command fails.</p>
<h5>Base Command</h5>
<p><code>cb-archive</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID to archive</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5>  </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>cb-archive session=3997</pre>
<h5>Context Example</h5>
<pre>{
  "EntryID": "56@a8449d77-4188-4270-846a-396c5a20d1ef",
  "Extension": "zip",
  "Info": "zip",
  "MD5": "81e67ceddfa1dd2fa668840ffab869c0",
  "Name": "session-3951-archive.zip",
  "SHA1": "212ee624e5312d6e589018c23b708682499074f3",
  "SHA256": "64ef1bd46694f9da1ddc1820d3e5f32e147945f024ab8808b6daba4c6b9b1d86",
  "SSDeep": "96:+DAlcOC5Ee//Jbv6CAOYfyYbzz10xldoqbcdqcLE:+DucOa5bv6CdYXbzJ0x7oLLE",
  "Size": 3751,
  "Type": "gzip compressed data, was "/tmp/tmpvpb7Nt", last modified: Mon Aug  6 07:41:02 2018, max compression\n"
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/28726415/43703413-677cbe4c-9965-11e8-9b1a-d4b3f04c4de7.png" target="_blank" rel="noopener"><img src="https://user-images.githubusercontent.com/28726415/43703413-677cbe4c-9965-11e8-9b1a-d4b3f04c4de7.png" alt="image" width="751" height="439"></a></p>
<h3 id="h_8239514313281541320813075">2. Cancel a pending command</h3>
<p>Cancels the specified command. Only pending commands can be canceled.</p>
<h5>Base Command</h5>
<p><code>cb-command-cancel</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID of command to cancel</td>
<td>Required</td>
</tr>
<tr>
<td>command</td>
<td>Command ID to cancel</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p> </p>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Path</strong></td>
<td><strong>Description</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>The command status.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Hostname</td>
<td>The hostname of the host running the command.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CbSensorID</td>
<td>The sensor ID.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CbSessionID</td>
<td>The session ID.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>The command ID.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td> Object argument for the CbLive command.For example, for <em>directory list</em> this is the <code>dir</code> path.<a href="https://github.com/carbonblack/cbapi/tree/master/sensor_apis#command-objects">Click here</a> for more information about the command objects. </td>
</tr>
<tr>
<td style="width: 381px;">CbLiveResponse.Commands.CreateTime</td>
<td style="width: 585px;">The command's time of creation.</td>
</tr>
<tr>
<td style="width: 381px;">CbLiveResponse.Commands.CommandCompletionTime</td>
<td style="width: 585px;">
<p>When the command was completed. (<em>0</em> means the command is still in progress.)</p>
</td>
</tr>
<tr>
<td style="width: 381px;">CbLiveResponse.Commands.Result.Desc</td>
<td style="width: 585px;">Result description.</td>
</tr>
<tr>
<td style="width: 381px;">CbLiveResponse.Commands.esult.Type</td>
<td style="width: 585px;">Result type.</td>
</tr>
<tr>
<td style="width: 381px;">CbLiveResponse.Commands.Result.Code</td>
<td style="width: 585px;">Result code.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-command-cancel command=1 session=348</pre>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h5> </h5>
<h3 id="h_7266081226381541320863194">3. Display information for a command</h3>
<hr>
<p>Displays the information of the specified command.</p>
<h5>Base Command</h5>
<p><code>cb-command-info</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td>Parameter</td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID of the command</td>
<td>Required</td>
</tr>
<tr>
<td>command</td>
<td>Command ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cb-command-info command=1 session=348</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 1,
            "CbSensorID": 17,
            "CbSessionID": 348,
            "CommandCompletionTime": 1540228071.195328,
            "CommandName": "process list",
            "CreateTime": 1540228071.098885,
            "OperandObject": null,
            "Process": [
                {
                    "CommandLine": "",
                    "CreateTime": 1535357799,
                    "Parent": 0,
                    "ParentGuid": "00000011-0000-0000-0000-000000000000",
                    "Path": "c:\\windows\\system32\\ntoskrnl.exe",
                    "ProcessGuid": "00000011-0000-0004-01d4-3dde478174d0",
                    "ProcessID": 4,
                    "SecurityIdentifier": "s-1-5-18",
                    "Username": "NT AUTHORITY\\SYSTEM"
                }
            ],
            "Result.Code": 0,
            "Result.Desc": "",
            "Result.Type": "WinHresult",
            "Status": "complete"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - List Processes: Command Status</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Cb Command ID</th>
<th>Command Name</th>
<th>Status</th>
<th>Create Time</th>
<th>Command Completion Time</th>
<th>Operand Object</th>
<th>Result Desc</th>
<th>Result Type</th>
<th>Result Code</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>348</td>
<td>1</td>
<td>process list</td>
<td>complete</td>
<td>1540228071.098885</td>
<td>1540228071.195328</td>
<td> </td>
<td> </td>
<td>WinHresult</td>
<td>0</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>CB Response - Processes</h3>
<table border="2">
<thead>
<tr>
<th>Process ID</th>
<th>Create Time</th>
<th>Process Guid</th>
<th>Path</th>
<th>Command Line</th>
<th>Security Identifier</th>
<th>Username</th>
<th>Parent</th>
<th>Parent Guid</th>
</tr>
</thead>
<tbody>
<tr>
<td>4</td>
<td>1535357799</td>
<td>00000011-0000-0004-01d4-3dde478174d0</td>
<td>c:\windows\system32\ntoskrnl.exe</td>
<td> </td>
<td>s-1-5-18</td>
<td>NT AUTHORITY\SYSTEM</td>
<td>0</td>
<td>00000011-0000-0000-0000-000000000000</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_86986130412521541321056425">4. Delete a file</h3>
<hr>
<p>Deletes the specified file from the Carbon Black server.</p>
<h5>Base Command</h5>
<p><code>cb-file-delete</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID</td>
<td>Required</td>
</tr>
<tr>
<td>file-id</td>
<td>File ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Files.Filename</td>
<td>The file name.</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Size</td>
<td>The file size.</td>
</tr>
<tr>
<td>CbLiveResponse.Files.CbFileID</td>
<td>
<p>The ID of the file within the Cb Session Storage.</p>
<p> - use with <code>cb-file-get</code></p>
</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Status</td>
<td>File status (<em>0</em> means there is no error).</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Delete</td>
<td>Whether the file was deleted (Boolean).</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output </h5>
<h3 id="h_84104270518651541321162601">5. Download a file</h3>
<hr>
<p>Downloads the specified file from the specified session from the Carbon Black server.</p>
<p>Before executing this command, push the file to the Carbon Black endpoint. use command 7-hyperlink, and the <em>name=get-file</em> argument to do this.</p>
<p>Use cb-command-create with name=get-file to push the file from a path on the endpoint to the Carbon Black server before executing cb-file-get.</p>
<h5>Base Command</h5>
<p><code>cb-file-get</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID</td>
<td>Required</td>
</tr>
<tr>
<td>file-id</td>
<td>File ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h5> </h5>
<h3 id="h_98933204721751541321179584">6. Get a file's metadata</h3>
<hr>
<p>Returns information about the specified file in a specified session.</p>
<h5>Base Command</h5>
<p><code>cb-file-info</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID</td>
<td>Required</td>
</tr>
<tr>
<td>file-id</td>
<td>File ID</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Files.Filename</td>
<td>The file name.</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Size</td>
<td>The file size.</td>
</tr>
<tr>
<td>CbLiveResponse.Files.CbFileID</td>
<td>
<p>The ID of the file within the Carbon Black Session Storage</p>
<p>use with cb-file-get.</p>
</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Status</td>
<td>File status (<em>0</em> means there is no error).</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Delete</td>
<td>Whether the file was deleted (Boolean).</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_66243703230841541321201349">7. Upload a file to the Carbon Black server</h3>
<hr>
<p>Uploads the specified file to the Carbon Black server.</p>
<p>Use cb-command-create with name=put-file to push the file from Cb server to a path on the endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-file-upload</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The ID of the session to upload the attachment file through</td>
<td>Required</td>
</tr>
<tr>
<td>file-id</td>
<td>The entry ID of the attachment file to upload.</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Files.Filename</td>
<td>The File name</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Size</td>
<td>The file size</td>
</tr>
<tr>
<td>CbLiveResponse.Files.CbFileID</td>
<td>
<p>The ID of the file within the Carbon Defence Session Storage -</p>
<p>use with cb-file-get.</p>
</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Status</td>
<td>File status (<em>0</em> means there is no error).</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Delete</td>
<td>Whether the file was deleted (Boolean).</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_44260355833921541321220783">8. Keep a session alive</h3>
<hr>
<p>Keeps the specified session alive so that it does not close due to timeout.</p>
<h5>Base Command</h5>
<p><code>cb-keepalive</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The ID of the session to keep alive</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_36578877936981541321283778">9. List existing command instances in a specified session</h3>
<hr>
<p>Returns a list of the existing command instances and their details for the specified session.</p>
<h5>Base Command</h5>
<p><code>cb-list-commands</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cb-list-commands session="3951"</pre>
<h5>Context Example</h5>
<pre>{
  "Commands": [
    {
      "CbCommandID": 1,
      "CbSensorID": 13,
      "CbSessionID": 3951,
      "CommandCompletionTime": 1533449964.328933,
      "CommandName": "process list",
      "CreateTime": 1533449963.906452,
      "OperandObject": null,
      "Result": {
        "Code": 0,
        "Desc": "",
        "Type": "WinHresult"
      },
      "Status": "complete"
    },
    {
      "CbCommandID": 2,
      "CbSensorID": 13,
      "CbSessionID": 3951,
      "CommandCompletionTime": 1533450217.730081,
      "CommandName": "process list",
      "CreateTime": 1533450217.214258,
      "OperandObject": null,
      "Result": {
        "Code": 0,
        "Desc": "",
        "Type": "WinHresult"
      },
      "Status": "complete"
    },
    {
      "CbCommandID": 3,
      "CbSensorID": 13,
      "CbSessionID": 3951,
      "CommandCompletionTime": 1533450219.874692,
      "CommandName": "directory list",
      "CreateTime": 1533450219.635134,
      "OperandObject": "C:\\Windows\\CarbonBlack",
      "Result": {
        "Code": 0,
        "Desc": "",
        "Type": "WinHresult"
      },
      "Status": "complete"
    },
    {
      "CbCommandID": 4,
      "CbSensorID": 13,
      "CbSessionID": 3951,
      "CommandCompletionTime": 1533450220.312491,
      "CommandName": "directory list",
      "CreateTime": 1533450220.067548,
      "OperandObject": "C:\\Windows\\CarbonBlack\\*",
      "Result": {
        "Code": 0,
        "Desc": "",
        "Type": "WinHresult"
      },
      "Status": "complete"
    },
    {
      "CbCommandID": 5,
      "CbSensorID": 13,
      "CbSessionID": 3951,
      "CommandCompletionTime": 1533450225.146843,
      "CommandName": "directory list",
      "CreateTime": 1533450224.903408,
      "OperandObject": "C:\\Windows",
      "Result": {
        "Code": 0,
        "Desc": "",
        "Type": "WinHresult"
      },
      "Status": "complete"
    }
  ]
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/28726415/43703931-e78b6146-9966-11e8-8ff1-aefad37df01d.png" target="_blank" rel="noopener"><img src="https://user-images.githubusercontent.com/28726415/43703931-e78b6146-9966-11e8-8ff1-aefad37df01d.png" alt="image"></a></p>
<h3 id="h_23514693443001541331956718">10. List files</h3>
<hr>
<p>Lists files in the given session</p>
<h5>Base Command</h5>
<p><code>cb-list-files</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Files.Filename</td>
<td>The file name</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Size</td>
<td>The file size</td>
</tr>
<tr>
<td>CbLiveResponse.Files.CbFileID</td>
<td>
<p>The ID of the file within the Carbon Black Session Storage -</p>
<p>use with cb-file-get.</p>
</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Status</td>
<td>File status (<em>0</em> means there is no error)</td>
</tr>
<tr>
<td>CbLiveResponse.Files.Delete</td>
<td>Whether the file was deleted (Boolean)</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-list-files session=3951</pre>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h5> </h5>
<h3 id="h_32320574151981541332064168">11. List Carbon Black sessions</h3>
<hr>
<p>Returns a list of the Carbon Black sessions.</p>
<h5>Base Command</h5>
<p><code>cb-list-sessions</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>sensor</td>
<td>Sensor ID to filter sessions by.</td>
<td>Optional</td>
</tr>
<tr>
<td>status</td>
<td>
<p>Status to filter by. Valid values are:</p>
<ul>
<li>active</li>
<li>pending</li>
<li>timeout</li>
<li>inactive</li>
<li>close</li>
</ul>
</td>
<td style="width: 130px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Sessions.CbSensorID</td>
<td>Sensor ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSessionID</td>
<td>Session ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.Hostname</td>
<td>Hostname</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.Status</td>
<td>Session status</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.WaitTimeout</td>
<td>Sensor wait timeout</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.SessionTimeout</td>
<td>Session Timeout</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-list-sessions status=timeout</pre>
<h5>Context Example</h5>
<pre>{
  "Sessions": {
    "CbSensorID": 13,
    "CbSessionID": 3951,
    "Hostname": "WIN1",
    "SessionTimeout": 300,
    "Status": "timeout",
    "SupportedCommands": [
      "delete file",
      "put file",
      "reg delete key",
      "directory list",
      "reg create key",
      "get file",
      "reg enum key",
      "reg query value",
      "kill",
      "create process",
      "process list",
      "reg delete value",
      "reg set value",
      "create directory",
      "memdump"
    ],
    "WaitTimeout": 120
  }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/28726415/43703073-629f8f40-9964-11e8-95ca-f1e909fdae0c.png" target="_blank" rel="noopener"><img src="https://user-images.githubusercontent.com/28726415/43703073-629f8f40-9964-11e8-95ca-f1e909fdae0c.png" alt="image" width="750" height="343"></a></p>
<h3 id="h_63487902757971541332115887">12. Close a session</h3>
<hr>
<p>Closes the specified session.</p>
<h5>Base Command</h5>
<p><code>cb-session-close</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The ID of the session to close</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Sessions.Status</td>
<td>Session status</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.Hostname</td>
<td>Hostname</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSensorID</td>
<td>Sensor ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSessionID</td>
<td>Session ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.SessionTimeout</td>
<td>Session Timeout</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.WaitTimeout</td>
<td>Sensor wait timeout</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-session-close session=3951</pre>
<h5>Context Example</h5>
<pre>{
  "CbSensorID": 13,
  "CbSessionID": 3951,
  "Hostname": "WIN1",
  "SessionTimeout": 300,
  "Status": "close",
  "SupportedCommands": [
    "delete file",
    "put file",
    "reg delete key",
    "directory list",
    "reg create key",
    "get file",
    "reg enum key",
    "reg query value",
    "kill",
    "create process",
    "process list",
    "reg delete value",
    "reg set value",
    "create directory",
    "memdump"
  ],
  "WaitTimeout": 120
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/28726415/43704204-9502339a-9967-11e8-8861-5b2b2ab7c16d.png" target="_blank" rel="noopener"><img src="https://user-images.githubusercontent.com/28726415/43704204-9502339a-9967-11e8-8861-5b2b2ab7c16d.png" alt="image" width="751" height="358"></a></p>
<h3 id="h_47996079263941541332614096">13. Create a new session</h3>
<hr>
<p>Creates a new Carbon Black session for the specified sensor.</p>
<h5>Base Command</h5>
<p><code>cb-session-create</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>sensor</td>
<td>The ID of the sensor to create a session for</td>
<td>Required</td>
</tr>
<tr>
<td>command-timeout</td>
<td>If a command is not be issued before this time, the session closes</td>
<td>Optional</td>
</tr>
<tr>
<td>keepalive-timeout</td>
<td>
<p>If a command is not issued after this specified number of seconds, the device quits.</p>
</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Sessions.Status</td>
<td>Session Status</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.Hostname</td>
<td>Hostname</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSensorID</td>
<td>Sensor ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSessionID</td>
<td>Session ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.SessionTimeout</td>
<td>Session Timeout</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.WaitTimeout</td>
<td>Sensor wait timeout</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-session-create sensor=13</pre>
<h5>Context Example</h5>
<pre>{
"CbSensorID": 13,
"CbSessionID": 3996,
"Hostname": "WIN1",
"SessionTimeout": 300,
"Status": "pending",
"SupportedCommands": [],
"WaitTimeout": 120
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/28726415/43704245-b033bd50-9967-11e8-9ba8-dab53573f7af.png" target="_blank" rel="noopener"><img src="https://user-images.githubusercontent.com/28726415/43704245-b033bd50-9967-11e8-9ba8-dab53573f7af.png" alt="image" width="750" height="324"></a></p>
<h3 id="h_19771795072861541332696812">14. Create a new session and wait</h3>
<hr>
<p>Creates a new Carbon Black session for the specified sensor and waits for it to be active.</p>
<h5>Base Command</h5>
<p><code>cb-session-create-and-wait</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>sensor</td>
<td>The ID of the sensor to create a session for</td>
<td>Required</td>
</tr>
<tr>
<td>command-timeout</td>
<td>If a command is not be issued before this time, the session closes</td>
<td>Optional</td>
</tr>
<tr>
<td>keepalive-timeout</td>
<td>
<p>If the 8 command (keepalive) -hyperlink, is not issued before this time, the session closes.</p>
</td>
<td>Optional</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>The number of seconds to wait for session to be active</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Sessions.Status</td>
<td>Session status</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.Hostname</td>
<td>Hostname</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSensorID</td>
<td>Sensor ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSessionID</td>
<td>Session ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.SessionTimeout</td>
<td>Session Timeout</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.WaitTimeout</td>
<td>Sensor wait timeout</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-session-create-and-wait sensor=17</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Sessions": {
            "CbSensorID": 17,
            "CbSessionID": 334,
            "Hostname": "WIN-B73RGE9AAIF",
            "SessionTimeout": 300,
            "Status": "active",
            "SupportedCommands": [
                "delete file",
                "put file",
                "reg delete key",
                "directory list",
                "reg create key",
                "get file",
                "reg enum key",
                "reg query value",
                "kill",
                "create process",
                "process list",
                "reg delete value",
                "reg set value",
                "create directory",
                "memdump"
            ],
            "WaitTimeout": 120
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - Create Session And Wait</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Hostname</th>
<th>Status</th>
<th>Wait Timeout</th>
<th>Session Timeout</th>
<th>Supported Commands</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>334</td>
<td>WIN-B73RGE9AAIF</td>
<td>active</td>
<td>120</td>
<td>300</td>
<td>delete file,put file,reg delete key,directory list,reg create key,get file,reg enum key,reg query value,kill,create process,process list,reg delete value,reg set value,create directory,memdump</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_88417855675911541332795275">15. Get information about a session</h3>
<hr>
<p>Displays information about the specified session.</p>
<h5>Base Command</h5>
<p><code>cb-session-info</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The ID of the session ID to get information about</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Sessions.Status</td>
<td>Session status</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.Hostname</td>
<td>Hostname</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSensorID</td>
<td>Sensor ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.CbSessionID</td>
<td>Session ID</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.SessionTimeout</td>
<td>Session Timeout</td>
</tr>
<tr>
<td>CbLiveResponse.Sessions.WaitTimeout</td>
<td>Sensor wait timeout</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-session-info session=3997</pre>
<h5>Context Example</h5>
<pre>{
"CbSensorID": 13,
"CbSessionID": 3997,
"Hostname": "WIN1",
"SessionTimeout": 300,
"Status": "active",
"SupportedCommands": [
"delete file",
"put file",
"reg delete key",
"directory list",
"reg create key",
"get file",
"reg enum key",
"reg query value",
"kill",
"create process",
"process list",
"reg delete value",
"reg set value",
"create directory",
"memdump"
],
"WaitTimeout": 120
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/28726415/43704732-4b5aa8f6-9969-11e8-8f45-e76e3bef8ca0.png" target="_blank" rel="noopener"><img src="https://user-images.githubusercontent.com/28726415/43704732-4b5aa8f6-9969-11e8-8f45-e76e3bef8ca0.png" alt="image" width="751" height="367"></a></p>
<h3 id="h_8091131581881541333003941">16. Terminate a process</h3>
<hr>
<p>Terminates the specified process on the sensor or endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-process-kill</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID</td>
<td>Optional</td>
</tr>
<tr>
<td>pid</td>
<td>The PID of the process to terminate</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from <em>pending</em> to <em>in progress&lt;/em/<em>complete</em>)</em>
</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>If the command is still pending after this time, the command is cancelled</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The time the command was completed (<em>0</em> if not completed)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The process ID</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-process-kill pid=972 sensor=17</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 1,
            "CbSensorID": 17,
            "CbSessionID": 328,
            "CommandCompletionTime": 1540219865.188614,
            "CommandName": "kill",
            "CreateTime": 1540219865.160948,
            "OperandObject": "972",
            "Result": {
                "Code": 0,
                "Desc": "",
                "Type": "WinHresult"
            },
            "Status": "complete"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - Kill Process 972: Command Status</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Cb Command ID</th>
<th>Command Name</th>
<th>Status</th>
<th>Create Time</th>
<th>Command Completion Time</th>
<th>Operand Object</th>
<th>Result Desc</th>
<th>Result Type</th>
<th>Result Code</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>328</td>
<td>1</td>
<td>kill</td>
<td>complete</td>
<td>1540219865.160948</td>
<td>1540219865.188614</td>
<td>972</td>
<td> </td>
<td>WinHresult</td>
<td>0</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_85680905287911541333134540">17. List directories</h3>
<hr>
<p>Returns a list of directories on the endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-directory-listing</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>Path for the directory (e.g. "c:\Users\"). Note to end with double backslash.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.DirectoryList.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The time the command was completed (<em>0</em> if not complete)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>the directory listing filter (or path)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Files.FileAttributes</td>
<td>A list of file attributes</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Files.CreateTime</td>
<td>Create time in Unix time format</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Files.LastAccessTime</td>
<td>Last access time in Unix time format.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Files.LastWriteTime</td>
<td>Last write time in Unix time format.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Files.FileSize</td>
<td>The file size.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Files.FileName</td>
<td>The file name.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-directory-listing path="c:\Users\All Users\Desktop\" sensor=17</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 1,
            "CbSensorID": 17,
            "CbSessionID": 332,
            "CommandCompletionTime": 1540220585.720132,
            "CommandName": "directory list",
            "CreateTime": 1540220585.692945,
            "Files": [
                {
                    "AlternativeName": null,
                    "CreateTime": 1377185970,
                    "FileAttributes": [
                        "READONLY",
                        "HIDDEN",
                        "DIRECTORY"
                    ],
                    "FileName": ".",
                    "FileSize": 0,
                    "LastAccessTime": 1534297982,
                    "LastWriteTime": 1534297982
                },
                {
                    "AlternativeName": null,
                    "CreateTime": 1377185970,
                    "FileAttributes": [
                        "READONLY",
                        "HIDDEN",
                        "DIRECTORY"
                    ],
                    "FileName": "..",
                    "FileSize": 0,
                    "LastAccessTime": 1534297982,
                    "LastWriteTime": 1534297982
                },
                {
                    "AlternativeName": null,
                    "CreateTime": 1377185972,
                    "FileAttributes": [
                        "HIDDEN",
                        "SYSTEM",
                        "ARCHIVE"
                    ],
                    "FileName": "desktop.ini",
                    "FileSize": 174,
                    "LastAccessTime": 1377185877,
                    "LastWriteTime": 1377185877
                },
                {
                    "AlternativeName": "GOOGLE~1.LNK",
                    "CreateTime": 1509481395,
                    "FileAttributes": [
                        "ARCHIVE"
                    ],
                    "FileName": "Google Chrome.lnk",
                    "FileSize": 2163,
                    "LastAccessTime": 1509481395,
                    "LastWriteTime": 1533760799
                }
            ],
            "OperandObject": "c:\\Users\\All Users\\Desktop\\",
            "Result": {
                "Code": 0,
                "Desc": "",
                "Type": "WinHresult"
            },
            "Status": "complete"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - Directory Listing: Command Status</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Cb Command ID</th>
<th>Command Name</th>
<th>Status</th>
<th>Create Time</th>
<th>Command Completion Time</th>
<th>Operand Object</th>
<th>Result Desc</th>
<th>Result Type</th>
<th>Result Code</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>332</td>
<td>1</td>
<td>directory list</td>
<td>complete</td>
<td>1540220585.692945</td>
<td>1540220585.720132</td>
<td>c:\Users\All Users\Desktop|</td>
<td>WinHresult</td>
<td>0</td>
<td> </td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>CB Response - Directory Listing</h3>
<table border="2">
<thead>
<tr>
<th>File Attributes</th>
<th>Create Time</th>
<th>Last Access Time</th>
<th>Last Write Time</th>
<th>File Size</th>
<th>File Name</th>
<th>Alternative Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>READONLY,HIDDEN,DIRECTORY</td>
<td>1377185970</td>
<td>1534297982</td>
<td>1534297982</td>
<td>0</td>
<td>.</td>
<td> </td>
</tr>
<tr>
<td>READONLY,HIDDEN,DIRECTORY</td>
<td>1377185970</td>
<td>1534297982</td>
<td>1534297982</td>
<td>0</td>
<td>..</td>
<td> </td>
</tr>
<tr>
<td>HIDDEN,SYSTEM,ARCHIVE</td>
<td>1377185972</td>
<td>1377185877</td>
<td>1377185877</td>
<td>174</td>
<td>desktop.ini</td>
<td> </td>
</tr>
<tr>
<td>ARCHIVE</td>
<td>1509481395</td>
<td>1509481395</td>
<td>1533760799</td>
<td>2163</td>
<td>Google Chrome.lnk</td>
<td>GOOGLE~1.LNK</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_547321474108831541333344651">18. Run an executable on an endpoint</h3>
<hr>
<p>Runs the executable on an endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-process-execute</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>the path and command line of the executable</td>
<td>Required</td>
</tr>
<tr>
<td>wait</td>
<td>An optional parameter to specify whether to wait for the process to complete execution before reporting the result.</td>
<td>Optional</td>
</tr>
<tr>
<td>working-directory</td>
<td>An optional parameter to specify the working directory of the executable.</td>
<td>Optional</td>
</tr>
<tr>
<td>output-file</td>
<td>An option file that STDERR and STDOUT will be redirected to.</td>
<td>Optional</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command Status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The path and command line of the executable</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.ReturnCode</td>
<td>The return code of the process (if wait was set to <em>true</em>)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.ProcessID</td>
<td>The PID of the executed process</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_894139734117801541333380560">19. Endpoint memory dump</h3>
<hr>
<p>Endpoint memory dump.</p>
<h5>Base Command</h5>
<p><code>cb-memdump</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>the path to save the resulting memory dump (on the endpoint).</td>
<td>Required</td>
</tr>
<tr>
<td>compress</td>
<td>An optional parameter to specify whether to compress resulting memory dump.</td>
<td>Optional</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command Status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (0 if not complete)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The path to save the resulting memory dump (on the endpoint)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.ReturnCode</td>
<td>Return code of the memory dump process</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CompressingEnabled</td>
<td>Boolean flag indicating if compression is enabled.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Complete</td>
<td>Boolean flag indicating if memory dump is completed.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.PercentDone</td>
<td>Percent of the process completed</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.DumpingInProgress</td>
<td>Boolean flag indicating if memory dump is in progress.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-memdump path="c:\Users\All Users\Desktop" sensor=17</pre>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_696629611123791541333655660">20. Create a live response command</h3>
<hr>
<p>Creates a Carbon Black Live Response command.</p>
<h5>Base Command</h5>
<p><code>cb-command-create</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>name</td>
<td>Command name</td>
<td>Required</td>
</tr>
<tr>
<td>timeout</td>
<td>Command timeout</td>
<td>Optional</td>
</tr>
<tr>
<td>object</td>
<td>the object the command operates on. This is specific to the command but has meaning in a generic way for logging, and display purposes</td>
<td>Optional</td>
</tr>
<tr>
<td>compress</td>
<td>"true" or "false" - an optional parameter to specify whether to compress resulting memory dump</td>
<td>Optional</td>
</tr>
<tr>
<td>working-dir</td>
<td>An optional parameter to specify the working directory of the executable</td>
<td>Optional</td>
</tr>
<tr>
<td>output-file</td>
<td>An option file that STDERR and STDOUT will be redirected to.</td>
<td>Optional</td>
</tr>
<tr>
<td>value-data</td>
<td>the data associated with the registry value</td>
<td>Optional</td>
</tr>
<tr>
<td>value-type</td>
<td>the string representation of the registry value type (ie REG_DWORD, REG_QWORD, ….)</td>
<td>Optional</td>
</tr>
<tr>
<td>overwrite</td>
<td>“true” or “false”. An optional parameter to specify whether to overwrite the value if it already exists (default value is “false”)</td>
<td>Optional</td>
</tr>
<tr>
<td>offset</td>
<td>a byte offset to start getting the file. Supports a partial get.</td>
<td>Optional</td>
</tr>
<tr>
<td>get-count</td>
<td>the number of bytes to grab</td>
<td>Optional</td>
</tr>
<tr>
<td>session</td>
<td>Session ID to create command for</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.Status</td>
<td>The Command Status</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Hostname</td>
<td>The hostname running the command</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CbLiveResponse.Commands.CbSensorID</td>
<td>The Sensor ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The Command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CbSessionID</td>
<td>The Session ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>The Command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>Object argument for the CbLive command - e.g. for 'directory list' this is the path of the dir to list. For more information, see the <a href="https://github.com/carbonblack/cbapi/tree/master/sensor_apis#command-objects" target="_blank" rel="noopener">Carbon Black documentation</a>.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CreateTime</td>
<td>Command create time</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The time the command completed or 0 if still in progres.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Result.Desc</td>
<td>Result description</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Result.Type</td>
<td>Result type</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Result.Code</td>
<td>Result code</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-command-create session=337 name="process-list"</pre>
<pre>!cb-command-create session=337 name="directory-list" object="c:\Users\" <strong>(path)</strong></pre>
<pre>!cb-command-create session=337 name=kill object=1 <strong>(pid)</strong></pre>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_688812215129761541333716647">21. Create a Live Response command and wait</h3>
<hr>
<p>Creates a Live Response command and waits for it to finish executing.</p>
<h5>Base Command</h5>
<p><code>cb-command-create-and-wait</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>name</td>
<td>Command name</td>
<td>Required</td>
</tr>
<tr>
<td>timeout</td>
<td>Command timeout</td>
<td>Optional</td>
</tr>
<tr>
<td>object</td>
<td>the object the command operates on. This is specific to the command but has meaning in a generic way for logging, and display purposes</td>
<td>Optional</td>
</tr>
<tr>
<td>compress</td>
<td>"true" or "false" - an optional parameter to specify whether to compress resulting memory dump</td>
<td>Optional</td>
</tr>
<tr>
<td>working-dir</td>
<td>An optional parameter to specify the working directory of the executable</td>
<td>Optional</td>
</tr>
<tr>
<td>output-file</td>
<td>An option file that STDERR and STDOUT will be redirected to.</td>
<td>Optional</td>
</tr>
<tr>
<td>value-data</td>
<td>the data associated with the registry value</td>
<td>Optional</td>
</tr>
<tr>
<td>value-type</td>
<td>the string representation of the registry value type (ie REG_DWORD, REG_QWORD, ….)</td>
<td>Optional</td>
</tr>
<tr>
<td>overwrite</td>
<td>“true” or “false”. An optional parameter to specify whether to overwrite the value if it already exists (default value is “false”)</td>
<td>Optional</td>
</tr>
<tr>
<td>offset</td>
<td>a byte offset to start getting the file. Supports a partial get.</td>
<td>Optional</td>
</tr>
<tr>
<td>get-count</td>
<td>the number of bytes to grab</td>
<td>Optional</td>
</tr>
<tr>
<td>session</td>
<td>Session ID to create command for</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait in seconds to wait for command to finish executing</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!cb-command-create-and-wait session=337 name="process-list"</pre>
<pre>!cb-command-create-and-wait session=337 name="directory-list" object="c:\Users\" <strong>(path)</strong></pre>
<pre>!cb-command-create-and-wait session=337 name=kill object=1 <strong>(pid)</strong></pre>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_358153233135701541333863539">22. Terminate a process</h3>
<hr>
<p>Terminates the specified process at the sensor endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-terminate-process</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>Session ID</td>
<td>Required</td>
</tr>
<tr>
<td>pid</td>
<td>The PID of the process to terminate</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait in seconds for process to complete termination</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_757732769141641541333979374">23. Delete a file from an endpoint</h3>
<hr>
<p>Deletes the specified file from an endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-file-delete-from-endpoint</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The source path of the object to delete.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The source path of the object to delete</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-file-delete-from-endpoint sensor="17" path="c:\Users\All Users\Desktop\mooncake.jpg" wait-timeout="20"</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 1,
            "CbSensorID": 17,
            "CbSessionID": 339,
            "CommandCompletionTime": 1540224791.225669,
            "CommandName": "delete file",
            "CreateTime": 1540224791.197925,
            "OperandObject": "c:\\Users\\All Users\\Desktop\\mooncake.jpg",
            "Result": {
                "Code": 2147942402,
                "Desc": "",
                "Type": "WinHresult"
            },
            "Status": "error"
        }
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - Delete File From Endpoint: Command Status</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Cb Command ID</th>
<th>Command Name</th>
<th>Status</th>
<th>Create Time</th>
<th>Command Completion Time</th>
<th>Operand Object</th>
<th>Result Desc</th>
<th>Result Type</th>
<th>Result Code</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>339</td>
<td>1</td>
<td>delete file</td>
<td>error</td>
<td>1540224791.197925</td>
<td>1540224791.225669</td>
<td>c:\Users\All Users\Desktop\mooncake.jpg</td>
<td> </td>
<td>WinHresult</td>
<td>2147942402</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_275333432150541541334039951">24. Enumerate registry values</h3>
<hr>
<p>Enumerates the registry values.</p>
<h5>Base Command</h5>
<p><code>cb-registry-get-values</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The path of the key to query</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The path of the key to queried</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Values.RegKeyType</td>
<td>Registry value type</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Values.RegKeyName</td>
<td>The name of the registry value</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Values.RegKeyData</td>
<td>The data associated with the registry value</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.SubKeys</td>
<td>List of subkey names</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_987425608159391541334112772">25. Query for a registry value</h3>
<hr>
<p>Query for registry value.</p>
<h5>Base Command</h5>
<p><code>cb-registry-query-value</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The path of the key + the path of the value (e.g. HKEY_LOCAL_MACHINE\blah\key\value).</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command identifier.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>The command Status ('pending', 'in progress', 'complete', 'error', 'canceled').</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (0 if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>the path of the key + the path of the value (ie HKEY_LOCAL_MACHINE\blah\key\value).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Registry.QueryValue.Values.RegKeyType</td>
<td>Registry value type.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.RegKeyName</td>
<td>the name of the registry value.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.RegKeyData</td>
<td>The data associated with the registry value.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.SubKeys</td>
<td>List of subkey names.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_967989363162391541334169756">26. Create a new registry key</h3>
<hr>
<p>Creates a new registry key.</p>
<h5>Base Command</h5>
<p><code>cb-registry-create-key</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The key path to create.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The key path</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_485208221168281541334199010">27. Delete a registry key</h3>
<hr>
<p>Deletes the specified registry key.</p>
<h5>Base Command</h5>
<p><code>cb-registry-delete-key</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The key path to delete.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>the key path</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_280293840174151541334261891">28. Delete a registry value</h3>
<hr>
<p>Delete registry value.</p>
<h5>Base Command</h5>
<p><code>cb-registry-delete-value</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The path of the key + the path of the value.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The key path</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_924942710182881541334303802">29. Set a registry value</h3>
<hr>
<p>Sets a registry value.</p>
<h5>Base Command</h5>
<p><code>cb-registry-set-value</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The path of the key + the path of the value.</td>
<td>Required</td>
</tr>
<tr>
<td>data</td>
<td>The data to set for the value. Note if the value type ‘REG_MULTI_SZ’ then multiple values should be separated by a comma (e.g. value1, value2, value3).</td>
<td>Required</td>
</tr>
<tr>
<td>type</td>
<td>One of common registry value types (REG_DWORD, REG_QWORD, REG_SZ etc).</td>
<td>Required</td>
</tr>
<tr>
<td>overwrite</td>
<td>An optional parameter to specify whether to overwrite the value if it already exists (default value is ’no’).</td>
<td>Optional</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command ID</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>
<p>The command status</p>
<ul>
<li>pending</li>
<li>in progress</li>
<li>complete</li>
<li>error</li>
<li>canceled</li>
</ul>
</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (<em>0</em> if not complete)</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The key path</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<h3 id="h_725204070188751541334456592">30. Get a list processes running on an endpoint</h3>
<hr>
<p>Returns a list of processes running on the endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-process-list</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>cancel-on-timeout</td>
<td>Cancel the command if still 'pending' after timeout.</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command identifier.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>The command Status ('pending', 'in progress', 'complete', 'error', 'canceled').</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (0 if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.ProcessID</td>
<td>Process ID.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.CreateTime</td>
<td>The creation time of the process in Unix time.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.ProcessGuid</td>
<td>The process guid of the process.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.Path</td>
<td>The execution path of the process.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.SecurityIdentifier</td>
<td>The Security Identifier (SID) of the default process token.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.Username</td>
<td>The username of the default process token.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.Parent</td>
<td>The pid (process id ) of the parent.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Processes.ParentGuid</td>
<td>The process guid of the parent process.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-process-list sensor=1</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 1,
            "CbSensorID": 17,
            "CbSessionID": 327,
            "CommandCompletionTime": 1540219086.030599,
            "CommandName": "process list",
            "CreateTime": 1540219085.939409,
            "OperandObject": null,
            "Process": [
                {
                    "CommandLine": "",
                    "CreateTime": 1535357799,
                    "Parent": 0,
                    "ParentGuid": "00000011-0000-0000-0000-000000000000",
                    "Path": "c:\\windows\\system32\\ntoskrnl.exe",
                    "ProcessGuid": "00000011-0000-0004-01d4-3dde478174d0",
                    "ProcessID": 4,
                    "SecurityIdentifier": "s-1-5-18",
                    "Username": "NT AUTHORITY\\SYSTEM"
                },
                {
                    "CommandLine": "\\SystemRoot\\System32\\smss.exe",
                    "CreateTime": 1535357799,
                    "Parent": 4,
                    "ParentGuid": "00000011-0000-0004-01d4-3dde478174d0",
                    "Path": "c:\\windows\\system32\\smss.exe",
                    "ProcessGuid": "00000011-0000-0188-01d4-3dde4783d56b",
                    "ProcessID": 392,
                    "SecurityIdentifier": "s-1-5-18",
                    "Username": "NT AUTHORITY\\SYSTEM"
                }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - List Processes: Command Status</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Cb Command ID</th>
<th>Command Name</th>
<th>Status</th>
<th>Create Time</th>
<th>Command Completion Time</th>
<th>Operand Object</th>
<th>Result Desc</th>
<th>Result Type</th>
<th>Result Code</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>327</td>
<td>1</td>
<td>process list</td>
<td>complete</td>
<td>1540219085.939409</td>
<td>1540219086.030599</td>
<td> </td>
<td> </td>
<td>WinHresult</td>
<td>0</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>CB Response - Processes</h3>
<table border="2">
<thead>
<tr>
<th>Process ID</th>
<th>Create Time</th>
<th>Process Guid</th>
<th>Path</th>
<th>Command Line</th>
<th>Security Identifier</th>
<th>Username</th>
<th>Parent</th>
<th>Parent Guid</th>
</tr>
</thead>
<tbody>
<tr>
<td>4</td>
<td>1535357799</td>
<td>00000011-0000-0004-01d4-3dde478174d0</td>
<td>c:\windows\system32\ntoskrnl.exe</td>
<td> </td>
<td>s-1-5-18</td>
<td>NT AUTHORITY\SYSTEM</td>
<td>0</td>
<td>00000011-0000-0000-0000-000000000000</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_990945715194681541334532882">31. Get a file from an endpoint</h3>
<hr>
<p>Retrieves a file from a path on the endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-get-file-from-endpoint</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The source path of the file.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command identifier.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>The command Status ('pending', 'in progress', 'complete', 'error', 'canceled').</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (0 if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The source path of the file.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.FileID</td>
<td>Unique file ID.</td>
</tr>
<tr>
<td>CbLiveResponse.File.Size</td>
<td>File size.</td>
</tr>
<tr>
<td>CbLiveResponse.File.SHA1</td>
<td>File SHA1.</td>
</tr>
<tr>
<td>CbLiveResponse.File.SHA256</td>
<td>File SHA256.</td>
</tr>
<tr>
<td>CbLiveResponse.File.Name</td>
<td>File name.</td>
</tr>
<tr>
<td>CbLiveResponse.File.SSDeep</td>
<td>File SSDeep.</td>
</tr>
<tr>
<td>CbLiveResponse.File.EntryID</td>
<td>File EntryID.</td>
</tr>
<tr>
<td>CbLiveResponse.File.Info</td>
<td>File info.</td>
</tr>
<tr>
<td>CbLiveResponse.File.Type</td>
<td>File type.</td>
</tr>
<tr>
<td>CbLiveResponse.File.MD5</td>
<td>File MD5 hash</td>
</tr>
<tr>
<td>CbLiveResponse.File.Extension</td>
<td>File extension.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cb-get-file-from-endpoint path="c:\Users\All Users\Desktop\mooncake.jpg" sensor=17</pre>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 2,
            "CbSensorID": 17,
            "CbSessionID": 356,
            "CommandCompletionTime": 1540229207.655335,
            "CommandName": "get file",
            "CreateTime": 1540229207.608662,
            "FileID": 1,
            "OperandObject": "c:\\Users\\All Users\\Desktop\\mooncake.jpg",
            "Result": {
                "Code": 0,
                "Desc": "",
                "Type": "WinHresult"
            },
            "Status": "complete"
        }
    },
    "File": {
        "EntryID": "168@583490",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "1fe52b291d16c7f9a6eaf43074024011",
        "Name": "mooncake.jpg",
        "SHA1": "30bd2461d6cee80227bcf557a6fd47922b96263c",
        "SHA256": "a87b0fa1006b301b7ef2259cfa9aed2ff12c15217796b5dd08b36e006a137cd2",
        "SSDeep": "192:pAzQbZ/ujghzcZHcsWw6o6E7ODeADcBwjZ4P:pAzG/ujgh6xCo60ODe3wj8",
        "Size": 11293,
        "Type": "data\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/31587493/47308009-1e9ebe80-d639-11e8-840a-558301dd6c1d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/31587493/47308009-1e9ebe80-d639-11e8-840a-558301dd6c1d.png" alt="screen shot 2018-10-22 at 20 27 52" width="749" height="421"></a></p>
<h3 id="h_229737590200581541334677178">32. Save a file to an endpoint</h3>
<hr>
<p>Saves a file to a specific path on an endpoint.</p>
<h5>Base Command</h5>
<p><code>cb-push-file-to-endpoint</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<td><strong>Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
</thead>
<tbody>
<tr>
<td>session</td>
<td>The session ID.</td>
<td>Optional</td>
</tr>
<tr>
<td>sensor</td>
<td>The sensor ID. Provided the sensor ID to run the command with a new session. The session will be created and closed automatically.</td>
<td>Optional</td>
</tr>
<tr>
<td>entry-id</td>
<td>The file entry ID.</td>
<td>Required</td>
</tr>
<tr>
<td>wait-timeout</td>
<td>Time to wait (in seconds) for Cb command to be executed (change status from 'pending' to 'in-progress'/'complete').</td>
<td>Optional</td>
</tr>
<tr>
<td>path</td>
<td>The destination path of the file. Include file name and type (e.g. "c:\Users\USER\Desktop\log.txt").</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
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
<td>CbLiveResponse.Commands.CbCommandID</td>
<td>Unique command identifier.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandName</td>
<td>The command name.</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.Status</td>
<td>The command Status ('pending', 'in progress', 'complete', 'error', 'canceled').</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.CommandCompletionTime</td>
<td>The command completion time (0 if not complete).</td>
</tr>
<tr>
<td>CbLiveResponse.Commands.OperandObject</td>
<td>The destination path of the file.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p>!cb-push-file-to-endpoint entry-id=84@583490 path="c:\Users\All Users\Desktop" sensor=17</p>
<h5>Context Example</h5>
<pre>{
    "CbLiveResponse": {
        "Commands": {
            "CbCommandID": 1,
            "CbSensorID": 17,
            "CbSessionID": 338,
            "CommandCompletionTime": 1540224253.942851,
            "CommandName": "put file",
            "CreateTime": 1540224253.915233,
            "OperandObject": "c:\\Users\\All Users\\Desktop",
            "Result": {
                "Code": 2147942405,
                "Desc": "",
                "Type": "WinHresult"
            },
            "Status": "error"
        },
        "Files": {
            "CbFileID": 1,
            "Delete": false,
            "Filename": "mooncake.jpg",
            "Size": 6167,
            "SizeUploaded": 6167,
            "Status": 0
        }
    },
    "File": {
        "EntryID": "84@583490",
        "Extension": "jpg",
        "Info": "image/jpeg",
        "MD5": "e42a08714529d9c78cce07a04d2e5e7c",
        "Name": "mooncake.jpg",
        "SHA1": "d5b5f31018a1d6d51ff1857d3d79cda60ae525ac",
        "SHA256": "769509b39aad9992435bf900dd9c96ac409be154eaae5c52f40393e9a9c2ffb4",
        "SSDeep": "96:dkwEkdwRnxWUfLO//UTDEuDQ/qBIG9ywAPIloeAIVvx7TM01LT9C:9z2JQLGDQkRzoeAIvlRT9C",
        "Size": 6167,
        "Type": "JPEG image data, JFIF standard 1.01\n"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>CB Response - Push File: Command Status</h3>
<table border="2">
<thead>
<tr>
<th>Cb Sensor ID</th>
<th>Cb Session ID</th>
<th>Cb Command ID</th>
<th>Command Name</th>
<th>Status</th>
<th>Create Time</th>
<th>Command Completion Time</th>
<th>Operand Object</th>
<th>Result Desc</th>
<th>Result Type</th>
<th>Result Code</th>
</tr>
</thead>
<tbody>
<tr>
<td>17</td>
<td>338</td>
<td>1</td>
<td>put file</td>
<td>error</td>
<td>1540224253.915233</td>
<td>1540224253.942851</td>
<td>c:\Users\All Users\Desktop</td>
<td> </td>
<td>WinHresult</td>
<td>2147942405</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3>CB Response - File Info</h3>
<table border="2">
<thead>
<tr>
<th>Cb File ID</th>
<th>Filename</th>
<th>Size</th>
<th>Size Uploaded</th>
<th>Status</th>
<th>Delete</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>mooncake.jpg</td>
<td>6167</td>
<td>6167</td>
<td>0</td>
<td>false</td>
</tr>
</tbody>
</table>
