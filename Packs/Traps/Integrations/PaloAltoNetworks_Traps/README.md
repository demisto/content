<!-- HTML_DOC -->
<p><span>Deprecated. Use CortexXDR instead. Use the Palo Alto Networks Traps integration to initiate scans, retrieve files from events, isolate endpoints, quarantine files, and manage the allow list and block list.</span></p>
<h2>Traps Playbooks</h2>
<ul>
<li>Traps Retrieve And Download Files</li>
<li>Traps Scan Endpoint</li>
</ul>
<h2>Get Your API Key and Application ID</h2>
<p>You will need to provide the API key and Application ID when configuring an instance of the Traps integration in Cortex XSOAR.</p>
<p><strong>NOTE</strong>: This procedure requires Super User privileges.</p>
<ol>
<li>Access your Traps TMS UI.</li>
<li>Click the settings button and select <strong>API Keys</strong>.</li>
<li>To create new API Key click the <strong>Add</strong> button.</li>
<li>Copy and save the entire text of your API key as you will not be able to access it again, and the Application ID. </li>
</ol>
<p> </p>
<h2>Configure Traps on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>  &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Traps.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li><strong>Name</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Server URL</strong></li>
<li><strong>Application ID</strong></li>
<li><strong>Private Key</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the new instance.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_48358393-53a5-43e5-9e5a-83368fe7e2a6" target="_self">Get endpoint details: traps-get-endpoint-by-id</a></li>
<li><a href="#h_7dd4af9c-4191-42ce-b8fe-801542f08a51" target="_self">Execute a file retrieve operation / SAM on an agent: traps-endpoint-files-retrieve</a></li>
<li><a href="#h_c4951f1a-5b1b-4012-8f27-373ee83cd8e0" target="_self">Scan an endpoint: traps-endpoint-scan</a></li>
<li><a href="#h_aff0ef39-1af6-4777-a375-f946e5e295f1" target="_self">Modify details for an event: traps-event-update</a></li>
<li><a href="#h_4e113a1b-d46a-4b84-8083-98b4b54626f3" target="_self">Modify details for multiple events: traps-event-bulk-update-status</a></li>
<li><a href="#h_ba1cf623-1363-40e4-b77b-6e0d96b9aaae" target="_self">Add a file hash to the block list: traps-hash-blacklist</a></li>
<li><a href="#h_3c467ab9-13ec-46d4-8d51-5d207d462c92" target="_self">Remove a file hash from the block list: traps-hash-blacklist-remove</a></li>
<li><a href="#h_10e63ba1-0e9e-4a5f-8840-a0b1dd752d0c" target="_self">Return a file hash to the block list: traps-hashes-blacklist-status</a></li>
<li><a href="#h_2b3c9090-99ed-473a-9818-9f7f28046e54" target="_self">Quarantine an event: traps-event-quarantine</a></li>
<li><a href="#h_a469746d-6210-4d13-b7cd-7e79b37fce4b" target="_self">Isolate an endpoint: traps-endpoint-isolate</a></li>
<li><a href="#h_e26af638-bd84-416d-9642-aaae647dab5a" target="_self">Get the result of a quarantine operation: traps-event-quarantine-result</a></li>
<li><a href="#h_84666544-eab3-4d4b-88cf-3e5d2f6bf281" target="_self">Get the result of an isolate operation: traps-endpoint-isolate-status</a></li>
<li><a href="#h_494733b8-f5c5-4236-84d4-a72ac01a3e6e" target="_self">Get the results of an endpoint file retrieve operation: traps-endpoint-files-retrieve-result</a></li>
<li><a href="#h_47027a19-92a6-4513-bd07-0aa1769f42ab" target="_self">Get the results of an endpoint scan operation: traps-endpoint-scan-result</a></li>
</ol>
<h3 id="h_48358393-53a5-43e5-9e5a-83368fe7e2a6">1. Get endpoint details</h3>
<hr>
<p>Returns details for the specified endpoint.</p>
<h5>Base Command</h5>
<p><code>traps-get-endpoint-by-id</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 300px;"><strong>Argument Name</strong></th>
<th style="width: 228px;"><strong>Description</strong></th>
<th style="width: 180px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">endpoint_id</td>
<td style="width: 228px;">Endpoint ID.</td>
<td style="width: 180px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 288px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 359px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 288px;">Traps.Endpoint.ID</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.Name</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The name of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.Domain</td>
<td style="width: 61px;">date</td>
<td style="width: 359px;">The domain of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.Platform</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The OS of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.Status</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The status of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.IP</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The IP address of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.ComputerSid</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The computer SID.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.IsCompromised</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">Whether the endpoint is compromised.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.OsVersion</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The version of the OS on the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.OsProductType</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The OS type of the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.OsProductName</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The name of the OS on the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.Is64</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The bitness of the OS on the endpoint.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.LastSeen</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The date/time of the last active ping.</td>
</tr>
<tr>
<td style="width: 288px;">Traps.Endpoint.LastUser</td>
<td style="width: 61px;">String</td>
<td style="width: 359px;">The last active user on the machine.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-get-endpoint-by-id endpoint_id="d3339851f18f470182bf2bf98ad5db4b"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.Endpoint": {
        "ComputerSid": "S-1-5-21-202186053-2642234773-3690463397",
        "Domain": "WORKGROUP",
        "ID": "d3339851f18f470182bf2bf98ad5db4b",
        "IP": "172.31.33.227",
        "Is64": true,
        "IsCompromised": false,
        "LastSeen": "2019-10-03T09:06:40.000Z",
        "LastUser": "Administrator",
        "Name": "EC2AMAZ-8IEUJEN",
        "OsProductName": "",
        "OsProductType": "server",
        "OsVersion": "10.0.14393",
        "Platform": "windows",
        "Status": "active"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Endpoint d3339851f18f470182bf2bf98ad5db4b data:</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Computer Sid</strong></th>
<th><strong>Domain</strong></th>
<th><strong>ID</strong></th>
<th><strong>IP</strong></th>
<th><strong>Is 64</strong></th>
<th><strong>Is Compromised</strong></th>
<th><strong>Last Seen</strong></th>
<th><strong>Last User</strong></th>
<th><strong>Name</strong></th>
<th><strong>Os Product Name</strong></th>
<th><strong>Os Product Type</strong></th>
<th><strong>Os Version</strong></th>
<th><strong>Platform</strong></th>
<th><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>S-1-5-21-202186053-2642234773-3690463397</td>
<td>WORKGROUP</td>
<td>d3339851f18f470182bf2bf98ad5db4b</td>
<td>172.31.33.227</td>
<td>true</td>
<td>false</td>
<td>2019-10-03T09:06:40.000Z</td>
<td>Administrator</td>
<td>EC2AMAZ-8IEUJEN</td>
<td> </td>
<td>server</td>
<td>10.0.14393</td>
<td>windows</td>
<td>active</td>
</tr>
</tbody>
</table>
<h3 id="h_7dd4af9c-4191-42ce-b8fe-801542f08a51">2. Execute a file retrieve operation / SAM on an agent</h3>
<hr>
<p>Executes a file retrieve operation / SAM on the specified agent.</p>
<h5>Base Command</h5>
<p><code>traps-endpoint-files-retrieve</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 440px;"><strong>Description</strong></th>
<th style="width: 96px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">endpoint_id</td>
<td style="width: 440px;">The ID of the endpoint.</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">file_name</td>
<td style="width: 440px;">The name of the file to retrieve (including path).</td>
<td style="width: 96px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">event_id</td>
<td style="width: 440px;">The ID of the event.</td>
<td style="width: 96px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 346px;"><strong>Path</strong></th>
<th style="width: 82px;"><strong>Type</strong></th>
<th style="width: 280px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 346px;">Traps.FileRetrieve.EndpointID</td>
<td style="width: 82px;">String</td>
<td style="width: 280px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 346px;">Traps.FileRetrieve.OperationID</td>
<td style="width: 82px;">String</td>
<td style="width: 280px;">The ID of the operation.</td>
</tr>
<tr>
<td style="width: 346px;">Traps.FileRetrieve.Type</td>
<td style="width: 82px;">String</td>
<td style="width: 280px;">The type of operation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-endpoint-files-retrieve endpoint_id="d3339851f18f470182bf2bf98ad5db4b" file_name="C:\\Program Files
        (x86)\\Notepad++\\notepad++.exe" event_id="1cfb8fac7b504dc9894eabb9eb33de73"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.FileRetrieve": {
        "EndpointID": "d3339851f18f470182bf2bf98ad5db4b",
        "OperationID": "3f7d6e86e5bd11e9acbf0245d8e950da",
        "Type": "files-retrieve"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Files retrieve command on endpoint: d3339851f18f470182bf2bf98ad5db4b received</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 296px;"><strong>Endpoint ID</strong></th>
<th style="width: 309px;"><strong>Operation ID</strong></th>
<th style="width: 103px;"><strong>Type</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 296px;">d3339851f18f470182bf2bf98ad5db4b</td>
<td style="width: 309px;">3f7d6e86e5bd11e9acbf0245d8e950da</td>
<td style="width: 103px;">files-retrieve</td>
</tr>
</tbody>
</table>
<h3 id="h_c4951f1a-5b1b-4012-8f27-373ee83cd8e0">3. Scan an endpoint</h3>
<hr>
<p>Performs a scan operation on the specified endpoint.</p>
<h5>Base Command</h5>
<p><code>traps-endpoint-scan</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 243px;"><strong>Argument Name</strong></th>
<th style="width: 321px;"><strong>Description</strong></th>
<th style="width: 144px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 243px;">endpoint_id</td>
<td style="width: 321px;">The ID of the endpoint.</td>
<td style="width: 144px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 309px;"><strong>Path</strong></th>
<th style="width: 85px;"><strong>Type</strong></th>
<th style="width: 314px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 309px;">Traps.Scan.EndpointID</td>
<td style="width: 85px;">String</td>
<td style="width: 314px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 309px;">Traps.Scan.OperationID</td>
<td style="width: 85px;">String</td>
<td style="width: 314px;">The ID of the operation.</td>
</tr>
<tr>
<td style="width: 309px;">Traps.Scan.Type</td>
<td style="width: 85px;">String</td>
<td style="width: 314px;">The type of operation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-endpoint-scan endpoint_id="d3339851f18f470182bf2bf98ad5db4b"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.Scan": {
        "EndpointID": "d3339851f18f470182bf2bf98ad5db4b",
        "OperationID": "404d5231e5bd11e9acbf0245d8e950da",
        "Type": "endpoint-scan"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Scan command on endpoint: d3339851f18f470182bf2bf98ad5db4b received</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 293px;"><strong>Endpoint ID</strong></th>
<th style="width: 304px;"><strong>Operation ID</strong></th>
<th style="width: 111px;"><strong>Type</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293px;">d3339851f18f470182bf2bf98ad5db4b</td>
<td style="width: 304px;">404d5231e5bd11e9acbf0245d8e950da</td>
<td style="width: 111px;">endpoint-scan</td>
</tr>
</tbody>
</table>
<h3 id="h_aff0ef39-1af6-4777-a375-f946e5e295f1">4. Modify details for an event</h3>
<hr>
<p>Modifies the status and adds a comment to an existing event.</p>
<h5>Base Command</h5>
<p><code>traps-event-update</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 216px;"><strong>Argument Name</strong></th>
<th style="width: 365px;"><strong>Description</strong></th>
<th style="width: 127px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">event_id</td>
<td style="width: 365px;">The ID of the event to modify.</td>
<td style="width: 127px;">Required</td>
</tr>
<tr>
<td style="width: 216px;">status</td>
<td style="width: 365px;">The new status for the event.</td>
<td style="width: 127px;">Optional</td>
</tr>
<tr>
<td style="width: 216px;">comment</td>
<td style="width: 365px;">A comment for the event.</td>
<td style="width: 127px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-event-update event_id="53edb3fa9a3b4b83bcf168390a2ec08d" status="new"</pre>
<h5>Human Readable Output</h5>
<h3>Event: 53edb3fa9a3b4b83bcf168390a2ec08d was updated</h3>
<h5>New status: new</h5>
<h3 id="h_4e113a1b-d46a-4b84-8083-98b4b54626f3">5. Modify details for multiple events</h3>
<hr>
<p>Modifies the status of multiple events.</p>
<h5>Base Command</h5>
<p><code>traps-event-bulk-update-status</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 169px;"><strong>Argument Name</strong></th>
<th style="width: 448px;"><strong>Description</strong></th>
<th style="width: 91px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 169px;">event_ids</td>
<td style="width: 448px;">A comma-separated list of IDs for events to modify.</td>
<td style="width: 91px;">Required</td>
</tr>
<tr>
<td style="width: 169px;">status</td>
<td style="width: 448px;">The new status for the event.</td>
<td style="width: 91px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-event-bulk-update-status event_ids="df4e60a62515482f98c8ef37e74363df,cfe4d15aca924bfcb7d2fc629b696bdd"
        status="new"</pre>
<h5>Context Example</h5>
<pre>{}
</pre>
<h5>Human Readable Output</h5>
<h3>Successfully updated</h3>
<p>**No entries.**</p>
<h3>Failed to update</h3>
<p>**No entries.**</p>
<h3>Ignored</h3>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Event ID</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>cfe4d15aca924bfcb7d2fc629b696bdd</td>
</tr>
<tr>
<td>df4e60a62515482f98c8ef37e74363df</td>
</tr>
</tbody>
</table>
<h3 id="h_ba1cf623-1363-40e4-b77b-6e0d96b9aaae">6. Add a file hash to the block list</h3>
<hr>
<p>Adds the specified file hash to the block list.</p>
<h5>Base Command</h5>
<p><code>traps-hash-blacklist</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 192px;"><strong>Argument Name</strong></th>
<th style="width: 409px;"><strong>Description</strong></th>
<th style="width: 107px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 192px;">hash_id</td>
<td style="width: 409px;">The SHA256 hash to add to the block list.</td>
<td style="width: 107px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 211px;"><strong>Path</strong></th>
<th style="width: 55px;"><strong>Type</strong></th>
<th style="width: 442px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 211px;">Traps.File.BlacklistStatus</td>
<td style="width: 55px;">String</td>
<td style="width: 442px;">The status of the file hash ("blacklisted" or "none").</td>
</tr>
<tr>
<td style="width: 211px;">Traps.File.SHA256</td>
<td style="width: 55px;">String</td>
<td style="width: 442px;">The SHA256 hash of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p>!traps-hash-blacklist hash_id="1111111111111111111111111111111111111111111111111111111111111111"</p>
<h5>Context Example</h5>
<pre>{
    "Traps.File": {
        "BlacklistStatus": "blacklisted",
        "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h4>Successfully blacklisted: 1111111111111111111111111111111111111111111111111111111111111111</h4>
<h3 id="h_3c467ab9-13ec-46d4-8d51-5d207d462c92">7. Remove a file hash from the block list</h3>
<hr>
<p>Removes the specified file hash from the block list.</p>
<h5>Base Command</h5>
<p><code>traps-hash-blacklist-remove</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 173px;"><strong>Argument Name</strong></th>
<th style="width: 438px;"><strong>Description</strong></th>
<th style="width: 97px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 173px;">hash_id</td>
<td style="width: 438px;">The SHA256 hash to remove from the block list.</td>
<td style="width: 97px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 209px;"><strong>Path</strong></th>
<th style="width: 57px;"><strong>Type</strong></th>
<th style="width: 442px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 209px;">Traps.File.BlacklistStatus</td>
<td style="width: 57px;">String</td>
<td style="width: 442px;">The status of the file hash ("blacklisted" or "none").</td>
</tr>
<tr>
<td style="width: 209px;">Traps.File.SHA256</td>
<td style="width: 57px;">String</td>
<td style="width: 442px;">The SHA256 hash of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-hash-blacklist-remove
        hash_id="1111111111111111111111111111111111111111111111111111111111111111"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.File": {
        "BlacklistStatus": "none",
        "SHA256": "1111111111111111111111111111111111111111111111111111111111111111"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h4>Successfully removed 1111111111111111111111111111111111111111111111111111111111111111 from block list</h4>
<h3 id="h_10e63ba1-0e9e-4a5f-8840-a0b1dd752d0c">8. Return a file hash to the block list</h3>
<hr>
<p>Returns the block list status of the specified file hashes.</p>
<h5>Base Command</h5>
<p><code>traps-hashes-blacklist-status</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 140px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 140px;">hash_ids</td>
<td style="width: 497px;">A comma-separated list of SHA256 file hashes for which to return the block list status.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 182px;"><strong>Path</strong></th>
<th style="width: 41px;"><strong>Type</strong></th>
<th style="width: 485px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 182px;">Traps.File.BlacklistStatus</td>
<td style="width: 41px;">String</td>
<td style="width: 485px;">The block list status of the file hash. Can be "blacklisted" or "none".</td>
</tr>
<tr>
<td style="width: 182px;">Traps.File.SHA256</td>
<td style="width: 41px;">String</td>
<td style="width: 485px;">The SHA256 hash of the file.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-hashes-blacklist-status
        hash_ids="5616ff15b3f5df4e18d28771ccdae19173873009f2318761aa9f9e573b9d9acc,360b12ccfa33c6d2021bf34162b111ffc2f5939b0524b2e045cd682d93318d69"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.File": [
        {
            "BlacklistStatus": "blacklisted",
            "SHA256": "360b12ccfa33c6d2021bf34162b111ffc2f5939b0524b2e045cd682d93318d69"
        },
        {
            "BlacklistStatus": "none",
            "SHA256": "5616ff15b3f5df4e18d28771ccdae19173873009f2318761aa9f9e573b9d9acc"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Hashes status:</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Blacklist Status</strong></th>
<th style="width: 590px;"><strong>SHA256</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">blacklisted</td>
<td style="width: 590px;">360b12ccfa33c6d2021bf34162b111ffc2f5939b0524b2e045cd682d93318d69</td>
</tr>
<tr>
<td style="width: 131px;">none</td>
<td style="width: 590px;">5616ff15b3f5df4e18d28771ccdae19173873009f2318761aa9f9e573b9d9acc</td>
</tr>
</tbody>
</table>
<h3 id="h_2b3c9090-99ed-473a-9818-9f7f28046e54">9. Quarantine an event</h3>
<hr>
<p>Creates a quarantine entry for the specified event.</p>
<h5>Base Command</h5>
<p><code>traps-event-quarantine</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 484px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">event_id</td>
<td style="width: 484px;">The ID of the event for which to create a quarantine entry..</td>
<td style="width: 83px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 345px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 283px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 345px;">Traps.Quarantine.EventID</td>
<td style="width: 80px;">String</td>
<td style="width: 283px;">The ID of the event.</td>
</tr>
<tr>
<td style="width: 345px;">Traps.Quarantine.OperationID</td>
<td style="width: 80px;">String</td>
<td style="width: 283px;">The ID of the operation.</td>
</tr>
<tr>
<td style="width: 345px;">Traps.Quarantine.Type</td>
<td style="width: 80px;">String</td>
<td style="width: 283px;">The type of operation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-event-quarantine event_id="19903a443a47441a86c92c3aea5abb30"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.Quarantine": [
        {
            "EventID": "19903a443a47441a86c92c3aea5abb30",
            "OperationID": "42185783e5bd11e9acbf0245d8e950da",
            "Type": "event-quarantine"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<h3>Quarantine command on event: 19903a443a47441a86c92c3aea5abb30 received</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 286px;"><strong>Event ID</strong></th>
<th style="width: 294px;"><strong>Operation ID</strong></th>
<th style="width: 128px;"><strong>Type</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 286px;">19903a443a47441a86c92c3aea5abb30</td>
<td style="width: 294px;">42185783e5bd11e9acbf0245d8e950da</td>
<td style="width: 128px;">event-quarantine</td>
</tr>
</tbody>
</table>
<h3 id="h_a469746d-6210-4d13-b7cd-7e79b37fce4b">10. Isolate an endpoint</h3>
<hr>
<p>Isolates the specified endpoint.</p>
<h5>Base Command</h5>
<p><code>traps-endpoint-isolate</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 208px;"><strong>Argument Name</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
<th style="width: 121px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 208px;">endpoint_id</td>
<td style="width: 379px;">The ID of the endpoint to isolate.</td>
<td style="width: 121px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 325px;"><strong>Path</strong></th>
<th style="width: 80px;"><strong>Type</strong></th>
<th style="width: 303px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 325px;">Traps.Isolate.EndpointID</td>
<td style="width: 80px;">String</td>
<td style="width: 303px;">The ID of the endpoint.</td>
</tr>
<tr>
<td style="width: 325px;">Traps.Isolate.OperationID</td>
<td style="width: 80px;">String</td>
<td style="width: 303px;">The ID of the operation.</td>
</tr>
<tr>
<td style="width: 325px;">Traps.Isolate.Type</td>
<td style="width: 80px;">String</td>
<td style="width: 303px;">The type of operation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-endpoint-isolate endpoint_id=d3339851f18f470182bf2bf98ad5db4b</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.Isolate": {
        "EndpointID": "d3339851f18f470182bf2bf98ad5db4b",
        "OperationID": "4278ac6ce5bd11e9acbf0245d8e950da",
        "Type": "endpoint-isolate"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Isolate command on endpoint d3339851f18f470182bf2bf98ad5db4b received</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 293px;"><strong>Endpoint ID</strong></th>
<th style="width: 290px;"><strong>Operation ID</strong></th>
<th style="width: 125px;"><strong>Type</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 293px;">d3339851f18f470182bf2bf98ad5db4b</td>
<td style="width: 290px;">4278ac6ce5bd11e9acbf0245d8e950da</td>
<td style="width: 125px;">endpoint-isolate</td>
</tr>
</tbody>
</table>
<h3 id="h_e26af638-bd84-416d-9642-aaae647dab5a">11. Get the result of a quarantine operation</h3>
<hr>
<p>Returns the result of the specified quarantine operation.</p>
<h5>Base Command</h5>
<p><code>traps-event-quarantine-result</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 154px;"><strong>Argument Name</strong></th>
<th style="width: 483px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 154px;">operation_id</td>
<td style="width: 483px;">The ID of the operation for which to get the result of the quarantine operation.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 317px;"><strong>Path</strong></th>
<th style="width: 50px;"><strong>Type</strong></th>
<th style="width: 341px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 317px;">Traps.QuarantineResult.SHA256</td>
<td style="width: 50px;">String</td>
<td style="width: 341px;">The SHA256 hash of the file.</td>
</tr>
<tr>
<td style="width: 317px;">Traps.QuarantineResult.FilePath</td>
<td style="width: 50px;">String</td>
<td style="width: 341px;">The file path on the endpoint.</td>
</tr>
<tr>
<td style="width: 317px;">Traps.QuarantineResult.OperationID</td>
<td style="width: 50px;">String</td>
<td style="width: 341px;">The ID of the operation.</td>
</tr>
<tr>
<td style="width: 317px;">Traps.QuarantineResult.Status</td>
<td style="width: 50px;">String</td>
<td style="width: 341px;">The status of the quarantine operation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-event-quarantine-result operation_id="e092afa2e08511e9acbf0245d8e950da"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.QuarantineResult": {
        "FilePath": "C:\\Users\\Administrator\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\f_000013",
        "OperationID": "e092afa2e08511e9acbf0245d8e950da",
        "SHA256": "2f937ee2fd10a6ea58faca31ab455d18e29ded5d88b4a6f8cc29127a23232e45",
        "Status": "finished"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Status of quarantine operation: e092afa2e08511e9acbf0245d8e950da</h3>
<table style="width: 1347px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 424px;"><strong>File Path</strong></th>
<th style="width: 274px;"><strong>Operation ID</strong></th>
<th style="width: 541px;"><strong>SHA256</strong></th>
<th style="width: 55px;"><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 424px;">C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Cache\f_000013</td>
<td style="width: 274px;">e092afa2e08511e9acbf0245d8e950da</td>
<td style="width: 541px;">2f937ee2fd10a6ea58faca31ab455d18e29ded5d88b4a6f8cc29127a23232e45</td>
<td style="width: 55px;">finished</td>
</tr>
</tbody>
</table>
<h3 id="h_84666544-eab3-4d4b-88cf-3e5d2f6bf281">12. Get the result of an isolate operation</h3>
<hr>
<p>Returns the status of the specified endpoint isolate operation.</p>
<h5>Base Command</h5>
<p><code>traps-endpoint-isolate-status</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 243px;"><strong>Argument Name</strong></th>
<th style="width: 323px;"><strong>Description</strong></th>
<th style="width: 142px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 243px;">operation_id</td>
<td style="width: 323px;">The ID of the operation.</td>
<td style="width: 142px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 259px;"><strong>Path</strong></th>
<th style="width: 47px;"><strong>Type</strong></th>
<th style="width: 402px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 259px;">Traps.IsolateResult.OperationID</td>
<td style="width: 47px;">String</td>
<td style="width: 402px;">Operation ID. Use this to retrieve status / results.</td>
</tr>
<tr>
<td style="width: 259px;">Traps.IsolateResult.Status</td>
<td style="width: 47px;">String</td>
<td style="width: 402px;">The status of the isolation operation.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-endpoint-isolate-status operation_id=d4abbbc4e5ba11e9acbf0245d8e950da</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.IsolateResult": {
        "OperationID": "d4abbbc4e5ba11e9acbf0245d8e950da",
        "Status": "finished"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Isolate status is: finished</h3>
<h3 id="h_494733b8-f5c5-4236-84d4-a72ac01a3e6e">13. Get the results of an endpoint file retrieve operation</h3>
<hr>
<p>Returns the result of the endpoint file retrieve operation.</p>
<h5>Base Command</h5>
<p><code>traps-endpoint-files-retrieve-result</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 241px;"><strong>Argument Name</strong></th>
<th style="width: 325px;"><strong>Description</strong></th>
<th style="width: 142px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 241px;">operation_id</td>
<td style="width: 325px;">The ID of the operation.</td>
<td style="width: 142px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There are no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-endpoint-files-retrieve-result operation_id="d129d313e5ba11e9acbf0245d8e950da"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.FileRetrieveResult": {
        "OperationID": "d129d313e5ba11e9acbf0245d8e950da",
        "Status": "finished"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>File retrieval status is: finished</h3>
<h3 id="h_47027a19-92a6-4513-bd07-0aa1769f42ab">14. Get the results of an endpoint scan operation</h3>
<hr>
<p>Returns the results of an endpoint scan operation.</p>
<h5>Base Command</h5>
<p><code>traps-endpoint-scan-result</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 242px;"><strong>Argument Name</strong></th>
<th style="width: 324px;"><strong>Description</strong></th>
<th style="width: 142px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 242px;">operation_id</td>
<td style="width: 324px;">The ID of the operation.</td>
<td style="width: 142px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 278px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 367px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 278px;">Traps.ScanResult.FileScanned</td>
<td style="width: 63px;">Number</td>
<td style="width: 367px;">The number of scanned files.</td>
</tr>
<tr>
<td style="width: 278px;">Traps.ScanResult.FilesFailed</td>
<td style="width: 63px;">Number</td>
<td style="width: 367px;">The number of files that were not scanned.</td>
</tr>
<tr>
<td style="width: 278px;">Traps.ScanResult.MalwareFound</td>
<td style="width: 63px;">Number</td>
<td style="width: 367px;">The number of detected malware.</td>
</tr>
<tr>
<td style="width: 278px;">Traps.ScanResult.OperationID</td>
<td style="width: 63px;">String</td>
<td style="width: 367px;">The ID of the operation.</td>
</tr>
<tr>
<td style="width: 278px;">Traps.ScanResult.Status</td>
<td style="width: 63px;">String</td>
<td style="width: 367px;">The status of the scan.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<pre>!traps-endpoint-scan-result operation_id="d270d8bce5ba11e9acbf0245d8e950da"</pre>
<h5>Context Example</h5>
<pre>{
    "Traps.ScanResult": {
        "FileScanned": 57295,
        "FilesFailed": 0,
        "MalwareFound": 1,
        "OperationID": "d270d8bce5ba11e9acbf0245d8e950da",
        "Status": "error"
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Status of scan operation: d270d8bce5ba11e9acbf0245d8e950da</h3>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 114px;"><strong>File Scanned</strong></th>
<th style="width: 89px;"><strong>Files Failed</strong></th>
<th style="width: 129px;"><strong>Malware Found</strong></th>
<th style="width: 294px;"><strong>Operation ID</strong></th>
<th style="width: 56px;"><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 114px;">57295</td>
<td style="width: 89px;">0</td>
<td style="width: 129px;">1</td>
<td style="width: 294px;">d270d8bce5ba11e9acbf0245d8e950da</td>
<td style="width: 56px;">error</td>
</tr>
</tbody>
</table>
<h2> </h2>