<!-- HTML_DOC -->
<section class="article-info">
        <div class="article-content">
          <div class="article-body"><div class="cl-preview-section">
<p>Use the LogRhythm integration to manage hosts and entities.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Execute queries on logs data.</li>
<li>Add new host.</li>
<li>Get host information.</li>
<li>Update host status.</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-logrhythmrest-on-demisto">Configure LogRhythmRest on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span>&nbsp;</span><strong>Settings</strong><span>&nbsp;</span>&gt;<span>&nbsp;</span><strong>Integrations</strong><span>&nbsp;</span>&gt;<span>&nbsp;</span><strong>Servers &amp; Services</strong>.</li>
<li>Search for LogRhythmRest.</li>
<li>Click<span>&nbsp;</span><strong>Add instance</strong><span>&nbsp;</span>to create and configure a new integration instance.
<ul>
<li><strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Hostname, IP address, or server URL.</strong></li>
<li><strong>API Token</strong>: see the <a href="https://onlinehelp74.logrhythm.com/#3Administration/PeopleAndUsers/GrantCaseAPIAccessUserAccount.htm" target="_blank" rel="noopener">LogRhythm documentation</a></li>
<li><strong>Trust any certificate (unsecure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Search API cluster ID</strong>: In the LogRhythm host, enter&nbsp;<code>http://localhost:8500/ui/#/dc1/services/lr-legacy-search-api</code>,&nbsp;the cluster ID is under the <code>TAGS</code> header</li>
</ul>
</li>
<li>Click<span>&nbsp;</span><strong>Test</strong><span>&nbsp;</span>to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#search-for-logs" target="_self">Search for logs: lr-execute-query</a></li>
<li><a href="#get-a-list-of-hosts-for-an-entity" target="_self">Get a list of hosts for an entity: lr-get-hosts-by-entity</a></li>
<li><a href="#add-a-host-to-an-entity" target="_self">Add a host to an entity: lr-add-host</a></li>
<li><a href="#update-the-status-of-a-host" target="_self">Update the status of a host: lr-update-host-status</a></li>
<li><a href="#h_4b05d8f1-f84c-4ff0-8a91-ac6364046282" target="_self">Get a list of persons: lr-get-persons</a></li>
<li><a href="#h_53cc2ff2-69ab-4629-82b5-8f57034eb921" target="_self">Get a list of networks: lr-get-networks</a></li>
<li><a href="#h_36b3d717-30b8-4a5b-b9ca-cd7ee14ad977" target="_self">Get a list of hosts: lr-get-hosts</a></li>
<li><a href="#h_25fc3009-00ee-4576-a35c-fde6742ed8ab" target="_self">Get information for an alarm: lr-get-alarm-data</a></li>
<li><a href="#h_b97bfa47-d772-457f-a065-36ca18895a31" target="_self">Get a list of events: lr-get-alarm-events</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="search-for-logs">1. Search for logs</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Executes a query for logs that match query parameters.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>lr-execute-query</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">keyword</td>
<td style="width: 538px;">Filter log messages by this argument.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 131px;">page-size</td>
<td style="width: 538px;">Number of logs to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">time-frame</td>
<td style="width: 538px;">If time_frame is “Custom”, specify the start time for the time range.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">start-date</td>
<td style="width: 538px;">Start date for the data query, for example: “2018-04-20”. Only use this argument if the time-frame argument is “Custom”.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 131px;">end-date</td>
<td style="width: 538px;">End date for the data query, for example: “2018-04-20”. Only use this argument if the time-frame argument is “Custom”.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
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
<th style="width: 425px;"><strong>Path</strong></th>
<th style="width: 103px;"><strong>Type</strong></th>
<th style="width: 212px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 425px;">Logrhythm.Log.Channel</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Channel.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.Computer</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Computer.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.EventData</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Event data.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.EventID</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Event ID.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.Keywords</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Keywords.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.Level</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Level.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.Opcode</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Opcode.</td>
</tr>
<tr>
<td style="width: 425px;">Logrhythm.Log.Task</td>
<td style="width: 103px;">string</td>
<td style="width: 212px;">Task.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>lr-execute-query keyword=Failure time-frame=Custom start-date=2019-05-15 end-date=2019-05-16 page-size=2
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Logrhythm.Log": [
        {
            "EventID": "4625", 
            "Task": "Logon", 
            "Level": "Information", 
            "Computer": "WIN-1234.demisto.lab", 
            "Opcode": "Info", 
            "Keywords": "Audit Failure", 
            "EventData": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tGPWARD\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.", 
            "Channel": "Security"
        }, 
        {
            "EventID": "4625", 
            "Task": "Logon", 
            "Level": "Information", 
            "Computer": "WIN-1234.demisto.lab", 
            "Opcode": "Info", 
            "Keywords": "Audit Failure", 
            "EventData": "An account failed to log on.\n\nSubject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\nLogon Type:\t\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\tTMARTIN\n\tAccount Domain:\t\t\n\nFailure Information:\n\tFailure Reason:\t\tUnknown user name or bad password.\n\tStatus:\t\t\t0xC000006D\n\tSub Status:\t\t0xC0000064\n\nProcess Information:\n\tCaller Process ID:\t0x0\n\tCaller Process Name:\t-\n\nNetwork Information:\n\tWorkstation Name:\t-\n\tSource Network Address:\t-\n\tSource Port:\t\t-\n\nDetailed Authentication Information:\n\tLogon Process:\t\tNtLmSsp \n\tAuthentication Package:\tNTLM\n\tTransited Services:\t-\n\tPackage Name (NTLM only):\t-\n\tKey Length:\t\t0\n\nThis event is generated when a logon request fails. It is generated on the computer where access was attempted.\n\nThe Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.\n\nThe Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).\n\nThe Process Information fields indicate which account and process on the system requested the logon.\n\nThe Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.\n\nThe authentication information fields provide detailed information about this specific logon request.\n\t- Transited services indicate which intermediate services have participated in this logon request.\n\t- Package name indicates which sub-protocol was used among the NTLM protocols.\n\t- Key length indicates the length of the generated session key. This will be 0 if no session key was requested.", 
            "Channel": "Security"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="logs-results">Logs results</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Level</th>
<th>Computer</th>
<th>Channel</th>
<th>Keywords</th>
<th>EventData</th>
</tr>
</thead>
<tbody>
<tr>
<td>Information</td>
<td>WIN-1234.demisto.lab</td>
<td>Security</td>
<td>Audit Failure</td>
<td>An account failed to log on.<br> <br> Subject:<br> Security ID: NULL SID<br> Account Name: -<br> Account Domain: -<br> Logon ID: 0x0<br> <br> Logon Type: 3<br> <br> Account For Which Logon Failed:<br> Security ID: NULL SID<br> Account Name: GPWARD<br> Account Domain:<span>&nbsp;</span><br> <br> Failure Information:<br> Failure Reason: Unknown user name or bad password.<br> Status: 0xC000006D<br> Sub Status: 0xC0000064<br> <br> Process Information:<br> Caller Process ID: 0x0<br> Caller Process Name: -<br> <br> Network Information:<br> Workstation Name: -<br> Source Network Address: -<br> Source Port: -<br> <br> Detailed Authentication Information:<br> Logon Process: NtLmSsp<span>&nbsp;</span><br> Authentication Package: NTLM<br> Transited Services: -<br> Package Name (NTLM only): -<br> Key Length: 0<br> <br> This event is generated when a logon request fails. It is generated on the computer where access was attempted.<br> <br> The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.<br> <br> The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).<br> <br> The Process Information fields indicate which account and process on the system requested the logon.<br> <br> The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.<br> <br> The authentication information fields provide detailed information about this specific logon request.<br> - Transited services indicate which intermediate services have participated in this logon request.<br> - Package name indicates which sub-protocol was used among the NTLM protocols.<br> - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</td>
</tr>
<tr>
<td>Information</td>
<td>WIN-1234.demisto.lab</td>
<td>Security</td>
<td>Audit Failure</td>
<td>An account failed to log on.<br> <br> Subject:<br> Security ID: NULL SID<br> Account Name: -<br> Account Domain: -<br> Logon ID: 0x0<br> <br> Logon Type: 3<br> <br> Account For Which Logon Failed:<br> Security ID: NULL SID<br> Account Name: TMARTIN<br> Account Domain:<span>&nbsp;</span><br> <br> Failure Information:<br> Failure Reason: Unknown user name or bad password.<br> Status: 0xC000006D<br> Sub Status: 0xC0000064<br> <br> Process Information:<br> Caller Process ID: 0x0<br> Caller Process Name: -<br> <br> Network Information:<br> Workstation Name: -<br> Source Network Address: -<br> Source Port: -<br> <br> Detailed Authentication Information:<br> Logon Process: NtLmSsp<span>&nbsp;</span><br> Authentication Package: NTLM<br> Transited Services: -<br> Package Name (NTLM only): -<br> Key Length: 0<br> <br> This event is generated when a logon request fails. It is generated on the computer where access was attempted.<br> <br> The Subject fields indicate the account on the local system which requested the logon. This is most commonly a service such as the Server service, or a local process such as Winlogon.exe or Services.exe.<br> <br> The Logon Type field indicates the kind of logon that was requested. The most common types are 2 (interactive) and 3 (network).<br> <br> The Process Information fields indicate which account and process on the system requested the logon.<br> <br> The Network Information fields indicate where a remote logon request originated. Workstation name is not always available and may be left blank in some cases.<br> <br> The authentication information fields provide detailed information about this specific logon request.<br> - Transited services indicate which intermediate services have participated in this logon request.<br> - Package name indicates which sub-protocol was used among the NTLM protocols.<br> - Key length indicates the length of the generated session key. This will be 0 if no session key was requested.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-hosts-for-an-entity">2. Get a list of hosts for an entity</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a list of hosts for a given entity, or an empty list if none is found.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>lr-get-hosts-by-entity</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 240px;"><strong>Argument Name</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
<th style="width: 137px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 240px;">entity-name</td>
<td style="width: 363px;">The entity name.</td>
<td style="width: 137px;">Required</td>
</tr>
<tr>
<td style="width: 240px;">count</td>
<td style="width: 363px;">Number of hosts to return.</td>
<td style="width: 137px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
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
<th style="width: 370px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 370px;">Logrhythm.Host.EntityId</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The entity ID.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.EntityName</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The entity name.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.OS</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host OS.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.ThreatLevel</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host threat level.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.UseEventlogCredentials</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">Use event log credentials</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.DateUpdated</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The last update date of the host.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.HostZone</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host zone.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.RiskLevel</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The risk level.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Location</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host location.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Status</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host status.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.ID</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The unique ID of the host object.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.OSType</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The type of the host OS.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>lr-get-hosts-by-entity entity-name=primary count=2
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Logrhythm.Host": [
        {
            "Status": "Active", 
            "Name": "AI Engine Server", 
            "RiskLevel": "None", 
            "OS": "Unknown", 
            "EntityName": "Primary Site", 
            "ID": -1000002, 
            "Location": "NA", 
            "OSType": "Other", 
            "ThreatLevel": "None", 
            "DateUpdated": "2019-04-24T09:58:32.003Z", 
            "HostZone": "Internal", 
            "EntityId": 1, 
            "UseEventlogCredentials": false
        }, 
        {
            "Status": "Active", 
            "Name": "WIN-JSBOL5ERCQA", 
            "RiskLevel": "Medium-Medium", 
            "OS": "Windows", 
            "EntityName": "Primary Site", 
            "ID": 1, 
            "Location": "NA", 
            "OSType": "Other", 
            "ThreatLevel": "None", 
            "DateUpdated": "2018-10-04T05:02:01.893Z", 
            "HostZone": "Internal", 
            "EntityId": 1, 
            "UseEventlogCredentials": false
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="hosts-for-primary">Hosts for primary</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>EntityId</th>
<th>EntityName</th>
<th>OS</th>
<th>Status</th>
<th>Location</th>
<th>RiskLevel</th>
<th>ThreatLevel</th>
<th>ThreatLevelComments</th>
<th>DateUpdated</th>
<th>HostZone</th>
</tr>
</thead>
<tbody>
<tr>
<td>-1000002</td>
<td>AI Engine Server</td>
<td>1</td>
<td>Primary Site</td>
<td>Unknown</td>
<td>Active</td>
<td>NA</td>
<td>None</td>
<td>None</td>
<td>&nbsp;</td>
<td>2019-04-24T09:58:32.003Z</td>
<td>Internal</td>
</tr>
<tr>
<td>1</td>
<td>WIN-1234</td>
<td>1</td>
<td>Primary Site</td>
<td>Windows</td>
<td>Active</td>
<td>NA</td>
<td>Medium-Medium</td>
<td>None</td>
<td>&nbsp;</td>
<td>2018-10-04T05:02:01.893Z</td>
<td>Internal</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="add-a-host-to-an-entity">3. Add a host to an entity</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Add a new host to an entity.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>lr-add-host</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 250px;"><strong>Argument Name</strong></th>
<th style="width: 383px;"><strong>Description</strong></th>
<th style="width: 107px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 250px;">entity-id</td>
<td style="width: 383px;">The entity ID.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">entity-name</td>
<td style="width: 383px;">The entity name.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">name</td>
<td style="width: 383px;">The LogRhythm host name.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">short-description</td>
<td style="width: 383px;">The short description.</td>
<td style="width: 107px;">Optional</td>
</tr>
<tr>
<td style="width: 250px;">long-description</td>
<td style="width: 383px;">The long description.</td>
<td style="width: 107px;">Optional</td>
</tr>
<tr>
<td style="width: 250px;">risk-level</td>
<td style="width: 383px;">The short description.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">threat-level</td>
<td style="width: 383px;">The host threat level.</td>
<td style="width: 107px;">Optional</td>
</tr>
<tr>
<td style="width: 250px;">threat-level-comments</td>
<td style="width: 383px;">Comments for the host threat level.</td>
<td style="width: 107px;">Optional</td>
</tr>
<tr>
<td style="width: 250px;">host-status</td>
<td style="width: 383px;">The host status.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">host-zone</td>
<td style="width: 383px;">The host zone.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">os</td>
<td style="width: 383px;">The host OS.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">use-eventlog-credentials</td>
<td style="width: 383px;">Use eventlog credentials.</td>
<td style="width: 107px;">Required</td>
</tr>
<tr>
<td style="width: 250px;">os-type</td>
<td style="width: 383px;">The host OS.</td>
<td style="width: 107px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
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
<th style="width: 370px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 370px;">Logrhythm.Host.EntityId</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The entity ID.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.EntityName</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The entity name.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.OS</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host OS.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.ThreatLevel</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host threat level.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.UseEventlogCredentials</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">Use event log credentials</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Name</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.DateUpdated</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The last update date of the host.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.HostZone</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host zone.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.RiskLevel</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The risk level.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Location</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host location.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Status</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The host status.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.ID</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The unique ID of the host object.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.OSType</td>
<td style="width: 59px;">string</td>
<td style="width: 311px;">The type of the host OS.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>lr-add-host entity-id=1 entity-name=`Primary Site` host-status=New host-zone=Internal name=host-name os=Windows risk-level="High-Medium" use-eventlog-credentials=false
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Logrhythm.Host": [
        {
            "Status": "New", 
            "Name": "host-name", 
            "RiskLevel": "High-Medium", 
            "OS": "Windows", 
            "EntityName": "Primary Site", 
            "ThreatLevelComments": "None", 
            "ID": 46, 
            "Location": "NA", 
            "OSType": "Unknown", 
            "ThreatLevel": "None", 
            "DateUpdated": "2019-05-28T14:26:19.543Z", 
            "HostZone": "Internal", 
            "EntityId": 1, 
            "UseEventlogCredentials": true
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>host-name added successfully to Primary Site</p>
</div>
<div class="cl-preview-section">
<h3 id="update-the-status-of-a-host">4. Update the status of a host</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Updates an host status.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>lr-update-host-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 206px;"><strong>Argument Name</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
<th style="width: 117px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">host-id</td>
<td style="width: 417px;">The unique ID of the host.</td>
<td style="width: 117px;">Required</td>
</tr>
<tr>
<td style="width: 206px;">status</td>
<td style="width: 417px;">The enumeration status of the host.</td>
<td style="width: 117px;">Required</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 371px;"><strong>Path</strong></th>
<th style="width: 58px;"><strong>Type</strong></th>
<th style="width: 311px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 371px;">Logrhythm.Host.EntityId</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The entity ID.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.EntityName</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The entity name.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.OS</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The host OS.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.ThreatLevel</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The host threat level.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.UseEventlogCredentials</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">Use event log credentials</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.Name</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.DateUpdated</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The last update date of the host.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.HostZone</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The host zone.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.RiskLevel</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The risk level.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.Location</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The host location.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.Status</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The host status.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.ID</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The unique ID of the host object.</td>
</tr>
<tr>
<td style="width: 371px;">Logrhythm.Host.OSType</td>
<td style="width: 58px;">string</td>
<td style="width: 311px;">The type of the host OS.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>lr-update-host-status host-id=8 status=Retired
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Logrhythm": {
        "Host": {
            "Status": "Retired", 
            "Name": "test-host7", 
            "RiskLevel": "Low-Medium", 
            "OS": "Linux", 
            "EntityName": "Primary Site", 
            "ID": 8, 
            "Location": "NA", 
            "OSType": "Other", 
            "ThreatLevel": "Low-High", 
            "DateUpdated": "2019-05-28T14:32:39.43Z", 
            "HostZone": "Internal", 
            "EntityId": 1, 
            "UseEventlogCredentials": false
        }
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Status updated to Retired</p>
<h3 id="h_4b05d8f1-f84c-4ff0-8a91-ac6364046282">5. Get a list of persons</h3>
<hr>
<p>Retrieves a list of persons.</p>
<h5><a id="Base_Command_3"></a>Base Command</h5>
<p><code>lr-get-persons</code></p>
<h5><a id="Input_6"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 240px;"><strong>Argument Name</strong></th>
<th style="width: 369px;"><strong>Description</strong></th>
<th style="width: 131px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 240px;">person-id</td>
<td style="width: 369px;">The LogRhythm person id.</td>
<td style="width: 131px;">Optional</td>
</tr>
<tr>
<td style="width: 240px;">count</td>
<td style="width: 369px;">Number of persons to return.</td>
<td style="width: 131px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Context_Output_14"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 430px;"><strong>Path</strong></th>
<th style="width: 121px;"><strong>Type</strong></th>
<th style="width: 189px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 430px;">Logrhythm.Person.DateUpdated</td>
<td style="width: 121px;">String</td>
<td style="width: 189px;">Date updated</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.FirstName</td>
<td style="width: 121px;">String</td>
<td style="width: 189px;">First name</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.LastName</td>
<td style="width: 121px;">String</td>
<td style="width: 189px;">Last name</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.HostStatus</td>
<td style="width: 121px;">string</td>
<td style="width: 189px;">Host status</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.ID</td>
<td style="width: 121px;">String</td>
<td style="width: 189px;">Person ID</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.IsAPIPerson</td>
<td style="width: 121px;">Boolean</td>
<td style="width: 189px;">Is API person</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.UserID</td>
<td style="width: 121px;">String</td>
<td style="width: 189px;">User ID</td>
</tr>
<tr>
<td style="width: 430px;">Logrhythm.Person.UserLogin</td>
<td style="width: 121px;">String</td>
<td style="width: 189px;">User login</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Command_Example_28"></a>Command Example</h5>
<pre>!lr-get-persons person-id=7</pre>
<h5><a id="Context_Example_31"></a>Context Example</h5>
<pre>{
    "Logrhythm.Person": [
        {
            "IsAPIPerson": false, 
            "FirstName": "demisto", 
            "LastName": "demisto", 
            "UserID": 5, 
            "UserLogin": "DEMISTO\\lrapi", 
            "DateUpdated": "0001-01-01T00:00:00Z", 
            "ID": 7, 
            "HostStatus": "Retired"
        }
    ]
}
</pre>
<h5><a id="Human_Readable_Output_49"></a>Human Readable Output</h5>
<h3><a id="Persons_information_50"></a>Persons information</h3>
<table class="table table-striped table-bordered" style="width: 698px;" border="2">
<thead>
<tr>
<th style="width: 20px;">ID</th>
<th style="width: 87px;">HostStatus</th>
<th style="width: 100px;">IsAPIPerson</th>
<th style="width: 81px;">FirstName</th>
<th style="width: 79px;">LastName</th>
<th style="width: 56px;">UserID</th>
<th style="width: 117px;">UserLogin</th>
<th style="width: 133px;">DateUpdated</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 20px;">7</td>
<td style="width: 87px;">Retired</td>
<td style="width: 100px;">false</td>
<td style="width: 81px;">demisto</td>
<td style="width: 79px;">demisto</td>
<td style="width: 56px;">5</td>
<td style="width: 117px;">DEMISTO\lrapi</td>
<td style="width: 133px;">0001-01-01T00:00:00Z</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_53cc2ff2-69ab-4629-82b5-8f57034eb921"><a id="6_Get_a_list_of_networks_56"></a>6. Get a list of networks</h3>
<hr>
<p>Retrieves a list of networks.</p>
<h5><a id="Base_Command_59"></a>Base Command</h5>
<p><code>lr-get-networks</code></p>
<h5><a id="Input_62"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 233px;"><strong>Argument Name</strong></th>
<th style="width: 379px;"><strong>Description</strong></th>
<th style="width: 128px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 233px;">network-id</td>
<td style="width: 379px;">The LogRhythm network ID.</td>
<td style="width: 128px;">Optional</td>
</tr>
<tr>
<td style="width: 233px;">count</td>
<td style="width: 379px;">Number of networks to return.</td>
<td style="width: 128px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Context_Output_70"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 426px;"><strong>Path</strong></th>
<th style="width: 88px;"><strong>Type</strong></th>
<th style="width: 226px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 426px;">Logrhythm.Network.BIP</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Began ip address</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.ThreatLevel</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Threat level</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.Name</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Network name</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.EIP</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">End ip address</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.DateUpdated</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Date updated</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.EntityName</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Entity name</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.HostZone</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Host zone</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.RiskLevel</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Risk level</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.Location</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Network location</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.HostStatus</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Host status</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.ID</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Network ID</td>
</tr>
<tr>
<td style="width: 426px;">Logrhythm.Network.EntityId</td>
<td style="width: 88px;">String</td>
<td style="width: 226px;">Entity ID</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Command_Example_88"></a>Command Example</h5>
<pre>!lr-get-networks network-id=1</pre>
<h5><a id="Context_Example_91"></a>Context Example</h5>
<pre>{
    "Logrhythm.Network": [
        {
            "EndIP": "2.2.2.2", 
            "Name": "test", 
            "RiskLevel": "None", 
            "EntityName": "Global Entity", 
            "ID": 1, 
            "Location": {
                "id": -1
            }, 
            "ThreatLevel": "None", 
            "DateUpdated": "2019-02-20T10:57:13.983Z", 
            "BeganIP": "1.1.1.1", 
            "HostZone": "External", 
            "EntityId": -100, 
            "HostStatus": "Active"
        }
    ]
}
</pre>
<h5><a id="Human_Readable_Output_115"></a>Human Readable Output</h5>
<h3><a id="Networks_information_116"></a>Networks information</h3>
<table class="table table-striped table-bordered" style="width: 908px;" border="2">
<thead>
<tr>
<th style="width: 20px;">ID</th>
<th style="width: 69px;">BeganIP</th>
<th style="width: 49px;">EndIP</th>
<th style="width: 87px;">HostStatus</th>
<th style="width: 46px;">Name</th>
<th style="width: 75px;">RiskLevel</th>
<th style="width: 64px;">EntityId</th>
<th style="width: 92px;">EntityName</th>
<th style="width: 67px;">Location</th>
<th style="width: 93px;">ThreatLevel</th>
<th style="width: 134px;">DateUpdated</th>
<th style="width: 75px;">HostZone</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 20px;">1</td>
<td style="width: 69px;">1.1.1.1</td>
<td style="width: 49px;">2.2.2.2</td>
<td style="width: 87px;">Active</td>
<td style="width: 46px;">test</td>
<td style="width: 75px;">None</td>
<td style="width: 64px;">-100</td>
<td style="width: 92px;">Global Entity</td>
<td style="width: 67px;">id: -1</td>
<td style="width: 93px;">None</td>
<td style="width: 134px;">2019-02-20T10:57:13.983Z</td>
<td style="width: 75px;">External</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_36b3d717-30b8-4a5b-b9ca-cd7ee14ad977"><a id="7_Get_a_list_of_hosts_122"></a>7. Get a list of hosts</h3>
<hr>
<p>Retrieves a list of hosts.</p>
<h5><a id="Base_Command_125"></a>Base Command</h5>
<p><code>lr-get-hosts</code></p>
<h5><a id="Input_128"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 236px;"><strong>Argument Name</strong></th>
<th style="width: 367px;"><strong>Description</strong></th>
<th style="width: 137px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 236px;">host-id</td>
<td style="width: 367px;">The LogRhythm host ID.</td>
<td style="width: 137px;">Optional</td>
</tr>
<tr>
<td style="width: 236px;">count</td>
<td style="width: 367px;">Number of hosts to return.</td>
<td style="width: 137px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Context_Output_136"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 370px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 370px;">Logrhythm.Host.EntityId</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The entity ID.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.EntityName</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The entity name.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.OS</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The host OS.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.ThreatLevel</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The host threat level.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.UseEventlogCredentials</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">Use event log credentials</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Name</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The name of the host.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.DateUpdated</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The last update date of the host.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.HostZone</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The host zone.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.RiskLevel</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The risk level.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Location</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The host location.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.Status</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The host status.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.ID</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The unique ID of the host object.</td>
</tr>
<tr>
<td style="width: 370px;">Logrhythm.Host.OSType</td>
<td style="width: 60px;">String</td>
<td style="width: 310px;">The type of the host OS.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Command_Example_155"></a>Command Example</h5>
<pre>!lr-get-hosts host-id=1</pre>
<h5><a id="Context_Example_158"></a>Context Example</h5>
<pre>{
    "Logrhythm.Host": [
        {
            "Status": "Active", 
            "Name": "WIN-JSBOL5ERCQA", 
            "RiskLevel": "Medium-Medium", 
            "OS": "Windows", 
            "EntityName": "Primary Site", 
            "ID": 1, 
            "Location": {
                "id": -1
            }, 
            "OSType": "Other", 
            "ThreatLevel": "None", 
            "DateUpdated": "2019-07-03T07:20:24.44Z", 
            "HostZone": "Internal", 
            "EntityId": 1, 
            "UseEventlogCredentials": false
        }
    ]
}
</pre>
<h5><a id="Human_Readable_Output_183"></a>Human Readable Output</h5>
<h3><a id="Hosts_information_184"></a>Hosts information:</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>EntityId</th>
<th>EntityName</th>
<th>OS</th>
<th>Status</th>
<th>Location</th>
<th>RiskLevel</th>
<th>ThreatLevel</th>
<th>ThreatLevelComments</th>
<th>DateUpdated</th>
<th>HostZone</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>WIN-JSBOL5ERCQA</td>
<td>1</td>
<td>Primary Site</td>
<td>Windows</td>
<td>Active</td>
<td>id: -1</td>
<td>Medium-Medium</td>
<td>None</td>
<td>&nbsp;</td>
<td>2019-07-03T07:20:24.44Z</td>
<td>Internal</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_25fc3009-00ee-4576-a35c-fde6742ed8ab"><a id="8_Get_information_for_an_alarm_190"></a>8. Get information for an alarm</h3>
<hr>
<p>Retrieves alarm data.</p>
<h5><a id="Base_Command_193"></a>Base Command</h5>
<p><code>lr-get-alarm-data</code></p>
<h5><a id="Input_196"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 312px;"><strong>Argument Name</strong></th>
<th style="width: 250px;"><strong>Description</strong></th>
<th style="width: 178px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 312px;">alarm-id</td>
<td style="width: 250px;">The alarm ID.</td>
<td style="width: 178px;">Required</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Context_Output_203"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 748px;">
<thead>
<tr>
<th style="width: 364px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 310px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.Status</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm status.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.EventID</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm event ID.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.LastDxTimeStamp</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The timestamp of the last time the drilldown returned new results from the Data Indexer.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.DateInserted</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm date inserted.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.AIERuleName</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm AI engine (AIE) rule.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.Priority</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm priority.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.AIERuleID</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm AI engine (AIE) rule ID.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.ID</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm ID.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.NotificationSent</td>
<td style="width: 66px;">Boolean</td>
<td style="width: 310px;">Whether the alarm notification was sent.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.AlarmGuid</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm GUID.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.RetryCount</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm retry count.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.NormalMessageDate</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">The alarm message date.</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.WebConsoleIds</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">
<p>The alarm web console IDs</p>
</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.Summary.PIFType</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">Alarm Primary Inspection Field (the original name for “Summary Field”).</td>
</tr>
<tr>
<td style="width: 364px;">Logrhythm.Alarm.Summary.DrillDownSummaryLogs</td>
<td style="width: 66px;">String</td>
<td style="width: 310px;">Drill down summary logs.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Command_Example_224"></a>Command Example</h5>
<pre>!lr-get-alarm-data alarm-id=1824</pre>
<h5><a id="Context_Example_227"></a>Context Example</h5>
<pre>{
    "Logrhythm.Alarm": {
        "EventID": 337555, 
        "Priority": 85, 
        "LastDxTimeStamp": "0001-01-01T00:00:00", 
        "DateInserted": "2019-06-20T12:13:28.363", 
        "AIERuleName": "Use Of Admin User", 
        "AIERuleID": 1000000003, 
        "Status": "Completed", 
        "AIEMsgXml": {
            "v": "1", 
            "_": {
                "DateEdited": "2019-06-20 11:54:42", 
                "AIERuleID": "1000000003"
            }, 
            "_0": {
                "FactCount": "1", 
                "RuleBlockType": "1", 
                "NormalMsgDate": "2019-06-20 12:13:19", 
                "NormalMsgDateLower": "2019-06-20 12:13:19", 
                "NormalMsgDateUpper": "2019-06-20 12:13:20", 
                "Login": "administrator"
            }
        }, 
        "Summary": [
            {
                "DrillDownSummaryLogs": "administrator", 
                "PIFType": "User (Origin)"
            }
        ], 
        "NotificationSent": false, 
        "AlarmGuid": "5a4d8d77-5ec6-4669-b455-fb0cdbeed7df", 
        "RetryCount": 0, 
        "NormalMessageDate": "2019-06-20T12:13:20.243", 
        "WebConsoleIds": [
            "c272b5f5-1db6-461b-9e9c-78d171429494"
        ], 
        "ID": 1824
    }
}
</pre>
<h5><a id="Human_Readable_Output_271"></a>Human Readable Output</h5>
<h3><a id="Alarm_information_for_alarm_id_1824_272"></a>Alarm information for alarm id 1824</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>AIERuleID</th>
<th>AIERuleName</th>
<th>Status</th>
<th>RetryCount</th>
<th>LastDxTimeStamp</th>
<th>DateInserted</th>
<th>AlarmGuid</th>
<th>NotificationSent</th>
<th>EventID</th>
<th>NormalMessageDate</th>
<th>WebConsoleIds</th>
<th>Priority</th>
<th>ID</th>
</tr>
</thead>
<tbody>
<tr>
<td>1000000003</td>
<td>Use Of Admin User</td>
<td>Completed</td>
<td>0</td>
<td>0001-01-01T00:00:00</td>
<td>2019-06-20T12:13:28.363</td>
<td>5a4d8d77-5ec6-4669-b455-fb0cdbeed7df</td>
<td>false</td>
<td>337555</td>
<td>2019-06-20T12:13:20.243</td>
<td>c272b5f5-1db6-461b-9e9c-78d171429494</td>
<td>85</td>
<td>1824</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3><a id="Alarm_summaries_276"></a>Alarm summaries</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>PIFType</th>
<th>DrillDownSummaryLogs</th>
</tr>
</thead>
<tbody>
<tr>
<td>User (Origin)</td>
<td>administrator</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h3 id="h_b97bfa47-d772-457f-a065-36ca18895a31"><a id="9_Get_a_list_of_events_282"></a>9. Get a list of events</h3>
<hr>
<p>Retrieves a list of events by alarm ID.</p>
<h5><a id="Base_Command_285"></a>Base Command</h5>
<p><code>lr-get-alarm-events</code></p>
<h5><a id="Input_288"></a>Input</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 168px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 168px;">alarm-id</td>
<td style="width: 501px;">The alarm ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 168px;">count</td>
<td style="width: 501px;">Number of events to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168px;">fields</td>
<td style="width: 501px;">CSV list of fields (outputs) to return in the context. If empty, will return all fields.&nbsp; &nbsp; &nbsp; &nbsp; &nbsp;</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 168px;">get-log-message</td>
<td style="width: 501px;">Retrieves the log message from the event.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Context_Output_298"></a>Context Output</h5>
<table class="table table-striped table-bordered" style="width: 749px;">
<thead>
<tr>
<th style="width: 315px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 338px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 315px;">Logrhythm.Alarm.Event</td>
<td style="width: 87px;">String</td>
<td style="width: 338px;">Alarm event information.</td>
</tr>
<tr>
<td style="width: 315px;">Logrhythm.Alarm.ID</td>
<td style="width: 87px;">String</td>
<td style="width: 338px;">The alarm ID.</td>
</tr>
</tbody>
</table>
<p>&nbsp;</p>
<h5><a id="Command_Example_306"></a>Command Example</h5>
<pre>!lr-get-alarm-events alarm-id=1835</pre>
<h5><a id="Context_Example_309"></a>Context Example</h5>
<pre>{
    "Logrhythm.Alarm": {
        "Event": [
            {
                "originEntityId": 1, 
                "rootEntityId": 1, 
                "classificationTypeName": "Audit", 
                "logSourceName": "WIN-JSBOL5ERCQA MS Security Log", 
                "entityName": "Primary Site", 
                "originZone": 0, 
                "session": "0x0", 
                "normalDateMin": "2019-06-20 12:27:03", 
                "normalDate": "2019-06-20 12:27:03", 
                "vendorMessageId": "4625", 
                "entityId": 1, 
                "subject": "Unknown user name or bad password", 
                "priority": 3, 
                "sequenceNumber": 211157, 
                "impactedZoneName": "Unknown", 
                "originHostId": -1, 
                "mpeRuleId": 1060400, 
                "logSourceHostName": "WIN-JSBOL5ERCQA", 
                "logSourceHost": "WIN-JSBOL5ERCQA", 
                "originZoneName": "Unknown", 
                "logSourceType": 1000030, 
                "mpeRuleName": "EVID 4625 : User Logon Type 3: Wrong Password", 
                "impactedName": "win-jsbol5ercqa.demisto.lab", 
                "normalMsgDateMax": "2019-06-20 12:27:03", 
                "status": "0xC000006D", 
                "direction": 0, 
                "logSourceHostId": 1, 
                "ruleBlockNumber": 1, 
                "objectName": "0xC000006A", 
                "classificationId": 1040, 
                "impactedEntityId": 1, 
                "messageTypeEnum": 1, 
                "impactedEntityName": "Primary Site", 
                "reason": "Unknown user name or bad password", 
                "directionName": "Unknown", 
                "logDate": "2019-06-20 05:27:03", 
                "commonEventName": "User Logon Failure : Bad Password", 
                "impactedHostName": "", 
                "messageId": "1e28712d-4af4-4e82-9403-a2ebfda82f2d", 
                "originEntityName": "Primary Site", 
                "severity": "Information", 
                "count": 1, 
                "keyField": "messageId", 
                "rootEntityName": "Primary Site", 
                "parentProcessId": "0x0", 
                "protocolId": -1, 
                "logSourceTypeName": "MS Windows Event Logging - Security", 
                "object": "NtLmSsp", 
                "vendorInfo": "An account failed to log on", 
                "impactedHost": "win-jsbol5ercqa.demisto.lab", 
                "command": "3", 
                "commonEventId": 19812, 
                "login": "administrator", 
                "classificationName": "Authentication Failure", 
                "logSourceId": 1
            }, 
        ], 
        "ID": 1835
    }
}
</pre>
<h5><a id="Human_Readable_Output_378"></a>Human Readable Output</h5>
<h3><a id="Events_information_for_alarm_1835_379"></a>Events information for alarm 1835</h3>
<table class="table table-striped table-bordered" border="2">
<thead>
<tr>
<th>classificationId</th>
<th>classificationName</th>
<th>classificationTypeName</th>
<th>command</th>
<th>commonEventName</th>
<th>commonEventId</th>
<th>direction</th>
<th>directionName</th>
<th>impactedEntityId</th>
<th>impactedEntityName</th>
<th>impactedHost</th>
<th>impactedHostName</th>
<th>impactedName</th>
<th>impactedZoneName</th>
<th>logDate</th>
<th>mpeRuleId</th>
<th>mpeRuleName</th>
<th>object</th>
<th>objectName</th>
<th>originEntityName</th>
<th>originEntityId</th>
<th>originHostId</th>
<th>login</th>
<th>originZone</th>
<th>originZoneName</th>
<th>priority</th>
<th>protocolId</th>
<th>ruleBlockNumber</th>
<th>session</th>
<th>severity</th>
<th>subject</th>
<th>vendorMessageId</th>
<th>sequenceNumber</th>
<th>vendorInfo</th>
<th>parentProcessId</th>
<th>reason</th>
<th>status</th>
<th>keyField</th>
<th>count</th>
<th>entityId</th>
<th>rootEntityId</th>
<th>rootEntityName</th>
<th>entityName</th>
<th>logSourceHostId</th>
<th>logSourceHost</th>
<th>logSourceHostName</th>
<th>logSourceId</th>
<th>logSourceName</th>
<th>logSourceType</th>
<th>logSourceTypeName</th>
<th>messageId</th>
<th>messageTypeEnum</th>
<th>normalDate</th>
<th>normalMsgDateMax</th>
<th>normalDateMin</th>
</tr>
</thead>
<tbody>
<tr>
<td>1040</td>
<td>Authentication Failure</td>
<td>Audit</td>
<td>3</td>
<td>User Logon Failure : Bad Password</td>
<td>19812</td>
<td>0</td>
<td>Unknown</td>
<td>1</td>
<td>Primary Site</td>
<td>win-jsbol5ercqa.demisto.lab</td>
<td>&nbsp;</td>
<td>win-jsbol5ercqa.demisto.lab</td>
<td>Unknown</td>
<td>2019-06-20 05:27:03</td>
<td>1060400</td>
<td>EVID 4625 : User Logon Type 3: Wrong Password</td>
<td>NtLmSsp</td>
<td>0xC000006A</td>
<td>Primary Site</td>
<td>1</td>
<td>-1</td>
<td>administrator</td>
<td>0</td>
<td>Unknown</td>
<td>3</td>
<td>-1</td>
<td>1</td>
<td>0x0</td>
<td>Information</td>
<td>Unknown user name or bad password</td>
<td>4625</td>
<td>211157</td>
<td>An account failed to log on</td>
<td>0x0</td>
<td>Unknown user name or bad password</td>
<td>0xC000006D</td>
<td>messageId</td>
<td>1</td>
<td>1</td>
<td>1</td>
<td>Primary Site</td>
<td>Primary Site</td>
<td>1</td>
<td>WIN-JSBOL5ERCQA</td>
<td>WIN-JSBOL5ERCQA</td>
<td>1</td>
<td>WIN-JSBOL5ERCQA MS Security Log</td>
<td>1000030</td>
<td>MS Windows Event Logging - Security</td>
<td>1e28712d-4af4-4e82-9403-a2ebfda82f2d</td>
<td>1</td>
<td>2019-06-20 12:27:03</td>
<td>2019-06-20 12:27:03</td>
<td>2019-06-20 12:27:03</td>
</tr>
</tbody>
</table>
</div>
<p>&nbsp;</p></div>

          <div class="article-attachments">
            <ul class="attachments">
              
            </ul>
          </div>
        </div>
      </section>
