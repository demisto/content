<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the McAfee ESM v10 integration to get actionable intelligence and integrations to prioritize, investigate, and respond to threats.</p>
</div>
<div class="cl-preview-section">
<h2 id="configure-mcafee-esm-v10-on-demisto">Configure McAfee ESM-v10 on Demisto</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for McAfee ESM-v10.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Port</strong></li>
<li><strong>ESM IP (e.g. 78.125.0.209)</strong></li>
<li><strong>Username</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Fetch Types: cases, alarms, both (relevant only for fetch incident mode)</strong></li>
<li><strong>Start fetch after Case ID: (relevant only for fetch incident mode)</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Version: (one of 10.0, 10.1, 10.2, 10.3)</strong></li>
<li><strong>ESM time format, e.g., %Y/%m/%d %H:%M:%S. Select “auto-discovery” to extract the format automatically.</strong></li>
<li>__McAfee ESM Timezone in hours (e.g if ESM timezone is +0300 =&gt; then insert 3) __</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
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
<li><a href="#get-list-of-all-fields" target="_self">Get a list of all fields: esm-fetch-fields</a></li>
<li><a href="#perform-a-search-in-mcafee-esm" target="_self">Perform a search in McAfee ESM: esm-search</a></li>
<li><a href="#get-a-list-of-triggered-alarms" target="_self">Get a list of triggered alarms: esm-fetch-alarms</a></li>
<li><a href="#get-a-list-of-cases" target="_self">Get a list of cases: esm-get-case-list</a></li>
<li><a href="#add-a-case" target="_self">Add a case: esm-add-case</a></li>
<li><a href="#edit-a-case" target="_self">Edit a case: esm-edit-case</a></li>
<li><a href="#get-a-list-of-case-statuses" target="_self">Get a list of case statuses: esm-get-case-statuses</a></li>
<li><a href="#edit-the-status-of-a-case" target="_self">Edit the status of a case: esm-edit-case-status</a></li>
<li><a href="#get-details-of-a-case" target="_self">Get details of a case: esm-get-case-detail</a></li>
<li><a href="#get-details-of-a-case-event" target="_self">Get details of a case event: esm-get-case-event-list</a></li>
<li><a href="#add-a-status-to-a-case" target="_self">Add a status to a case: esm-add-case-status</a></li>
<li><a href="#remove-a-status-from-a-case" target="_self">Remove a status from a case: esm-delete-case-status</a></li>
<li><a href="#get-a-list-of-case-organizations" target="_self">Get a list of case organizations: esm-get-organization-list</a></li>
<li><a href="#get-a-list-of-all-users" target="_self">Get a list of all users: esm-get-user-list</a></li>
<li><a href="#mark-triggered-alarms-as-acknowledged" target="_self">Mark triggered alarms as acknowledged: esm-acknowledge-alarms</a></li>
<li><a href="#mark-triggered-alarms-as-unacknowledged" target="_self">Mark triggered alarms as unacknowledgedesm-unacknowledge-alarms</a></li>
<li><a href="#delete-triggered-alarms" target="_self">Delete triggered alarms: esm-delete-alarms</a></li>
<li><a href="#get-details-for-a-triggered-alarm" target="_self">Get details for a triggered alarm: esm-get-alarm-event-details</a></li>
<li><a href="#get-an-event-list-related-to-an-alarm" target="_self">Get an event list related to an alarm: esm-list-alarm-events</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-list-of-all-fields">1. Get list of all fields</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all fields (and the field type) that can be used in query filters.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-fetch-fields</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>esm-fetch-fields</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable">Human Readable</h5>
</div>
<div class="cl-preview-section">
<p>This output is truncated.</p>
</div>
<div class="cl-preview-section">
<h3 id="result">Result:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>name</th>
<th>types</th>
</tr>
</thead>
<tbody>
<tr>
<td>AppID</td>
<td>STRING</td>
</tr>
<tr>
<td>CommandID</td>
<td>STRING</td>
</tr>
<tr>
<td>DomainID</td>
<td>STRING</td>
</tr>
<tr>
<td>HostID</td>
<td>STRING</td>
</tr>
<tr>
<td>ObjectID</td>
<td>STRING</td>
</tr>
<tr>
<td>UserIDDst</td>
<td>STRING</td>
</tr>
<tr>
<td>UserIDSrc</td>
<td>STRING</td>
</tr>
<tr>
<td>URL</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Database_Name</td>
<td>STRING</td>
</tr>
<tr>
<td>Message_Text</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Response_Time</td>
<td>UINT32,UINT32</td>
</tr>
<tr>
<td>Application_Protocol</td>
<td>STRING</td>
</tr>
<tr>
<td>Object_Type</td>
<td>STRING</td>
</tr>
<tr>
<td>Filename</td>
<td>SSTRING</td>
</tr>
<tr>
<td>From</td>
<td>SSTRING</td>
</tr>
<tr>
<td>To</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Cc</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Bcc</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Subject</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Method</td>
<td>STRING</td>
</tr>
<tr>
<td>User_Agent</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Cookie</td>
<td>SSTRING</td>
</tr>
<tr>
<td>Referer</td>
<td>SSTRING</td>
</tr>
<tr>
<td>File_Operation</td>
<td>STRING</td>
</tr>
<tr>
<td>File_Operation_Succeeded</td>
<td>STRING</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="perform-a-search-in-mcafee-esm">2. Perform a search in McAfee ESM</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Performs a query against McAfee ESM.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-search</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 167px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">timeRange</td>
<td style="width: 502px;">The time period for the search</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 167px;">filters</td>
<td style="width: 502px;">Filter on the query results in the format EsmFilter. Should be a JSON string.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 167px;">queryType</td>
<td style="width: 502px;">Query type to preform, by default EVENT (other possible values are : FLOW/ASSET)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">maxWait</td>
<td style="width: 502px;">Maximum time to wait (in minutes), default is 30</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">customStart</td>
<td style="width: 502px;">if timeRange is CUSTOM, start time for the time range (e.g. 2017-06-01T12:48:16.734Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">customEnd</td>
<td style="width: 502px;">if timeRange is CUSTOM, end time for the time range (e.g. 2017-06-01T12:48:16.734Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">fields</td>
<td style="width: 502px;">The fields that will be selected when this query is executed.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-1">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-search timeRange=LAST_10_MINUTES filters=`[{"type": "EsmFieldFilter", "field": {"name": "SrcIP"}, "operator": "EQUALS", "values": [{"type": "EsmBasicValue", "value": "52.15.91.198"}]}]</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "SearchResults": [
        {
            "AlertIPSIDAlertID": "144115188075855872|10201"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 14:57:38"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10202"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 14:58:37"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10203"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 14:59:35"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10204"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:00:36"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10208"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:01:37"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10209"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:02:38"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10210"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:03:36"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10211"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:04:36"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10212"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:05:37"
        }, 
        {
            "ActionName": "success"
        }, 
        {
            "AlertIPSIDAlertID": "144115188075855872|10213"
        }, 
        {
            "AlertSrcIP": "52.15.91.198"
        }, 
        {
            "AlertSrcPort": "0"
        }, 
        {
            "AlertDstIP": "192.168.1.25"
        }, 
        {
            "AlertDstPort": "0"
        }, 
        {
            "AlertProtocol": "n/a"
        }, 
        {
            "AlertLastTime": "03/11/2019 15:06:38"
        }, 
        {
            "ActionName": "success"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="results">results:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>Alert.IPSIDAlertID</th>
<th>Alert.SrcIP</th>
<th>Alert.SrcPort</th>
<th>Alert.DstIP</th>
<th>Alert.DstPort</th>
<th>Alert.Protocol</th>
<th>Alert.LastTime</th>
<th>Action.Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>144115188075855872|10201</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 14:57:38</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10202</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 14:58:37</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10203</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 14:59:35</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10204</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:00:36</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10208</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:01:37</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10209</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:02:38</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10210</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:03:36</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10211</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:04:36</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10212</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:05:37</td>
<td>success</td>
</tr>
<tr>
<td>144115188075855872|10213</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
<td>n/a</td>
<td>03/11/2019 15:06:38</td>
<td>success</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-triggered-alarms">3. Get a list of triggered alarms</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves a list of triggered alarms.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-fetch-alarms</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 141px;"><strong>Argument Name</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 141px;">timeRange</td>
<td style="width: 528px;">The time period for the fetch.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 141px;">customStart</td>
<td style="width: 528px;">if timeRange is CUSTOM, start time for the time range (e.g. 2017-06-01T12:48:16.734Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">customEnd</td>
<td style="width: 528px;">if timeRange is CUSTOM, end time for the time range (e.g. 2017-06-01T12:48:16.734Z)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">assignedUser</td>
<td style="width: 528px;">user assigned to handle this triggered alarm (use ‘ME’ option to use instance user, or use format EsmUser (read more on that here - https://:/rs/esm/help/types/EsmUser)</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-2">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 322px;"><strong>Path</strong></th>
<th style="width: 87px;"><strong>Type</strong></th>
<th style="width: 331px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 322px;">Alarm.ID</td>
<td style="width: 87px;">number</td>
<td style="width: 331px;">Alarm ID</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.summary</td>
<td style="width: 87px;">string</td>
<td style="width: 331px;">Alarm summary</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.assignee</td>
<td style="width: 87px;">string</td>
<td style="width: 331px;">Alarm assignee</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.severity</td>
<td style="width: 87px;">number</td>
<td style="width: 331px;">Alarm severity</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.triggeredDate</td>
<td style="width: 87px;">date</td>
<td style="width: 331px;">Alarm triggered date</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.acknowledgedDate</td>
<td style="width: 87px;">date</td>
<td style="width: 331px;">Alarm acknowledged date</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.acknowledgedUsername</td>
<td style="width: 87px;">string</td>
<td style="width: 331px;">Alarm acknowledged username</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.alarmName</td>
<td style="width: 87px;">string</td>
<td style="width: 331px;">Alarm name</td>
</tr>
<tr>
<td style="width: 322px;">Alarm.conditionType</td>
<td style="width: 87px;">number</td>
<td style="width: 331px;">Alarm condition type</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-2">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-fetch-alarms timeRange="LAST_3_DAYS"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Alarm": [
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:48:10", 
            "acknowledgedDate": "03/11/2019 08:16:19", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "NGCP", 
            "ID": 25
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:44:40", 
            "acknowledgedDate": "03/11/2019 08:16:20", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "NGCP", 
            "ID": 24
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:41:10", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 23
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:27:39", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 22
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:24:39", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 21
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:21:39", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 20
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:19:09", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 19
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:14:09", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 18
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:07:09", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 17
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:06:09", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 16
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/11/2019 01:01:39", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 15
        }, 
        {
            "conditionType": 13, 
            "severity": 50, 
            "triggeredDate": "03/10/2019 17:01:30", 
            "acknowledgedDate": "", 
            "summary": "408944640 - Failed Login Attempts - 306-31", 
            "assignee": "NGCP", 
            "alarmName": "Failed Login Attempts", 
            "acknowledgedUsername": "", 
            "ID": 14
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="result-1">Result:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>conditionType</th>
<th>severity</th>
<th>triggeredDate</th>
<th>acknowledgedDate</th>
<th>summary</th>
<th>assignee</th>
<th>alarmName</th>
<th>ID</th>
<th>acknowledgedUsername</th>
</tr>
</thead>
<tbody>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:48:10</td>
<td>03/11/2019 08:16:19</td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>25</td>
<td>NGCP</td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:44:40</td>
<td>03/11/2019 08:16:20</td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>24</td>
<td>NGCP</td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:41:10</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>23</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:27:39</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>22</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:24:39</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>21</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:21:39</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>20</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:19:09</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>19</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:14:09</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>18</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:07:09</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>17</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:06:09</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>16</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/11/2019 01:01:39</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>15</td>
<td> </td>
</tr>
<tr>
<td>13</td>
<td>50</td>
<td>03/10/2019 17:01:30</td>
<td> </td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>NGCP</td>
<td>Failed Login Attempts</td>
<td>14</td>
<td> </td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-cases">4. Get a list of cases</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of cases from the McAfee ESM.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-case-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 520px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">since</td>
<td style="width: 520px;">Filter for a case opened before this date. Given in format " <time>",e.g. 1 day,30 minutes,2 weeks,6 months,1 year</time>
</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-3">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 253px;"><strong>Path</strong></th>
<th style="width: 111px;"><strong>Type</strong></th>
<th style="width: 376px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 253px;">Case.ID</td>
<td style="width: 111px;">number</td>
<td style="width: 376px;">The ID of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Summary</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The summary of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Status</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The status of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.OpenTime</td>
<td style="width: 111px;">date</td>
<td style="width: 376px;">The open time of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Severity</td>
<td style="width: 111px;">number</td>
<td style="width: 376px;">The severity of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Assignee</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The Assignee of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Organization</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The organization of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.EventList</td>
<td style="width: 111px;">unknown</td>
<td style="width: 376px;">List of case’s events</td>
</tr>
<tr>
<td style="width: 253px;">Case.Notes</td>
<td style="width: 111px;">unknown</td>
<td style="width: 376px;">List of case’s notes</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-3">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-get-case-list</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Case": [
        {
            "Status": "Open", 
            "Summary": "case to be deleted", 
            "OpenTime": "03/11/2019 08:15:02", 
            "ID": 1, 
            "Severity": 1
        }, 
        {
            "Status": "Open", 
            "Summary": "New Virus Detected", 
            "OpenTime": "03/11/2019 11:39:18", 
            "ID": 2, 
            "Severity": 1
        }, 
        {
            "Status": "Open", 
            "Summary": "408944640 - Failed Login Attempts - 306-31", 
            "OpenTime": "03/11/2019 11:41:02", 
            "ID": 3, 
            "Severity": 1
        }, 
        {
            "Status": "Open", 
            "Summary": "this is the first case", 
            "OpenTime": "03/11/2019 12:54:50", 
            "ID": 4, 
            "Severity": 1
        }, 
        {
            "Status": "Open", 
            "Summary": "this is the first case", 
            "OpenTime": "03/11/2019 13:27:22", 
            "ID": 5, 
            "Severity": 1
        }, 
        {
            "Status": "Open", 
            "Summary": "this is the first case", 
            "OpenTime": "03/11/2019 13:29:47", 
            "ID": 6, 
            "Severity": 1
        }, 
        {
            "Status": "Open", 
            "Summary": "this is the first case", 
            "OpenTime": "03/11/2019 13:33:13", 
            "ID": 7, 
            "Severity": 1
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="all-cases">All cases:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Summary</th>
<th>Status</th>
<th>Severity</th>
<th>OpenTime</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>case to be deleted</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 08:15:02</td>
</tr>
<tr>
<td>2</td>
<td>New Virus Detected</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 11:39:18</td>
</tr>
<tr>
<td>3</td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 11:41:02</td>
</tr>
<tr>
<td>4</td>
<td>this is the first case</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 12:54:50</td>
</tr>
<tr>
<td>5</td>
<td>this is the first case</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 13:27:22</td>
</tr>
<tr>
<td>6</td>
<td>this is the first case</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 13:29:47</td>
</tr>
<tr>
<td>7</td>
<td>this is the first case</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 13:33:13</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-a-case">5. Add a case</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds a case to McAfee ESM.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-add-case</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 745px;">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 528px;"><strong>Description</strong></th>
<th style="width: 63px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">summary</td>
<td style="width: 528px;">The name of the case</td>
<td style="width: 63px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">status</td>
<td style="width: 528px;">The status of the case (use <code>esm-get-case-statuses</code> to view all statuses)</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">assignee</td>
<td style="width: 528px;">The user the case is assigned to</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">severity</td>
<td style="width: 528px;">The severity of the case (1 - 100)</td>
<td style="width: 63px;">Optional</td>
</tr>
<tr>
<td style="width: 149px;">organization</td>
<td style="width: 528px;">The organization assigned to the case (use <code>esm-get-organization-list</code> to view all organizations)</td>
<td style="width: 63px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 249px;"><strong>Path</strong></th>
<th style="width: 115px;"><strong>Type</strong></th>
<th style="width: 376px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">Case.ID</td>
<td style="width: 115px;">number</td>
<td style="width: 376px;">The ID of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.Summary</td>
<td style="width: 115px;">string</td>
<td style="width: 376px;">The summary of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.Status</td>
<td style="width: 115px;">string</td>
<td style="width: 376px;">The status of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.OpenTime</td>
<td style="width: 115px;">date</td>
<td style="width: 376px;">The open time of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.Severity</td>
<td style="width: 115px;">number</td>
<td style="width: 376px;">The severity of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.Assignee</td>
<td style="width: 115px;">string</td>
<td style="width: 376px;">The assignee of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.Organization</td>
<td style="width: 115px;">string</td>
<td style="width: 376px;">The organization of the case</td>
</tr>
<tr>
<td style="width: 249px;">Case.EventList</td>
<td style="width: 115px;">unknown</td>
<td style="width: 376px;">List of case’s events</td>
</tr>
<tr>
<td style="width: 249px;">Case.Notes</td>
<td style="width: 115px;">unknown</td>
<td style="width: 376px;">List of case’s notes</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-4">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-add-case summary="this is the first case"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Case": [
        {
            "Status": "Open", 
            "OpenTime": "03/11/2019 15:07:22", 
            "Severity": 1, 
            "EventList": [], 
            "Notes": [
                {
                    "action": "Open", 
                    "content": "", 
                    "username": "NGCP", 
                    "changes": [], 
                    "timestamp": "03/11/2019 15:07:22(GMT)"
                }
            ], 
            "Summary": "this is the first case", 
            "Assignee": "NGCP", 
            "Organization": "None", 
            "ID": 8
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="new-case">New Case:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Summary</th>
<th>Status</th>
<th>Severity</th>
<th>OpenTime</th>
<th>Assignee</th>
<th>Organization</th>
<th>Event List</th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td>8</td>
<td>this is the first case</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 15:07:22</td>
<td>NGCP</td>
<td>None</td>
<td>[]</td>
<td>[{“action”: “Open”, “timestamp”: “03/11/2019 15:07:22(GMT)”, “username”: “NGCP”, “content”: “”, “changes”: []}]</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="edit-a-case">6. Edit a case</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Modifies an existing case.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-edit-case</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 143px;"><strong>Argument Name</strong></th>
<th style="width: 526px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 143px;">id</td>
<td style="width: 526px;">The ID of the case</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 143px;">summary</td>
<td style="width: 526px;">The name of the case</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">severity</td>
<td style="width: 526px;">The new severity of the case (1 - 100)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">assignee</td>
<td style="width: 526px;">The user that the case should be assigned to</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">status</td>
<td style="width: 526px;">The new status of the case (use the <code>esm-get-case-statuses</code> command to view all statuses)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 143px;">organization</td>
<td style="width: 526px;">The organization assigned to the case (use the <code>esm-get-organization-list</code> command to view all organizations)</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 253px;"><strong>Path</strong></th>
<th style="width: 111px;"><strong>Type</strong></th>
<th style="width: 376px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 253px;">Case.ID</td>
<td style="width: 111px;">number</td>
<td style="width: 376px;">The ID of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Summary</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The summary of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Status</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The status of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.OpenTime</td>
<td style="width: 111px;">date</td>
<td style="width: 376px;">The open time of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Severity</td>
<td style="width: 111px;">number</td>
<td style="width: 376px;">The severity of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Assignee</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The Assignee of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.Organization</td>
<td style="width: 111px;">string</td>
<td style="width: 376px;">The organization of the case</td>
</tr>
<tr>
<td style="width: 253px;">Case.EventList</td>
<td style="width: 111px;">unknown</td>
<td style="width: 376px;">List of case’s events</td>
</tr>
<tr>
<td style="width: 253px;">Case.Notes</td>
<td style="width: 111px;">unknown</td>
<td style="width: 376px;">List of case’s notes</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-edit-case id="2" summary="editing first case" severity="50" organization="LuthorCorp"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Case": [
        {
            "Status": "Open", 
            "OpenTime": "03/11/2019 11:39:18", 
            "Severity": 50, 
            "EventList": [], 
            "Notes": [
                {
                    "action": "Changes", 
                    "content": "Summary\n    old: New Virus Detected\n    new: editing first case\n\n  Severity\n    old: 1\n    new: 50", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Summary", 
                            "changes": [
                                "old: New Virus Detected", 
                                "new: editing first case"
                            ]
                        }, 
                        {
                            "changeType": "Severity", 
                            "changes": [
                                "old: 1", 
                                "new: 50"
                            ]
                        }
                    ], 
                    "timestamp": "03/11/2019 15:07:26(GMT)"
                }, 
                {
                    "action": "Changes", 
                    "content": "Summary\n    old: editing first case\n    new: New Virus Detected\n\n  Severity\n    old: 50\n    new: 1", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Summary", 
                            "changes": [
                                "old: editing first case", 
                                "new: New Virus Detected"
                            ]
                        }, 
                        {
                            "changeType": "Severity", 
                            "changes": [
                                "old: 50", 
                                "new: 1"
                            ]
                        }
                    ], 
                    "timestamp": "03/11/2019 15:01:28(GMT)"
                }, 
                {
                    "action": "Changes", 
                    "content": "Summary\n    old: New Virus Detection\n    new: editing first case\n\n  Severity\n    old: 1\n    new: 50", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Summary", 
                            "changes": [
                                "old: New Virus Detection", 
                                "new: editing first case"
                            ]
                        }, 
                        {
                            "changeType": "Severity", 
                            "changes": [
                                "old: 1", 
                                "new: 50"
                            ]
                        }
                    ], 
                    "timestamp": "03/11/2019 13:33:16(GMT)"
                }, 
                {
                    "action": "Changes", 
                    "content": "Summary\n    old: editing first New Virus Detection\n    new: New Virus Detection", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Summary", 
                            "changes": [
                                "old: editing first New Virus Detection", 
                                "new: New Virus Detection"
                            ]
                        }
                    ], 
                    "timestamp": "03/11/2019 13:31:59(GMT)"
                }, 
                {
                    "action": "Changes", 
                    "content": "Summary\n    old: editing first case\n    new: editing first New Virus Detection\n\n  Severity\n    old: 50\n    new: 1", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Summary", 
                            "changes": [
                                "old: editing first case", 
                                "new: editing first New Virus Detection"
                            ]
                        }, 
                        {
                            "changeType": "Severity", 
                            "changes": [
                                "old: 50", 
                                "new: 1"
                            ]
                        }
                    ], 
                    "timestamp": "03/11/2019 13:31:45(GMT)"
                }, 
                {
                    "action": "Changes", 
                    "content": "Summary\n    old: New Virus Detection\n    new: editing first case\n\n  Severity\n    old: 1\n    new: 50", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Summary", 
                            "changes": [
                                "old: New Virus Detection", 
                                "new: editing first case"
                            ]
                        }, 
                        {
                            "changeType": "Severity", 
                            "changes": [
                                "old: 1", 
                                "new: 50"
                            ]
                        }
                    ], 
                    "timestamp": "03/11/2019 13:27:25(GMT)"
                }, 
                {
                    "action": "Open", 
                    "content": "", 
                    "username": "NGCP", 
                    "changes": [], 
                    "timestamp": "03/11/2019 11:39:18(GMT)"
                }
            ], 
            "Summary": "editing first case", 
            "Assignee": "NGCP", 
            "Organization": "None", 
            "ID": 2
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="edited-case">Edited Case:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Summary</th>
<th>Status</th>
<th>Severity</th>
<th>OpenTime</th>
<th>Assignee</th>
<th>Organization</th>
<th>Event List</th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td>2</td>
<td>editing first case</td>
<td>Open</td>
<td>50</td>
<td>03/11/2019 11:39:18</td>
<td>NGCP</td>
<td>None</td>
<td>[]</td>
<td>[{“action”: “Changes”, “timestamp”: “03/11/2019 15:07:26(GMT)”, “username”: “NGCP”, “content”: “Summary\n old: New Virus Detected\n new: editing first case\n\n Severity\n old: 1\n new: 50”, “changes”: [{“changeType”: “Summary”, “changes”: [“old: New Virus Detected”, “new: editing first case”]}, {“changeType”: “Severity”, “changes”: [“old: 1”, “new: 50”]}]}, {“action”: “Changes”, “timestamp”: “03/11/2019 15:01:28(GMT)”, “username”: “NGCP”, “content”: “Summary\n old: editing first case\n new: New Virus Detected\n\n Severity\n old: 50\n new: 1”, “changes”: [{“changeType”: “Summary”, “changes”: [“old: editing first case”, “new: New Virus Detected”]}, {“changeType”: “Severity”, “changes”: [“old: 50”, “new: 1”]}]}, {“action”: “Changes”, “timestamp”: “03/11/2019 13:33:16(GMT)”, “username”: “NGCP”, “content”: “Summary\n old: New Virus Detection\n new: editing first case\n\n Severity\n old: 1\n new: 50”, “changes”: [{“changeType”: “Summary”, “changes”: [“old: New Virus Detection”, “new: editing first case”]}, {“changeType”: “Severity”, “changes”: [“old: 1”, “new: 50”]}]}, {“action”: “Changes”, “timestamp”: “03/11/2019 13:31:59(GMT)”, “username”: “NGCP”, “content”: “Summary\n old: editing first New Virus Detection\n new: New Virus Detection”, “changes”: [{“changeType”: “Summary”, “changes”: [“old: editing first New Virus Detection”, “new: New Virus Detection”]}]}, {“action”: “Changes”, “timestamp”: “03/11/2019 13:31:45(GMT)”, “username”: “NGCP”, “content”: “Summary\n old: editing first case\n new: editing first New Virus Detection\n\n Severity\n old: 50\n new: 1”, “changes”: [{“changeType”: “Summary”, “changes”: [“old: editing first case”, “new: editing first New Virus Detection”]}, {“changeType”: “Severity”, “changes”: [“old: 50”, “new: 1”]}]}, {“action”: “Changes”, “timestamp”: “03/11/2019 13:27:25(GMT)”, “username”: “NGCP”, “content”: “Summary\n old: New Virus Detection\n new: editing first case\n\n Severity\n old: 1\n new: 50”, “changes”: [{“changeType”: “Summary”, “changes”: [“old: New Virus Detection”, “new: editing first case”]}, {“changeType”: “Severity”, “changes”: [“old: 1”, “new: 50”]}]}, {“action”: “Open”, “timestamp”: “03/11/2019 11:39:18(GMT)”, “username”: “NGCP”, “content”: “”, “changes”: []}]</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-case-statuses">7. Get a list of case statuses</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of valid case statuses from McAfee ESM.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-case-statuses</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
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
<pre>!esm-get-case-statuses</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="result-2">Result:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>Is Default</th>
<th>Show In Case Pane</th>
</tr>
</thead>
<tbody>
<tr>
<td>2</td>
<td>Closed</td>
<td>false</td>
<td>false</td>
</tr>
<tr>
<td>1</td>
<td>Open</td>
<td>true</td>
<td>true</td>
</tr>
<tr>
<td>8</td>
<td>Pending</td>
<td>false</td>
<td>true</td>
</tr>
<tr>
<td>4</td>
<td>Research</td>
<td>false</td>
<td>false</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="edit-the-status-of-a-case">8. Edit the status of a case</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Modifies a case status.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-edit-case-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 209px;"><strong>Argument Name</strong></th>
<th style="width: 427px;"><strong>Description</strong></th>
<th style="width: 104px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 209px;">original_name</td>
<td style="width: 427px;">The name of the case status to edit</td>
<td style="width: 104px;">Required</td>
</tr>
<tr>
<td style="width: 209px;">new_name</td>
<td style="width: 427px;">The new name for the case status</td>
<td style="width: 104px;">Required</td>
</tr>
<tr>
<td style="width: 209px;">show_in_case_pane</td>
<td style="width: 427px;">Whether the status will be shown in the case pane</td>
<td style="width: 104px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-7">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-7">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-edit-case-status original_name=Research new_name=RnD</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Edit case status with ID: 4</p>
</div>
<div class="cl-preview-section">
<h3 id="get-details-of-a-case">9. Get details of a case</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns details about an existing case.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-case-detail</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 294px;"><strong>Argument Name</strong></th>
<th style="width: 285px;"><strong>Description</strong></th>
<th style="width: 161px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 294px;">id</td>
<td style="width: 285px;">The ID of the case</td>
<td style="width: 161px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-8">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 248px;"><strong>Path</strong></th>
<th style="width: 116px;"><strong>Type</strong></th>
<th style="width: 376px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 248px;">Case.ID</td>
<td style="width: 116px;">number</td>
<td style="width: 376px;">The ID of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.Summary</td>
<td style="width: 116px;">string</td>
<td style="width: 376px;">The summary of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.Status</td>
<td style="width: 116px;">string</td>
<td style="width: 376px;">The status of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.OpenTime</td>
<td style="width: 116px;">date</td>
<td style="width: 376px;">The open time of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.Severity</td>
<td style="width: 116px;">number</td>
<td style="width: 376px;">The severity of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.Assignee</td>
<td style="width: 116px;">string</td>
<td style="width: 376px;">The assignee of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.Organization</td>
<td style="width: 116px;">string</td>
<td style="width: 376px;">The organization of the case</td>
</tr>
<tr>
<td style="width: 248px;">Case.EventList</td>
<td style="width: 116px;">unknown</td>
<td style="width: 376px;">List of case’s events</td>
</tr>
<tr>
<td style="width: 248px;">Case.Notes</td>
<td style="width: 116px;">unknown</td>
<td style="width: 376px;">List of case’s notes</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-8">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-get-case-detail id=3</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Case": [
        {
            "Status": "Open", 
            "OpenTime": "03/11/2019 11:41:02", 
            "Severity": 1, 
            "EventList": [
                {
                    "message": "Failed User Logon", 
                    "lastTime": "03/11/2019 01:01:13", 
                    "id": {
                        "value": "144115188075855872|8850"
                    }
                }
            ], 
            "Notes": [
                {
                    "action": "Open", 
                    "content": "Events Added: 144115188075855872|8850\n    Events Removed:", 
                    "username": "NGCP", 
                    "changes": [
                        {
                            "changeType": "Events Added", 
                            "changes": [
                                "144115188075855872|8850"
                            ]
                        }, 
                        {
                            "changeType": "Events Removed", 
                            "changes": []
                        }
                    ], 
                    "timestamp": "03/11/2019 11:41:02(GMT)"
                }
            ], 
            "Summary": "408944640 - Failed Login Attempts - 306-31", 
            "Assignee": "NGCP", 
            "Organization": "None", 
            "ID": 3
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="case-3">Case 3:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Summary</th>
<th>Status</th>
<th>Severity</th>
<th>OpenTime</th>
<th>Assignee</th>
<th>Organization</th>
<th>Event List</th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr>
<td>3</td>
<td>408944640 - Failed Login Attempts - 306-31</td>
<td>Open</td>
<td>1</td>
<td>03/11/2019 11:41:02</td>
<td>NGCP</td>
<td>None</td>
<td>[{“message”: “Failed User Logon”, “lastTime”: “03/11/2019 01:01:13”, “id”: {“value”: “144115188075855872|8850”}}]</td>
<td>[{“action”: “Open”, “timestamp”: “03/11/2019 11:41:02(GMT)”, “username”: “NGCP”, “content”: “Events Added: 144115188075855872|8850\n Events Removed:”, “changes”: [{“changeType”: “Events Added”, “changes”: [“144115188075855872|8850”]}, {“changeType”: “Events Removed”, “changes”: []}]}]</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-details-of-a-case-event">10. Get details of a case event</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns case event details.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-9">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-case-event-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-9">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 219px;"><strong>Argument Name</strong></th>
<th style="width: 402px;"><strong>Description</strong></th>
<th style="width: 119px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 219px;">ids</td>
<td style="width: 402px;">CSV list of event IDs</td>
<td style="width: 119px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-9">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 258px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 415px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 258px;">CaseEvents.ID</td>
<td style="width: 67px;">string</td>
<td style="width: 415px;">The ID of the event</td>
</tr>
<tr>
<td style="width: 258px;">CaseEvents.LastTime</td>
<td style="width: 67px;">date</td>
<td style="width: 415px;">The last updated time of the event</td>
</tr>
<tr>
<td style="width: 258px;">CaseEvents.Message</td>
<td style="width: 67px;">string</td>
<td style="width: 415px;">The message of the event</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-9">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-get-case-event-list ids=144115188075855872|8850,144115188075855872|9718</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-6">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "CaseEvents": [
        {
            "Message": "Failed User Logon", 
            "LastTime": "03/11/2019 01:01:13", 
            "ID": "144115188075855872|8850"
        }, 
        {
            "Message": "User Logon", 
            "LastTime": "03/11/2019 11:09:37", 
            "ID": "144115188075855872|9718"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="case-events">Case Events:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>LastTime</th>
<th>Message</th>
</tr>
</thead>
<tbody>
<tr>
<td>144115188075855872|8850</td>
<td>03/11/2019 01:01:13</td>
<td>Failed User Logon</td>
</tr>
<tr>
<td>144115188075855872|9718</td>
<td>03/11/2019 11:09:37</td>
<td>User Logon</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="add-a-status-to-a-case">11. Add a status to a case</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds a case status to a case.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-10">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-add-case-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-10">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 185px;"><strong>Argument Name</strong></th>
<th style="width: 457px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 185px;">name</td>
<td style="width: 457px;">The name of the case status</td>
<td style="width: 98px;">Required</td>
</tr>
<tr>
<td style="width: 185px;">show_in_case_pane</td>
<td style="width: 457px;">Whether the status will be shown in case pane</td>
<td style="width: 98px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-10">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-10">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-add-case-status name=Deprecated</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-9">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Added case status : Deprecated</p>
</div>
<div class="cl-preview-section">
<h3 id="remove-a-status-from-a-case">12. Remove a status from a case</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes a case status from a case.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-11">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-delete-case-status</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-11">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 196px;"><strong>Argument Name</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
<th style="width: 114px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 196px;">name</td>
<td style="width: 430px;">The name of the case status to delete</td>
<td style="width: 114px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-11">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-11">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>esm-delete-case-status name=Pending</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-10">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Deleted case status with ID: 8</p>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-case-organizations">13. Get a list of case organizations</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list case organizations.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-12">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-organization-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-12">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-12">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 748px;">
<thead>
<tr>
<th style="width: 326px;"><strong>Path</strong></th>
<th style="width: 112px;"><strong>Type</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 326px;">Organizations.ID</td>
<td style="width: 112px;">number</td>
<td style="width: 302px;">Organization ID</td>
</tr>
<tr>
<td style="width: 326px;">Organizations.Name</td>
<td style="width: 112px;">string</td>
<td style="width: 302px;">Organization Name</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-12">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-get-organization-list</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-7">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "Organizations": [
        {
            "ID": 1, 
            "Name": "None"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-11">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="organizations">Organizations:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Name</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>None</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-users">14. Get a list of all users</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns a list of all users.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-13">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-user-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-13">Input</h5>
</div>
<div class="cl-preview-section">
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="context-output-13">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 216px;"><strong>Path</strong></th>
<th style="width: 104px;"><strong>Type</strong></th>
<th style="width: 420px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 216px;">EsmUser.ID</td>
<td style="width: 104px;">number</td>
<td style="width: 420px;">The ID of the user</td>
</tr>
<tr>
<td style="width: 216px;">EsmUser.Name</td>
<td style="width: 104px;">string</td>
<td style="width: 420px;">The ESM user name</td>
</tr>
<tr>
<td style="width: 216px;">EsmUser.Email</td>
<td style="width: 104px;">string</td>
<td style="width: 420px;">The email address of the user</td>
</tr>
<tr>
<td style="width: 216px;">EsmUser.SMS</td>
<td style="width: 104px;">string</td>
<td style="width: 420px;">The SMS details of the user</td>
</tr>
<tr>
<td style="width: 216px;">EsmUser.IsMaster</td>
<td style="width: 104px;">boolean</td>
<td style="width: 420px;">Whether the user is a master user</td>
</tr>
<tr>
<td style="width: 216px;">EsmUser.IsAdmin</td>
<td style="width: 104px;">boolean</td>
<td style="width: 420px;">Whether the user is an admin</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-13">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-get-user-list</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-8">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "EsmUser": [
        {
            "IsMaster": true, 
            "Name": "NGCP", 
            "SMS": "", 
            "ID": 1, 
            "IsAdmin": false, 
            "Email": ""
        }, 
        {
            "IsMaster": false, 
            "Name": "POLICY", 
            "SMS": "", 
            "ID": 3, 
            "IsAdmin": false, 
            "Email": ""
        }, 
        {
            "IsMaster": false, 
            "Name": "REPORT", 
            "SMS": "", 
            "ID": 2, 
            "IsAdmin": false, 
            "Email": ""
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-12">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="users">Users:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>Email</th>
<th>SMS</th>
<th>IsMaster</th>
<th>IsAdmin</th>
</tr>
</thead>
<tbody>
<tr>
<td>1</td>
<td>NGCP</td>
<td> </td>
<td> </td>
<td>true</td>
<td>false</td>
</tr>
<tr>
<td>3</td>
<td>POLICY</td>
<td> </td>
<td> </td>
<td>false</td>
<td>false</td>
</tr>
<tr>
<td>2</td>
<td>REPORT</td>
<td> </td>
<td> </td>
<td>false</td>
<td>false</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="mark-triggered-alarms-as-acknowledged">15. Mark triggered alarms as acknowledged</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Marks triggered alarms as acknowledged.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-14">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-acknowledge-alarms</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-14">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 160px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 83px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 160px;">alarmIds</td>
<td style="width: 497px;">A CSV list of triggered alarm IDs to be marked acknowledged </td>
<td style="width: 83px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-14">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-14">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-acknowledge-alarms alarmIds=2,5,6</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-13">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Alarms has been Acknowledged.</p>
</div>
<div class="cl-preview-section">
<h3 id="mark-triggered-alarms-as-unacknowledged">16. Mark triggered alarms as unacknowledged</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Marks triggered alarms as unacknowledged.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-15">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-unacknowledge-alarms</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-15">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 497px;"><strong>Description</strong></th>
<th style="width: 81px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">alarmIds</td>
<td style="width: 497px;">A CSV list of triggered alarm IDs to be marked unacknowledged</td>
<td style="width: 81px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-15">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-15">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-unacknowledge-alarms alarmIds="1,8,7"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-14">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Alarms has been Unacknowledged.</p>
</div>
<div class="cl-preview-section">
<h3 id="delete-triggered-alarms">17. Delete triggered alarms</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Deletes triggered alarms.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-16">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-delete-alarms</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-16">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 187px;"><strong>Argument Name</strong></th>
<th style="width: 452px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 187px;">alarmIds</td>
<td style="width: 452px;">A CSV list of triggered alarm IDs to be deleted</td>
<td style="width: 101px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-16">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-16">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-delete-alarms alarmIds=26</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-15">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Alarms has been Deleted.</p>
</div>
<div class="cl-preview-section">
<h3 id="get-details-for-a-triggered-alarm">18. Get details for a triggered alarm</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns details for a triggered alarm.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-17">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-get-alarm-event-details</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-17">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 523px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">eventId</td>
<td style="width: 523px;">The event to get the details for. The ID can be retrieved from the esm-list-alarm-events command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-17">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 339px;"><strong>Path</strong></th>
<th style="width: 85px;"><strong>Type</strong></th>
<th style="width: 316px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 339px;">EsmAlarmEvent.ID</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Event ID</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.SubType</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Event type</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Severity</td>
<td style="width: 85px;">number</td>
<td style="width: 316px;">Event severity</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Message</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Event message</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.LastTime</td>
<td style="width: 85px;">date</td>
<td style="width: 316px;">Event time</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.SrcIP</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Source IP of the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.DstIP</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Destination IP of the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Cases</td>
<td style="width: 85px;">unknown</td>
<td style="width: 316px;">A list of related cases to the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Cases.ID</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Case ID</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Cases.OpenTime</td>
<td style="width: 85px;">date</td>
<td style="width: 316px;">Case creation time</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Cases.Severity</td>
<td style="width: 85px;">number</td>
<td style="width: 316px;">Case severity</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Cases.Status</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Case status</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.Cases.Summary</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Case summary</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.DstMac</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Destination MAC of the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.SrcMac</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Source MAC of the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.DstPort</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Destination port of the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.SrcPort</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Source port of the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.FirstTime</td>
<td style="width: 85px;">date</td>
<td style="width: 316px;">The first time for the event</td>
</tr>
<tr>
<td style="width: 339px;">EsmAlarmEvent.NormalizedDescription</td>
<td style="width: 85px;">string</td>
<td style="width: 316px;">Normalized description of the event</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-17">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-get-alarm-event-details eventId="144115188075855872|9718"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-9">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "EsmAlarmEvent": [
        {
            "DstIP": "192.168.1.25", 
            "FirstTime": "03/11/2019 11:09:37", 
            "Severity": 19, 
            "DstPort": "0", 
            "SrcPort": "0", 
            "DstMac": "00:00:00:00:00:00", 
            "SubType": "success", 
            "SrcIP": "52.15.91.198", 
            "Message": "User Logon", 
            "LastTime": "03/11/2019 11:09:37", 
            "ID": "144115188075855872|9718", 
            "NormalizedDescription": "The Login category indicates events related to logging in to hosts or services.  Belongs to Authentication: The authentication category indicates events relating to system access.", 
            "SrcMac": "00:00:00:00:00:00"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-16">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="alarm-events">Alarm Events:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>SubType</th>
<th>Severity</th>
<th>Message</th>
<th>LastTime</th>
<th>SrcIP</th>
<th>SrcPort</th>
<th>DstIP</th>
<th>DstPort</th>
</tr>
</thead>
<tbody>
<tr>
<td>144115188075855872|9718</td>
<td>success</td>
<td>19</td>
<td>User Logon</td>
<td>03/11/2019 11:09:37</td>
<td>52.15.91.198</td>
<td>0</td>
<td>192.168.1.25</td>
<td>0</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h3 id="get-an-event-list-related-to-an-alarm">19. Get an event list related to an alarm</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns an event list related to an alarm.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-18">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>esm-list-alarm-events</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-18">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 534px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">alarmId</td>
<td style="width: 534px;">The alarm to get the details for. The ID can be retrieved from the esm-fetch-alarms command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="context-output-18">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 320px;"><strong>Path</strong></th>
<th style="width: 92px;"><strong>Type</strong></th>
<th style="width: 328px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 320px;">EsmAlarmEvent.ID</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Event ID</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.SubType</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Event type</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Severity</td>
<td style="width: 92px;">number</td>
<td style="width: 328px;">Event severity</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Message</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Event message</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.LastTime</td>
<td style="width: 92px;">date</td>
<td style="width: 328px;">Event time</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.SrcIP</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Source IP of the event</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.DstIP</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Destination IP of the event</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Cases</td>
<td style="width: 92px;">unknown</td>
<td style="width: 328px;">A list of related cases to the event</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Cases.ID</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Case ID</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Cases.OpenTime</td>
<td style="width: 92px;">date</td>
<td style="width: 328px;">Case creation time</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Cases.Severity</td>
<td style="width: 92px;">number</td>
<td style="width: 328px;">Case severity</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Cases.Status</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Case status</td>
</tr>
<tr>
<td style="width: 320px;">EsmAlarmEvent.Cases.Summary</td>
<td style="width: 92px;">string</td>
<td style="width: 328px;">Case summary</td>
</tr>
</tbody>
</table>
</div>
</div>
<p> </p>
<div class="cl-preview-section">
<h5 id="command-example-18">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!esm-list-alarm-events alarmId="24"</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-10">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "EsmAlarmEvent": [
        {
            "DstIP": "192.168.1.25", 
            "Severity": 25, 
            "SubType": "failure", 
            "SrcIP": "186.29.149.40", 
            "Message": "Failed User Logon", 
            "LastTime": "03/11/2019 01:44:27", 
            "ID": "144115188075855872|8919"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-17">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="alarm-events-1">Alarm Events:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table>
<thead>
<tr>
<th>ID</th>
<th>SubType</th>
<th>Severity</th>
<th>Message</th>
<th>LastTime</th>
<th>SrcIP</th>
<th>SrcPort</th>
<th>DstIP</th>
<th>DstPort</th>
</tr>
</thead>
<tbody>
<tr>
<td>144115188075855872|8919</td>
<td>failure</td>
<td>25</td>
<td>Failed User Logon</td>
<td>03/11/2019 01:44:27</td>
<td>186.29.149.40</td>
<td> </td>
<td>192.168.1.25</td>
<td> </td>
</tr>
</tbody>
</table>
</div>
</div>