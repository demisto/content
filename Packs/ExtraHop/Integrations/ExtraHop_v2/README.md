<p>
  Network detection and response. Complete visibility of network communications at enterprise scale, real-time threat detections backed by machine learning, and guided investigation workflows that simplify response.
</p>
<h2>ExtraHop Reveal(x) Playbooks</h2>
<ul>
  <li>ExtraHop - Default</li>
  <li>ExtraHop - CVE-2019-0708 (BlueKeep)</li>
  <li>ExtraHop - Ticket Tracking</li>
  <li>ExtraHop - Get Peers by Host</li>
</ul>
<h2>Use Cases</h2>
<ul>
<li>Create incidents for every detection that ExtraHop Reveal(x) surfaces in real-time.</li>
<li>Enable guided investigation and response through playbooks and automation scripts.</li>
<li>Interrogate the ExtraHop Reveal(x) REST API using the simple and powerful Demisto CLI.</li>
</ul><h2>Detailed Description</h2>
<p>Visit the <a href="https://www.extrahop.com/customers/community/bundles/extrahop/demisto-integration/">ExtraHop + Demisto Setup Guide</a> for detailed integration instructions.</p>
<h2>Fetch Incidents</h2>
<p>Incidents are pushed in via the Demisto REST API by a trigger running on the ExtraHop Reveal(x) appliance.</p>
<h2>Configure ExtraHop Reveal(x) on Demisto</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for ExtraHop Reveal(x).</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a name to identify the ExtraHop appliance.</li>
      <li><strong>API Key</strong>: the value of the ExtraHop API key that was generated while configuring the ExtraHop appliance.</li>
      <li><strong>URL</strong>: the URL of the ExtraHop appliance including the protocol (e.g. https://).</li>
      <li><strong>Trust any certificate</strong>: whether to verify the SSL certificate on REST API requests.</li>
      <li><strong>Use System Proxy</strong>: whether to use the system configured proxy for requests.</li>
    </ul>
  </li>
</ol>
<ol start="4">
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance by querying the ExtraHop version from the REST API. If the test fails, check the instance configuration including the Trust any certificate (Not Secure) setting for correctness.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>Get all alert rules: extrahop-get-alert-rules</li>
  <li>Query records: extrahop-query-records</li>
  <li>Search for devices: extrahop-device-search</li>
  <li>Add or remove devices from the watchlist: extrahop-edit-watchlist</li>
  <li>Get all devices on the watchlist: extrahop-get-watchlist</li>
  <li>Create a new alert rule: extrahop-create-alert-rule</li>
  <li>Modify an alert rule: extrahop-edit-alert-rule</li>
  <li>Link an ExtraHop Detection to a Demisto Investigation: extrahop-track-ticket</li>
  <li>Get all peers for a device: extrahop-get-peers</li>
  <li>Get all active network protocols for a device: extrahop-get-protocols</li>
  <li>Add or remove a tag from devices: extrahop-tag-devices</li>
  <li>Get a link to a Live Activity Map: extrahop-get-activity-map</li>
  <li>Search for specific packets: extrahop-search-packets</li>
</ol>
<h3>1. Get all alert rules</h3>
<!-- <hr> -->
<p>Get all alert rules from ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-get-alert-rules</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>

  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Extrahop.Alert.Operator</td>
      <td>String</td>
      <td>b'The logical operator applied when comparing the value of the operand field to alert conditions.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.FieldName</td>
      <td>String</td>
      <td>b'The name of the monitored metric.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.NotifySnmp</td>
      <td>Boolean</td>
      <td>b'Indicates whether to send an SNMP trap when an alert is generated. '</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Operand</td>
      <td>String</td>
      <td>b'The value to compare against alert conditions.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.IntervalLength</td>
      <td>Number</td>
      <td>b'The length of the alert interval, expressed in seconds.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Author</td>
      <td>String</td>
      <td>b'The name of the user that created the alert. '</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Name</td>
      <td>String</td>
      <td>b'The unique, friendly name for the alert.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.FieldName2</td>
      <td>String</td>
      <td>b'The second monitored metric when applying a ratio.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.RefireInterval</td>
      <td>Number</td>
      <td>b'The time interval in which alert conditions are monitored, expressed in seconds.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.ModTime</td>
      <td>Number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch. '</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Units</td>
      <td>String</td>
      <td>b'The interval in which to evaluate the alert condition.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.ApplyAll</td>
      <td>Boolean</td>
      <td>b'Indicates whether the alert is assigned to all available data sources.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Type</td>
      <td>String</td>
      <td>b'The type of alert.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.FieldOp</td>
      <td>String</td>
      <td>b'The type of comparison between the "field_name" and "field_name2" fields when applying a ratio.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Id</td>
      <td>Number</td>
      <td>b'The unique identifier for the alert.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Disabled</td>
      <td>Boolean</td>
      <td>b'Indicates whether the alert is disabled.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Description</td>
      <td>String</td>
      <td>b'An optional description for the alert.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.Severity</td>
      <td>Number</td>
      <td>b'The severity level of the alert.'</td>
    </tr>
    <tr>
      <td>Extrahop.Alert.StatName</td>
      <td>String</td>
      <td>b'The statistic name for the alert.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-get-alert-rules</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "Alert": [
            {
                "ApplyAll": false,
                "Author": "ExtraHop",
                "Description": "Alert triggered when ratio of web errors is greater than 5%.",
                "Disabled": true,
                "FieldName": "rsp_error",
                "FieldName2": "rsp",
                "FieldOp": "/",
                "Id": 11,
                "IntervalLength": 30,
                "ModTime": 1522964293585,
                "Name": "Web Error Ratio - Red",
                "NotifySnmp": false,
                "Operand": ".05",
                "Operator": ">",
                "RefireInterval": 300,
                "Severity": 1,
                "StatName": "extrahop.application.http",
                "Type": "threshold",
                "Units": "none"
            },
            {
                "ApplyAll": false,
                "Author": "ExtraHop",
                "Description": "Alert triggered when ratio of web errors is greater than 1%.",
                "Disabled": true,
                "FieldName": "rsp_error",
                "FieldName2": "rsp",
                "FieldOp": "/",
                "Id": 12,
                "IntervalLength": 30,
                "ModTime": 1522964293596,
                "Name": "Web Error Ratio - Orange",
                "NotifySnmp": false,
                "Operand": ".01",
                "Operator": ">",
                "RefireInterval": 300,
                "Severity": 3,
                "StatName": "extrahop.application.http",
                "Type": "threshold",
                "Units": "none"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Found 2 Alert(s)</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Apply All</strong></th>
      <th><strong>Author</strong></th>
      <th><strong>Description</strong></th>
      <th><strong>Disabled</strong></th>
      <th><strong>Field Name</strong></th>
      <th><strong>Field Name2</strong></th>
      <th><strong>Field Op</strong></th>
      <th><strong>Id</strong></th>
      <th><strong>Interval Length</strong></th>
      <th><strong>Mod Time</strong></th>
      <th><strong>Name</strong></th>
      <th><strong>Notify Snmp</strong></th>
      <th><strong>Operand</strong></th>
      <th><strong>Operator</strong></th>
      <th><strong>Refire Interval</strong></th>
      <th><strong>Severity</strong></th>
      <th><strong>Stat Name</strong></th>
      <th><strong>Type</strong></th>
      <th><strong>Units</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>false</td>
      <td>ExtraHop</td>
      <td>Alert triggered when ratio of web errors is greater than 5%.</td>
      <td>true</td>
      <td>rsp_error</td>
      <td>rsp</td>
      <td>/</td>
      <td>11</td>
      <td>30</td>
      <td>1522964293585</td>
      <td>Web Error Ratio - Red</td>
      <td>false</td>
      <td>.05</td>
      <td>></td>
      <td>300</td>
      <td>1</td>
      <td>extrahop.application.http</td>
      <td>threshold</td>
      <td>none</td>
    </tr>
    <tr>
      <td>false</td>
      <td>ExtraHop</td>
      <td>Alert triggered when ratio of web errors is greater than 1%.</td>
      <td>true</td>
      <td>rsp_error</td>
      <td>rsp</td>
      <td>/</td>
      <td>12</td>
      <td>30</td>
      <td>1522964293596</td>
      <td>Web Error Ratio - Orange</td>
      <td>false</td>
      <td>.01</td>
      <td>></td>
      <td>300</td>
      <td>3</td>
      <td>extrahop.application.http</td>
      <td>threshold</td>
      <td>none</td>
    </tr>
  </tbody>
</table>

</p>

<h3>2. Query records</h3>
<!-- <hr> -->
<p>Query records from ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-query-records</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>query_from</td>
      <td>The beginning timestamp of the time range the query will search, expressed in milliseconds since the epoch. A negative value specifies that the search will begin with records created at a time in the past relative to the current time. For example, specify -10m to begin the search with records created 10 minutes before the time of the request. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>query_until</td>
      <td>The ending timestamp of the time range the query will search, expressed in milliseconds since the epoch. A 0 value specifies that the search will end with records created at the time of the request. A negative value specifies that the search will end with records created at a time in the past relative to the current time. For example, specify -5m to end the search with records created 5 minutes before the time of the request. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of entries to return.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>offset</td>
      <td>The number of records to skip in the query results.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field1</td>
      <td>The name of the field in the record to be filtered. The query compares field1 to value1 and applies the compare method specified by the operator1 parameter. If the specified field name is ".any", the union of all field values will be searched. If the specified field name is ".ipaddr" or ".port", the client, server, sender, and receiver roles are included in the search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operator1</td>
      <td>The compare method applied when matching value1 against the field1 contents.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>value1</td>
      <td>The value that the query attempts to match. The query compares this value to the contents of the field1 parameter and applies the compare method specified by the operator1 parameter.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field2</td>
      <td>The name of the field in the record to be filtered. The query compares field2 to value2 and applies the compare method specified by the operator2 parameter. If the specified field name is ".any", the union of all field values will be searched. If the specified field name is ".ipaddr" or ".port", the client, server, sender, and receiver roles are included in the search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operator2</td>
      <td>The compare method applied when matching value2 against the field2 contents.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>value2</td>
      <td>The value that the query attempts to match. The query compares this value to the contents of the field2 parameter and applies the compare method specified by the operator2 parameter.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>match_type</td>
      <td>The match operator to use when chaining the search fields of 1 and 2 together. For example, to find HTTP records with status code 500 or a processing time greater than 100ms (set match_type=or, field1=statusCode, operator1==, value1=500, field2=processingTime, operator2=> value2=100, types=http).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>types</td>
      <td>A list of one or more record formats for the query to filter on, comma separated. The query returns only records that match the specified formats.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ExtraHop.Record.Type</td>
      <td>string</td>
      <td>b'The record format.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.timestamp</td>
      <td>Number</td>
      <td>b'The timestamp of the item.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.detection</td>
      <td>string</td>
      <td>b'The detection type that committed the record.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ex.isSuspicious</td>
      <td>Boolean</td>
      <td>b'Marked as suspicious by Threat Intelligence.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.accessTime</td>
      <td>Number</td>
      <td>b'Access Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ackCode</td>
      <td>String</td>
      <td>b'Ack Code'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ackId</td>
      <td>String</td>
      <td>b'Ack ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.adminQueue</td>
      <td>String</td>
      <td>b'Admin Queue'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.age</td>
      <td>Number</td>
      <td>b'Age'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.alertCode</td>
      <td>Number</td>
      <td>b'Alert Code'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.alertLevel</td>
      <td>String</td>
      <td>b'Alert Level'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.answer</td>
      <td>Unknown</td>
      <td>b'Answer'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.answers</td>
      <td>Unknown</td>
      <td>b'Answers'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.appName</td>
      <td>String</td>
      <td>b'Application Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.application</td>
      <td>Unknown</td>
      <td>b'Application'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.args</td>
      <td>String</td>
      <td>b'Arguments'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.authDomain</td>
      <td>String</td>
      <td>b'Authentication Domain'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.authMethod</td>
      <td>String</td>
      <td>b'Authentication Method'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.authResult</td>
      <td>Number</td>
      <td>b'Auth Result'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.authType</td>
      <td>Number</td>
      <td>b'Auth Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.authenticator</td>
      <td>String</td>
      <td>b'Authenticator'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.bindDN</td>
      <td>String</td>
      <td>b'Bind Distinguished Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.bytes</td>
      <td>Number</td>
      <td>b'Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cName</td>
      <td>String</td>
      <td>b'Canonical Endpoint'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cNameType</td>
      <td>String</td>
      <td>b'Client Name Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cNames</td>
      <td>String</td>
      <td>b'Client Name Components'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cRealm</td>
      <td>String</td>
      <td>b'Client Realm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.callId</td>
      <td>String</td>
      <td>b'Call ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateFingerprint</td>
      <td>String</td>
      <td>b'Certificate Fingerprint'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateIsSelfSigned</td>
      <td>Boolean</td>
      <td>b'Certificate Self Signed'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateIssuer</td>
      <td>String</td>
      <td>b'Certificate Issuer'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateKeySize</td>
      <td>Number</td>
      <td>b'Certificate Key Size'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateNotAfter</td>
      <td>Number</td>
      <td>b'Certificate Not After'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateNotBefore</td>
      <td>Number</td>
      <td>b'Certificate Not Before'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateSignatureAlgorithm</td>
      <td>String</td>
      <td>b'Certificate Signature Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateSubject</td>
      <td>String</td>
      <td>b'Certificate Subject'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.certificateSubjectAlternativeNames</td>
      <td>String</td>
      <td>b'Certificate Subject Alternative Names'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.channel</td>
      <td>String</td>
      <td>b'Channel'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cipherSuite</td>
      <td>String</td>
      <td>b'Cipher Suite'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.client.type</td>
      <td>String</td>
      <td>b'Client Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.client.value</td>
      <td>String</td>
      <td>b'Client Discovery ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientAddr.type</td>
      <td>String</td>
      <td>b'Client IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientAddr.value</td>
      <td>String</td>
      <td>b'Client IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientBuild</td>
      <td>String</td>
      <td>b'Client Build'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientBytes</td>
      <td>Number</td>
      <td>b'Client Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientCGPMsgCount</td>
      <td>Number</td>
      <td>b'Client CGP Messages'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientCertificateRequested</td>
      <td>Boolean</td>
      <td>b'Client Certificate Requested'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientCipherAlgorithm</td>
      <td>String</td>
      <td>b'Client Cipher Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientCompressionAlgorithm</td>
      <td>String</td>
      <td>b'Client Compression Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientImplementation</td>
      <td>String</td>
      <td>b'Client Implementation'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientL2Bytes</td>
      <td>Number</td>
      <td>b'Client L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientLatency</td>
      <td>Number</td>
      <td>b'Client Latency'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientMacAlgorithm</td>
      <td>String</td>
      <td>b'Client MAC Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientMachine</td>
      <td>String</td>
      <td>b'Client Machine'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientMsgCount</td>
      <td>Number</td>
      <td>b'Client Messages'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientName</td>
      <td>String</td>
      <td>b'Client Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientPkts</td>
      <td>Number</td>
      <td>b'Client Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientPort</td>
      <td>Number</td>
      <td>b'Client Port'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientPrincipalName</td>
      <td>String</td>
      <td>b'Client Principal Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientRTO</td>
      <td>Number</td>
      <td>b'Client RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientReqDelay</td>
      <td>Number</td>
      <td>b'Client Request Delay'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientType</td>
      <td>String</td>
      <td>b'ICA Client Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientVersion</td>
      <td>String</td>
      <td>b'Client Version'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.clientZeroWnd</td>
      <td>Number</td>
      <td>b'Client Zero Windows'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.collection</td>
      <td>String</td>
      <td>b'Collection'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.command</td>
      <td>String</td>
      <td>b'Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.contentType</td>
      <td>String</td>
      <td>b'Content Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.conversationId</td>
      <td>Number</td>
      <td>b'Conversation ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cookie</td>
      <td>String</td>
      <td>b'Cookie'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.correlationId</td>
      <td>String</td>
      <td>b'Correlation ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.cwd</td>
      <td>String</td>
      <td>b'Current Working Directory'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.dataSize</td>
      <td>Number</td>
      <td>b'Data Size'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.database</td>
      <td>String</td>
      <td>b'Database'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.deltaBytes</td>
      <td>Number</td>
      <td>b'Delta Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.deltaPkts</td>
      <td>Number</td>
      <td>b'Delta Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.desktopHeight</td>
      <td>Number</td>
      <td>b'Desktop Height'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.desktopWidth</td>
      <td>Number</td>
      <td>b'Desktop Width'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.destination</td>
      <td>String</td>
      <td>b'Destination'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.dn</td>
      <td>String</td>
      <td>b'Distinguished Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.domain</td>
      <td>String</td>
      <td>b'Domain'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.drops</td>
      <td>Number</td>
      <td>b'Drops'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.dscpName</td>
      <td>String</td>
      <td>b'DSCP'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.dstQueueMgr</td>
      <td>String</td>
      <td>b'Destination Queue Manager'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.dups</td>
      <td>Number</td>
      <td>b'Dups'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.duration</td>
      <td>Number</td>
      <td>b'Duration'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.egressInterface</td>
      <td>Unknown</td>
      <td>b'Egress Interface'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.error</td>
      <td>String</td>
      <td>b'Error'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.errorDetail</td>
      <td>String</td>
      <td>b'Error Detail'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.expiration</td>
      <td>Number</td>
      <td>b'Expiration'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.first</td>
      <td>Number</td>
      <td>b'First'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.flowId</td>
      <td>String</td>
      <td>b'Flow'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.format</td>
      <td>String</td>
      <td>b'Format'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.frameCutDuration</td>
      <td>Number</td>
      <td>b'Frame Cut Duration'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.frameSendDuration</td>
      <td>Number</td>
      <td>b'Frame Send Duration'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.from</td>
      <td>String</td>
      <td>b'From'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.functionId</td>
      <td>Number</td>
      <td>b'Function ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.functionName</td>
      <td>String</td>
      <td>b'Function Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.fwdReqClientAddr.type</td>
      <td>String</td>
      <td>b'Forwarded Request Client IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.fwdReqClientAddr.value</td>
      <td>String</td>
      <td>b'Forwarded Request Client IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.fwdReqHost</td>
      <td>String</td>
      <td>b'Forwarded Request Host'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.fwdReqIsEncrypted</td>
      <td>Boolean</td>
      <td>b'Forwarded Request Is Encrypted'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.fwdReqServerName</td>
      <td>String</td>
      <td>b'Forwarded Request Server Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.fwdReqServerPort</td>
      <td>Number</td>
      <td>b'Forwarded Request Server Port'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.gwAddr.type</td>
      <td>String</td>
      <td>b'Gateway IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.gwAddr.value</td>
      <td>String</td>
      <td>b'Gateway IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.handshakeTime</td>
      <td>Number</td>
      <td>b'Handshake Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.hasSDP</td>
      <td>Boolean</td>
      <td>b'Has SDP'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.hassh</td>
      <td>String</td>
      <td>b'HASSH'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.hasshServer</td>
      <td>String</td>
      <td>b'HASSH Server'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.heartbeatPayloadLength</td>
      <td>Number</td>
      <td>b'Heartbeat Payload Length'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.heartbeatType</td>
      <td>Number</td>
      <td>b'Heartbeat Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.hitCount</td>
      <td>Number</td>
      <td>b'Hit Count'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.hopLimit</td>
      <td>Number</td>
      <td>b'Hop Limit'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.host</td>
      <td>String</td>
      <td>b'Host'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.htype</td>
      <td>Number</td>
      <td>b'Hardware Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ingressInterface</td>
      <td>Unknown</td>
      <td>b'Ingress Interface'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.interface</td>
      <td>String</td>
      <td>b'Interface'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isAborted</td>
      <td>Boolean</td>
      <td>b'Aborted'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isAuthoritative</td>
      <td>Boolean</td>
      <td>b'Authoritative'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isBinaryProtocol</td>
      <td>Boolean</td>
      <td>b'Binary Protocol'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCheckingDisabled</td>
      <td>Boolean</td>
      <td>b'Checking Disabled'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCleanShutdown</td>
      <td>Boolean</td>
      <td>b'Clean Shutdown'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isClientDiskRead</td>
      <td>Boolean</td>
      <td>b'Client Disk Read'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isClientDiskWrite</td>
      <td>Boolean</td>
      <td>b'Client Disk Write'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandCreate</td>
      <td>Boolean</td>
      <td>b'Create Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandDelete</td>
      <td>Boolean</td>
      <td>b'Delete Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandFileInfo</td>
      <td>Boolean</td>
      <td>b'FileInfo Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandLock</td>
      <td>Boolean</td>
      <td>b'Lock Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandRead</td>
      <td>Boolean</td>
      <td>b'Read Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandRename</td>
      <td>Boolean</td>
      <td>b'Rename Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCommandWrite</td>
      <td>Boolean</td>
      <td>b'Write Command'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isCompressed</td>
      <td>Boolean</td>
      <td>b'Compressed'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isEncrypted</td>
      <td>Boolean</td>
      <td>b'Encrypted'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isNoReply</td>
      <td>Boolean</td>
      <td>b'No Reply'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isPipelined</td>
      <td>Boolean</td>
      <td>b'Pipelined'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRecursionAvailable</td>
      <td>Boolean</td>
      <td>b'Recursion Available'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRecursionDesired</td>
      <td>Boolean</td>
      <td>b'Recursion Desired'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRenegotiate</td>
      <td>Boolean</td>
      <td>b'Renegotiate'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isReqAborted</td>
      <td>Boolean</td>
      <td>b'Request Aborted'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isReqTimeout</td>
      <td>Boolean</td>
      <td>b'Request Timed Out'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isReqTruncated</td>
      <td>Boolean</td>
      <td>b'Request Truncated'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRspAborted</td>
      <td>Boolean</td>
      <td>b'Response Aborted'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRspChunked</td>
      <td>Boolean</td>
      <td>b'Chunked'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRspCompressed</td>
      <td>Boolean</td>
      <td>b'Rsp Compressed'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRspImplicit</td>
      <td>Boolean</td>
      <td>b'Response Implicit'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isRspTruncated</td>
      <td>Boolean</td>
      <td>b'Response Truncated'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isSQLi</td>
      <td>Boolean</td>
      <td>b'Contains SQLi'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isSharedSession</td>
      <td>Boolean</td>
      <td>b'Shared Session'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isSubOperation</td>
      <td>Boolean</td>
      <td>b'Is a suboperation'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isWeakCipherSuite</td>
      <td>Boolean</td>
      <td>b'Weak Cipher Suite'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.isXSS</td>
      <td>Boolean</td>
      <td>b'Contains XSS'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ja3Hash</td>
      <td>String</td>
      <td>b'JA3 Hash'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ja3sHash</td>
      <td>String</td>
      <td>b'JA3S Hash'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.jitter</td>
      <td>Number</td>
      <td>b'Jitter'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.kexAlgorithm</td>
      <td>String</td>
      <td>b'KEX Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.keyboardLayout</td>
      <td>String</td>
      <td>b'Keyboard Layout'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.l2Bytes</td>
      <td>Number</td>
      <td>b'L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.l7proto</td>
      <td>String</td>
      <td>b'L7 Protocol'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.label</td>
      <td>String</td>
      <td>b'Label'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.last</td>
      <td>Number</td>
      <td>b'Last'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.launchParams</td>
      <td>String</td>
      <td>b'Parameters'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.loadTime</td>
      <td>Number</td>
      <td>b'Load Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.loginTime</td>
      <td>Number</td>
      <td>b'Login Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.method</td>
      <td>String</td>
      <td>b'Method'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.missCount</td>
      <td>Number</td>
      <td>b'Miss Count'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.mos</td>
      <td>Number</td>
      <td>b'MOS'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgClass</td>
      <td>String</td>
      <td>b'Message Class'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgCode</td>
      <td>Number</td>
      <td>b'Message Code'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgFormat</td>
      <td>String</td>
      <td>b'Message Format'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgId</td>
      <td>Number</td>
      <td>b'Message ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgLength</td>
      <td>Number</td>
      <td>b'Message Length'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgSize</td>
      <td>Number</td>
      <td>b'Message Size'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgText</td>
      <td>String</td>
      <td>b'Message Text'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.msgType</td>
      <td>String</td>
      <td>b'Message Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.network</td>
      <td>Unknown</td>
      <td>b'Flow Network'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.networkAddr.type</td>
      <td>String</td>
      <td>b'Flow Network IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.networkAddr.value</td>
      <td>String</td>
      <td>b'Flow Network IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.networkLatency</td>
      <td>Number</td>
      <td>b'Network Latency'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.nextHop.type</td>
      <td>String</td>
      <td>b'Next Hop IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.nextHop.value</td>
      <td>String</td>
      <td>b'Next Hop IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.nextHopMTU</td>
      <td>Number</td>
      <td>b'Next Hop MTU'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.notAfter</td>
      <td>Number</td>
      <td>b'Certificate Not After'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.offeredAddr.type</td>
      <td>String</td>
      <td>b'Offered IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.offeredAddr.value</td>
      <td>String</td>
      <td>b'Offered IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.offset</td>
      <td>Number</td>
      <td>b'Offset'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.opcode</td>
      <td>String</td>
      <td>b'Opcode'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.operation</td>
      <td>String</td>
      <td>b'Operation'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.option</td>
      <td>String</td>
      <td>b'Options'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.origin</td>
      <td>String</td>
      <td>b'Origin'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.outOfOrder</td>
      <td>Number</td>
      <td>b'Out Of Order'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.path</td>
      <td>String</td>
      <td>b'Path'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.payloadType</td>
      <td>String</td>
      <td>b'Payload Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.payloadTypeId</td>
      <td>Number</td>
      <td>b'Payload Type ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.persistent</td>
      <td>Boolean</td>
      <td>b'Persistent'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.pkts</td>
      <td>Number</td>
      <td>b'Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.pointer</td>
      <td>Number</td>
      <td>b'Pointer'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.printerName</td>
      <td>String</td>
      <td>b'Printer Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.priority</td>
      <td>Number</td>
      <td>b'Priority'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.procedure</td>
      <td>String</td>
      <td>b'Procedure'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.processingTime</td>
      <td>Number</td>
      <td>b'Processing Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.program</td>
      <td>String</td>
      <td>b'Program'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.proto</td>
      <td>String</td>
      <td>b'IP Protocol'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.protocol</td>
      <td>String</td>
      <td>b'Protocol'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.putAppName</td>
      <td>String</td>
      <td>b'Put Application Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.qname</td>
      <td>String</td>
      <td>b'Query Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.qtype</td>
      <td>String</td>
      <td>b'Query Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.query</td>
      <td>String</td>
      <td>b'Query'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.queue</td>
      <td>String</td>
      <td>b'Queue'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.queueMgr</td>
      <td>String</td>
      <td>b'Queue Manager'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rFactor</td>
      <td>Number</td>
      <td>b'R Factor'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.realm</td>
      <td>String</td>
      <td>b'Server Realm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiver.type</td>
      <td>String</td>
      <td>b'Receiver Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiver.value</td>
      <td>String</td>
      <td>b'Receiver Discovery ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverAddr.type</td>
      <td>String</td>
      <td>b'Receiver IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverAddr.value</td>
      <td>String</td>
      <td>b'Receiver IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverAsn</td>
      <td>Number</td>
      <td>b'Receiver ASN'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverBytes</td>
      <td>Number</td>
      <td>b'Receiver Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverIsBroker</td>
      <td>Boolean</td>
      <td>b'To Broker'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverL2Bytes</td>
      <td>Number</td>
      <td>b'Receiver L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverPkts</td>
      <td>Number</td>
      <td>b'Receiver Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverPort</td>
      <td>Number</td>
      <td>b'Receiver Port'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverPrefixLength</td>
      <td>Number</td>
      <td>b'Receiver Prefix Length'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverRTO</td>
      <td>Number</td>
      <td>b'Receiver RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.receiverZeroWnd</td>
      <td>Number</td>
      <td>b'Receiver Zero Windows'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.recipient</td>
      <td>String</td>
      <td>b'Recipient'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.recipientList</td>
      <td>String</td>
      <td>b'Recipient List'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.redeliveryCount</td>
      <td>Number</td>
      <td>b'Redelivery Count'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.referer</td>
      <td>String</td>
      <td>b'Referer'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.renameDirChanged</td>
      <td>Boolean</td>
      <td>b'Rename Directory Changed'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.replyTo</td>
      <td>String</td>
      <td>b'Reply To'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqBytes</td>
      <td>Number</td>
      <td>b'Request Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqKey</td>
      <td>String</td>
      <td>b'Request Key'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqL2Bytes</td>
      <td>Number</td>
      <td>b'Request L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqPdu</td>
      <td>String</td>
      <td>b'Request PDU Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqPkts</td>
      <td>Number</td>
      <td>b'Request Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqRTO</td>
      <td>Number</td>
      <td>b'Request RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqSize</td>
      <td>Number</td>
      <td>b'Request Size'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqTimeToLastByte</td>
      <td>Number</td>
      <td>b'Req Time To Last Byte'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.reqTransferTime</td>
      <td>Number</td>
      <td>b'Request Transfer Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.requestedColorDepth</td>
      <td>String</td>
      <td>b'Requested Color Depth'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.requestedProtocols</td>
      <td>String</td>
      <td>b'Requested Protocols'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.resolvedQueue</td>
      <td>String</td>
      <td>b'Resolved Queue'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.resolvedQueueMgr</td>
      <td>String</td>
      <td>b'Resolved Queue Manager'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.resource</td>
      <td>String</td>
      <td>b'Resource'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.responseQueue</td>
      <td>String</td>
      <td>b'Response Queue'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.roundTripTime</td>
      <td>Number</td>
      <td>b'Round Trip Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspBytes</td>
      <td>Number</td>
      <td>b'Response Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspL2Bytes</td>
      <td>Number</td>
      <td>b'Response L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspPdu</td>
      <td>String</td>
      <td>b'Response PDU Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspPkts</td>
      <td>Number</td>
      <td>b'Response Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspRTO</td>
      <td>Number</td>
      <td>b'Response RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspSize</td>
      <td>Number</td>
      <td>b'Response Size'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspTimeToFirstByte</td>
      <td>Number</td>
      <td>b'Rsp Time To First Byte'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspTimeToFirstHeader</td>
      <td>Number</td>
      <td>b'Rsp Time To First Header'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspTimeToFirstPayload</td>
      <td>Number</td>
      <td>b'Rsp Time To First Payload'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspTimeToLastByte</td>
      <td>Number</td>
      <td>b'Rsp Time To Last Byte'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspTransferTime</td>
      <td>Number</td>
      <td>b'Response Transfer Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rspVersion</td>
      <td>String</td>
      <td>b'Response Version'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.rto</td>
      <td>Number</td>
      <td>b'RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.sNameType</td>
      <td>String</td>
      <td>b'Server Name Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.sNames</td>
      <td>String</td>
      <td>b'Server Name Components'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.saslMechanism</td>
      <td>String</td>
      <td>b'SASL Mechanism'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.searchFilter</td>
      <td>String</td>
      <td>b'Search Filter'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.searchScope</td>
      <td>String</td>
      <td>b'Search Scope'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.selectedProtocol</td>
      <td>String</td>
      <td>b'Selected Protocol'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.sender.type</td>
      <td>String</td>
      <td>b'Sender Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.sender.value</td>
      <td>String</td>
      <td>b'Sender Discovery ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderAddr.type</td>
      <td>String</td>
      <td>b'Sender IP Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderAddr.value</td>
      <td>String</td>
      <td>b'Sender IP Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderAsn</td>
      <td>Number</td>
      <td>b'Sender ASN'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderBytes</td>
      <td>Number</td>
      <td>b'Sender Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderIsBroker</td>
      <td>Boolean</td>
      <td>b'From Broker'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderL2Bytes</td>
      <td>Number</td>
      <td>b'Sender L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderPkts</td>
      <td>Number</td>
      <td>b'Sender Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderPort</td>
      <td>Number</td>
      <td>b'Sender Port'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderPrefixLength</td>
      <td>Number</td>
      <td>b'Sender Prefix Length'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderRTO</td>
      <td>Number</td>
      <td>b'Sender RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.senderZeroWnd</td>
      <td>Number</td>
      <td>b'Sender Zero Windows'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.seqNum</td>
      <td>Number</td>
      <td>b'Sequence Number'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.server.type</td>
      <td>String</td>
      <td>b'Server Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.server.value</td>
      <td>String</td>
      <td>b'Server Discovery ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverAddr.type</td>
      <td>String</td>
      <td>b'Server IPv4 Address Type'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverAddr.value</td>
      <td>String</td>
      <td>b'Server IPv4 Address Value'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverBytes</td>
      <td>Number</td>
      <td>b'Server Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverCGPMsgCount</td>
      <td>Number</td>
      <td>b'Server CGP Messages'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverCipherAlgorithm</td>
      <td>String</td>
      <td>b'Server Cipher Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverCompressionAlgorithm</td>
      <td>String</td>
      <td>b'Server Compression Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverImplementation</td>
      <td>String</td>
      <td>b'Server Implementation'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverL2Bytes</td>
      <td>Number</td>
      <td>b'Server L2 Bytes'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverMacAlgorithm</td>
      <td>String</td>
      <td>b'Server MAC Algorithm'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverMsgCount</td>
      <td>Number</td>
      <td>b'Server Messages'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverPkts</td>
      <td>Number</td>
      <td>b'Server Packets'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverPort</td>
      <td>Number</td>
      <td>b'Server Port'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverPrincipalName</td>
      <td>String</td>
      <td>b'Server Principal Name'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverRTO</td>
      <td>Number</td>
      <td>b'Server RTO'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverVersion</td>
      <td>String</td>
      <td>b'Server Version'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.serverZeroWnd</td>
      <td>Number</td>
      <td>b'Server Zero Windows'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.share</td>
      <td>String</td>
      <td>b'Share'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.source</td>
      <td>String</td>
      <td>b'Source'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.sqli</td>
      <td>String</td>
      <td>b'Potential SQLi'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.srcQueueMgr</td>
      <td>String</td>
      <td>b'Source Queue Manager'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ssrc</td>
      <td>Number</td>
      <td>b'Sender SSRC'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.statement</td>
      <td>String</td>
      <td>b'Statement'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.status</td>
      <td>String</td>
      <td>b'Status'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.statusCode</td>
      <td>Number</td>
      <td>b'Status Code'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.statusText</td>
      <td>String</td>
      <td>b'Status Text'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.table</td>
      <td>String</td>
      <td>b'Table'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.target</td>
      <td>String</td>
      <td>b'Target'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.tcpFlags</td>
      <td>Number</td>
      <td>b'TCP Flags'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.thinkTime</td>
      <td>Number</td>
      <td>b'Think Time'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.tickChannel</td>
      <td>String</td>
      <td>b'Tick Channel'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.ticketHash</td>
      <td>String</td>
      <td>b'Encrypted Ticket Hash'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.till</td>
      <td>String</td>
      <td>b'Till'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.title</td>
      <td>String</td>
      <td>b'Title'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.to</td>
      <td>String</td>
      <td>b'To'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.totalMsgLength</td>
      <td>Number</td>
      <td>b'Total Msg Length'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.transferBytes</td>
      <td>Number</td>
      <td>b'Bytes Transferred'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.txId</td>
      <td>Number</td>
      <td>b'Transaction ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.unitId</td>
      <td>Number</td>
      <td>b'Unit ID'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.uri</td>
      <td>String</td>
      <td>b'URI'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.user</td>
      <td>String</td>
      <td>b'User'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.userAgent</td>
      <td>String</td>
      <td>b'User Agent'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.vbucket</td>
      <td>Number</td>
      <td>b'vBucket'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.version</td>
      <td>String</td>
      <td>b'Version'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.vlan</td>
      <td>Number</td>
      <td>b'VLAN'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.vxlanVNI</td>
      <td>Number</td>
      <td>b'VxLAN VNI'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.warning</td>
      <td>String</td>
      <td>b'Warning'</td>
    </tr>
    <tr>
      <td>ExtraHop.Record.Source.xss</td>
      <td>String</td>
      <td>b'Potential XSS'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-query-records query_from=-6h limit=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "Record": [
            {
                "Id": "AW1goQmvylOgLDUmuFLT",
                "Index": "extrahop-11-2019-9-24-0",
                "Sort": [
                    1569284181528.201
                ],
                "Source": {
                    "client": {
                        "type": "device",
                        "value": [
                            "fff41107140a0000"
                        ]
                    },
                    "clientAddr": {
                        "type": "ipaddr4",
                        "value": "172.16.34.152"
                    },
                    "clientPort": 34140,
                    "clientZeroWnd": 0,
                    "ex": {
                        "isSuspicious": false
                    },
                    "flowId": "0cac4df05d896054",
                    "host": "prod1.example.com",
                    "isPipelined": false,
                    "isReqAborted": false,
                    "isRspAborted": false,
                    "isRspChunked": false,
                    "isRspCompressed": false,
                    "isSQLi": false,
                    "isXSS": false,
                    "method": "POST",
                    "processingTime": 233.318,
                    "referer": "http://prod1.example.com/login?from=%2F",
                    "reqBytes": 1160,
                    "reqL2Bytes": 1518,
                    "reqPkts": 5,
                    "reqRTO": 0,
                    "reqSize": 64,
                    "reqTimeToLastByte": 0,
                    "roundTripTime": 0.245,
                    "rspBytes": 346,
                    "rspL2Bytes": 1284,
                    "rspPkts": 8,
                    "rspRTO": 0,
                    "rspSize": 0,
                    "rspTimeToFirstHeader": 233.318,
                    "rspTimeToLastByte": 234.528,
                    "rspVersion": "1.1",
                    "server": {
                        "type": "device",
                        "value": [
                            "fff4c3090a0a0000"
                        ]
                    },
                    "serverAddr": {
                        "type": "ipaddr4",
                        "value": "172.16.34.161"
                    },
                    "serverPort": 80,
                    "serverZeroWnd": 0,
                    "statusCode": 302,
                    "timestamp": 1569284181528.201,
                    "uri": "prod1.example.com/j_acegi_security_check",
                    "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
                },
                "Type": "~http"
            },
            {
                "Id": "AW1gQF7uylOgLDUmoClO",
                "Index": "extrahop-11-2019-9-23-0",
                "Sort": [
                    1569277857270.787
                ],
                "Source": {
                    "args": "<EH-REDACTED>",
                    "client": {
                        "type": "device",
                        "value": [
                            "fff48dff0a0a0000"
                        ]
                    },
                    "clientAddr": {
                        "type": "ipaddr4",
                        "value": "172.16.34.11"
                    },
                    "clientPort": 1920,
                    "clientZeroWnd": 0,
                    "cwd": "/",
                    "detection": [
                        "anonymous_ftp"
                    ],
                    "ex": {
                        "isSuspicious": false
                    },
                    "flowId": "037efd385d8947a0",
                    "isReqAborted": false,
                    "isRspAborted": false,
                    "method": "PASS",
                    "processingTime": 0.25,
                    "reqBytes": 22,
                    "reqL2Bytes": 490,
                    "reqPkts": 6,
                    "reqRTO": 0,
                    "rspBytes": 21,
                    "rspL2Bytes": 239,
                    "rspPkts": 2,
                    "rspRTO": 0,
                    "server": {
                        "type": "device",
                        "value": [
                            "fff45a060a0a0000"
                        ]
                    },
                    "serverAddr": {
                        "type": "ipaddr4",
                        "value": "172.16.34.231"
                    },
                    "serverPort": 21,
                    "serverZeroWnd": 0,
                    "statusCode": 230,
                    "timestamp": 1569277857270.787,
                    "user": "anonymous"
                },
                "Type": "~ftp"
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Showing 2 out of 15 Record(s) Found.</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>client</strong></th>
      <th><strong>clientAddr</strong></th>
      <th><strong>clientPort</strong></th>
      <th><strong>clientZeroWnd</strong></th>
      <th><strong>ex</strong></th>
      <th><strong>flowId</strong></th>
      <th><strong>host</strong></th>
      <th><strong>isPipelined</strong></th>
      <th><strong>isReqAborted</strong></th>
      <th><strong>isRspAborted</strong></th>
      <th><strong>isRspChunked</strong></th>
      <th><strong>isRspCompressed</strong></th>
      <th><strong>isSQLi</strong></th>
      <th><strong>isXSS</strong></th>
      <th><strong>method</strong></th>
      <th><strong>processingTime</strong></th>
      <th><strong>referer</strong></th>
      <th><strong>reqBytes</strong></th>
      <th><strong>reqL2Bytes</strong></th>
      <th><strong>reqPkts</strong></th>
      <th><strong>reqRTO</strong></th>
      <th><strong>reqSize</strong></th>
      <th><strong>reqTimeToLastByte</strong></th>
      <th><strong>roundTripTime</strong></th>
      <th><strong>rspBytes</strong></th>
      <th><strong>rspL2Bytes</strong></th>
      <th><strong>rspPkts</strong></th>
      <th><strong>rspRTO</strong></th>
      <th><strong>rspSize</strong></th>
      <th><strong>rspTimeToFirstHeader</strong></th>
      <th><strong>rspTimeToLastByte</strong></th>
      <th><strong>rspVersion</strong></th>
      <th><strong>server</strong></th>
      <th><strong>serverAddr</strong></th>
      <th><strong>serverPort</strong></th>
      <th><strong>serverZeroWnd</strong></th>
      <th><strong>statusCode</strong></th>
      <th><strong>timestamp</strong></th>
      <th><strong>uri</strong></th>
      <th><strong>userAgent</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>type: device<br>value: fff41107140a0000</td>
      <td>type: ipaddr4<br>value: 172.16.34.152</td>
      <td>34140</td>
      <td>0</td>
      <td>isSuspicious: false</td>
      <td>0cac4df05d896054</td>
      <td>prod1.example.com</td>
      <td>false</td>
      <td>false</td>
      <td>false</td>
      <td>false</td>
      <td>false</td>
      <td>false</td>
      <td>false</td>
      <td>POST</td>
      <td>233.318</td>
      <td>http://prod1.example.com/login?from=%2F</td>
      <td>1160</td>
      <td>1518</td>
      <td>5</td>
      <td>0</td>
      <td>64</td>
      <td>0</td>
      <td>0.245</td>
      <td>346</td>
      <td>1284</td>
      <td>8</td>
      <td>0</td>
      <td>0</td>
      <td>233.318</td>
      <td>234.528</td>
      <td>1.1</td>
      <td>type: device<br>value: fff4c3090a0a0000</td>
      <td>type: ipaddr4<br>value: 172.16.34.161</td>
      <td>80</td>
      <td>0</td>
      <td>302</td>
      <td>1569284181528.201</td>
      <td>prod1.example.com/j_acegi_security_check</td>
      <td>Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36</td>
    </tr>
    <tr>
      <td>type: device<br>value: fff48dff0a0a0000</td>
      <td>type: ipaddr4<br>value: 172.16.34.11</td>
      <td>1920</td>
      <td>0</td>
      <td>isSuspicious: false</td>
      <td>037efd385d8947a0</td>
      <td></td>
      <td></td>
      <td>false</td>
      <td>false</td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>PASS</td>
      <td>0.25</td>
      <td></td>
      <td>22</td>
      <td>490</td>
      <td>6</td>
      <td>0</td>
      <td></td>
      <td></td>
      <td></td>
      <td>21</td>
      <td>239</td>
      <td>2</td>
      <td>0</td>
      <td></td>
      <td></td>
      <td></td>
      <td></td>
      <td>type: device<br>value: fff45a060a0a0000</td>
      <td>type: ipaddr4<br>value: 172.16.34.231</td>
      <td>21</td>
      <td>0</td>
      <td>230</td>
      <td>1569277857270.787</td>
      <td></td>
      <td></td>
    </tr>
  </tbody>
</table>

</p>

<h3>3. Search for devices</h3>
<!-- <hr> -->
<p>Search for devices in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-device-search</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>name</td>
      <td>The name of the device. This searches for matches on all ExtraHop name fields (DHCP, DNS, NetBIOS, Cisco Discovery Protocol, etc).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ip</td>
      <td>The IP address of the device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>mac</td>
      <td>The MAC address of the device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>role</td>
      <td>The role of the device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>software</td>
      <td>The OS of the device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tag</td>
      <td>A tag present on the device. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>vendor</td>
      <td>The vendor of the device, based on MAC address via OUI lookup.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>discover_time</td>
      <td>The time that device was first seen by ExtraHop, expressed in milliseconds since the epoch. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with the following unit suffixes: ms, s, m, h, d, w, M, y. For example, to look one day back enter -1d or -24h. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>vlan</td>
      <td>The VLAN ID of the Virtual LAN that the device is on.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>activity</td>
      <td>The activity of the device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operator</td>
      <td>The compare method applied when matching the fields against their values. For example, to find devices with names that begin with 'SEA1' (set name=SEA1, operator=startswith)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>match_type</td>
      <td>The match operator to use when chaining the search fields together. For example, to find all HTTP servers running Windows on the network (set match_type=and, role=http_server, software=windows).</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>active_from</td>
      <td>The beginning timestamp for the request. Return only devices active after this time. Time is expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>active_until</td>
      <td>The ending timestamp for the request. Return only devices active before this time. Time is expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit</td>
      <td>The maximum number of devices to return.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>l3_only</td>
      <td>Only returns layer 3 devices by filtering out any layer 2 parent devices.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ExtraHop.Device.Macaddr</td>
      <td>String</td>
      <td>b'The MAC Address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DeviceClass</td>
      <td>String</td>
      <td>b'The class of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.UserModTime</td>
      <td>Number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.AutoRole</td>
      <td>String</td>
      <td>b'The role automatically detected by the ExtraHop.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ParentId</td>
      <td>Number</td>
      <td>b'The ID of the parent device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Vendor</td>
      <td>String</td>
      <td>b'The device vendor.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Analysis</td>
      <td>string</td>
      <td>b'The level of analysis preformed on the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DiscoveryId</td>
      <td>String</td>
      <td>b'The UUID given by the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DefaultName</td>
      <td>String</td>
      <td>b'The default name of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DisplayName</td>
      <td>String</td>
      <td>b'The display name of device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.OnWatchlist</td>
      <td>Boolean</td>
      <td>b'Whether the device is on the advanced analysis whitelist.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ModTime</td>
      <td>Number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.IsL3</td>
      <td>Boolean</td>
      <td>b'Indicates whether the device is a Layer 3 device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Role</td>
      <td>String</td>
      <td>b'The role of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DiscoverTime</td>
      <td>Number</td>
      <td>b'The time that the device was discovered.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Id</td>
      <td>Number</td>
      <td>b'The ID of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr4</td>
      <td>String</td>
      <td>b'The IPv4 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Vlanid</td>
      <td>Number</td>
      <td>b'The ID of VLan.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr6</td>
      <td>string</td>
      <td>b'The IPv6 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NodeId</td>
      <td>number</td>
      <td>b'The Node ID of the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Description</td>
      <td>string</td>
      <td>b'A user customizable description of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DnsName</td>
      <td>string</td>
      <td>b'The DNS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DhcpName</td>
      <td>string</td>
      <td>b'The DHCP name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.CdpName</td>
      <td>string</td>
      <td>b'The Cisco Discovery Protocol name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NetbiosName</td>
      <td>string</td>
      <td>b'The NetBIOS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Url</td>
      <td>string</td>
      <td>b'Link to the device details page in ExtraHop.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-device-search limit=2</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "Device": [
            {
                "Analysis": "l2_exempt",
                "AnalysisLevel": 4,
                "AutoRole": "other",
                "DefaultName": "Dell A9B1F6",
                "DeviceClass": "node",
                "DhcpName": "Win3-Web",
                "DiscoverTime": 1569277980000,
                "DiscoveryId": "509a4ca9b1f60000",
                "DisplayName": "Win3-Web",
                "ExtrahopId": "509a4ca9b1f60000",
                "Id": 18628,
                "IsL3": false,
                "Macaddr": "70:F6:4C:A3:C2:F0",
                "ModTime": 1569278201104,
                "OnWatchlist": false,
                "Role": "other",
                "Url": "https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.509a4ca9b1f60000/overview/",
                "UserModTime": 1569277990763,
                "Vendor": "Dell",
                "Vlanid": 0
            },
            {
                "Analysis": "l2_exempt",
                "AnalysisLevel": 4,
                "AutoRole": "other",
                "DefaultName": "Device a0510b0e4e210000",
                "DeviceClass": "node",
                "DhcpName": "PG1NP0ZR",
                "DiscoverTime": 1569276630000,
                "DiscoveryId": "a0510b0e4e210000",
                "DisplayName": "PF1NP0ZR",
                "ExtrahopId": "a0510b0e4e210000",
                "Id": 18627,
                "IsL3": false,
                "Macaddr": "B1:62:1C:1F:5F:32",
                "ModTime": 1569276641503,
                "OnWatchlist": false,
                "Role": "other",
                "Url": "https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.a0510b0e4e210000/overview/",
                "UserModTime": 1569276640285,
                "Vlanid": 0
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>2 Device(s) Found</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Display Name</strong></th>
      <th><strong>IP Address</strong></th>
      <th><strong>MAC Address</strong></th>
      <th><strong>Role</strong></th>
      <th><strong>Vendor</strong></th>
      <th><strong>URL</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Win3-Web</td>
      <td></td>
      <td>70:F6:4C:A3:C2:F0</td>
      <td>other</td>
      <td>Dell</td>
      <td>[View Device in ExtraHop](https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.509a4ca9b1f60000/overview/)</td>
    </tr>
    <tr>
      <td>PG1NP0ZR</td>
      <td></td>
      <td>B1:62:1C:1F:5F:32</td>
      <td>other</td>
      <td></td>
      <td>[View Device in ExtraHop](https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.a0510b0e4e210000/overview/)</td>
    </tr>
  </tbody>
</table>

</p>

<h3>4. Add or remove devices from the watchlist</h3>
<!-- <hr> -->
<p>Add or remove devices from the watchlist in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-edit-watchlist</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>add</td>
      <td>The list of IP Addresses or ExtraHop API IDs of the devices to add, comma separated.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>remove</td>
      <td>The list of IP Addresses or ExtraHop API IDs of the devices to remove, comma separated.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-edit-watchlist add=172.16.34.152</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Successful Modification
</p>
</p>

<h3>5. Get all devices on the watchlist</h3>
<!-- <hr> -->
<p>Get all devices on the watchlist in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-get-watchlist</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>

  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Extrahop.Device.Macaddr</td>
      <td>String</td>
      <td>b'The MAC Address of the device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.DeviceClass</td>
      <td>String</td>
      <td>b'The class of this device. '</td>
    </tr>
    <tr>
      <td>Extrahop.Device.UserModTime</td>
      <td>Number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.AutoRole</td>
      <td>String</td>
      <td>b'The role automatically detected by the ExtraHop. '</td>
    </tr>
    <tr>
      <td>Extrahop.Device.ParentId</td>
      <td>Number</td>
      <td>b'The ID of the parent device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.Vendor</td>
      <td>String</td>
      <td>b'The device vendor.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.Analysis</td>
      <td>string</td>
      <td>b'The level of analysis preformed on the device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.DiscoveryId</td>
      <td>String</td>
      <td>b'The UUID given by the Discover appliance.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.DefaultName</td>
      <td>String</td>
      <td>b'The default name for this device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.DisplayName</td>
      <td>String</td>
      <td>b'The display name of device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.OnWatchlist</td>
      <td>Boolean</td>
      <td>b'Whether the device is on the advanced analysis whitelist.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.ModTime</td>
      <td>Number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.IsL3</td>
      <td>Boolean</td>
      <td>b'Indicates whether the device is a Layer 3 device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.Role</td>
      <td>String</td>
      <td>b'The role of the device. '</td>
    </tr>
    <tr>
      <td>Extrahop.Device.DiscoverTime</td>
      <td>Number</td>
      <td>b'The time that the device was discovered.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.Id</td>
      <td>Number</td>
      <td>b'The ID of the device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.Ipaddr4</td>
      <td>String</td>
      <td>b'The IPv4 address for this device.'</td>
    </tr>
    <tr>
      <td>Extrahop.Device.Vlanid</td>
      <td>Number</td>
      <td>b'The unique identifier for the VLAN this device is associated with.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr6</td>
      <td>string</td>
      <td>b'The IPv6 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NodeId</td>
      <td>number</td>
      <td>b'The Node ID of the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Description</td>
      <td>string</td>
      <td>b'A user customizable description of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DnsName</td>
      <td>string</td>
      <td>b'The DNS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DhcpName</td>
      <td>string</td>
      <td>b'The DHCP name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.CdpName</td>
      <td>string</td>
      <td>b'The Cisco Discovery Protocol name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NetbiosName</td>
      <td>string</td>
      <td>b'The NetBIOS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Url</td>
      <td>string</td>
      <td>b'Link to the device details page in ExtraHop.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-get-watchlist</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "Device": [
            {
                "Analysis": "advanced",
                "AnalysisLevel": 2,
                "AutoRole": "other",
                "DefaultName": "Device 172.16.34.152",
                "DeviceClass": "node",
                "DhcpName": "dem-is-to",
                "DiscoverTime": 1522964970000,
                "DiscoveryId": "fff49b080a0a0000",
                "DisplayName": "dem-is-to",
                "DnsName": "dem-is-to.example.com",
                "ExtrahopId": "fff49b080a0a0000",
                "Id": 1554,
                "Ipaddr4": "172.16.34.152",
                "IsL3": true,
                "Macaddr": "63:65:11:A1:3B:2B",
                "ModTime": 1569283538898,
                "NetbiosName": "DEMISTO",
                "OnWatchlist": true,
                "ParentId": 1445,
                "Role": "other",
                "Url": "https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff49b080a0a0000/overview/",
                "UserModTime": 1522964985837,
                "Vlanid": 0
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>1 Device(s) Found</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Display Name</strong></th>
      <th><strong>IP Address</strong></th>
      <th><strong>MAC Address</strong></th>
      <th><strong>Role</strong></th>
      <th><strong>Vendor</strong></th>
      <th><strong>URL</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>dem-is-to</td>
      <td>172.16.34.152</td>
      <td>63:65:11:A1:3B:2B</td>
      <td>other</td>
      <td></td>
      <td>[View Device in ExtraHop](https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff49b080a0a0000/overview/)</td>
    </tr>
  </tbody>
</table>

</p>

<h3>6. Create a new alert rule</h3>
<!-- <hr> -->
<p>Create a new alert rule in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-create-alert-rule</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>apply_all</td>
      <td>Indicates whether the alert is assigned to all available data sources.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>disabled</td>
      <td>Indicates whether the alert is disabled.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The unique, friendly name for the alert.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>notify_snmp</td>
      <td>Indicates whether to send an SNMP trap when an alert is generated.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>refire_interval</td>
      <td>The time interval in which alert conditions are monitored, expressed in seconds. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>severity</td>
      <td>The severity level of the alert, which is displayed in the Alert History, email notifications, and SNMP traps. Supported values: 0, 1, 2, 3, 4, 5, 6, 7</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>type</td>
      <td>The type of alert. </td>
      <td>Required</td>
    </tr>
    <tr>
      <td>object_type</td>
      <td>The type of metric source monitored by the alert configuration. Only applicable to detection alerts. </td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocols</td>
      <td>The list of monitored protocols. Only applicable to detection alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field_name</td>
      <td>The name of the monitored metric. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field_name2</td>
      <td>The second monitored metric when applying a ratio. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>stat_name</td>
      <td>The statistic name for the alert. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>units</td>
      <td>The interval in which to evaluate the alert condition. Only applicable to threshold alerts. 
Supported values: "none", "period", "1 sec", "1 min", "1 hr"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>interval_length</td>
      <td>The length of the alert interval, expressed in seconds. Only applicable to threshold alerts. 
Supported values: 30, 60, 120, 300, 600, 900, 1200, 1800</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operand</td>
      <td>The value to compare against alert conditions. The compare method is specified by the value of the operator field. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operator</td>
      <td>The logical operator applied when comparing the value of the operand field to alert conditions. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field_op</td>
      <td>The type of comparison between the field_name and field_name2 fields when applying a ratio. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>param</td>
      <td>The first alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>param2</td>
      <td>The second alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-create-alert-rule apply_all=false disabled=true name="Demisto Test Alert" notify_snmp=false refire_interval=3600 severity=3 type=threshold object_type=device operator=> operand=0.1 field_name=rsp_error field_name2=rsp field_op=/ units=none stat_name="extrahop.application.http"</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Successfully Created
</p>
</p>

<h3>7. Modify an alert rule</h3>
<!-- <hr> -->
<p>Modify an alert rule in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-edit-alert-rule</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>alert_id</td>
      <td>The unique identifier for the alert.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>apply_all</td>
      <td>Indicates whether the alert is assigned to all available data sources.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>disabled</td>
      <td>Indicates whether the alert is disabled.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>name</td>
      <td>The unique, friendly name for the alert.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>notify_snmp</td>
      <td>Indicates whether to send an SNMP trap when an alert is generated.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>field_name</td>
      <td>The name of the monitored metric. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>stat_name</td>
      <td>The statistic name for the alert. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>units</td>
      <td>The interval in which to evaluate the alert condition. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>interval_length</td>
      <td>The length of the alert interval, expressed in seconds. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operand</td>
      <td>The value to compare against alert conditions. The compare method is specified by the value of the operator field. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>refire_interval</td>
      <td>The time interval in which alert conditions are monitored, expressed in seconds.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>severity</td>
      <td>The severity level of the alert, which is displayed in the Alert History, email notifications, and SNMP traps.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>type</td>
      <td>The type of alert.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>object_type</td>
      <td>The type of metric source monitored by the alert configuration. Only applicable to detection alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocols</td>
      <td>The list of monitored protocols. Only applicable to detection alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>operator</td>
      <td>The logical operator applied when comparing the value of the operand field to alert conditions. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field_name2</td>
      <td>The second monitored metric when applying a ratio. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>field_op</td>
      <td>The type of comparison between the field_name and field_name2 fields when applying a ratio. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>param</td>
      <td>The first alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>param2</td>
      <td>The second alert parameter, which is either a key pattern or a data point. Only applicable to threshold alerts.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-edit-alert-rule alert_id=32 apply_all=false disabled=true name="Demisto Test" notify_snmp=false refire_interval=3600 severity=3 type=threshold object_type=device operator=> operand=0.1 field_name=rsp_error field_name2=rsp field_op=/ units=none stat_name="extrahop.application.http"  interval_length=30</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Successful Modification
</p>
</p>

<h3>8. Link an ExtraHop Detection to a Demisto Investigation</h3>
<!-- <hr> -->
<p>Link an ExtraHop Detection to a Demisto Investigation.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-track-ticket</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>incident_id</td>
      <td>The ID of the Demisto Incident to ticket track.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>detection_id</td>
      <td>The ID of the ExtraHop Detection to ticket track.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>incident_owner</td>
      <td>Owner of the incident.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>incident_status</td>
      <td>Status of the incident. 0=New, 1=In-progress, 2=Closed.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>incident_close_reason</td>
      <td>Reason the incident was closed</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ExtraHop.TicketId</td>
      <td>string</td>
      <td>b'Demisto Incident ID successfully tracked to ExtraHop Detection'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-track-ticket detection_id=25910 incident_id=40360 incident_owner='colinw' incident_status=1</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "TicketId": "40360"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Successful Modification
</p>
</p>

<h3>9. Get all peers for a device</h3>
<!-- <hr> -->
<p>Get all peers for a device from ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-get-peers</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip_or_id</td>
      <td>The IP Address or ExtraHop API ID of the source device to get peer devices.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>query_from</td>
      <td>The beginning timestamp of the time range the query will search, expressed in milliseconds since the epoch. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query_until</td>
      <td>The ending timestamp of the time range the query will search, expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>peer_role</td>
      <td>The role of the peer device in relation to the origin device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocol</td>
      <td>A filter to only return peers that the source device has communicated with over this protocol. If no value is set, the object includes any protocol.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ExtraHop.Device.Macaddr</td>
      <td>string</td>
      <td>b'The MAC Address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DeviceClass</td>
      <td>string</td>
      <td>b'The class of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.UserModTime</td>
      <td>number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.AutoRole</td>
      <td>string</td>
      <td>b'The role automatically detected by the ExtraHop.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ParentId</td>
      <td>number</td>
      <td>b'The ID of the parent device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Vendor</td>
      <td>string</td>
      <td>b'The device vendor.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Analysis</td>
      <td>string</td>
      <td>b'The level of analysis preformed on the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DiscoveryId</td>
      <td>string</td>
      <td>b'The UUID given by the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DefaultName</td>
      <td>string</td>
      <td>b'The default name of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DisplayName</td>
      <td>string</td>
      <td>b'The display name of device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.OnWatchlist</td>
      <td>boolean</td>
      <td>b'Whether the device is on the advanced analysis whitelist.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ModTime</td>
      <td>number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.IsL3</td>
      <td>boolean</td>
      <td>b'Indicates whether the device is a Layer 3 device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Role</td>
      <td>string</td>
      <td>b'The role of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DiscoverTime</td>
      <td>number</td>
      <td>b'The time that the device was discovered.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Id</td>
      <td>number</td>
      <td>b'The ID of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr4</td>
      <td>string</td>
      <td>b'The IPv4 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Vlanid</td>
      <td>number</td>
      <td>b'The ID of VLan.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr6</td>
      <td>string</td>
      <td>b'The IPv6 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NodeId</td>
      <td>number</td>
      <td>b'The Node ID of the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Description</td>
      <td>string</td>
      <td>b'A user customizable description of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DnsName</td>
      <td>string</td>
      <td>b'The DNS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DhcpName</td>
      <td>string</td>
      <td>b'The DHCP name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.CdpName</td>
      <td>string</td>
      <td>b'The Cisco Discovery Protocol name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NetbiosName</td>
      <td>string</td>
      <td>b'The NetBIOS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Url</td>
      <td>string</td>
      <td>b'Link to the device details page in ExtraHop.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ClientProtocols</td>
      <td>string</td>
      <td>b'The list of protocols the peer device is communicating as a client.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ServerProtocols</td>
      <td>string</td>
      <td>b'The list of protocols the peer device is communicating as a server.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-get-peers ip_or_id=172.16.34.23</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "Device": [
            {
                "Analysis": "advanced",
                "AnalysisLevel": 1,
                "AutoRole": "other",
                "DefaultName": "VMware 172.16.34.161",
                "DeviceClass": "node",
                "DhcpName": "joker.example.com",
                "DiscoverTime": 1522964910000,
                "DiscoveryId": "fff4bb070a0a0000",
                "DisplayName": "joker.example.com",
                "DnsName": "joker.example.com",
                "ExtrahopId": "fff4bb070a0a0000",
                "Id": 374,
                "Ipaddr4": "172.16.34.161",
                "IsL3": true,
                "Macaddr": "11:1D:3A:3C:3E:BE",
                "ModTime": 1569284586752,
                "OnWatchlist": false,
                "ParentId": 18018,
                "Role": "other",
                "ServerProtocols": [
                    "TCP:SSL:LDAP",
                    "TCP:SSL"
                ],
                "Url": "https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff4bb070a0a0000/overview/",
                "UserModTime": 1564016944279,
                "Vendor": "VMware",
                "Vlanid": 0
            },
            {
                "Analysis": "discovery",
                "AnalysisLevel": 3,
                "AutoRole": "other",
                "ClientProtocols": [
                    "TCP:HTTP"
                ],
                "DefaultName": "Qumranet 172.16.34.11",
                "DeviceClass": "node",
                "DhcpName": "soundboard2",
                "DiscoverTime": 1533851220000,
                "DiscoveryId": "fff44001150a0000",
                "DisplayName": "soundboard2",
                "DnsName": "soundboard2.example.com",
                "ExtrahopId": "fff44001150a0000",
                "Id": 10751,
                "Ipaddr4": "172.16.34.11",
                "IsL3": true,
                "Macaddr": "11:2B:5B:27:12:9D",
                "ModTime": 1569279163337,
                "OnWatchlist": false,
                "ParentId": 10746,
                "Role": "other",
                "ServerProtocols": [
                    "TCP:OTHER"
                ],
                "Url": "https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff44001150a0000/overview/",
                "UserModTime": 1533851289829,
                "Vendor": "Qumranet",
                "Vlanid": 0
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>2 Peer Device(s) Found</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Display Name</strong></th>
      <th><strong>IP Address</strong></th>
      <th><strong>MAC Address</strong></th>
      <th><strong>Role</strong></th>
      <th><strong>Protocols</strong></th>
      <th><strong>URL</strong></th>
      <th><strong>Vendor</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>joker.example.com</td>
      <td>172.16.34.161</td>
      <td>11:1D:3A:3C:3E:BE</td>
      <td>other</td>
      <td>Client: <br>Server: TCP:SSL:LDAP, TCP:SSL</td>
      <td>[View Device in ExtraHop](https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff4bb070a0a0000/overview/)</td>
      <td>VMware</td>
    </tr>
    <tr>
      <td>soundboard2</td>
      <td>172.16.34.11</td>
      <td>11:2B:5B:27:12:9D</td>
      <td>other</td>
      <td>Client: TCP:HTTP<br>Server: TCP:OTHER</td>
      <td>[View Device in ExtraHop](https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff44001150a0000/overview/)</td>
      <td>Qumranet</td>
    </tr>
  </tbody>
</table>

</p>

<h3>10. Get all active network protocols for a device</h3>
<!-- <hr> -->
<p>Get all active network protocols for a device from ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-get-protocols</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip_or_id</td>
      <td>The IP Address or ExtraHop API ID of the device to get all active network protocols.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>query_from</td>
      <td>The beginning timestamp of the time range the query will search, expressed in milliseconds since the epoch. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query_until</td>
      <td>The ending timestamp of the time range the query will search, expressed in milliseconds since the epoch. 0 indicates the time of the request. A negative value is evaluated relative to the current time. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ExtraHop.Device.Macaddr</td>
      <td>string</td>
      <td>b'The MAC Address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DeviceClass</td>
      <td>string</td>
      <td>b'The class of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.UserModTime</td>
      <td>number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.AutoRole</td>
      <td>string</td>
      <td>b'The role automatically detected by the ExtraHop.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ParentId</td>
      <td>number</td>
      <td>b'The ID of the parent device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Vendor</td>
      <td>string</td>
      <td>b'The device vendor.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Analysis</td>
      <td>string</td>
      <td>b'The level of analysis preformed on the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DiscoveryId</td>
      <td>string</td>
      <td>b'The UUID given by the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DefaultName</td>
      <td>string</td>
      <td>b'The default name of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DisplayName</td>
      <td>string</td>
      <td>b'The display name of device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.OnWatchlist</td>
      <td>boolean</td>
      <td>b'Whether the device is on the advanced analysis whitelist.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ModTime</td>
      <td>number</td>
      <td>b'The time of the most recent update, expressed in milliseconds since the epoch.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.IsL3</td>
      <td>boolean</td>
      <td>b'Indicates whether the device is a Layer 3 device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Role</td>
      <td>string</td>
      <td>b'The role of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DiscoverTime</td>
      <td>number</td>
      <td>b'The time that the device was discovered.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Id</td>
      <td>number</td>
      <td>b'The ID of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr4</td>
      <td>string</td>
      <td>b'The IPv4 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Vlanid</td>
      <td>number</td>
      <td>b'The ID of VLan.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Ipaddr6</td>
      <td>string</td>
      <td>b'The IPv6 address of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NodeId</td>
      <td>number</td>
      <td>b'The Node ID of the Discover appliance.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Description</td>
      <td>string</td>
      <td>b'A user customizable description of the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DnsName</td>
      <td>string</td>
      <td>b'The DNS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.DhcpName</td>
      <td>string</td>
      <td>b'The DHCP name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.CdpName</td>
      <td>string</td>
      <td>b'The Cisco Discovery Protocol name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.NetbiosName</td>
      <td>string</td>
      <td>b'The NetBIOS name associated with the device.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.Url</td>
      <td>string</td>
      <td>b'Link to the device details page in ExtraHop.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ClientProtocols</td>
      <td>string</td>
      <td>b'The list of protocols the peer device is communicating as a client.'</td>
    </tr>
    <tr>
      <td>ExtraHop.Device.ServerProtocols</td>
      <td>string</td>
      <td>b'The list of protocols the peer device is communicating as a server.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-get-protocols ip_or_id=172.16.34.11</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "Device": [
            {
                "Analysis": "advanced",
                "AnalysisLevel": 2,
                "AutoRole": "http_server",
                "ClientProtocols": [
                    "TCP:SSL:LDAP",
                    "TCP:SSL",
                    "TCP:OTHER",
                    "UDP:NTP",
                    "UDP:DNS"
                ],
                "DefaultName": "Qumranet 172.16.34.11",
                "DeviceClass": "node",
                "DhcpName": "soundboard2",
                "DiscoverTime": 1533851430000,
                "DiscoveryId": "fff40601150a0000",
                "DisplayName": "tme-lab-ubuntu",
                "ExtrahopId": "fff40601150a0000",
                "Id": 10754,
                "Ipaddr4": "172.16.34.11",
                "IsL3": true,
                "Macaddr": "11:2B:5B:27:12:9D",
                "ModTime": 1569276433204,
                "OnWatchlist": true,
                "ParentId": 10748,
                "Role": "http_server",
                "ServerProtocols": [
                    "TCP:HTTP"
                ],
                "Url": "https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff40601150a0000/overview/",
                "UserModTime": 1569284010207,
                "Vendor": "Qumranet",
                "Vlanid": 0
            }
        ]
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Device Activity Found</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>Display Name</strong></th>
      <th><strong>IP Address</strong></th>
      <th><strong>MAC Address</strong></th>
      <th><strong>Protocols (Client)</strong></th>
      <th><strong>Protocols (Server)</strong></th>
      <th><strong>Role</strong></th>
      <th><strong>Vendor</strong></th>
      <th><strong>URL</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>soundboard2</td>
      <td>172.16.34.11</td>
      <td>11:2B:5B:27:12:9D</td>
      <td>TCP:SSL:LDAP, TCP:SSL, TCP:OTHER, UDP:NTP, UDP:DNS</td>
      <td>TCP:HTTP</td>
      <td>http_server</td>
      <td>Qumranet</td>
      <td>[View Device in ExtraHop](https://test1.extrahop.com/extrahop/#/metrics/devices/a74b9b6aa9e44de9baedcf8112c27ec4.fff40601150a0000/overview/)</td>
    </tr>
  </tbody>
</table>

</p>

<h3>11. Add or remove a tag from devices</h3>
<!-- <hr> -->
<p>Add or remove a tag from devices in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-tag-devices</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>tag</td>
      <td>The case-sensitive value of the tag.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>add</td>
      <td>The list of IP Addresses or ExtraHop API IDs of the devices to tag, comma separated.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>remove</td>
      <td>The list of IP Addresses or ExtraHop API IDs of the devices to remove the tag from, comma separated.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-tag-devices tag='demisto' add=172.16.34.11</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Successful Modification
</p>
</p>

<h3>12. Get a link to a Live Activity Map</h3>
<!-- <hr> -->
<p>Get a link to a visual activity map in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-get-activity-map</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ip_or_id</td>
      <td>The IP Address or ExtraHop API ID of the source device to get an activity map.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>time_interval</td>
      <td>The time interval of the live activity map, expressed as the "Last" 30 minutes. For example, specify a value of 30 minutes to get an activity map showing the time range of the last 30 minutes. This field is ignored if from_time and until_time are provided.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>from_time</td>
      <td>The beginning timestamp of a fixed time range the activity map will display, expressed in seconds since the epoch.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>until_time</td>
      <td>The ending timestamp of a fixed time range the activity map will display, expressed in seconds since the epoch.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>peer_role</td>
      <td>The role of the peer devices in relation to the source device. For example, specifying a peer_role of client will show All Clients communicating with the source device. Additionally specifying a protocol of HTTP will result in further filtering and only showing HTTP Clients communicating with the source device.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>protocol</td>
      <td>The protocol over which the source device is communicating. For example, specifying a protocol of HTTP show only HTTP Clients and HTTP Servers communicating with the source device. Additionally specifying a peer_role of client will result in further filtering and only showing HTTP Clients communicating with the source device.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Path</strong>
      </th>
      <th>
        <strong>Type</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>ExtraHop.ActivityMap</td>
      <td>string</td>
      <td>b'The link to a visual activity map in ExtraHop.'</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-get-activity-map ip_or_id=172.16.34.11 time_interval="6 hours"</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "ExtraHop": {
        "ActivityMap": "https://test1.extrahop.com/extrahop/#/activitymaps?appliance_id=a74b9b6aa9e44de9baedcf8112c27ec4&discovery_id=fff40601150a0000&from=6&interval_type=HR&object_type=device&protocol=any&role=any&until=0"
    }
}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
[View Live Activity Map in ExtraHop](https://test1.extrahop.com/extrahop/#/activitymaps?appliance_id=a74b9b6aa9e44de9baedcf8112c27ec4&discovery_id=fff40601150a0000&from=6&interval_type=HR&object_type=device&protocol=any&role=any&until=0)
</p>
</p>

<h3>13. Search for specific packets</h3>
<!-- <hr> -->
<p>Search for specific packets in ExtraHop.</p>
<h5>Base Command</h5>
<p>
  <code>extrahop-search-packets</code>
</p>
<h5>Required Permissions</h5>
<ul>
    <li>Full write privileges</li>
    <li>Packet and Session Key Access</li>
</ul>
<h5>Input</h5>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th>
        <strong>Argument Name</strong>
      </th>
      <th>
        <strong>Description</strong>
      </th>
      <th>
        <strong>Required</strong>
      </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>output</td>
      <td>The output format. A pcap file, A keylog.txt file that can be loaded in wireshark to decode ssl packets, or a zip file containing both a packets.pcap and keylog.txt.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit_bytes</td>
      <td>The maximum number of bytes to return.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>limit_search_duration</td>
      <td>The maximum amount of time to run the packet search. The default unit is milliseconds, but other units can be specified with a unit suffix.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>query_from</td>
      <td>The beginning timestamp of the time range the search will include, expressed in milliseconds since the epoch. A negative value specifies that the search will begin with packets captured at a time in the past relative to the current time. For example, specify -10m to begin the search with packets captured 10 minutes before the time of the request. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>query_until</td>
      <td>The ending timestamp of the time range the search will include, expressed in milliseconds since the epoch. A 0 value specifies that the search will end with packets captured at the time of the search. A negative value specifies that the search will end with packets captured at a time in the past relative to the current time. For example, specify -5m to end the search with packets captured 5 minutes before the time of the request. The default unit for a negative value is milliseconds, but other units can be specified with one of the following unit suffixes: ms, s, m, h, d, w, M, y. See https://docs.extrahop.com/current/rest-api-guide/#supported-time-units- for more details on supported time units and suffixes.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>bpf</td>
      <td>The Berkeley Packet Filter (BPF) syntax for the packet search.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ip1</td>
      <td>Returns packets sent to or received by the specified IP address.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>port1</td>
      <td>Returns packets sent from or received on the specified port.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ip2</td>
      <td>Returns packets sent to or received by the specified IP address.</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>port2</td>
      <td>Returns packets sent from or received on the specified port.</td>
      <td>Optional</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!extrahop-search-packets ip1=172.16.34.23 port1=10057 ip2=172.16.34.11 port2=44576</code>
</p>

<h5>Human Readable Output</h5>
<p>
<p>
Uploaded file: extrahop 2019-09-23 16.59.01 to 17.29.01 PST.pcap
</p>
</p>
<h2>Additional Information</h2>
<h2>Known Limitations</h2>
<h2>Troubleshooting</h2>
<p>This integration was integrated and tested with version 7.8 of ExtraHop Reveal(x) and version 4.5 of Demisto.
