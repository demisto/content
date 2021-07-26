<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the SCADAfence integration to manage alerts and assets.</p>
<p>This integration was integrated and tested with SCADAfence CNM v.</p>
<h2> </h2>
<h2>Use cases</h2>
<hr>
<ol>
<li>Fetch alerts from SCADAfence</li>
</ol>
<h2> </h2>
<h2>Configure the SCADAfence CNM Integration on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for SCADAfence CNM.</li>
<li>Click _<strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>API auth secret</strong></li>
<li><strong>API auth key</strong></li>
<li><strong>API url</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Required severity levels for alerts separated by comma, from [Information,Warning,Threat,Severe,Critical]. For ex.: Warning, Threat</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2> </h2>
<h2>Fetched Incidents Data</h2>
<hr>
<pre>[
    {
        "createdOn": "2018-08-05T12:06:22.278Z",
        "details": "1.1.1.1 sent suspicious write command to PLC 2.2.2.2.",
        "id": "5b600cecfeb8001f1cc5d2ea",
        "ip": "2.2.2.2",
        "severity": "Critical",
        "status": "InProgress",
        "type": "Suspicious write command to PLC"
    }
]
</pre>
<h2> </h2>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.<br>After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_341447190111536054048838">Query alert data: scadafence-getAlerts</a></li>
<li><a href="#h_598010968831536054057134">Get asset data: scadafence-getAsset</a></li>
<li><a href="#h_2254461141531536054062511">Set the status of an alert: scadafence-setAlertStatus</a></li>
<li><a href="#h_3245436082181536054068568">Get asset connection data: scadafence-getAssetConnections</a></li>
<li><a href="#h_4323121422861536054073929">Get asset network activity data: scadafence-getAssetTraffic</a></li>
<li><a href="#h_181184278621541923404372">Create an alert: scadafence-createAlert</a></li>
<li><a href="#h_5094126331561541923409511">Get all connections: scadafence-getAllConnections</a></li>
</ol>
<h3 id="h_341447190111536054048838">1. Query alert data</h3>
<hr>
<p>Queries alerts data from SCADAfence CNM.</p>
<h5>Base Command</h5>
<pre><code>scadafence-getAlerts</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 191px;"><strong>Argument Name</strong></th>
<th style="width: 325px;"><strong>Description</strong></th>
<th style="width: 112px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 191px;">severity</td>
<td style="width: 325px;">Required severity level of alert</td>
<td style="width: 112px;">Optional</td>
</tr>
<tr>
<td style="width: 191px;">ipAddress</td>
<td style="width: 325px;">IP address to get alerts for</td>
<td style="width: 112px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<pre><code>[
    {
        "createdOn": "2018-08-05T12:06:22.278Z",
        "details": "140.80.0.101 sent suspicious write command to PLC 2.2.2.2.",
        "id": "5b600cecfeb8001f1cc5d2ea",
        "ip": "2.2.2.2",
        "severity": "Critical",
        "status": "Resolved",
        "type": "Suspicious write command to PLC"
    }
]
</code></pre>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 312px;"><strong>Path</strong></th>
<th style="width: 81px;"><strong>Type</strong></th>
<th style="width: 315px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 312px;">SCADAfence.Alert.id</td>
<td style="width: 81px;">string</td>
<td style="width: 315px;">Alert ID</td>
</tr>
<tr>
<td style="width: 312px;">SCADAfence.Alert.ip</td>
<td style="width: 81px;">string</td>
<td style="width: 315px;">Asset IP</td>
</tr>
<tr>
<td style="width: 312px;">SCADAfence.Alert.severity</td>
<td style="width: 81px;">string</td>
<td style="width: 315px;">Alert severity level</td>
</tr>
<tr>
<td style="width: 312px;">SCADAfence.Alert.type</td>
<td style="width: 81px;">string</td>
<td style="width: 315px;">Short description of the alert</td>
</tr>
<tr>
<td style="width: 312px;">SCADAfence.Alert.details</td>
<td style="width: 81px;">string</td>
<td style="width: 315px;">Extended description of the alert</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!scadafence-getAlerts severity=Critical</code></pre>
<h5>Human Readable Output</h5>
<h3>Alerts are:</h3>
<table style="width: 738px;" border="2">
<thead>
<tr>
<th style="width: 63px;">status</th>
<th style="width: 68px;">severity</th>
<th style="width: 83px;">ip</th>
<th style="width: 134px;">createdOn</th>
<th style="width: 96px;">details</th>
<th style="width: 75px;">type</th>
<th style="width: 197px;">id</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 63px;">Resolved</td>
<td style="width: 68px;">Critical</td>
<td style="width: 83px;">2.2.2.2</td>
<td style="width: 134px;">2018-08-05T12:06:22.278Z</td>
<td style="width: 96px;">140.80.0.101 sent suspicious write command to PLC 2.2.2.2.</td>
<td style="width: 75px;">Suspicious write command to PLC</td>
<td style="width: 197px;">5b600cecfeb8001f1cc5d2ea</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_598010968831536054057134">2. Get asset data</h3>
<hr>
<p>Fetches asset data from SCADAfence CNM.</p>
<h5>Base Command</h5>
<pre><code>scadafence-getAsset</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ipAddress</td>
<td>Asset IP address</td>
<td>Optional</td>
</tr>
<tr>
<td>hostName</td>
<td>Hostname</td>
<td>Optional</td>
</tr>
<tr>
<td>assetType</td>
<td>Asset type (from list of options)</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>SCADAfence.Asset.ip</td>
<td>string</td>
<td>IP address of the suspicious asset</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!scadafence-getAsset ip=10.10.10.10</code></p>
<h5>Context Example</h5>
<pre>[
    {
        "assetTypes": "hmi, server",
        "eventsCount": 0,
        "externalIpsCount": 0,
        "firstSeen": "2016-05-23T12:25:03.838Z",
        "hostname": "wmhtp25",
        "internalIpsCount": 13,
        "ip": "3.3.3.3",
        "lastSeen": "2016-05-23T12:25:03.838Z",
        "mac": "E8:39:35:BD:24:76",
        "nicType": "Ethernet",
        "operatingSystem": "Windows Server 2008 R2",
        "totalBytes": 0,
        "vendor": "Hewlett-Packard Company"
    }
]
</pre>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 255px;"><strong>Path</strong></th>
<th style="width: 83px;"><strong>Type</strong></th>
<th style="width: 370px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 255px;">SCADAfence.Asset.ip</td>
<td style="width: 83px;">string</td>
<td style="width: 370px;">IP address of the suspicious asset</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>scadafence-getAsset ip=10.10.10.10</code></pre>
<h5>Human Readable Output</h5>
<h3>Asset details:</h3>
<table border="2">
<thead>
<tr>
<th>assetTypes</th>
<th>eventsCount</th>
<th>vendor</th>
<th>ip</th>
<th>externalIpsCount</th>
<th>hostname</th>
<th>nicType</th>
<th>mac</th>
<th>lastSeen</th>
<th>totalBytes</th>
<th>internalIpsCount</th>
<th>operatingSystem</th>
<th>firstSeen</th>
</tr>
</thead>
<tbody>
<tr>
<td>hmi, server</td>
<td>0</td>
<td>Hewlett-Packard Company</td>
<td>3.3.3.3</td>
<td>0</td>
<td>wmhtp25</td>
<td>Ethernet</td>
<td>E8:39:35:BD:24:76</td>
<td>2016-05-23T12:25:03.838Z</td>
<td>0</td>
<td>13</td>
<td>Windows Server 2008 R2</td>
<td>2016-05-23T12:25:03.838Z</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_2254461141531536054062511">3. Set the status of an alert</h3>
<hr>
<p>Sets the status of a specified alert.</p>
<h5>Base Command</h5>
<pre><code>scadafence-setAlertStatus</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>alertId</td>
<td>Alert ID</td>
<td>Required</td>
</tr>
<tr>
<td>alertStatus</td>
<td>Alert status</td>
<td>Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<h3>Setting status for alert 5bcf0e1a106e0c000f5448b6 to 'Resolved':</h3>
<table style="width: 70px;" border="2">
<thead>
<tr>
<th style="width: 67px;">success</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 67px;">true</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!scadafence-setAlertStatus alertId=5b600cecfeb8001f1cc5d2ea alertStatus=InProgress</code></pre>
<h5>Human Readable Output</h5>
<h3>Setting status for alert 5bcf0e1a106e0c000f5448b6 to 'Resolved':</h3>
<table style="width: 72px;" border="2">
<thead>
<tr>
<th style="width: 68px;">success</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 68px;">true</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h3 id="h_3245436082181536054068568">4. Get asset connection data</h3>
<hr>
<p>Fetches asset connections data according to one or more parameters.</p>
<h5>Base Command</h5>
<pre><code>scadafence-getAssetConnections</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ipAddress</td>
<td>IP address of the asset</td>
<td>Optional</td>
</tr>
<tr>
<td>hostName</td>
<td>Hostname that corresponds to the asset of interest</td>
<td>Optional</td>
</tr>
<tr>
<td>macAddress</td>
<td>MAC address of the asset</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<pre><code>[
    {
        "dir": "DEST",
        "hostname": "",
        "ip": "1.1.1.1",
        "mac": "08:00:06:01:00:02",
        "port": null,
        "proto": "TCP",
        "traffic": 9691680
    },
    {
        "dir": "DEST",
        "hostname": "t20102173",
        "ip": "2.2.2.2",
        "mac": "00:80:80:8E:8F:F0",
        "port": null,
        "proto": "TCP",
        "traffic": 101410609
    },
    {
        "dir": "SRC",
        "hostname": "",
        "ip": "3.3.3.3",
        "mac": "",
        "port": null,
        "proto": "UDP",
        "traffic": 24768
    },
    {
        "dir": "SRC",
        "hostname": "",
        "ip": "4.4.4.4",
        "mac": "",
        "port": 5355,
        "proto": "UDP",
        "traffic": 816
    }
]</code></pre>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>SCADAfence.Asset.Conn.ip</td>
<td>string</td>
<td>Another endpoint's IP address</td>
</tr>
<tr>
<td>SCADAfence.Asset.Conn.port</td>
<td>number</td>
<td>Another endpoint's port</td>
</tr>
<tr>
<td>SCADAfence.Asset.Conn.protocol</td>
<td>string</td>
<td>Protocol used for the connection</td>
</tr>
<tr>
<td>SCADAfence.Asset.Conn.traffic</td>
<td>number</td>
<td>Total bytes sent (both directions)</td>
</tr>
<tr>
<td>SCADAfence.Asset.Conn.hostname</td>
<td>string</td>
<td>Another endpoint's hostname</td>
</tr>
<tr>
<td>SCADAfence.Asset.Conn.mac</td>
<td>string</td>
<td>Another endpoint's MAC address</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!scadafence-getAssetConnections ipAddress=3.3.3.3</code></pre>
<h5>Context Example</h5>
<pre>[
    {
        "dir": "DEST",
        "hostname": "",
        "ip": "1.1.1.1",
        "mac": "08:00:06:01:00:02",
        "port": null,
        "proto": "TCP",
        "traffic": 9691680
    },
    {
        "dir": "DEST",
        "hostname": "t20102173",
        "ip": "2.2.2.2",
        "mac": "00:80:80:8E:8F:F0",
        "port": null,
        "proto": "TCP",
        "traffic": 101410609
    },
    {
        "dir": "SRC",
        "hostname": "",
        "ip": "3.3.3.3",
        "mac": "",
        "port": null,
        "proto": "UDP",
        "traffic": 24768
    },
    {
        "dir": "SRC",
        "hostname": "",
        "ip": "4.4.4.4",
        "mac": "",
        "port": 5355,
        "proto": "UDP",
        "traffic": 816
    }
]
</pre>
<h5>Human Readable Output</h5>
<h3>Asset connections:</h3>
<table border="2">
<thead>
<tr>
<th>proto</th>
<th>ip</th>
<th>hostname</th>
<th>mac</th>
<th>traffic</th>
<th>port</th>
<th>dir</th>
</tr>
</thead>
<tbody>
<tr>
<td>TCP</td>
<td>1.1.1.1</td>
<td> </td>
<td>08:00:06:01:00:02</td>
<td>9691680</td>
<td> </td>
<td>DEST</td>
</tr>
<tr>
<td>TCP</td>
<td>2.2.2.2</td>
<td>t20102173</td>
<td>00:80:80:8E:8F:F0</td>
<td>101410609</td>
<td> </td>
<td>DEST</td>
</tr>
<tr>
<td>UDP</td>
<td>3.3.3.3</td>
<td> </td>
<td> </td>
<td>24768</td>
<td> </td>
<td>SRC</td>
</tr>
<tr>
<td>UDP</td>
<td>4.4.4.4</td>
<td> </td>
<td> </td>
<td>816</td>
<td>5355</td>
<td>SRC</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_4323121422861536054073929">5. Get asset network activity data</h3>
<hr>
<p>Fetches asset network activity data according to one or more parameters.</p>
<h5>Base Command</h5>
<pre><code>scadafence-getAssetTraffic</code></pre>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Argument Name</strong></th>
<th><strong>Description</strong></th>
<th><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>ipAddress</td>
<td>IP address of the asset</td>
<td>Optional</td>
</tr>
<tr>
<td>macAddress</td>
<td>MAC address of the asset</td>
<td>Optional</td>
</tr>
<tr>
<td>hostName</td>
<td>Hostname of the asset</td>
<td>Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5> </h5>
<h5>Context Output</h5>
<pre><code>{
    "TCP": {
        "Bytes received": 447191388,
        "Bytes sent": 100766536
    },
    "UDP": {
        "Bytes received": 0,
        "Bytes sent": 27560
    }
}
</code></pre>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 331px;"><strong>Path</strong></th>
<th style="width: 71px;"><strong>Type</strong></th>
<th style="width: 306px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 331px;">SCADAfence.AssetTraffic.TCP_tx_bytes</td>
<td style="width: 71px;">number</td>
<td style="width: 306px;">Bytes sent by the asset via TCP</td>
</tr>
<tr>
<td style="width: 331px;">SCADAfence.AssetTraffic.TCP_rx_bytes</td>
<td style="width: 71px;">number</td>
<td style="width: 306px;">Bytes received by the asset via TCP</td>
</tr>
<tr>
<td style="width: 331px;">SCADAfence.AssetTraffic.UDP_tx_bytes</td>
<td style="width: 71px;">number</td>
<td style="width: 306px;">Bytes sent by the asset via UDP</td>
</tr>
<tr>
<td style="width: 331px;">SCADAfence.AssetTraffic.UDP_rx_bytes</td>
<td style="width: 71px;">number</td>
<td style="width: 306px;">Bytes received by the asset via UDP</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!scadafence-getAssetTraffic ipAddress=3.3.3.3</code></pre>
<h5>Context Example</h5>
<pre>{
    "TCP": {
        "Bytes received": 447191388,
        "Bytes sent": 100766536
    },
    "UDP": {
        "Bytes received": 0,
        "Bytes sent": 27560
    }
}
</pre>
<h5>Human Readable Output</h5>
<h3>Asset network activity:</h3>
<table border="2">
<thead>
<tr>
<th>UDP_tx_bytes</th>
<th>TCP_rx_bytes</th>
<th>TCP_tx_bytes</th>
<th>UDP_rx_bytes</th>
</tr>
</thead>
<tbody>
<tr>
<td>27560</td>
<td>447191388</td>
<td>100766536</td>
<td>0</td>
</tr>
</tbody>
</table>
<h3> </h3>
<h3 id="h_181184278621541923404372">6. Create an alert</h3>
<hr>
<p>Creates an alert in SCADAfence CNM.</p>
<h5>Base Command</h5>
<p><code>scadafence-createAlert</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 146px;"><strong>Argument Name</strong></th>
<th style="width: 476px;"><strong>Description</strong></th>
<th style="width: 86px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 146px;">ipAddress</td>
<td style="width: 476px;">IP address of the asset that the alert is related to</td>
<td style="width: 86px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">severity</td>
<td style="width: 476px;">Alert severity level</td>
<td style="width: 86px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">description</td>
<td style="width: 476px;">Human readable alert description</td>
<td style="width: 86px;">Required</td>
</tr>
<tr>
<td style="width: 146px;">remediationText</td>
<td style="width: 476px;">Instructions for issue remediation</td>
<td style="width: 86px;">Optional</td>
</tr>
<tr>
<td style="width: 146px;">alertIsActive</td>
<td style="width: 476px;">Set active=True to make the alert appear in the SCADAfence UI</td>
<td style="width: 86px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 299px;"><strong>Path</strong></th>
<th style="width: 84px;"><strong>Type</strong></th>
<th style="width: 325px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 299px;">SCADAfence.Alert.alertCreated</td>
<td style="width: 84px;">boolean</td>
<td style="width: 325px;">Flag defining alert creation status</td>
</tr>
<tr>
<td style="width: 299px;">SCADAfence.Alert.id</td>
<td style="width: 84px;">string</td>
<td style="width: 325px;">Unique ID set to a new alert</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!scadafence-createAlert alertIsActive=True description=test_alert ipAddress=10.0.0.6 severity=Information remediationText="test alert"</pre>
<h5>Context Example</h5>
<h3>Create alert:</h3>
<table border="2">
<thead>
<tr>
<th>alertCreated</th>
<th>id</th>
</tr>
</thead>
<tbody>
<tr>
<td>true</td>
<td>5bcf1925a81ed3000f831578</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Human Readable Output</h5>
<h3>Create alert:</h3>
<table border="2">
<thead>
<tr>
<th>alertCreated</th>
<th>id</th>
</tr>
</thead>
<tbody>
<tr>
<td>true</td>
<td>5bcf1925a81ed3000f831578</td>
</tr>
</tbody>
</table>
<h2> </h2>
<h3 id="h_5094126331561541923409511">7. Get all connections</h3>
<hr>
<p>Fetches all connections from SCADAfence CNM.</p>
<h5>Base Command</h5>
<pre><code>scadafence-getAllConnections</code></pre>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 289px;"><strong>Path</strong></th>
<th style="width: 65px;"><strong>Type</strong></th>
<th style="width: 354px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 289px;">SCADAfence.Connection.src_ip</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">IP address of endpoint A</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.dest_ip</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">IP address of endpoint B</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.src_port</td>
<td style="width: 65px;">number</td>
<td style="width: 354px;">Port of endpoint A</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.dest_port</td>
<td style="width: 65px;">number</td>
<td style="width: 354px;">Port of endpoint B</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.src_mac</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">Endpoint A MAC address</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.dest_mac</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">Endpoint B MAC address</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.src_cname</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">Endpoint A hostname</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.dest_cname</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">Endpoint B hostname</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.proto</td>
<td style="width: 65px;">string</td>
<td style="width: 354px;">L4 protocol</td>
</tr>
<tr>
<td style="width: 289px;">SCADAfence.Connection.traffic</td>
<td style="width: 65px;">number</td>
<td style="width: 354px;">Total number of bytes sent (both directions)</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!scadafence-getAllConnections</pre>
<h5>Context Example</h5>
<pre>[
  {
    "dest_hostname": "",
    "dest_ip": "1.1.1.1",
    "dest_mac": "F4:54:33:A9:13:23",
    "dest_port": 44818,
    "proto": "TCP",
    "src_hostname": "",
    "src_ip": "4.4.4.4",
    "src_mac": "00:0C:29:65:1C:29",
    "src_port": 50153,
    "traffic": 234840
  },
  {
    "dest_hostname": "",
    "dest_ip": "2.2.2.2",
    "dest_mac": "F4:54:33:A9:0E:60",
    "dest_port": 44818,
    "proto": "TCP",
    "src_hostname": "",
    "src_ip": "3.3.3.3",
    "src_mac": "00:0C:29:65:1C:29",
    "src_port": 50154,
    "traffic": 151722
  },
  {
    "dest_hostname": "",
    "dest_ip": "4.4.4.4",
    "dest_mac": "F4:54:33:A8:33:93",
    "dest_port": 44818,
    "proto": "TCP",
    "src_hostname": "",
    "src_ip": "5.5.5.5",
    "src_mac": "00:0C:29:65:1C:29",
    "src_port": 50108,
    "traffic": 23936
  }
]</pre>
<p> </p>
<h5>Human Readable Output</h5>
<table border="2">
<thead>
<tr>
<th>src_port</th>
<th>proto</th>
<th>dest_hostname</th>
<th>src_hostname</th>
<th>src_ip</th>
<th>traffic</th>
<th>dest_mac</th>
<th>dest_port</th>
<th>src_mac</th>
<th>dest_ip</th>
</tr>
</thead>
<tbody>
<tr>
<td>50153</td>
<td>TCP</td>
<td> </td>
<td> </td>
<td>1.1.1.1</td>
<td>234840</td>
<td>F4:54:33:A9:13:23</td>
<td>44818</td>
<td>00:0C:29:65:1C:29</td>
<td>4.4.4.4</td>
</tr>
<tr>
<td>50154</td>
<td>TCP</td>
<td> </td>
<td> </td>
<td>1.1.1.1</td>
<td>151722</td>
<td>F4:54:33:A9:0E:60</td>
<td>44818</td>
<td>00:0C:29:65:1C:29</td>
<td>1.1.1.1</td>
</tr>
<tr>
<td>50108</td>
<td>TCP</td>
<td> </td>
<td> </td>
<td>1.1.1.1</td>
<td>23936</td>
<td>F4:54:33:A8:33:93</td>
<td>44818</td>
<td>00:0C:29:65:1C:29</td>
<td>4.4.4.4</td>
</tr>
</tbody>
</table>
