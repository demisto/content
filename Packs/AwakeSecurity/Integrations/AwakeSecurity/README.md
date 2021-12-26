<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the Awake Security integration to manage and respond to network threats.</p>
<h2>Configure Awake Security on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Awake Security.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Credentials</strong></li>
<li><strong>Awake Security server address</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Comma-separated list of threat behaviors to generate incidents for, e.g., "Exfiltration: SSL upload from non-browser to notable domain, Lateral Movement: Unix-based PSEXEC, C2: Possible ICMP tunnel"</strong></li>
<li><strong>Period between incident fetch interval (in minutes)</strong></li>
<li><strong>Minimum threshold to determine an indicator suspicious in Cortex XSOAR</strong></li>
<li><strong>Minimum threshold to determine an indicator malicious in Cortex XSOAR</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2> </h2>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_99540541251544465827889">Query devices: awake-query-devices</a></li>
<li><a href="#h_275281160801544465832555">Query activities: awake-query-activities</a></li>
<li><a href="#h_860964791541544465837899">Query domains: awake-query-domains</a></li>
<li><a href="#h_8010832212271544465843116">Download a PCAP: awake-pcap-download</a></li>
<li><a href="#h_9509238262991544465847677">Lookup and enrich a domain: domain</a></li>
<li><a href="#h_762108223701544465852418">Lookup and enrich an IP address: ip</a></li>
<li><a href="#h_6557446534401544465856852">Lookup and enrich an email address: email</a></li>
<li><a href="#h_5008973985091544465861235">Lookup and enrich a device: device</a></li>
</ol>
<h3 id="h_99540541251544465827889">1. Query devices</h3>
<p>Query devices in Awake Security.</p>
<h5>Base Command</h5>
<p><code>awake-query-devices</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 172px;"><strong>Argument Name</strong></th>
<th style="width: 437px;"><strong>Description</strong></th>
<th style="width: 99px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">queryExpression</td>
<td style="width: 437px;">A query expression in Awake Query Language</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">startTime</td>
<td style="width: 437px;">Query start time ("2000-01-01T00:00:00Z")</td>
<td style="width: 99px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">endTime</td>
<td style="width: 437px;">Query end time ("2000-01-01T00:00:00Z")</td>
<td style="width: 99px;">Required</td>
</tr>
<tr>
<td style="width: 172px;">ipAddress</td>
<td style="width: 437px;">IP address to filter by (exact match)</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">deviceName</td>
<td style="width: 437px;">Device name to filter by (regular expression)</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">domainName</td>
<td style="width: 437px;">Domain name to filter by (regular expression)</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">protocol</td>
<td style="width: 437px;">Protocol to filter by (all uppercase, i.e. "TLS")</td>
<td style="width: 99px;">Optional</td>
</tr>
<tr>
<td style="width: 172px;">tag</td>
<td style="width: 437px;">Tag to filter by (regular expression)</td>
<td style="width: 99px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 321px;"><strong>Path</strong></th>
<th style="width: 67px;"><strong>Type</strong></th>
<th style="width: 320px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.deviceId</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">Awake Security unique identifier for the specified device</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.deviceName</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">Device name</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.firstSeen</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">Date that the specified device was first seen</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.lastSeen</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">Date that the specified device was last seen</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.os</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">Operating system associated with the specified device</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.deviceType</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">Device type</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.ips</td>
<td style="width: 67px;">unknown</td>
<td style="width: 320px;">List of IP addresses associated with the specified device</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.monitoringPointIds</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">List of monitoring point IDs the specified device was seen on</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.application</td>
<td style="width: 67px;">string</td>
<td style="width: 320px;">List of applications the specified device was seen using</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.notabilityPercentile</td>
<td style="width: 67px;">number</td>
<td style="width: 320px;">How the notability of this device compares to other devices</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.numberSimilarDevices</td>
<td style="width: 67px;">number</td>
<td style="width: 320px;">Number of devices that are similar to this device</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.numberSessions</td>
<td style="width: 67px;">number</td>
<td style="width: 320px;">Number of TCP sessions for this device</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.ackTime</td>
<td style="width: 67px;">number</td>
<td style="width: 320px;">Date of the last TCP session acknowledgment of the device associated with the specified email address</td>
</tr>
<tr>
<td style="width: 321px;">AwakeSecurity.Devices.whiteListed</td>
<td style="width: 67px;">bool</td>
<td style="width: 320px;">Is the device associated with the specified email address in the allow list</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!awake-query-devices startTime="2018-07-18T07:00:00Z" endTime="2018-07-18T07:30:00Z"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49085895-c96b5380-f25b-11e8-981f-49094d9f5995.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49085895-c96b5380-f25b-11e8-981f-49094d9f5995.png" alt="screen shot 2018-11-27 at 15 47 31"></a></p>
<h3 id="h_275281160801544465832555">2. Query activities</h3>
<p>Query activities in Awake Security</p>
<h5>Base Command</h5>
<p><code>awake-query-activities</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 161px;"><strong>Argument Name</strong></th>
<th style="width: 453px;"><strong>Description</strong></th>
<th style="width: 94px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 161px;">queryExpression</td>
<td style="width: 453px;">A query expression in the Awake Query Language</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">startTime</td>
<td style="width: 453px;">Query start time ("2000-01-01T00:00:00Z")</td>
<td style="width: 94px;">Required</td>
</tr>
<tr>
<td style="width: 161px;">endTime</td>
<td style="width: 453px;">Query end time ("2000-01-01T00:00:00Z")</td>
<td style="width: 94px;">Required</td>
</tr>
<tr>
<td style="width: 161px;">ipAddress</td>
<td style="width: 453px;">IP address to filter by (exact match)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">deviceName</td>
<td style="width: 453px;">Device name to filter by (regular expression)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">domainName</td>
<td style="width: 453px;">Domain name to filter by (regular expression)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">protocol</td>
<td style="width: 453px;">Protocol to filter by (all uppercase, e.g., "TLS")</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 161px;">tag</td>
<td style="width: 453px;">Tag to filter by (regular expression)</td>
<td style="width: 94px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 310px;"><strong>Path</strong></th>
<th style="width: 60px;"><strong>Type</strong></th>
<th style="width: 338px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.activityId</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">UUID that uniquely identifies the activity</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.sessionId</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">UUID that uniquely identifies the corresponding session</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.sourceIP</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">IP address of the source</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.sourceHost</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">Hostname of the source</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.sourcePort</td>
<td style="width: 60px;">number</td>
<td style="width: 338px;">Port of the source</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.destinationIP</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">IP address of the destination</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.destinationHost</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">Hostname of the destination</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.destinationPort</td>
<td style="width: 60px;">number</td>
<td style="width: 338px;">Port of the destination</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.directionKnown</td>
<td style="width: 60px;">bool</td>
<td style="width: 338px;">Do we know for sure which endpoint was the client?</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.activityDeviceName</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">Device name for the endpoint within your network</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.activityStart</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">Date when the activity began</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.activityEnd</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">Date when the activity ended</td>
</tr>
<tr>
<td style="width: 310px;">AwakeSecurity.Activities.protocols</td>
<td style="width: 60px;">string</td>
<td style="width: 338px;">Protocols that the activity used</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!awake-query-activities startTime="2018-07-01T00:00:00Z" endTime="2018-08-01T00:00:00Z" domainName="kck.st"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49085933-e7d14f00-f25b-11e8-9df3-b345ebba8400.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49085933-e7d14f00-f25b-11e8-9df3-b345ebba8400.png" alt="screen shot 2018-11-27 at 15 48 27"></a></p>
<h3 id="h_860964791541544465837899">3. Query domains</h3>
<p>Query domains in Awake Security</p>
<h5>Base Command</h5>
<p><code>awake-query-domains</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 162px;"><strong>Argument Name</strong></th>
<th style="width: 452px;"><strong>Description</strong></th>
<th style="width: 94px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 162px;">queryExpression</td>
<td style="width: 452px;">A query expression in the Awake Query Language</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">startTime</td>
<td style="width: 452px;">Query start time ("2000-01-01T00:00:00Z")</td>
<td style="width: 94px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">endTime</td>
<td style="width: 452px;">Query end time ("2000-01-01T00:00:00Z")</td>
<td style="width: 94px;">Required</td>
</tr>
<tr>
<td style="width: 162px;">ipAddress</td>
<td style="width: 452px;">IP address to filter by (exact match)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">deviceName</td>
<td style="width: 452px;">Device name to filter by (regular expression)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">domainName</td>
<td style="width: 452px;">Domain name to filter by (regular expression)</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">protocol</td>
<td style="width: 452px;">Protocol to filter by (all uppercase, e.g., "TLS")</td>
<td style="width: 94px;">Optional</td>
</tr>
<tr>
<td style="width: 162px;">tag</td>
<td style="width: 452px;">Tag to filter by (regular expression)</td>
<td style="width: 94px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 294px;"><strong>Path</strong></th>
<th style="width: 59px;"><strong>Type</strong></th>
<th style="width: 355px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.name</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Domain name</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.created</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Date the specified domain was created</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.lastUpdated</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Date the specified domain was last updated</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.registrantOrg</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Organization of the registrant</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.registrantCountry</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Country of the registrant</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.registrarName</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Name of the registrar</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.whoisServer</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">Address of the WHOIS server</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.whoisFound</td>
<td style="width: 59px;">bool</td>
<td style="width: 355px;">Was this domain found via WHOIS</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.deviceCount</td>
<td style="width: 59px;">number</td>
<td style="width: 355px;">Number of devices currently interacting with the specified domain</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.totalDevices</td>
<td style="width: 59px;">number</td>
<td style="width: 355px;">Total number of devices that have interacted with the specified domain</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.intelCount</td>
<td style="width: 59px;">number</td>
<td style="width: 355px;">Number of matches of imported intel against the specified domain</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.lastSeen</td>
<td style="width: 59px;">number</td>
<td style="width: 355px;">Date of the most recent interaction with the specified domain</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.nameservers</td>
<td style="width: 59px;">string</td>
<td style="width: 355px;">List of authoritative nameservers for the specified domain</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.notability</td>
<td style="width: 59px;">number</td>
<td style="width: 355px;">Notability score of the domain</td>
</tr>
<tr>
<td style="width: 294px;">AwakeSecurity.Domains.whiteListed</td>
<td style="width: 59px;">bool</td>
<td style="width: 355px;">Is the specified domain in allow list</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!awake-query-domains startTime="2018-07-18T07:00:00Z" endTime="2018-07-18T07:30:00Z"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49086057-47c7f580-f25c-11e8-8bec-053dc454cfcd.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49086057-47c7f580-f25c-11e8-8bec-053dc454cfcd.png" alt="screen shot 2018-11-27 at 15 51 07"></a></p>
<h3 id="h_8010832212271544465843116">4. Download a PCAP</h3>
<p>Download a PCAP.</p>
<h5>Base Command</h5>
<p><code>awake-pcap-download</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 167px;"><strong>Argument Name</strong></th>
<th style="width: 443px;"><strong>Description</strong></th>
<th style="width: 98px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 167px;">protocol</td>
<td style="width: 443px;">Protocol to filter by (all uppercase, e.g., "TLS")</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">hostA</td>
<td style="width: 443px;">First host's address</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">portA</td>
<td style="width: 443px;">First host's port</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">hostB</td>
<td style="width: 443px;">Second host's address</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">portB</td>
<td style="width: 443px;">Second host's port</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">startTime</td>
<td style="width: 443px;">Query start time ("2000-01-01T00:00:00Z")</td>
<td style="width: 98px;">Optional</td>
</tr>
<tr>
<td style="width: 167px;">endTime</td>
<td style="width: 443px;">Query end time ("2000-01-01T00:00:00Z")</td>
<td style="width: 98px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 188px;"><strong>Path</strong></th>
<th style="width: 121px;"><strong>Type</strong></th>
<th style="width: 399px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 188px;">File.Size</td>
<td style="width: 121px;">number</td>
<td style="width: 399px;">File size</td>
</tr>
<tr>
<td style="width: 188px;">File.MD5</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">MD5 of the file</td>
</tr>
<tr>
<td style="width: 188px;">File.SHA1</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">SHA-1 of the file</td>
</tr>
<tr>
<td style="width: 188px;">File.SHA256</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">SHA-256 of the file</td>
</tr>
<tr>
<td style="width: 188px;">File.Name</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">File name</td>
</tr>
<tr>
<td style="width: 188px;">File.SSDeep</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">SSDeep hash of the file</td>
</tr>
<tr>
<td style="width: 188px;">File.EntryID</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">War Room Entry ID of the file</td>
</tr>
<tr>
<td style="width: 188px;">File.Info</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">File common metadata</td>
</tr>
<tr>
<td style="width: 188px;">File.Type</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">File type</td>
</tr>
<tr>
<td style="width: 188px;">File.Extension</td>
<td style="width: 121px;">string</td>
<td style="width: 399px;">File Extension e.g., "pcap"</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!awake-pcap-download hostA="10.200.103.100" hostB="10.200.103.100" portA="67" portB="68"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49086088-5e6e4c80-f25c-11e8-8166-377e45e63fee.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49086088-5e6e4c80-f25c-11e8-8166-377e45e63fee.png" alt="screen shot 2018-11-27 at 15 51 46"></a></p>
<h3 id="h_9509238262991544465847677">5. Lookup and enrich a domain</h3>
<p>Lookup and enrich a domain.</p>
<h5>Base Command</h5>
<p><code>domain</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 149px;"><strong>Argument Name</strong></th>
<th style="width: 488px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 149px;">domain</td>
<td style="width: 488px;">The domain name</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 149px;">lookback_minutes</td>
<td style="width: 488px;">How many minutes of history to query from the current time. Default is 480.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 487px;"><strong>Path</strong></th>
<th style="width: 72px;"><strong>Type</strong></th>
<th style="width: 149px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.approxBytesTransferred</td>
<td style="width: 72px;">number</td>
<td style="width: 149px;">Approximate bytes the indicator transferred</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.DomainWithSameRegistrant</td>
<td style="width: 72px;">unknown</td>
<td style="width: 149px;">Domains with the same registrant</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.domainsWithSameRegistrant.registrationDate</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Date that the domain with the same registrant as the specified domain was registered</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.IntelSources</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Indicators of compromise from Awake Security</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.ipAddresses</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">IP addresses associated with the domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.isAlexaTopOneMillion</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Does the domain appear in Alexa 1 million list</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.isDGA</td>
<td style="width: 72px;">boolean</td>
<td style="width: 149px;">Is domain generation algorithm</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.lastSeen</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Last time the domain was seen</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.notabillity</td>
<td style="width: 72px;">number</td>
<td style="width: 149px;">Notability score of the domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.numAssociatedActivities</td>
<td style="width: 72px;">number</td>
<td style="width: 149px;">Number of network activities associated with the domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.numAssociatedADevices</td>
<td style="width: 72px;">number</td>
<td style="width: 149px;">Number of devices associated with the domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.protocols</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">List of protocols used in the domain activities</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.relatedSubdomains</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Related subdomains of the specified domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.subdomains</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Subdomains of the specified domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.topDevices</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">List of devices that accessed the specified domain (maximum is 10)</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.totalNumDevices</td>
<td style="width: 72px;">number</td>
<td style="width: 149px;">Total number of devices that accessed the specified domain</td>
</tr>
<tr>
<td style="width: 487px;">AwakeSecurity.Domains.whiteListed</td>
<td style="width: 72px;">boolean</td>
<td style="width: 149px;">Is the specified domain in allow list</td>
</tr>
<tr>
<td style="width: 487px;">DBotScore.Indicator</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">The specified domain</td>
</tr>
<tr>
<td style="width: 487px;">DBotScore.Score</td>
<td style="width: 72px;">number</td>
<td style="width: 149px;">Severity score of the specified domain in Cortex XSOAR</td>
</tr>
<tr>
<td style="width: 487px;">DBotScore.Type</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Indicator type in Cortex XSOAR</td>
</tr>
<tr>
<td style="width: 487px;">DBotScore.Vendor</td>
<td style="width: 72px;">string</td>
<td style="width: 149px;">Vendor used to assess the specified domain</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!domain domain="adobesc.com"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49086142-7c3bb180-f25c-11e8-822b-61520fa109a9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49086142-7c3bb180-f25c-11e8-822b-61520fa109a9.png" alt="screen shot 2018-11-27 at 15 52 31"></a></p>
<h3 id="h_762108223701544465852418">6. Lookup and enrich an IP address</h3>
<p>Lookup and enrich an IP address.</p>
<h5>Base Command</h5>
<p><code>ip</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 478px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">ip</td>
<td style="width: 478px;">The IP address</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 159px;">lookback_minutes</td>
<td style="width: 478px;">How many minutes of history to query from the current time. Default is 480.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 215px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 417px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 215px;">AwakeSecurity.IPs.activityCount</td>
<td style="width: 76px;">number</td>
<td style="width: 417px;">Number of activities associated with the specified IP address</td>
</tr>
<tr>
<td style="width: 215px;">AwakeSecurity.IPs.deviceCount</td>
<td style="width: 76px;">number</td>
<td style="width: 417px;">Number of devices associated with the specified IP address</td>
</tr>
<tr>
<td style="width: 215px;">AwakeSecurity.IPs.devices</td>
<td style="width: 76px;">unknown</td>
<td style="width: 417px;">Device object associated with the specified IP address</td>
</tr>
<tr>
<td style="width: 215px;">AwakeSecurity.IPs.domains</td>
<td style="width: 76px;">unknown</td>
<td style="width: 417px;">Domain object associated with the specified IP address</td>
</tr>
<tr>
<td style="width: 215px;">AwakeSecurity.IPs.ipFirstSeen</td>
<td style="width: 76px;">string</td>
<td style="width: 417px;">Date that the IP address was first seen in Awake Security</td>
</tr>
<tr>
<td style="width: 215px;">AwakeSecurity.IPs.ipLastSeen</td>
<td style="width: 76px;">string</td>
<td style="width: 417px;">Date that the IP address was last seen in Awake Security</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Indicator</td>
<td style="width: 76px;">string</td>
<td style="width: 417px;">The specified IP address</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Score</td>
<td style="width: 76px;">number</td>
<td style="width: 417px;">Severity score of the specified IP address in Cortex XSOAR</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Vendor</td>
<td style="width: 76px;">string</td>
<td style="width: 417px;">Vendor used to assess the specified IP address</td>
</tr>
<tr>
<td style="width: 215px;">DBotScore.Type</td>
<td style="width: 76px;">string</td>
<td style="width: 417px;">Indicator type in Cortex XSOAR</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!ip ip="10.200.104.236"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49086196-970e2600-f25c-11e8-9817-0a7c9f674028.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49086196-970e2600-f25c-11e8-9817-0a7c9f674028.png" alt="screen shot 2018-11-27 at 15 53 19"></a></p>
<h3 id="h_6557446534401544465856852">7. Lookup and enrich and enrich an email address</h3>
<p>Lookup and enrich an email address.</p>
<h5>Base Command</h5>
<p><code>email</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 156px;"><strong>Argument Name</strong></th>
<th style="width: 481px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 156px;">email</td>
<td style="width: 481px;">The email address</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 156px;">lookback_minutes</td>
<td style="width: 481px;">How many minutes of history to query from the current time. Default is 480.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 308px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 337px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.deviceId</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Device ID associated with the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.deviceName</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Device name associated with the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.firstSeen</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Date that the email address was first seen in Awake Security</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.lastSeen</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Date that the email address was last seen in Awake Security</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.duration</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Time (in seconds) between the email address first seen date and last seen date in Awake Security</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.os</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Operating system of the device associated with the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.deviceType</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Device type associated with the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.ips</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">IP addresses that the device associated with the specified email address accessed</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.monitoringPointIds</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Monitoring point IDs on which the device associated with the specified email address were seen</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.application</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Email applications associated with this email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.notabilityPercentile</td>
<td style="width: 63px;">number</td>
<td style="width: 337px;">Notability (risk score) of the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.numberSimilarDevices</td>
<td style="width: 63px;">number</td>
<td style="width: 337px;">Number of similar devices associated with the device of the specified email addresses</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.numberSessions</td>
<td style="width: 63px;">number</td>
<td style="width: 337px;">Number of TCP sessions the device associated with this email address initiated</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.ackTime</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Date of the last TCP session acknowledgment of the device associated with the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">AwakeSecurity.Emails.whiteListed</td>
<td style="width: 63px;">bool</td>
<td style="width: 337px;">Is the device associated with the specified email address in the allow list</td>
</tr>
<tr>
<td style="width: 308px;">DBotScore.Score</td>
<td style="width: 63px;">number</td>
<td style="width: 337px;">Severity score of the specified email address in Cortex XSOAR</td>
</tr>
<tr>
<td style="width: 308px;">DBotScore.Type</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Indicator type in Cortex XSOAR</td>
</tr>
<tr>
<td style="width: 308px;">DBotScore.Vendor</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">Vendor used to assess the specified email address</td>
</tr>
<tr>
<td style="width: 308px;">DBotScore.Indicator</td>
<td style="width: 63px;">string</td>
<td style="width: 337px;">The specified email address</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!email email="rajguru2003@yahoo.com"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49086239-b311c780-f25c-11e8-8d39-b1ddabfeb019.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49086239-b311c780-f25c-11e8-8d39-b1ddabfeb019.png" alt="screen shot 2018-11-27 at 15 54 03"></a></p>
<h3 id="h_5008973985091544465861235">8. Lookup and enrich a device</h3>
<p>Lookup and enrich a device.</p>
<h5>Base Command</h5>
<p><code>device</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">device</td>
<td style="width: 492px;">The device ID</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">lookback_minutes</td>
<td style="width: 492px;">How many minutes of history to query from the current time. Default is 480.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 387px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 255px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.deviceScore</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Risk score of the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.notableDomainCount.value</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of suspicious domains accessed by the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.notableDomainCount.percentile</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Percentile of the specified device for notable domains accessed</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.notableDomainCount.weight</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Importance given to the suspicious domains when calculating the specified device risk score</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.iocCount.value</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of suspicious IOCs associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.iocCount.percentile</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Percentile of the specified device for notable IOCs</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.iocCount.weight</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Importance given to the IOCs when calculating the specified device risk score</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.watchlistCount.value</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Total number of current threat behaviors associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.watchlistCount.percentile</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">How this device compares to other devices for number of threat behaviors</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.watchlistCount.weight</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Importance given to the threat behaviors when calculating the specified device risk score</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.activityCount.value</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of characteristic artifacts associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.activityCount.percentile</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">How this device compares to other devices for characteristic artifacts</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.activityCount.weight</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Importance given to the characteristic artifacts when calculating the specified device risk score</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.deviceName</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Device name</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.deviceType</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Device type</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.os</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Operating system associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.recentIp</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Most recent IP address associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.activeIp</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Most common IP address associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.commonEmail</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Most common email address associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.commonUsername</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Most common username associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.commonMpid</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Most common monitoring point ID the specified device was seen on</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.nSimilarDevices</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of devices that are similar to the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.tags</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Tags applied to the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.ipCount</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of IP addresses associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.emailCount</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of email addresses associated with this device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.usernameCount</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of usernames associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.applicationCount</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of applications associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.mpids</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">List of monitoring point IDs associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.protocols.count</td>
<td style="width: 66px;">number</td>
<td style="width: 255px;">Number of time this protocol was used by the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.firstSeen</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Date that the specified device was first seen</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.lastSeen</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Date that the specified device was last seen</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.osVersion</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Operating system version of the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.deviceGuid</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Awake Security unique identifier for the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.ips</td>
<td style="width: 66px;">unknown</td>
<td style="width: 255px;">List of IP addresses associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.usernames</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">List of usernames that were inferred as accounts on the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.emails</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">List of email addresses associated with the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.ackTs</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Date of the last TCP session acknowledgment of the specified device</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.whiteListed</td>
<td style="width: 66px;">bool</td>
<td style="width: 255px;">Is the device associated with the specified email address in the allow list</td>
</tr>
<tr>
<td style="width: 387px;">AwakeSecurity.Devices.protocols.name</td>
<td style="width: 66px;">string</td>
<td style="width: 255px;">Type of protocol used by the specified device</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!device device="dae6720d-0588-d23b-c006-63cf1134537b"</code></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/37335599/49086270-cf156900-f25c-11e8-8bcf-3fcc02c17db6.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/37335599/49086270-cf156900-f25c-11e8-8bcf-3fcc02c17db6.png" alt="screen shot 2018-11-27 at 15 54 03"></a></p>