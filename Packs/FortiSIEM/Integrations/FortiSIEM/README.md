<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Use the FortiSIEM integration to search and update events and manage resource lists.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ul>
<li>Get alerts using different filters</li>
<li>Maintain resource lists</li>
<li>Close incidents</li>
</ul>
</div>
<div class="cl-preview-section">
<h2 id="configure-fortisiem-on-demisto">Configure FortiSIEM on Cortex XSOAR</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for FortiSIEM.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Server URL (e.g.: https://192.168.0.1)</strong></li>
<li><strong>Credentials</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li><a href="#get-events-by-incident" target="_self">Get events by incident: fortisiem-get-events-by-incident</a></li>
<li><a href="#clear-an-incident" target="_self">Clear an incident: fortisiem-clear-incident</a></li>
<li><a href="#get-events-using-a-filter" target="_self">Get events using a filter: fortisiem-get-events-by-filter</a></li>
<li><a href="#get-device-descriptions" target="_self">Get device descriptions: fortisiem-get-cmdb-devices</a></li>
<li><a href="#get-events-using-a-query" target="_self">Get events using a query: fortisiem-get-events-by-query</a></li>
<li><a href="#get-all-resource-lists" target="_self">Get all resource lists: fortisiem-get-lists</a></li>
<li><a href="#add-an-element-to-a-resource-list." target="_self">Add an element to a resource list: fortisiem-add-item-to-resource-list</a></li>
<li><a href="#remove-elements-from-a-resource-list" target="_self">Remove an element from a resource list: fortisiem-remove-item-from-resource-list</a></li>
<li><a href="#get-a-list-of-all-elements-in-a-resource-list" target="_self">Get a list of all elements in a resource list: fortisiem-get-resource-list</a></li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-events-by-incident">1. Get events by incident</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Gets events by incident.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-get-events-by-incident</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 163px;"><strong>Argument Name</strong></th>
<th style="width: 489px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 163px;">incID</td>
<td style="width: 489px;">ID of the incident by which to filter.</td>
<td style="width: 88px;">Required</td>
</tr>
<tr>
<td style="width: 163px;">maxResults</td>
<td style="width: 489px;">Maximum number of results to return.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 163px;">extendedData</td>
<td style="width: 489px;">Whether to extend the data.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 163px;">maxWaitTime</td>
<td style="width: 489px;">Maximum time for the event report to finish (in seconds).</td>
<td style="width: 88px;">Optional</td>
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
<th style="width: 291px;"><strong>Path</strong></th>
<th style="width: 51px;"><strong>Type</strong></th>
<th style="width: 398px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventType</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Event type.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventID</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">FortiSIEM Event ID.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.RawEventLog</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Raw Event Log.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.ReportingDevice</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Reporting Device.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.IncidentID</td>
<td style="width: 51px;">number</td>
<td style="width: 398px;">Incident ID.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.User</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Event User.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventReceiveTime</td>
<td style="width: 51px;">number</td>
<td style="width: 398px;">Event received timestamp.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Event Name.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.ReportingIP</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Reporting IP address.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.SystemEventCategory</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">System Event Category.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventAction</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">EventAction.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.RelayingIP</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Relaying IP address.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventSeverityCategory</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Severity Category.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.OrganizationName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Organization Name.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.ReportingVendor</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Reporting Vendor.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.ReportingModel</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Reporting Model.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.OrganizationName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Organization name.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.CollectorID</td>
<td style="width: 51px;">number</td>
<td style="width: 398px;">Collector ID.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.EventParserName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Name of raw event parser.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.HostIP</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Host IP address.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.HostName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Host name.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.FileName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Name of the file associated with the event.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.ProcessName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Name of the process associated with the event.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.JobName</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Name of the job associated with the event.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.Status</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Event status.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.DestinationPort</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Port of the traffic’s destination.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.SourcePort</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Port of the traffic’s origin.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.DestinationIP</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Destination IP address for the web.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.SourceIP</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">IP address of the traffic’s origin. The source varies by the direction: In HTTP requests, this is the web browser or other client. In HTTP responses, this is the physical server.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.ExtendedData</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">All additional data returned by FortiSIEM.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.DestinationInterface</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">Interface of the traffic’s destination.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.NATTranslation</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">NAT source port.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.Protocol</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">tcp: The protocol used by web traffic (tcp by default).</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.SourceMAC</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">MAC address associated with the source IP address.</td>
</tr>
<tr>
<td style="width: 291px;">FortiSIEM.Events.NATIP</td>
<td style="width: 51px;">string</td>
<td style="width: 398px;">NAT source IP.</td>
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
<pre>!fortisiem-get-events-by-incident incID=1919 maxResults=3</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.Events": [
        {
            "Destination Host Name": "google-public-dns-a.google.com", 
            "Event Name": "Permitted traffic flow started", 
            "Destination IP": "8.8.8.8", 
            "Incident ID": "1919", 
            "Source IP": "10.10.10.17", 
            "Raw Event Log": "&lt;14&gt;May  2 19:53:33 PA-Firewall 1,2019/05/02 19:53:33,007151000004733,TRAFFIC,start,2304,2019/05/02 19:53:33,10.100.100.17,8.8.8.8,80.80.80.146,8.8.8.8,Internet allow,,,dns,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/05/02 19:53:33,156575,1,57184,53,59686,53,0x400000,udp,allow,109,109,0,1,2019/05/02 19:53:31,0,any,0,32724731,0x0,10.0.0.0-10.255.255.255,United States,0,1,0,n/a,0,0,0,0,,PA-Firewall,from-policy,,,0,,0,,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0", 
            "Reporting IP": "10.100.100.254", 
            "Source TCP/UDP Port": "57184", 
            "IP Protocol": "17 (UDP)", 
            "ExtendedData": {
                "1121": "HOST-10.100.100.17", 
                "1126": "Trust", 
                "1127": "Untrust", 
                "3061": "dns", 
                "3001": "", 
                "110": 10000, 
                "3008": "dns", 
                "24": "LOW", 
                "20": "Permitted traffic flow started", 
                "21": 1, 
                "1": "PAN-OS-TRAFFIC-start-allow", 
                "1038": 0, 
                "5": "0 (Permit)", 
                "8": "10.10.10.254", 
                "1010": "17 (UDP)", 
                "2422": "Google", 
                "1151": "allow", 
                "1150": "Internet allow", 
                "9": "10.10.10.254", 
                "2410": "United States", 
                "1004": "8.8.8.8", 
                "1002": "google-public-dns-a.google.com", 
                "1001": "8.8.8.8", 
                "1000": "10.10.10.17"
                ...
            }, 
            "Event Receive Time": 1556690013000, 
            "Event Type": "PAN-OS-TRAFFIC-start-allow", 
            "Destination TCP/UDP Port": "53 (DOMAIN)", 
            "Event ID": "8255801804490150940"
        }, 
        ...
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="fortisiem-events-for-incident-1919">FortiSIEM events for Incident 1919</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Event Receive Time</th>
<th>Event Type</th>
<th>Event Name</th>
<th>Source IP</th>
<th>Destination IP</th>
<th>Destination Host Name</th>
<th>IP Protocol</th>
<th>Source TCP/UDP Port</th>
<th>Destination TCP/UDP Port</th>
<th>Reporting IP</th>
<th>Raw Event Log</th>
</tr>
</thead>
<tbody>
<tr>
<td>1556690013000</td>
<td>PAN-OS-TRAFFIC-start-allow</td>
<td>Permitted traffic flow started</td>
<td>10.10.10.17</td>
<td>8.8.8.8</td>
<td>google-public-dns-a.google.com</td>
<td>17 (UDP)</td>
<td>57184</td>
<td>53 (DOMAIN)</td>
<td>10.10.10.254</td>
<td>&lt;14&gt;May 2 19:53:33 PA-Firewall 1,2019/05/02 19:53:33,007151000004733,TRAFFIC,start,2304,2019/05/01 09:53:33,10.100.100.17,8.8.8.8,80.227.43.146,8.8.8.8,Internet allow,dns,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/05/02 19:53:33,156575,1,57184,53,59686,53,0x400000,udp,allow,109,109,0,1,2019/05/02 19:53:31,0,any,0,32724731,0x0,10.0.0.0-10.255.255.255,United States,0,1,0,n/a,0,0,0,0,PA-Firewall,from-policy,0,0,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="clear-an-incident">2. Clear an incident</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Clear (close) a FortiSIEM incident.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-clear-incident</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 242px;"><strong>Argument Name</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
<th style="width: 137px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 242px;">incident_id</td>
<td style="width: 361px;">ID of the incident to close.</td>
<td style="width: 137px;">Required</td>
</tr>
<tr>
<td style="width: 242px;">close_reason</td>
<td style="width: 361px;">Reason for closing.</td>
<td style="width: 137px;">Optional</td>
</tr>
</tbody>
</table>
</div>
</div>
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
<pre>!fortisiem-clear-incident incident_id=1919 close_reason="False Positive"</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>Incident cleared successfully.</p>
</div>
<div class="cl-preview-section">
<h3 id="get-events-using-a-filter">3. Get events using a filter</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns an event list according to the specified filters.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-get-events-by-filter</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-2">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 159px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 88px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 159px;">maxResults</td>
<td style="width: 493px;">Maximum number of results to return.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">extendedData</td>
<td style="width: 493px;">Whether to extend the data.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">maxWaitTime</td>
<td style="width: 493px;">Maximum time for the event report to finish (in seconds).</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">reptDevIpAddr</td>
<td style="width: 493px;">Reporting IP address.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">destIpAddr</td>
<td style="width: 493px;">Destination IP address.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">srcIpAddr</td>
<td style="width: 493px;">Source IP address.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">destMACAddr</td>
<td style="width: 493px;">Destination MAC address.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">srcMACAddr</td>
<td style="width: 493px;">Source MAC address.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">destDomain</td>
<td style="width: 493px;">Destination domain.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">srcDomain</td>
<td style="width: 493px;">Source domain.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">destName</td>
<td style="width: 493px;">Destination name.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">srcName</td>
<td style="width: 493px;">Source name.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">destAction</td>
<td style="width: 493px;">Destination action.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">destUser</td>
<td style="width: 493px;">Destination user.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">reportWindow</td>
<td style="width: 493px;">Relative report time value.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">reportWindowUnit</td>
<td style="width: 493px;">Relative report time unit.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">eventType</td>
<td style="width: 493px;">Event type.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">srcGeoCountry</td>
<td style="width: 493px;">Source geo country.</td>
<td style="width: 88px;">Optional</td>
</tr>
<tr>
<td style="width: 159px;">User</td>
<td style="width: 493px;">User.</td>
<td style="width: 88px;">Optional</td>
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
<th style="width: 373px;"><strong>Path</strong></th>
<th style="width: 112px;"><strong>Type</strong></th>
<th style="width: 255px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 373px;">FortiSIEM.Events.EventType</td>
<td style="width: 112px;">Unknown</td>
<td style="width: 255px;">FortiSIEM event type.</td>
</tr>
<tr>
<td style="width: 373px;">FortiSIEM.Events.SourceCountry</td>
<td style="width: 112px;">Unknown</td>
<td style="width: 255px;">Event source country.</td>
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
<pre>!fortisiem-get-events-by-filter maxResults=4 srcIpAddr=10.100.100.17</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.Events": [
        {
            "Destination Host Name": "google-public-dns-a.google.com", 
            "Event Name": "Permitted traffic flow started", 
            "Destination IP": "8.8.8.8", 
            "Incident ID": "1919", 
            "Source IP": "10.100.100.17", 
            "Raw Event Log": "&lt;14&gt;May  2 19:53:33 PA-Firewall 1,2019/05/02 19:53:33,007151000004733,TRAFFIC,start,2304,2019/05/02 19:53:33,10.100.100.17,8.8.8.8,80.80.80.146,8.8.8.8,Internet allow,,,dns,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/05/02 19:53:33,156575,1,57184,53,59686,53,0x400000,udp,allow,109,109,0,1,2019/05/02 19:53:31,0,any,0,32724731,0x0,10.0.0.0-10.255.255.255,United States,0,1,0,n/a,0,0,0,0,,PA-Firewall,from-policy,,,0,,0,,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0", 
            "Reporting IP": "10.100.100.254", 
            "Source TCP/UDP Port": "57184", 
            "IP Protocol": "17 (UDP)", 
            "ExtendedData": {
                "1121": "HOST-10.100.100.17", 
                "1126": "Trust", 
                "1127": "Untrust", 
                "3061": "dns", 
                "3001": "", 
                "110": 10000, 
                "3008": "dns", 
                "24": "LOW", 
                "20": "Permitted traffic flow started", 
                "21": 1, 
                "1": "PAN-OS-TRAFFIC-start-allow", 
                "1038": 0, 
                "5": "0 (Permit)", 
                "8": "10.10.10.254", 
                "1010": "17 (UDP)", 
                "2422": "Google", 
                "1151": "allow", 
                "1150": "Internet allow", 
                "9": "10.10.10.254", 
                "2410": "United States", 
                "1004": "8.8.8.8", 
                "1002": "google-public-dns-a.google.com", 
                "1001": "8.8.8.8", 
                "1000": "10.10.10.17"
                ...
            }, 
            "Event Receive Time": 1556690013000, 
            "Event Type": "PAN-OS-TRAFFIC-start-allow", 
            "Destination TCP/UDP Port": "53 (DOMAIN)", 
            "Event ID": "8255801804490150940"
        }, 
        ...
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Event Receive Time</th>
<th>Event Type</th>
<th>Event Name</th>
<th>Source IP</th>
<th>Destination IP</th>
<th>Destination Host Name</th>
<th>IP Protocol</th>
<th>Source TCP/UDP Port</th>
<th>Destination TCP/UDP Port</th>
<th>Reporting IP</th>
<th>Raw Event Log</th>
</tr>
</thead>
<tbody>
<tr>
<td>1556690013000</td>
<td>PAN-OS-TRAFFIC-start-allow</td>
<td>Permitted traffic flow started</td>
<td>10.10.10.17</td>
<td>8.8.8.8</td>
<td>google-public-dns-a.google.com</td>
<td>17 (UDP)</td>
<td>57184</td>
<td>53 (DOMAIN)</td>
<td>10.10.10.254</td>
<td>&lt;14&gt;May 2 19:53:33 PA-Firewall 1,2019/05/02 19:53:33,007151000004733,TRAFFIC,start,2304,2019/05/01 09:53:33,10.100.100.17,8.8.8.8,80.227.43.146,8.8.8.8,Internet allow,dns,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/05/02 19:53:33,156575,1,57184,53,59686,53,0x400000,udp,allow,109,109,0,1,2019/05/02 19:53:31,0,any,0,32724731,0x0,10.0.0.0-10.255.255.255,United States,0,1,0,n/a,0,0,0,0,PA-Firewall,from-policy,0,0,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-device-descriptions">4. Get device descriptions</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns the description of each device.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-get-cmdb-devices</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 197px;"><strong>Argument Name</strong></th>
<th style="width: 430px;"><strong>Description</strong></th>
<th style="width: 113px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 197px;">device_ip</td>
<td style="width: 430px;">CSV list of device IPs.</td>
<td style="width: 113px;">Optional</td>
</tr>
<tr>
<td style="width: 197px;">limit</td>
<td style="width: 430px;">Maximum number of results to return.</td>
<td style="width: 113px;">Optional</td>
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
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 350px;"><strong>Path</strong></th>
<th style="width: 155px;"><strong>Type</strong></th>
<th style="width: 235px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 350px;">FortiSIEM.CmdbDevice</td>
<td style="width: 155px;">Unknown</td>
<td style="width: 235px;">CMDB devices.</td>
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
<pre>!fortisiem-get-cmdb-devices limit=4</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.CmdbDevices": [
        {
            "Name": "HOST-10.10.10.230", 
            "DiscoverTime": "N/A", 
            "WinMachineGuid": "N/A", 
            "CreationMethod": "N/A", 
            "UpdateMethod": "N/A", 
            "Version": "N/A", 
            "DeviceType": "FortiSIEM Fortinet", 
            "Unmanaged": "false", 
            "AccessIp": "10.10.10.230", 
            "DiscoverMethod": "N/A", 
            "Approved": "false"
        }, 
        {
            "Name": "HOST-10.10.10.21", 
            "DiscoverTime": "N/A", 
            "WinMachineGuid": "N/A", 
            "CreationMethod": "N/A", 
            "UpdateMethod": "N/A", 
            "Version": "N/A", 
            "DeviceType": "FortiSIEM Fortinet", 
            "Unmanaged": "false", 
            "AccessIp": "10.10.10.21", 
            "DiscoverMethod": "N/A", 
            "Approved": "false"
        }, 
        {
            "Name": "HOST-10.10.10.243", 
            "DiscoverTime": "N/A", 
            "WinMachineGuid": "N/A", 
            "CreationMethod": "N/A", 
            "UpdateMethod": "N/A", 
            "Version": "N/A", 
            "DeviceType": "FortiSIEM Fortinet", 
            "Unmanaged": "false", 
            "AccessIp": "10.10.10.243", 
            "DiscoverMethod": "N/A", 
            "Approved": "false"
        }, 
        {
            "Name": "HOST-10.10.10.241", 
            "DiscoverTime": "N/A", 
            "WinMachineGuid": "N/A", 
            "CreationMethod": "N/A", 
            "UpdateMethod": "N/A", 
            "Version": "N/A", 
            "DeviceType": "FortiSIEM Fortinet", 
            "Unmanaged": "false", 
            "AccessIp": "10.10.10.241", 
            "DiscoverMethod": "N/A", 
            "Approved": "false"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="devices">Devices</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Name</th>
<th>DiscoverTime</th>
<th>Version</th>
<th>DeviceType</th>
<th>AccessIp</th>
<th>WinMachineGuid</th>
<th>CreationMethod</th>
<th>UpdateMethod</th>
<th>Unmanaged</th>
<th>DiscoverMethod</th>
<th>Approved</th>
</tr>
</thead>
<tbody>
<tr>
<td>HOST-10.10.10.230</td>
<td>N/A</td>
<td>N/A</td>
<td>FortiSIEM Fortinet</td>
<td>10.10.10.230</td>
<td>N/A</td>
<td>N/A</td>
<td>N/A</td>
<td>false</td>
<td>N/A</td>
<td>false</td>
</tr>
<tr>
<td>HOST-10.10.10.21</td>
<td>N/A</td>
<td>N/A</td>
<td>FortiSIEM Fortinet</td>
<td>10.10.10.21</td>
<td>N/A</td>
<td>N/A</td>
<td>N/A</td>
<td>false</td>
<td>N/A</td>
<td>false</td>
</tr>
<tr>
<td>HOST-10.10.10.243</td>
<td>N/A</td>
<td>N/A</td>
<td>FortiSIEM Fortinet</td>
<td>10.10.10.243</td>
<td>N/A</td>
<td>N/A</td>
<td>N/A</td>
<td>false</td>
<td>N/A</td>
<td>false</td>
</tr>
<tr>
<td>HOST-10.10.10.241</td>
<td>N/A</td>
<td>N/A</td>
<td>FortiSIEM Fortinet</td>
<td>10.10.10.241</td>
<td>N/A</td>
<td>N/A</td>
<td>N/A</td>
<td>false</td>
<td>N/A</td>
<td>false</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-events-using-a-query">5. Get events using a query</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Returns an event list filtered by a query.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-4">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-get-events-by-query</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-4">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 198px;"><strong>Argument Name</strong></th>
<th style="width: 429px;"><strong>Description</strong></th>
<th style="width: 113px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 198px;">query</td>
<td style="width: 429px;">The query to get events.</td>
<td style="width: 113px;">Required</td>
</tr>
<tr>
<td style="width: 198px;">report-window</td>
<td style="width: 429px;">Interval time of the search.</td>
<td style="width: 113px;">Optional</td>
</tr>
<tr>
<td style="width: 198px;">interval-type</td>
<td style="width: 429px;">Interval unit.</td>
<td style="width: 113px;">Optional</td>
</tr>
<tr>
<td style="width: 198px;">limit</td>
<td style="width: 429px;">Maximum number of results to return.</td>
<td style="width: 113px;">Optional</td>
</tr>
<tr>
<td style="width: 198px;">extended-data</td>
<td style="width: 429px;">Whether to extend the data.</td>
<td style="width: 113px;">Optional</td>
</tr>
<tr>
<td style="width: 198px;">max-wait-time</td>
<td style="width: 429px;">Command timeout.</td>
<td style="width: 113px;">Optional</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-4">Context Output</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 365px;"><strong>Path</strong></th>
<th style="width: 120px;"><strong>Type</strong></th>
<th style="width: 255px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 365px;">FortiSIEM.Events.EventType</td>
<td style="width: 120px;">Unknown</td>
<td style="width: 255px;">FortiSIEM event type.</td>
</tr>
<tr>
<td style="width: 365px;">FortiSIEM.Events.SourceCountry</td>
<td style="width: 120px;">Unknown</td>
<td style="width: 255px;">Event source country.</td>
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
<pre>!fortisiem-get-events-by-query query=`destIpAddr = 116.202.56.112 OR destIpAddr = 17.252.141.15` interval-type=Hourly report-window=17</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.Events": [
        {
            "Event Name": "Permitted traffic flow started", 
            "Destination IP": "116.202.56.112", 
            "Incident ID": null, 
            "Raw Event Log": "&lt;14&gt;Apr 30 17:42:25 PA-Firewall 1,2019/04/30 17:42:24,007151000004733,TRAFFIC,start,2304,2019/04/30 17:42:24,10.100.100.66,116.202.56.112,80.227.43.146,116.202.56.112,Internet allow,,,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/04/30 17:42:24,201358,1,54273,443,51021,443,0x400000,tcp,allow,553,487,66,4,2019/04/30 17:42:22,0,any,0,32241586,0x0,10.0.0.0-10.255.255.255,Germany,0,3,1,n/a,0,0,0,0,,PA-Firewall,from-policy,,,0,,0,,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0", 
            "Reporting IP": "10.100.100.254", 
            "ExtendedData": {
                "1322": 4, 
                "4188": "Syslog", 
                "1121": "HOST-10.100.100.66", 
                "2430": "77.2167", 
                "1126": "Trust", 
                "1127": "Untrust", 
                "3061": "ssl", 
                "3001": "", 
                "110": 10000, 
                "3008": "ssl", 
                "2531": "Emirates Integrated Telecommunications Company PJS", 
                "24": "LOW", 
                "20": "Permitted traffic flow started", 
                "21": 1, 
                "44": "PAN-OS", 
                "2529": "Dubai", 
                "2528": "United Arab Emirates", 
                "1": "PAN-OS-TRAFFIC-start-allow", 
                "1038": 0, 
                "2": 1, 
                "5": "0 (Permit)", 
                "7": 1556631745000, 
                "6": 1556631742000, 
                "1014": "443 (HTTPS)", 
                "8": "10.100.100.254", 
                "1010": "6 (TCP)", 
                "1011": 54273, 
                "1012": "443 (HTTPS)", 
                "1013": 51021, 
                "43": "Palo Alto", 
                "2422": "MTS", 
                "1151": "allow", 
                "1150": "Internet allow", 
                "2426": "28.6667", 
                "9": "10.100.100.254", 
                "122": "PaloAltoParser", 
                "17": 1, 
                "2533": "55.3081", 
                "128": 3, 
                "129": 1, 
                "11": "PA-Firewall", 
                "1284": 553, 
                "12": 1, 
                "15": "8255801804489112226", 
                "1046": "201358", 
                "1023": "ethernet1/1", 
                "1022": "ethernet1/3", 
                "3035": "any", 
                "16": "4 (Traffic)", 
                "53": "Super", 
                "2410": "India", 
                "3000": "", 
                "2414": "Delhi", 
                "1100": 1, 
                "2532": "25.2639", 
                "2418": "Delhi", 
                "2530": "Dubai", 
                "1004": "116.202.56.112", 
                "1003": "80.227.43.146", 
                "1002": "static.112.56.202.116.clients.your-server.de", 
                "1001": "116.202.56.112", 
                "1000": "10.100.100.66"
            }, 
            "Event Receive Time": 1556631745000, 
            "Event Type": "PAN-OS-TRAFFIC-start-allow", 
            "Event ID": "8255801804489112226"
        }, 
        {
            "Event Name": "Permitted traffic flow started", 
            "Destination IP": "116.202.56.112", 
            "Incident ID": null, 
            "Raw Event Log": "&lt;14&gt;Apr 30 17:42:26 PA-Firewall 1,2019/04/30 17:42:25,007151000004733,TRAFFIC,start,2304,2019/04/30 17:42:25,10.100.100.66,116.202.56.112,80.227.43.146,116.202.56.112,Internet allow,,,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/04/30 17:42:25,195836,1,54274,443,1459,443,0x400000,tcp,allow,493,427,66,3,2019/04/30 17:42:24,0,any,0,32241609,0x0,10.0.0.0-10.255.255.255,Germany,0,2,1,n/a,0,0,0,0,,PA-Firewall,from-policy,,,0,,0,,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0", 
            "Reporting IP": "10.100.100.254", 
            "ExtendedData": {
                "1322": 3, 
                "4188": "Syslog", 
                "1121": "HOST-10.100.100.66", 
                "2430": "77.2167", 
                "1126": "Trust", 
                "1127": "Untrust", 
                "3061": "ssl", 
                "3001": "", 
                "110": 10000, 
                "3008": "ssl", 
                "2531": "Emirates Integrated Telecommunications Company PJS", 
                "24": "LOW", 
                "20": "Permitted traffic flow started", 
                "21": 1, 
                "44": "PAN-OS", 
                "2529": "Dubai", 
                "2528": "United Arab Emirates", 
                "1": "PAN-OS-TRAFFIC-start-allow", 
                "1038": 0, 
                "2": 1, 
                "5": "0 (Permit)", 
                "7": 1556631746000, 
                "6": 1556631744000, 
                "1014": "443 (HTTPS)", 
                "8": "10.100.100.254", 
                "1010": "6 (TCP)", 
                "1011": 54274, 
                "1012": "443 (HTTPS)", 
                "1013": 1459, 
                "43": "Palo Alto", 
                "2422": "MTS", 
                "1151": "allow", 
                "1150": "Internet allow", 
                "2426": "28.6667", 
                "9": "10.100.100.254", 
                "122": "PaloAltoParser", 
                "17": 1, 
                "2533": "55.3081", 
                "128": 2, 
                "129": 1, 
                "11": "PA-Firewall", 
                "1284": 493, 
                "12": 1, 
                "15": "8255801804489112236", 
                "1046": "195836", 
                "1023": "ethernet1/1", 
                "1022": "ethernet1/3", 
                "3035": "any", 
                "16": "4 (Traffic)", 
                "53": "Super", 
                "2410": "India", 
                "3000": "", 
                "2414": "Delhi", 
                "1100": 1, 
                "2532": "25.2639", 
                "2418": "Delhi", 
                "2530": "Dubai", 
                "1004": "116.202.56.112", 
                "1003": "80.227.43.146", 
                "1002": "static.112.56.202.116.clients.your-server.de", 
                "1001": "116.202.56.112", 
                "1000": "10.100.100.66"
            }, 
            "Event Receive Time": 1556631746000, 
            "Event Type": "PAN-OS-TRAFFIC-start-allow", 
            "Event ID": "8255801804489112236"
        }, 
        {
            "Event Name": "Permitted traffic flow started", 
            "Destination IP": "116.202.56.112", 
            "Incident ID": null, 
            "Raw Event Log": "&lt;14&gt;Apr 30 17:42:27 PA-Firewall 1,2019/04/30 17:42:26,007151000004733,TRAFFIC,start,2304,2019/04/30 17:42:26,10.100.100.66,116.202.56.112,80.227.43.146,116.202.56.112,Internet allow,,,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/04/30 17:42:26,200640,1,59920,443,27164,443,0x400000,tcp,allow,775,709,66,4,2019/04/30 17:42:24,0,any,0,32241625,0x0,10.0.0.0-10.255.255.255,Germany,0,3,1,n/a,0,0,0,0,,PA-Firewall,from-policy,,,0,,0,,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0", 
            "Reporting IP": "10.100.100.254", 
            "ExtendedData": {
                "1322": 4, 
                "4188": "Syslog", 
                "1121": "HOST-10.100.100.66", 
                "2430": "77.2167", 
                "1126": "Trust", 
                "1127": "Untrust", 
                "3061": "ssl", 
                "3001": "", 
                "110": 10000, 
                "3008": "ssl", 
                "2531": "Emirates Integrated Telecommunications Company PJS", 
                "24": "LOW", 
                "20": "Permitted traffic flow started", 
                "21": 1, 
                "44": "PAN-OS", 
                "2529": "Dubai", 
                "2528": "United Arab Emirates", 
                "1": "PAN-OS-TRAFFIC-start-allow", 
                "1038": 0, 
                "2": 1, 
                "5": "0 (Permit)", 
                "7": 1556631747000, 
                "6": 1556631744000, 
                "1014": "443 (HTTPS)", 
                "8": "10.100.100.254", 
                "1010": "6 (TCP)", 
                "1011": 59920, 
                "1012": "443 (HTTPS)", 
                "1013": 27164, 
                "43": "Palo Alto", 
                "2422": "MTS", 
                "1151": "allow", 
                "1150": "Internet allow", 
                "2426": "28.6667", 
                "9": "10.100.100.254", 
                "122": "PaloAltoParser", 
                "17": 1, 
                "2533": "55.3081", 
                "128": 3, 
                "129": 1, 
                "11": "PA-Firewall", 
                "1284": 775, 
                "12": 1, 
                "15": "8255801804489310488", 
                "1046": "200640", 
                "1023": "ethernet1/1", 
                "1022": "ethernet1/3", 
                "3035": "any", 
                "16": "4 (Traffic)", 
                "53": "Super", 
                "2410": "India", 
                "3000": "", 
                "2414": "Delhi", 
                "1100": 1, 
                "2532": "25.2639", 
                "2418": "Delhi", 
                "2530": "Dubai", 
                "1004": "116.202.56.112", 
                "1003": "80.227.43.146", 
                "1002": "static.112.56.202.116.clients.your-server.de", 
                "1001": "116.202.56.112", 
                "1000": "10.100.100.66"
            }, 
            "Event Receive Time": 1556631747000, 
            "Event Type": "PAN-OS-TRAFFIC-start-allow", 
            "Event ID": "8255801804489310488"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-4">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="fortisiem-event-results">FortiSIEM Event Results</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Event Receive Time</th>
<th>Reporting IP</th>
<th>Event Type</th>
<th>Event Name</th>
<th>Raw Event Log</th>
<th>Destination IP</th>
</tr>
</thead>
<tbody>
<tr>
<td>1556631745000</td>
<td>10.100.100.254</td>
<td>PAN-OS-TRAFFIC-start-allow</td>
<td>Permitted traffic flow started</td>
<td>&lt;14&gt;Apr 30 17:42:25 PA-Firewall 1,2019/04/30 17:42:24,007151000004733,TRAFFIC,start,2304,2019/04/30 17:42:24,10.100.100.66,116.202.56.112,80.227.43.146,116.202.56.112,Internet allow,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/04/30 17:42:24,201358,1,54273,443,51021,443,0x400000,tcp,allow,553,487,66,4,2019/04/30 17:42:22,0,any,0,32241586,0x0,10.0.0.0-10.255.255.255,Germany,0,3,1,n/a,0,0,0,0,PA-Firewall,from-policy,0,0,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0</td>
<td>116.202.56.112</td>
</tr>
<tr>
<td>1556631746000</td>
<td>10.100.100.254</td>
<td>PAN-OS-TRAFFIC-start-allow</td>
<td>Permitted traffic flow started</td>
<td>&lt;14&gt;Apr 30 17:42:26 PA-Firewall 1,2019/04/30 17:42:25,007151000004733,TRAFFIC,start,2304,2019/04/30 17:42:25,10.100.100.66,116.202.56.112,80.227.43.146,116.202.56.112,Internet allow,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/04/30 17:42:25,195836,1,54274,443,1459,443,0x400000,tcp,allow,493,427,66,3,2019/04/30 17:42:24,0,any,0,32241609,0x0,10.0.0.0-10.255.255.255,Germany,0,2,1,n/a,0,0,0,0,PA-Firewall,from-policy,0,0,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0</td>
<td>116.202.56.112</td>
</tr>
<tr>
<td>1556631747000</td>
<td>10.100.100.254</td>
<td>PAN-OS-TRAFFIC-start-allow</td>
<td>Permitted traffic flow started</td>
<td>&lt;14&gt;Apr 30 17:42:27 PA-Firewall 1,2019/04/30 17:42:26,007151000004733,TRAFFIC,start,2304,2019/04/30 17:42:26,10.100.100.66,116.202.56.112,80.227.43.146,116.202.56.112,Internet allow,ssl,vsys1,Trust,Untrust,ethernet1/3,ethernet1/1,Forward to Fortisiem,2019/04/30 17:42:26,200640,1,59920,443,27164,443,0x400000,tcp,allow,775,709,66,4,2019/04/30 17:42:24,0,any,0,32241625,0x0,10.0.0.0-10.255.255.255,Germany,0,3,1,n/a,0,0,0,0,PA-Firewall,from-policy,0,0,N/A,0,0,0,0,dcc8adba-6c1a-4eb1-9ac3-d0f33439ea67,0</td>
<td>116.202.56.112</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-all-resource-lists">6. Get all resource lists</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Get all FortiSIEM resource lists hierarchy.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-5">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-get-lists</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-5">Input</h5>
<p>There are no input arguments for this command.</p>
</div>
<div class="cl-preview-section">
<div class="table-wrapper"> </div>
</div>
<div class="cl-preview-section">
<h5 id="context-output-5">Context Output</h5>
</div>
<div class="cl-preview-section">
<p>There is no context output for this command.</p>
</div>
<div class="cl-preview-section">
<h5 id="command-example-5">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fortisiem-get-lists</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-4">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.ResourceList": [
        {
            "ResourceType": "Reports", 
            "NatualID": "PH_SYS_REPORT_Freq", 
            "DisplayName": "Frequently Used", 
            "Children": [], 
            "ID": 500425
        }, 
        {
            "ResourceType": "Reports", 
            "NatualID": "PH_SYS_REPORT_Incident", 
            "DisplayName": "Incidents", 
            "Children": [], 
            "ID": 500427
        }, 
        {
            "ResourceType": "Malware IP", 
            "NatualID": "Emerging_Threat_Malware_IP_testing_1", 
            "DisplayName": "testing", 
            "Children": [
                "l4"
            ], 
            "ID": 766037000
        }, 
        {
            "ResourceType": "Malware IP", 
            "NatualID": "testing_l4_1", 
            "DisplayName": "l4", 
            "Children": [], 
            "ID": 766037001
        }, 
        {
            "ResourceType": "User Agent", 
            "NatualID": "PH_SYS_HTTP_UA_BLACKLIST", 
            "DisplayName": "User Agent Blacklist", 
            "Children": [], 
            "ID": 500675
        }, 
        {
            "ResourceType": "User Agent", 
            "NatualID": "PH_SYS_HTTP_UA_WHITELIST", 
            "DisplayName": "User Agent Whitelist", 
            "Children": [], 
            "ID": 500676
        }, 
        {
            "ResourceType": "User Agent", 
            "NatualID": "User_Agents_Ungrouped_1", 
            "DisplayName": "Ungrouped", 
            "Children": [], 
            "ID": -1
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-5">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="lists">Lists:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ResourceType</th>
<th>NatualID</th>
<th>DisplayName</th>
<th>ID</th>
<th>Children</th>
</tr>
</thead>
<tbody>
<tr>
<td>Reports</td>
<td>PH_SYS_REPORT_Freq</td>
<td>Frequently Used</td>
<td>500425</td>
<td> </td>
</tr>
<tr>
<td>Reports</td>
<td>PH_SYS_REPORT_Incident</td>
<td>Incidents</td>
<td>500427</td>
<td> </td>
</tr>
<tr>
<td>Malware IP</td>
<td>Emerging_Threat_Malware_IP_testing_1</td>
<td>testing</td>
<td>766037000</td>
<td>l4</td>
</tr>
<tr>
<td>Malware IP</td>
<td>testing_l4_1</td>
<td>l4</td>
<td>766037001</td>
<td> </td>
</tr>
<tr>
<td>User Agent</td>
<td>PH_SYS_HTTP_UA_BLACKLIST</td>
<td>User Agent Blacklist</td>
<td>500675</td>
<td> </td>
</tr>
<tr>
<td>User Agent</td>
<td>PH_SYS_HTTP_UA_WHITELIST</td>
<td>User Agent Whitelist</td>
<td>500676</td>
<td> </td>
</tr>
<tr>
<td>User Agent</td>
<td>User_Agents_Ungrouped_1</td>
<td>Ungrouped</td>
<td>-1</td>
<td> </td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="add-an-element-to-a-resource-list.">7. Add an element to a resource list.</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Adds an element to a resource list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-6">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-add-item-to-resource-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-6">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 132px;"><strong>Argument Name</strong></th>
<th style="width: 537px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 132px;">group_id</td>
<td style="width: 537px;">ID of the resource group. Run the <a href="#get-all-resource-lists" target="_self">fortisiem-get-lists</a> command to get the ID. command.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 132px;">object-info</td>
<td style="width: 537px;">CSV list of key-value pairs of attributes, for example: name=SomeName,lowIp=192.168.1.1,highIp=192.168.1.2</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 132px;">resource_type</td>
<td style="width: 537px;">Resource type.</td>
<td style="width: 71px;">Required</td>
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
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 224px;"><strong>Path</strong></th>
<th style="width: 115px;"><strong>Type</strong></th>
<th style="width: 401px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 224px;">FortiSIEM.Resource</td>
<td style="width: 115px;">Unknown</td>
<td style="width: 401px;">Resource object in FortiSIEM lists.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-6">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!fortisiem-add-item-to-resource-list resource_type="Malware Domains" group_id=766567954 object-info=domainName=test.domain.com,ipAddr=2.2.2.2,org=TeST</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-5">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.Resource": {
        "xmlId": "MalwareSite$test.domain.com", 
        "domainName": "test.domain.com", 
        "ipAddr": "2.2.2.2", 
        "creationTime": 1556692917786, 
        "naturalId": "test.domain.com", 
        "systemEntity": true, 
        "id": 936390355, 
        "sysDefined": false, 
        "lastModifiedDate": 1556692917786, 
        "lastModified": 1556692917786, 
        "active": true, 
        "org": "TeST", 
        "creationDate": 1556692917786, 
        "custId": 0, 
        "groupId": 766567954, 
        "naturalIdProperty": "naturalId", 
        "ownerId": 500151
    }
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-6">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="resource-was-added">Resource was added:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>naturalId</th>
<th>systemEntity</th>
<th>id</th>
<th>groupId</th>
<th>sysDefined</th>
<th>custId</th>
<th>naturalIdProperty</th>
<th>xmlId</th>
<th>lastModifiedDate</th>
<th>ipAddr</th>
<th>active</th>
<th>org</th>
<th>creationDate</th>
<th>domainName</th>
<th>lastModified</th>
<th>creationTime</th>
<th>ownerId</th>
</tr>
</thead>
<tbody>
<tr>
<td>test.domain.com</td>
<td>true</td>
<td>936390355</td>
<td>766567954</td>
<td>false</td>
<td>0</td>
<td>naturalId</td>
<td>MalwareSite$test.domain.com</td>
<td>1556692917786</td>
<td>2.2.2.2</td>
<td>true</td>
<td>TeST</td>
<td>1556692917786</td>
<td>test.domain.com</td>
<td>1556692917786</td>
<td>1556692917786</td>
<td>500151</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="remove-elements-from-a-resource-list">8. Remove elements from a resource list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Removes elements from a resource list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-7">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-remove-item-from-resource-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-7">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 249px;"><strong>Argument Name</strong></th>
<th style="width: 348px;"><strong>Description</strong></th>
<th style="width: 143px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 249px;">ids</td>
<td style="width: 348px;">CSV list of resource IDs.</td>
<td style="width: 143px;">Required</td>
</tr>
<tr>
<td style="width: 249px;">resource_type</td>
<td style="width: 348px;">Resource type.</td>
<td style="width: 143px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
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
<pre>!fortisiem-remove-item-from-resource-list resource_type="Malware Domains" ids=936390353</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-7">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<p>items with id [u’936390353’] were removed.</p>
</div>
<div class="cl-preview-section">
<h3 id="get-a-list-of-all-elements-in-a-resource-list">9. Get a list of all elements in a resource list</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Lists all elements in a resource list.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-8">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>fortisiem-get-resource-list</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-8">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 174px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174px;">group_id</td>
<td style="width: 495px;">ID of the resource group. Run the <a href="#get-all-resource-lists" target="_self">fortisiem-get-lists</a> command to get the ID.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 174px;">resource_type</td>
<td style="width: 495px;">Resource type.</td>
<td style="width: 71px;">Required</td>
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
<pre>!fortisiem-get-resource-list resource_type="Malware Domains" group_id=766567954</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-6">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "FortiSIEM.Resource": [
        {
            "origin": "User", 
            "domainName": "malware.com", 
            "ipAddr": "3.2.3.2", 
            "active": true, 
            "org": "TeST", 
            "id": 936390354
        },
        {
            "origin": "User", 
            "domainName": "testing.com", 
            "ipAddr": "1.2.3.4", 
            "active": true, 
            "org": "TeST", 
            "id": 930309355
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-8">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="resource-list">Resource list:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>Origin</th>
<th>Domain Name</th>
<th>Ip Addr</th>
<th>Id</th>
<th>Active</th>
<th>Org</th>
</tr>
</thead>
<tbody>
<tr>
<td>User</td>
<td>malware.com</td>
<td>3.2.3.2</td>
<td>936390354</td>
<td>true</td>
<td>TeST</td>
</tr>
<tr>
<td>User</td>
<td>testing.com</td>
<td>1.2.3.4</td>
<td>930309355</td>
<td>true</td>
<td>TeST</td>
</tr>
</tbody>
</table>
</div>
</div>