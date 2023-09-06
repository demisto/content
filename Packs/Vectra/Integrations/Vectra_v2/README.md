<p>
Vectra is a detection product that alerts on suspicious network behavior. It can recognize certain known attacks and suspicious interactions on the network level (e.g. Reverse Shell, Port Scans, etc)
</p>
<h2>Detailed Description</h2>
<ul>
Vectra API is available for administrators and developers to integrate Vectra's breach detection data into their applications. Vectra provides access to security event data, platform configuration, and health information via URI paths.

<li>Tested with API version 2.1. </li>
<li>c_score and t_score fields changed to certainty and threat accordingly</li>
</ul><h2>Fetch Incidents</h2>
<p>You can Fetch only Detections with Greater/Equal Certainty score and Threat score</p>
<h2>Configure Vectra v2 on Cortex XSOAR</h2>
<ol>
  <li>Navigate to&nbsp;<strong>Settings</strong>&nbsp;&gt;&nbsp;<strong>Integrations</strong>
  &nbsp;&gt;&nbsp;<strong>Servers &amp; Services</strong>.</li>
  <li>Search for Vectra v2.</li>
  <li>
    Click&nbsp;<strong>Add instance</strong>&nbsp;to create and configure a new integration instance.
    <ul>
      <li><strong>Name</strong>: a textual name for the integration instance.</li>
   <li><strong>Server URL (e.g. https://192.168.0.1)</strong></li>
   <li><strong>API Token</strong></li>
   <li><strong>First fetch time range (<number> <time unit>, e.g., 1 hour, 30 minutes)</strong></li>
   <li><strong>Fetch only Detections with greater/equal Certainty score</strong></li>
   <li><strong>Fetch only Detections with greater/equal Threat score</strong></li>
   <li><strong>Fetch only Detections with matching State</strong></li>
   <li><strong>The number of results returned in each fetch</strong></li>
   <li><strong>Fetch incidents</strong></li>
   <li><strong>Trust any certificate (not secure)</strong></li>
   <li><strong>Incident type</strong></li>
   <li><strong>Use system proxy settings</strong></li>
    </ul>
  </li>
  <li>
    Click&nbsp;<strong>Test</strong>&nbsp;to validate the new instance.
  </li>
</ol>
<h2>Commands</h2>
<p>
  You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
  After you successfully execute a command, a DBot message appears in the War Room with the command details.
</p>
<ol>
  <li>vectra-get-detections: vectra-get-detections</li>
  <li>vectra-get-hosts: vectra-get-hosts</li>
  <li>vectra-triage: vectra-triage</li>
  <li>vectra-get-host-by-id: vectra-get-host-by-id</li>
  <li>vectra-get-detection-by-id: vectra-get-detection-by-id</li>
  <li>vectra-get-users: vectra-get-users</li>
  <li>vectra-get-proxies: vectra-get-proxies</li>
  <li>vectra-get-threatfeed: vectra-get-threatfeed</li>
  <li>vectra-search: vectra-search</li>
</ol>
<h3>1. vectra-get-detections</h3>
<hr>
<p>Detection objects contain all the information related to security events detected on the network</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-detections</code>
</p>

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
      <td>detection_id</td>
      <td>Filter by detection ID</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>Filters objects listed</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page</td>
      <td>Page number. Possible values are a positive integer or last</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page_size</td>
      <td>Page size. Possible values are a positive integer or all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ordering</td>
      <td>Orders records by last timestamp, threat score and certainty score. The default out sorts threat and certainty score in ascending order. Scores can sorted in descending order by prepending the query with “minus” symbol</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>min_id</td>
      <td>>= the id provided</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>max_id</td>
      <td><= the id provided</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>state</td>
      <td>filter by state: active, inactive, ignored, ignored for all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>type_vname</td>
      <td>filter by the detection type (verbose name)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>category</td>
      <td>filter by the detection category</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>src_ip</td>
      <td>filter by source (ip address)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threat_score</td>
      <td>filter by threat score</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threat_score_gte</td>
      <td>filter by threat score >= the score provided</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>certainty_score</td>
      <td>filter by certainty score</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>certainty_score_gte</td>
      <td>filter by certainty score >= the score provided</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>last_timestamp</td>
      <td>filter by last timestamp</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>host_id</td>
      <td>filter by id of the host object a detection is attributed to</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tags</td>
      <td>filter by a tag or a comma-separated list of tags</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>destination</td>
      <td>filter by destination in the detection detail set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>proto</td>
      <td>filter by the protocol in the detection detail set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>destination_port</td>
      <td>filter by the destination port in the detection detail set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>inbound_ip</td>
      <td>filter by the inbound_ip in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>inbound_proto</td>
      <td>filter by the inbound_proto in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>inbound_port</td>
      <td>filter by the inbound_port in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>inbound_dns</td>
      <td>filter by the inbound_dns in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>outbound_ip</td>
      <td>filter by the outbound_ip in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>outbound_proto</td>
      <td>filter by the outbound_proto in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>outbound_port</td>
      <td>filter by the outbound_port in the relayed comm set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>outbound_dns</td>
      <td>filter by the outbound_dns in the relayed_comm_set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>dns_ip</td>
      <td>filter by the dns_ip in the dns_set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>dns_request</td>
      <td>filter by the dns_request in the dns_set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>resp_code</td>
      <td>filter by the resp_code in the dns_set</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>resp</td>
      <td>filter by the resp in the dns_set</td>
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
      <td>Vectra.Detection.Category</td>
      <td>String</td>
      <td>The category of the vname attack detected</td>
    </tr>
    <tr>
      <td>Vectra.Detection.TargetsKeyAsset</td>
      <td>Boolean</td>
      <td>Flag indicating if the host has a detection targeting a key asset</td>
    </tr>
    <tr>
      <td>Vectra.Detection.CertaintyScore</td>
      <td>Number</td>
      <td>The current certainty score correlated to this host</td>
    </tr>
    <tr>
      <td>Vectra.Detection.ID</td>
      <td>Number</td>
      <td>Object ID</td>
    </tr>
    <tr>
      <td>Vectra.Detection.FirstTimestamp</td>
      <td>String</td>
      <td>The timestamp when the event was first detected</td>
    </tr>
    <tr>
      <td>Vectra.Detection.LastTimestamp</td>
      <td>String</td>
      <td>The timestamp when the event was last detected</td>
    </tr>
    <tr>
      <td>Vectra.Detection.State</td>
      <td>String</td>
      <td>The state of the detection</td>
    </tr>
    <tr>
      <td>Vectra.Detection.Threat_Score</td>
      <td>Number</td>
      <td>The threat score attributed to the detection</td>
    </tr>
    <tr>
      <td>Vectra.Detection.SourceIP</td>
      <td>String</td>
      <td>The source IP address of the host attributed to the security event</td>
    </tr>
    <tr>
      <td>Vectra.Detection.SourceAccount</td>
      <td>Unknown</td>
      <td>A dictionary with fields that describe the Account the detection is from</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!vectra-get-detections certainty_score_gte=20</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Vectra.Detection": [
        {
            "Category": "LATERAL MOVEMENT",
            "CertaintyScore": 22,
            "Detection": "Automated Replication",
            "DetectionCategory": "LATERAL MOVEMENT",
            "DetectionType": "Automated Replication",
            "FirstTimestamp": "2019-10-02T22:05:34Z",
            "ID": 3,
            "LastTimestamp": "2019-10-02T22:12:39Z",
            "SourceHost": {
                "certainty": 0,
                "groups": [],
                "id": 9,
                "ip": "0.0.0.0",
                "is_key_asset": false,
                "name": "sandbox",
                "threat": 0,
                "url": ""
            },
            "SourceIP": "0.0.0.0",
            "State": "inactive",
            "TargetsKeyAsset": false,
            "ThreatScore": 22
        },
        {
            "Category": "RECONNAISSANCE",
            "CertaintyScore": 80,
            "Detection": "Port Sweep",
            "DetectionCategory": "RECONNAISSANCE",
            "DetectionType": "Port Sweep",
            "FirstTimestamp": "2019-10-02T22:38:58Z",
            "ID": 5,
            "LastTimestamp": "2019-10-02T22:54:49Z",
            "SourceHost": {
                "certainty": 27,
                "groups": [],
                "id": 11,
                "ip": "0.0.0.0",
                "is_key_asset": false,
                "name": "Robert-MBP",
                "threat": 11,
                "url": ""
            },
            "SourceIP": "0.0.0.0",
            "State": "active",
            "TargetsKeyAsset": false,
            "ThreatScore": 60            
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Detection table (Showing Page 1 out of 1)</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>id</strong></th>
      <th><strong>category</strong></th>
      <th><strong>src_ip</strong></th>
      <th><strong>threat</strong></th>
      <th><strong>certainty</strong></th>
      <th><strong>state</strong></th>
      <th><strong>detection</strong></th>
      <th><strong>detection_category</strong></th>
      <th><strong>detection_type</strong></th>
      <th><strong>first_timestamp</strong></th>
      <th><strong>tags</strong></th>
      <th><strong>targets_key_asset</strong></th>
      <th><strong>type_vname</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 3 </td>
      <td> LATERAL MOVEMENT </td>
      <td> 0.0.0.0 </td>
      <td> 22 </td>
      <td> 22 </td>
      <td> inactive </td>
      <td> Automated Replication </td>
      <td> LATERAL MOVEMENT </td>
      <td> Automated Replication </td>
      <td> 2019-10-02T22:05:34Z </td>
      <td>  </td>
      <td> false </td>
      <td>  </td>
    </tr>
    <tr>
      <td> 5 </td>
      <td> RECONNAISSANCE </td>
      <td> 0.0.0.0 </td>
      <td> 60 </td>
      <td> 80 </td>
      <td> active </td>
      <td> Port Sweep </td>
      <td> RECONNAISSANCE </td>
      <td> Port Sweep </td>
      <td> 2019-10-02T22:38:58Z </td>
      <td>  </td>
      <td> false </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>2. vectra-get-hosts</h3>
<hr>
<p>Host information includes data that correlates the host data to detected security events</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-hosts</code>
</p>

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
      <td>host_id</td>
      <td>Filter by host ID</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>fields</td>
      <td>Filters objects listed</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page</td>
      <td>Page number. Possible values are a positive integer or last</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>page_size</td>
      <td>Page size. Possible values are a positive integer or all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>ordering</td>
      <td>Orders records by last timestamp, threat score and certainty score. The default out sorts threat and certainty score in ascending order. Scores can sorted in descending order by prepending the query with “minus” symbol</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>name</td>
      <td>filter by name</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>state</td>
      <td>filter by state: active, inactive, suspended, ignored, ignored for all</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>last_source</td>
      <td>filter by last_source (ip address)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threat_score</td>
      <td>filter by threat score</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>threat_score_gte</td>
      <td>filter by threat score >= the score provided</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>certainty_score</td>
      <td>filter by certainty score</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>certainty_score_gte</td>
      <td>filter by certainty score >= the score provided</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>last_detection_timestamp</td>
      <td>filter by last_detection_timestamp</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>tags</td>
      <td>filter by a tag or a comma-separated list of tags (returns hosts that contain any of the tags specified), e.g.tags=baz | tags=foo,bar"</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>key_assest</td>
      <td>filter by key asset: True, False</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>mac_address</td>
      <td>filter by mac address</td>
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
      <td>Vectra.Host.Name</td>
      <td>String</td>
      <td>The learned hostname</td>
    </tr>
    <tr>
      <td>Vectra.Host.TargetsKeyAsset</td>
      <td>Boolean</td>
      <td>Flag indicating if the host has a detection targeting a key asset</td>
    </tr>
    <tr>
      <td>Vectra.Host.CertaintyScore</td>
      <td>Number</td>
      <td>The current certainty score correlated to this host</td>
    </tr>
    <tr>
      <td>Vectra.Host.DetectionID</td>
      <td>String</td>
      <td>List of Detections for Account</td>
    </tr>
    <tr>
      <td>Vectra.Host.KeyAsset</td>
      <td>Boolean</td>
      <td>Flag indicating if the host is a key asset</td>
    </tr>
    <tr>
      <td>Vectra.Host.State</td>
      <td>String</td>
      <td>The state of this host</td>
    </tr>
    <tr>
      <td>Vectra.Host.Threat_Score</td>
      <td>Number</td>
      <td>The current threat score correlated to this host</td>
    </tr>
    <tr>
      <td>Vectra.Host.LastDetection</td>
      <td>String</td>
      <td>Last detection activity from this host (Timestamp format: YYYY-MM-DD HH-MM-SS GMT)</td>
    </tr>
    <tr>
      <td>Vectra.Host.IP</td>
      <td>String</td>
      <td>Last source IP associated with this host</td>
    </tr>
    <tr>
      <td>Vectra.Host.ID</td>
      <td>Number</td>
      <td>ID of the Host</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!vectra-get-hosts threat_score_gte=20 </code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Vectra.Host": [
        {
            "ActiveTraffic": false,
            "CertaintyScore": 45,
            "DetectionID": [
                "22",
                "23",
                "37",
                "42",
                "61",
                "62",
                "63",
                "64"
            ],
            "HostLuid": "duOUtBa4",
            "ID": 57,
            "IP": "0.0.0.0",
            "KeyAsset": true,
            "LastDetection": "2019-10-07T05:37:12Z",
            "LastDetectionTimestamp": "2019-10-07T05:37:12Z",
            "LastModified": "2019-10-03T07:04:06Z",
            "LastSource": "0.0.0.0",
            "Name": "leroy_brown",
            "Note": null,
            "OwnerName": "lbrown",
            "Severity": "low",
            "State": "active",
            "Tags": [],
            "ThreatScore": 34
        },
        {
            "ActiveTraffic": false,
            "CertaintyScore": 32,
            "DetectionID": [
                "53",
                "56",
                "60"
            ],
            "HostLuid": "dwGUtBaK",
            "ID": 103,
            "IP": "0.0.0.0",
            "KeyAsset": false,
            "LastDetection": "2019-10-04T19:24:04Z",
            "LastDetectionTimestamp": "2019-10-04T19:24:04Z",
            "LastModified": "2019-10-04T12:40:38Z",
            "LastSource": "0.0.0.0",
            "Name": "winfs06r3u17",
            "Note": null,
            "OwnerName": null,
            "Severity": "low",
            "State": "active",
            "Tags": [],
            "ThreatScore": 22
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Hosts table (Showing Page 1 out of 1)</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>id</strong></th>
      <th><strong>name</strong></th>
      <th><strong>state</strong></th>
      <th><strong>threat</strong></th>
      <th><strong>certainty</strong></th>
      <th><strong>last_source</strong></th>
      <th><strong>url</strong></th>
      <th><strong>assigned_to</strong></th>
      <th><strong>owner_name</strong></th>
      <th><strong>first_timestamp</strong></th>
      <th><strong>tags</strong></th>
      <th><strong>note</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 7 </td>
      <td> BThomas-Win7 </td>
      <td> active </td>
      <td> 23 </td>
      <td> 33 </td>
      <td> 0.0.0.0 </td>
      <td> demist.com/api/v2/hosts/7 </td>
      <td>  </td>
      <td> bthomas </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
    <tr>
      <td> 11 </td>
      <td> Robert-MBP </td>
      <td> active </td>
      <td> 25 </td>
      <td> 46 </td>
      <td> 0.0.0.0 </td>
      <td> demist.com/api/v2/hosts/11 </td>
      <td>  </td>
      <td> rwilliams </td>
      <td>  </td>
      <td>  </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>3. vectra-triage</h3>
<hr>
<p>The rules branch can be used to retrieve a listing of configured Triage rules</p>
<h5>Base Command</h5>
<p>
  <code>vectra-triage</code>
</p>

<h5>Input</h5>
There are no input arguments for this command.
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
      <td>Vectra.Rule.ID</td>
      <td>Unknown</td>
      <td>The record id</td>
    </tr>
    <tr>
      <td>Vectra.Rule.SmartCategory</td>
      <td>Unknown</td>
      <td>Custom Triage label used to recategorize specified detections</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Description</td>
      <td>Unknown</td>
      <td>Name of Triage filter</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Type</td>
      <td>Unknown</td>
      <td>Original detection type</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Category</td>
      <td>Unknown</td>
      <td>Original detection category</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Created</td>
      <td>Unknown</td>
      <td>The timestamp when this Triage filter was created</td>
    </tr>
    <tr>
      <td>Vectra.Rule.LastUpdate</td>
      <td>Unknown</td>
      <td>The timestamp when this Triage filter was triggered</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Host.ID</td>
      <td>Unknown</td>
      <td>Host(s) that this Triage filter applies to</td>
    </tr>
    <tr>
      <td>Vectra.Rule.IP</td>
      <td>Unknown</td>
      <td>Host IP</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Priority</td>
      <td>Unknown</td>
      <td>Used in ordering execution of Triage filters</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Remote.IP</td>
      <td>Unknown</td>
      <td>Destination IP where this Triage filter will be applied to</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Remote.Protocol</td>
      <td>Unknown</td>
      <td>Destination protocol where this Triage filter will be applied to</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Remote.Port</td>
      <td>Unknown</td>
      <td>Destination port where this Triage filter will be applied to</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Remote.DNS</td>
      <td>Unknown</td>
      <td>Destination FQDN where this Triage filter will apply to</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Remote.Kerberos.Account</td>
      <td>Unknown</td>
      <td>Kerberos Account</td>
    </tr>
    <tr>
      <td>Vectra.Rule.Remote.Kerberos.Service</td>
      <td>Unknown</td>
      <td>Kerberos Service</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!vectra-triage</code>
</p>
<h5>Context Example</h5>
<pre>
No output examples
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Couldn't find any results
</p>
</p>

<h3>4. vectra-get-host-by-id</h3>
<hr>
<p>Get host by id</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-host-by-id</code>
</p>

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
      <td>host_id</td>
      <td>The id of the required host (Can get from vectra-get-hosts)</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Context Output</h5>
There are no context output for this command.
<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!vectra-get-host-by-id host_id=11</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Vectra.Host": [
        {
            "CertaintyScore": 27,
            "Hostname": "Robert-MBP",
            "ID": 11,
            "IP": "0.0.0.0",
            "KeyAsset": false,
            "LastDetection": "2019-10-03T01:10:43Z",
            "State": "active",
            "TargetsKeyAsset": false,
            "ThreatScore": 11
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Search results table</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>id</strong></th>
      <th><strong>threat</strong></th>
      <th><strong>certainty</strong></th>
      <th><strong>state</strong></th>
      <th><strong>first_timestamp</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 11 </td>
      <td> 25 </td>
      <td> 46 </td>
      <td> active </td>
      <td>  </td>
    </tr>
  </tbody>
</table>
</p>

<h3>5. vectra-get-detection-by-id</h3>
<hr>
<p>Get detections by detetction id</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-detection-by-id</code>
</p>

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
      <td>detection_id</td>
      <td>The id of the required detection (Can get from vectra-get-detections)</td>
      <td>Required</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
</p>

<h3>6. vectra-get-users</h3>
<hr>
<p>Retrieves the current list of Users</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-users</code>
</p>

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
      <td>username</td>
      <td>Filter by username</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>role</td>
      <td>Filter by role</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>account_type</td>
      <td>Filter by account type (Local, Special, Limited Time Link, LDAP, TACACS)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>authentication_profile</td>
      <td>Filter by authentication profile (LDAP or TACACS only)</td>
      <td>Optional</td>
    </tr>
    <tr>
      <td>last_login_gte</td>
      <td>Filters for User’s that have logged in since the given timestamp</td>
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
  <code>!vectra-get-users</code>
</p>
</p>

<h3>7. vectra-get-proxies</h3>
<hr>
<p>Retrieves the current list of proxy IP addresses, or just one by Proxy ID</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-proxies</code>
</p>

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
      <td>proxy_id</td>
      <td>The id of the Proxy object</td>
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
      <td>Vectra.Proxy.Source</td>
      <td>String</td>
      <td>Whether the proxy was auto detected by Cognito or was added by user</td>
    </tr>
    <tr>
      <td>Vectra.Proxy.ID</td>
      <td>String</td>
      <td>The ID of the Proxy</td>
    </tr>
    <tr>
      <td>Vectra.Proxy.Source</td>
      <td>String</td>
      <td>Whether the proxy was auto detected by Cognito or was added by user</td>
    </tr>
    <tr>
      <td>Vectra.Proxy.ConsidersProxy</td>
      <td>String</td>
      <td>Whether to consider the object as a proxy or not</td>
    </tr>
    <tr>
      <td>Vectra.Proxy.Address</td>
      <td>String</td>
      <td>The proxy IP address</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!vectra-get-proxies</code>
</p>
<h5>Context Example</h5>
<pre>
{}
</pre>
<h5>Human Readable Output</h5>
<p>
<p>
Couldn't find any results
</p>
</p>

<h3>8. vectra-get-threatfeed</h3>
<hr>
<p>Retrieves the current list of all ThreatFeeds, or just one by ThreatFeed ID</p>
<h5>Base Command</h5>
<p>
  <code>vectra-get-threatfeed</code>
</p>

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
      <td>threatfeed_id</td>
      <td>The id of the ThreatFeed object</td>
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
      <td>Vectra.ThreatFeed.Category</td>
      <td>String</td>
      <td>The category in which the detection will fire if a match is observed with any indicator in the ThreatFeed</td>
    </tr>
    <tr>
      <td>Vectra.ThreatFeed.Name</td>
      <td>String</td>
      <td>The name of the ThreatFeed</td>
    </tr>
    <tr>
      <td>Vectra.ThreatFeed.Certainty</td>
      <td>String</td>
      <td>The default certainty to use for indicators in the STIX file</td>
    </tr>
    <tr>
      <td>Vectra.ThreatFeed.IndicatorType</td>
      <td>String</td>
      <td>The default indicatorType to use for the observables in the STIX file</td>
    </tr>
    <tr>
      <td>Vectra.ThreatFeed.Duration</td>
      <td>Number</td>
      <td>The default duration for which indicators in the ThreatFeed are valid</td>
    </tr>
    <tr>
      <td>Vectra.ThreatFeed.ID</td>
      <td>String</td>
      <td>The ID of the ThreatFeed</td>
    </tr>
  </tbody>
</table>

<p>&nbsp;</p>
<h5>Command Example</h5>
<p>
  <code>!vectra-get-threatfeed</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Vectra.ThreatFeed": [
        {
            "Category": "exfil",
            "Certainty": "Medium",
            "Duration": 14,
            "ID": "50f897f3c9bdc606472e8d72348c3263",
            "IndicatorType": "Exfiltration",
            "Name": "Suspicious Domains"
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Rules table</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>id</strong></th>
      <th><strong>name</strong></th>
      <th><strong>certainty</strong></th>
      <th><strong>category</strong></th>
      <th><strong>duration</strong></th>
      <th><strong>indicatorType</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 50f897f3c9bdc606472e8d72348c3263 </td>
      <td> Suspicious Domains </td>
      <td> Medium </td>
      <td> exfil </td>
      <td> 14 </td>
      <td> Exfiltration </td>
    </tr>
  </tbody>
</table>
</p>

<h3>9. vectra-search</h3>
<hr>
<p>Advanced search on hosts and detections</p>
<h5>Base Command</h5>
<p>
  <code>vectra-search</code>
</p>

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
      <td>query_string</td>
      <td>The query that needs to be performed, e.g. `host.threat:>=50 and host.certainty:>=50` will find all hosts in the critical quadrant. `host.owner_name:bob` will find hosts with probable owner that contains the phrase “bob” in it.</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>search_type</td>
      <td>The type of search to preform, can be either Hosts or Detections</td>
      <td>Required</td>
    </tr>
    <tr>
      <td>page_size</td>
      <td>Number of results returned per page. the default page_size is 50, max 5000</td>
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
  <code>!vectra-search query_string="host.threat:>=20 and host.certainty:>=20" search_type=hosts</code>
</p>
<h5>Context Example</h5>
<pre>
{
    "Vectra.Host": [
        {
            "Certainty_Score": 33,
            "Hostname": "BThomas-Win7",
            "ID": 7,
            "IP": "0.0.0.0",
            "KeyAsset": true,
            "LastDetection": "2019-10-03T05:56:31Z",
            "State": "active",
            "TargetsKeyAsset": false,
            "Threat_Score": 23
        },
        {
            "Certainty_Score": 46,
            "Hostname": "Robert-MBP",
            "ID": 11,
            "IP": "0.0.0.0",
            "KeyAsset": false,
            "LastDetection": "2019-10-03T01:10:43Z",
            "State": "active",
            "TargetsKeyAsset": false,
            "Threat_Score": 25
        }
    ]
}
</pre>
<h5>Human Readable Output</h5>
<p>
<h3>Search results table</h3>
<table style="width:750px" border="2" cellpadding="6">
  <thead>
    <tr>
      <th><strong>id</strong></th>
      <th><strong>threat</strong></th>
      <th><strong>certainty</strong></th>
      <th><strong>state</strong></th>
      <th><strong>first_timestamp</strong></th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td> 7 </td>
      <td> 23 </td>
      <td> 33 </td>
      <td> active </td>
      <td>  </td>
    </tr>
    <tr>
      <td> 11 </td>
      <td> 25 </td>
      <td> 46 </td>
      <td> active </td>
      <td>  </td>
    </tr>
  </tbody>
</table>

# Replacement Commands

Vectra has developed a new XSOAR content pack to replace the legacy Cortex XSOAR content pack. This new content pack includes commands that replace and extend the functionality of existing commands. The following table outlines which commands should be used for updating existing integrations.


| Legacy Command               | Replacement Command                               |
|------------------------------|---------------------------------------------------|
| `vectra-detections`          | `vectra-search-detections`                        |
| `vectra-get-detections`      | `vectra-search-detections`                        |
| `vectra-get-detection-by-id` | `vectra-detection-describe`                       |
| `vectra-hosts`               | `vectra-search-hosts`                             |
| `vectra-get-hosts`           | `vectra-search-hosts`                             |
| `vectra-get-host-by-id`      | `vectra-host-describe`                            |
| `vectra-get-users`           | `vectra-search-users`                             |
| `vectra-search`              | `vectra-search-hosts`, `vectra-search-detections` |


# New Commands

In addition to the replacement commands, new functionality is included with the current content pack. The following table outlines the new functionality provided.

| Command                        | Command Description                                               |
|--------------------------------|-------------------------------------------------------------------|
| `vectra-search-accounts`       | Returns a list of Account objects                                 |
| `vectra-search-assignments`    | Return a list of assignments                                      |
| `vectra-search-outcomes`       | Returns a list of assignment outcomes                             |
| `vectra-account-describe`      | Returns a single Account details                                  |
| `vectra-account-add-tags`      | Add tags to an Account                                            |
| `vectra-host-del-tags`         | Delete tags from an Host                                          |
| `vectra-detection-get-pcap`    | Returns a Detection's PCAP file (if available)                    |
| `vectra-detection-markasfixed` | Marks/Unmarks a Detection as fixed by providing the Detection ID  |
| `vectra-detection-add-tags`    | Add tags to a Detection                                           |
| `vectra-detection-del-tags`    | Delete tags from a Detection                                      |
| `vectra-outcome-describe`      | Returns a single outcome details                                  |
| `vectra-outcome-create`        | Creates a new assignment outcome                                  |
| `vectra-assignment-describe`   | Returns a single assignment details                               |
| `vectra-assignment-assign`     | Assigns an Account/Host entity to a Vectra User for investigation |
| `vectra-assignment-resolve`    | Resolves an assignment by selecting resolution scheme             |
