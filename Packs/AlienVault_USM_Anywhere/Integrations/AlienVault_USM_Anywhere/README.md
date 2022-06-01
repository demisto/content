<!-- HTML_DOC -->
<div class="cl-preview-section">
<p>Search and monitor alarms and events from AlienVault USM Anywhere.</p>
</div>
<div class="cl-preview-section">
<h2 id="use-cases">Use Cases</h2>
</div>
<div class="cl-preview-section">
<ol>
<li>Fetch new AlienVault alarms as Cortex XSOAR incidents.</li>
<li>Search AlienVault alarms.</li>
<li>Search AlienVault events.</li>
<li>Retrieve events related to an AlienVault alarms.</li>
</ol>
</div>
<div class="cl-preview-section">
<ol>
<li>Navigate to<span> </span><strong>Settings</strong><span> </span>&gt;<span> </span><strong>Integrations</strong><span> </span>&gt;<span> </span><strong>Servers &amp; Services</strong>.</li>
<li>Search for AlienVault USM Anywhere.</li>
<li>Click<span> </span><strong>Add instance</strong><span> </span>to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Server URL (e.g.,<span> </span><a href="https://www.example.com/">https://www.example.com</a>)</strong></li>
<li><strong>Client ID</strong></li>
<li><strong>Client Secret</strong></li>
<li><strong>Trust any certificate (insecure)</strong></li>
<li><strong>Use system proxy</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li><strong>Fetch limit</strong></li>
<li><strong>Time format</strong></li>
<li><strong>First fetch timestamp (<span> </span><time>, e.g., 12 hours, 7 days)</time></strong></li>
</ul>
</li>
<li>Click<span> </span><strong>Test</strong><span> </span>to validate the URLs, token, and connection.</li>
</ol>
</div>
<div class="cl-preview-section">
<h2 id="fetched-incidents-data">Fetched Incidents Data</h2>
</div>
<div class="cl-preview-section">
<pre>{
    "uuid": "9f4aa992-cc85-394a-57a2-cc3a755320a8",
    "has_alarm": false,
    "needs_enrichment": true,
    "packet_data": [
        "a415b77a-a80f-c098-5643-733a9e31f62f"
    ],
    "priority": 20,
    "suppressed": false,
    "events": [
        {
            "_links": {
                "self": {
                    "href": "https://paloalto-networks.alienvault.cloud/api/2.0/events/{eventId}",
                    "templated": true
                }
            },
            "timeStamp": 1558311648948,
            "enriched": true,
            "message": {
                "packet_type": "log",
                "source_country": "US",
                "source_port": 47301,
                "source_organisation": "Digital Ocean",
                "event_type": "alert",
                "time_zone": "+0000",
                "was_guessed": false,
                "rep_device_address": "127.0.0.1",
                "needs_enrichment": true,
                "sensor_uuid": "dfd08cb3-5454-1c99-4f37-770935e0a941",
                "event_category": "Recon",
                "source_registered_country": "US",
                "timestamp_received_iso8601": "2019-05-20T00:20:48.920Z",
                "access_control_outcome": "Allow",
                "destination_name": "192.168.1.77",
                "log": "",
                "source_longitude": "-74.1403",
                "destination_address": "192.168.1.77",
                "bytes_out": 0,
                "event_severity": "2",
                "source_blacklist_priority": "2",
                "source_city": "Clifton",
                "timestamp_occured_iso8601": "2019-05-20T00:20:48.912Z",
                "was_fuzzied": false,
                "source_blacklist_reliability": "4",
                "source_name": "159.203.169.16",
                "source_address": "159.203.169.16",
                "bytes_in": 60,
                "timestamp_occured": "1558311648912",
                "plugin_device": "AlienVault NIDS",
                "transport_protocol": "TCP",
                "malware_family": "nmap",
                "suppressed": "false",
                "event_name": "ET SCAN NMAP -sS window 1024",
                "packets_sent": 0,
                "plugin_version": "0.11",
                "received_from": "USMA-Sensor",
                "plugin": "AlienVault NIDS",
                "plugin_device_type": "Intrusion Detection",
                "destination_canonical": "ab6cde77-8082-df02-a087-a0bdd08fff38",
                "timestamp_received": "1558311648920",
                "plugin_enrichment_script": "dns.lua",
                "used_hint": true,
                "event_subcategory": "Scanner",
                "destination_port": 80,
                "source_region": "NJ",
                "source_blacklist_activity": "Malicious Host",
                "uuid": "a415b77a-a70f-cf98-5643-733a9e31f62f",
                "has_alarm": "false",
                "source_latitude": "40.8364",
                "tag": "lt-suricata",
                "device_direction": "inbound",
                "device_event_category": "Attempted Information Leak",
                "highlight_fields": [
                    "event_category",
                    "event_subcategory",
                    "event_activity",
                    "http_hostname",
                    "malware_family",
                    "event_cve",
                    "rep_device_rule_id",
                    "transport_protocol",
                    "request_url",
                    "file_name",
                    "dns_rrname",
                    "file_hash",
                    "tls_subject",
                    "ssh_server_version",
                    "request_user_agent",
                    "affected_platform",
                    "tls_sni",
                    "tls_fingerprint",
                    "packets_received",
                    "packets_sent",
                    "bytes_in",
                    "bytes_out"
                ],
                "rep_dev_canonical": "127.0.0.1",
                "rep_device_rule_id": "2009582",
                "source_canonical": "159.203.169.16",
                "destination_asset_id": "ab6cde77-8082-df02-a087-a0bdd08fff38",
                "destination_fqdn": "192.168.1.77",
                "packets_received": 1,
                "transient": false,
                "destination_port_label": "HTTP"
            }
        }
    ],
    "_links": {
        "self": {
            "href": "https://paloalto-networks.alienvault.cloud/api/2.0/alarms/9f4aa992-cc85-394a-57a2-cc3a755320a8"
        }
    },
    "rule_intent": "Reconnaissance &amp; Probing",
    "alarm_events_count": 1,
    "alarm_source_countries": [
        "US"
    ],
    "alarm_sensor_sources": [
        "dfd08cb3-5454-1c99-4f37-770935e0a941"
    ],
    "destination_name": "192.168.1.77",
    "rule_dictionary": "SuricataScanRules-Dict",
    "timestamp_occured": "1558311648912",
    "source_organisation": "Digital Ocean",
    "alarm_source_cities": [
        "Clifton"
    ],
    "event_type": "Alarm",
    "rule_method": "Nmap",
    "priority_label": "low",
    "rule_attack_tactic": [
        "Discovery"
    ],
    "source_name": "159.203.169.16",
    "timestamp_received": "1558311648971",
    "destination_canonical": "ab6cde77-8082-df02-a087-a0bdd08fff38",
    "rule_strategy": "Portscan",
    "timestamp_received_iso8601": "2019-05-20T00:20:48.971Z",
    "alarm_destination_assset_ids": [
        "ab6cde77-8082-df02-a087-a0bdd08fff38"
    ],
    "alarm_destinations": [
        "ab6cde77-8082-df02-a087-a0bdd08fff38"
    ],
    "alarm_sources": [
        "159.203.169.16"
    ],
    "rule_attack_id": "T1046",
    "highlight_fields": [
        "source_canonical",
        " destination_canonical",
        " malware_family",
        "rule_attack_id",
        "rule_attack_tactic",
        "rule_attack_technique"
    ],
    "alarm_source_names": [
        "159.203.169.16"
    ],
    "destination_asset_id": "ab6cde77-8082-df02-a087-a0bdd08fff38",
    "alarm_source_longitudes": [
        "-74.1403"
    ],
    "rule_id": "Nmap",
    "alarm_source_organisations": [
        "Digital Ocean"
    ],
    "alarm_source_latitudes": [
        "40.8364"
    ],
    "sensor_uuid": "25032f5b-3707-442a-8d8d-7c4ff8965b14",
    "timestamp_occured_iso8601": "2019-05-20T00:20:48.912Z",
    "alarm_destination_names": [
        "192.168.1.77"
    ],
    "transient": false,
    "alarm_source_blacklist_activity": [
        "Malicious Host"
    ],
    "rule_attack_technique": "Network Service Scanning",
    "source_canonical": "159.203.169.16",
    "packet_type": "alarm"
}
</pre>
</div>
<div class="cl-preview-section">
<h2 id="commands">Commands</h2>
</div>
<div class="cl-preview-section">
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
</div>
<div class="cl-preview-section">
<ol>
<li>Get alarms: alienvault-search-alarms</li>
<li>Get alarm details: alienvault-get-alarm</li>
<li>Search for events: alienvault-search-events</li>
<li>Get alarm events: alienvault-get-events-by-alarm</li>
</ol>
</div>
<div class="cl-preview-section">
<h3 id="get-alarms">1. Get alarms</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves alarms from AlienVault.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>alienvault-search-alarms</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 148px;"><strong>Argument Name</strong></th>
<th style="width: 521px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 148px;">limit</td>
<td style="width: 521px;">Maximum number of alarms to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">status</td>
<td style="width: 521px;">Filter by alarm status.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">priority</td>
<td style="width: 521px;">Filter by alarm priority.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">show_suppressed</td>
<td style="width: 521px;">Whether to include suppressed alarms in the search.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">time_frame</td>
<td style="width: 521px;">Filter by time frame, for example: Last 48 Hours.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">start_time</td>
<td style="width: 521px;">If time_frame is Custom, specify the start time for the time range, for example: 2017-06-01T12:48:16Z.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">end_time</td>
<td style="width: 521px;">If time_frame is Custom, specify the end time for the time range, for example: 2017-06-01T12:48:16Z.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">rule_intent</td>
<td style="width: 521px;">Filter alarms by rule intention.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">rule_method</td>
<td style="width: 521px;">Filter alarms by rule method.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 148px;">rule_strategy</td>
<td style="width: 521px;">Filter alarms by rule strategy</td>
<td style="width: 71px;">Optional</td>
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
<th style="width: 364px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 281px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 364px;">AlienVault.Alarm.ID</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm ID.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Priority</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm priority.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.OccurredTime</td>
<td style="width: 95px;">Date</td>
<td style="width: 281px;">Time the alarm occurred.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.ReceivedTime</td>
<td style="width: 95px;">Date</td>
<td style="width: 281px;">Time the alarm was received.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 281px;">Alarm source object.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source.IPAddress</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm Source IP Address.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source.Organization</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Source organization.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source.Country</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Source country.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Destination</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 281px;">Alarm destination object.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Destination.IPAddress</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm destination IP Address.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleAttackID</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule attack ID.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleStrategy</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule strategy.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleIntent</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule intent.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleID</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule ID.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleDictionary</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule dictionary.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleMethod</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule method.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleAttackTactic</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 281px;">Rule attack tactic.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleAttackTechnique</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule attack technique.</td>
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
<pre>!alienvault-search-alarms limit=2 time_frame="Last 7 Days" rule_method=Nmap
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "AlienVault.Alarm": [
        {
            "Source": {
                "Country": [
                    "RU"
                ], 
                "IPAddress": [
                    "185.176.27.118"
                ], 
                "Organization": [
                    "IP Khnykin Vitaliy Yakovlevich"
                ]
            }, 
            "RuleMethod": "Nmap", 
            "OccurredTime": "2019-05-21T10:11:39.226Z", 
            "RuleID": "Nmap", 
            "RuleDictionary": "SuricataScanRules-Dict", 
            "ReceivedTime": "2019-05-21T10:11:39.288Z", 
            "Destination": {
                "IPAddress": [
                    "192.168.1.201"
                ]
            }, 
            "RuleAttackTactic": [
                "Discovery"
            ], 
            "ID": "62c61fd9-cb74-2ca3-fe53-f7e43489c807", 
            "Priority": "low", 
            "RuleAttackID": "T1046", 
            "RuleStrategy": "Portscan", 
            "RuleAttackTechnique": "Network Service Scanning", 
            "Event": [
                {
                    "ReceivedTime": "2019-05-21T10:11:39.228Z", 
                    "ID": "7c076810-22dd-47f1-b745-f4b559fa26df", 
                    "OccurredTime": "2019-05-21T10:11:39.226Z"
                }
            ], 
            "RuleIntent": "Reconnaissance &amp; Probing"
        }, 
        {
            "Source": {
                "Country": [
                    "RU"
                ], 
                "IPAddress": [
                    "92.119.160.40"
                ], 
                "Organization": [
                    "SingleHost"
                ]
            }, 
            "RuleMethod": "Nmap", 
            "OccurredTime": "2019-05-21T09:53:07.962Z", 
            "RuleID": "Nmap", 
            "RuleDictionary": "SuricataScanRules-Dict", 
            "ReceivedTime": "2019-05-21T09:53:08.044Z", 
            "Destination": {
                "IPAddress": [
                    "192.168.1.31"
                ]
            }, 
            "RuleAttackTactic": [
                "Discovery"
            ], 
            "ID": "45ccbeb3-b69f-9bee-7427-a3e0cfd4666b", 
            "Priority": "low", 
            "RuleAttackID": "T1046", 
            "RuleStrategy": "Portscan", 
            "RuleAttackTechnique": "Network Service Scanning", 
            "Event": [
                {
                    "ReceivedTime": "2019-05-27T09:34:45.224Z", 
                    "ID": "009e8bab-34e4-2882-c1a8-7349e9ecff88", 
                    "OccurredTime": "2019-05-27T09:34:45.220Z"
                }
            ], 
            "RuleIntent": "Reconnaissance &amp; Probing"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="alarms">Alarms:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Priority</th>
<th>OccurredTime</th>
<th>ReceivedTime</th>
<th>RuleAttackID</th>
<th>RuleAttackTactic</th>
<th>RuleAttackTechnique</th>
<th>RuleDictionary</th>
<th>RuleID</th>
<th>RuleIntent</th>
<th>RuleMethod</th>
<th>RuleStrategy</th>
<th>Source</th>
<th>Destination</th>
<th>Event</th>
</tr>
</thead>
<tbody>
<tr>
<td>62c61fd9-cb74-2ca3-fe53-f7e43489c807</td>
<td>low</td>
<td>2019-05-21T10:11:39.226Z</td>
<td>2019-05-21T10:11:39.288Z</td>
<td>T1046</td>
<td>Discovery</td>
<td>Network Service Scanning</td>
<td>SuricataScanRules-Dict</td>
<td>Nmap</td>
<td>Reconnaissance &amp; Probing</td>
<td>Nmap</td>
<td>Portscan</td>
<td>IPAddress: 185.176.27.118<br> Organization: IP Khnykin Vitaliy Yakovlevich<br> Country: RU</td>
<td>IPAddress: 192.168.1.201</td>
<td>{‘ID’: ‘7c076810-22dd-47f1-b745-f4b559fa26df’, ‘OccurredTime’: ‘2019-05-21T10:11:39.226Z’, ‘ReceivedTime’: ‘2019-05-21T10:11:39.228Z’}</td>
</tr>
<tr>
<td>45ccbeb3-b69f-9bee-7427-a3e0cfd4666b</td>
<td>low</td>
<td>2019-05-21T09:53:07.962Z</td>
<td>2019-05-21T09:53:08.044Z</td>
<td>T1046</td>
<td>Discovery</td>
<td>Network Service Scanning</td>
<td>SuricataScanRules-Dict</td>
<td>Nmap</td>
<td>Reconnaissance &amp; Probing</td>
<td>Nmap</td>
<td>Portscan</td>
<td>IPAddress: 92.119.160.40<br> Organization: OOO Network of data-centers Selectel<br> Country: RU</td>
<td>IPAddress: 192.168.1.31</td>
<td>{‘ID’: ‘41ee3f2d-ad61-0130-52b7-ebf31bdb79a2’, ‘OccurredTime’: ‘2019-05-21T09:53:07.962Z’, ‘ReceivedTime’: ‘2019-05-21T09:53:07.968Z’}</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-alarm-details">2. Get alarm details</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves details for an alarm, using alarm_id.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-1">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>alienvault-get-alarm</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-1">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 158px;"><strong>Argument Name</strong></th>
<th style="width: 511px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 158px;">alarm_id</td>
<td style="width: 511px;">Alarm ID. Can be obtained by running the<span> </span><code>alienvault-search-alarms</code> command.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
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
<th style="width: 364px;"><strong>Path</strong></th>
<th style="width: 95px;"><strong>Type</strong></th>
<th style="width: 281px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 364px;">AlienVault.Alarm.ID</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm ID.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Priority</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm priority.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.OccurredTime</td>
<td style="width: 95px;">Date</td>
<td style="width: 281px;">Time the alarm occurred.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.ReceivedTime</td>
<td style="width: 95px;">Date</td>
<td style="width: 281px;">Time the alarm was received.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 281px;">Alarm source object.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source.IPAddress</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm source IP address.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source.Organization</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Source organization.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Source.Country</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Source country.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Destination</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 281px;">Alarm destination object.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.Destination.IPAddress</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Alarm destination IP address.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleAttackID</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule attack ID.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleStrategy</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule strategy.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleIntent</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule intent.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleID</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule ID.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleDictionary</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule dictionary.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleMethod</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule method.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleAttackTactic</td>
<td style="width: 95px;">Unknown</td>
<td style="width: 281px;">Rule attack tactic.</td>
</tr>
<tr>
<td style="width: 364px;">AlienVault.Alarm.RuleAttackTechnique</td>
<td style="width: 95px;">String</td>
<td style="width: 281px;">Rule attack technique.</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h5 id="command-example-1">Command Example</h5>
</div>
<div class="cl-preview-section">
<pre>!alienvault-get-alarm alarm_id=3194f0f5-0350-7a09-87b2-8fb20b963ed8
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-1">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "AlienVault.Alarm": [
        {
            "Source": {
                "Country": [
                    "PL"
                ], 
                "IPAddress": [
                    "85.93.20.34"
                ], 
                "Organization": [
                    "GHOSTnet GmbH"
                ]
            }, 
            "RuleMethod": "Microsoft Remote Desktop", 
            "OccurredTime": "2019-05-15T12:42:10.743Z", 
            "RuleID": "RDP", 
            "RuleDictionary": "SuricataBruteforceRules-Dict", 
            "ReceivedTime": "2019-05-15T12:42:20.815Z", 
            "Destination": {
                "IPAddress": [
                    "192.168.1.8"
                ]
            }, 
            "RuleAttackTactic": [
                "Credential Access"
            ], 
            "ID": "3194f0f5-0350-7a09-87b2-8fb20b963ed8", 
            "Priority": "medium", 
            "RuleAttackID": "T1110", 
            "RuleStrategy": "Brute Force Authentication", 
            "RuleAttackTechnique": "Brute Force", 
            "Event": [
                {
                    "ReceivedTime": "2019-05-15T12:40:46.076Z", 
                    "ID": "b36a0259-6203-ecfc-5023-aa198c1e4329", 
                    "OccurredTime": "2019-05-15T12:40:46.071Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:48.745Z", 
                    "ID": "eab1d04d-4251-44a4-6cf8-0b1ad7f23c36", 
                    "OccurredTime": "2019-05-15T12:40:48.740Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:51.048Z", 
                    "ID": "1a0f4f1a-c855-2808-f758-127e5578bda9", 
                    "OccurredTime": "2019-05-15T12:40:51.041Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:51.049Z", 
                    "ID": "4c6d5d9d-a5f8-2d24-0176-060f4139e5a0", 
                    "OccurredTime": "2019-05-15T12:40:51.041Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:55.940Z", 
                    "ID": "a14ef1a1-2617-3b85-02dc-8c5531b96e5f", 
                    "OccurredTime": "2019-05-15T12:40:55.936Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:55.943Z", 
                    "ID": "36233284-0aea-14cf-a90f-91f8c3952056", 
                    "OccurredTime": "2019-05-15T12:40:55.936Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:55.947Z", 
                    "ID": "551c58fd-0f22-e3a8-5478-056444759f5d", 
                    "OccurredTime": "2019-05-15T12:40:55.936Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:03.414Z", 
                    "ID": "9c019302-7f60-3c33-f725-dd12c9bdb97a", 
                    "OccurredTime": "2019-05-15T12:41:03.405Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:10.809Z", 
                    "ID": "7f7011b9-b57e-c46e-3e95-5e86e51832e0", 
                    "OccurredTime": "2019-05-15T12:41:10.803Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:10.814Z", 
                    "ID": "6dddab25-f3e2-c293-afd4-84081e5a41ff", 
                    "OccurredTime": "2019-05-15T12:41:10.803Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:10.815Z", 
                    "ID": "211627df-ec2e-52c4-ff76-dc103951d340", 
                    "OccurredTime": "2019-05-15T12:41:10.803Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:10.815Z", 
                    "ID": "52bf99f5-1f79-e04e-9fad-1b423a644e89", 
                    "OccurredTime": "2019-05-15T12:41:10.803Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:18.014Z", 
                    "ID": "6553b62f-d1db-2318-7e9d-4ae5f0de5d41", 
                    "OccurredTime": "2019-05-15T12:41:18.007Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:24.554Z", 
                    "ID": "1e635a85-d8a5-66cc-abf4-9067db82955a", 
                    "OccurredTime": "2019-05-15T12:41:20.525Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:31.840Z", 
                    "ID": "124314f7-bcb2-c706-ada3-50a57ef2d8b3", 
                    "OccurredTime": "2019-05-15T12:41:31.837Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:31.845Z", 
                    "ID": "35cafad8-2e36-9bef-45ce-d37f919bb3ac", 
                    "OccurredTime": "2019-05-15T12:41:31.837Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:37.224Z", 
                    "ID": "ea2b003a-44b7-4b17-9438-993a0a5fe7c5", 
                    "OccurredTime": "2019-05-15T12:41:37.221Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:41.945Z", 
                    "ID": "318ffee9-dfd5-4ef9-ded0-b8fbf7fd0402", 
                    "OccurredTime": "2019-05-15T12:41:41.942Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:50.283Z", 
                    "ID": "22a04ec4-cbbd-49c2-dcee-4329e97dbcd3", 
                    "OccurredTime": "2019-05-15T12:41:46.766Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:52.654Z", 
                    "ID": "d2d62bbd-5db2-823c-28a1-a1acf21af7fc", 
                    "OccurredTime": "2019-05-15T12:41:46.766Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:54.125Z", 
                    "ID": "6042e4a2-4982-7016-bbd3-5506030d2dc4", 
                    "OccurredTime": "2019-05-15T12:41:46.766Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:42:06.010Z", 
                    "ID": "b3beeb7e-9ee2-f417-3cc8-228bd5e9a18f", 
                    "OccurredTime": "2019-05-15T12:42:06.005Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:46.079Z", 
                    "ID": "720d9a9d-92cc-45b1-bbb3-604fb053282b", 
                    "OccurredTime": "2019-05-15T12:40:46.071Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:46.080Z", 
                    "ID": "79549d86-40df-0032-e3cf-cf6d1cd86ecf", 
                    "OccurredTime": "2019-05-15T12:40:46.071Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:46.081Z", 
                    "ID": "220a996a-a64c-a7ea-14b6-3aca57681722", 
                    "OccurredTime": "2019-05-15T12:40:46.071Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:53.608Z", 
                    "ID": "bb2107e0-ff7e-f3ee-d7ec-f7bb32a6f795", 
                    "OccurredTime": "2019-05-15T12:40:53.604Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:55.945Z", 
                    "ID": "a21fd0a8-b2ae-fbae-ef22-f23d30a30099", 
                    "OccurredTime": "2019-05-15T12:40:55.936Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:03.409Z", 
                    "ID": "249827bf-e31d-79d7-8725-cee8ffc7037f", 
                    "OccurredTime": "2019-05-15T12:41:03.405Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:03.413Z", 
                    "ID": "ed0c4580-69a6-d462-2205-d06fc436ecde", 
                    "OccurredTime": "2019-05-15T12:41:03.405Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:13.246Z", 
                    "ID": "7a3ceb92-9ea7-2387-39b8-deddfd1000ec", 
                    "OccurredTime": "2019-05-15T12:41:13.242Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:18.013Z", 
                    "ID": "42b0c4dc-c260-0cfd-6b44-e99716f8a736", 
                    "OccurredTime": "2019-05-15T12:41:18.007Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:18.016Z", 
                    "ID": "69be0a19-9b9b-f226-02fd-cb694bb24197", 
                    "OccurredTime": "2019-05-15T12:41:18.007Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:26.070Z", 
                    "ID": "47bdc7ee-9679-714c-a5b2-b9bbbb68cc4a", 
                    "OccurredTime": "2019-05-15T12:41:22.874Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:31.848Z", 
                    "ID": "be9f159f-1225-3461-d863-c55d46517b81", 
                    "OccurredTime": "2019-05-15T12:41:31.837Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:34.821Z", 
                    "ID": "8a6639c8-db0e-3077-aa0d-764c83726590", 
                    "OccurredTime": "2019-05-15T12:41:34.816Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:56.364Z", 
                    "ID": "f65faf00-d0d8-6059-7784-20407a8a1231", 
                    "OccurredTime": "2019-05-15T12:41:56.359Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:42:06.013Z", 
                    "ID": "21684ce5-55dd-8017-71b5-46369ae14e17", 
                    "OccurredTime": "2019-05-15T12:42:06.005Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:42:10.744Z", 
                    "ID": "b56d2afd-a5e3-aab8-5509-0a9dcabdedb0", 
                    "OccurredTime": "2019-05-15T12:42:10.743Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:51.046Z", 
                    "ID": "2ce1d100-de85-1ef0-0673-8bfae574c1ce", 
                    "OccurredTime": "2019-05-15T12:40:51.041Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:40:51.044Z", 
                    "ID": "09550d30-e275-6bfe-fdf3-1d01b43ba6ef", 
                    "OccurredTime": "2019-05-15T12:40:51.041Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:03.410Z", 
                    "ID": "15c4ff5e-a9f8-1a3c-2285-5100ecbfdd40", 
                    "OccurredTime": "2019-05-15T12:41:03.405Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:08.100Z", 
                    "ID": "d9736b73-d8ad-6c39-1df5-49a2f3784337", 
                    "OccurredTime": "2019-05-15T12:41:08.098Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:18.012Z", 
                    "ID": "93e98ec6-d6b6-cca9-255e-2944ce5fad4c", 
                    "OccurredTime": "2019-05-15T12:41:18.007Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:31.843Z", 
                    "ID": "6b526907-c9d6-eabe-f2d5-9eb783b28715", 
                    "OccurredTime": "2019-05-15T12:41:31.837Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:50.287Z", 
                    "ID": "b5312239-5c45-d036-66fc-1c1fbb3d7260", 
                    "OccurredTime": "2019-05-15T12:41:49.216Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:51.693Z", 
                    "ID": "1cfb337f-9725-7c44-34dc-4f18172c3f6c", 
                    "OccurredTime": "2019-05-15T12:41:51.690Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:54.807Z", 
                    "ID": "c2ef5423-76b1-a0a0-0a0b-b4443507d4a5", 
                    "OccurredTime": "2019-05-15T12:41:46.766Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:41:54.808Z", 
                    "ID": "463049df-c917-821a-9d43-d1d813394eac", 
                    "OccurredTime": "2019-05-15T12:41:51.690Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:42:06.010Z", 
                    "ID": "94d8203b-6db5-702c-3e7f-d2601f888ea3", 
                    "OccurredTime": "2019-05-15T12:42:06.005Z"
                }, 
                {
                    "ReceivedTime": "2019-05-15T12:42:06.011Z", 
                    "ID": "8868f432-89b1-2740-3007-7dadc57700e4", 
                    "OccurredTime": "2019-05-15T12:42:06.005Z"
                }
            ], 
            "RuleIntent": "Delivery &amp; Attack"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-1">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="alarm-3194f0f5-0350-7a09-87b2-8fb20b963ed8">Alarm 3194f0f5-0350-7a09-87b2-8fb20b963ed8</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Priority</th>
<th>OccurredTime</th>
<th>ReceivedTime</th>
<th>RuleAttackID</th>
<th>RuleAttackTactic</th>
<th>RuleAttackTechnique</th>
<th>RuleDictionary</th>
<th>RuleID</th>
<th>RuleIntent</th>
<th>RuleMethod</th>
<th>RuleStrategy</th>
<th>Source</th>
<th>Destination</th>
<th>Event</th>
</tr>
</thead>
<tbody>
<tr>
<td>3194f0f5-0350-7a09-87b2-8fb20b963ed8</td>
<td>medium</td>
<td>2019-05-15T12:42:10.743Z</td>
<td>2019-05-15T12:42:20.815Z</td>
<td>T1110</td>
<td>Credential Access</td>
<td>Brute Force</td>
<td>SuricataBruteforceRules-Dict</td>
<td>RDP</td>
<td>Delivery &amp; Attack</td>
<td>Microsoft Remote Desktop</td>
<td>Brute Force Authentication</td>
<td>IPAddress: 85.93.20.34<br> Organization: GHOSTnet GmbH<br> Country: PL</td>
<td>IPAddress: 192.168.1.8</td>
<td>{‘ID’: ‘b36a0259-6203-ecfc-5023-aa198c1e4329’, ‘OccurredTime’: ‘2019-05-15T12:40:46.071Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:46.076Z’},<br> {‘ID’: ‘eab1d04d-4251-44a4-6cf8-0b1ad7f23c36’, ‘OccurredTime’: ‘2019-05-15T12:40:48.740Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:48.745Z’},<br> {‘ID’: ‘1a0f4f1a-c855-2808-f758-127e5578bda9’, ‘OccurredTime’: ‘2019-05-15T12:40:51.041Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:51.048Z’},<br> {‘ID’: ‘4c6d5d9d-a5f8-2d24-0176-060f4139e5a0’, ‘OccurredTime’: ‘2019-05-15T12:40:51.041Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:51.049Z’},<br> {‘ID’: ‘a14ef1a1-2617-3b85-02dc-8c5531b96e5f’, ‘OccurredTime’: ‘2019-05-15T12:40:55.936Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:55.940Z’},<br> {‘ID’: ‘36233284-0aea-14cf-a90f-91f8c3952056’, ‘OccurredTime’: ‘2019-05-15T12:40:55.936Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:55.943Z’},<br> {‘ID’: ‘551c58fd-0f22-e3a8-5478-056444759f5d’, ‘OccurredTime’: ‘2019-05-15T12:40:55.936Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:55.947Z’},<br> {‘ID’: ‘9c019302-7f60-3c33-f725-dd12c9bdb97a’, ‘OccurredTime’: ‘2019-05-15T12:41:03.405Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:03.414Z’},<br> {‘ID’: ‘7f7011b9-b57e-c46e-3e95-5e86e51832e0’, ‘OccurredTime’: ‘2019-05-15T12:41:10.803Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:10.809Z’},<br> {‘ID’: ‘6dddab25-f3e2-c293-afd4-84081e5a41ff’, ‘OccurredTime’: ‘2019-05-15T12:41:10.803Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:10.814Z’},<br> {‘ID’: ‘211627df-ec2e-52c4-ff76-dc103951d340’, ‘OccurredTime’: ‘2019-05-15T12:41:10.803Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:10.815Z’},<br> {‘ID’: ‘52bf99f5-1f79-e04e-9fad-1b423a644e89’, ‘OccurredTime’: ‘2019-05-15T12:41:10.803Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:10.815Z’},<br> {‘ID’: ‘6553b62f-d1db-2318-7e9d-4ae5f0de5d41’, ‘OccurredTime’: ‘2019-05-15T12:41:18.007Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:18.014Z’},<br> {‘ID’: ‘1e635a85-d8a5-66cc-abf4-9067db82955a’, ‘OccurredTime’: ‘2019-05-15T12:41:20.525Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:24.554Z’},<br> {‘ID’: ‘124314f7-bcb2-c706-ada3-50a57ef2d8b3’, ‘OccurredTime’: ‘2019-05-15T12:41:31.837Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:31.840Z’},<br> {‘ID’: ‘35cafad8-2e36-9bef-45ce-d37f919bb3ac’, ‘OccurredTime’: ‘2019-05-15T12:41:31.837Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:31.845Z’},<br> {‘ID’: ‘ea2b003a-44b7-4b17-9438-993a0a5fe7c5’, ‘OccurredTime’: ‘2019-05-15T12:41:37.221Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:37.224Z’},<br> {‘ID’: ‘318ffee9-dfd5-4ef9-ded0-b8fbf7fd0402’, ‘OccurredTime’: ‘2019-05-15T12:41:41.942Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:41.945Z’},<br> {‘ID’: ‘22a04ec4-cbbd-49c2-dcee-4329e97dbcd3’, ‘OccurredTime’: ‘2019-05-15T12:41:46.766Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:50.283Z’},<br> {‘ID’: ‘d2d62bbd-5db2-823c-28a1-a1acf21af7fc’, ‘OccurredTime’: ‘2019-05-15T12:41:46.766Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:52.654Z’},<br> {‘ID’: ‘6042e4a2-4982-7016-bbd3-5506030d2dc4’, ‘OccurredTime’: ‘2019-05-15T12:41:46.766Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:54.125Z’},<br> {‘ID’: ‘b3beeb7e-9ee2-f417-3cc8-228bd5e9a18f’, ‘OccurredTime’: ‘2019-05-15T12:42:06.005Z’, ‘ReceivedTime’: ‘2019-05-15T12:42:06.010Z’},<br> {‘ID’: ‘720d9a9d-92cc-45b1-bbb3-604fb053282b’, ‘OccurredTime’: ‘2019-05-15T12:40:46.071Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:46.079Z’},<br> {‘ID’: ‘79549d86-40df-0032-e3cf-cf6d1cd86ecf’, ‘OccurredTime’: ‘2019-05-15T12:40:46.071Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:46.080Z’},<br> {‘ID’: ‘220a996a-a64c-a7ea-14b6-3aca57681722’, ‘OccurredTime’: ‘2019-05-15T12:40:46.071Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:46.081Z’},<br> {‘ID’: ‘bb2107e0-ff7e-f3ee-d7ec-f7bb32a6f795’, ‘OccurredTime’: ‘2019-05-15T12:40:53.604Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:53.608Z’},<br> {‘ID’: ‘a21fd0a8-b2ae-fbae-ef22-f23d30a30099’, ‘OccurredTime’: ‘2019-05-15T12:40:55.936Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:55.945Z’},<br> {‘ID’: ‘249827bf-e31d-79d7-8725-cee8ffc7037f’, ‘OccurredTime’: ‘2019-05-15T12:41:03.405Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:03.409Z’},<br> {‘ID’: ‘ed0c4580-69a6-d462-2205-d06fc436ecde’, ‘OccurredTime’: ‘2019-05-15T12:41:03.405Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:03.413Z’},<br> {‘ID’: ‘7a3ceb92-9ea7-2387-39b8-deddfd1000ec’, ‘OccurredTime’: ‘2019-05-15T12:41:13.242Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:13.246Z’},<br> {‘ID’: ‘42b0c4dc-c260-0cfd-6b44-e99716f8a736’, ‘OccurredTime’: ‘2019-05-15T12:41:18.007Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:18.013Z’},<br> {‘ID’: ‘69be0a19-9b9b-f226-02fd-cb694bb24197’, ‘OccurredTime’: ‘2019-05-15T12:41:18.007Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:18.016Z’},<br> {‘ID’: ‘47bdc7ee-9679-714c-a5b2-b9bbbb68cc4a’, ‘OccurredTime’: ‘2019-05-15T12:41:22.874Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:26.070Z’},<br> {‘ID’: ‘be9f159f-1225-3461-d863-c55d46517b81’, ‘OccurredTime’: ‘2019-05-15T12:41:31.837Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:31.848Z’},<br> {‘ID’: ‘8a6639c8-db0e-3077-aa0d-764c83726590’, ‘OccurredTime’: ‘2019-05-15T12:41:34.816Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:34.821Z’},<br> {‘ID’: ‘f65faf00-d0d8-6059-7784-20407a8a1231’, ‘OccurredTime’: ‘2019-05-15T12:41:56.359Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:56.364Z’},<br> {‘ID’: ‘21684ce5-55dd-8017-71b5-46369ae14e17’, ‘OccurredTime’: ‘2019-05-15T12:42:06.005Z’, ‘ReceivedTime’: ‘2019-05-15T12:42:06.013Z’},<br> {‘ID’: ‘b56d2afd-a5e3-aab8-5509-0a9dcabdedb0’, ‘OccurredTime’: ‘2019-05-15T12:42:10.743Z’, ‘ReceivedTime’: ‘2019-05-15T12:42:10.744Z’},<br> {‘ID’: ‘2ce1d100-de85-1ef0-0673-8bfae574c1ce’, ‘OccurredTime’: ‘2019-05-15T12:40:51.041Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:51.046Z’},<br> {‘ID’: ‘09550d30-e275-6bfe-fdf3-1d01b43ba6ef’, ‘OccurredTime’: ‘2019-05-15T12:40:51.041Z’, ‘ReceivedTime’: ‘2019-05-15T12:40:51.044Z’},<br> {‘ID’: ‘15c4ff5e-a9f8-1a3c-2285-5100ecbfdd40’, ‘OccurredTime’: ‘2019-05-15T12:41:03.405Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:03.410Z’},<br> {‘ID’: ‘d9736b73-d8ad-6c39-1df5-49a2f3784337’, ‘OccurredTime’: ‘2019-05-15T12:41:08.098Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:08.100Z’},<br> {‘ID’: ‘93e98ec6-d6b6-cca9-255e-2944ce5fad4c’, ‘OccurredTime’: ‘2019-05-15T12:41:18.007Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:18.012Z’},<br> {‘ID’: ‘6b526907-c9d6-eabe-f2d5-9eb783b28715’, ‘OccurredTime’: ‘2019-05-15T12:41:31.837Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:31.843Z’},<br> {‘ID’: ‘b5312239-5c45-d036-66fc-1c1fbb3d7260’, ‘OccurredTime’: ‘2019-05-15T12:41:49.216Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:50.287Z’},<br> {‘ID’: ‘1cfb337f-9725-7c44-34dc-4f18172c3f6c’, ‘OccurredTime’: ‘2019-05-15T12:41:51.690Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:51.693Z’},<br> {‘ID’: ‘c2ef5423-76b1-a0a0-0a0b-b4443507d4a5’, ‘OccurredTime’: ‘2019-05-15T12:41:46.766Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:54.807Z’},<br> {‘ID’: ‘463049df-c917-821a-9d43-d1d813394eac’, ‘OccurredTime’: ‘2019-05-15T12:41:51.690Z’, ‘ReceivedTime’: ‘2019-05-15T12:41:54.808Z’},<br> {‘ID’: ‘94d8203b-6db5-702c-3e7f-d2601f888ea3’, ‘OccurredTime’: ‘2019-05-15T12:42:06.005Z’, ‘ReceivedTime’: ‘2019-05-15T12:42:06.010Z’},<br> {‘ID’: ‘8868f432-89b1-2740-3007-7dadc57700e4’, ‘OccurredTime’: ‘2019-05-15T12:42:06.005Z’, ‘ReceivedTime’: ‘2019-05-15T12:42:06.011Z’}</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="search-for-events">3. Search for events</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Search for events.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-2">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>alienvault-search-events</code></p>
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
<td style="width: 141px;">limit</td>
<td style="width: 528px;">Maximum number of alarms to return.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">account_name</td>
<td style="width: 528px;">The account name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">event_name</td>
<td style="width: 528px;">Event name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">source_name</td>
<td style="width: 528px;">Source name.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">time_frame</td>
<td style="width: 528px;">Filter by time frame, for example: Last 48 Hours.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">start_time</td>
<td style="width: 528px;">If time_frame is Custom, specify the start time for the time range, for example: 2017-06-01T12:48:16Z.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 141px;">end_time</td>
<td style="width: 528px;">If time_frame is Custom, specify the end time for the time range, for exmaple: 2017-06-01T12:48:16Z.</td>
<td style="width: 71px;">Optional</td>
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
<th style="width: 359px;"><strong>Path</strong></th>
<th style="width: 79px;"><strong>Type</strong></th>
<th style="width: 302px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 359px;">AlienVault.Event.Category</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Event category.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Source.IPAddress</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Source IP address.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Source.Port</td>
<td style="width: 79px;">Number</td>
<td style="width: 302px;">Source port.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Destination.IPAddress</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Destination IP address.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Destination.Port</td>
<td style="width: 79px;">Number</td>
<td style="width: 302px;">Destination port.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Severity</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Event severity.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.OccurredTime</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Time the even occurred.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.ReceivedTime</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Time the even was received.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.AccessControlOutcome</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Access control outcome.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Suppressed</td>
<td style="width: 79px;">Bool</td>
<td style="width: 302px;">Whether the even is suppressed.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.ID</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Event ID.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Name</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Event name.</td>
</tr>
<tr>
<td style="width: 359px;">AlienVault.Event.Subcategory</td>
<td style="width: 79px;">String</td>
<td style="width: 302px;">Event subcategory.</td>
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
<pre>!alienvault-search-events limit="5" event_name="ET POLICY RDP connection confirm" time_frame="Today"
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-2">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "AlienVault.Event": [
        {
            "Category": "Information", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY RDP connection confirm", 
            "OccurredTime": "2019-05-27T12:27:58.457Z", 
            "ReceivedTime": "2019-05-27T12:27:58.463Z", 
            "Destination": {
                "IPAddress": "77.247.110.59", 
                "Port": 30304
            }, 
            "Source": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "f4f4c3bf-9b49-f080-3b14-8f1b348a5cbd", 
            "Severity": "3"
        }, 
        {
            "Category": "Information", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY RDP connection confirm", 
            "OccurredTime": "2019-05-27T12:27:50.390Z", 
            "ReceivedTime": "2019-05-27T12:27:57.338Z", 
            "Destination": {
                "IPAddress": "185.254.120.27", 
                "Port": 29411
            }, 
            "Source": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "b71d0aa1-e234-6007-69d8-d880c1955336", 
            "Severity": "3"
        }, 
        {
            "Category": "Information", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY RDP connection confirm", 
            "OccurredTime": "2019-05-27T12:27:50.390Z", 
            "ReceivedTime": "2019-05-27T12:27:56.050Z", 
            "Destination": {
                "IPAddress": "185.254.120.27", 
                "Port": 29411
            }, 
            "Source": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "c380e2ee-acc7-a899-d8eb-22095fbd1a9b", 
            "Severity": "3"
        }, 
        {
            "Category": "Information", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY RDP connection confirm", 
            "OccurredTime": "2019-05-27T12:27:50.390Z", 
            "ReceivedTime": "2019-05-27T12:27:58.586Z", 
            "Destination": {
                "IPAddress": "185.254.120.27", 
                "Port": 29411
            }, 
            "Source": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "d8f5c4f7-3466-2342-6ee0-6beeff7587ae", 
            "Severity": "3"
        }, 
        {
            "Category": "Information", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY RDP connection confirm", 
            "OccurredTime": "2019-05-27T12:27:50.390Z", 
            "ReceivedTime": "2019-05-27T12:27:54.841Z", 
            "Destination": {
                "IPAddress": "185.254.120.27", 
                "Port": 29411
            }, 
            "Source": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "1f9d3d71-5ec2-b58f-e3a6-f575a525b3d5", 
            "Severity": "3"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-2">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="events">Events:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>OccurredTime</th>
<th>ReceivedTime</th>
<th>Suppressed</th>
<th>AccessControlOutcome</th>
<th>Category</th>
<th>Severity</th>
<th>Subcategory</th>
<th>Source</th>
<th>Destination</th>
</tr>
</thead>
<tbody>
<tr>
<td>f4f4c3bf-9b49-f080-3b14-8f1b348a5cbd</td>
<td>ET POLICY RDP connection confirm</td>
<td>2019-05-27T12:27:58.457Z</td>
<td>2019-05-27T12:27:58.463Z</td>
<td>false</td>
<td>Allow</td>
<td>Information</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
<td>IPAddress: 77.247.110.59<br> Port: 30304</td>
</tr>
<tr>
<td>b71d0aa1-e234-6007-69d8-d880c1955336</td>
<td>ET POLICY RDP connection confirm</td>
<td>2019-05-27T12:27:50.390Z</td>
<td>2019-05-27T12:27:57.338Z</td>
<td>false</td>
<td>Allow</td>
<td>Information</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
<td>IPAddress: 185.254.120.27<br> Port: 29411</td>
</tr>
<tr>
<td>c380e2ee-acc7-a899-d8eb-22095fbd1a9b</td>
<td>ET POLICY RDP connection confirm</td>
<td>2019-05-27T12:27:50.390Z</td>
<td>2019-05-27T12:27:56.050Z</td>
<td>false</td>
<td>Allow</td>
<td>Information</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
<td>IPAddress: 185.254.120.27<br> Port: 29411</td>
</tr>
<tr>
<td>d8f5c4f7-3466-2342-6ee0-6beeff7587ae</td>
<td>ET POLICY RDP connection confirm</td>
<td>2019-05-27T12:27:50.390Z</td>
<td>2019-05-27T12:27:58.586Z</td>
<td>false</td>
<td>Allow</td>
<td>Information</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
<td>IPAddress: 185.254.120.27<br> Port: 29411</td>
</tr>
<tr>
<td>1f9d3d71-5ec2-b58f-e3a6-f575a525b3d5</td>
<td>ET POLICY RDP connection confirm</td>
<td>2019-05-27T12:27:50.390Z</td>
<td>2019-05-27T12:27:54.841Z</td>
<td>false</td>
<td>Allow</td>
<td>Information</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
<td>IPAddress: 185.254.120.27<br> Port: 29411</td>
</tr>
</tbody>
</table>
<p> </p>
</div>
</div>
<div class="cl-preview-section">
<h3 id="get-alarm-events">4. Get alarm events</h3>
</div>
<div class="cl-preview-section"><hr></div>
<div class="cl-preview-section">
<p>Retrieves events associated with an alarm.</p>
</div>
<div class="cl-preview-section">
<h5 id="base-command-3">Base Command</h5>
</div>
<div class="cl-preview-section">
<p><code>alienvault-get-events-by-alarm</code></p>
</div>
<div class="cl-preview-section">
<h5 id="input-3">Input</h5>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table style="width: 749px;">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 538px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">alarm_id</td>
<td style="width: 538px;">Alarm ID to get events for. Can be obtained by running the<span> </span><code>alienvault-search-alarms</code><span> </span>command.</td>
<td style="width: 71px;">Required</td>
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
<th style="width: 358px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 307px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 358px;">AlienVault.Event.Category</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Event category.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Source.IPAddress</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Source IP address.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Source.Port</td>
<td style="width: 75px;">Number</td>
<td style="width: 307px;">Source port.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Destination.IPAddress</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Destination IP address.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Destination.Port</td>
<td style="width: 75px;">Number</td>
<td style="width: 307px;">Destination port.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Severity</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Event severity.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.OccurredTime</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Time the event occurred.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.ReceivedTime</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Time the event was received.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.AccessControlOutcome</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Access control outcome.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Suppressed</td>
<td style="width: 75px;">Bool</td>
<td style="width: 307px;">Whether the event is suppressed.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.ID</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Event ID.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Name</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Event name.</td>
</tr>
<tr>
<td style="width: 358px;">AlienVault.Event.Subcategory</td>
<td style="width: 75px;">String</td>
<td style="width: 307px;">Event subcategory.</td>
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
<pre>!alienvault-get-events-by-alarm alarm_id=3194f0f5-0350-7a09-87b2-8fb20b963ed8
</pre>
</div>
<div class="cl-preview-section">
<h5 id="context-example-3">Context Example</h5>
</div>
<div class="cl-preview-section">
<pre>{
    "AlienVault.Event": [
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:46.071Z", 
            "ReceivedTime": "2019-05-15T12:40:46.076Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 50243
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "b36a0259-6203-ecfc-5023-aa198c1e4329", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:48.740Z", 
            "ReceivedTime": "2019-05-15T12:40:48.745Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 50243
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "eab1d04d-4251-44a4-6cf8-0b1ad7f23c36", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:51.041Z", 
            "ReceivedTime": "2019-05-15T12:40:51.048Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 53013
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "1a0f4f1a-c855-2808-f758-127e5578bda9", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:51.041Z", 
            "ReceivedTime": "2019-05-15T12:40:51.049Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 53013
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "4c6d5d9d-a5f8-2d24-0176-060f4139e5a0", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:55.936Z", 
            "ReceivedTime": "2019-05-15T12:40:55.940Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 54739
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "a14ef1a1-2617-3b85-02dc-8c5531b96e5f", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:55.936Z", 
            "ReceivedTime": "2019-05-15T12:40:55.943Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 54739
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "36233284-0aea-14cf-a90f-91f8c3952056", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:55.936Z", 
            "ReceivedTime": "2019-05-15T12:40:55.947Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 54739
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "551c58fd-0f22-e3a8-5478-056444759f5d", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:03.405Z", 
            "ReceivedTime": "2019-05-15T12:41:03.414Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 58090
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "9c019302-7f60-3c33-f725-dd12c9bdb97a", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:10.803Z", 
            "ReceivedTime": "2019-05-15T12:41:10.809Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 1969
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "7f7011b9-b57e-c46e-3e95-5e86e51832e0", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:10.803Z", 
            "ReceivedTime": "2019-05-15T12:41:10.814Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 1969
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "6dddab25-f3e2-c293-afd4-84081e5a41ff", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:10.803Z", 
            "ReceivedTime": "2019-05-15T12:41:10.815Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 1969
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "211627df-ec2e-52c4-ff76-dc103951d340", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:10.803Z", 
            "ReceivedTime": "2019-05-15T12:41:10.815Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 1969
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "52bf99f5-1f79-e04e-9fad-1b423a644e89", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:18.007Z", 
            "ReceivedTime": "2019-05-15T12:41:18.014Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 5213
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "6553b62f-d1db-2318-7e9d-4ae5f0de5d41", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:20.525Z", 
            "ReceivedTime": "2019-05-15T12:41:24.554Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 5213
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "1e635a85-d8a5-66cc-abf4-9067db82955a", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:31.837Z", 
            "ReceivedTime": "2019-05-15T12:41:31.840Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 10772
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "124314f7-bcb2-c706-ada3-50a57ef2d8b3", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:31.837Z", 
            "ReceivedTime": "2019-05-15T12:41:31.845Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 10772
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "35cafad8-2e36-9bef-45ce-d37f919bb3ac", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:37.221Z", 
            "ReceivedTime": "2019-05-15T12:41:37.224Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 13554
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "ea2b003a-44b7-4b17-9438-993a0a5fe7c5", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:41.942Z", 
            "ReceivedTime": "2019-05-15T12:41:41.945Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 13554
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "318ffee9-dfd5-4ef9-ded0-b8fbf7fd0402", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:46.766Z", 
            "ReceivedTime": "2019-05-15T12:41:50.283Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 17267
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "22a04ec4-cbbd-49c2-dcee-4329e97dbcd3", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:46.766Z", 
            "ReceivedTime": "2019-05-15T12:41:52.654Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 17267
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "d2d62bbd-5db2-823c-28a1-a1acf21af7fc", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:46.766Z", 
            "ReceivedTime": "2019-05-15T12:41:54.125Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 17267
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "6042e4a2-4982-7016-bbd3-5506030d2dc4", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:42:06.005Z", 
            "ReceivedTime": "2019-05-15T12:42:06.010Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 25757
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "b3beeb7e-9ee2-f417-3cc8-228bd5e9a18f", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:46.071Z", 
            "ReceivedTime": "2019-05-15T12:40:46.079Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 50243
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "720d9a9d-92cc-45b1-bbb3-604fb053282b", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:46.071Z", 
            "ReceivedTime": "2019-05-15T12:40:46.080Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 50243
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "79549d86-40df-0032-e3cf-cf6d1cd86ecf", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:46.071Z", 
            "ReceivedTime": "2019-05-15T12:40:46.081Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 50243
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "220a996a-a64c-a7ea-14b6-3aca57681722", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:53.604Z", 
            "ReceivedTime": "2019-05-15T12:40:53.608Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 53013
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "bb2107e0-ff7e-f3ee-d7ec-f7bb32a6f795", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:55.936Z", 
            "ReceivedTime": "2019-05-15T12:40:55.945Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 54739
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "a21fd0a8-b2ae-fbae-ef22-f23d30a30099", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:03.405Z", 
            "ReceivedTime": "2019-05-15T12:41:03.409Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 58090
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "249827bf-e31d-79d7-8725-cee8ffc7037f", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:03.405Z", 
            "ReceivedTime": "2019-05-15T12:41:03.413Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 58090
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "ed0c4580-69a6-d462-2205-d06fc436ecde", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:13.242Z", 
            "ReceivedTime": "2019-05-15T12:41:13.246Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 1969
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "7a3ceb92-9ea7-2387-39b8-deddfd1000ec", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:18.007Z", 
            "ReceivedTime": "2019-05-15T12:41:18.013Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 5213
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "42b0c4dc-c260-0cfd-6b44-e99716f8a736", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:18.007Z", 
            "ReceivedTime": "2019-05-15T12:41:18.016Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 5213
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "69be0a19-9b9b-f226-02fd-cb694bb24197", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:22.874Z", 
            "ReceivedTime": "2019-05-15T12:41:26.070Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 7372
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "47bdc7ee-9679-714c-a5b2-b9bbbb68cc4a", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:31.837Z", 
            "ReceivedTime": "2019-05-15T12:41:31.848Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 10772
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "be9f159f-1225-3461-d863-c55d46517b81", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:34.816Z", 
            "ReceivedTime": "2019-05-15T12:41:34.821Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 10772
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "8a6639c8-db0e-3077-aa0d-764c83726590", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:56.359Z", 
            "ReceivedTime": "2019-05-15T12:41:56.364Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 19868
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "f65faf00-d0d8-6059-7784-20407a8a1231", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:42:06.005Z", 
            "ReceivedTime": "2019-05-15T12:42:06.013Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 25757
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "21684ce5-55dd-8017-71b5-46369ae14e17", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:42:10.743Z", 
            "ReceivedTime": "2019-05-15T12:42:10.744Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 25757
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "b56d2afd-a5e3-aab8-5509-0a9dcabdedb0", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:51.041Z", 
            "ReceivedTime": "2019-05-15T12:40:51.046Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 53013
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "2ce1d100-de85-1ef0-0673-8bfae574c1ce", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:40:51.041Z", 
            "ReceivedTime": "2019-05-15T12:40:51.044Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 53013
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "09550d30-e275-6bfe-fdf3-1d01b43ba6ef", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:03.405Z", 
            "ReceivedTime": "2019-05-15T12:41:03.410Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 58090
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "15c4ff5e-a9f8-1a3c-2285-5100ecbfdd40", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:08.098Z", 
            "ReceivedTime": "2019-05-15T12:41:08.100Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 58090
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "d9736b73-d8ad-6c39-1df5-49a2f3784337", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:18.007Z", 
            "ReceivedTime": "2019-05-15T12:41:18.012Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 5213
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "93e98ec6-d6b6-cca9-255e-2944ce5fad4c", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:31.837Z", 
            "ReceivedTime": "2019-05-15T12:41:31.843Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 10772
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "6b526907-c9d6-eabe-f2d5-9eb783b28715", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:49.216Z", 
            "ReceivedTime": "2019-05-15T12:41:50.287Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 17267
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "b5312239-5c45-d036-66fc-1c1fbb3d7260", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:51.690Z", 
            "ReceivedTime": "2019-05-15T12:41:51.693Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 19868
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "1cfb337f-9725-7c44-34dc-4f18172c3f6c", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:46.766Z", 
            "ReceivedTime": "2019-05-15T12:41:54.807Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 17267
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "c2ef5423-76b1-a0a0-0a0b-b4443507d4a5", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:41:51.690Z", 
            "ReceivedTime": "2019-05-15T12:41:54.808Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 19868
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "463049df-c917-821a-9d43-d1d813394eac", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:42:06.005Z", 
            "ReceivedTime": "2019-05-15T12:42:06.010Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 25757
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "94d8203b-6db5-702c-3e7f-d2601f888ea3", 
            "Severity": "3"
        }, 
        {
            "Category": "Policy Violation", 
            "Subcategory": "Remote access application", 
            "Name": "ET POLICY MS Remote Desktop Administrator Login Request", 
            "OccurredTime": "2019-05-15T12:42:06.005Z", 
            "ReceivedTime": "2019-05-15T12:42:06.011Z", 
            "Destination": {
                "IPAddress": "192.168.1.8", 
                "Port": 3389
            }, 
            "Source": {
                "IPAddress": "85.93.20.34", 
                "Port": 25757
            }, 
            "AccessControlOutcome": "Allow", 
            "Suppressed": false, 
            "ID": "8868f432-89b1-2740-3007-7dadc57700e4", 
            "Severity": "3"
        }
    ]
}
</pre>
</div>
<div class="cl-preview-section">
<h5 id="human-readable-output-3">Human Readable Output</h5>
</div>
<div class="cl-preview-section">
<h3 id="events-of-alarm-3194f0f5-0350-7a09-87b2-8fb20b963ed8">Events of Alarm 3194f0f5-0350-7a09-87b2-8fb20b963ed8:</h3>
</div>
<div class="cl-preview-section">
<div class="table-wrapper">
<table border="2">
<thead>
<tr>
<th>ID</th>
<th>Name</th>
<th>OccurredTime</th>
<th>ReceivedTime</th>
<th>Suppressed</th>
<th>AccessControlOutcome</th>
<th>Category</th>
<th>Severity</th>
<th>Subcategory</th>
<th>Source</th>
<th>Destination</th>
</tr>
</thead>
<tbody>
<tr>
<td>b36a0259-6203-ecfc-5023-aa198c1e4329</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:46.071Z</td>
<td>2019-05-15T12:40:46.076Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 50243</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>eab1d04d-4251-44a4-6cf8-0b1ad7f23c36</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:48.740Z</td>
<td>2019-05-15T12:40:48.745Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 50243</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>1a0f4f1a-c855-2808-f758-127e5578bda9</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:51.041Z</td>
<td>2019-05-15T12:40:51.048Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 53013</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>4c6d5d9d-a5f8-2d24-0176-060f4139e5a0</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:51.041Z</td>
<td>2019-05-15T12:40:51.049Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 53013</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>a14ef1a1-2617-3b85-02dc-8c5531b96e5f</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:55.936Z</td>
<td>2019-05-15T12:40:55.940Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 54739</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>36233284-0aea-14cf-a90f-91f8c3952056</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:55.936Z</td>
<td>2019-05-15T12:40:55.943Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 54739</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>551c58fd-0f22-e3a8-5478-056444759f5d</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:55.936Z</td>
<td>2019-05-15T12:40:55.947Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 54739</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>9c019302-7f60-3c33-f725-dd12c9bdb97a</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:03.405Z</td>
<td>2019-05-15T12:41:03.414Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 58090</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>7f7011b9-b57e-c46e-3e95-5e86e51832e0</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:10.803Z</td>
<td>2019-05-15T12:41:10.809Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 1969</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>6dddab25-f3e2-c293-afd4-84081e5a41ff</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:10.803Z</td>
<td>2019-05-15T12:41:10.814Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 1969</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>211627df-ec2e-52c4-ff76-dc103951d340</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:10.803Z</td>
<td>2019-05-15T12:41:10.815Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 1969</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>52bf99f5-1f79-e04e-9fad-1b423a644e89</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:10.803Z</td>
<td>2019-05-15T12:41:10.815Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 1969</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>6553b62f-d1db-2318-7e9d-4ae5f0de5d41</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:18.007Z</td>
<td>2019-05-15T12:41:18.014Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 5213</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>1e635a85-d8a5-66cc-abf4-9067db82955a</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:20.525Z</td>
<td>2019-05-15T12:41:24.554Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 5213</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>124314f7-bcb2-c706-ada3-50a57ef2d8b3</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:31.837Z</td>
<td>2019-05-15T12:41:31.840Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 10772</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>35cafad8-2e36-9bef-45ce-d37f919bb3ac</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:31.837Z</td>
<td>2019-05-15T12:41:31.845Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 10772</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>ea2b003a-44b7-4b17-9438-993a0a5fe7c5</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:37.221Z</td>
<td>2019-05-15T12:41:37.224Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 13554</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>318ffee9-dfd5-4ef9-ded0-b8fbf7fd0402</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:41.942Z</td>
<td>2019-05-15T12:41:41.945Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 13554</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>22a04ec4-cbbd-49c2-dcee-4329e97dbcd3</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:46.766Z</td>
<td>2019-05-15T12:41:50.283Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 17267</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>d2d62bbd-5db2-823c-28a1-a1acf21af7fc</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:46.766Z</td>
<td>2019-05-15T12:41:52.654Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 17267</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>6042e4a2-4982-7016-bbd3-5506030d2dc4</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:46.766Z</td>
<td>2019-05-15T12:41:54.125Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 17267</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>b3beeb7e-9ee2-f417-3cc8-228bd5e9a18f</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:42:06.005Z</td>
<td>2019-05-15T12:42:06.010Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 25757</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>720d9a9d-92cc-45b1-bbb3-604fb053282b</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:46.071Z</td>
<td>2019-05-15T12:40:46.079Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 50243</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>79549d86-40df-0032-e3cf-cf6d1cd86ecf</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:46.071Z</td>
<td>2019-05-15T12:40:46.080Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 50243</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>220a996a-a64c-a7ea-14b6-3aca57681722</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:46.071Z</td>
<td>2019-05-15T12:40:46.081Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 50243</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>bb2107e0-ff7e-f3ee-d7ec-f7bb32a6f795</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:53.604Z</td>
<td>2019-05-15T12:40:53.608Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 53013</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>a21fd0a8-b2ae-fbae-ef22-f23d30a30099</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:55.936Z</td>
<td>2019-05-15T12:40:55.945Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 54739</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>249827bf-e31d-79d7-8725-cee8ffc7037f</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:03.405Z</td>
<td>2019-05-15T12:41:03.409Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 58090</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>ed0c4580-69a6-d462-2205-d06fc436ecde</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:03.405Z</td>
<td>2019-05-15T12:41:03.413Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 58090</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>7a3ceb92-9ea7-2387-39b8-deddfd1000ec</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:13.242Z</td>
<td>2019-05-15T12:41:13.246Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 1969</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>42b0c4dc-c260-0cfd-6b44-e99716f8a736</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:18.007Z</td>
<td>2019-05-15T12:41:18.013Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 5213</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>69be0a19-9b9b-f226-02fd-cb694bb24197</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:18.007Z</td>
<td>2019-05-15T12:41:18.016Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 5213</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>47bdc7ee-9679-714c-a5b2-b9bbbb68cc4a</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:22.874Z</td>
<td>2019-05-15T12:41:26.070Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 7372</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>be9f159f-1225-3461-d863-c55d46517b81</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:31.837Z</td>
<td>2019-05-15T12:41:31.848Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 10772</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>8a6639c8-db0e-3077-aa0d-764c83726590</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:34.816Z</td>
<td>2019-05-15T12:41:34.821Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 10772</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>f65faf00-d0d8-6059-7784-20407a8a1231</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:56.359Z</td>
<td>2019-05-15T12:41:56.364Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 19868</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>21684ce5-55dd-8017-71b5-46369ae14e17</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:42:06.005Z</td>
<td>2019-05-15T12:42:06.013Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 25757</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>b56d2afd-a5e3-aab8-5509-0a9dcabdedb0</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:42:10.743Z</td>
<td>2019-05-15T12:42:10.744Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 25757</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>2ce1d100-de85-1ef0-0673-8bfae574c1ce</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:51.041Z</td>
<td>2019-05-15T12:40:51.046Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 53013</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>09550d30-e275-6bfe-fdf3-1d01b43ba6ef</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:40:51.041Z</td>
<td>2019-05-15T12:40:51.044Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 53013</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>15c4ff5e-a9f8-1a3c-2285-5100ecbfdd40</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:03.405Z</td>
<td>2019-05-15T12:41:03.410Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 58090</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>d9736b73-d8ad-6c39-1df5-49a2f3784337</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:08.098Z</td>
<td>2019-05-15T12:41:08.100Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 58090</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>93e98ec6-d6b6-cca9-255e-2944ce5fad4c</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:18.007Z</td>
<td>2019-05-15T12:41:18.012Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 5213</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>6b526907-c9d6-eabe-f2d5-9eb783b28715</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:31.837Z</td>
<td>2019-05-15T12:41:31.843Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 10772</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>b5312239-5c45-d036-66fc-1c1fbb3d7260</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:49.216Z</td>
<td>2019-05-15T12:41:50.287Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 17267</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>1cfb337f-9725-7c44-34dc-4f18172c3f6c</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:51.690Z</td>
<td>2019-05-15T12:41:51.693Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 19868</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>c2ef5423-76b1-a0a0-0a0b-b4443507d4a5</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:46.766Z</td>
<td>2019-05-15T12:41:54.807Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 17267</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>463049df-c917-821a-9d43-d1d813394eac</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:41:51.690Z</td>
<td>2019-05-15T12:41:54.808Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 19868</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>94d8203b-6db5-702c-3e7f-d2601f888ea3</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:42:06.005Z</td>
<td>2019-05-15T12:42:06.010Z</td>
<td>false</td>
<td>Allow</td>
<td>Policy Violation</td>
<td>3</td>
<td>Remote access application</td>
<td>IPAddress: 85.93.20.34<br> Port: 25757</td>
<td>IPAddress: 192.168.1.8<br> Port: 3389</td>
</tr>
<tr>
<td>8868f432-89b1-2740-3007-7dadc57700e4</td>
<td>ET POLICY MS Remote Desktop Administrator Login Request</td>
<td>2019-05-15T12:42:06.005Z</td>
<td>2019-05-15T12:42:06.011Z</td>
<td>false</td>
<td>Allow</td>
</tr>
</tbody>
</table>
</div>
</div>