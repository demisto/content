<!-- HTML_DOC -->
<p>Use the FireEye HX integration to access information about endpoints, acquisitions, alerts, indicators, and containment.</p>
<p> </p>
<h2>Use Cases</h2>
<p>FireEye HX integration can be used for the following use cases:</p>
<h3>Monitor FireEye HX alerts</h3>
<p>Simply use the ‘fetch-incidents’ option in the integration settings (as explained in ‘Fetched incidents data’ section above) for a continues pull of alerts to the Cortex XSOAR platform.</p>
<h3>Search Hosts</h3>
<p>Search all hosts or a subset of hosts for a specific file or indicator.<br>The produces a list of hosts with a list of results for each host.</p>
<p>Find more information on ‘Additional Information’ section below.</p>
<h3>Apply or remove containment from hosts</h3>
<p>Containment prevents further compromise of a host system and its components by restricting the hostʼs ability to communicate.</p>
<h3>Host containment</h3>
<p>To request that a specific host be contained so that it no longer has access to other systems, run the <code>fireeye-host-containment</code> command and pass either the host name or its agent ID, for example, <code>fireeye-host-containment hostname=“DESKTOP-HK8OI62”</code></p>
<p>Notes:</p>
<ul>
<li>Some hosts are ineligible for containment.</li>
<li>The time it takes to contain a host varies, based on factors such as agent connectivity, network traffic, and other jobs running in your environment .</li>
<li>You cannot contain a host if the agent package for that host is not available on the FireEye HX Series appliance.</li>
</ul>
<h3>Host containment removal</h3>
<p>To release a specific host from containment, run the <code>fireeye-cancel-containment</code> command and pass either the host name or its agent ID, for example <code>fireeye-cancel-containment agentId=”uGvn34ZkM3bfSf1nOT”</code></p>
<p> </p>
<h2>Prerequisites</h2>
<p>Make sure you have a valid <strong>user account</strong> on the FireEye HX Series appliance associated with the <em>api_admin</em> or <em>api_analyst</em> role.</p>
<p>For more information about setting up user accounts on the FireEye HX Series appliance, see the FireEye HX Series System Administration Guide.</p>
<p> </p>
<h2>Configure FireEye HX on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for FireEye HX.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: Exchange server URL.</li>
<li>
<strong>Credentials: </strong>Your personal account username.</li>
<li>
<strong>Password</strong>: Your personal account password.</li>
<li>
<strong>Version</strong>: The API version. Default is 3.</li>
<li>
<strong>Fetched incidents data</strong>: The integration imports FireEye HX alerts as Cortex XSOAR incidents<strong>. </strong>The first pull of incidents will fetch the last 100 alerts on FireEye HX.</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<p> </p>
<h2>Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_4940381161531225583805">Contain a host: fireeye-hx-host-containment</a></li>
<li><a href="#h_753562077941531225590399">Release host from containment: fireeye-hx-cancel-containment</a></li>
<li><a href="#h_3659112741821531225598795">Get alert list: fireeye-hx-get-alerts</a></li>
<li><a href="#h_4996266442681531225609912">Get alert details: fireeye-hx-get-alert</a></li>
<li><a href="#h_2089802313531531225618306">Suppress an alert: fireeye-hx-suppress-alert</a></li>
<li><a href="#h_6259227744371531225635704">Get indicator list: fireeye-get-indicators</a></li>
<li><a href="#h_3177394125201531225647008">Get indicator information: fireeye-get-indicator</a></li>
<li><a href="#h_1285237886021531225659162">Find hostname correlated with agent-ID or agent-ID correlated with hostname: fireeye-get-host-information</a></li>
<li><a href="#h_9238521966831531225671914">Acquire a file: fireeye-file-acquisition</a></li>
<li><a href="#h_8039477917631531225683376">Delete a file acquisition: fireeye-delete-file-acquisition</a></li>
<li><a href="#h_284510558421531225696011">Acquire data: fireeye-data-acquisition</a></li>
<li><a href="#h_7751566479201531225716697">Delete data acquisition: fireeye-delete-data-acquisition</a></li>
</ol>
<p> </p>
<h3 id="h_4940381161531225583805">1. Contain a host</h3>
<hr>
<p>Contains a specific host, so it cannot access to other systems.</p>
<h5>Command Limitations</h5>
<ul>
<li>Some hosts cannot be contained.</li>
<li>The time it takes to contain a host varies, based on factors such as agent connectivity, network traffic, and other jobs running in your environment.</li>
<li>You can only contain a host if the agent package for that host is available on the FireEye HX Series appliance.</li>
</ul>
<h5>Base Command</h5>
<p><code>fireeye-hx-host-containment</code></p>
<h5>Input</h5>
<p>All arguments are optional, but you need to specify at least one to run this command.</p>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">hostName</td>
<td style="width: 499px;">The host name to be contained. If the <em>hostName</em> is not specified, the <em>agentId</em> is required.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">agentId</td>
<td style="width: 499px;">The agent ID running on the host to be contained. If the <em>agentId</em> is not specified, the <em>hostName</em> is required.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Hosts._id</td>
<td>FireEye HX Agent ID</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.agent_version</td>
<td>The agent version</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.excluded_from_containment</td>
<td>Determines whether the host is excluded from containment</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_missing_software</td>
<td>Boolean value to indicate for containment missing software</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_queued</td>
<td>Determines whether the host is queued for containment</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_state</td>
<td>The containment state of the host. Possible values normal</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.alerting_conditions</td>
<td>The number of conditions that have alerted the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.alerts</td>
<td>Total number of alerts, including exploit-detection alerts</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.exploit_blocks</td>
<td>The number of blocked exploits on the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.malware_alerts</td>
<td>The number of malware alerts associated with the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.hostname</td>
<td>Host name</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.domain</td>
<td>Domain name</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.timezone</td>
<td>Host time zone</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.primary_ip_address</td>
<td>Host IP address</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_poll_timestamp</td>
<td>The timestamp of the last system poll performed on the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.initial_agent_checkin</td>
<td>Timestamp of the initial agent check-in</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_alert_timestamp</td>
<td>The time stamp of the last alert for the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_exploit_block_timestamp</td>
<td>Time when the last exploit was blocked on the host. The value is null if no exploits were blocked</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.product_name</td>
<td>Operating system</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.bitness</td>
<td>OS bitness (32 or 64)</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.platform</td>
<td>
<p>Family of operating systems</p>
<ul>
<li>win</li>
<li>osx</li>
<li>linux</li>
</ul>
</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.primary_mac</td>
<td>The host MAC address</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Examples</h5>
<p><code>!fireeye-hx-host-containment agentId=”uGvn34ZkM3bfSf1nOT”</code></p>
<p><code>!fireeye-hx-host-containment hostname=“DESKTOP-HK8OI62”</code></p>
<h5>Context Example</h5>
<pre> {  
   "FireEyeHX":{  
      "Hosts":{  
         "last_alert":{  
            "url":"/hx/api/v3/alerts/5",
            "_id":5
         },
         "domain":"DEMISTO",
         "last_exploit_block_timestamp":null,
         "containment_state":"contain",
         "timezone":"Eastern Daylight Time",
         "gmt_offset_seconds":-14400,
         "initial_agent_checkin":"2018-03-26T14:21:31.273Z",
         "stats":{  
            "alerting_conditions":1,
            "exploit_alerts":0,
            "acqs":11,
            "malware_false_positive_alerts":0,
            "alerts":1,
            "exploit_blocks":0,
            "malware_cleaned_count":0,
            "malware_alerts":0,
            "malware_quarantined_count":0
         },
         "primary_mac":"XX-XX-XX-XX-XX-XX",
         "hostname":"DESKTOP-XXX",
         "primary_ip_address":"^^^XX.XX.XX.XX^^^",
         "last_audit_timestamp":"2018-05-03T13:59:23.000Z",
         "last_alert_timestamp":"2018-04-16T08:59:51.693+00:00",
         "containment_queued":false,
         "sysinfo":{  
            "url":"/hx/api/v3/hosts/uGvnGVpZkDSFySf2ZOiT/sysinfo"
         },
         "last_exploit_block":null,
         "reported_clone":false,
         "url":"/hx/api/v3/hosts/uGvnGVpZkeySf2ZOiT",
         "excluded_from_containment":false,
         "last_poll_timestamp":"2018-05-03T14:01:22.000Z",
         "last_poll_ip":"^^^XX.XX.XX.XX^^^",
         "containment_missing_software":false,
         "_id":" uGvnGVpZkDSFySf2ZOiT ",
         "os":{  
            "kernel_version":null,
            "platform":"win",
            "patch_level":null,
            "bitness":"64-bit",
            "product_name":"Windows 10 Enterprise Evaluation"
         },
         "agent_version":"26.21.10"
      }
   }
}</pre>
<p> </p>
<h3 id="h_753562077941531225590399">2. Release host from containment</h3>
<hr>
<p>Releases a specific host from containment.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-cancel-containment</code></p>
<h5>Input</h5>
<p>All arguments are optional, but you need to specify at least one to run this command.</p>
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
<td>hostName</td>
<td>The host name to be contained. If the <em>hostName</em> is not specified, the <em>agentId</em> is required.</td>
<td>Optional</td>
</tr>
<tr>
<td>agentId</td>
<td>The agent ID running on the host to be contained. If the <em>agentId</em> is not specified, the <em>hostName</em> is required.</td>
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
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Hosts._id</td>
<td>FireEye HX Agent ID</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.agent_version</td>
<td>The agent version</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.excluded_from_containment</td>
<td>Determines whether the host is excluded from containment</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_missing_software</td>
<td>Boolean value to indicate for containment missing software</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_queued</td>
<td>Determines whether the host is queued for containment</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_state</td>
<td>The containment state of the host. Possible values normal</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.alerting_conditions</td>
<td>The number of conditions that have alerted the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.alerts</td>
<td>Total number of alerts, including exploit-detection alerts</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.exploit_blocks</td>
<td>The number of blocked exploits on the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.malware_alerts</td>
<td>The number of malware alerts associated with the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.hostname</td>
<td>Host name</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.domain</td>
<td>Domain name</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.timezone</td>
<td>Host time zone</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.primary_ip_address</td>
<td>Host IP address</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_poll_timestamp</td>
<td>The timestamp of the last system poll performed on the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.initial_agent_checkin</td>
<td>Timestamp of the initial agent check-in</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_alert_timestamp</td>
<td>The time stamp of the last alert for the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_exploit_block_timestamp</td>
<td>Time when the last exploit was blocked on the host. The value is null if no exploits were blocked</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.product_name</td>
<td>Operating system</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.bitness</td>
<td>OS bitness (32 or 64)</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.platform</td>
<td>
<p>Family of operating systems</p>
<ul>
<li>win</li>
<li>osx</li>
<li>linux</li>
</ul>
</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.primary_mac</td>
<td>The host MAC address</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Examples</h5>
<p><code>!fireeye-hx-cancel-containment agentId=”uGvn34ZkM3bfSf1nOT”</code></p>
<p><code>!fireeye-hx-cancel-containment hostname=“DESKTOP-HK8OI62”</code></p>
<h5>Context Example</h5>
<pre>{
    "FireEyeHX": {
        "Hosts": {
            "last_alert": {
                "url": "/hx/api/v3/alerts/5", 
                "_id": 5
            }, 
            "domain": "DEMISTO", 
            "last_exploit_block_timestamp": null, 
            "containment_state": "normal", 
            "timezone": "Eastern Daylight Time", 
            "gmt_offset_seconds": -14400, 
            "initial_agent_checkin": "2018-03-26T14:21:31.273Z", 
            "stats": {
                "alerting_conditions": 1, 
                "exploit_alerts": 0, 
                "acqs": 11, 
                "malware_false_positive_alerts": 0, 
                "alerts": 1, 
                "exploit_blocks": 0, 
                "malware_cleaned_count": 0, 
                "malware_alerts": 0, 
                "malware_quarantined_count": 0
            }, 
            "primary_mac": "XX-XX-XX-XX-XX-XX", 
            "hostname": "DESKTOP-XXX", 
            "primary_ip_address": "^^^XX.XX.XX.XX^^^", 
            "last_audit_timestamp": "2018-05-03T13:59:23.000Z", 
            "last_alert_timestamp": "2018-04-16T08:59:51.693+00:00", 
            "containment_queued": false, 
            "sysinfo": {
                "url": "/hx/api/v3/hosts/uGvnGVpZkDSFySf2ZOiT/sysinfo"
            }, 
            "last_exploit_block": null, 
            "reported_clone": false, 
            "url": "/hx/api/v3/hosts/uGvnGVpZkeySf2ZOiT", 
            "excluded_from_containment": false, 
            "last_poll_timestamp": "2018-05-03T14:01:22.000Z", 
            "last_poll_ip": "^^^XX.XX.XX.XX^^^", 
            "containment_missing_software": false, 
            "_id": " uGvnGVpZkDSFySf2ZOiT ", 
            "os": {
                "kernel_version": null, 
                "platform": "win", 
                "patch_level": null, 
                "bitness": "64-bit", 
                "product_name": "Windows 10 Enterprise Evaluation"
            }, 
            "agent_version": "26.21.10"
        }
    }
 }
 </pre>
<p> </p>
<h3 id="h_3659112741821531225598795">3. Get alert list</h3>
<hr>
<p>Gets a list of alerts according to specified filters.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-get-alerts</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">hasShareMode</td>
<td style="width: 493px;">Identifies which alerts result from indicators with the specified share mode</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">resolution</td>
<td style="width: 493px;">Sorts the results by the specified field</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">agentId</td>
<td style="width: 493px;">Filter by the agent ID</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">conditionId</td>
<td style="width: 493px;">Filter by condition ID</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">eventAt</td>
<td style="width: 493px;">Filter event occurred time (ISO-8601 timestamp)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">alertId</td>
<td style="width: 493px;">Filter by alert ID</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">matchedAt</td>
<td style="width: 493px;">Filter by match detection time (ISO-8601 timestamp)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">minId</td>
<td style="width: 493px;">Filter that returns only records with an <em>AlertId</em> field value great than the <em>minId</em> value</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">reportedAt</td>
<td style="width: 493px;">Filter by reported time (ISO-8601 timestamp)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">IOCsource</td>
<td style="width: 493px;">Source of alert (indicator of compromise)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">EXDsource</td>
<td style="width: 493px;">Source of alert (exploit detection)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">MALsource</td>
<td style="width: 493px;">Source of alert (malware alert)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">minId</td>
<td style="width: 493px;">Return only records with an ID greater than <em>minId</em>
</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">limit</td>
<td style="width: 493px;">Specifies the number of results to return</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">sort</td>
<td style="width: 493px;">Sorts the results by the specified field in ascending order</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">sortOrder</td>
<td style="width: 493px;">The sort order for the results</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Alerts._id</td>
<td>FireEye alert ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.agent._id</td>
<td>FireEye agent ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.agent.containment_state</td>
<td>Host containment state</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.condition._id</td>
<td>The condition unique ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.event_at</td>
<td>Time when the event occured</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_at</td>
<td>Time when the event was matched</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.reported_at</td>
<td>Time when the event was reported</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.source</td>
<td>Source of alert</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts._id</td>
<td>Source alert ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts.appliance_id</td>
<td>Appliance ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts.meta</td>
<td>Source alert meta</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts.indicator_id</td>
<td>Indicator ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.resolution</td>
<td>Alert resolution</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.event_type</td>
<td>Event type</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!fireeye-hx-get-alerts limit="10" sort="id" sortOrder="descending"</code></p>
<h5>Raw Output</h5>
<pre> {
    "FireEyeHX": {
        "Alerts": {
            "_id": 5,
            "agent": {
                "_id": "uGvnGVp…4bKeySf2ZOiT",
                "containment_state": "normal",
                "url": "/hx/api/v3/hosts/ uGvnGVp…4bKeySf2ZOiT "
            },
            "condition": {
                "_id": "CSaoSZFw…JNPW0mw==",
                "url": "/hx/api/v3/conditions/ CSaoSZFw…JNPW0mw =="
            },
            "event_at": "2018-04-16T08:59:02.061Z",
            "event_id": 7885715,
            "event_type": "fileWriteEvent",
            "event_values": {
                "fileWriteEvent/closed": 1,
                "fileWriteEvent/dataAtLowestOffset": "dGVzdGVzdA==",
                "fileWriteEvent/devicePath": "\\Device\\HarddiskVolume2",
                "fileWriteEvent/drive": "C",
                "fileWriteEvent/fileExtension": "txt",
                "fileWriteEvent/fileName": "testest - Copy.txt",
                "fileWriteEvent/filePath": "Users\\demistodev\\Documents",
                "fileWriteEvent/fullPath": "C:\\Users\\User\\Documents\\testest - Copy.txt",
                "fileWriteEvent/lowestFileOffsetSeen": 0,
                "fileWriteEvent/md5": " c3add7b947…817c79f7b7bd ",
                "fileWriteEvent/numBytesSeenWritten": 7,
                "fileWriteEvent/pid": 3308,
                "fileWriteEvent/process": "explorer.exe",
                "fileWriteEvent/processPath": "C:\\Windows",
                "fileWriteEvent/size": 7,
                "fileWriteEvent/textAtLowestOffset": "testest",
                "fileWriteEvent/timestamp": "2018-04-16T08:59:02.061Z",
                "fileWriteEvent/username": "DEMISTO\\User",
                "fileWriteEvent/writes": 1
            },
            "is_false_positive": null,
            "matched_at": "2018-04-16T08:59:10.000Z",
            "matched_source_alerts": [],
            "reported_at": "2018-04-16T08:59:51.693Z",
            "resolution": "ALERT",
            "source": "IOC",
            "url": "/hx/api/v3/alerts/5"
        }
    },
    "File": [
        {
            "Extension": "txt",
            "MD5": "c3add7b947…817c79f7b7bd",
            "Name": "testest - Copy.txt",
            "Path": "C:\\Users\\User\\Documents\\testest - Copy.txt"
        }
    ],
    "IP": [],	
    "RrgistryKey": []
}
</pre>
<p> </p>
<h3 id="h_4996266442681531225609912">4. Get alert details</h3>
<hr>
<p>Retrieves the details of a specific alert.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-get-alert</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
<tr>
<td>alertId</td>
<td>ID of alert to get details of</td>
<td>Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Alerts._id</td>
<td>FireEye alert ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.agent._id</td>
<td>FireEye agent ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.agent.containment_state</td>
<td>Host containment state</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.condition._id</td>
<td>The condition unique ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.event_at</td>
<td>Time when the event occurred</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_at</td>
<td>Time when the event was matched</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.reported_at</td>
<td>Time when the event was reported</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.source</td>
<td>Source of alert</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts._id</td>
<td>Source alert ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts.appliance_id</td>
<td>Appliance ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts.meta</td>
<td>Source alert meta</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.matched_source_alerts.indicator_id</td>
<td>Indicator ID</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.resolution</td>
<td>Alert resolution</td>
</tr>
<tr>
<td>FireEyeHX.Alerts.event_type</td>
<td>Event type</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!fireeye-hx-get-alert alertId=5</code></p>
<h5>Context Example</h5>
<pre> {
    "FireEyeHX": {
        "Alerts": {
            "_id": 5,
            "agent": {
                "_id": "uGvnGVpZkM4bKeySf2ZOiT",
                "containment_state": "normal",
                "url": "/hx/api/v3/hosts/uGvnGVpZkM4bKeySf2ZOiT"
            },
            "condition": {
                "_id": "CSaoSZFwVBtjGJBJNPW0mw==",
                "url": "/hx/api/v3/conditions/CSaoSZFwVBtjGJBJNPW0mw=="
            },
            "event_at": "2018-04-16T08:59:02.061Z",
            "event_id": 7885715,
            "event_type": "fileWriteEvent",
            "event_values": {
                "fileWriteEvent/closed": 1,
                "fileWriteEvent/dataAtLowestOffset": "dGVzdGVzdA==",
                "fileWriteEvent/devicePath": "\\Device\\HarddiskVolume2",
                "fileWriteEvent/drive": "C",
                "fileWriteEvent/fileExtension": "txt",
                "fileWriteEvent/fileName": "testest - Copy.txt",
                "fileWriteEvent/filePath": "Users\\demistodev\\Documents",
                "fileWriteEvent/fullPath": "C:\\Users\\demistodev\\Documents\\testest - Copy.txt",
                "fileWriteEvent/lowestFileOffsetSeen": 0,
                "fileWriteEvent/md5": "c3add7b94781ee70ec7c817c79f7b7bd",
                "fileWriteEvent/numBytesSeenWritten": 7,
                "fileWriteEvent/pid": 3308,
                "fileWriteEvent/process": "explorer.exe",
                "fileWriteEvent/processPath": "C:\\Windows",
                "fileWriteEvent/size": 7,
                "fileWriteEvent/textAtLowestOffset": "testest",
                "fileWriteEvent/timestamp": "2018-04-16T08:59:02.061Z",
                "fileWriteEvent/username": "DEMISTO\\demistodev",
                "fileWriteEvent/writes": 1
            },
            "is_false_positive": null,
            "matched_at": "2018-04-16T08:59:10.000Z",
            "matched_source_alerts": [],
            "reported_at": "2018-04-16T08:59:51.693Z",
            "resolution": "ALERT",
            "source": "IOC",
            "url": "/hx/api/v3/alerts/5"
        }
    }
}
</pre>
<p> </p>
<h3 id="h_2089802313531531225618306">5. Suppress an alert</h3>
<hr>
<p>Suppresses an alert.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-suppress-alert</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 132px;"><strong>Argument Name</strong></td>
<td style="width: 505px;"><strong>Description</strong></td>
<td style="width: 71px;"><strong>Required</strong></td>
</tr>
<tr>
<td style="width: 132px;">alertId</td>
<td style="width: 505px;">ID of alert to suppress (listed in the output of the <code>get-alerts</code> command)</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!fireeye-hx-suppress-alert alertId=2</code></p>
<p> </p>
<p> </p>
<h3 id="h_6259227744371531225635704">6. Get indicator list</h3>
<hr>
<p>Gets a list of indicators.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-get-indicators</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 139px;"><strong>Argument Name</strong></th>
<th style="width: 498px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 139px;">category</td>
<td style="width: 498px;">The indicator category</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">searchTerm</td>
<td style="width: 498px;">The searchTerm can be any name, category, signature, source, or condition value.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">shareMode</td>
<td style="width: 498px;">Determines who can see the indicator. You must belong to the correct authorization group .</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">sort</td>
<td style="width: 498px;">Sorts the results by the specified field in ascending order</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">createdBy</td>
<td style="width: 498px;">Person who created the indicator</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">alerted</td>
<td style="width: 498px;">Whether the indicator resulted in alerts</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 139px;">limit</td>
<td style="width: 498px;">Limit the number of results</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Indicators._id</td>
<td>FireEye unique indicator ID</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.name</td>
<td>The indicator name as displayed in the UI</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.description</td>
<td>Indicator description</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.category.name</td>
<td>Category name</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.created_by</td>
<td>The <em>Created By</em> field as displayed in UI</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.active_since</td>
<td>Date that the indicator became active</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.stats.source_alerts</td>
<td>Total number of source alerts associated with this indicator</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.stats.alerted_agents</td>
<td>Total number of agents with FireEye HX alerts associated with this indicator</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.platforms</td>
<td>List of OS families</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!fireeye-hx-get-indicators sort="activeSince" alerted="yes"</code></p>
<h5>Raw Output</h5>
<pre>    "FireEyeHX": {
        "Indicators": [
            {
                "category": {
                    "url": "/hx/api/v3/indicator_categories/custom", 
                    "_id": 2, 
                    "uri_name": "Custom", 
                    "name": "Custom", 
                    "share_mode": "unrestricted"
                }, 
                "display_name": null, 
                "description": "", 
                "create_actor": {
                    "username": "admin", 
                    "_id": 1000
                }, 
                "platforms": [
                    "win", 
                    "osx"
                ], 
                "url": "/hx/api/v3/indicators/custom/txt", 
                "_revision": "20180501131901519705101701", 
                "update_actor": {
                    "username": "admin", 
                    "_id": 1000
                }, 
                "create_text": null, 
                "created_by": "admin", 
                "active_since": "2018-05-01T13:19:01.519Z", 
                "meta": null, 
                "signature": null, 
                "stats": {
                    "active_conditions": 2, 
                    "alerted_agents": 0, 
                    "source_alerts": 0
                },
		…
        ]
    }
}
 </pre>
<p> </p>
<h3 id="h_3177394125201531225647008">7. Get indicator information</h3>
<hr>
<p>Retrieves information of a specific indicator.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-get-indicator</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Input Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
<tr>
<td>category</td>
<td>Indicator category</td>
<td>Required</td>
</tr>
<tr>
<td>name</td>
<td>Indicator name</td>
<td>Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Indicators._id</td>
<td>FireEye unique indicator ID.</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.name</td>
<td>The indicator name as displayed in the UI</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.description</td>
<td>Indicator description</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.category.name</td>
<td>Category name</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.created_by</td>
<td>The <em>Created By</em> field as displayed in UI</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.active_since</td>
<td>Date that the indicator became active</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.stats.source_alerts</td>
<td>Total number of source alerts associated with this indicator</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.stats.alerted_agents</td>
<td>Total number of agents with FireEye HX alerts associated with this indicator</td>
</tr>
<tr>
<td>FireEyeHX.Indicators.platforms</td>
<td>List of OS families</td>
</tr>
<tr>
<td>FireEyeHX.Conditions._id</td>
<td>FireEye unique condition ID</td>
</tr>
<tr>
<td>FireEyeHX.Conditions.event_type</td>
<td>Event type</td>
</tr>
<tr>
<td>FireEyeHX.Conditions.enabled</td>
<td>Indicates whether the condition is enabled</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!fireeye-hx-get-indicator category=Custom name="test indicator"</code></p>
<h5>Raw Output</h5>
<pre> {
    "FireEyeHX": {
        "Indicators": {
            "category": {
                "url": "/hx/api/v3/indicator_categories/custom", 
                "_id": 2, 
                "uri_name": "Custom", 
                "name": "Custom", 
                "share_mode": "unrestricted"
            }, 
            "display_name": null, 
            "description": "", 
            "create_actor": {
                "username": "admin", 
                "_id": 1000
            }, 
            "platforms": [
                "win", 
                "osx"
            ], 
            "url": "/hx/api/v3/indicators/custom/txt", 
            "_revision": "20180501131901519705101701", 
            "update_actor": {
                "username": "admin", 
                "_id": 1000
            }, 
            "create_text": null, 
            "created_by": "admin", 
            "active_since": "2018-05-01T13:19:01.519Z", 
            "meta": null, 
            "signature": null, 
            "stats": {
                "active_conditions": 2, 
                "alerted_agents": 0, 
                "source_alerts": 0
            }, 
            "_id": "00807331-8982-4e27-94f0-abe873f88366", 
            "uri_name": "txt", 
            "name": "txt"
        }, 
        "Conditions": [
            {
                "tests": [
                    {
                        "operator": "equal", 
                        "token": "ipv4NetworkEvent/remoteIP", 
                        "type": "text", 
                        "value": "^^^8.8.8.8^^^"
                    }
                ], 
                "event_type": "ipv4NetworkEvent", 
                "url": "/hx/api/v3/conditions/G7fmpVr1gxFU2JKXUIu2Cg", 
                "enabled": true, 
                "_id": "G7fmpVr1gxFU2JKXUIu2Cg==", 
                "is_private": false, 
                "uuid": "1bb7e6a5-5af5-4311-94d8-9297508bb60a"
            }, 
            {
                "tests": [
                    {
                        "operator": "equal", 
                        "token": "dnsLookupEvent/hostname", 
                        "type": "text", 
                        "value": "google.com"
                    }
                ], 
                "event_type": "dnsLookupEvent", 
                "url": "/hx/api/v3/conditions/vCc2bJosTJdxrhkqvanEFw", 
                "enabled": true, 
                "_id": "vCc2bJosTJdxrhkqvanEFw==", 
                "is_private": false, 
                "uuid": "bc27366c-9a2c-4c97-b1ae-192abda9c417"
            }
        ]
    }
}
</pre>
<p> </p>
<h3 id="h_1285237886021531225659162">8. Find hostname correlated with agent-ID or agent-ID correlated with hostname </h3>
<hr>
<p>Returns agent-ID for specified hostname, or hostname for specified agent-ID.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-get-host-information</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 130px;"><strong>Argument Name</strong></th>
<th style="width: 507px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 130px;">agentId</td>
<td style="width: 507px;">The agent ID. If the agent ID is not specified, the host Name must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 130px;">hostName</td>
<td style="width: 507px;">The host name. If the host name is not specified, the agent ID must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Hosts._id</td>
<td>FireEye HX Agent ID</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.agent_version</td>
<td>The agent version</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.excluded_from_containment</td>
<td>Determines whether the host is excluded from containment</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_missing_software</td>
<td>Boolean value to indicate for containment missing software</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_queued</td>
<td>Determines whether the host is queued for containment</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.containment_state</td>
<td>The containment state of the host. Possible values normal</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.alerting_conditions</td>
<td>The number of conditions that have alerted for the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.alerts</td>
<td>Total number of alerts, including exploit-detection alerts</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.exploit_blocks</td>
<td>The number of blocked exploits on the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.stats.malware_alerts</td>
<td>The number of malware alerts associated with the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.hostname</td>
<td>The host name</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.domain</td>
<td>Domain name</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.timezone</td>
<td>Host time zone</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.primary_ip_address</td>
<td>The host IP address</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_poll_timestamp</td>
<td>The timestamp of the last system poll performed on the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.initial_agent_checkin</td>
<td>Timestamp of the initial agent check-in</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_alert_timestamp</td>
<td>The time stamp of the last alert for the host</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.last_exploit_block_timestamp</td>
<td>Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked.</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.product_name</td>
<td>Specific operating system</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.bitness</td>
<td>OS Bitness (32 or 64)</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.os.platform</td>
<td>
<p>OS families</p>
<ul>
<li>win</li>
<li>osx</li>
<li>linux</li>
</ul>
</td>
</tr>
<tr>
<td>FireEyeHX.Hosts.primary_mac</td>
<td>The host MAC address</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!fireeye-hx-get-host-information hostName=”DESKTOP-XXX”</code></p>
<h5>Context Example</h5>
<pre> {
    "FireEyeHX": {
        "Hosts": {
            "last_alert": {
                "url": "/hx/api/v3/alerts/5", 
                "_id": 5
            }, 
            "domain": "DEMISTO", 
            "last_exploit_block_timestamp": null, 
            "containment_state": "normal", 
            "timezone": "Eastern Daylight Time", 
            "gmt_offset_seconds": -14400, 
            "initial_agent_checkin": "2018-03-26T14:21:31.273Z", 
            "stats": {
                "alerting_conditions": 1, 
                "exploit_alerts": 0, 
                "acqs": 11, 
                "malware_false_positive_alerts": 0, 
                "alerts": 1, 
                "exploit_blocks": 0, 
                "malware_cleaned_count": 0, 
                "malware_alerts": 0, 
                "malware_quarantined_count": 0
            }, 
            "primary_mac": "XX-XX-XX-XX-XX-XX", 
            "hostname": "DESKTOP-XXX", 
            "primary_ip_address": "^^^XX.XX.XX.XX^^^", 
            "last_audit_timestamp": "2018-05-03T13:59:23.000Z", 
            "last_alert_timestamp": "2018-04-16T08:59:51.693+00:00", 
            "containment_queued": false, 
            "sysinfo": {
                "url": "/hx/api/v3/hosts/uGvnGVpZkDSFySf2ZOiT/sysinfo"
            }, 
            "last_exploit_block": null, 
            "reported_clone": false, 
            "url": "/hx/api/v3/hosts/uGvnGVpZkeySf2ZOiT", 
            "excluded_from_containment": false, 
            "last_poll_timestamp": "2018-05-03T14:01:22.000Z", 
            "last_poll_ip": "^^^XX.XX.XX.XX^^^", 
            "containment_missing_software": false, 
            "_id": " uGvnGVpZkDSFySf2ZOiT ", 
            "os": {
                "kernel_version": null, 
                "platform": "win", 
                "patch_level": null, 
                "bitness": "64-bit", 
                "product_name": "Windows 10 Enterprise Evaluation"
            }, 
            "agent_version": "26.21.10"
        }
    },
    "Endpoint": {
        "MACAddress": "XX-XX-XX-XX-XX-XX", 
        "Domain": "DEMISTO", 
        "IPAddress": "^^^XX.XX.XX.XX^^^", 
        "Hostname": "DESKTOP-XXX", 
        "OSVersion": "Windows 10 Enterprise Evaluation", 
        "OS": "win", 
        "ID": " uGvnGVpZkDSFySf2ZOiT "
    }, 
}
</pre>
<p> </p>
<h3 id="h_9238521966831531225671914">9. Acquire file</h3>
<hr>
<p>Acquires a specific file as a password protected zip file.</p>
<p>Command Limitations</p>
<ul>
<li>Acquisitions are stored for 14 days or until the aggregate size of all acquisitions exceeds the acquisition space limit, which is from 30 GB to 9 TB, depending on the HX Series appliance<strong>.</strong>
</li>
<li>When the acquisition space is completely full and automatic triages fill 10 percent of the acquisition space, the HX Series appliance reclaims disk space by removing automatic triage collections.</li>
<li>When the acquisition space is 90 percent full, no new acquisitions can be created, and bulk acquisitions that are running might be canceled<strong>.</strong>
</li>
</ul>
<h5>Base Command</h5>
<p><code>fireeye-hx-file-acquisition</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 134px;"><strong>Argument Name</strong></th>
<th style="width: 503px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 134px;">fileName</td>
<td style="width: 503px;">The file name</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 134px;">filePath</td>
<td style="width: 503px;">The file path</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 134px;">acquireUsing</td>
<td style="width: 503px;">Whether to aqcuire the file using the API or RAW. By default, raw file will be acquired. Use API option when file is encrypted.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">agentId</td>
<td style="width: 503px;">The agent ID associated with the host that holds the file. If the hostName is not specified, the agentId must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 134px;">hostName</td>
<td style="width: 503px;">The host that holds the file. If the agentId is not specified, hostName must be specified.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Acquisitions.Files._id</td>
<td>The acquisition unique ID</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Files.state</td>
<td>The acquisition state</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Files.md5</td>
<td>File MD5</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Files.req_filename</td>
<td>The file name</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Files.req_path</td>
<td>The file path</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Files.host._id</td>
<td>FireEye HX agent ID</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!fireeye-hx-file-acquisition fileName="test.txt"filePath="C:\\Users\\user\\Documents" hostName="DESKTOP-DES01" </code></p>
<h5>Raw Output</h5>
<pre>     "FireEyeHX": {
        "Acquisitions": {
            "Files": {
                "_id": 13,
                "_revision": "206073441021688",
                "alert": null,
                "comment": null,
                "condition": null,
                "error_message": "The acquisition completed with issues.",
                "external_id": null,
                "finish_time": "2018-04-26T07:34:14.100Z",
                "host": {
                    "_id": "uGvnGVpZkKeySf2ZT",
                    "url": "/hx/api/v3/hosts/ uGvnGVpZkKeySf2ZT "
                },
                "indicator": null,
                "md5": "ee26908bf9…64b37da4754a",
                "req_filename": "ex.txt",
                "req_path": "C:\\Users\\user\\Documents",
                "req_use_api": null,
                "request_actor": {
                    "_id": 1001,
                    "username": "api"
                },
                "request_time": "2018-04-26T07:33:03.000Z",
                "state": "COMPLETE",
                "url": "/hx/api/v3/acqs/files/13",
                "zip_passphrase": "unzip-me"
            }
        }
    }
</pre>
<p> </p>
<h3 id="h_8039477917631531225683376">10. Delete file acquisition</h3>
<hr>
<p>Deletes the file acquisition, by acquisition ID.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-delete-file-acquisition</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Argument Name</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
<tr>
<td>acquisitionId</td>
<td> The acquisition ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output.</p>
<h5>Command Example</h5>
<p><code>!fireeye-hx-delete-file-acquisition acquisitionId=10</code></p>
<p> </p>
<h3 id="h_284510558421531225696011">11. Acquire data</h3>
<hr>
<p>Initiate a data acquisition process that gathers artifacts from the system disk and memory. The data is fetched as a MANS file.</p>
<p><strong>Limitations</strong></p>
<ul>
<li>Acquisitions are stored for 14 days or until the aggregate size of all acquisitions exceeds the acquisition space limit, which is from 30 GB to 9 TB, depending on the HX Series appliance<strong>.</strong>
</li>
<li>When the acquisition space is completely full and automatic triages fill 10 percent of the acquisition space, the HX Series appliance reclaims disk space by removing automatic triage collections.</li>
<li>When the acquisition space is 90 percent full, no new acquisitions can be created, and bulk acquisitions that are running might be canceled<strong>.</strong>
</li>
</ul>
<h5>Base Command</h5>
<p><code>fireeye-hx-data-acquisition</code></p>
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
<td>script</td>
<td>Acquisition script in JSON format</td>
<td>Optional</td>
</tr>
<tr>
<td>scriptName</td>
<td>The script name. If the Acquisition script is specified, you must also specify the script name.</td>
<td>Optional</td>
</tr>
<tr>
<td>defaultSystemScript</td>
<td>Use default script. Select the host system.</td>
<td>Optional</td>
</tr>
<tr>
<td>agentId</td>
<td>The agent ID. If the host name is not specified, the agent ID must be specified.</td>
<td>Optional</td>
</tr>
<tr>
<td>hostName</td>
<td>The host name. If the agent ID is not specified, the host name must be specified.</td>
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
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>FireEyeHX.Acquisitions.Data._id</td>
<td>The acquisition unique ID</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Data.state</td>
<td>The acquisition state</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Data.md5</td>
<td>File MD5</td>
</tr>
<tr>
<td>FireEyeHX.Acquisitions.Data.host._id</td>
<td>Time that the acquisition completed</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>! fireeye-hx-data-acquisition hostName="DESKTOP-DES01" defaultSystemScript=win</code></p>
<h5>Raw Output</h5>
<pre>{
    "FireEyeHX": {
        "Acquisitions": {
            "Data": {
                "comment": null, 
                "zip_passphrase": null, 
                "request_actor": {
                    "username": "api", 
                    "_id": 1001
                }, 
                "name": "test", 
                "script": {
                    "download": "/hx/api/v3/scripts/131ab1da5086fe09f5a210437de366007867fa26.json", 
                    "url": "/hx/api/v3/scripts/^^^131ab1da5086fe09f5a210437de366007867fa26^^^", 
                    "_id": "^^^131ab1da5086fe09f5a210437de366007867fa26^^^"
                }, 
                "finish_time": "2018-05-15T11:58:18.541Z", 
                "_revision": "20180515115818542250101787", 
                "error_message": "The triage completed with issues.", 
                "state": "COMPLETE", 
                "request_time": "2018-05-15T11:57:22.000Z", 
                "url": "/hx/api/v3/acqs/live/28", 
                "host": {
                    "url": "/hx/api/v3/hosts/uGvnGVpZkM4bKeySf2ZOiT", 
                    "_id": "uGvnGVpZkXXXX2ZOiT"
                }, 
                "download": "/hx/api/v3/acqs/live/28.mans", 
                "_id": 28, 
                "external_id": null, 
                "md5": null
            }
        }
    }, 
    "File": {
        "Info": "mans", 
        "SHA1": "^^^4374d09a27ef85XXXXX66785c040d7febff7d8^^^", 
        "Name": "agent_uGvnGVpZkMXXXX2ZOiT_data.mans", 
        "Extension": "mans", 
        "Size": 5154, 
        "EntryID": "383@1", 
        "SSDeep": "96:JraN9hyFIVls4Dst99i462teLuf0XXXXyU2y46Gd/pV:xapyFIVibPi462teLuf0TXdLNJLU23dt", 
        "SHA256": "7944d5e86ce2bXXXXe154d4c2923ddf47016a07b84b460f08b0f2f", 
        "Type": "Zip archive data, at least v2.0 to extract\n", 
        "MD5": "^^^c24a2c4aeXXXXf89e1e012dae^^^"
    }
}

</pre>
<p> </p>
<h3 id="h_7751566479201531225716697">12. Delete data acquisition</h3>
<hr>
<p>Deletes data acquisition, by acquisition ID.</p>
<h5>Base Command</h5>
<p><code>fireeye-hx-delete-data-acquisition</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td><strong>Input Parameter</strong></td>
<td><strong>Description</strong></td>
<td><strong>Required</strong></td>
</tr>
<tr>
<td>
<p>acquisitionId</p>
</td>
<td> The acquisition ID</td>
<td>Required</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!fireeye-hx-delete-data-acquisition acquisitionId=10</code></p>
<p> </p>
<p> </p>
<h2>Error Responses - Timeout Error</h2>
<p><strong>Timeout error</strong> indicates that time limitation for the command has exceeded before results are returned.</p>
<p>To resolve this issue, configure new time limitation for the command.</p>
<p> </p>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>About</strong> &gt; <strong>Troubleshooting</strong> &gt; <strong>Server Configuration</strong>.</li>
<li>click <strong>Add Server Configuration</strong>.</li>
<li>Set the <strong>key</strong> field using this format: FireEye HX.&lt;<em>command-name</em>&gt;.timeout.</li>
<li>Set the <strong>value</strong> field to the desired time limit for the command to run (in minutes).</li>
</ol>
<p><img src="https://raw.githubusercontent.com/demisto/content/ca13780e216a39751600dcb1e386d12f52fc8f25/docs/images/Integrations/FireEyeHX_mceclip0.png" width="814" height="123"></p>
<p> </p>
<h2>Known Limitations</h2>
<h3>Acquisitions limitations</h3>
<ul>
<li>Acquisitions are stored for 14 days or until the aggregate size of all acquisitions exceeds the acquisition space limit, which is from 30 GB to 9 TB, depending on the HX Series appliance<strong>.</strong>
</li>
<li>When the acquisition space is completely full and automatic triages fill 10 percent of the acquisition space, the HX Series appliance reclaims disk space by removing automatic triage collections.</li>
<li>When the acquisition space is 90 percent full, no new acquisitions can be created, and bulk acquisitions that are running might be canceled<strong>.</strong>
</li>
</ul>
<h3>Containment Limitations</h3>
<ul>
<li>Some hosts cannot be contained.</li>
<li>The time it takes to contain a host varies, based on factors such as agent connectivity, network traffic, and other jobs running in your environment.</li>
<li>You can only contain a host if the agent package for that host is available on the HX Series appliance.</li>
</ul>
<p> </p>
<h2>Command Timeout</h2>
<p>The following commands have high potential to exceed the default time limit for a running command. To avoid command timeout, change the command timeout settings.</p>
<ul>
<li>fireeye-hx-search</li>
<li>fireeye-hx-data-acquisition</li>
<li>fireeye-hx-file-acquisition</li>
</ul>
<h3>Configure Command Timeout</h3>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>About</strong> &gt; <strong>Troubleshooting</strong>.</li>
<li>In the <strong>Server Configuration</strong> section, click <strong>Add Server Configuration</strong>.</li>
<li>Set the <em><strong>K</strong><strong>ey</strong></em>’ field using this format: FireEye HX.timeout</li>
<li>Set the <em><strong>Value</strong></em> field to the timeout you need (in minutes).</li>
</ol>
