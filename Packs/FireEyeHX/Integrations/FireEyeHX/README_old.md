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
        "Indicators": [
            {
                "_id": "34757fe7-bdd7-4c85-b0e1-9adfb5e48300",
                "_revision": "20211017115618818832920449",
                "active_since": "2021-10-17T11:56:18.818Z",
                "category": {
                    "_id": 2,
                    "name": "Custom",
                    "share_mode": "unrestricted",
                    "uri_name": "Custom",
                    "url": "/hx/api/v3/indicator_categories/custom"
                },
                "create_actor": {
                    "_id": 1001,
                    "username": "api-admin"
                },
                "create_text": null,
                "created_by": "api-admin",
                "description": null,
                "display_name": null,
                "meta": null,
                "name": "34757fe7-bdd7-4c85-b0e1-9adfb5e48300",
                "platforms": [
                    "win",
                    "osx",
                    "linux"
                ],
                "signature": null,
                "stats": {
                    "active_conditions": 0,
                    "alerted_agents": 0,
                    "source_alerts": 0
                },
                "update_actor": {
                    "_id": 1001,
                    "username": "api-admin"
                },
                "uri_name": "34757fe7-bdd7-4c85-b0e1-9adfb5e48300",
                "url": "/hx/api/v3/indicators/custom/34757fe7_bdd7_4c85_b0e1_9adfb5e48300"
            },
            {
                "_id": "c6286e1b-10bd-4046-8aff-0dbcc5b1e974",
                "_revision": "20201214155227728995101265",
                "active_since": "2021-09-28T14:44:04.245Z",
                "category": {
                    "_id": 7,
                    "name": "Mandiant Unrestricted Intel",
                    "share_mode": "unrestricted",
                    "uri_name": "mandiant_unrestricted",
                    "url": "/hx/api/v3/indicator_categories/mandiant_unrestricted"
                },
                "create_actor": {
                    "_id": 3,
                    "username": "mandiant"
                },
                "create_text": "General_Windows_unrestricted_2021.09.270849",
                "created_by": "General_Windows_unrestricted_2021.09.270849",
                "description": "This IOC alerts on suspicious filewrites by the legitimate solarwinds process solarwinds.businesslayerhost.exe. solarwinds.businesslayerhost.exe is part of the the Network Performance Monitor (NPM) module of Solarwinds; responsible for detecting and diagnosing network performance issues. This may be an evidence of SUNBURST which is a backdoor that has the ability to spawn and kill processes, write and delete files, set and create registry keys, gather system information, and disable a set of forensic analysis tools and services.This is associated with MITRE ATT&CK (r) Tactic(s): Initial Access and Technique(s): T1195.002.",
                "display_name": "SUNBURST SUSPICIOUS FILEWRITES (METHODOLOGY)",
                "meta": null,
                "name": "SUNBURST SUSPICIOUS FILEWRITES (METHODOLOGY)",
                "platforms": [
                    "win",
                    "osx",
                    "linux"
                ],
                "signature": null,
                "stats": {
                    "active_conditions": 6,
                    "alerted_agents": 0,
                    "source_alerts": 0
                },
                "update_actor": {
                    "_id": 3,
                    "username": "mandiant"
                },
                "uri_name": "c6286e1b-10bd-4046-8aff-0dbcc5b1e974",
                "url": "/hx/api/v3/indicators/mandiant_unrestricted/c6286e1b_10bd_4046_8aff_0dbcc5b1e974"
            }
        ]
    }
}
```

#### Human Readable Output

>### FireEye HX Get Indicator- None
>|OS|Name|Created By|Active Since|Category|Signature|Active Condition|Hosts With Alerts|Source Alerts|
>|---|---|---|---|---|---|---|---|---|
>| win, osx, linux | 34757fe7-bdd7-4c85-b0e1-9adfb5e48300 | api-admin | 2021-10-17T11:56:18.818Z | Custom |  | 0 | 0 | 0 |
>| win, osx, linux | SUNBURST SUSPICIOUS FILEWRITES (METHODOLOGY) | General_Windows_unrestricted_2021.09.270849 | 2021-09-28T14:44:04.245Z | Mandiant Unrestricted Intel |  | 6 | 0 | 0 |


### fireeye-hx-get-indicator
***
Get a specific indicator details


#### Base Command

`fireeye-hx-get-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | Indicator category. Please use the `uri_category` value. | Required | 
| name | Indicator name. Please use the `uri_name` value. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators._id | Unknown | FireEye unique indicator ID. | 
| FireEyeHX.Indicators.name | Unknown | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.description | Unknown | Indicator description. | 
| FireEyeHX.Indicators.category.name | Unknown | Catagory name. | 
| FireEyeHX.Indicators.created_by | Unknown | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.active_since | Unknown | Date indicator became active. | 
| FireEyeHX.Indicators.stats.source_alerts | Unknown | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.alerted_agents | Unknown | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.platforms | Unknown | List of families of operating systems. | 
| FireEyeHX.Conditions._id | Unknown | FireEye unique condition ID. | 
| FireEyeHX.Conditions.event_type | Unknown | Event type. | 
| FireEyeHX.Conditions.enabled | Unknown | Indicates whether the condition is enabled. | 


#### Command Example
```!fireeye-hx-get-indicator category=Custom name="5def0b16-87bc-42a2-877a-bca45ebcbc9a"```

#### Context Example
```json
{
    "FireEyeHX": {
        "Conditions": [
            {
                "_id": "YhXur1M8FNRDi8GAr9CMbQ==",
                "enabled": true,
                "event_type": "dnsLookupEvent",
                "is_private": false,
                "tests": [
                    {
                        "operator": "equal",
                        "token": "dnsLookupEvent/hostname",
                        "type": "text",
                        "value": "example.lol"
                    }
                ],
                "url": "/hx/api/v3/conditions/YhXur1M8FNRDi8GAr9CMbQ",
                "uuid": "6215eeaf-533c-44d4-838b-c180afd08c6d"
            },
            {
                "_id": "gB7gGHN9RmLNdf8mwuvQ8Q==",
                "enabled": true,
                "event_type": "dnsLookupEvent",
                "is_private": false,
                "tests": [
                    {
                        "operator": "equal",
                        "token": "dnsLookupEvent/hostname",
                        "type": "text",
                        "value": "example.abc"
                    }
                ],
                "url": "/hx/api/v3/conditions/gB7gGHN9RmLNdf8mwuvQ8Q",
                "uuid": "801ee018-737d-4662-8d75-ff26c2ebd0f1"
            }
        ],
        "Indicators": {
            "_id": "5def0b16-87bc-42a2-877a-bca45ebcbc9a",
            "_revision": "20210920184007966360614215",
            "active_since": "2021-09-20T18:40:07.966Z",
            "category": {
                "_id": 2,
                "name": "Custom",
                "share_mode": "unrestricted",
                "uri_name": "Custom",
                "url": "/hx/api/v3/indicator_categories/custom"
            },
            "create_actor": {
                "_id": 1001,
                "username": "api-admin"
            },
            "create_text": null,
            "created_by": "api-admin",
            "description": null,
            "display_name": null,
            "meta": null,
            "name": "5def0b16-87bc-42a2-877a-bca45ebcbc9a",
            "platforms": [
                "win",
                "osx",
                "linux"
            ],
            "signature": null,
            "stats": {
                "active_conditions": 2,
                "alerted_agents": 0,
                "source_alerts": 0
            },
            "update_actor": {
                "_id": 1001,
                "username": "api-admin"
            },
            "uri_name": "5def0b16-87bc-42a2-877a-bca45ebcbc9a",
            "url": "/hx/api/v3/indicators/custom/5def0b16_87bc_42a2_877a_bca45ebcbc9a"
        }
    }
}
```

#### Human Readable Output

>### Indicator "5def0b16-87bc-42a2-877a-bca45ebcbc9a" Alerts on
>|Event Type|Operator|Value|
>|---|---|---|
>| dnsLookupEvent | equal | example.lol |
>| dnsLookupEvent | equal | example.abc |


### fireeye-hx-get-host-information
***
Get information on a host associated with an agent.


#### Base Command

`fireeye-hx-get-host-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentId | The agent ID. If the agent ID is not specified, the host Name must be specified. | Optional | 
| hostName | The host name. If the host name is not specified, the agent ID must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal|contain|contain_fail|containing|contained|uncontain|uncontaining|wtfc|wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-get-alert
***
Get details of a specific alert


#### Base Command

`fireeye-hx-get-alert`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| alertId | The alert ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Alerts._id | Unknown | FireEye alert ID. | 
| FireEyeHX.Alerts.agent._id | Unknown | FireEye agent ID. | 
| FireEyeHX.Alerts.agent.containment_state | Unknown | Host containment state. | 
| FireEyeHX.Alerts.condition._id | Unknown | The condition unique ID. | 
| FireEyeHX.Alerts.event_at | Unknown | Time when the event occoured. | 
| FireEyeHX.Alerts.matched_at | Unknown | Time when the event was matched. | 
| FireEyeHX.Alerts.reported_at | Unknown | Time when the event was reported. | 
| FireEyeHX.Alerts.source | Unknown | Source of alert. | 
| FireEyeHX.Alerts.matched_source_alerts._id | Unknown | Source alert ID. | 
| FireEyeHX.Alerts.matched_source_alerts.appliance_id | Unknown | Appliance ID | 
| FireEyeHX.Alerts.matched_source_alerts.meta | Unknown | Source alert meta. | 
| FireEyeHX.Alerts.matched_source_alerts.indicator_id | Unknown | Indicator ID. | 
| FireEyeHX.Alerts.resolution | Unknown | Alert resulotion. | 
| FireEyeHX.Alerts.event_type | Unknown | Event type. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-file-acquisition
***
Aquire a specific file as a password protected zip file. The password for unlocking the zip file is 'unzip-me'.


#### Base Command

`fireeye-hx-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| fileName | The file name. | Required | 
| filePath | The file path. | Required | 
| acquireUsing | Whether to aqcuire the file using the API or RAW. By default, raw file will be acquired. Use API option when file is encrypted. Possible values are: API, RAW. | Optional | 
| agentId | The agent ID associated with the host that holds the file. If the hostName is not specified, the agentId must be specified. | Optional | 
| hostName | The host that holds the file. If the agentId is not specified, hostName must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Files._id | Unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Files.state | Unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Files.md5 | Unknown | File md5. | 
| FireEyeHX.Acquisitions.Files.req_filename | Unknown | The file name. | 
| FireEyeHX.Acquisitions.Files.req_path | Unknown | The file path. | 
| FireEyeHX.Acquisitions.Files.host._id | Unknown | FireEye HX agent ID. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-delete-file-acquisition
***
Delete the file acquisition, by ID.


#### Base Command

`fireeye-hx-delete-file-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-data-acquisition
***
Start a data acquisition process to gather artifacts from the system disk and memory. The data is fetched as mans file.


#### Base Command

`fireeye-hx-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | Acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Use default script. Select the host system. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | Unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | Unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Data.md5 | Unknown | File md5. | 
| FireEyeHX.Acquisitions.Data.finish_time | Unknown | Time when the acquisition was finished. | 
| FireEyeHX.Acquisitions.Data.host._id | unknown | Agent ID | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-delete-data-acquisition
***
Delete data acquisition.


#### Base Command

`fireeye-hx-delete-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition ID. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-search
***
Search endpoints to check all hosts or a subset of hosts for a specific file or indicator.


#### Base Command

`fireeye-hx-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| agentsIds | IDs of agents to be searched. | Optional | 
| hostsNames | Names of hosts to be searched. | Optional | 
| hostSet | Id of host set to be searched. | Optional | 
| limit | Limit results count (once limit is reached, the search is stopped). | Optional | 
| exhaustive | Should search be exhaustive or quick. Possible values are: yes, no. Default is True. | Optional | 
| ipAddress | A valid IPv4 address to search for. | Optional | 
| ipAddressOperator | Which operator to apply to the given IP address. Possible values are: equals, not equals. | Optional | 
| fileMD5Hash | A 32-character MD5 hash value to search for. | Optional | 
| fileMD5HashOperator | Which operator to apply to the given MD5 hash. Possible values are: equals, not equals. | Optional | 
| fileFullPath | Full path of file to search. | Optional | 
| fileFullPathOperator | Which operator to apply to the given file path. Possible values are: equals, not equals, contains, not contains. | Optional | 
| dnsHostname | DNS value to search for. | Optional | 
| dnsHostnameOperator | Which operator to apply to the given DNS. Possible values are: equals, not equals, contains, not contains. | Optional | 
| stopSearch | Method in which search should be stopped after finding &lt;limit&gt; number of results. Possible values are: stopAndDelete, stop. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Search.Results.Timestamp - Modified | string | Time when the entry was last modified | 
| FireEyeHX.Search.Results.File Text Written | string | The file text content | 
| FireEyeHX.Search.Results.File Name | string | Name of the file | 
| FireEyeHX.Search.Results.File Full Path | string | The full path of the file | 
| FireEyeHX.Search.Results.File Bytes Written | string | Number of bytes written to the file | 
| FireEyeHX.Search.Results.Size in bytes | string | Size of the file in bytes | 
| FireEyeHX.Search.Results.Browser Version | string | Version of the browser | 
| FireEyeHX.Search.Results.Browser Name | string | Name of the browser | 
| FireEyeHX.Search.Results.Cookie Name | string | Name of the cookie | 
| FireEyeHX.Search.Results.DNS Hostname | string | Name of the DNS host | 
| FireEyeHX.Search.Results.URL | string | The event URL | 
| FireEyeHX.Search.Results.Username | string | The event username | 
| FireEyeHX.Search.Results.File MD5 Hash | string | MD5 hash of the file | 
| FireEyeHX.Search.HostID | string | ID of the host | 
| FireEyeHX.Search.HostName | string | Name of host | 
| FireEyeHX.Search.HostUrl | string | Inner FireEye host url | 
| FireEyeHX.Search.SearchID | string | ID of performed search | 
| FireEyeHX.Search.Results.Timestamp - Accessed | string | Last accessed time | 
| FireEyeHX.Search.Results.Port | number | Port | 
| FireEyeHX.Search.Results.Process ID | string | ID of the process | 
| FireEyeHX.Search.Results.Local IP Address | string | Local IP Address | 
| FireEyeHX.Search.Results.Local IP Address | string | Local IP Address | 
| FireEyeHX.Search.Results.Local Port | number | Local Port | 
| FireEyeHX.Search.Results.Username | string | Username | 
| FireEyeHX.Search.Results.Remote Port | number | Remote Port | 
| FireEyeHX.Search.Results.IP Address | string | IP Address | 
| FireEyeHX.Search.Results.Process Name | string | Process Name | 
| FireEyeHX.Search.Results.Timestamp - Event | string | Timestamp - Event | 
| FireEyeHX.Search.Results.type | string | The type of the event | 
| FireEyeHX.Search.Results.id | string | ID of the result | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-get-host-set-information
***
Get a list of all host sets known to your HX Series appliance


#### Base Command

`fireeye-hx-get-host-set-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostSetID | ID of a specific host set to get. | Optional | 
| offset | Specifies which record to start with in the response. The offset value must be an unsigned 32-bit integer. The default is 0. | Optional | 
| limit | Specifies how many records are returned. The limit value must be an unsigned 32-bit integer. The default is 50. | Optional | 
| search | Searches the names of all host sets connected to the specified HX appliance. | Optional | 
| sort | Sorts the results by the specified field in ascending or descending order. The default is sorting by name in ascending order. Sortable fields are _id (host set ID) and name (host set name). | Optional | 
| name | Specifies the name of host set to look for. | Optional | 
| type | Specifies the type of host sets to search for. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.HostSets._id | number | host set id | 
| FireEyeHX.HostSets._revision | string | Revision number | 
| FireEyeHX.HostSets.name | string | Host set name | 
| FireEyeHX.HostSets.type | string | Host set type \(static/dynamic/hidden\) | 
| FireEyeHX.HostSets.url | string | Host set FireEye url | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-create-indicator
***
Create new indicator


#### Base Command

`fireeye-hx-create-indicator`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Indicators.active_since | date | Date indicator became active. | 
| FireEyeHX.Indicators.meta | string | Meta data for new indicator | 
| FireEyeHX.Indicators.display_name | string | The indicator display name | 
| FireEyeHX.Indicators.name | string | The indicator name as displayed in the UI. | 
| FireEyeHX.Indicators.created_by | string | The "Created By" field as displayed in UI | 
| FireEyeHX.Indicators.url | string | The data URL | 
| FireEyeHX.Indicators.create_text | Unknown | The indicator create text | 
| FireEyeHX.Indicators.platforms | string | List of families of operating systems. | 
| FireEyeHX.Indicators.create_actor._id | number | The ID of the actor | 
| FireEyeHX.Indicators.create_actor.username | string | Actor user name | 
| FireEyeHX.Indicators.signature | string | Signature of indicator  | 
| FireEyeHX.Indicators._revision | string | Indicator revision | 
| FireEyeHX.Indicators._id | string | FireEye unique indicator ID. | 
| FireEyeHX.Indicator.description | string | Indicator description | 
| FireEyeHX.Indicators.category._id | number | Category ID | 
| FireEyeHX.Indicators.category.name | string | Category name | 
| FireEyeHX.Indicators.category.share_mode | string | Category share mode | 
| FireEyeHX.Indicators.category.uri_name | string | Category uri name | 
| FireEyeHX.Indicators.category.url | string | Category URL | 
| FireEyeHX.Indicators.uri_name | string | The indicator uri name | 
| FireEyeHX.Indicators.stats.active_conditions | number | Indicator active conditions | 
| FireEyeHX.Indicators.stats.alerted_agents | number | Total number of agents with HX alerts associated with this indicator. | 
| FireEyeHX.Indicators.stats.source_alerts | number | Total number of source alerts associated with this indicator. | 
| FireEyeHX.Indicators.update_actor._id | number | Update actor ID | 
| FireEyeHX.Indicators.update_actor.username | string | Update actor name | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-append-conditions
***
Add conditions to an indicator. Conditions can be MD5, hash values, domain names and IP addresses.


#### Base Command

`fireeye-hx-append-conditions`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| category | The indicator category. Please use the `uri_category` value. | Required | 
| name | The name of the indicator. Please use the `uri_name` value. | Required | 
| condition | A list of conditions to add. The list can include a list of IPv4 addresses, MD5 files, and domain names. For example: example.netexample.orgexample.lol. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-get-all-hosts-information
***
Get information on all hosts


#### Base Command

`fireeye-hx-get-all-hosts-information`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Hosts._id | Unknown | FireEye HX Agent ID. | 
| FireEyeHX.Hosts.agent_version | Unknown | The agent version. | 
| FireEyeHX.Hosts.excluded_from_containment | Unknown | Determines whether the host is excluded from containment. | 
| FireEyeHX.Hosts.containment_missing_software | Unknown | Boolean value to indicate for containment missing software. | 
| FireEyeHX.Hosts.containment_queued | Unknown | Determines whether the host is queued for containment. | 
| FireEyeHX.Hosts.containment_state | Unknown | The containment state of the host. Possible values normal|contain|contain_fail|containing|contained|uncontain|uncontaining|wtfc|wtfu | 
| FireEyeHX.Hosts.stats.alerting_conditions | Unknown | The number of conditions that have alerted for the host. | 
| FireEyeHX.Hosts.stats.alerts | Unknown | Total number of alerts, including exploit-detection alerts. | 
| FireEyeHX.Hosts.stats.exploit_blocks | Unknown | The number of blocked exploits on the host. | 
| FireEyeHX.Hosts.stats.malware_alerts | Unknown | The number of malware alerts associated with the host. | 
| FireEyeHX.Hosts.hostname | Unknown | The host name. | 
| FireEyeHX.Hosts.domain | Unknown | Domain name. | 
| FireEyeHX.Hosts.timezone | Unknown | Host time zone. | 
| FireEyeHX.Hosts.primary_ip_address | Unknown | The host IP address. | 
| FireEyeHX.Hosts.last_poll_timestamp | Unknown | The timestamp of the last system poll preformed on the host. | 
| FireEyeHX.Hosts.initial_agent_checkin | Unknown | Timestamp of the initial agent check-in. | 
| FireEyeHX.Hosts.last_alert_timestamp | Unknown | The time stamp of the last alert for the host. | 
| FireEyeHX.Hosts.last_exploit_block_timestamp | Unknown | Time when the last exploit was blocked on the host. The value is null if no exploits have been blocked. | 
| FireEyeHX.Hosts.os.product_name | Unknown | Specific operating system | 
| FireEyeHX.Hosts.os.bitness | Unknown | OS Bitness. | 
| FireEyeHX.Hosts.os.platform | Unknown | Family of operating systems. Valid values are win, osx, and linux. | 
| FireEyeHX.Hosts.primary_mac | Unknown | The host MAC address. | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-initiate-data-acquisition
***
Initiate a data acquisition process to gather artifacts from the system disk and memory


#### Base Command

`fireeye-hx-initiate-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| script | Acquisition script in JSON format. | Optional | 
| scriptName | The script name. If the Acquisition script is specified, the script name must be specified as well. | Optional | 
| defaultSystemScript | Use default script. Select the host system. Possible values are: osx, win, linux. | Optional | 
| agentId | The agent ID. If the host name is not specified, the agent ID must be specified. | Optional | 
| hostName | The host name. If the agent ID is not specified, the host name must be specified. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | unknown | The acquisition state | 
| FireEyeHX.Acquisitions.Data.md5 | unknown | File md5 | 
| FireEyeHX.Acquisitions.Data.host._id | unknown | Agent ID | 
| FireEyeHX.Acquisitions.Data.host.hostname | unknown | Hostname | 
| FireEyeHX.Acquisitions.Data.instance | unknown | FIreEye HX instance | 
| FireEyeHX.Acquisitions.Data.finish_time | unknown | Time when the acquisition finished | 


#### Command Example
``` ```

#### Human Readable Output



### fireeye-hx-get-data-acquisition
***
Gather artifacts from the system disk and memory for the given acquisition id. The data is fetched as mans file


#### Base Command

`fireeye-hx-get-data-acquisition`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| acquisitionId | The acquisition unique ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| FireEyeHX.Acquisitions.Data._id | unknown | The acquisition unique ID. | 
| FireEyeHX.Acquisitions.Data.state | unknown | The acquisition state. | 
| FireEyeHX.Acquisitions.Data.md5 | unknown | File md5. | 
| FireEyeHX.Acquisitions.Data.host._id | unknown | Agent ID | 
| FireEyeHX.Acquisitions.Data.finish_time | unknown | Time when the acquisition finished | 
| FireEyeHX.Acquisitions.Data.host.hostname | unknown | Hostname | 
| FireEyeHX.Acquisitions.Data.instance | unknown | FIreEye HX instance | 


#### Command Example
``` ```

#### Human Readable Output


