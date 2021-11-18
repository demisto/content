<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the Cisco Secure Cloud Analytics (Stealthwatch Cloud) integration to manage threats to your networks.</p>
<p>This integration was integrated and tested with Cisco Secure Cloud Analytics (Stealthwatch Cloud) v1.0.0.</p>
<h2>Use cases</h2>
<hr>
<ol>
<li>Fetch incidents</li>
<li>Block domains (Block list)</li>
<li>Update alerts</li>
</ol>
<h2>Configure Cisco Secure Cloud Analytics (Stealthwatch Cloud) on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Stealthwatch Cloud.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Stealthwatch server URL</strong></li>
<li><strong>Stealthwatch Cloud API key. Should be in the form of "ApiKey :&lt;api_key&gt;"</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_46121017251544340041243">Get information for an alert: sw-show-alert</a></li>
<li><a href="#h_146688479731544340044713">Update an alert: sw-update-alert</a></li>
<li><a href="#h_9254938391391544340048923">Get a list of all alerts: sw-list-alerts</a></li>
<li><a href="#h_1721575142041544340053332">Block a domain or IP: sw-block-domain-or-ip</a></li>
<li><a href="#h_9208148722681544340078867">Unblock a domain: sw-unblock-domain</a></li>
<li><a href="#h_9871599403301544340083627">Get a list of blocked domains: sw-list-blocked-domains</a></li>
<li><a href="#h_8197387423921544340087540">Get a list of observations: sw-list-observations</a></li>
<li><a href="#h_878911594541544340092421">Get a list of sessions by session occurrence time: sw-list-sessions</a></li>
</ol>
<h3 id="h_46121017251544340041243">1. Get information for an alert</h3>
<hr>
<p>Returns information about a specific alert by the alert ID.</p>
<h5>Base Command</h5>
<pre><code>sw-show-alert</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 184px;"><strong>Argument Name</strong></th>
<th style="width: 416px;"><strong>Description</strong></th>
<th style="width: 108px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 184px;">alertID</td>
<td style="width: 416px;">The id of the required alert</td>
<td style="width: 108px;">Required</td>
</tr>
<tr>
<td style="width: 184px;">addComments</td>
<td style="width: 416px;">Add comments information, can be long</td>
<td style="width: 108px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 360px;"><strong>Path</strong></th>
<th style="width: 78px;"><strong>Type</strong></th>
<th style="width: 270px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.id</td>
<td style="width: 78px;">number</td>
<td style="width: 270px;">Alert ID</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.assigned_to</td>
<td style="width: 78px;">string</td>
<td style="width: 270px;">Alert assignee</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.obj_created</td>
<td style="width: 78px;">date</td>
<td style="width: 270px;">Alert creation date</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.last_modified</td>
<td style="width: 78px;">date</td>
<td style="width: 270px;">Alert last modification</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.resolved</td>
<td style="width: 78px;">boolean</td>
<td style="width: 270px;">Alert state</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.source_info.ips</td>
<td style="width: 78px;">string</td>
<td style="width: 270px;">IP of the alert's source</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.source_info.hostnames</td>
<td style="width: 78px;">string</td>
<td style="width: 270px;">Hostname of the alert's source</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!sw-show-alert alertID=275</code></pre>
<h5>Context Example</h5>
<pre><code>{
  "assigned_to": null,
  "assigned_to_username": null,
  "created": "2018-07-23T15:30:00Z",
  "description": "Source has started a port scan on a device internal to your network.",
  "hostname": "",
  "id": 275,
  "ips_when_created": [],
  "last_modified": "2018-10-02T22:41:07.749868Z",
  "merit": 3,
  "natural_time": "1 month ago",
  "obj_created": "2018-07-23T16:34:01.566717Z",
  "priority": 2,
  "publish_time": "2018-07-23T16:34:01.531458+00:00",
  "resolved": true,
  "resolved_time": "2018-11-17T05:00:01.458445Z",
  "resolved_user": null,
  "rules_matched": null,
  "snooze_settings": null,
  "source": 48858,
  "source_info": {
    "created": "2018-09-23T15:49:39.025415+00:00",
    "hostnames": [],
    "ips": [
      "5.5.255.25"
    ],
    "name": "test.com",
    "namespace": "default"
  },
  "source_name": "5.5.255.25",
  "source_params": {
    "id": 48852,
    "meta": "net-link",
    "name": "test.com"
  },
  "tags": [],
  "text": "Internal Port Scanner on 5.5.255.25",
  "time": "2018-10-02T21:49:00Z",
  "type": "Internal Port Scanner"
}
</code></pre>
<h3 id="h_146688479731544340044713">2. Update an alert</h3>
<hr>
<p>Updates an alert.</p>
<h5>Base Command</h5>
<pre><code>sw-update-alert</code></pre>
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
<td style="width: 144px;">alertID</td>
<td style="width: 493px;">The ID of the alert to update</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 144px;">resolved</td>
<td style="width: 493px;">Set the <strong>resolved</strong> field to <em>true</em> and set the <strong>merit</strong> field to <em>close</em> an alert. merit can be 8 ("helpful") or 9 ("not helpful")</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">merit</td>
<td style="width: 493px;">Set the <strong>resolved</strong> field to <em>true</em> and set the <strong>merit</strong> field to <em>close</em> an alert. merit can be 8 ("helpful") or 9 ("not helpful")</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">tags</td>
<td style="width: 493px;">Tags (string)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">new_comment</td>
<td style="width: 493px;">Set the <strong>new_comment</strong> field to add a comment to the alert</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">publish_time</td>
<td style="width: 493px;">Publish time (string), e.g., publish_time=2018-08-01T07:54:39Z</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">snooze_settings</td>
<td style="width: 493px;">Snooze settings (string)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">resolved_user</td>
<td style="width: 493px;">Username (string)</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 144px;">assigned_to</td>
<td style="width: 493px;">Assigned to (integer)</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 359px;"><strong>Path</strong></th>
<th style="width: 76px;"><strong>Type</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.id</td>
<td style="width: 76px;">number</td>
<td style="width: 273px;">Alert ID</td>
</tr>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.assigned_to</td>
<td style="width: 76px;">string</td>
<td style="width: 273px;">Alert assignee</td>
</tr>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.obj_created</td>
<td style="width: 76px;">date</td>
<td style="width: 273px;">Alert creation date</td>
</tr>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.last_modified</td>
<td style="width: 76px;">date</td>
<td style="width: 273px;">Date the alert was last modified</td>
</tr>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.resolved</td>
<td style="width: 76px;">boolean</td>
<td style="width: 273px;">Alert state</td>
</tr>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.source_info.ips</td>
<td style="width: 76px;">string</td>
<td style="width: 273px;">IP of the alert's source</td>
</tr>
<tr>
<td style="width: 359px;">Stealthwatch.Alert.source_info.hostname</td>
<td style="width: 76px;">string</td>
<td style="width: 273px;">Hostname of the alert's source</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!sw-update-alert alertID=275 merit=8 tags=test</code></pre>
<h3 id="h_9254938391391544340048923">3. Get a list of all alerts</h3>
<hr>
<p>Get the list of Stealthwatch alerts.</p>
<h5>Base Command</h5>
<pre><code>sw-list-alerts</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">status</td>
<td style="width: 501px;">Filters alerts by status: <em>open</em>, <em>closed</em>, or <em>all</em>. Default is open. The <em>all</em> status enables you to see an individual alert whether it is open or closed.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">search</td>
<td style="width: 501px;">Finds a particular string in the alerts, e.g., a particular IP address, hostname, or alert type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">assignee</td>
<td style="width: 501px;">Filter to only display alerts assigned to a specific user</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">tags</td>
<td style="width: 501px;">Tags shows alerts that are assigned a particular incident tag</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">limit</td>
<td style="width: 501px;">Number of alerts to list, default is 5</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">addComments</td>
<td style="width: 501px;">Add comment to an alert, long-text supported</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 360px;"><strong>Path</strong></th>
<th style="width: 75px;"><strong>Type</strong></th>
<th style="width: 273px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.id</td>
<td style="width: 75px;">number</td>
<td style="width: 273px;">Alert ID</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.assigned_to</td>
<td style="width: 75px;">string</td>
<td style="width: 273px;">Alert assignee</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.obj_created</td>
<td style="width: 75px;">date</td>
<td style="width: 273px;">Alert creation date</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.last_modified</td>
<td style="width: 75px;">date</td>
<td style="width: 273px;">Date the alert was last modified</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.resolved</td>
<td style="width: 75px;">boolean</td>
<td style="width: 273px;">Alert state</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.source_info.ips</td>
<td style="width: 75px;">string</td>
<td style="width: 273px;">IP of the alert's source</td>
</tr>
<tr>
<td style="width: 360px;">Stealthwatch.Alert.source_info.hostname</td>
<td style="width: 75px;">string</td>
<td style="width: 273px;">Hostname of the alert's source</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>{
  "assigned_to": null,
  "assigned_to_username": null,
  "created": "2018-07-23T15:30:00Z",
  "description": "Source has started a port scan on a device internal to your network.",
  "hostname": "",
  "id": 275,
  "ips_when_created": [],
  "last_modified": "2018-10-02T22:41:07.749868Z",
  "merit": 3,
  "natural_time": "1 month ago",
  "obj_created": "2018-07-23T16:34:01.566717Z",
  "priority": 2,
  "publish_time": "2018-07-23T16:34:01.531458+00:00",
  "resolved": true,
  "resolved_time": "2018-11-17T05:00:01.458445Z",
  "resolved_user": null,
  "rules_matched": null,
  "snooze_settings": null,
  "source": 48858,
  "source_info": {
    "created": "2018-09-23T15:49:39.025415+00:00",
    "hostnames": [],
    "ips": [
      "5.5.255.25"
    ],
    "name": "test.com",
    "namespace": "default"
  },
  "source_name": "5.5.255.25",
  "source_params": {
    "id": 48852,
    "meta": "net-link",
    "name": "test.com"
  },
  "tags": [],
  "text": "Internal Port Scanner on 5.5.255.25",
  "time": "2018-10-02T21:49:00Z",
  "type": "Internal Port Scanner"
}
</code></pre>
<h3 id="h_1721575142041544340053332">4. Block a domain or IP</h3>
<hr>
<p>Adds a domain or IP to the block list.</p>
<h5>Base Command</h5>
<pre><code>sw-block-domain-or-ip</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 218px;"><strong>Argument Name</strong></th>
<th style="width: 363px;"><strong>Description</strong></th>
<th style="width: 127px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 218px;">domain</td>
<td style="width: 363px;">Domain to add to the block list</td>
<td style="width: 127px;">Optional</td>
</tr>
<tr>
<td style="width: 218px;">ip</td>
<td style="width: 363px;">IP to add to the block list</td>
<td style="width: 127px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 404px;"><strong>Path</strong></th>
<th style="width: 112px;"><strong>Type</strong></th>
<th style="width: 192px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 404px;">Stealthwatch.Domain.identifier</td>
<td style="width: 112px;">string</td>
<td style="width: 192px;">Domain name</td>
</tr>
<tr>
<td style="width: 404px;">Stealthwatch.Domain.title</td>
<td style="width: 112px;">string</td>
<td style="width: 192px;">Domain title</td>
</tr>
<tr>
<td style="width: 404px;">Stealthwatch.Domain.id</td>
<td style="width: 112px;">number</td>
<td style="width: 192px;">Domain ID</td>
</tr>
<tr>
<td style="width: 404px;">Stealthwatch.IP.identifier</td>
<td style="width: 112px;">string</td>
<td style="width: 192px;">IP address</td>
</tr>
<tr>
<td style="width: 404px;">Stealthwatch.IP.title</td>
<td style="width: 112px;">string</td>
<td style="width: 192px;">IP title</td>
</tr>
<tr>
<td style="width: 404px;">Stealthwatch.IP.id</td>
<td style="width: 112px;">string</td>
<td style="width: 192px;">IP ID</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!sw-block-domain-or-ip domain=test.com</code></pre>
<h3 id="h_9208148722681544340078867">5. Unblock a domain</h3>
<hr>
<p>Removes a domain from the block list.</p>
<h5>Base Command</h5>
<pre><code>sw-unblock-domain</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 131px;"><strong>Argument Name</strong></th>
<th style="width: 506px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 131px;">id</td>
<td style="width: 506px;">ID of the domain to remove from the block list. You can find the <em>id</em> by running the <em>sw-list-blocked-domains</em> command.</td>
<td style="width: 71px;">True</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre><code>!sw-unblock-domain id=5</code></pre>
<h3 id="h_9871599403301544340083627">6. Get a list of blocked domains</h3>
<hr>
<p>Returns a list of blocked domains.</p>
<h5>Base Command</h5>
<pre><code>sw-list-blocked-domains</code></pre>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">search</td>
<td style="width: 504px;">Finds a particular string in the alerts, e.g., a particular IP address, hostname, or alert type.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">domain</td>
<td style="width: 504px;">Search for a specific domain</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">limit</td>
<td style="width: 504px;">Number of domains to list, default is 5</td>
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
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Stealthwatch.Domain.identifier</td>
<td>string</td>
<td>Domain name</td>
</tr>
<tr>
<td>Stealthwatch.Domain.title</td>
<td>string</td>
<td>Domain title</td>
</tr>
<tr>
<td>Stealthwatch.Domain.id</td>
<td>number</td>
<td>Domain ID</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!sw-list-blocked-domains limit=5</code></pre>
<h3 id="h_8197387423921544340087540">7. Get a list of observations</h3>
<hr>
<p>Returns observations by alert ID, observation ID, or a free search.</p>
<h5>Base Command</h5>
<pre><code>sw-list-observations</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 135px;"><strong>Argument Name</strong></th>
<th style="width: 502px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 135px;">search</td>
<td style="width: 502px;">Finds a particular string amongst the alerts. For example, a particular IP address, hostname, or alert type.</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 135px;">alert</td>
<td style="width: 502px;">Use the alert query parameter with an alert id to only show observations referenced by the alert</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 135px;">id</td>
<td style="width: 502px;">Get a specific observation by its ID</td>
<td style="width: 71px;">False</td>
</tr>
<tr>
<td style="width: 135px;">limit</td>
<td style="width: 502px;">Amount of observations to list. Default is 5</td>
<td style="width: 71px;">False</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table>
<thead>
<tr>
<th><strong>Path</strong></th>
<th><strong>Type</strong></th>
<th><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td>Stealthwatch.Observation.id</td>
<td>number</td>
<td>Observation ID</td>
</tr>
<tr>
<td>Stealthwatch.Observation.port_count</td>
<td>number</td>
<td>Observation port count</td>
</tr>
<tr>
<td>Stealthwatch.Observation.creation_time</td>
<td>string</td>
<td>Observation creation time</td>
</tr>
<tr>
<td>Stealthwatch.Observation.end_time</td>
<td>string</td>
<td>Observation end time</td>
</tr>
<tr>
<td>Stealthwatch.Observation.scanned_ip</td>
<td>string</td>
<td>Observation scanned ip</td>
</tr>
<tr>
<td>Stealthwatch.Observation.scanner_ip</td>
<td>string</td>
<td>Observation scanner ip</td>
</tr>
<tr>
<td>Stealthwatch.Observation.source</td>
<td>unknown</td>
<td>Observation source</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!sw-list-observations alert=222</code></pre>
<h5>Context Example</h5>
<pre><code>{
	"cidr_range": "5.5.5.179/32",
	"connected_ip": null,
	"connected_ip_country_code": "",
	"creation_time": "2018-07-23T15:30:00Z",
	"end_time": "2018-07-23T15:30:00Z",
	"id": 12345,
	"observation_name": "Port Scanner",
	"port_count": 24,
	"port_ranges": "0-1023",
	"resource_name": "port_scanner_v1",
	"scan_type": "internal",
	"scanned_packets": 5,
	"scanner_packets": 75,
	"source": 48822,
	"time": "2018-07-23T15:30:00Z"
}
</code></pre>
<h3 id="h_878911594541544340092421">8. Get a list of sessions by session occurrence time</h3>
<hr>
<p>Get sessions by the session's occurrence time ( Time format: YYYY-MM-DDTHH:MM:SSZ)</p>
<h5>Base Command</h5>
<pre><code>sw-list-sessions</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">startTime</td>
<td style="width: 501px;">Session start time (UTC), e.g., startTime="2018-09-30T12:00:00Z"</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">endTime</td>
<td style="width: 501px;">Session end time (UTC), e.g., endTime="2018-07-31T15:00:00Z"</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">limit</td>
<td style="width: 501px;">Number of observations to list, default is 400</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">ip</td>
<td style="width: 501px;">Source IP address to filter by</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">connectedIP</td>
<td style="width: 501px;">Connected IP to filter by</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">connectedDeviceId</td>
<td style="width: 501px;">Connected device ID</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">sessionType</td>
<td style="width: 501px;">Type of session - select external/internal to receive data only about this type of session</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 392px;"><strong>Path</strong></th>
<th style="width: 66px;"><strong>Type</strong></th>
<th style="width: 250px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 392px;">Stealthwatch.Session.id</td>
<td style="width: 66px;">number</td>
<td style="width: 250px;">Session ID</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.port</td>
<td style="width: 66px;">number</td>
<td style="width: 250px;">Session port</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.start_timestamp_utc</td>
<td style="width: 66px;">string</td>
<td style="width: 250px;">Session start time</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.ip</td>
<td style="width: 66px;">string</td>
<td style="width: 250px;">Session IP</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.connected_ip</td>
<td style="width: 66px;">string</td>
<td style="width: 250px;">Session connected IP</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.device_id</td>
<td style="width: 66px;">number</td>
<td style="width: 250px;">Source device ID</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.connected_device_id</td>
<td style="width: 66px;">number</td>
<td style="width: 250px;">Connected device ID</td>
</tr>
<tr>
<td style="width: 392px;">Stealthwatch.Session.connected_device_is_external</td>
<td style="width: 66px;">boolean</td>
<td style="width: 250px;">Is the connected device external</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre><code>!sw-list-sessions startTime="2018-10-30T12:00:00Z" endTime="2018-11-01T12:00:00Z"</code></pre>