<!-- HTML_DOC -->
<h2>Overview</h2>
<p>Use the Cylance Protect v2 integration to manage endpoints, streamline remediation, and response from Cortex XSOAR.</p>
<p>This integration was integrated and tested with version 2.0.5 rev6 of Cylance Protect and Optics.</p>
<h2>Prerequisites</h2>
<p>Before you integrate Cylance Protect on Cortex XSOAR, you need to obtain a Cylance token.</p>
<ol>
<li>In Cylance, navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong>.</li>
<li>Click <strong>Add Application</strong>.</li>
<li>Enter an Application Name, and select the necessary privileges.</li>
<li>Click <strong>Save</strong>.</li>
<li>Record the Application ID and Application Secret for later use. You will not be able to access these later.</li>
<li>Locate the Tenant ID at the top right side of the Integrations page and record it for later use. </li>
</ol>
<h2>Configure the Cylance Protect v2 Integration on Cortex XSOAR</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for Cylance Protect v2.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.<br>
<ul>
<li>
<strong>Name</strong>: A textual name for the integration instance.</li>
<li>
<strong>Server URL</strong>: URL of Cylance server.</li>
<li><strong>Application ID</strong></li>
<li><strong>Application Secret</strong></li>
<li><strong>Tenant API Key</strong></li>
<li><strong>Use system proxy settings</strong></li>
<li>
<strong>File Threshold</strong>: Default is -59</li>
<li><strong>Fetch Incidents</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and connection.</li>
</ol>
<h2>Understanding the Cylance Score</h2>
<p>The Cylance score ranges from -100 to 100, and is translated as follows.</p>
<p>Score translation</p>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Score Range</strong></td>
<td style="width: 190px;"><strong>Color</strong></td>
<td style="width: 308px;"><strong>Severity Level</strong></td>
</tr>
<tr>
<td style="width: 210px;">-100 to -60 </td>
<td style="width: 190px;">Red</td>
<td style="width: 308px;">Malicious</td>
</tr>
<tr>
<td style="width: 210px;">-59 to 0</td>
<td style="width: 190px;">Red</td>
<td style="width: 308px;">Supsicious</td>
</tr>
<tr>
<td style="width: 210px;">1-100</td>
<td style="width: 190px;">Green</td>
<td style="width: 308px;">Good</td>
</tr>
</tbody>
</table>
<h2>Use Cases</h2>
<ul>
<li>Retrieve and update threats and devices.</li>
<li>Produce threat data report of indicators.</li>
<li>Retrieve and create policies and zones.</li>
</ul>
<h2> Commands</h2>
<p>You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_2673377171530178254852">List console device resources for a tenant: cylance-protect-get-devices</a></li>
<li><a href="#h_594628183251530425419438">Get a console device resource for a tenant: cylance-protect-get-device</a></li>
<li><a href="#h_594628183251530425419438">Update a device: cylance-protect-update-device</a></li>
<li><a href="#h_841770284981530427896798">Get information for device threats: cylance-protect-get-device-threats</a></li>
<li><a href="#h_1786905061791530428400287">Get information for console policy resources: cylance-protect-get-policies</a></li>
<li><a href="#h_2720711922181530512175412">Create a zone: cylance-protect-create-zone</a></li>
<li><a href="#h_2710048682601530782277794">Get information for multiple zones: cylance-protect-get-zones</a></li>
<li><a href="#h_980124483071530782631684">Get information for a single zone: cylance-protect-get-zone</a></li>
<li><a href="#h_8048145683591530784000224">Update a zone: cylance-protect-update-zone</a></li>
<li><a href="#h_7519754784161530784958202">Get information for a threat: cylance-protect-get-threat</a></li>
<li><a href="#h_3857035914781530786420157">Get information for a threat device: cylance-protect-get-threat-devices</a></li>
<li><a href="#h_1730263115451530786642819">Generate a report for indicators: cylance-protect-get-indicators-report</a></li>
<li><a href="#h_1465160246171530787140805">Get information for threats: cylance-protect-get-threats</a></li>
<li><a href="#h_9499907176941530787720968">Update device threats: cylance-protect-update-device-threats</a></li>
<li><a href="#h_8691440967761530787902533">Get a list for hashes: cylance-protect-get-list</a></li>
<li><a href="#h_607606529821541937915926">Download a threat: cylance-protect-download-threat</a></li>
<li><a href="#h_1161821402141541937920711">Add a hash to a list: cylance-protect-add-hash-to-list</a></li>
<li><a href="#h_5039804193441541937926117">Delete a hash from a list: cylance-protect-delete-hash-from-lists</a></li>
<li><a href="#h_1587684564731541937931567">Get details of a policy: cylance-protect-get-policy-details</a></li>
<li><a href="#h_2255369916021541937938187">Delete devices: cylance-protect-delete-devices</a></li>
<li><a href="#h_2255369916021541937938188">Create a new Instaquery: cylance-optics-create-instaquery</a></li>
<li><a href="#h_2255369916021541937938189">Get Instaquery result: cylance-optics-get-instaquery-result</a></li>
<li><a href="#h_2255369916021541937938190">List current Instaquery: cylance-optics-list-instaquery</a></li>   
</ol>
<h3 id="h_2673377171530178254852">1. List console device resources for a tenant</h3>
<hr>
<p>Returns a list of console device resources that belong to a tenant. The list is sorted by registration created date, with the most recent at the top of the list.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-devices</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">pageNumber</td>
<td style="width: 565px;">Page number, default is 1</td>
</tr>
<tr>
<td style="width: 180px;">pageSize</td>
<td style="width: 565px;">Specifies if the command polls for the result of the analysis, default is 100, maximum is 200</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 306px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 181px;"><strong>Path</strong></td>
<td style="width: 454px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.AgentVersion</td>
<td style="width: 454px;">CylancePROTECT Agent version installed on the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.DateFirstRegistered</td>
<td style="width: 454px;">Date and time (in UTC) when the device record was created</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.ID</td>
<td style="width: 454px;">Device’s unique identifier</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.IPAddress</td>
<td style="width: 454px;">List of IP addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.MACAddress</td>
<td style="width: 454px;">List of MAC addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.Hostname</td>
<td style="width: 454px;">Device name</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.Policy.ID</td>
<td style="width: 454px;">Device policy ID</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.State</td>
<td style="width: 454px;">Machine state</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.Policy.Name</td>
<td style="width: 454px;">Device policy name</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.Hostname</td>
<td style="width: 454px;">Device name</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.MACAddress</td>
<td style="width: 454px;">List of MAC addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.IPAddress</td>
<td style="width: 454px;">List of IP addresses for the device</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-devices pageNumber=2 pageSize=75</code></p>
<h5>Raw Output</h5>
<pre>{  
   "agent_version":"2.0.1440",
   "date_first_registered":"2018-01-21T15:45:42",
   "id":"652bbfa9-cf74-4e24-90f7-d01b16429701",
   "ip_addresses":[  
      "172.31.31.110"
   ],
   "mac_addresses":[  
      "06-F8-13-8B-16-C9"
   ],
   "name":"WIN-0VJ9RO3P33Q",
   "policy":{  
      "id":null,
      "name":"Default"
   },
   "state":"Online"
}
</pre>
<h3 id="h_594628183251530425419438">2. Get a console device resource for a tenant</h3>
<hr>
<p>Returns a single device resource that belongs to a tenant.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-device</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">id</td>
<td style="width: 565px;">Device ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 306px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 181px;"><strong>Path</strong></td>
<td style="width: 454px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.AgentVersion</td>
<td style="width: 454px;">CylancePROTECT Agent version installed on the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.DateFirstRegistered</td>
<td style="width: 454px;">Date and time (in UTC) when the device record was created</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.BackgroundDetection</td>
<td style="width: 454px;">If <em>true</em>, the agent is running</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.DateLastModified</td>
<td style="width: 454px;">Date and time (in UTC) when the device record was last modified</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.DateOffline</td>
<td style="width: 454px;">Date and time (in UTC) when the device last communicated with the console</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.Hostname</td>
<td style="width: 454px;">Hostname for the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.ID</td>
<td style="width: 454px;">Unique identifier for the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.IPAddress</td>
<td style="width: 454px;">List of IP addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.MACAddress</td>
<td style="width: 454px;">List of MAC addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.IsSafe</td>
<td style="width: 454px;">If <em>true</em>, there are no outstanding threats</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.UpdateAvailable</td>
<td style="width: 454px;">If <em>true</em>, there is available update for the device</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.State</td>
<td style="width: 454px;">Machine state</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.Hostname</td>
<td style="width: 454px;">Device hostname</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.MACAddress</td>
<td style="width: 454px;">List of MAC addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.IPAddress</td>
<td style="width: 454px;">List of IP addresses for the device</td>
</tr>
<tr>
<td style="width: 181px;">Endpoint.OSVersion</td>
<td style="width: 454px;">Device OS version</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.OSVersion</td>
<td style="width: 454px;">Device OS version</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Device.Name</td>
<td style="width: 454px;">Device name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-devices pageNumber=2 pageSize=75</code></p>
<h5>Raw Output</h5>
<pre>{  
   "agent_version":"2.0.1440",
   "date_first_registered":"2018-01-21T15:45:42",
   "id":"652bbfa9-cf74-4e24-90f7-d01b16429701",
   "ip_addresses":[  
      "172.31.31.110"
   ],
   "mac_addresses":[  
      "06-F8-13-8B-16-C9"
   ],
   "name":"WIN-0VJ9RO3P33Q",
   "policy":{  
      "id":null,
      "name":"Default"
   },
   "state":"Online"
}
</pre>
<h3 id="h_594628183251530425419438">3. Update a device</h3>
<hr>
<p>Updates a specified device.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-update-device</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr style="height: 33.3281px;">
<td style="width: 180px; height: 33.3281px;"><strong>Input Parameter</strong></td>
<td style="width: 565px; height: 33.3281px;"><strong>Description</strong></td>
</tr>
<tr style="height: 31px;">
<td style="width: 180px; height: 31px;">id</td>
<td style="width: 565px; height: 31px;">Device ID</td>
</tr>
<tr style="height: 32px;">
<td style="width: 180px; height: 32px;">name</td>
<td style="width: 565px; height: 32px;">Device name</td>
</tr>
<tr style="height: 32px;">
<td style="width: 180px; height: 32px;">policyId</td>
<td style="width: 565px; height: 32px;">Policy ID</td>
</tr>
<tr style="height: 32px;">
<td style="width: 180px; height: 32px;">addZones</td>
<td style="width: 565px; height: 32px;">Zones IDs to add</td>
</tr>
<tr style="height: 32px;">
<td style="width: 180px; height: 32px;">removeZones</td>
<td style="width: 565px; height: 32px;">Zones IDs to remove</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-update-device id=652bbfa9-cf74-4e24-90f7-d01b16429701</code></p>
<h5>Raw Output</h5>
<pre>{  
   "Name":"TestName",
   "PolicyID":"7bcb0817-e9c9-444d-96e2-be9b59f429cb",
   "id":"6033f7a1-e66c-4aef-9c7d-ed454457d071"
}
</pre>
<h3 id="h_841770284981530427896798">4. Get information for device threats</h3>
<hr>
<p>Returns information about threats to devices, including classification, threat score, and more.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-device-threats</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">id</td>
<td style="width: 565px;">Device ID</td>
</tr>
<tr>
<td style="width: 180px;">pageNumber</td>
<td style="width: 565px;">Page number, default is 1</td>
</tr>
<tr>
<td style="width: 180px;">pageSize</td>
<td style="width: 565px;">Specifies if the command polls for the result of the analysis, default is 100, maximum is 200</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 306px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 181px;"><strong>Path</strong></td>
<td style="width: 454px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 181px;">File.Classification</td>
<td style="width: 454px;">Cylance threat classification assigned to the threat</td>
</tr>
<tr>
<td style="width: 181px;">File.CylanceScore</td>
<td style="width: 454px;">Cylance score assigned to the threat</td>
</tr>
<tr>
<td style="width: 181px;">File.DateFound</td>
<td style="width: 454px;">Date and time (in UTC) when the threat was found on the device</td>
</tr>
<tr>
<td style="width: 181px;">File.FilePath</td>
<td style="width: 454px;">File path where the threat was found on the device</td>
</tr>
<tr>
<td style="width: 181px;">File.FileStatus</td>
<td style="width: 454px;">Current status of the file on the device.
<ul>
<li>0 = Default</li>
<li>1 = Quarantined</li>
<li>2 = Whitelisted</li>
<li>3 = Suspicious</li>
<li>4 = FileRemoved</li>
<li>5 = Corrupt</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 181px;"> File.Name</td>
<td style="width: 454px;">Threat name</td>
</tr>
<tr>
<td style="width: 181px;">File.Sha256</td>
<td style="width: 454px;">SHA-256 has for the threat</td>
</tr>
<tr>
<td style="width: 181px;">File.SubClassification</td>
<td style="width: 454px;">Cylance threat sub-classification assigned to the threat</td>
</tr>
<tr>
<td style="width: 181px;">DBotScore.Indicator</td>
<td style="width: 454px;">Tested indicator</td>
</tr>
<tr>
<td style="width: 181px;">DBotScore.Type</td>
<td style="width: 454px;">Indicator type</td>
</tr>
<tr>
<td style="width: 181px;">DBotScore.Vendor</td>
<td style="width: 454px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 181px;">DbotScore.Score</td>
<td style="width: 454px;">Actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-device-threats id=6033f7a1-e66c-4aef-9c7d-ed454457d071 pageNumber=2 pageSize=75</code></p>
<h5>Raw Output</h5>
<pre>{  
   "classification":"Malware",
   "cylance_score":-1,
   "date_found":"2017-11-21T17:34:51",
   "file_path":"C:\\$Recycle.Bin\\S-1-5-21-3378384064-522475393-1698893855-1001\\$RPJNCM8\\artifacts\\2017-08-12-Trickbot-binary-from-usdata.estoreseller.com.exe",
   "file_status":"Default",
   "name":"2017-08-12-Trickbot-binary-from-usdata.estoreseller.com.exe",
   "sha256":"5DA547E87D6EF12349FB4DBBA9CF3146A358E284F72361DD07BBABFC95B0BAC3",
   "sub_classification":"Trojan"
}
</pre>
<h3 id="h_1786905061791530428400287">5. Get information for console policy resources</h3>
<hr>
<p>Returns information for console policy resources.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-policies</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">pageNumber</td>
<td style="width: 565px;">Page number, default is 1</td>
</tr>
<tr>
<td style="width: 180px;">pageItems</td>
<td style="width: 565px;">Number of items on a page, default is 100</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 306px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 181px;"><strong>Path</strong></td>
<td style="width: 454px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Policies.DateAdded</td>
<td style="width: 454px;">Date and time (in UTC) when the Console policy resource was first created</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Policies.DateModified</td>
<td style="width: 454px;">Date and time (in UTC) when the Console policy resource was last modified</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Policies.DeviceCount</td>
<td style="width: 454px;">Number of devices assigned to this policy</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Policies.Id</td>
<td style="width: 454px;">Unique ID for the policy resource</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Policies.Name</td>
<td style="width: 454px;">Policy name</td>
</tr>
<tr>
<td style="width: 181px;">CylanceProtect.Policies.ZoneCount</td>
<td style="width: 454px;">Number of zones assigned to this policy</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-policies id=6033f7a1-e66c-4aef-9c7d-ed454457d071 pageNumber=2 pageSize=75</code></p>
<h5>Raw Output</h5>
<pre>{  
   "date_added":"2018-03-05T12:29:02",
   "date_modified":"2018-03-05T12:29:02",
   "device_count":0,
   "id":"7bcb0817-e9c9-444d-96e2-be9b59f429cb",
   "name":"Test_Policy",
   "zone_count":4
}
</pre>
<h3 id="h_2720711922181530512175412">6. Create a zone</h3>
<hr>
<p>Creates a zone with a policy ID and criticality level.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-create-zone</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">name</td>
<td style="width: 565px;">Zone name</td>
</tr>
<tr>
<td style="width: 180px;">policy_id</td>
<td style="width: 565px;">Unique ID for the policy assigned to the zone</td>
</tr>
<tr>
<td style="width: 180px;">criticality</td>
<td style="width: 565px;">Criticality value of the zone</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-create-zone name=TestingZone3 criticality=High</code></p>
<h5>Raw Output</h5>
<pre>{  
   "criticality":"High",
   "date_created":"2018-03-13T11:38:52.2065082Z",
   "id":"f15b2f79-c100-4146-b056-a8005c13b2de",
   "name":"TestingZone3",
   "policy_id":"7bcb0817-e9c9-444d-96e2-be9b59f429cb"
}
</pre>
<h3 id="h_2710048682601530782277794">7. Get information for multiple zones</h3>
<hr>
<p>Returns information for multiple zones.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-zones</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">pageNumber</td>
<td style="width: 565px;">Page number to request</td>
</tr>
<tr>
<td style="width: 180px;">pageItems</td>
<td style="width: 565px;">Number of zone records to retrieve for each page</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.Criticality</td>
<td style="width: 565px;">
<p>Zone value.</p>
<ul>
<li>Low</li>
<li>Medium</li>
<li>High</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.DateCreated</td>
<td style="width: 565px;">Date and time (in UTC) when the zone was created</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.DateModified</td>
<td style="width: 565px;">Date and time (in UTC) when the zone was last modified</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.Id</td>
<td style="width: 565px;">Zone unique ID</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.Name</td>
<td style="width: 565px;">Zone name</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.PolicyId</td>
<td style="width: 565px;">Unique ID of the policy assigned to the zone</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.UpdateType</td>
<td style="width: 565px;">Update type for the zone</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.ZoneRuleId</td>
<td style="width: 565px;">Unique ID for the zone rule created for the zone</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-zones pageNumber=2 pageItems=10</code></p>
<h5>Raw Output</h5>
<pre>{  
   "criticality":"High",
   "date_created":"2018-03-13T11:38:52",
   "date_modified":"2018-03-13T11:38:52",
   "id":"f15b2f79-c100-4146-b056-a8005c13b2de",
   "name":"TestingZone3",
   "policy_id":"7bcb0817-e9c9-444d-96e2-be9b59f429cb",
   "update_type":"Production",
   "zone_rule_id":null
}
</pre>
<h3 id="h_980124483071530782631684">8. Get information for a single zone</h3>
<hr>
<p>Returns information for a single zone.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-zone</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">id</td>
<td style="width: 565px;">Zone ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.Criticality</td>
<td style="width: 565px;">
<p>Zone value.</p>
<ul>
<li>Low</li>
<li>Medium</li>
<li>High</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.DateCreated</td>
<td style="width: 565px;">Date and time (in UTC) when the zone was created</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.DateModified</td>
<td style="width: 565px;">Date and time (in UTC) when the zone was last modified</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.Id</td>
<td style="width: 565px;">Zone unique ID</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.Name</td>
<td style="width: 565px;">Zone name</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.PolicyId</td>
<td style="width: 565px;">Unique ID of the policy assigned to the zone</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.UpdateType</td>
<td style="width: 565px;">Update type for the zone</td>
</tr>
<tr>
<td style="width: 180px;">CylanceProtect.Zones.ZoneRuleId</td>
<td style="width: 565px;">Unique ID for the zone rule created for the zone</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-zone id=f15b2f79-c100-4146-b056-a8005c13b2de</code></p>
<h5>Raw Output</h5>
<pre>{  
   "criticality":"High",
   "date_created":"2018-03-13T11:38:52",
   "date_modified":"2018-03-13T11:38:52",
   "id":"f15b2f79-c100-4146-b056-a8005c13b2de",
   "name":"TestingZone3",
   "policy_id":"7bcb0817-e9c9-444d-96e2-be9b59f429cb",
   "update_type":"Production",
   "zone_rule_id":null
}
</pre>
<h3 id="h_8048145683591530784000224">9. Update a zone</h3>
<hr>
<p>Updates a specified zone.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-update-zone</code></p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">id</td>
<td style="width: 565px;">Zone ID</td>
</tr>
<tr>
<td style="width: 180px;">name</td>
<td style="width: 565px;">Zone name</td>
</tr>
<tr>
<td style="width: 180px;">policyId</td>
<td style="width: 565px;">Unique ID for the policy assigned to the Zone</td>
</tr>
<tr>
<td style="width: 180px;">criticality</td>
<td style="width: 565px;">Criticality value of the zone</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-update-zone id=f15b2f79-c100-4146-b056-a8005c13b2de</code></p>
<h5>Raw Output</h5>
<pre>true
</pre>
<h3 id="h_7519754784161530784958202">10. Get information for a threat</h3>
<hr>
<p>Returns information for a threat.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-threat</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">sha256</td>
<td style="width: 565px;">SHA-256 hash of the threat</td>
</tr>
<tr>
<td style="width: 180px;">theshold</td>
<td style="width: 565px;">Threat threshold</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">File.AutoRun</td>
<td style="width: 565px;">Indicates if the file is set to automatically run on system startup</td>
</tr>
<tr>
<td style="width: 180px;">File.AvIndustry</td>
<td style="width: 565px;">The score provided by the Anti-Virus industry</td>
</tr>
<tr>
<td style="width: 180px;">File.CertIssuer</td>
<td style="width: 565px;">ID for the certificate issuer</td>
</tr>
<tr>
<td style="width: 180px;">File.CertPublisher</td>
<td style="width: 565px;">ID for the certificate publisher</td>
</tr>
<tr>
<td style="width: 180px;">File.CertTimestamp</td>
<td style="width: 565px;">Date and time (in UTC) when the file was signed using the certificate</td>
</tr>
<tr>
<td style="width: 180px;">File.Classification</td>
<td style="width: 565px;">Threat classification for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.CylanceScore</td>
<td style="width: 565px;">Cylance Score assigned to the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.DetectedBy</td>
<td style="width: 565px;">Name of the Cylance module that detected the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.FileSize</td>
<td style="width: 565px;">Size of the file</td>
</tr>
<tr>
<td style="width: 180px;">File.GlobalQuarantine</td>
<td style="width: 565px;">Identifies if the threat is on the Global Quarantine list</td>
</tr>
<tr>
<td style="width: 180px;">File.Md5</td>
<td style="width: 565px;">MD5 hash for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.Name</td>
<td style="width: 565px;">Threat name</td>
</tr>
<tr>
<td style="width: 180px;">File.Running</td>
<td style="width: 565px;">Identifies if the threat is executing, or another executable loaded or called it</td>
</tr>
<tr>
<td style="width: 180px;">File.Safelisted</td>
<td style="width: 565px;">Identifies if the threat is on the Safe List</td>
</tr>
<tr>
<td style="width: 180px;">File.Sha256</td>
<td style="width: 565px;">SHA-256 hash for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.Signed</td>
<td style="width: 565px;">Identifies the file as signed or not signed</td>
</tr>
<tr>
<td style="width: 180px;">File.SubClassification</td>
<td style="width: 565px;">The threat sub-classification for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.UniqueToCylance</td>
<td style="width: 565px;">The threat was identified by Cylance but not by other anti-virus sources</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Indicator</td>
<td style="width: 565px;">The tested indicator</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Type</td>
<td style="width: 565px;">Indicator type</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Vendor</td>
<td style="width: 565px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Score</td>
<td style="width: 565px;">The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-threat sha256=ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA</code></p>
<h5>Raw Output</h5>
<pre>{  
   "auto_run":false,
   "av_industry":null,
   "cert_issuer":"",
   "cert_publisher":"",
   "cert_timestamp":"0001-01-01T00:00:00",
   "classification":"Malware",
   "cylance_score":-1,
   "detected_by":"File Watcher",
   "file_size":3514368,
   "global_quarantined":true,
   "md5":"84C82835A5D21BBCF75A61706D8AB549",
   "name":"wanncry.exe",
   "running":false,
   "safelisted":false,
  "sha256":"ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA",
   "signed":false,
   "sub_classification":"Ransom",
   "unique_to_cylance":false
}
</pre>
<h3 id="h_3857035914781530786420157">11. Get information for a threat device</h3>
<hr>
<p>Returns information for a threat device.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-threat-devices</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">sha256</td>
<td style="width: 565px;">SHA-256 hash of the threat</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;"><strong>Path</strong></td>
<td style="width: 565px; height: 21px;"><strong>Description</strong></td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">CylanceProtect.Threat.Devices.ID</td>
<td style="width: 565px; height: 21px;">Device ID</td>
</tr>
<tr style="height: 42px;">
<td style="width: 180px; height: 42px;">CylanceProtect.Threat.Devices.DateFound</td>
<td style="width: 565px; height: 42px;">Date and time (in UTC) when the threat was found on the device</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">CylanceProtect.Threat.Devices.AgentVersion</td>
<td style="width: 565px; height: 21px;">Agent version installed on the device</td>
</tr>
<tr style="height: 189px;">
<td style="width: 180px; height: 189px;">CylanceProtect.Threat.Devices.FileStatus</td>
<td style="width: 565px; height: 189px;">
<p>Current quarantine status of the file on the device.</p>
<ul>
<li>0 = Default</li>
<li>1 = Quarantined</li>
<li>2 = Whitelisted</li>
<li>3 = Suspicious</li>
<li>4 = FileRemoved</li>
<li>5 = Corrupt</li>
</ul>
</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">Endpoint.IPAddress</td>
<td style="width: 565px; height: 21px;">List of IP addresses for the device</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">Endpoint.MACAddress</td>
<td style="width: 565px; height: 21px;">List of MAC addresses for the device</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">Endpoint.Hostname</td>
<td style="width: 565px; height: 21px;">Device name for the device</td>
</tr>
<tr style="height: 42px;">
<td style="width: 180px; height: 42px;">CylanceProtect.Threat.Devices.PolicyID</td>
<td style="width: 565px; height: 42px;">Unique identifier of the policy assigned to the device, or <em>null</em> if no policy is assigned</td>
</tr>
<tr style="height: 106.594px;">
<td style="width: 180px; height: 106.594px;">CylanceProtect.Threat.Devices.State</td>
<td style="width: 565px; height: 106.594px;">
<p>Device state.</p>
<ul>
<li>Online</li>
<li>Offline</li>
</ul>
</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">File.SHA256</td>
<td style="width: 565px; height: 21px;">SHA-256 hash of the threat</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">File.Path</td>
<td style="width: 565px; height: 21px;">Path where the file was found on the device</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">CylanceProtect.Threat.Devices.Hostname</td>
<td style="width: 565px; height: 21px;">Device name for the device</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">CylanceProtect.Threat.Devices.IPAddress</td>
<td style="width: 565px; height: 21px;">List of IP addresses for the device</td>
</tr>
<tr style="height: 21px;">
<td style="width: 180px; height: 21px;">CylanceProtect.Threat.Devices.MACAddress</td>
<td style="width: 565px; height: 21px;">List of MAC addresses for the device</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-threat-devices sha256=ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA</code></p>
<h5>Raw Output</h5>
<pre>{  
   "agent_version":"2.0.1440",
   "date_found":"2018-01-21T15:45:46",
   "file_status":"Whitelisted",
   "id":"652bbfa9-cf74-4e24-90f7-d01b16429701",
   "ip_addresses":"172.31.31.110",
   "mac_addresses":"06-F8-13-8B-16-C9",
   "name":"WIN-0VJ9RO3P33Q",
   "policy_id":null,
   "state":"Online"
}
</pre>
<h3 id="h_1730263115451530786642819">12. Generate a report for indicators</h3>
<hr>
<p>Generates a report for indicators.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-indicators-report</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">token</td>
<td style="width: 565px;">Threat data report token</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is not context output for this command.</p>
<h5>Command Example</h5>
<p><code>cylance-protect-get-indicators-report token=As3424$%</code></p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<h3 id="h_1465160246171530787140805">13. Get information for threats</h3>
<hr>
<p>Returns information for threats.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-threats</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">page_size</td>
<td style="width: 565px;">Number of device records to retrieve for each page</td>
</tr>
<tr>
<td style="width: 180px;">page</td>
<td style="width: 565px;">Page number to request</td>
</tr>
<tr>
<td style="width: 180px;">threshold</td>
<td style="width: 565px;">Threat threshold</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">File.Classification</td>
<td style="width: 565px;">Threat classification for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.SubClassification</td>
<td style="width: 565px;">Threat sub-classification for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.Sha256</td>
<td style="width: 565px;">SHA-256 hash for the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.Safelisted</td>
<td style="width: 565px;">Identifies if the threat is on the Safe List</td>
</tr>
<tr>
<td style="width: 180px;">File.Name</td>
<td style="width: 565px;">Threat name</td>
</tr>
<tr>
<td style="width: 180px;">File.LastFound</td>
<td style="width: 565px;">Date and time (in UTC) when the file was last found</td>
</tr>
<tr>
<td style="width: 180px;">File.CylanceScore</td>
<td style="width: 565px;">The Cylance Score assigned to the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.GlobalQuarantine</td>
<td style="width: 565px;">Identifies if the threat is on the Global Quarantine list</td>
</tr>
<tr>
<td style="width: 180px;">File.UniqueToCylance</td>
<td style="width: 565px;">The threat was identified by Cylance but not by other anti-virus sources</td>
</tr>
<tr>
<td style="width: 180px;">File.FileSize</td>
<td style="width: 565px;">File size</td>
</tr>
<tr>
<td style="width: 180px;">File.Md5</td>
<td style="width: 565px;">MD5 hash for the threat</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Indicator</td>
<td style="width: 565px;">The tested indicator</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Type</td>
<td style="width: 565px;">Indicator type</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Vendor</td>
<td style="width: 565px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Score</td>
<td style="width: 565px;">The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-threats page_size=4</code></p>
<h5>Raw Output</h5>
<pre>{  
   "av_industry":null,
   "classification":"Malware",
   "cylance_score":-1,
   "file_size":3514368,
   "global_quarantined":true,
   "last_found":"2018-01-21T15:45:46",
   "md5":"84C82835A5D21BBCF75A61706D8AB549",
   "name":"wanncry.exe",
   "safelisted":false,
   "sha256":"ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA",
   "sub_classification":"Ransom",
   "unique_to_cylance":false
}
</pre>
<h3 id="h_9499907176941530787720968">14. Update device threats</h3>
<hr>
<p>Updates multiple device threats.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-update-device-threats</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">threat_id</td>
<td style="width: 565px;">SHA-256 of the convicted threat</td>
</tr>
<tr>
<td style="width: 180px;">event</td>
<td style="width: 565px;">Requested status update for the convicted threat</td>
</tr>
<tr>
<td style="width: 180px;">device_id</td>
<td style="width: 565px;">ID of the device to update</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-update-device-threats threat_id=ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA</code></p>
<h5>Raw Output</h5>
<pre>true
</pre>
<h3 id="h_8691440967761530787902533">15. Get a list for hashes</h3>
<hr>
<p>Returns a list for hashes.</p>
<h5>Base Command</h5>
<p><code>cylance-protect-get-list</code></p>
<p> </p>
<h5>Input</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Input Parameter</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">listTypeId</td>
<td style="width: 565px;">
<p>Type of list to retrieve hashes for.</p>
<ul>
<li>0 = GlobalQuarantine</li>
<li>1 = GlobalSafe</li>
</ul>
</td>
</tr>
<tr>
<td style="width: 180px;">page_size</td>
<td style="width: 565px;">Number of device records to retrieve for each page</td>
</tr>
<tr>
<td style="width: 180px;">page</td>
<td style="width: 565px;">Page number to request</td>
</tr>
<tr>
<td style="width: 180px;">threshold</td>
<td style="width: 565px;">Threat threshold</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 271px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 180px;"><strong>Path</strong></td>
<td style="width: 565px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 180px;">File.Added</td>
<td style="width: 565px;">Timestamp when the file was added to the list</td>
</tr>
<tr>
<td style="width: 180px;">File.AddedBy</td>
<td style="width: 565px;">Tenant user ID who added the file to the list</td>
</tr>
<tr>
<td style="width: 180px;">File.AvIndustry</td>
<td style="width: 565px;">The score provided by the Anti-Virus industry</td>
</tr>
<tr>
<td style="width: 180px;">File.Category</td>
<td style="width: 565px;">The category for the list specified (for the Global Safe list only)</td>
</tr>
<tr>
<td style="width: 180px;">File.Classification</td>
<td style="width: 565px;">Threat classification assigned by Cylance</td>
</tr>
<tr>
<td style="width: 180px;">File.CylanceScore</td>
<td style="width: 565px;">The Cylance score assigned to the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.ListType</td>
<td style="width: 565px;">list type that the threat belongs to</td>
</tr>
<tr>
<td style="width: 180px;">File.Md5</td>
<td style="width: 565px;">MD5 of the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.Sha256</td>
<td style="width: 565px;">SHA-256 of the threat</td>
</tr>
<tr>
<td style="width: 180px;">File.Name</td>
<td style="width: 565px;">Threat name</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Indicator</td>
<td style="width: 565px;">The tested indicator</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Type</td>
<td style="width: 565px;">Indicator type</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Vendor</td>
<td style="width: 565px;">Vendor used to calculate the score</td>
</tr>
<tr>
<td style="width: 180px;">DBotScore.Score</td>
<td style="width: 565px;">The actual score</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cylance-protect-get-list listTypeId=0 page_size=4</code></p>
<h5>Raw Output</h5>
<pre>{  
   "added":"2017-11-07T04:30:04",
   "added_by":"3ff9b11e-b64e-4350-97ba-aeb0a099b8ee",
   "av_industry":null,
   "category":"",
   "classification":"Malware",
   "cylance_score":-1,
   "list_type":"GlobalQuarantine",
   "md5":"84C82835A5D21BBCF75A61706D8AB549",
   "name":"wanncry.exe",
   "reason":"Malicious File Found",
   "sha256":"ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA",
   "sub_classification":"Ransom"
}
</pre>
<p> </p>
<h3 id="h_607606529821541937915926">16. Download a threat</h3>
<hr>
<p>Downloads a threat attached to a specific SHA-256 hash.</p>
<h5>Base Command</h5>
<pre><code>cylance-protect-download-threat</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 496px;"><strong>Description</strong></th>
<th style="width: 75px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">sha256</td>
<td style="width: 496px;">The SHA-256 hash for the file you want to download</td>
<td style="width: 75px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">threshold</td>
<td style="width: 496px;">File threshold to determine reputation</td>
<td style="width: 75px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">unzip</td>
<td style="width: 496px;">Check to return the file unzipped to the War Room</td>
<td style="width: 75px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 172px;"><strong>Path</strong></th>
<th style="width: 62px;"><strong>Type</strong></th>
<th style="width: 474px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 172px;">File.SHA256</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">SHA-256 of the file</td>
</tr>
<tr>
<td style="width: 172px;">File.Name</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">File name</td>
</tr>
<tr>
<td style="width: 172px;">File.Size</td>
<td style="width: 62px;">number</td>
<td style="width: 474px;">File size</td>
</tr>
<tr>
<td style="width: 172px;">File.Safelisted</td>
<td style="width: 62px;">boolean</td>
<td style="width: 474px;">Safelisted</td>
</tr>
<tr>
<td style="width: 172px;">File.Timestamp</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">Timestamp</td>
</tr>
<tr>
<td style="width: 172px;">File.Md5</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">MD5</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Indicator</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">The Indicator</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Score</td>
<td style="width: 62px;">number</td>
<td style="width: 474px;">The DBot score</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Type</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">The Indicator type</td>
</tr>
<tr>
<td style="width: 172px;">DBotScore.Vendor</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">The DBot score vendor</td>
</tr>
<tr>
<td style="width: 172px;">File.Malicious.Vendor</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">For malicious files, the vendor that made the decision</td>
</tr>
<tr>
<td style="width: 172px;">File.Malicious.Description</td>
<td style="width: 62px;">string</td>
<td style="width: 474px;">For malicious files, the reason that the vendor made the decision</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cylance-protect-download-threat sha256="0f427b33b824110427b2ba7be20740b45ea4da41bc1416dd55771edfb0c18f09" unzip="yes"</pre>
<h5>Context Example</h5>
<pre>DBotScore<br>{<br>  "Indicator": "AutoitLocker.exe",<br>  "Score": 3,<br>  "Type": "file",<br>  "Vendor": "Cylance Protect"<br>}<br>File<br>{<br>  "DownloadURL":       "https://cylanceephemeralfilestore.s3.amazonaws.com/0F/42/7B/33/0F427B33B824110427B2BA7BE20740B45EA4DA41BC1416DD55771EDFB0C18F09.zip? Signature=98kI7a19I2q%2BeE7Ef1un4BjSolQ%3D&amp;Expires=1541875473&amp;AWSAccessKeyId=AKIAIAD6JC2YTYVBFRFA",<br>  "MD5": "2FC103D0D52466B63D44444CE12A5901",<br>  "Malicious": {<br>  "Description": "Score determined by get threat command",<br>  "Vendor": "Cylance Protect"<br>},<br>  "Name": "AutoitLocker.exe",<br>  "SHA256": "0F427B33B824110427B2BA7BE20740B45EA4DA41BC1416DD55771EDFB0C18F09",<br>  "Safelisted": false,<br>  "Size": 405345,<br>  "Timestamp": "0001-01-01T00:00:00"<br>}</pre>
<h5>Human Readable Output</h5>
<p><a href="../../doc_files/48305021-47292280-e52c-11e8-9ba0-6a579b41ed4e.png" target="_blank" rel="noopener noreferrer"><img src="../../doc_files/48305021-47292280-e52c-11e8-9ba0-6a579b41ed4e.png" alt="screen shot 2018-11-10 at 20 56 40" width="749" height="370"></a></p>
<h3 id="h_1161821402141541937920711">17. Add a hash to a list</h3>
<hr>
<p>Adds an identified threat to either the Global Quarantine list or the Global Safe list for a particular Tenant.</p>
<h5>Base Command</h5>
<pre><code>cylance-protect-add-hash-to-list</code></pre>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">sha256</td>
<td style="width: 499px;">SHA-256 hash to add to the Global Safe list</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">listType</td>
<td style="width: 499px;">The list type the threat belongs to (GlobalQuarantine or GlobalSafe)</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">reason</td>
<td style="width: 499px;">The reason why the file was added to the list</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">category</td>
<td style="width: 499px;">This field is required only if the <em>list_type</em> value is Global Safe. The value can be one ofthe following:• Admin Tool• Commercial Software• Drivers• Internal Application• Operating System• Security Software• None</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 150px;"><strong>Path</strong></th>
<th style="width: 44px;"><strong>Type</strong></th>
<th style="width: 514px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 150px;">File.SHA256</td>
<td style="width: 44px;">string</td>
<td style="width: 514px;">The SHA-256 hash for the threat</td>
</tr>
<tr>
<td style="width: 150px;">File.Cylance.ListType</td>
<td style="width: 44px;">string</td>
<td style="width: 514px;">The list type the threat belongs to (GlobalQuarantine or GlobalSafe)</td>
</tr>
<tr>
<td style="width: 150px;">File.Cylance.Category</td>
<td style="width: 44px;">string</td>
<td style="width: 514px;">This field is required only if the <em>list_type</em> value is Global Safe. The value can be one of the following: • Admin Tool • Commercial Software • Drivers • Internal Application • Operating System • Security Software • None</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cylance-protect-add-hash-to-list sha256="9ACD45F5F3F2C7629E51FE3123D31296EF763F6ABC1F895CDD1BF1AFB9A7453B" listType="GlobalQuarantine"</pre>
<h5>Human Readable Output</h5>
<p><a href="../../doc_files/48305028-51e3b780-e52c-11e8-8dd6-14ec09966997.png" target="_blank" rel="noopener noreferrer"><img src="../../doc_files/48305028-51e3b780-e52c-11e8-8dd6-14ec09966997.png" alt="screen shot 2018-11-10 at 20 58 58" width="749" height="103"></a></p>
<h3 id="h_5039804193441541937926117">18. Remove a threat from a list</h3>
<hr>
<p>Removes an identified threat from either the Global Quarantine list or the Global Safe list for a particular Tenant.</p>
<h5>Base Command</h5>
<pre><code>cylance-protect-delete-hash-from-lists</code></pre>
<h5>Input</h5>
<table style="width: 744px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 144px;"><strong>Argument Name</strong></th>
<th style="width: 493px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 144px;">sha256</td>
<td style="width: 493px;">The SHA-256 hash for the threat</td>
<td style="width: 71px;">True</td>
</tr>
<tr>
<td style="width: 144px;">listType</td>
<td style="width: 493px;">The list type the threat belongs to (GlobalQuarantine or GlobalSafe) </td>
<td style="width: 71px;">True</td>
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
<td>File.SHA256</td>
<td>string</td>
<td>SHA-256 of the file</td>
</tr>
<tr>
<td>File.Cylance.ListType</td>
<td>string</td>
<td>The list type the threat belongs to (GlobalQuarantine or GlobalSafe)</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cylance-protect-delete-hash-from-lists sha256="9ACD45F5F3F2C7629E51FE3123D31296EF763F6ABC1F895CDD1BF1AFB9A7453B" listType="GlobalQuarantine"</pre>
<h5>Human Readable Output</h5>
<p><a href="../../doc_files/48305036-57410200-e52c-11e8-98c0-9f714ae2e7ed.png" target="_blank" rel="noopener noreferrer"><img src="../../doc_files/48305036-57410200-e52c-11e8-98c0-9f714ae2e7ed.png" alt="screen shot 2018-11-10 at 21 01 23" width="748" height="111"></a></p>
<h3 id="h_1587684564731541937931567">19. Get details for a policy</h3>
<hr>
<p>Gets details for a single policy.</p>
<h5>Base Command</h5>
<pre><code>cylance-protect-get-policy-details</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 174px;"><strong>Argument Name</strong></th>
<th style="width: 433px;"><strong>Description</strong></th>
<th style="width: 101px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 174px;">policyID</td>
<td style="width: 433px;">The Tenant policy ID to the service endpoint.</td>
<td style="width: 101px;">True</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 221px;"><strong>Path</strong></th>
<th style="width: 54px;"><strong>Type</strong></th>
<th style="width: 433px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 221px;">Cylance.Policy.ID</td>
<td style="width: 54px;">string</td>
<td style="width: 433px;">Policy ID</td>
</tr>
<tr>
<td style="width: 221px;">Cylance.Policy.Name</td>
<td style="width: 54px;">string</td>
<td style="width: 433px;">Policy name</td>
</tr>
<tr>
<td style="width: 221px;">Cylance.Policy.Timestamp</td>
<td style="width: 54px;">string</td>
<td style="width: 433px;">The date and time the policy was created, in UTC.</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5> </h5>
<h3 id="h_2255369916021541937938187">20. Delete devices</h3>
<hr>
<p>Deletes one or more devices from an organization.</p>
<h5>Base Command</h5>
<pre><code>cylance-protect-delete-devices</code></pre>
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
<td style="width: 130px;">deviceIds</td>
<td style="width: 507px;">The unique identifiers for the devices to delete. The maximum number of Device IDs per request is 20.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 130px;">batch_size</td>
<td style="width: 507px;">The number of devices to delete per request (batch)</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 222px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 423px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 222px;">Cylance.Device.Id</td>
<td style="width: 63px;">string</td>
<td style="width: 423px;">The unique identifier of the deletion request</td>
</tr>
<tr>
<td style="width: 222px;">Cylance.Device.Name</td>
<td style="width: 63px;">string</td>
<td style="width: 423px;">Device name</td>
</tr>
<tr>
<td style="width: 222px;">Cylance.Device.Deleted</td>
<td style="width: 63px;">string</td>
<td style="width: 423px;">Checks if the device was deleted (boolean)</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!cylance-protect-get-policy-details policyID="7bcb0817-e9c9-444d-96e2-be9b59f429cb"</pre>
<h5>Context Example</h5>
<pre>Cylance<br>{<br>  "Policy": {<br>  "ID": "7bcb0817-e9c9-444d-96e2-be9b59f429cb",<br>  "Name": "Test_Policy",<br>  "Timestamp": "2018-03-05T12:29:03.000000+00:00"<br>               }<br>}</pre>
<h5>Human Readable Output</h5>
<p><a href="../../doc_files/48305037-5d36e300-e52c-11e8-8444-db223ee4b34e.png" target="_blank" rel="noopener noreferrer"><img src="../../doc_files/48305037-5d36e300-e52c-11e8-8444-db223ee4b34e.png" alt="screen shot 2018-11-10 at 21 02 56" width="595" height="685"></a></p>

### cylance-protect-get-device-by-hostname
***
Allows a caller to request a specific device resource belonging to a Tenant by hostname


#### Base Command

`cylance-protect-get-device-by-hostname`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The hostname (DNS name). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CylanceProtect.Device.AgentVersion | String | The CylancePROTECT Agent version installed on the device. | 
| CylanceProtect.Device.IPAddress | Unknown | The list of IP addresses for the device. | 
| CylanceProtect.Device.MACAddress | Unknown | The list of MAC addresses for the device. | 
| CylanceProtect.Device.Hostname | string | The hostname for the device. | 
| CylanceProtect.Device.OSVersion | string | Device OS version. | 
| CylanceProtect.Device.UpdateAvailable | boolean | If true, there is available update for the device. | 
| CylanceProtect.Device.BackgroundDetection | boolean | If true, the Agent is currently running. | 
| CylanceProtect.Device.DateFirstRegistered | date | The date and time \(in UTC\) when the device record was created. | 
| CylanceProtect.Device.DateLastModified | date | The date and time \(in UTC\) when the device record was last modified. | 
| CylanceProtect.Device.DateOffline | date | The date and time \(in UTC\) when the device last communicated with the Console. | 
| CylanceProtect.Device.IsSafe | boolean | If true, there are no outstanding threats. | 
| CylanceProtect.Device.LastLoggedInUser | string | Last logged in user. | 
| CylanceProtect.Device.State | string | Machine state. | 
| CylanceProtect.Device.ID | string | The unique identifier for the device. | 
| CylanceProtect.Device.Name | string | Device name. | 
| CylanceProtect.Device.UpdateType | string | Device update type. | 
| CylanceProtect.Device.Policy.ID | string | Device policy ID. | 
| CylanceProtect.Device.Policy.Name | string | Device policy name. | 
| Endpoint.Hostname | string | Device hostname. | 
| Endpoint.MACAddress | Unknown | The list of MAC addresses for the device. | 
| Endpoint.IPAddress | Unknown | The list of IP addresses for the device. | 
| Endpoint.OSVersion | string | Device OS version. | 


#### Command Example
```!cylance-protect-get-device-by-hostname hostname=WIN-5HMOGIEG6M5```

#### Context Example
```json
{
    "CylanceProtect": {
        "Device": {
            "AgentVersion": "1.2.1418",
            "BackgroundDetection": false,
            "DateFirstRegistered": "2017-12-29T04:07:56",
            "DateLastModified": null,
            "DateOffline": "2020-02-07T02:25:34.151",
            "Hostname": "WIN-5HMOGIEG6M5",
            "ID": "b4eceeb0-8699-4d42-b853-155513042d6e",
            "IPAddress": [
                "127.0.0.1"
            ],
            "IsSafe": true,
            "LastLoggedInUser": "",
            "MACAdress": [
                "02-76-91-6B-0A-BB"
            ],
            "Name": "WIN-5HMOGIEG6M5",
            "OSVersion": "Microsoft Windows Server 2012 R2 Standard",
            "Policy": {
                "ID": "32e4aacd-7698-4ef0-93e8-3e6f1f5c6857",
                "Name": "Default"
            },
            "State": "Offline",
            "UpdateAvailable": false
        }
    },
    "Endpoint": {
        "Hostname": "WIN-5HMOGIEG6M5",
        "IPAddress": [
            "127.0.0.1"
        ],
        "MACAdress": [
            "02-76-91-6B-0A-BB"
        ],
        "OSVersion": "Microsoft Windows Server 2012 R2 Standard"
    }
}
```

#### Human Readable Output

>### Cylance Protect Device WIN-5HMOGIEG6M5
>|AgentVersion|BackgroundDetection|DateFirstRegistered|DateOffline|DlcmStatus|HostName|Id|IpAddresses|IsSafe|MacAddresses|Name|OsKernelVersion|OsVersion|Policy|Products|State|UpdateAvailable|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1.2.1418 | false | 2017-12-29T04:07:56 | 2020-02-07T02:25:34.151 | Unknown | WIN-5HMOGIEG6M5 | b4eceeb0-8699-4d42-b853-155513042d6e | 127.0.0.1 | true | 02-76-91-6B-0A-BB | WIN-5HMOGIEG6M5 | 6.3.0 | Microsoft Windows Server 2012 R2 Standard | Default | {u'status': u'Offline', u'version': u'1.2.1418', u'name': u'protect'} | Offline | false |

<h3 id="h_2255369916021541937938188">21. Create a new Instaquery</h3>
### cylance-optics-create-instaquery
***
Create a cylance InstaQuery


#### Base Command

`cylance-optics-create-instaquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | InstaQuery name. | Required | 
| description | InstaQuery description. | Required | 
| artifact | InstaQuery artifact, select from the list. Possible values are: File, Process, NetworkConnection, RegistryKey. | Required | 
| match_value_type | InstaQuery value type to match, select from the list. Possible values are: File.Path, File.Md5, File.Sha2, File.Owner, File.CreationDateTime, Process.Name, Process.Commandline, Process.PrimaryImagePath, Process.PrimaryImageMd5, Process.StartDateTime, NetworkConnection.DestAddr, NetworkConnection.DestPort, RegistryKey.ProcessName, RegistryKey.ProcessPrimaryImagePath, RegistryKey.ValueName, RegistryKey.FilePath, RegistryKey.FileMd5, RegistryKey.IsPersistencePoint. | Required | 
| match_values | Value to search in InstaQuery. | Required | 
| zone | Zone of the object. | Required | 
| match_type | Match type fuzzy or exact. Possible values are: Fuzzy, Exact. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InstaQuery.New.id | string | The unique identifier of the created InstaQuery. | 
| InstaQuery.New.created_at | date | The Date and Time that the InstaQuery was created. | 
| InstaQuery.New.progress | string | The progress of the InstaQuery. | 


#### Command Example
``` 
!cylance-optics-create-instaquery name="Test Insta continue" description="Test only" artifact="File" match_value_type="File.Path" match_values="exe" zone="6608ca0e-88c6-4647-b276-271cc5ea4295" match_type="Fuzzy"
```

#### Human Readable Output
| Result            |                                  |
|-------------------|----------------------------------|
| case_sensitive    | false                            |
| artifact          | File                             |
| created_at        | 2022-05-05T05:52:36Z             |
| description       | Test only                        |
| id                | 9E2CCDA5A93918C588E6865ED6FEEA70 |
| match_type        | Fuzzy                            |
| match_value_type  | Path                             |
| match_values      | exe                              |
| name              | Test Insta continue              |
| progress          |                                  |
| results_available | false                            |
| zones             | 6608CA0E88C64647B276271CC5EA4295 |


<h3 id="h_2255369916021541937938189">22. Get Instaquery result</h3>
### cylance-optics-get-instaquery-result
***
Get a cylance InstaQuery search result


#### Base Command

`cylance-optics-get-instaquery-result`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query_id | InstaQuery ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InstaQuery.Results.result | string | The InstaQuery results. | 


#### Command Example
``` 
!cylance-optics-get-instaquery-result query_id=9E2CCDA5A93918C588E6865ED6FEEA70
```

#### Human Readable Output

|        | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| id     | 9E2CCDA5A93918C588E6865ED6FEEA70                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| result | false                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| status | {u'@timestamp': 1651729959.177779, u'HostName': u'windows-server-', u'DeviceId': u' 65DB26864E364409B50DDC23291A3511 ', u'@version': u'1', u'CorrelationId': u' 9E2CCDA5A93918C588E6865ED6FEEA70 ', u'Result': u'{"FirstObservedTime": "1970-01-01T00:00:00.000Z", "LastObservedTime": "1970-01-01T00:00:00.000Z", "Uid": "dHrtLYQzbt9oJPxO8HaeyA==", "Type": "File", "Properties": {"Path": "c:\\program files\\cylance\\optics\\ cyoptics.exe ", "CreationDateTime": "2021-03-29T22:34:14.000Z", "Md5": " A081D3268531485BF95DC1A15A5BC6B0 ", "Sha256": " 256809AABD3AB57949003B9AFCB556A9973222CDE81929982DAE7D306648E462 ", "Owner": "NT AUTHORITY\\SYSTEM", "SuspectedFileType": "Executable/PE", "FileSignature": "", "Size": "594104", "OwnerUid": "P3p6fdq3FlMsld6Rz95EOA=="}}'} |


<h3 id="h_2255369916021541937938190">23. List current Instaqueries</h3>
### cylance-optics-list-instaquery
***
Get a list of InstaQuery


#### Base Command

`cylance-optics-list-instaquery`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page | number of page to collect. | Optional | 
| page_size | number of items per page to collect. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InstaQuery.List | string | The list of InstaQuery | 


#### Command Example
``` 
!cylance-optics-list-instaquery page_size="10"
```

#### Human Readable Output
|                       | Result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| page_items            | {u'match_type': u'Fuzzy', u'name': u'Test Insta continue', u'created_at': u'2022-05-05T05:52:36Z', u'artifact': u'File', u'case_sensitive': False, u'zones': [u'6608CA0E88C64647B276271CC5EA4295'], u'progress': {u'queried': 0, u'responded': 0}, u'match_value_type': u'Path', u'results_available': True, u'match_values': [u'exe'], u'id': u'9E2CCDA5A93918C588E6865ED6FEEA70', u'description': u'Test only'} |
| page_number           | 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| page_size             | 10                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| total_number_of_items | 8                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| total_pages           | 1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |

